//! The daemon's own parse of `requestDetailsJson` and its WebAuthn-JSON `responseJson`
//! (ADR 0014 sections 10.2, 10.3 and 11).
//!
//! The worker forwards the browser's request details verbatim. The daemon parses them itself and
//! maps them onto the ceremony requests the handlers already validate. The origin comes only from
//! the browser-supplied `extensions.remoteDesktopClientOverride`; that entry is browser metadata and
//! is stripped from the RP's extension list here. The response is built only from the handler's
//! output, so `clientDataJSON` is always the one the daemon signed over.

use serde_json::{Map, Value, json};

use passless_core::agent::protocol::{
    RegisterCredentialRequest, RegisterCredentialResponse, SignAssertionRequest,
    SignAssertionResponse,
};

use crate::agent::sign::{b64u_decode, b64u_encode};

/// The browser metadata entry inside the request's `extensions` (ADR 0014 section 11).
pub(crate) const REMOTE_DESKTOP_OVERRIDE: &str = "remoteDesktopClientOverride";

const MAX_ORIGIN_LEN: usize = 512;
const MAX_RP_ID_LEN: usize = 253;
const MAX_CHALLENGE_BYTES: usize = 1024;
const MAX_CREDENTIAL_ID_BYTES: usize = 1023;
const MAX_CREDENTIAL_DESCRIPTORS: usize = 64;
const MAX_USER_ID_BYTES: usize = 64;
const MAX_USER_FIELD_LEN: usize = 1024;
const MAX_ALGORITHMS: usize = 64;
const MAX_ATTESTATION_LEN: usize = 32;
/// `pubKeyCredParams` when the RP passed an empty list (WebAuthn: ES256 and RS256).
const DEFAULT_ALGORITHMS: [i32; 2] = [-7, -257];

/// The ceremony a `request` frame names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    Get,
    Create,
}

impl Op {
    pub fn parse(op: &str) -> Option<Self> {
        match op {
            "get" => Some(Self::Get),
            "create" => Some(Self::Create),
            _ => None,
        }
    }
}

/// A request as the daemon parsed it.
#[derive(Debug)]
pub(crate) enum ParsedCeremony {
    Get(SignAssertionRequest),
    Create {
        request: RegisterCredentialRequest,
        /// The RP asked for the `credProps` client extension output.
        cred_props: bool,
    },
}

impl ParsedCeremony {
    pub fn origin(&self) -> &str {
        match self {
            Self::Get(request) => &request.origin,
            Self::Create { request, .. } => &request.origin,
        }
    }

    pub fn cross_origin(&self) -> bool {
        match self {
            Self::Get(request) => request.cross_origin,
            Self::Create { request, .. } => request.cross_origin,
        }
    }

    pub fn timeout_ms(&self) -> Option<u64> {
        match self {
            Self::Get(request) => request.timeout_ms,
            Self::Create { request, .. } => request.timeout_ms,
        }
    }
}

/// Parse `requestDetailsJson` for `op`. Every error is a malformed request (`bad_request`).
pub(crate) fn parse_request_details(op: Op, body: &str) -> Result<ParsedCeremony, &'static str> {
    let Ok(Value::Object(details)) = serde_json::from_str::<Value>(body) else {
        return Err("request details are not a JSON object");
    };
    let extensions = match details.get("extensions") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(map)) => map.clone(),
        Some(_) => return Err("extensions is not an object"),
    };
    let (origin, same_origin_with_ancestors) = browser_origin(&extensions)?;
    // The extension names the RP asked for, without the browser's metadata entry.
    let extension_names: Vec<String> = extensions
        .keys()
        .filter(|name| name.as_str() != REMOTE_DESKTOP_OVERRIDE)
        .cloned()
        .collect();
    let challenge_b64u = normalized_b64u(
        details.get("challenge"),
        1,
        MAX_CHALLENGE_BYTES,
        "invalid challenge",
    )?;
    let timeout_ms = details.get("timeout").and_then(timeout_ms);
    let cross_origin = !same_origin_with_ancestors;

    match op {
        Op::Get => {
            let rp_id = rp_id(details.get("rpId"))?;
            let allow_credentials =
                credential_descriptors(details.get("allowCredentials"), "allowCredentials")?;
            let user_verification = user_verification_required(details.get("userVerification"))?;
            Ok(ParsedCeremony::Get(SignAssertionRequest {
                origin,
                top_origin: None,
                rp_id,
                challenge_b64u,
                allow_credentials,
                user_verification,
                cross_origin,
                extensions: extension_names,
                timeout_ms,
            }))
        }
        Op::Create => {
            let Some(Value::Object(rp)) = details.get("rp") else {
                return Err("rp is missing");
            };
            let rp_id = rp_id(rp.get("id"))?;
            let rp_name = optional_text(rp.get("name"), "invalid rp.name")?;
            let Some(Value::Object(user)) = details.get("user") else {
                return Err("user is missing");
            };
            let user_id_b64u =
                normalized_b64u(user.get("id"), 1, MAX_USER_ID_BYTES, "invalid user.id")?;
            let user_name = match user.get("name") {
                Some(Value::String(name)) if name.len() <= MAX_USER_FIELD_LEN => name.clone(),
                _ => return Err("invalid user.name"),
            };
            let user_display_name =
                optional_text(user.get("displayName"), "invalid user.displayName")?;
            let exclude_credentials =
                credential_descriptors(details.get("excludeCredentials"), "excludeCredentials")?;
            let pub_key_cred_params = algorithms(details.get("pubKeyCredParams"))?;
            let (user_verification, authenticator_attachment) =
                match details.get("authenticatorSelection") {
                    None | Some(Value::Null) => (false, None),
                    Some(Value::Object(selection)) => (
                        user_verification_required(selection.get("userVerification"))?,
                        authenticator_selection(selection)?,
                    ),
                    Some(_) => return Err("authenticatorSelection is not an object"),
                };
            // Only `none` attestation is produced; the handler rejects `enterprise`.
            let attestation = match details.get("attestation") {
                Some(Value::String(value)) => {
                    Some(value.chars().take(MAX_ATTESTATION_LEN).collect())
                }
                _ => None,
            };
            let cred_props = extensions.get("credProps") == Some(&Value::Bool(true));
            Ok(ParsedCeremony::Create {
                request: RegisterCredentialRequest {
                    origin,
                    top_origin: None,
                    rp_id,
                    challenge_b64u,
                    user_id_b64u,
                    user_name,
                    user_display_name,
                    rp_name,
                    exclude_credentials,
                    pub_key_cred_params,
                    user_verification,
                    cross_origin,
                    extensions: extension_names,
                    attestation,
                    timeout_ms,
                    authenticator_attachment,
                },
                cred_props,
            })
        }
    }
}

/// The rest of `authenticatorSelection`: returns `authenticatorAttachment` (the handler refuses
/// `platform` with `NotSupportedError`, invariant 22). `residentKey` and `requireResidentKey` are
/// type-checked only: Passless always creates a discoverable credential, which satisfies every
/// value. Unknown enum strings are ignored, as WebAuthn requires.
fn authenticator_selection(selection: &Map<String, Value>) -> Result<Option<String>, &'static str> {
    match selection.get("residentKey") {
        None | Some(Value::Null) | Some(Value::String(_)) => {}
        Some(_) => return Err("invalid authenticatorSelection.residentKey"),
    }
    match selection.get("requireResidentKey") {
        None | Some(Value::Null) | Some(Value::Bool(_)) => {}
        Some(_) => return Err("invalid authenticatorSelection.requireResidentKey"),
    }
    match selection.get("authenticatorAttachment") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(attachment)) => {
            Ok(Some(attachment.chars().take(MAX_ATTESTATION_LEN).collect()))
        }
        Some(_) => Err("invalid authenticatorSelection.authenticatorAttachment"),
    }
}

/// The browser-supplied origin and `sameOriginWithAncestors` (ADR 0014 section 11). A page cannot
/// forge them: the browser overwrites a page-supplied override.
fn browser_origin(extensions: &Map<String, Value>) -> Result<(String, bool), &'static str> {
    let Some(Value::Object(client_override)) = extensions.get(REMOTE_DESKTOP_OVERRIDE) else {
        return Err("remoteDesktopClientOverride is missing");
    };
    let origin = match client_override.get("origin") {
        Some(Value::String(origin)) if !origin.is_empty() && origin.len() <= MAX_ORIGIN_LEN => {
            origin.clone()
        }
        _ => return Err("invalid remoteDesktopClientOverride.origin"),
    };
    let Some(Value::Bool(same_origin)) = client_override.get("sameOriginWithAncestors") else {
        return Err("invalid remoteDesktopClientOverride.sameOriginWithAncestors");
    };
    Ok((origin, *same_origin))
}

fn rp_id(value: Option<&Value>) -> Result<String, &'static str> {
    match value {
        Some(Value::String(rp_id)) if !rp_id.is_empty() && rp_id.len() <= MAX_RP_ID_LEN => {
            Ok(rp_id.clone())
        }
        _ => Err("invalid RP ID"),
    }
}

/// An optional string; an empty one counts as absent.
fn optional_text(
    value: Option<&Value>,
    error: &'static str,
) -> Result<Option<String>, &'static str> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if text.len() <= MAX_USER_FIELD_LEN => {
            Ok((!text.is_empty()).then(|| text.clone()))
        }
        _ => Err(error),
    }
}

/// A base64url value re-encoded without padding, with its decoded length within the bounds.
/// Re-encoding means the value the daemon writes into `clientDataJSON` is canonical.
fn normalized_b64u(
    value: Option<&Value>,
    min: usize,
    max: usize,
    error: &'static str,
) -> Result<String, &'static str> {
    let Some(Value::String(encoded)) = value else {
        return Err(error);
    };
    if encoded.len() > max.div_ceil(3) * 4 + 2 {
        return Err(error);
    }
    let bytes = b64u_decode(encoded).map_err(|_| error)?;
    if bytes.len() < min || bytes.len() > max {
        return Err(error);
    }
    Ok(b64u_encode(&bytes))
}

/// The ids of `allowCredentials` or `excludeCredentials` (normalized base64url).
fn credential_descriptors(
    value: Option<&Value>,
    error: &'static str,
) -> Result<Vec<String>, &'static str> {
    let descriptors = match value {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(descriptors)) if descriptors.len() <= MAX_CREDENTIAL_DESCRIPTORS => {
            descriptors
        }
        Some(_) => return Err(error),
    };
    descriptors
        .iter()
        .map(|descriptor| {
            let Value::Object(descriptor) = descriptor else {
                return Err(error);
            };
            if descriptor.get("type") != Some(&Value::String("public-key".into())) {
                return Err(error);
            }
            normalized_b64u(descriptor.get("id"), 1, MAX_CREDENTIAL_ID_BYTES, error)
        })
        .collect()
}

/// `userVerification == "required"`, as the previous extension computed it. Under `allow` the
/// daemon sets UV from the agent session regardless (ADR 0014 section 7).
fn user_verification_required(value: Option<&Value>) -> Result<bool, &'static str> {
    match value {
        None | Some(Value::Null) => Ok(false),
        Some(Value::String(requirement)) => Ok(requirement == "required"),
        Some(_) => Err("invalid userVerification"),
    }
}

/// The RP's algorithms in order. Entries of another credential type are ignored (WebAuthn); an
/// empty list means ES256 and RS256.
fn algorithms(value: Option<&Value>) -> Result<Vec<i32>, &'static str> {
    const ERROR: &str = "invalid pubKeyCredParams";
    let params = match value {
        None | Some(Value::Null) => return Ok(DEFAULT_ALGORITHMS.to_vec()),
        Some(Value::Array(params)) if params.len() <= MAX_ALGORITHMS => params,
        Some(_) => return Err(ERROR),
    };
    if params.is_empty() {
        return Ok(DEFAULT_ALGORITHMS.to_vec());
    }
    let mut algorithms = Vec::with_capacity(params.len());
    for param in params {
        let Value::Object(param) = param else {
            return Err(ERROR);
        };
        if param.get("type") != Some(&Value::String("public-key".into())) {
            continue;
        }
        let algorithm = param
            .get("alg")
            .and_then(Value::as_i64)
            .and_then(|alg| i32::try_from(alg).ok())
            .ok_or(ERROR)?;
        algorithms.push(algorithm);
    }
    Ok(algorithms)
}

/// The page timeout in milliseconds, if it is a non-negative number.
fn timeout_ms(value: &Value) -> Option<u64> {
    if let Some(ms) = value.as_u64() {
        return Some(ms);
    }
    value
        .as_f64()
        .filter(|ms| ms.is_finite() && *ms >= 0.0)
        .map(|ms| ms.min(u64::MAX as f64) as u64)
}

/// The best-effort RP ID of a request whose bearer is refused before it is parsed, for the
/// refusal audit. Untrusted: the caller validates it.
pub(crate) fn refused_rp_id(op: Op, body: &str) -> Option<String> {
    let details = serde_json::from_str::<Value>(body).ok()?;
    let rp_id = match op {
        Op::Get => details.get("rpId")?,
        Op::Create => details.get("rp")?.get("id")?,
    };
    rp_id
        .as_str()
        .filter(|rp_id| rp_id.len() <= MAX_RP_ID_LEN)
        .map(str::to_string)
}

/// The `responseJson` of an assertion (`PublicKeyCredential.toJSON()` shape).
pub(crate) fn assertion_response_json(response: &SignAssertionResponse) -> String {
    let user_handle = if response.user_handle_b64u.is_empty() {
        Value::Null
    } else {
        Value::String(response.user_handle_b64u.clone())
    };
    json!({
        "id": response.credential_id_b64u,
        "rawId": response.credential_id_b64u,
        "type": "public-key",
        "authenticatorAttachment": "cross-platform",
        "clientExtensionResults": {},
        "response": {
            "clientDataJSON": response.client_data_json_b64u,
            "authenticatorData": response.authenticator_data_b64u,
            "signature": response.signature_b64u,
            "userHandle": user_handle,
        },
    })
    .to_string()
}

/// The `responseJson` of a registration (`PublicKeyCredential.toJSON()` shape). `publicKey` is the
/// credential public key as SPKI DER, derived from the COSE key in the attested credential data.
pub(crate) fn attestation_response_json(
    response: &RegisterCredentialResponse,
    cred_props: bool,
) -> Result<String, &'static str> {
    let authenticator_data = b64u_decode(&response.authenticator_data_b64u)
        .map_err(|_| "authenticator data is not base64url")?;
    let cose_key = attested_cose_key(&authenticator_data)?;
    let public_key = spki_from_cose_key(&cose_key).ok_or("unsupported credential public key")?;
    let mut extension_results = Map::new();
    if cred_props {
        // Every agent credential is discoverable (`RegisterHandler` writes `discoverable: true`).
        extension_results.insert("credProps".into(), json!({ "rk": true }));
    }
    Ok(json!({
        "id": response.credential_id_b64u,
        "rawId": response.credential_id_b64u,
        "type": "public-key",
        "authenticatorAttachment": "cross-platform",
        "clientExtensionResults": extension_results,
        "response": {
            "clientDataJSON": response.client_data_json_b64u,
            "attestationObject": response.attestation_object_b64u,
            "authenticatorData": response.authenticator_data_b64u,
            "transports": ["usb"],
            "publicKeyAlgorithm": response.public_key_algorithm,
            "publicKey": b64u_encode(&public_key),
        },
    })
    .to_string())
}

/// The COSE public key of the attested credential data in `authenticator_data`.
fn attested_cose_key(authenticator_data: &[u8]) -> Result<ciborium::Value, &'static str> {
    // rpIdHash (32), flags (1), signCount (4), AAGUID (16), credentialIdLength (2).
    const ATTESTED_OFFSET: usize = 37;
    const ERROR: &str = "authenticator data has no attested credential data";
    let flags = *authenticator_data.get(32).ok_or(ERROR)?;
    if flags & 0x40 == 0 {
        return Err(ERROR);
    }
    let length_at = ATTESTED_OFFSET + 16;
    let length = authenticator_data
        .get(length_at..length_at + 2)
        .ok_or(ERROR)?;
    let id_length = u16::from_be_bytes([length[0], length[1]]) as usize;
    let key_at = length_at + 2 + id_length;
    let key_bytes = authenticator_data.get(key_at..).ok_or(ERROR)?;
    ciborium::from_reader(key_bytes).map_err(|_| "malformed COSE key")
}

/// The DER `SubjectPublicKeyInfo` of a COSE key: P-256 (EC2, crv 1) or Ed25519 (OKP, crv 6).
pub(crate) fn spki_from_cose_key(key: &ciborium::Value) -> Option<Vec<u8>> {
    // SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING (0 unused bits) }.
    const P256_PREFIX: [u8; 26] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    // SEQUENCE { SEQUENCE { id-Ed25519 }, BIT STRING (0 unused bits) }.
    const ED25519_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let map = key.as_map()?;
    let int = |label: i64| {
        map.iter().find_map(|(k, v)| {
            (k.as_integer() == Some(label.into()))
                .then(|| v.as_integer())
                .flatten()
                .map(i128::from)
        })
    };
    let bytes = |label: i64| {
        map.iter().find_map(|(k, v)| {
            (k.as_integer() == Some(label.into()))
                .then(|| v.as_bytes())
                .flatten()
        })
    };
    match (int(1)?, int(-1)?) {
        (2, 1) => {
            let (x, y) = (bytes(-2)?, bytes(-3)?);
            if x.len() != 32 || y.len() != 32 {
                return None;
            }
            let mut spki = P256_PREFIX.to_vec();
            spki.push(0x04);
            spki.extend_from_slice(x);
            spki.extend_from_slice(y);
            Some(spki)
        }
        (1, 6) => {
            let x = bytes(-2)?;
            if x.len() != 32 {
                return None;
            }
            let mut spki = ED25519_PREFIX.to_vec();
            spki.extend_from_slice(x);
            Some(spki)
        }
        _ => None,
    }
}
