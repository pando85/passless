use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use log::debug;
use sha2::{Digest, Sha256};

use passless_core::agent::protocol::{
    ErrorCode, IntentAction, ProtocolError, RecommendedAction, RegisterCredentialRequest,
    RegisterCredentialResponse,
};
use passless_core::agent::{ProfileId, RuleAction, RuleIdentity};
use passless_core::config::SecurityConfig;

use super::audit::AuditGate;
use super::audit_events::{AuditAction, PolicyAllowBuilder, PolicyDenyBuilder, PolicyDenyReason};
use super::policy_engine::PolicyRuntime;
use super::sign::{b64u_decode, b64u_encode, verify_origin_context};

use crate::storage::CredentialStorage;

use soft_fido2::CredentialKeyProvider;

const PASSLESS_AAGUID: [u8; 16] = [
    0x66, 0x69, 0x64, 0x6F, 0x2E, 0x70, 0x61, 0x73, 0x73, 0x6C, 0x65, 0x73, 0x73, 0x2E, 0x72, 0x73,
];

#[derive(Clone)]
pub struct RegisterContext {
    pub profile_id: ProfileId,
    /// Operation budget, copied from the profile at session creation (TODO(P5): frozen until the
    /// revocation epoch lands; authorization itself resolves live through `PolicyRuntime`).
    pub max_operations: u16,
    /// Set by the registry when the bearer is revoked (browser exit, lease revocation). An in-flight
    /// request re-checks it before key use and before the credential is written (ADR 0014 section 9).
    revoked: Arc<AtomicBool>,
}

impl RegisterContext {
    pub fn new(profile_id: ProfileId, max_operations: u16) -> Self {
        Self {
            profile_id,
            max_operations,
            revoked: Arc::new(AtomicBool::new(false)),
        }
    }

    /// A copy with its own revocation flag, so one bearer's revocation never reaches another's.
    pub fn with_fresh_revocation(mut self) -> Self {
        self.revoked = Arc::new(AtomicBool::new(false));
        self
    }

    /// Mark the bearer this context belongs to as revoked.
    pub fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
    }

    fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }
}

pub struct RegisterHandler {
    pub policy_runtime: Arc<PolicyRuntime>,
    pub credential_storage: Arc<Mutex<Box<dyn CredentialStorage>>>,
    pub audit_gate: Arc<AuditGate>,
    pub key_provider: Arc<dyn CredentialKeyProvider + Send + Sync>,
    pub security_config: SecurityConfig,
    pub operation_lock: Arc<Mutex<()>>,
}

impl RegisterHandler {
    fn record_policy_deny(&self, ctx: &RegisterContext, rp_id: &str, reason: PolicyDenyReason) {
        let deny_event =
            PolicyDenyBuilder::new(ctx.profile_id.clone(), AuditAction::Register, rp_id, reason)
                .build();
        let _ = self.audit_gate.record(deny_event);
    }

    /// Refuse and audit a registration made with a bearer that was revoked (browser exit or lease
    /// revocation). The request never reaches policy or key generation.
    /// Audit a registration that lost its bearer mid-flight and build the 401 returned for it.
    fn revoked_mid_flight(&self, ctx: &RegisterContext, rp_id: &str) -> ProtocolError {
        self.record_policy_deny(ctx, rp_id, PolicyDenyReason::BearerRevoked);
        ProtocolError::new(
            ErrorCode::Unauthorized,
            "registration bearer was revoked",
            RecommendedAction::Abort,
        )
    }

    pub fn refuse_revoked_bearer(&self, ctx: &RegisterContext, body: &[u8]) {
        // The body is untrusted: only a syntactically valid RP ID is recorded.
        let rp_id = serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|value| value.get("rp_id")?.as_str().map(normalize_rp_id))
            .filter(|rp| passless_core::agent::config::validate_rp_id(rp).is_ok())
            .unwrap_or_else(|| "unknown".to_string());
        self.record_policy_deny(ctx, &rp_id, PolicyDenyReason::BearerRevoked);
    }

    pub fn register(
        &self,
        ctx: &RegisterContext,
        req: &RegisterCredentialRequest,
    ) -> Result<RegisterCredentialResponse, ProtocolError> {
        let normalized_rp = normalize_rp_id(&req.rp_id);

        if !verify_origin_context(
            &req.origin,
            req.top_origin.as_deref(),
            req.cross_origin,
            &normalized_rp,
        ) {
            let (reason, message) = if req.cross_origin {
                (
                    PolicyDenyReason::CrossOriginDenied,
                    "cross-origin frames are not permitted",
                )
            } else {
                (PolicyDenyReason::OriginInvalid, "origin not valid for RP")
            };
            self.record_policy_deny(ctx, &normalized_rp, reason);
            return Err(ProtocolError::new(
                ErrorCode::Forbidden,
                message,
                RecommendedAction::FixRequest,
            ));
        }

        let _op_lock = self.operation_lock.lock().map_err(|_| {
            ProtocolError::new(
                ErrorCode::Internal,
                "operation lock poisoned",
                RecommendedAction::Abort,
            )
        })?;

        if ctx.is_revoked() {
            return Err(self.revoked_mid_flight(ctx, &normalized_rp));
        }

        // Registration authority is policy only (ADR 0014 section 10.3): an exact RP rule with
        // `register = "allow"`, resolved against the live policy on every request (plan R16). There
        // is no operator-minted enrollment grant. A wildcard rule never permits registration
        // (section 6.3): `resolve` never matches the wildcard for `register`.
        // TODO(P5): also compare the revocation epoch here and again immediately before key use.
        let matched =
            self.policy_runtime
                .resolve(&ctx.profile_id, &IntentAction::Register, &normalized_rp);
        match matched.action {
            RuleAction::Deny => {
                self.record_policy_deny(ctx, &normalized_rp, PolicyDenyReason::ActionNotAllowed);
                return Err(ProtocolError::new(
                    ErrorCode::Forbidden,
                    if matched.rule == RuleIdentity::None {
                        "RP policy does not allow registration"
                    } else {
                        "RP policy denies registration"
                    },
                    RecommendedAction::FixRequest,
                ));
            }
            // `request` acts as `deny` until the escalation service lands (P7); see sign.rs.
            RuleAction::Request => {
                self.record_policy_deny(
                    ctx,
                    &normalized_rp,
                    PolicyDenyReason::EscalationUnavailable,
                );
                return Err(ProtocolError::new(
                    ErrorCode::Forbidden,
                    "escalation is unavailable: policy requires approval",
                    RecommendedAction::FixRequest,
                ));
            }
            RuleAction::Allow => {}
        }

        let user_id = b64u_decode(&req.user_id_b64u).map_err(|_| {
            ProtocolError::new(
                ErrorCode::BadRequest,
                "invalid user_id_b64u encoding",
                RecommendedAction::FixRequest,
            )
        })?;

        let mut storage = self.credential_storage.lock().map_err(|_| {
            ProtocolError::new(
                ErrorCode::Internal,
                "storage lock poisoned",
                RecommendedAction::Abort,
            )
        })?;

        for excluded_b64u in &req.exclude_credentials {
            if let Ok(excluded_id) = b64u_decode(excluded_b64u)
                && storage.read(&excluded_id).is_ok()
            {
                let deny_event = PolicyDenyBuilder::new(
                    ctx.profile_id.clone(),
                    AuditAction::Register,
                    &normalized_rp,
                    PolicyDenyReason::CredentialNotMatch,
                )
                .build();
                let _ = self.audit_gate.record(deny_event);
                return Err(ProtocolError::new(
                    ErrorCode::Conflict,
                    "credential matches exclude list",
                    RecommendedAction::FixRequest,
                ));
            }
        }

        let algorithm = req
            .pub_key_cred_params
            .iter()
            .copied()
            .find(|algorithm| self.key_provider.supports_algorithm(*algorithm))
            .ok_or_else(|| {
                self.record_policy_deny(
                    ctx,
                    &normalized_rp,
                    PolicyDenyReason::AlgorithmUnsupported,
                );
                ProtocolError::new(
                    ErrorCode::BadRequest,
                    "no requested public-key algorithm is supported by this backend",
                    RecommendedAction::FixRequest,
                )
            })?;

        let allow_event = PolicyAllowBuilder::new(
            ctx.profile_id.clone(),
            AuditAction::Register,
            &normalized_rp,
        )
        .evidence_sources("allow", "agent", "agent")
        .build();
        self.audit_gate.record(allow_event).map_err(|_| {
            ProtocolError::new(
                ErrorCode::Internal,
                "audit record failed",
                RecommendedAction::Retry,
            )
        })?;

        if ctx.is_revoked() {
            return Err(self.revoked_mid_flight(ctx, &normalized_rp));
        }

        let generated = self.key_provider.generate(algorithm).map_err(|_| {
            ProtocolError::new(
                ErrorCode::Internal,
                "key generation failed",
                RecommendedAction::Retry,
            )
        })?;

        let credential_id = generate_credential_id();

        // `GeneratedCredentialKey::cose_public_key` is the provider's raw public key (SEC1 point or
        // Ed25519 bytes), not a COSE_Key; encode it before it goes into the attested credential data.
        let cose_key = cose_key_from_raw_public_key(algorithm, &generated.cose_public_key)
            .map_err(|_| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    "key provider returned an unusable public key",
                    RecommendedAction::Abort,
                )
            })?;

        let authenticator_data = build_authenticator_data_for_registration(
            &normalized_rp,
            &credential_id,
            &cose_key,
            // `allow` is the only agent evidence: UP and UV come from the validated agent session
            // (ADR 0014 section 7).
            true,
            true,
        );

        let client_data_json = build_client_data_json_for_registration(
            &req.origin,
            &req.challenge_b64u,
            req.cross_origin,
            req.top_origin.as_deref(),
        );

        let attestation_object = build_attestation_object(&authenticator_data);

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let credential = soft_fido2::Credential {
            id: credential_id.clone(),
            rp: soft_fido2_ctap::types::RelyingParty {
                id: normalized_rp.clone(),
                name: req.rp_name.clone(),
            },
            user: soft_fido2_ctap::types::User {
                id: user_id,
                name: Some(req.user_name.clone()),
                display_name: req.user_display_name.clone(),
            },
            sign_count: 0,
            alg: algorithm,
            key: generated.key,
            created: now_ms,
            discoverable: true,
            backup_state: if self.security_config.enable_credential_backup {
                soft_fido2::CredentialBackupState::Eligible
            } else {
                soft_fido2::CredentialBackupState::NotEligible
            },
            extensions: soft_fido2::Extensions::default(),
        };

        let cred_ref = soft_fido2::CredentialRef {
            id: &credential.id,
            rp_id: &credential.rp.id,
            rp_name: credential.rp.name.as_deref(),
            user_id: &credential.user.id,
            user_name: credential.user.name.as_deref(),
            user_display_name: credential.user.display_name.as_deref(),
            sign_count: &credential.sign_count,
            alg: &credential.alg,
            key: &credential.key,
            created: &credential.created,
            discoverable: &credential.discoverable,
            cred_protect: credential.extensions.cred_protect.as_ref(),
            cred_random: None,
            backup_state: &credential.backup_state,
        };

        if ctx.is_revoked() {
            return Err(self.revoked_mid_flight(ctx, &normalized_rp));
        }

        storage.write(cred_ref).map_err(|_| {
            ProtocolError::new(
                ErrorCode::Internal,
                "failed to write credential to storage",
                RecommendedAction::Retry,
            )
        })?;

        debug!(
            "registered credential for rp={} profile={}",
            normalized_rp, ctx.profile_id
        );

        Ok(RegisterCredentialResponse {
            credential_id_b64u: b64u_encode(&credential_id),
            public_key_algorithm: algorithm,
            authenticator_data_b64u: b64u_encode(&authenticator_data),
            attestation_object_b64u: b64u_encode(&attestation_object),
            client_data_json_b64u: b64u_encode(&client_data_json),
        })
    }
}

fn normalize_rp_id(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

fn generate_credential_id() -> Vec<u8> {
    let mut id = vec![0u8; 32];
    let mut rng = std::fs::File::open("/dev/urandom").expect("open urandom");
    std::io::Read::read_exact(&mut rng, &mut id).expect("read urandom");
    id
}

/// Encode a provider public key as a COSE_Key (RFC 9052 section 7) in CTAP2 canonical form.
///
/// - ES256 (-7): `{1: 2, 3: -7, -1: 1, -2: x, -3: y}` from an uncompressed SEC1 point.
/// - EdDSA (-8) and Ed25519 (-19): `{1: 1, 3: alg, -1: 6, -2: x}` from the 32-byte public key.
///
/// Map keys are sorted by their encoded bytes (1, 3, -1, -2, -3), which is the CTAP2 canonical order.
fn cose_key_from_raw_public_key(algorithm: i32, raw: &[u8]) -> Result<Vec<u8>, &'static str> {
    use ciborium::Value;

    let int = |n: i64| Value::Integer(n.into());
    let entries = match algorithm {
        -7 => {
            if raw.len() != 65 || raw[0] != 0x04 {
                return Err("expected an uncompressed P-256 point");
            }
            vec![
                (int(1), int(2)),
                (int(3), int(-7)),
                (int(-1), int(1)),
                (int(-2), Value::Bytes(raw[1..33].to_vec())),
                (int(-3), Value::Bytes(raw[33..65].to_vec())),
            ]
        }
        -8 | -19 => {
            if raw.len() != 32 {
                return Err("expected a 32-byte Ed25519 public key");
            }
            vec![
                (int(1), int(1)),
                (int(3), int(i64::from(algorithm))),
                (int(-1), int(6)),
                (int(-2), Value::Bytes(raw.to_vec())),
            ]
        }
        _ => return Err("unsupported COSE algorithm"),
    };

    let mut out = Vec::with_capacity(80);
    ciborium::into_writer(&Value::Map(entries), &mut out).map_err(|_| "CBOR encoding failed")?;
    Ok(out)
}

fn build_authenticator_data_for_registration(
    rp_id: &str,
    credential_id: &[u8],
    cose_public_key: &[u8],
    up: bool,
    uv: bool,
) -> Vec<u8> {
    let mut auth_data = Vec::with_capacity(37 + credential_id.len() + cose_public_key.len());

    let rp_id_hash = Sha256::digest(rp_id.as_bytes());
    auth_data.extend_from_slice(&rp_id_hash);

    let mut flags = 0x40;
    if up {
        flags |= 0x01;
    }
    if uv {
        flags |= 0x04;
    }
    auth_data.push(flags);

    auth_data.extend_from_slice(&0u32.to_be_bytes());

    auth_data.extend_from_slice(&PASSLESS_AAGUID);

    auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(credential_id);

    auth_data.extend_from_slice(cose_public_key);

    auth_data
}

fn build_client_data_json_for_registration(
    origin: &str,
    challenge_b64u: &str,
    cross_origin: bool,
    top_origin: Option<&str>,
) -> Vec<u8> {
    let mut cdj = String::with_capacity(128);
    cdj.push_str("{\"type\":\"webauthn.create\",\"challenge\":\"");
    cdj.push_str(challenge_b64u);
    cdj.push_str("\",\"origin\":\"");
    cdj.push_str(&json_escape_string(origin));
    cdj.push('"');
    if cross_origin {
        cdj.push_str(",\"crossOrigin\":true");
        if let Some(top_origin) = top_origin {
            cdj.push_str(",\"topOrigin\":\"");
            cdj.push_str(&json_escape_string(top_origin));
            cdj.push('"');
        }
    }
    cdj.push('}');
    cdj.into_bytes()
}

fn json_escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < '\x20' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

fn build_attestation_object(auth_data: &[u8]) -> Vec<u8> {
    let attestation_map = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("fmt".to_string()),
            ciborium::Value::Text("none".to_string()),
        ),
        (
            ciborium::Value::Text("attStmt".to_string()),
            ciborium::Value::Map(vec![]),
        ),
        (
            ciborium::Value::Text("authData".to_string()),
            ciborium::Value::Bytes(auth_data.to_vec()),
        ),
    ]);

    let mut buf = Vec::new();
    ciborium::into_writer(&attestation_map, &mut buf).expect("CBOR encoding of attestation object");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::agent::audit::{AuditGate, test_support::read_audit_events};
    use crate::agent::browser::SystemClock;
    use crate::agent::intent::SystemClock as MonotonicSystemClock;
    use crate::storage::CredentialStorage;
    use passless_core::agent::config::ANY_RP_ID as WILDCARD_RP_ID;
    use passless_core::agent::{
        AgentConfig, AgentMode, AgentProfileConfig, AgentRpRule, BrowserScope, CredentialSelection,
    };
    use passless_core::config::SecurityConfig;
    use soft_fido2::{CredentialBackupState, RelyingParty, SoftwareCredentialKeyProvider, User};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    pub struct WriteCountingStorage {
        creds: Mutex<Vec<soft_fido2::Credential>>,
        write_count: AtomicU64,
    }
    impl WriteCountingStorage {
        pub fn new() -> Self {
            Self {
                creds: Mutex::new(Vec::new()),
                write_count: AtomicU64::new(0),
            }
        }
        #[allow(dead_code)]
        fn writes(&self) -> u64 {
            self.write_count.load(Ordering::Acquire)
        }
        #[allow(dead_code)]
        pub fn add_cred(&self, cred: soft_fido2::Credential) {
            self.creds.lock().unwrap().push(cred);
        }
    }
    impl CredentialStorage for WriteCountingStorage {
        fn read_first(
            &mut self,
            filter: crate::storage::CredentialFilter,
        ) -> soft_fido2::Result<soft_fido2::Credential> {
            let creds = self.creds.lock().unwrap();
            match filter {
                crate::storage::CredentialFilter::ByRp(rp_id) => creds
                    .iter()
                    .find(|c| c.rp.id == rp_id)
                    .cloned()
                    .ok_or(soft_fido2::Error::Other),
                crate::storage::CredentialFilter::None => {
                    creds.first().cloned().ok_or(soft_fido2::Error::Other)
                }
                crate::storage::CredentialFilter::ById(id) => creds
                    .iter()
                    .find(|c| c.id == id)
                    .cloned()
                    .ok_or(soft_fido2::Error::Other),
                crate::storage::CredentialFilter::ByHash(_) => Err(soft_fido2::Error::Other),
            }
        }
        fn read_next(&mut self) -> soft_fido2::Result<soft_fido2::Credential> {
            Err(soft_fido2::Error::Other)
        }
        fn read(&mut self, id: &[u8]) -> soft_fido2::Result<soft_fido2::Credential> {
            self.creds
                .lock()
                .unwrap()
                .iter()
                .find(|c| c.id == id)
                .cloned()
                .ok_or(soft_fido2::Error::Other)
        }
        fn write(&mut self, cred: soft_fido2::CredentialRef) -> soft_fido2::Result<()> {
            self.write_count.fetch_add(1, Ordering::AcqRel);
            let owned = cred.to_owned();
            let mut creds = self.creds.lock().unwrap();
            if let Some(existing) = creds.iter_mut().find(|c| c.id == owned.id) {
                *existing = owned;
            } else {
                creds.push(owned);
            }
            Ok(())
        }
        fn delete(&mut self, id: &[u8]) -> soft_fido2::Result<()> {
            self.creds.lock().unwrap().retain(|c| c.id != id);
            Ok(())
        }
        fn count_credentials(&self) -> usize {
            self.creds.lock().unwrap().len()
        }
    }

    fn make_test_security_config() -> SecurityConfig {
        SecurityConfig {
            check_mlock: false,
            disable_core_dumps: false,
            constant_signature_counter: false,
            enable_credential_backup: false,
            always_uv: false,
            user_verification_registration: false,
            user_verification_authentication: false,
            notification_timeout: 0,
        }
    }

    fn register_rule(rp_id: &str, register: RuleAction) -> AgentRpRule {
        AgentRpRule {
            rp_id: rp_id.to_string(),
            register,
            authenticate: RuleAction::Deny,
            credential_selection: None,
        }
    }

    fn profile_with_rules(rules: Vec<AgentRpRule>) -> AgentProfileConfig {
        AgentProfileConfig {
            max_operations: 64,
            max_concurrent_sessions: 1,
            browser_scope: BrowserScope::Session,
            credential_selection: CredentialSelection::Single,
            mode: AgentMode::Isolated,
            principal_user: String::new(),
            credential_refs: Some(vec![]),
            max_grant_ttl: None,
            max_session_ttl: None,
            storage: None,
            rules,
            legacy: Default::default(),
            device: None,
            start_url: None,
            browser_command: None,
            browser_user: None,
            browser_runtime_root: None,
            browser_cdp_expose: None,
            browser_cdp_port: None,
        }
    }

    fn make_registration_profile_config() -> AgentProfileConfig {
        profile_with_rules(vec![register_rule("example.com", RuleAction::Allow)])
    }

    struct RegisterTestFixture {
        profile_id: ProfileId,
        storage: Arc<Mutex<Box<dyn CredentialStorage>>>,
        key_provider: Arc<SoftwareCredentialKeyProvider>,
        audit_gate: Arc<AuditGate>,
        audit_dir: std::path::PathBuf,
        operation_lock: Arc<Mutex<()>>,
        security_config: SecurityConfig,
        policy_runtime: Arc<PolicyRuntime>,
        _tmp: tempfile::TempDir,
    }

    impl RegisterTestFixture {
        fn new() -> Self {
            make_fixture_with_config(make_registration_profile_config())
        }

        fn make_handler(&self) -> RegisterHandler {
            RegisterHandler {
                policy_runtime: self.policy_runtime.clone(),
                credential_storage: self.storage.clone(),
                audit_gate: self.audit_gate.clone(),
                key_provider: self.key_provider.clone(),
                security_config: self.security_config.clone(),
                operation_lock: self.operation_lock.clone(),
            }
        }

        fn make_ctx(&self) -> RegisterContext {
            RegisterContext::new(self.profile_id.clone(), 64)
        }

        /// Replace the live policy (the session context is NOT rebuilt).
        fn reload_profile(&self, profile_config: AgentProfileConfig) {
            self.policy_runtime
                .reload(&agent_config_for(&self.profile_id, profile_config))
                .unwrap();
        }

        fn make_req(&self) -> RegisterCredentialRequest {
            RegisterCredentialRequest {
                origin: "https://example.com".to_string(),
                top_origin: None,
                rp_id: "example.com".to_string(),
                challenge_b64u: "dGVzdA".to_string(),
                user_id_b64u: "dXNlcg".to_string(),
                user_name: "testuser".to_string(),
                user_display_name: Some("Test User".to_string()),
                rp_name: Some("Example".to_string()),
                exclude_credentials: vec![],
                pub_key_cred_params: vec![-7],
                user_verification: false,
                cross_origin: false,
            }
        }

        fn policy_events(&self) -> Vec<serde_json::Value> {
            read_audit_events(&self.audit_dir)
                .into_iter()
                .filter(|e| {
                    e.get("kind")
                        .and_then(|k| k.as_str())
                        .is_some_and(|k| k == "policy.allow" || k == "policy.deny")
                })
                .collect()
        }
    }

    fn make_deny_profile_config() -> AgentProfileConfig {
        profile_with_rules(vec![AgentRpRule {
            rp_id: "example.com".to_string(),
            register: RuleAction::Deny,
            authenticate: RuleAction::Allow,
            credential_selection: None,
        }])
    }

    fn agent_config_for(profile_id: &ProfileId, profile_config: AgentProfileConfig) -> AgentConfig {
        let mut profiles = BTreeMap::new();
        profiles.insert(profile_id.as_str().to_string(), profile_config);
        AgentConfig {
            enabled: true,
            profiles,
            audit_path: Some(std::path::PathBuf::from("/tmp/test-audit")),
            acknowledge_global_same_user: vec![profile_id.as_str().to_string()],
            acknowledge_same_user_registration: vec![],
        }
    }

    fn make_fixture_with_config(profile_config: AgentProfileConfig) -> RegisterTestFixture {
        let tmp = tempfile::tempdir().unwrap();
        let audit_dir = tmp.path().join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::set_permissions(
            &audit_dir,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let audit_gate = Arc::new(AuditGate::open(&audit_dir).unwrap());
        let profile_id = ProfileId::new("test-register-profile").unwrap();
        let policy_runtime = Arc::new(
            PolicyRuntime::new(
                &agent_config_for(&profile_id, profile_config),
                Arc::new(SystemClock),
                Arc::new(MonotonicSystemClock::new()),
                None,
            )
            .unwrap(),
        );

        RegisterTestFixture {
            profile_id,
            storage: Arc::new(Mutex::new(
                Box::new(WriteCountingStorage::new()) as Box<dyn CredentialStorage>
            )),
            key_provider: Arc::new(SoftwareCredentialKeyProvider),
            audit_gate,
            audit_dir,
            operation_lock: Arc::new(Mutex::new(())),
            security_config: make_test_security_config(),
            policy_runtime,
            _tmp: tmp,
        }
    }

    #[test]
    fn test_build_authenticator_data_for_registration_structure() {
        let rp_id = "example.com";
        let cred_id = vec![0xAA; 32];
        let cose_key = vec![0xBB; 20];

        let auth_data =
            build_authenticator_data_for_registration(rp_id, &cred_id, &cose_key, true, false);

        assert_eq!(auth_data[32], 0x41);
        assert_eq!(&auth_data[33..37], &0u32.to_be_bytes());
        assert_eq!(&auth_data[37..53], &PASSLESS_AAGUID);
        let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]);
        assert_eq!(cred_id_len, 32);
        assert_eq!(&auth_data[55..87], &cred_id[..]);
        assert_eq!(&auth_data[87..], &cose_key[..]);
    }

    #[test]
    fn test_build_authenticator_data_rp_id_hash() {
        let rp_id = "example.com";
        let auth_data =
            build_authenticator_data_for_registration(rp_id, &[0; 10], &[0; 10], true, false);

        let mut hasher = Sha256::new();
        hasher.update(rp_id.as_bytes());
        let expected_hash = hasher.finalize();
        assert_eq!(&auth_data[0..32], expected_hash.as_slice());
    }

    #[test]
    fn test_build_client_data_json_for_registration_no_cross_origin() {
        let cdj =
            build_client_data_json_for_registration("https://example.com", "dGVzdA", false, None);
        let expected =
            br#"{"type":"webauthn.create","challenge":"dGVzdA","origin":"https://example.com"}"#;
        assert_eq!(cdj, expected);
    }

    #[test]
    fn test_build_client_data_json_for_registration_with_cross_origin() {
        let cdj = build_client_data_json_for_registration(
            "https://example.com",
            "dGVzdA",
            true,
            Some("https://top.example"),
        );
        let expected = br#"{"type":"webauthn.create","challenge":"dGVzdA","origin":"https://example.com","crossOrigin":true,"topOrigin":"https://top.example"}"#;
        assert_eq!(cdj, expected);
    }

    #[test]
    fn test_build_attestation_object_is_valid_cbor() {
        let auth_data = vec![0x01, 0x02, 0x03];
        let att_obj = build_attestation_object(&auth_data);

        let value: ciborium::Value = ciborium::from_reader(att_obj.as_slice()).expect("valid CBOR");

        if let ciborium::Value::Map(map) = value {
            let fmt = map
                .iter()
                .find(|(k, _)| k == &ciborium::Value::Text("fmt".to_string()))
                .map(|(_, v)| v);
            assert_eq!(fmt, Some(&ciborium::Value::Text("none".to_string())));

            let auth_data_val = map
                .iter()
                .find(|(k, _)| k == &ciborium::Value::Text("authData".to_string()))
                .map(|(_, v)| v);
            assert_eq!(auth_data_val, Some(&ciborium::Value::Bytes(auth_data)));
        } else {
            panic!("attestation object should be a CBOR map");
        }
    }

    #[test]
    fn test_generate_credential_id_length() {
        let id = generate_credential_id();
        assert_eq!(id.len(), 32);
    }

    #[test]
    fn test_generate_credential_id_unique() {
        let id1 = generate_credential_id();
        let id2 = generate_credential_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_json_escape_string_quotes() {
        let escaped = json_escape_string(r#"hello "world""#);
        assert_eq!(escaped, r#"hello \"world\""#);
    }

    #[test]
    fn test_json_escape_string_backslash() {
        let escaped = json_escape_string(r#"path\to\file"#);
        assert_eq!(escaped, r#"path\\to\\file"#);
    }

    #[test]
    fn test_json_escape_string_control_chars() {
        let escaped = json_escape_string("line1\nline2");
        assert_eq!(escaped, "line1\\nline2");
    }

    #[test]
    fn test_normalize_rp_id() {
        assert_eq!(normalize_rp_id("Example.COM"), "example.com");
        assert_eq!(normalize_rp_id("  test.com  "), "test.com");
    }

    #[test]
    fn test_register_origin_verification() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let mut req = f.make_req();
        req.origin = "https://evil.com".to_string();

        let result = handler.register(&ctx, &req);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::Forbidden);
    }

    #[test]
    fn test_register_invalid_user_id_b64u() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let mut req = f.make_req();
        req.user_id_b64u = "!!!invalid!!!".to_string();

        let result = handler.register(&ctx, &req);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::BadRequest);
    }

    #[test]
    fn test_register_exclude_list_match() {
        let f = RegisterTestFixture::new();

        let existing_cred = soft_fido2::Credential {
            id: vec![0xCC; 32],
            rp: RelyingParty::new("example.com".into()),
            user: User::new(vec![1, 2, 3]),
            sign_count: 0,
            alg: -7,
            key: f.key_provider.generate(-7).unwrap().key,
            created: 0,
            discoverable: true,
            backup_state: CredentialBackupState::NotEligible,
            extensions: soft_fido2::Extensions::default(),
        };
        {
            let mut storage = f.storage.lock().unwrap();
            let cred_ref = soft_fido2::CredentialRef {
                id: &existing_cred.id,
                rp_id: &existing_cred.rp.id,
                rp_name: existing_cred.rp.name.as_deref(),
                user_id: &existing_cred.user.id,
                user_name: existing_cred.user.name.as_deref(),
                user_display_name: existing_cred.user.display_name.as_deref(),
                sign_count: &existing_cred.sign_count,
                alg: &existing_cred.alg,
                key: &existing_cred.key,
                created: &existing_cred.created,
                discoverable: &existing_cred.discoverable,
                cred_protect: existing_cred.extensions.cred_protect.as_ref(),
                cred_random: None,
                backup_state: &existing_cred.backup_state,
            };
            storage.write(cred_ref).unwrap();
        }

        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let mut req = f.make_req();
        req.exclude_credentials = vec![b64u_encode(&existing_cred.id)];

        let result = handler.register(&ctx, &req);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::Conflict);
    }

    #[test]
    fn test_register_rejects_denied_policy() {
        let deny_config = make_deny_profile_config();
        let f = make_fixture_with_config(deny_config);
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let req = f.make_req();

        let result = handler.register(&ctx, &req);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::Forbidden);
    }

    #[test]
    fn test_register_request_rule_denies_with_escalation_unavailable_until_p7() {
        let f = make_fixture_with_config(profile_with_rules(vec![register_rule(
            "example.com",
            RuleAction::Request,
        )]));

        let err = f
            .make_handler()
            .register(&f.make_ctx(), &f.make_req())
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Forbidden);
        assert_ne!(err.code, ErrorCode::InteractionRequired);
        assert!(err.message.contains("escalation is unavailable"));
        assert_eq!(
            deny_reasons(&f),
            vec![(
                "example.com".to_string(),
                "escalation_unavailable".to_string()
            )]
        );
        assert_eq!(f.storage.lock().unwrap().count_credentials(), 0);
        assert!(
            f.policy_events()
                .iter()
                .all(|e| e["kind"] != "policy.allow"),
            "no allow event for a request rule"
        );
    }

    #[test]
    fn test_register_cross_origin_is_denied() {
        let f = RegisterTestFixture::new();
        let mut req = f.make_req();
        req.top_origin = Some("https://top.example".to_string());
        req.cross_origin = true;

        let err = f.make_handler().register(&f.make_ctx(), &req).unwrap_err();
        assert_eq!(err.code, ErrorCode::Forbidden);
    }

    #[test]
    fn test_register_generates_keypair() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let req = f.make_req();

        let result = handler.register(&ctx, &req);
        assert!(result.is_ok());
        let resp = result.unwrap();

        let auth_data = b64u_decode(&resp.authenticator_data_b64u).unwrap();
        assert!(auth_data.len() > 55);
        let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
        assert!(auth_data.len() >= 55 + cred_id_len);
    }

    #[test]
    fn test_register_writes_credential() {
        let f = RegisterTestFixture::new();
        let storage = f.storage.clone();
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let req = f.make_req();

        {
            let boxed = storage.lock().unwrap();
            let counting = unsafe {
                &*(boxed.as_ref() as *const dyn CredentialStorage as *const WriteCountingStorage)
            };
            assert_eq!(counting.writes(), 0);
        }

        let result = handler.register(&ctx, &req);
        assert!(result.is_ok());

        {
            let boxed = storage.lock().unwrap();
            let counting = unsafe {
                &*(boxed.as_ref() as *const dyn CredentialStorage as *const WriteCountingStorage)
            };
            assert_eq!(counting.writes(), 1);
            assert_eq!(counting.count_credentials(), 1);
        }
    }

    #[test]
    fn test_register_success_response_fields() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let req = f.make_req();

        let result = handler.register(&ctx, &req);
        assert!(result.is_ok());
        let resp = result.unwrap();

        assert!(!resp.credential_id_b64u.is_empty());
        assert!(!resp.authenticator_data_b64u.is_empty());
        assert!(!resp.attestation_object_b64u.is_empty());
        assert!(!resp.client_data_json_b64u.is_empty());

        let cdj = b64u_decode(&resp.client_data_json_b64u).unwrap();
        let cdj_str = std::str::from_utf8(&cdj).unwrap();
        assert!(cdj_str.contains("\"type\":\"webauthn.create\""));
        assert!(cdj_str.contains("\"challenge\":\"dGVzdA\""));
        assert!(cdj_str.contains("\"origin\":\"https://example.com\""));

        let auth_data = b64u_decode(&resp.authenticator_data_b64u).unwrap();
        assert_eq!(auth_data[32], 0x45);
        assert_eq!(&auth_data[37..53], &PASSLESS_AAGUID);

        let att_obj_bytes = b64u_decode(&resp.attestation_object_b64u).unwrap();
        let att_value: ciborium::Value =
            ciborium::from_reader(att_obj_bytes.as_slice()).expect("valid CBOR");
        if let ciborium::Value::Map(map) = att_value {
            let fmt = map
                .iter()
                .find(|(k, _)| k == &ciborium::Value::Text("fmt".to_string()))
                .map(|(_, v)| v);
            assert_eq!(fmt, Some(&ciborium::Value::Text("none".to_string())));
        } else {
            panic!("attestation object should be a CBOR map");
        }
    }

    #[test]
    fn test_register_allow_sets_up_and_uv_and_audits_agent_evidence() {
        let f = RegisterTestFixture::new();
        let mut req = f.make_req();
        // The RP's `userVerification` request does not matter: allow means UP and UV from the
        // agent session (ADR 0014 section 7).
        req.user_verification = false;
        let resp = f.make_handler().register(&f.make_ctx(), &req).unwrap();

        let auth_data = b64u_decode(&resp.authenticator_data_b64u).unwrap();
        assert_eq!(auth_data[32] & 0x05, 0x05, "UP and UV flags");
        assert_eq!(auth_data[32] & 0x40, 0x40, "AT flag");

        let events = f.policy_events();
        let allow = events.last().unwrap();
        assert_eq!(allow["kind"], "policy.allow");
        assert_eq!(allow["action"], "register");
        assert_eq!(allow["rp_id"], "example.com");
    }

    #[test]
    fn test_register_origin_spoofing_prevented() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();
        let ctx = f.make_ctx();

        let spoofed_origins = [
            "http://example.com",
            "https://example.com/path",
            "https://example.com?foo=bar",
            "https://example.com#frag",
            "https://user:pass@example.com",
            "https://notexample.com",
            "https://example.com.evil.com",
        ];

        for origin in &spoofed_origins {
            let mut req = f.make_req();
            req.origin = origin.to_string();
            let result = handler.register(&ctx, &req);
            assert!(result.is_err(), "should reject spoofed origin: {}", origin);
            assert_eq!(result.unwrap_err().code, ErrorCode::Forbidden);
        }
    }

    #[test]
    fn test_register_explicit_https_port_allowed() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let mut req = f.make_req();
        req.origin = "https://example.com:8443".to_string();

        let result = handler.register(&ctx, &req);
        assert!(result.is_ok());
    }

    #[test]
    fn test_register_concurrent_requests_serialized() {
        let f = Arc::new(RegisterTestFixture::new());
        let handler = Arc::new(f.make_handler());
        let mut handles = Vec::new();

        for _ in 0..4 {
            let h = handler.clone();
            let ctx = f.make_ctx();
            let req = f.make_req();
            handles.push(std::thread::spawn(move || h.register(&ctx, &req)));
        }

        let mut success_count = 0;
        for h in handles {
            if h.join().unwrap().is_ok() {
                success_count += 1;
            }
        }
        assert_eq!(success_count, 4);

        let boxed = f.storage.lock().unwrap();
        let counting = unsafe {
            &*(boxed.as_ref() as *const dyn CredentialStorage as *const WriteCountingStorage)
        };
        assert_eq!(counting.writes(), 4);
    }

    #[test]
    fn test_register_exclude_list_nonexistent_credential_passes() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let mut req = f.make_req();
        req.exclude_credentials = vec![b64u_encode(&[0xFF; 32])];

        let result = handler.register(&ctx, &req);
        assert!(result.is_ok());
    }

    // --- B3: the attested credential data carries a real COSE_Key ---

    /// Split registration `authenticatorData` into (credential id, COSE_Key bytes), checking that
    /// nothing is left over after the COSE_Key (the "Leftover bytes" failure a real RP reports).
    fn parse_attested_credential_data(auth_data: &[u8]) -> (Vec<u8>, ciborium::Value) {
        assert!(
            auth_data.len() > 55,
            "too short for attested credential data"
        );
        assert_eq!(auth_data[32] & 0x40, 0x40, "AT flag must be set");
        assert_eq!(&auth_data[37..53], &PASSLESS_AAGUID);
        let id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
        let id = auth_data[55..55 + id_len].to_vec();
        let mut cose = &auth_data[55 + id_len..];
        let key: ciborium::Value =
            ciborium::from_reader(&mut cose).expect("COSE_Key is valid CBOR");
        assert!(
            cose.is_empty(),
            "leftover bytes after the COSE_Key: {}",
            cose.len()
        );
        (id, key)
    }

    fn cose_int(key: &ciborium::Value, label: i64) -> Option<i128> {
        let ciborium::Value::Map(map) = key else {
            panic!("COSE_Key must be a CBOR map");
        };
        map.iter().find_map(|(k, v)| match (k, v) {
            (ciborium::Value::Integer(k), ciborium::Value::Integer(v))
                if i128::from(*k) == i128::from(label) =>
            {
                Some(i128::from(*v))
            }
            _ => None,
        })
    }

    fn cose_bytes(key: &ciborium::Value, label: i64) -> Option<Vec<u8>> {
        let ciborium::Value::Map(map) = key else {
            panic!("COSE_Key must be a CBOR map");
        };
        map.iter().find_map(|(k, v)| match (k, v) {
            (ciborium::Value::Integer(k), ciborium::Value::Bytes(v))
                if i128::from(*k) == i128::from(label) =>
            {
                Some(v.clone())
            }
            _ => None,
        })
    }

    #[test]
    fn test_cose_key_es256_exact_encoding() {
        let mut raw = vec![0x04];
        raw.extend_from_slice(&[0x11; 32]);
        raw.extend_from_slice(&[0x22; 32]);

        let cose = cose_key_from_raw_public_key(-7, &raw).unwrap();

        // {1: 2, 3: -7, -1: 1, -2: h'11..', -3: h'22..'} in CTAP2 canonical key order.
        assert_eq!(cose.len(), 77);
        assert_eq!(
            &cose[..10],
            &[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]
        );
        assert_eq!(&cose[10..42], &[0x11; 32]);
        assert_eq!(&cose[42..45], &[0x22, 0x58, 0x20]);
        assert_eq!(&cose[45..], &[0x22; 32]);
    }

    #[test]
    fn test_cose_key_eddsa_encoding() {
        let cose = cose_key_from_raw_public_key(-19, &[0x33; 32]).unwrap();
        let key: ciborium::Value = ciborium::from_reader(cose.as_slice()).unwrap();
        assert_eq!(cose_int(&key, 1), Some(1));
        assert_eq!(cose_int(&key, 3), Some(-19));
        assert_eq!(cose_int(&key, -1), Some(6));
        assert_eq!(cose_bytes(&key, -2), Some(vec![0x33; 32]));
    }

    #[test]
    fn test_cose_key_rejects_malformed_public_keys() {
        assert!(cose_key_from_raw_public_key(-7, &[0x04; 10]).is_err());
        let mut compressed = vec![0x02];
        compressed.extend_from_slice(&[0u8; 64]);
        assert!(cose_key_from_raw_public_key(-7, &compressed).is_err());
        assert!(cose_key_from_raw_public_key(-19, &[0u8; 31]).is_err());
        assert!(cose_key_from_raw_public_key(-257, &[0u8; 65]).is_err());
    }

    #[test]
    fn test_register_attested_credential_data_round_trips_and_verifies() {
        let f = RegisterTestFixture::new();
        let resp = f
            .make_handler()
            .register(&f.make_ctx(), &f.make_req())
            .unwrap();

        let auth_data = b64u_decode(&resp.authenticator_data_b64u).unwrap();
        let (credential_id, key) = parse_attested_credential_data(&auth_data);
        assert_eq!(b64u_encode(&credential_id), resp.credential_id_b64u);

        // EC2 / ES256 / P-256 with 32-byte coordinates.
        assert_eq!(cose_int(&key, 1), Some(2), "kty");
        assert_eq!(cose_int(&key, 3), Some(-7), "alg");
        assert_eq!(cose_int(&key, -1), Some(1), "crv");
        let x = cose_bytes(&key, -2).expect("x");
        let y = cose_bytes(&key, -3).expect("y");
        assert_eq!((x.len(), y.len()), (32, 32));

        // The decoded COSE key verifies a signature made with the stored credential key.
        let stored = f.storage.lock().unwrap().read(&credential_id).unwrap();
        let message = b"authenticatorData || clientDataHash";
        let signature = f.key_provider.sign(&stored.key, -7, message).unwrap();
        let mut sec1 = vec![0x04];
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        soft_fido2_crypto::ecdsa::verify(&sec1, message, &signature)
            .expect("signature verifies with the public key decoded from authenticatorData");
        assert!(soft_fido2_crypto::ecdsa::verify(&sec1, b"other message", &signature).is_err());
    }

    // --- registration authority is policy only (ADR 0014 section 10.3) ---

    fn deny_reasons(f: &RegisterTestFixture) -> Vec<(String, String)> {
        f.policy_events()
            .iter()
            .filter(|e| e["kind"] == "policy.deny")
            .map(|e| {
                (
                    e["rp_id"].as_str().unwrap_or_default().to_string(),
                    e["reason"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn test_register_allow_needs_no_enrollment_grant() {
        let f = RegisterTestFixture::new();
        f.make_handler()
            .register(&f.make_ctx(), &f.make_req())
            .expect("register = allow is sufficient");
        let events = f.policy_events();
        assert_eq!(events.last().unwrap()["kind"], "policy.allow");
        assert_eq!(events.last().unwrap()["action"], "register");
    }

    #[test]
    fn test_register_unlisted_rp_is_denied_and_audited() {
        let f = RegisterTestFixture::new();
        let mut req = f.make_req();
        req.rp_id = "other.com".to_string();
        req.origin = "https://other.com".to_string();

        let err = f.make_handler().register(&f.make_ctx(), &req).unwrap_err();
        assert_eq!(err.code, ErrorCode::Forbidden);
        assert_eq!(
            deny_reasons(&f),
            vec![("other.com".to_string(), "action_not_allowed".to_string())]
        );
    }

    #[test]
    fn test_register_deny_rule_is_audited() {
        let f = make_fixture_with_config(make_deny_profile_config());
        let err = f
            .make_handler()
            .register(&f.make_ctx(), &f.make_req())
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Forbidden);
        assert_eq!(
            deny_reasons(&f),
            vec![("example.com".to_string(), "action_not_allowed".to_string())]
        );
    }

    fn wildcard_register_config(register: RuleAction) -> AgentProfileConfig {
        let mut config = profile_with_rules(vec![register_rule(WILDCARD_RP_ID, register)]);
        config.mode = AgentMode::SameUser;
        config
    }

    #[test]
    fn test_register_under_wildcard_is_always_denied() {
        // `register = "deny"` is the only configuration the wildcard allows (section 6.3) ...
        // ... but resolution also never lets a wildcard rule that says `allow` or `request`
        // grant registration, so a validation bug elsewhere can never turn the wildcard into
        // registration authority.
        for register in [RuleAction::Deny, RuleAction::Allow, RuleAction::Request] {
            let f = make_fixture_with_config(wildcard_register_config(register));
            let err = f
                .make_handler()
                .register(&f.make_ctx(), &f.make_req())
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::Forbidden, "{register}");
            assert_eq!(
                deny_reasons(&f),
                vec![("example.com".to_string(), "action_not_allowed".to_string())],
                "{register}"
            );
            let boxed = f.storage.lock().unwrap();
            assert_eq!(boxed.count_credentials(), 0, "no credential may be written");
        }
    }

    #[test]
    fn test_exact_rule_wins_over_wildcard_for_registration() {
        let mut config = wildcard_register_config(RuleAction::Deny);
        config
            .rules
            .insert(0, register_rule("example.com", RuleAction::Allow));
        let f = make_fixture_with_config(config);
        f.make_handler()
            .register(&f.make_ctx(), &f.make_req())
            .expect("exact allow rule is used");
    }

    #[test]
    fn test_register_resolution_is_live_reload_to_deny() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();
        let ctx = f.make_ctx();

        handler
            .register(&ctx, &f.make_req())
            .expect("allowed before reload");
        assert_eq!(f.storage.lock().unwrap().count_credentials(), 1);

        // Reload without rebuilding the handler or the session context.
        f.reload_profile(make_deny_profile_config());
        let err = handler.register(&ctx, &f.make_req()).unwrap_err();
        assert_eq!(err.code, ErrorCode::Forbidden);
        assert_eq!(
            deny_reasons(&f),
            vec![("example.com".to_string(), "action_not_allowed".to_string())]
        );
        assert_eq!(
            f.storage.lock().unwrap().count_credentials(),
            1,
            "nothing written after the reload"
        );
    }

    #[test]
    fn test_register_resolution_is_live_reload_to_request_and_back() {
        let f = make_fixture_with_config(make_deny_profile_config());
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        assert!(handler.register(&ctx, &f.make_req()).is_err());

        // The reverse direction: a deny profile becomes allow without touching the context.
        f.reload_profile(make_registration_profile_config());
        handler
            .register(&ctx, &f.make_req())
            .expect("allowed after reload");

        f.reload_profile(profile_with_rules(vec![register_rule(
            "example.com",
            RuleAction::Request,
        )]));
        let err = handler.register(&ctx, &f.make_req()).unwrap_err();
        assert!(err.message.contains("escalation is unavailable"));
        let reasons = deny_reasons(&f);
        assert_eq!(
            reasons.last().unwrap(),
            &(
                "example.com".to_string(),
                "escalation_unavailable".to_string()
            )
        );
    }

    #[test]
    fn test_refuse_revoked_bearer_records_bearer_revoked() {
        let f = RegisterTestFixture::new();
        let body = serde_json::to_vec(&serde_json::json!({
            "origin": "https://example.com",
            "rp_id": "Example.com",
            "challenge_b64u": "dGVzdA",
            "user_id_b64u": "dXNlcg",
            "user_name": "testuser",
            "pub_key_cred_params": [-7],
        }))
        .unwrap();

        f.make_handler().refuse_revoked_bearer(&f.make_ctx(), &body);
        f.make_handler()
            .refuse_revoked_bearer(&f.make_ctx(), b"not json");

        assert_eq!(
            deny_reasons(&f),
            vec![
                ("example.com".to_string(), "bearer_revoked".to_string()),
                ("unknown".to_string(), "bearer_revoked".to_string()),
            ]
        );
        assert_eq!(f.storage.lock().unwrap().count_credentials(), 0);
    }

    // --- revocation while a request is in flight (ADR 0014 section 9) ---

    /// Counts `generate` calls and can revoke the bearer while the key is being generated, which is
    /// the window between the registry lookup and the credential write.
    struct InterferingKeyProvider {
        inner: SoftwareCredentialKeyProvider,
        generated: std::sync::atomic::AtomicUsize,
        revoke_during_generate: Option<RegisterContext>,
    }

    impl soft_fido2::CredentialKeyProvider for InterferingKeyProvider {
        fn provider_id(&self) -> soft_fido2::CredentialKeyProviderId {
            self.inner.provider_id()
        }
        fn supports_algorithm(&self, algorithm: i32) -> bool {
            self.inner.supports_algorithm(algorithm)
        }
        fn generate(
            &self,
            algorithm: i32,
        ) -> Result<soft_fido2::GeneratedCredentialKey, soft_fido2::CredentialKeyError> {
            self.generated.fetch_add(1, Ordering::AcqRel);
            if let Some(ctx) = &self.revoke_during_generate {
                ctx.revoke();
            }
            self.inner.generate(algorithm)
        }
        fn sign(
            &self,
            key: &soft_fido2::CredentialKey,
            algorithm: i32,
            data: &[u8],
        ) -> Result<Vec<u8>, soft_fido2::CredentialKeyError> {
            self.inner.sign(key, algorithm, data)
        }
    }

    fn handler_with_provider(
        f: &RegisterTestFixture,
        provider: Arc<InterferingKeyProvider>,
    ) -> RegisterHandler {
        RegisterHandler {
            key_provider: provider,
            ..f.make_handler()
        }
    }

    #[test]
    fn test_revoked_before_key_use_generates_nothing() {
        let f = RegisterTestFixture::new();
        let ctx = f.make_ctx();
        ctx.revoke();
        let provider = Arc::new(InterferingKeyProvider {
            inner: SoftwareCredentialKeyProvider,
            generated: std::sync::atomic::AtomicUsize::new(0),
            revoke_during_generate: None,
        });

        let err = handler_with_provider(&f, provider.clone())
            .register(&ctx, &f.make_req())
            .unwrap_err();

        assert_eq!(err.code, ErrorCode::Unauthorized);
        assert_eq!(provider.generated.load(Ordering::Acquire), 0, "no key use");
        assert_eq!(f.storage.lock().unwrap().count_credentials(), 0);
        assert_eq!(
            deny_reasons(&f),
            vec![("example.com".to_string(), "bearer_revoked".to_string())]
        );
    }

    #[test]
    fn test_revoked_between_claim_and_write_writes_no_credential() {
        let f = RegisterTestFixture::new();
        let ctx = f.make_ctx();
        let provider = Arc::new(InterferingKeyProvider {
            inner: SoftwareCredentialKeyProvider,
            generated: std::sync::atomic::AtomicUsize::new(0),
            revoke_during_generate: Some(ctx.clone()),
        });

        let err = handler_with_provider(&f, provider.clone())
            .register(&ctx, &f.make_req())
            .unwrap_err();

        assert_eq!(err.code, ErrorCode::Unauthorized);
        assert_eq!(provider.generated.load(Ordering::Acquire), 1);
        let boxed = f.storage.lock().unwrap();
        assert_eq!(
            boxed.count_credentials(),
            0,
            "the credential must not be written"
        );
        drop(boxed);
        // Audited once, as a revocation.
        assert_eq!(
            deny_reasons(&f),
            vec![("example.com".to_string(), "bearer_revoked".to_string())]
        );
    }

    #[test]
    fn test_unsupported_algorithm_is_a_deny_not_an_allow() {
        let f = RegisterTestFixture::new();
        let mut req = f.make_req();
        req.pub_key_cred_params = vec![-257];

        let err = f.make_handler().register(&f.make_ctx(), &req).unwrap_err();

        assert_eq!(err.code, ErrorCode::BadRequest);
        assert_eq!(
            deny_reasons(&f),
            vec![(
                "example.com".to_string(),
                "algorithm_unsupported".to_string()
            )]
        );
        assert!(
            f.policy_events()
                .iter()
                .all(|e| e["kind"] != "policy.allow"),
            "no allow without a credential"
        );
    }

    #[test]
    fn test_register_user_verification_request_is_irrelevant_under_allow() {
        // The RP's `userVerification` request and `always_uv` no longer matter: `allow` carries UV
        // from the agent session.
        let f = RegisterTestFixture::new();
        for rp_wants_uv in [false, true] {
            let mut req = f.make_req();
            req.user_verification = rp_wants_uv;
            let resp = f.make_handler().register(&f.make_ctx(), &req).unwrap();
            let auth_data = b64u_decode(&resp.authenticator_data_b64u).unwrap();
            assert_eq!(auth_data[32] & 0x05, 0x05);
        }
    }

    #[test]
    fn test_cose_key_eddsa_byte_order_and_signature_verify() {
        let provider = SoftwareCredentialKeyProvider;
        let generated = provider.generate(-19).unwrap();
        assert_eq!(generated.cose_public_key.len(), 32);

        let cose = cose_key_from_raw_public_key(-19, &generated.cose_public_key).unwrap();

        // {1: 1, 3: -19, -1: 6, -2: h'..'} in CTAP2 canonical key order.
        assert_eq!(cose.len(), 1 + 2 + 2 + 2 + 35);
        assert_eq!(
            &cose[..9],
            &[0xa4, 0x01, 0x01, 0x03, 0x32, 0x20, 0x06, 0x21, 0x58]
        );
        assert_eq!(cose[9], 0x20);

        let mut rest = cose.as_slice();
        let key: ciborium::Value = ciborium::from_reader(&mut rest).unwrap();
        assert!(rest.is_empty(), "leftover bytes after the COSE_Key");
        assert_eq!(cose_int(&key, 1), Some(1));
        assert_eq!(cose_int(&key, 3), Some(-19));
        assert_eq!(cose_int(&key, -1), Some(6));
        let x = cose_bytes(&key, -2).expect("x");

        let message = b"authenticatorData || clientDataHash";
        let signature = provider.sign(&generated.key, -19, message).unwrap();
        soft_fido2_crypto::eddsa::verify(&x, message, &signature)
            .expect("signature verifies with the public key decoded from the COSE_Key");
        assert!(soft_fido2_crypto::eddsa::verify(&x, b"other message", &signature).is_err());
    }
}
