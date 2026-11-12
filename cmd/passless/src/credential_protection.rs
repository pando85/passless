//! Passless vendor command `0x45`: change the stored `credProtect` level of credentials.
//!
//! `credProtect` is fixed when a credential is created. A credential created while user
//! verification ran (always the case with `security.always_uv = true`) is stored with level 3
//! and then needs user verification for every use. This command lets the human change the
//! stored level of their own credentials afterwards, in either direction.
//!
//! # Wire format
//!
//! The command is a vendor CTAP command, sent as CTAPHID_CBOR with the command byte
//! [`CMD_PASSLESS_SET_CRED_PROTECT`] followed by one CBOR map. It is not part of
//! authenticatorGetInfo, and standard credential management (`0x0A`, `0x41`) is unchanged.
//!
//! Request map:
//!
//! | Key | Type | Meaning |
//! |---|---|---|
//! | 1 | unsigned | subcommand, [`SET_CRED_PROTECT_SUBCOMMAND`] (`0x01`) |
//! | 2 | array of byte strings | credential IDs, 1 to [`MAX_CREDENTIALS_PER_REQUEST`], no duplicates |
//! | 3 | unsigned | new level, 1 to 3 |
//! | 4 | unsigned | pinUvAuthProtocol (1 or 2) |
//! | 5 | byte string | pinUvAuthParam = authenticate(pinUvAuthToken, [`set_cred_protect_auth_data`]) |
//!
//! Response: status byte `0x00` followed by a map `{1: [[credentialId, previousLevel, level], ...]}`
//! with one entry per requested credential, in request order. A credential that already has the
//! requested level is reported with `previousLevel == level` and is not rewritten.
//!
//! # Authorization
//!
//! Keys 4 and 5 are mandatory. The pinUvAuthToken must be a live token that carries the `cm`
//! (credential management) permission and is not bound to an RP: a PIN token when a PIN is set,
//! otherwise the token issued after the authenticator's built-in user verification (the desktop
//! notification). That is the same token standard credential management needs, and soft-fido2
//! also always requires a `pinUvAuthParam` there; only the `passless client` helpers for
//! `list`, `delete` and `rename` may send a request without one. This command has no such
//! fallback. The signed data binds the new level and the exact set of credential IDs, so a
//! captured parameter authorizes nothing else.
//!
//! # Consent to lower protection
//!
//! With a PIN set, typing it is the consent: no UV token can be minted then. Without a PIN the
//! token comes from one click on a generic "User Verification Required / Credential Management"
//! prompt that says nothing about what it buys. So when the request would lower any credential
//! (stored level above the requested one) and no PIN is set, the daemon asks a dedicated
//! question built only from its own storage ("Lower credential protection: N credential(s) for
//! <rp>: 3 -> 1 (presence only)") after reading the credentials and before any write. A denial,
//! timeout or prompt error refuses with no change (`OperationDenied` / `Other`). With
//! `PASSLESS_INTERACTION_MODE=automatic` the prompt layer would approve everything, so lowering
//! without a PIN is refused outright (`NotAllowed`). Raising and unchanged levels need no extra
//! prompt.
//!
//! The command exists only on the human CTAP path (`AuthenticatorService::handle`). Agent
//! sessions and the sign-proxy never reach it.
//!
//! # Atomicity
//!
//! Every credential is read before any is written. A missing credential fails the whole request
//! unchanged. A write failure rolls back the credentials already rewritten, best effort: the
//! rollback itself can fail, and on `pass` the Git commit of the operation may already exist.
//! After any error, check the result with `passless client list`.

use crate::authenticator::credential_ref;
use crate::storage::CredentialStorage;
use crate::util::bytes_to_hex;

use soft_fido2::{Credential, Error as SoftFido2Error, StatusCode};
use soft_fido2_ctap::cbor::{MapBuilder, MapParser};

use std::collections::HashSet;

use log::{info, warn};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};

/// Vendor command byte (`0x42` UV retry reset, `0x43` backup, `0x44` restore).
pub const CMD_PASSLESS_SET_CRED_PROTECT: u8 = 0x45;
/// The only subcommand: set the level of the listed credentials.
pub const SET_CRED_PROTECT_SUBCOMMAND: u8 = 0x01;
/// credProtect `userVerificationOptional`.
pub const MIN_CRED_PROTECT_LEVEL: u8 = 1;
/// credProtect `userVerificationRequired`.
pub const MAX_CRED_PROTECT_LEVEL: u8 = 3;
/// Largest batch (the authenticator stores at most 100 resident credentials).
pub const MAX_CREDENTIALS_PER_REQUEST: usize = 100;
/// Largest credential ID accepted (`CredentialRef` documents 64 bytes).
pub const MAX_CREDENTIAL_ID_LENGTH: usize = 64;

const AUTH_DOMAIN: &[u8] = b"passless-set-cred-protect-auth-v1";

/// One credential in the response of a successful request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredProtectChange {
    pub credential_id: Vec<u8>,
    /// Level before the request (a credential without a stored level counts as 1).
    pub previous: u8,
    /// Level after the request.
    pub current: u8,
}

/// A parsed, structurally valid request. Authorization is checked separately.
#[derive(Debug)]
pub struct SetCredProtectRequest {
    pub credential_ids: Vec<Vec<u8>>,
    pub level: u8,
    /// `(pinUvAuthProtocol, pinUvAuthParam)`; `None` when either is missing.
    pub auth: Option<(u8, Vec<u8>)>,
}

/// Human-readable name of a credProtect level.
pub fn level_name(level: u8) -> &'static str {
    match level {
        1 => "userVerificationOptional",
        2 => "userVerificationOptionalWithCredentialIDList",
        3 => "userVerificationRequired",
        _ => "unknown",
    }
}

/// Level a stored value stands for (no stored level means no constraint, level 1).
pub fn effective_level(stored: Option<u8>) -> u8 {
    stored.unwrap_or(MIN_CRED_PROTECT_LEVEL)
}

/// Reject any level outside 1..=3.
pub fn validate_level(level: u8) -> Result<u8, StatusCode> {
    if (MIN_CRED_PROTECT_LEVEL..=MAX_CRED_PROTECT_LEVEL).contains(&level) {
        Ok(level)
    } else {
        Err(StatusCode::InvalidParameter)
    }
}

/// Bytes the client authenticates with the pinUvAuthToken (a SHA-256 digest, like the backup
/// commands): domain, command, subcommand, then length-prefixed level, ID count and each ID.
pub fn set_cred_protect_auth_data(level: u8, credential_ids: &[Vec<u8>]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(AUTH_DOMAIN);
    hasher.update([CMD_PASSLESS_SET_CRED_PROTECT, SET_CRED_PROTECT_SUBCOMMAND]);
    let mut field = |bytes: &[u8]| {
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    };
    field(&[level]);
    field(&(credential_ids.len() as u32).to_be_bytes());
    for id in credential_ids {
        field(id);
    }
    hasher.finalize().into()
}

/// Encode a request (client side).
pub fn encode_request(
    level: u8,
    credential_ids: &[Vec<u8>],
    pin_uv_auth_protocol: u8,
    pin_uv_auth_param: &[u8],
) -> Result<Vec<u8>, StatusCode> {
    let ids: Vec<ByteBuf> = credential_ids
        .iter()
        .map(|id| ByteBuf::from(id.clone()))
        .collect();
    MapBuilder::new()
        .insert(1, SET_CRED_PROTECT_SUBCOMMAND)
        .and_then(|builder| builder.insert(2, ids))
        .and_then(|builder| builder.insert(3, level))
        .and_then(|builder| builder.insert(4, pin_uv_auth_protocol))
        .and_then(|builder| builder.insert_bytes(5, pin_uv_auth_param))
        .and_then(|builder| builder.build())
}

/// Parse and structurally validate a request (daemon side). Does not check authorization.
pub fn parse_request(payload: &[u8]) -> Result<SetCredProtectRequest, StatusCode> {
    let parser = MapParser::from_bytes(payload)?;

    let subcommand: u8 = parser.get(1)?;
    if subcommand != SET_CRED_PROTECT_SUBCOMMAND {
        return Err(StatusCode::InvalidSubcommand);
    }

    let ids: Vec<ByteBuf> = parser.get(2)?;
    if ids.is_empty() || ids.len() > MAX_CREDENTIALS_PER_REQUEST {
        return Err(StatusCode::InvalidParameter);
    }
    let mut seen = HashSet::new();
    let mut credential_ids = Vec::with_capacity(ids.len());
    for id in ids {
        let id = id.into_vec();
        if id.is_empty() || id.len() > MAX_CREDENTIAL_ID_LENGTH || !seen.insert(id.clone()) {
            return Err(StatusCode::InvalidParameter);
        }
        credential_ids.push(id);
    }

    let level: u8 = parser.get(3).map_err(|_| StatusCode::InvalidParameter)?;
    let level = validate_level(level)?;

    let auth = match (parser.get_opt::<u8>(4), parser.get_bytes(5)) {
        (Ok(Some(protocol)), Ok(param)) => Some((protocol, param)),
        _ => None,
    };

    Ok(SetCredProtectRequest {
        credential_ids,
        level,
        auth,
    })
}

/// Encode the response body (daemon side), without the status byte.
pub fn encode_response(changes: &[CredProtectChange]) -> Result<Vec<u8>, StatusCode> {
    let entries: Vec<(ByteBuf, u8, u8)> = changes
        .iter()
        .map(|change| {
            (
                ByteBuf::from(change.credential_id.clone()),
                change.previous,
                change.current,
            )
        })
        .collect();
    MapBuilder::new()
        .insert(1, entries)
        .and_then(|builder| builder.build())
}

/// Parse the response body (client side), without the status byte.
pub fn parse_response(body: &[u8]) -> Result<Vec<CredProtectChange>, StatusCode> {
    let parser = MapParser::from_bytes(body)?;
    let entries: Vec<(ByteBuf, u8, u8)> = parser.get(1)?;
    Ok(entries
        .into_iter()
        .map(|(id, previous, current)| CredProtectChange {
            credential_id: id.into_vec(),
            previous,
            current,
        })
        .collect())
}

/// A credential the request would touch, as stored right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedChange {
    pub credential_id: Vec<u8>,
    /// RP ID from storage (daemon-derived, never from the request).
    pub rp_id: String,
    /// Level before the request (no stored level counts as 1).
    pub previous: u8,
}

/// Read the credentials a request names, without writing anything.
pub fn plan<S: CredentialStorage + ?Sized>(
    storage: &mut S,
    credential_ids: &[Vec<u8>],
) -> Result<Vec<PlannedChange>, StatusCode> {
    let mut planned = Vec::with_capacity(credential_ids.len());
    for id in credential_ids {
        match storage.read(id) {
            Ok(credential) => planned.push(PlannedChange {
                credential_id: credential.id.clone(),
                rp_id: credential.rp.id.clone(),
                previous: effective_level(credential.extensions.cred_protect),
            }),
            Err(SoftFido2Error::DoesNotExist) => return Err(StatusCode::NoCredentials),
            Err(error) => {
                warn!(
                    "Cannot read credential {} for credProtect change: {:?}",
                    bytes_to_hex(id),
                    error
                );
                return Err(StatusCode::Other);
            }
        }
    }
    Ok(planned)
}

/// Keep what is shown to the user plain: RP IDs come from relying parties, so anything outside a
/// conservative set (control characters, markup) is replaced and the length is capped.
pub fn display_rp_id(rp_id: &str) -> String {
    const MAX_CHARS: usize = 64;
    let mut shown: String = rp_id
        .chars()
        .take(MAX_CHARS)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_' | '/' | '@' | '+') {
                c
            } else {
                '?'
            }
        })
        .collect();
    if rp_id.chars().count() > MAX_CHARS {
        shown.push_str("...");
    }
    shown
}

fn level_effect(level: u8) -> &'static str {
    match level {
        1 => "presence only",
        2 => "verification only when the site gives no credential list",
        _ => "verification required",
    }
}

/// `(summary, body)` of the consent prompt for the credentials that would be lowered, built only
/// from storage and the validated level. `None` when nothing is lowered.
pub fn lowering_prompt(planned: &[PlannedChange], level: u8) -> Option<(String, String)> {
    use std::collections::BTreeMap;

    let mut groups: BTreeMap<(String, u8), usize> = BTreeMap::new();
    for change in planned.iter().filter(|change| change.previous > level) {
        *groups
            .entry((display_rp_id(&change.rp_id), change.previous))
            .or_default() += 1;
    }
    if groups.is_empty() {
        return None;
    }
    let total: usize = groups.values().sum();

    const MAX_LINES: usize = 6;
    let mut lines = vec![format!(
        "Lower credential protection: {total} credential(s)"
    )];
    for ((rp, previous), count) in groups.iter().take(MAX_LINES) {
        lines.push(format!(
            "{count} for {rp}: {previous} \u{2192} {level} ({})",
            level_effect(level)
        ));
    }
    if groups.len() > MAX_LINES {
        lines.push(format!(
            "... and {} more group(s)",
            groups.len() - MAX_LINES
        ));
    }
    lines.push("Accept only if you just ran `passless client set-cred-protect`.".to_string());
    Some((
        "\u{1f513} Lower Credential Protection".to_string(),
        lines.join("\n"),
    ))
}

/// Set the level of every listed credential, rewriting only the `credProtect` field.
///
/// The caller has already authorized the request. The rewrite goes through
/// [`CredentialStorage::write`], so every backend persists it its usual way (local atomic file
/// replace, `pass` re-encryption plus the Git commit of the surrounding operation, TPM reseal)
/// and invalidates its own cache entry.
pub fn apply<S: CredentialStorage + ?Sized>(
    storage: &mut S,
    credential_ids: &[Vec<u8>],
    level: u8,
) -> Result<Vec<CredProtectChange>, StatusCode> {
    let level = validate_level(level)?;

    let mut originals = Vec::with_capacity(credential_ids.len());
    for id in credential_ids {
        match storage.read(id) {
            Ok(credential) => originals.push(credential),
            Err(SoftFido2Error::DoesNotExist) => return Err(StatusCode::NoCredentials),
            Err(error) => {
                warn!(
                    "Cannot read credential {} for credProtect change: {:?}",
                    bytes_to_hex(id),
                    error
                );
                return Err(StatusCode::Other);
            }
        }
    }

    let mut changes = Vec::with_capacity(originals.len());
    let mut rewritten: Vec<&Credential> = Vec::new();
    for original in &originals {
        let previous = effective_level(original.extensions.cred_protect);
        if original.extensions.cred_protect != Some(level) {
            let mut updated = original.clone();
            updated.extensions.cred_protect = Some(level);
            if let Err(error) = storage.write(credential_ref(&updated)) {
                warn!(
                    "Cannot write credential {} for credProtect change: {:?}; rolling back {} credential(s)",
                    bytes_to_hex(&original.id),
                    error,
                    rewritten.len()
                );
                for done in rewritten {
                    if let Err(error) = storage.write(credential_ref(done)) {
                        warn!(
                            "Rollback of credential {} failed: {:?}",
                            bytes_to_hex(&done.id),
                            error
                        );
                    }
                }
                return Err(StatusCode::Other);
            }
            rewritten.push(original);
            info!(
                "Changed credProtect of credential {} (RP {}): {} -> {} ({})",
                bytes_to_hex(&original.id),
                original.rp.id,
                previous,
                level,
                level_name(level)
            );
        } else {
            info!(
                "credProtect of credential {} (RP {}) is already {}; not rewritten",
                bytes_to_hex(&original.id),
                original.rp.id,
                level
            );
        }
        changes.push(CredProtectChange {
            credential_id: original.id.clone(),
            previous,
            current: level,
        });
    }
    Ok(changes)
}

/// Credential fixtures shared with the authenticator tests.
#[cfg(test)]
pub(crate) mod test_support {
    use soft_fido2::{Credential, CredentialBackupState};
    use soft_fido2_ctap::{CredentialKey, SecBytes};

    /// A credential whose fields all differ per `id`, so a lost field shows in a comparison.
    pub fn test_credential(id: u8, rp_id: &str, cred_protect: Option<u8>) -> Credential {
        let mut credential = Credential {
            id: vec![id; 32],
            rp: soft_fido2::RelyingParty {
                id: rp_id.to_string(),
                name: Some("Test RP".to_string()),
            },
            user: soft_fido2::User {
                id: vec![id, 1, 2, 3],
                name: Some(format!("user{id}@example.com")),
                display_name: Some(format!("User {id}")),
            },
            sign_count: 41 + u32::from(id),
            alg: -7,
            key: CredentialKey::software(SecBytes::from_slice(&[id; 32])),
            created: 1_700_000_000 + i64::from(id),
            discoverable: true,
            backup_state: CredentialBackupState::NotEligible,
            extensions: soft_fido2::Extensions::default(),
        };
        credential.extensions.cred_protect = cred_protect;
        credential.extensions.cred_random = Some(SecBytes::from_slice(&[id ^ 0x5a; 32]));
        credential
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::test_support::test_credential;

    use crate::storage::{CredentialFilter, LocalStorageAdapter};

    use soft_fido2::CredentialRef;

    use std::collections::HashMap;

    fn local_storage(dir: &std::path::Path) -> LocalStorageAdapter {
        LocalStorageAdapter::new(dir.to_path_buf()).expect("create local storage")
    }

    /// Storage double that records writes and can fail the n-th write.
    struct RecordingStorage {
        credentials: HashMap<Vec<u8>, Credential>,
        writes: Vec<Vec<u8>>,
        fail_on_write: Option<usize>,
    }

    impl RecordingStorage {
        fn new(credentials: Vec<Credential>) -> Self {
            Self {
                credentials: credentials.into_iter().map(|c| (c.id.clone(), c)).collect(),
                writes: Vec::new(),
                fail_on_write: None,
            }
        }
    }

    impl CredentialStorage for RecordingStorage {
        fn read_first(&mut self, _filter: CredentialFilter) -> soft_fido2::Result<Credential> {
            Err(SoftFido2Error::DoesNotExist)
        }
        fn read_next(&mut self) -> soft_fido2::Result<Credential> {
            Err(SoftFido2Error::DoesNotExist)
        }
        fn read(&mut self, id: &[u8]) -> soft_fido2::Result<Credential> {
            self.credentials
                .get(id)
                .cloned()
                .ok_or(SoftFido2Error::DoesNotExist)
        }
        fn write(&mut self, cred: CredentialRef) -> soft_fido2::Result<()> {
            if self.fail_on_write == Some(self.writes.len()) {
                // Fail once; the rollback writes that follow succeed.
                self.fail_on_write = None;
                return Err(SoftFido2Error::Other);
            }
            self.writes.push(cred.id.to_vec());
            let owned = cred.to_owned();
            self.credentials.insert(owned.id.clone(), owned);
            Ok(())
        }
        fn delete(&mut self, _id: &[u8]) -> soft_fido2::Result<()> {
            Ok(())
        }
        fn count_credentials(&self) -> usize {
            self.credentials.len()
        }
    }

    #[test]
    fn level_validation_accepts_one_to_three_only() {
        for level in 1..=3 {
            assert_eq!(validate_level(level), Ok(level));
        }
        for level in [0u8, 4, 5, 127, 255] {
            assert_eq!(
                validate_level(level),
                Err(StatusCode::InvalidParameter),
                "level {level}"
            );
        }
    }

    #[test]
    fn apply_rejects_an_invalid_level_without_touching_storage() {
        let mut storage = RecordingStorage::new(vec![test_credential(1, "ssh:", Some(3))]);
        for level in [0u8, 4, 255] {
            assert_eq!(
                apply(&mut storage, &[vec![1; 32]], level).unwrap_err(),
                StatusCode::InvalidParameter
            );
        }
        assert!(storage.writes.is_empty());
    }

    #[test]
    fn request_round_trips_and_carries_the_authorization() {
        let ids = vec![vec![1u8; 32], vec![2u8; 16]];
        let payload = encode_request(2, &ids, 2, &[0xaa; 32]).expect("encode");
        let parsed = parse_request(&payload).expect("parse");
        assert_eq!(parsed.credential_ids, ids);
        assert_eq!(parsed.level, 2);
        assert_eq!(parsed.auth, Some((2, vec![0xaa; 32])));
    }

    #[test]
    fn request_without_authorization_fields_parses_with_none() {
        let payload = MapBuilder::new()
            .insert(1, SET_CRED_PROTECT_SUBCOMMAND)
            .and_then(|b| b.insert(2, vec![ByteBuf::from(vec![1u8; 32])]))
            .and_then(|b| b.insert(3, 1u8))
            .and_then(|b| b.build())
            .unwrap();
        assert!(parse_request(&payload).unwrap().auth.is_none());

        // A parameter without its protocol (or the reverse) is not authorization either.
        let half = MapBuilder::new()
            .insert(1, SET_CRED_PROTECT_SUBCOMMAND)
            .and_then(|b| b.insert(2, vec![ByteBuf::from(vec![1u8; 32])]))
            .and_then(|b| b.insert(3, 1u8))
            .and_then(|b| b.insert_bytes(5, &[0u8; 32]))
            .and_then(|b| b.build())
            .unwrap();
        assert!(parse_request(&half).unwrap().auth.is_none());
    }

    #[test]
    fn request_validation_rejects_malformed_input() {
        let id = vec![ByteBuf::from(vec![1u8; 32])];
        let build = |sub: u8, ids: Vec<ByteBuf>, level: u8| {
            MapBuilder::new()
                .insert(1, sub)
                .and_then(|b| b.insert(2, ids))
                .and_then(|b| b.insert(3, level))
                .and_then(|b| b.insert(4, 2u8))
                .and_then(|b| b.insert_bytes(5, &[0u8; 32]))
                .and_then(|b| b.build())
                .unwrap()
        };

        assert!(parse_request(&build(1, id.clone(), 3)).is_ok());
        assert_eq!(
            parse_request(&build(2, id.clone(), 3)).unwrap_err(),
            StatusCode::InvalidSubcommand
        );
        for level in [0u8, 4, 255] {
            assert_eq!(
                parse_request(&build(1, id.clone(), level)).unwrap_err(),
                StatusCode::InvalidParameter,
                "level {level}"
            );
        }
        assert_eq!(
            parse_request(&build(1, vec![], 3)).unwrap_err(),
            StatusCode::InvalidParameter
        );
        assert_eq!(
            parse_request(&build(1, vec![ByteBuf::from(vec![])], 3)).unwrap_err(),
            StatusCode::InvalidParameter
        );
        assert_eq!(
            parse_request(&build(1, vec![ByteBuf::from(vec![9u8; 65])], 3)).unwrap_err(),
            StatusCode::InvalidParameter
        );
        let too_many: Vec<ByteBuf> = (0..=MAX_CREDENTIALS_PER_REQUEST)
            .map(|n| ByteBuf::from(vec![n as u8; 8]))
            .collect();
        assert_eq!(
            parse_request(&build(1, too_many, 3)).unwrap_err(),
            StatusCode::InvalidParameter
        );
        assert_eq!(
            parse_request(&build(1, vec![id[0].clone(), id[0].clone()], 3)).unwrap_err(),
            StatusCode::InvalidParameter,
            "duplicate IDs"
        );
        assert!(parse_request(&[0xff]).is_err());
    }

    #[test]
    fn response_round_trips() {
        let changes = vec![
            CredProtectChange {
                credential_id: vec![1; 32],
                previous: 3,
                current: 1,
            },
            CredProtectChange {
                credential_id: vec![2; 32],
                previous: 1,
                current: 1,
            },
        ];
        let body = encode_response(&changes).expect("encode");
        assert_eq!(parse_response(&body).expect("parse"), changes);
    }

    #[test]
    fn auth_data_binds_level_and_every_credential_id() {
        let ids = vec![vec![1u8; 32], vec![2u8; 32]];
        let base = set_cred_protect_auth_data(1, &ids);
        assert_eq!(base, set_cred_protect_auth_data(1, &ids), "deterministic");
        assert_ne!(base, set_cred_protect_auth_data(2, &ids), "level");
        assert_ne!(base, set_cred_protect_auth_data(1, &ids[..1]), "subset");
        assert_ne!(
            base,
            set_cred_protect_auth_data(1, &[ids[1].clone(), ids[0].clone()]),
            "order"
        );
        // Moving bytes between IDs must not collide.
        assert_ne!(
            set_cred_protect_auth_data(1, &[vec![1, 2], vec![3]]),
            set_cred_protect_auth_data(1, &[vec![1], vec![2, 3]])
        );
    }

    #[test]
    fn local_backend_lowers_and_raises_the_level_preserving_everything_else() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut storage = local_storage(dir.path());
        let original = test_credential(7, "ssh:", Some(3));
        storage.write(credential_ref(&original)).expect("seed");

        let changes = apply(&mut storage, std::slice::from_ref(&original.id), 1).expect("lower");
        assert_eq!(
            changes,
            vec![CredProtectChange {
                credential_id: original.id.clone(),
                previous: 3,
                current: 1
            }]
        );
        let lowered = storage.read(&original.id).expect("read");
        let mut expected = original.clone();
        expected.extensions.cred_protect = Some(1);
        // Only the credProtect field differs; the write path never stores hmac_secret.
        expected.extensions.hmac_secret = None;
        assert_eq!(lowered, expected);
        assert_eq!(lowered.sign_count, original.sign_count);
        assert_eq!(lowered.created, original.created);
        assert_eq!(lowered.user, original.user);
        assert_eq!(lowered.rp, original.rp);
        assert_eq!(lowered.key, original.key);
        assert_eq!(
            lowered.extensions.cred_random,
            original.extensions.cred_random
        );

        let changes = apply(&mut storage, std::slice::from_ref(&original.id), 3).expect("raise");
        assert_eq!((changes[0].previous, changes[0].current), (1, 3));
        assert_eq!(
            storage.read(&original.id).unwrap().extensions.cred_protect,
            Some(3)
        );
        assert_eq!(storage.count_credentials(), 1);
    }

    #[test]
    fn a_credential_without_stored_level_counts_as_level_one() {
        let mut storage = RecordingStorage::new(vec![test_credential(1, "example.com", None)]);
        let changes = apply(&mut storage, &[vec![1; 32]], 3).expect("raise");
        assert_eq!((changes[0].previous, changes[0].current), (1, 3));
        assert_eq!(storage.writes.len(), 1);

        // Setting level 1 on a credential without a stored level normalizes it.
        let mut storage = RecordingStorage::new(vec![test_credential(1, "example.com", None)]);
        let changes = apply(&mut storage, &[vec![1; 32]], 1).expect("normalize");
        assert_eq!((changes[0].previous, changes[0].current), (1, 1));
    }

    #[test]
    fn an_unchanged_level_is_not_rewritten() {
        let mut storage = RecordingStorage::new(vec![
            test_credential(1, "ssh:", Some(1)),
            test_credential(2, "ssh:", Some(3)),
        ]);
        let changes = apply(&mut storage, &[vec![1; 32], vec![2; 32]], 1).expect("apply");
        assert_eq!(storage.writes, vec![vec![2; 32]]);
        assert_eq!((changes[0].previous, changes[0].current), (1, 1));
        assert_eq!((changes[1].previous, changes[1].current), (3, 1));
    }

    #[test]
    fn only_the_listed_credentials_change() {
        let mut storage = RecordingStorage::new(vec![
            test_credential(1, "ssh:", Some(3)),
            test_credential(2, "ssh:", Some(3)),
            test_credential(3, "example.com", Some(3)),
        ]);
        apply(&mut storage, &[vec![1; 32]], 1).expect("apply");
        assert_eq!(
            storage.credentials[&vec![1u8; 32]].extensions.cred_protect,
            Some(1)
        );
        assert_eq!(
            storage.credentials[&vec![2u8; 32]].extensions.cred_protect,
            Some(3)
        );
        assert_eq!(
            storage.credentials[&vec![3u8; 32]].extensions.cred_protect,
            Some(3)
        );
    }

    #[test]
    fn a_missing_credential_fails_the_whole_request_unchanged() {
        let mut storage = RecordingStorage::new(vec![test_credential(1, "ssh:", Some(3))]);
        assert_eq!(
            apply(&mut storage, &[vec![1; 32], vec![9; 32]], 1).unwrap_err(),
            StatusCode::NoCredentials
        );
        assert!(storage.writes.is_empty());
        assert_eq!(
            storage.credentials[&vec![1u8; 32]].extensions.cred_protect,
            Some(3)
        );
    }

    #[test]
    fn a_write_failure_rolls_back_the_credentials_already_rewritten() {
        let mut storage = RecordingStorage::new(vec![
            test_credential(1, "ssh:", Some(3)),
            test_credential(2, "ssh:", Some(3)),
        ]);
        // The first write succeeds, the second fails, then the first is written back.
        storage.fail_on_write = Some(1);
        assert_eq!(
            apply(&mut storage, &[vec![1; 32], vec![2; 32]], 1).unwrap_err(),
            StatusCode::Other
        );
        assert_eq!(storage.writes, vec![vec![1; 32], vec![1; 32]]);
        assert_eq!(
            storage.credentials[&vec![1u8; 32]].extensions.cred_protect,
            Some(3)
        );
        assert_eq!(
            storage.credentials[&vec![2u8; 32]].extensions.cred_protect,
            Some(3)
        );
    }

    /// Collect `.rs` files below `dir`.
    fn rust_sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read source directory") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                rust_sources(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    /// The command is reachable only from the human CTAP path. Agent sessions and the
    /// sign-proxy never carry CTAP bytes into `AuthenticatorService::handle`, and nothing in the
    /// agent code may name the command, its handler, or its storage logic.
    #[test]
    fn the_command_is_not_reachable_from_agent_code() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut sources = Vec::new();
        rust_sources(&src, &mut sources);
        assert!(sources.len() > 20, "found the source tree");

        let allowed = [
            "authenticator.rs",
            "commands/client.rs",
            "human_prompts.rs",
            "main.rs",
            "notification.rs",
        ];
        let needles = [
            "credential_protection",
            "CMD_PASSLESS_SET_CRED_PROTECT",
            "set_cred_protect",
        ];
        for path in sources {
            let relative = path.strip_prefix(&src).expect("below src");
            let relative_str = relative.to_string_lossy();
            if relative_str == "credential_protection.rs"
                || allowed.contains(&relative_str.as_ref())
            {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read source");
            for needle in needles {
                assert!(
                    !text.contains(needle),
                    "{relative_str} mentions {needle}; the credProtect command must stay on the \
                     human CTAP path"
                );
            }
        }

        // The agent and sign-proxy code also never hands CTAP bytes to the human service.
        let mut agent_sources = Vec::new();
        rust_sources(&src.join("agent"), &mut agent_sources);
        agent_sources.push(src.join("bin").join("sign-proxy.rs"));
        for path in agent_sources {
            let text = std::fs::read_to_string(&path).expect("read agent source");
            // Test fixtures may drive the human service directly; production code must not.
            let production = text.split("#[cfg(test)]").next().unwrap_or("");
            assert!(
                !production.contains("AuthenticatorService")
                    && !production.contains("0x45")
                    && !production.contains("CMD_PASSLESS"),
                "{} reaches the human CTAP service or a vendor command",
                path.display()
            );
        }
    }

    #[test]
    fn rp_ids_are_made_plain_before_they_are_shown() {
        assert_eq!(display_rp_id("ssh:"), "ssh:");
        assert_eq!(display_rp_id("example.com"), "example.com");
        let hostile = "evil.com\n<b>Allow</b> & <a href=x>y</a>\u{202e}";
        let shown = display_rp_id(hostile);
        assert!(
            shown
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || ".-:_/@+?".contains(c)),
            "{shown}"
        );
        assert!(!shown.contains('<') && !shown.contains('\n') && !shown.contains('&'));
        let long = "a".repeat(200);
        assert!(display_rp_id(&long).len() <= 67);
    }

    #[test]
    fn lowering_prompt_is_built_from_storage_and_lists_only_lowered_credentials() {
        let planned = vec![
            PlannedChange {
                credential_id: vec![1; 32],
                rp_id: "ssh:".to_string(),
                previous: 3,
            },
            PlannedChange {
                credential_id: vec![2; 32],
                rp_id: "ssh:".to_string(),
                previous: 3,
            },
            PlannedChange {
                credential_id: vec![3; 32],
                rp_id: "example.com".to_string(),
                previous: 1,
            },
        ];
        let (summary, body) = lowering_prompt(&planned, 1).expect("lowering");
        assert!(summary.contains("Lower Credential Protection"));
        assert!(
            body.contains("Lower credential protection: 2 credential(s)"),
            "{body}"
        );
        assert!(
            body.contains("2 for ssh:: 3 \u{2192} 1 (presence only)"),
            "{body}"
        );
        assert!(
            !body.contains("example.com"),
            "unchanged credentials are not listed"
        );

        // Nothing lowered: raising to 3, or already at the level.
        assert!(lowering_prompt(&planned, 3).is_none());
        assert!(lowering_prompt(&planned[2..], 1).is_none());
    }
}
