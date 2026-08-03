use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use log::debug;
use sha2::{Digest, Sha256};

use passless_core::agent::protocol::{
    ErrorCode, ProtocolError, RecommendedAction, RegisterCredentialRequest,
    RegisterCredentialResponse,
};
use passless_core::agent::{AgentProfileConfig, ProfileId, RegistrationGrantId};
use passless_core::config::SecurityConfig;

use super::audit::AuditGate;
use super::audit_events::{AuditAction, PolicyAllowBuilder, PolicyDenyBuilder, PolicyDenyReason};
use super::policy_engine::PolicyRuntime;
use super::sign::{b64u_decode, b64u_encode, verify_origin_structural};

use crate::storage::CredentialStorage;

use soft_fido2::CredentialKeyProvider;

const COSE_ALG_ES256: i32 = -7;

const PASSLESS_AAGUID: [u8; 16] = [
    0x66, 0x69, 0x64, 0x6F, 0x2E, 0x70, 0x61, 0x73, 0x73, 0x6C, 0x65, 0x73, 0x73, 0x2E, 0x72, 0x73,
];

#[derive(Clone)]
pub struct RegisterContext {
    pub profile_id: ProfileId,
    pub registration_grant_id: RegistrationGrantId,
    pub profile_config: AgentProfileConfig,
}

pub struct RegisterHandler {
    pub human_storage: Arc<Mutex<Box<dyn CredentialStorage>>>,
    pub policy_runtime: Arc<PolicyRuntime>,
    pub audit_gate: Arc<AuditGate>,
    pub key_provider: Arc<dyn CredentialKeyProvider + Send + Sync>,
    pub security_config: SecurityConfig,
    pub operation_lock: Arc<Mutex<()>>,
}

impl RegisterHandler {
    pub fn register(
        &self,
        ctx: &RegisterContext,
        req: &RegisterCredentialRequest,
    ) -> Result<RegisterCredentialResponse, ProtocolError> {
        let normalized_rp = normalize_rp_id(&req.rp_id);

        if !verify_origin_structural(&req.origin, &normalized_rp) {
            let deny_event = PolicyDenyBuilder::new(
                ctx.profile_id.clone(),
                AuditAction::Register,
                &normalized_rp,
                PolicyDenyReason::OriginInvalid,
            )
            .build();
            let _ = self.audit_gate.record(deny_event);
            return Err(ProtocolError::new(
                ErrorCode::Forbidden,
                "origin not valid for RP",
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

        let grant_snapshot = self
            .policy_runtime
            .resolve_registration_grant(&ctx.profile_id, &ctx.registration_grant_id, &normalized_rp)
            .ok_or_else(|| {
                let deny_event = PolicyDenyBuilder::new(
                    ctx.profile_id.clone(),
                    AuditAction::Register,
                    &normalized_rp,
                    PolicyDenyReason::GrantNotFound,
                )
                .build();
                let _ = self.audit_gate.record(deny_event);
                ProtocolError::new(
                    ErrorCode::Forbidden,
                    "registration grant not valid",
                    RecommendedAction::FixRequest,
                )
            })?;

        if grant_snapshot.state != super::grant::GrantState::Active {
            let deny_event = PolicyDenyBuilder::new(
                ctx.profile_id.clone(),
                AuditAction::Register,
                &normalized_rp,
                PolicyDenyReason::GrantExpired,
            )
            .build();
            let _ = self.audit_gate.record(deny_event);
            return Err(ProtocolError::new(
                ErrorCode::Forbidden,
                "registration grant not active",
                RecommendedAction::FixRequest,
            ));
        }

        let ceremony_policy = ctx
            .profile_config
            .rule_for_rp(&normalized_rp)
            .and_then(|rule| {
                if rule.register.authorization == passless_core::agent::AgentAuthorization::Allow {
                    Some(rule.register)
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                let deny_event = PolicyDenyBuilder::new(
                    ctx.profile_id.clone(),
                    AuditAction::Register,
                    &normalized_rp,
                    PolicyDenyReason::ActionNotAllowed,
                )
                .build();
                let _ = self.audit_gate.record(deny_event);
                ProtocolError::new(
                    ErrorCode::Forbidden,
                    "RP policy does not allow registration",
                    RecommendedAction::FixRequest,
                )
            })?;

        let user_id = b64u_decode(&req.user_id_b64u).map_err(|_| {
            ProtocolError::new(
                ErrorCode::BadRequest,
                "invalid user_id_b64u encoding",
                RecommendedAction::FixRequest,
            )
        })?;

        let mut storage = self.human_storage.lock().map_err(|_| {
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

        let allow_event = PolicyAllowBuilder::new(
            ctx.profile_id.clone(),
            AuditAction::Register,
            &normalized_rp,
        )
        .evidence_sources(
            &ceremony_policy.authorization.to_string(),
            &ceremony_policy.user_presence.to_string(),
            &ceremony_policy.user_verification.to_string(),
        )
        .build();
        self.audit_gate.record(allow_event).map_err(|_| {
            ProtocolError::new(
                ErrorCode::Internal,
                "audit record failed",
                RecommendedAction::Retry,
            )
        })?;

        let generated = self.key_provider.generate(COSE_ALG_ES256).map_err(|_| {
            ProtocolError::new(
                ErrorCode::Internal,
                "key generation failed",
                RecommendedAction::Retry,
            )
        })?;

        let credential_id = generate_credential_id();

        let authenticator_data = build_authenticator_data_for_registration(
            &normalized_rp,
            &credential_id,
            &generated.cose_public_key,
        );

        let client_data_json = build_client_data_json_for_registration(
            &req.origin,
            &req.challenge_b64u,
            req.cross_origin,
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
            alg: COSE_ALG_ES256,
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

fn build_authenticator_data_for_registration(
    rp_id: &str,
    credential_id: &[u8],
    cose_public_key: &[u8],
) -> Vec<u8> {
    let mut auth_data = Vec::with_capacity(37 + credential_id.len() + cose_public_key.len());

    let rp_id_hash = Sha256::digest(rp_id.as_bytes());
    auth_data.extend_from_slice(&rp_id_hash);

    auth_data.push(0x41);

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
) -> Vec<u8> {
    let mut cdj = String::with_capacity(128);
    cdj.push_str("{\"type\":\"webauthn.create\",\"challenge\":\"");
    cdj.push_str(challenge_b64u);
    cdj.push_str("\",\"origin\":\"");
    cdj.push_str(&json_escape_string(origin));
    cdj.push('"');
    if cross_origin {
        cdj.push_str(",\"crossOrigin\":true");
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

    use crate::agent::audit::AuditGate;
    use crate::agent::browser;
    use crate::agent::intent;
    use crate::agent::policy_engine::PolicyRuntime;
    use crate::storage::CredentialStorage;
    use passless_core::agent::{
        AgentAuthorization, AgentCeremonyPolicy, AgentConfig, AgentMode, AgentProfileConfig,
        AgentRpRule, DeviceIdentity, UserPresenceSource, UserVerificationSource,
    };
    use passless_core::config::SecurityConfig;
    use soft_fido2::{CredentialBackupState, RelyingParty, SoftwareCredentialKeyProvider, User};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    pub struct MockClock {
        inner: Mutex<MockClockInner>,
    }
    struct MockClockInner {
        base: Instant,
        offset: Duration,
    }
    impl MockClock {
        pub fn new() -> Self {
            Self {
                inner: Mutex::new(MockClockInner {
                    base: Instant::now(),
                    offset: Duration::ZERO,
                }),
            }
        }
        #[allow(dead_code)]
        pub fn advance(&self, d: Duration) {
            self.inner.lock().unwrap().offset += d;
        }
    }
    impl browser::Clock for MockClock {
        fn now(&self) -> Instant {
            let inner = self.inner.lock().unwrap();
            inner.base + inner.offset
        }
        fn monotonic_secs(&self) -> u64 {
            self.inner.lock().unwrap().offset.as_secs()
        }
    }

    pub struct MockMonoClock {
        inner: Mutex<MockClockInner>,
    }
    impl MockMonoClock {
        pub fn new() -> Self {
            Self {
                inner: Mutex::new(MockClockInner {
                    base: Instant::now(),
                    offset: Duration::ZERO,
                }),
            }
        }
    }
    impl intent::MonotonicClock for MockMonoClock {
        fn now(&self) -> intent::MonotonicTime {
            let inner = self.inner.lock().unwrap();
            let elapsed = inner.offset;
            intent::MonotonicTime::from_millis(elapsed.as_millis() as u64)
        }
    }

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

    fn make_registration_profile_config() -> AgentProfileConfig {
        AgentProfileConfig {
            mode: AgentMode::Isolated,
            principal_user: String::new(),
            rp_ids: vec!["example.com".to_string()],
            require_uv: false,
            credential_refs: Some(vec![]),
            max_grant_ttl: None,
            max_session_ttl: None,
            storage: None,
            registration_allowed: true,
            rules: vec![AgentRpRule {
                rp_id: "example.com".to_string(),
                register: AgentCeremonyPolicy {
                    authorization: AgentAuthorization::Allow,
                    user_presence: UserPresenceSource::Policy,
                    user_verification: UserVerificationSource::Policy,
                },
                authenticate: AgentCeremonyPolicy::deny(),
            }],
            device: DeviceIdentity {
                name: "test-device".to_string(),
                phys: "test-phys".to_string(),
                uniq: "test-uniq".to_string(),
                vendor_id: 0x1234,
                product_id: 0x5678,
            },
            start_url: None,
            browser_command: None,
            browser_user: None,
            browser_runtime_root: None,
            browser_cdp_expose: None,
            browser_cdp_port: None,
        }
    }

    struct RegisterTestFixture {
        profile_id: ProfileId,
        registration_grant_id: RegistrationGrantId,
        clock: Arc<MockClock>,
        policy_runtime: Arc<PolicyRuntime>,
        storage: Arc<Mutex<Box<dyn CredentialStorage>>>,
        key_provider: Arc<SoftwareCredentialKeyProvider>,
        audit_gate: Arc<AuditGate>,
        operation_lock: Arc<Mutex<()>>,
        security_config: SecurityConfig,
        profile_config: AgentProfileConfig,
    }

    impl RegisterTestFixture {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let audit_path = tmp.path().to_path_buf();
            drop(tmp);
            std::fs::create_dir_all(&audit_path).unwrap();
            std::fs::set_permissions(
                &audit_path,
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            )
            .unwrap();
            let audit_gate = Arc::new(AuditGate::open(&audit_path).unwrap());

            let profile_id = ProfileId::new("test-register-profile").unwrap();

            let storage = Arc::new(Mutex::new(
                Box::new(WriteCountingStorage::new()) as Box<dyn CredentialStorage>
            ));

            let profile_config = make_registration_profile_config();

            let mut profiles = BTreeMap::new();
            profiles.insert("test-register-profile".to_string(), profile_config.clone());
            let agent_config = AgentConfig {
                enabled: true,
                profiles,
                audit_path: Some(audit_path),
            };

            let clock = Arc::new(MockClock::new());
            let mono_clock = Arc::new(MockMonoClock::new());

            let policy_runtime = Arc::new(
                PolicyRuntime::new(&agent_config, clock.clone(), mono_clock.clone()).unwrap(),
            );

            let registration_grant_id = policy_runtime
                .request_registration_grant(profile_id.clone(), "example.com".to_string())
                .unwrap();

            let key_provider = Arc::new(SoftwareCredentialKeyProvider);
            let operation_lock = Arc::new(Mutex::new(()));
            let security_config = make_test_security_config();

            Self {
                profile_id,
                registration_grant_id,
                clock,
                policy_runtime,
                storage,
                key_provider,
                audit_gate,
                operation_lock,
                security_config,
                profile_config,
            }
        }

        fn make_handler(&self) -> RegisterHandler {
            RegisterHandler {
                human_storage: self.storage.clone(),
                policy_runtime: self.policy_runtime.clone(),
                audit_gate: self.audit_gate.clone(),
                key_provider: self.key_provider.clone(),
                security_config: self.security_config.clone(),
                operation_lock: self.operation_lock.clone(),
            }
        }

        fn make_ctx(&self) -> RegisterContext {
            RegisterContext {
                profile_id: self.profile_id.clone(),
                registration_grant_id: self.registration_grant_id.clone(),
                profile_config: self.profile_config.clone(),
            }
        }

        fn make_req(&self) -> RegisterCredentialRequest {
            RegisterCredentialRequest {
                origin: "https://example.com".to_string(),
                rp_id: "example.com".to_string(),
                challenge_b64u: "dGVzdA".to_string(),
                user_id_b64u: "dXNlcg".to_string(),
                user_name: "testuser".to_string(),
                user_display_name: Some("Test User".to_string()),
                rp_name: Some("Example".to_string()),
                exclude_credentials: vec![],
                user_verification: false,
                cross_origin: false,
            }
        }
    }

    fn make_deny_profile_config() -> AgentProfileConfig {
        AgentProfileConfig {
            mode: AgentMode::Isolated,
            principal_user: String::new(),
            rp_ids: vec!["example.com".to_string()],
            require_uv: false,
            credential_refs: Some(vec![]),
            max_grant_ttl: None,
            max_session_ttl: None,
            storage: None,
            registration_allowed: true,
            rules: vec![AgentRpRule {
                rp_id: "example.com".to_string(),
                register: AgentCeremonyPolicy::deny(),
                authenticate: AgentCeremonyPolicy {
                    authorization: AgentAuthorization::Allow,
                    user_presence: UserPresenceSource::Policy,
                    user_verification: UserVerificationSource::Policy,
                },
            }],
            device: DeviceIdentity {
                name: "test-device".to_string(),
                phys: "test-phys".to_string(),
                uniq: "test-uniq".to_string(),
                vendor_id: 0x1234,
                product_id: 0x5678,
            },
            start_url: None,
            browser_command: None,
            browser_user: None,
            browser_runtime_root: None,
            browser_cdp_expose: None,
            browser_cdp_port: None,
        }
    }

    fn make_fixture_with_config(profile_config: AgentProfileConfig) -> RegisterTestFixture {
        let tmp = tempfile::tempdir().unwrap();
        let audit_path = tmp.path().to_path_buf();
        drop(tmp);
        std::fs::create_dir_all(&audit_path).unwrap();
        std::fs::set_permissions(
            &audit_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let audit_gate = Arc::new(AuditGate::open(&audit_path).unwrap());

        let profile_id = ProfileId::new("test-register-profile").unwrap();

        let storage = Arc::new(Mutex::new(
            Box::new(WriteCountingStorage::new()) as Box<dyn CredentialStorage>
        ));

        let mut profiles = BTreeMap::new();
        profiles.insert("test-register-profile".to_string(), profile_config.clone());
        let agent_config = AgentConfig {
            enabled: true,
            profiles,
            audit_path: Some(audit_path),
        };

        let clock = Arc::new(MockClock::new());
        let mono_clock = Arc::new(MockMonoClock::new());

        let policy_runtime =
            Arc::new(PolicyRuntime::new(&agent_config, clock.clone(), mono_clock.clone()).unwrap());

        let registration_grant_id = policy_runtime
            .request_registration_grant(profile_id.clone(), "example.com".to_string())
            .unwrap();

        let key_provider = Arc::new(SoftwareCredentialKeyProvider);
        let operation_lock = Arc::new(Mutex::new(()));
        let security_config = make_test_security_config();

        RegisterTestFixture {
            profile_id,
            registration_grant_id,
            clock,
            policy_runtime,
            storage,
            key_provider,
            audit_gate,
            operation_lock,
            security_config,
            profile_config,
        }
    }

    #[test]
    fn test_build_authenticator_data_for_registration_structure() {
        let rp_id = "example.com";
        let cred_id = vec![0xAA; 32];
        let cose_key = vec![0xBB; 20];

        let auth_data = build_authenticator_data_for_registration(rp_id, &cred_id, &cose_key);

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
        let auth_data = build_authenticator_data_for_registration(rp_id, &[0; 10], &[0; 10]);

        let mut hasher = Sha256::new();
        hasher.update(rp_id.as_bytes());
        let expected_hash = hasher.finalize();
        assert_eq!(&auth_data[0..32], expected_hash.as_slice());
    }

    #[test]
    fn test_build_client_data_json_for_registration_no_cross_origin() {
        let cdj = build_client_data_json_for_registration("https://example.com", "dGVzdA", false);
        let expected =
            br#"{"type":"webauthn.create","challenge":"dGVzdA","origin":"https://example.com"}"#;
        assert_eq!(cdj, expected);
    }

    #[test]
    fn test_build_client_data_json_for_registration_with_cross_origin() {
        let cdj = build_client_data_json_for_registration("https://example.com", "dGVzdA", true);
        let expected = br#"{"type":"webauthn.create","challenge":"dGVzdA","origin":"https://example.com","crossOrigin":true}"#;
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
    fn test_register_rejects_expired_grant() {
        let f = RegisterTestFixture::new();
        f.clock.advance(Duration::from_secs(301));
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let req = f.make_req();

        let result = handler.register(&ctx, &req);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::Forbidden);
    }

    #[test]
    fn test_register_rejects_invalid_grant_id() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();
        let ctx = RegisterContext {
            profile_id: f.profile_id.clone(),
            registration_grant_id: RegistrationGrantId::new(),
            profile_config: f.profile_config.clone(),
        };
        let req = f.make_req();

        let result = handler.register(&ctx, &req);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::Forbidden);
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
        assert_eq!(auth_data[32], 0x41);
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
    fn test_register_origin_spoofing_prevented() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();
        let ctx = f.make_ctx();

        let spoofed_origins = [
            "http://example.com",
            "https://example.com:8443",
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
    fn test_register_unauthorized_without_grant() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();

        let other_profile = ProfileId::new("other-profile").unwrap();
        let ctx = RegisterContext {
            profile_id: other_profile,
            registration_grant_id: f.registration_grant_id.clone(),
            profile_config: f.profile_config.clone(),
        };
        let req = f.make_req();

        let result = handler.register(&ctx, &req);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ErrorCode::Forbidden);
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
    fn test_register_rp_id_mismatch_with_grant() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let mut req = f.make_req();
        req.rp_id = "other.com".to_string();
        req.origin = "https://other.com".to_string();

        let result = handler.register(&ctx, &req);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ErrorCode::Forbidden);
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
}
