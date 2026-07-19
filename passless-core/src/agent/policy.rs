use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::config::AgentRpRule;
use super::ids::{CredentialRef, ProfileId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    InvalidVersion(u8),
    EmptyActions,
    InvalidTtl(u64),
    InvalidMaxConcurrent(u64),
    CborEncoding(String),
    InvalidHex(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::InvalidVersion(v) => write!(f, "unsupported policy version: {}", v),
            PolicyError::EmptyActions => write!(f, "allowed_actions must not be empty"),
            PolicyError::InvalidTtl(ttl) => write!(f, "invalid TTL: {}", ttl),
            PolicyError::InvalidMaxConcurrent(n) => {
                write!(f, "max_concurrent_grants must be >= 1, got {}", n)
            }
            PolicyError::CborEncoding(s) => write!(f, "CBOR encoding error: {}", s),
            PolicyError::InvalidHex(s) => write!(f, "invalid hex encoding: {}", s),
        }
    }
}

impl std::error::Error for PolicyError {}

pub const CURRENT_POLICY_VERSION: u8 = 3;
const MAX_TTL: u64 = 86400 * 365;
const MAX_CONCURRENT_GRANTS_LIMIT: u64 = 1000;

#[derive(Clone, PartialEq, Eq)]
pub struct PolicyParams {
    pub profile_id: ProfileId,
    pub mode: String,
    pub normalized_rp_ids: Vec<String>,
    pub credential_refs: Vec<CredentialRef>,
    pub allowed_actions: Vec<String>,
    pub registration_allowed: bool,
    pub require_uv: bool,
    pub max_concurrent_grants: u64,
    pub max_grant_ttl: u64,
    pub max_session_ttl: u64,
    pub principal_user: String,
    pub device_name: String,
    pub device_phys: String,
    pub device_uniq: String,
    pub device_vendor_id: u16,
    pub device_product_id: u16,
    pub start_url: Option<String>,
    pub browser_argv: Vec<String>,
    pub storage_backend: String,
    pub storage_path: String,
    pub browser_user: String,
    pub browser_runtime_root: String,
    pub rules: Vec<AgentRpRule>,
    pub delegated_registration_storage: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub version: u8,
    pub profile_id: String,
    pub mode: String,
    pub normalized_rp_ids: Vec<String>,
    pub credential_refs: Vec<String>,
    pub allowed_actions: Vec<String>,
    pub registration_allowed: bool,
    pub require_uv: bool,
    pub max_concurrent_grants: u64,
    pub max_grant_ttl: u64,
    pub max_session_ttl: u64,
    pub principal_user: String,
    pub device_name: String,
    pub device_phys: String,
    pub device_uniq: String,
    pub device_vendor_id: u16,
    pub device_product_id: u16,
    pub start_url: String,
    pub browser_argv: Vec<String>,
    pub storage_backend: String,
    pub storage_path: String,
    pub browser_user: String,
    pub browser_runtime_root: String,
    pub rules: Vec<AgentRpRule>,
    pub delegated_registration_storage: String,
}

impl Policy {
    pub fn from_params(params: PolicyParams) -> Result<Self, PolicyError> {
        let mut sorted_rp_ids = params.normalized_rp_ids;
        sorted_rp_ids.sort();
        sorted_rp_ids.dedup();

        let mut sorted_cred_refs: Vec<String> =
            params.credential_refs.iter().map(|c| c.to_hex()).collect();
        sorted_cred_refs.sort();
        sorted_cred_refs.dedup();

        let mut sorted_actions = params.allowed_actions;
        sorted_actions.sort();
        sorted_actions.dedup();

        let mut sorted_rules = params.rules;
        sorted_rules.sort_by_key(|rule| rule.rp_id.trim().to_ascii_lowercase());

        let policy = Self {
            version: CURRENT_POLICY_VERSION,
            profile_id: params.profile_id.as_str().to_string(),
            mode: params.mode,
            normalized_rp_ids: sorted_rp_ids,
            credential_refs: sorted_cred_refs,
            allowed_actions: sorted_actions,
            registration_allowed: params.registration_allowed,
            require_uv: params.require_uv,
            max_concurrent_grants: params.max_concurrent_grants,
            max_grant_ttl: params.max_grant_ttl,
            max_session_ttl: params.max_session_ttl,
            principal_user: params.principal_user,
            device_name: params.device_name,
            device_phys: params.device_phys,
            device_uniq: params.device_uniq,
            device_vendor_id: params.device_vendor_id,
            device_product_id: params.device_product_id,
            start_url: params.start_url.unwrap_or_default(),
            browser_argv: params.browser_argv,
            storage_backend: params.storage_backend,
            storage_path: params.storage_path,
            browser_user: params.browser_user,
            browser_runtime_root: params.browser_runtime_root,
            rules: sorted_rules,
            delegated_registration_storage: params.delegated_registration_storage,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn new(
        profile_id: &ProfileId,
        allowed_actions: Vec<String>,
        max_concurrent_grants: u64,
        require_uv: bool,
        max_grant_ttl: u64,
    ) -> Result<Self, PolicyError> {
        Self::from_params(PolicyParams {
            profile_id: profile_id.clone(),
            mode: "isolated".to_string(),
            normalized_rp_ids: vec![],
            credential_refs: vec![],
            allowed_actions,
            registration_allowed: false,
            require_uv,
            max_concurrent_grants,
            max_grant_ttl,
            max_session_ttl: 0,
            principal_user: String::new(),
            device_name: String::new(),
            device_phys: String::new(),
            device_uniq: String::new(),
            device_vendor_id: 0,
            device_product_id: 0,
            start_url: None,
            browser_argv: vec![],
            storage_backend: String::new(),
            storage_path: String::new(),
            browser_user: String::new(),
            browser_runtime_root: String::new(),
            rules: vec![],
            delegated_registration_storage: String::new(),
        })
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.version != CURRENT_POLICY_VERSION {
            return Err(PolicyError::InvalidVersion(self.version));
        }
        if self.allowed_actions.is_empty() {
            return Err(PolicyError::EmptyActions);
        }
        if self.max_grant_ttl == 0 || self.max_grant_ttl > MAX_TTL {
            return Err(PolicyError::InvalidTtl(self.max_grant_ttl));
        }
        if self.max_session_ttl > MAX_TTL {
            return Err(PolicyError::InvalidTtl(self.max_session_ttl));
        }
        if self.max_concurrent_grants == 0
            || self.max_concurrent_grants > MAX_CONCURRENT_GRANTS_LIMIT
        {
            return Err(PolicyError::InvalidMaxConcurrent(
                self.max_concurrent_grants,
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> PolicyDigest {
        PolicyDigest::from_policy(self)
    }

    pub fn to_deterministic_cbor(&self) -> Vec<u8> {
        cbor::encode_policy(self)
    }
}

impl fmt::Debug for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Policy")
            .field("version", &self.version)
            .field("profile_id", &self.profile_id)
            .field("mode", &self.mode)
            .field("max_concurrent_grants", &self.max_concurrent_grants)
            .field("require_uv", &self.require_uv)
            .field("max_grant_ttl", &self.max_grant_ttl)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyDigest([u8; 32]);

impl PolicyDigest {
    pub fn from_policy(policy: &Policy) -> Self {
        let cbor_bytes = policy.to_deterministic_cbor();
        let mut hasher = Sha256::new();
        hasher.update(&cbor_bytes);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    pub fn from_cbor_bytes(cbor_bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(cbor_bytes);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, PolicyError> {
        let bytes =
            hex::decode(s).map_err(|_| PolicyError::InvalidHex(format!("invalid hex: {}", s)))?;
        if bytes.len() != 32 {
            return Err(PolicyError::InvalidHex(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn verify(&self, policy: &Policy) -> bool {
        *self == Self::from_policy(policy)
    }
}

impl fmt::Display for PolicyDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for PolicyDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PolicyDigest").field(&self.to_hex()).finish()
    }
}

impl AsRef<[u8]> for PolicyDigest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub mod cbor {
    use super::Policy;

    use crate::agent::{AgentCeremonyPolicy, AgentRpRule};

    pub fn encode_uint(value: u64) -> Vec<u8> {
        encode_type_and_length(0, value)
    }

    pub fn encode_bool(value: bool) -> Vec<u8> {
        if value { vec![0xf5] } else { vec![0xf4] }
    }

    pub fn encode_text(text: &str) -> Vec<u8> {
        let bytes = text.as_bytes();
        let mut result = encode_type_and_length(3, bytes.len() as u64);
        result.extend_from_slice(bytes);
        result
    }

    pub fn encode_byte_string(data: &[u8]) -> Vec<u8> {
        let mut result = encode_type_and_length(2, data.len() as u64);
        result.extend_from_slice(data);
        result
    }

    pub fn encode_array(items: &[Vec<u8>]) -> Vec<u8> {
        let mut result = encode_type_and_length(4, items.len() as u64);
        for item in items {
            result.extend_from_slice(item);
        }
        result
    }

    pub fn encode_text_array(items: &[&str]) -> Vec<u8> {
        let encoded: Vec<Vec<u8>> = items.iter().map(|s| encode_text(s)).collect();
        encode_array(&encoded)
    }

    pub fn encode_map_sorted(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
        let mut sorted: Vec<(String, Vec<u8>)> = entries.to_vec();
        sorted.sort_by(|a, b| {
            let a_key = a.0.as_bytes();
            let b_key = b.0.as_bytes();
            a_key.len().cmp(&b_key.len()).then_with(|| a_key.cmp(b_key))
        });

        let mut result = encode_type_and_length(5, sorted.len() as u64);
        for (key, value) in &sorted {
            result.extend_from_slice(&encode_text(key));
            result.extend_from_slice(value);
        }
        result
    }

    pub fn encode_type_and_length(major_type: u8, length: u64) -> Vec<u8> {
        let mt = major_type << 5;
        if length <= 23 {
            vec![mt | length as u8]
        } else if length <= 0xff {
            vec![mt | 24, length as u8]
        } else if length <= 0xffff {
            vec![mt | 25, (length >> 8) as u8, length as u8]
        } else if length <= 0xffff_ffff {
            vec![
                mt | 26,
                (length >> 24) as u8,
                (length >> 16) as u8,
                (length >> 8) as u8,
                length as u8,
            ]
        } else {
            vec![
                mt | 27,
                (length >> 56) as u8,
                (length >> 48) as u8,
                (length >> 40) as u8,
                (length >> 32) as u8,
                (length >> 24) as u8,
                (length >> 16) as u8,
                (length >> 8) as u8,
                length as u8,
            ]
        }
    }

    pub fn encode_policy(policy: &Policy) -> Vec<u8> {
        let entries: Vec<(String, Vec<u8>)> = vec![
            ("version".to_string(), encode_uint(policy.version as u64)),
            ("profile_id".to_string(), encode_text(&policy.profile_id)),
            ("mode".to_string(), encode_text(&policy.mode)),
            (
                "normalized_rp_ids".to_string(),
                encode_text_array(
                    &policy
                        .normalized_rp_ids
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>(),
                ),
            ),
            (
                "credential_refs".to_string(),
                encode_text_array(
                    &policy
                        .credential_refs
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>(),
                ),
            ),
            (
                "allowed_actions".to_string(),
                encode_text_array(
                    &policy
                        .allowed_actions
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>(),
                ),
            ),
            (
                "registration_allowed".to_string(),
                encode_bool(policy.registration_allowed),
            ),
            ("require_uv".to_string(), encode_bool(policy.require_uv)),
            (
                "max_concurrent_grants".to_string(),
                encode_uint(policy.max_concurrent_grants),
            ),
            (
                "max_grant_ttl".to_string(),
                encode_uint(policy.max_grant_ttl),
            ),
            (
                "max_session_ttl".to_string(),
                encode_uint(policy.max_session_ttl),
            ),
            (
                "principal_user".to_string(),
                encode_text(&policy.principal_user),
            ),
            ("device_name".to_string(), encode_text(&policy.device_name)),
            ("device_phys".to_string(), encode_text(&policy.device_phys)),
            ("device_uniq".to_string(), encode_text(&policy.device_uniq)),
            (
                "device_vendor_id".to_string(),
                encode_uint(policy.device_vendor_id as u64),
            ),
            (
                "device_product_id".to_string(),
                encode_uint(policy.device_product_id as u64),
            ),
            ("start_url".to_string(), encode_text(&policy.start_url)),
            (
                "browser_argv".to_string(),
                encode_text_array(
                    &policy
                        .browser_argv
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>(),
                ),
            ),
            (
                "storage_backend".to_string(),
                encode_text(&policy.storage_backend),
            ),
            (
                "storage_path".to_string(),
                encode_text(&policy.storage_path),
            ),
            (
                "browser_user".to_string(),
                encode_text(&policy.browser_user),
            ),
            (
                "browser_runtime_root".to_string(),
                encode_text(&policy.browser_runtime_root),
            ),
            ("rules".to_string(), encode_rules(&policy.rules)),
            (
                "delegated_registration_storage".to_string(),
                encode_text(&policy.delegated_registration_storage),
            ),
        ];
        encode_map_sorted(&entries)
    }

    fn encode_ceremony_policy(policy: &AgentCeremonyPolicy) -> Vec<u8> {
        encode_map_sorted(&[
            (
                "authorization".to_string(),
                encode_text(&policy.authorization.to_string()),
            ),
            (
                "user_presence".to_string(),
                encode_text(&policy.user_presence.to_string()),
            ),
            (
                "user_verification".to_string(),
                encode_text(&policy.user_verification.to_string()),
            ),
        ])
    }

    fn encode_rules(rules: &[AgentRpRule]) -> Vec<u8> {
        let encoded = rules
            .iter()
            .map(|rule| {
                encode_map_sorted(&[
                    (
                        "rp_id".to_string(),
                        encode_text(&rule.rp_id.trim().to_ascii_lowercase()),
                    ),
                    (
                        "register".to_string(),
                        encode_ceremony_policy(&rule.register),
                    ),
                    (
                        "authenticate".to_string(),
                        encode_ceremony_policy(&rule.authenticate),
                    ),
                ])
            })
            .collect::<Vec<_>>();
        encode_array(&encoded)
    }

    pub fn encode_generation_digest(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
        let mut sorted = entries.to_vec();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));

        let items: Vec<Vec<u8>> = sorted
            .iter()
            .map(|(pid, digest)| {
                let pair = vec![encode_text(pid), encode_byte_string(digest)];
                encode_array(&pair)
            })
            .collect();
        encode_array(&items)
    }

    pub fn sorted_keys_for_policy() -> Vec<&'static str> {
        let mut keys = vec![
            "version",
            "profile_id",
            "mode",
            "normalized_rp_ids",
            "credential_refs",
            "allowed_actions",
            "registration_allowed",
            "require_uv",
            "max_concurrent_grants",
            "max_grant_ttl",
            "max_session_ttl",
            "principal_user",
            "device_name",
            "device_phys",
            "device_uniq",
            "device_vendor_id",
            "device_product_id",
            "start_url",
            "browser_argv",
            "storage_backend",
            "storage_path",
            "browser_user",
            "browser_runtime_root",
            "rules",
            "delegated_registration_storage",
        ];
        keys.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));
        keys
    }
}

#[cfg(test)]
mod tests {
    use super::cbor;
    use super::*;

    use crate::agent::{
        AgentAuthorization, AgentCeremonyPolicy, UserPresenceSource, UserVerificationSource,
    };

    fn test_profile_id() -> ProfileId {
        ProfileId::new("test-agent").unwrap()
    }

    fn test_policy() -> Policy {
        Policy::new(
            &test_profile_id(),
            vec!["make_credential".to_string(), "get_assertion".to_string()],
            3,
            true,
            300,
        )
        .unwrap()
    }

    fn minimal_policy() -> Policy {
        Policy::new(
            &ProfileId::new("a").unwrap(),
            vec!["act".to_string()],
            1,
            false,
            1,
        )
        .unwrap()
    }

    #[test]
    fn test_encode_uint_small() {
        assert_eq!(cbor::encode_uint(0), vec![0x00]);
        assert_eq!(cbor::encode_uint(1), vec![0x01]);
        assert_eq!(cbor::encode_uint(23), vec![0x17]);
    }

    #[test]
    fn test_encode_uint_one_byte() {
        assert_eq!(cbor::encode_uint(24), vec![0x18, 0x18]);
        assert_eq!(cbor::encode_uint(255), vec![0x18, 0xff]);
    }

    #[test]
    fn test_encode_uint_two_bytes() {
        assert_eq!(cbor::encode_uint(256), vec![0x19, 0x01, 0x00]);
        assert_eq!(cbor::encode_uint(300), vec![0x19, 0x01, 0x2c]);
        assert_eq!(cbor::encode_uint(0xffff), vec![0x19, 0xff, 0xff]);
    }

    #[test]
    fn test_encode_uint_four_bytes() {
        assert_eq!(
            cbor::encode_uint(0x10000),
            vec![0x1a, 0x00, 0x01, 0x00, 0x00]
        );
        assert_eq!(
            cbor::encode_uint(0xffffffff),
            vec![0x1a, 0xff, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn test_encode_uint_eight_bytes() {
        assert_eq!(
            cbor::encode_uint(0x100000000),
            vec![0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_encode_bool() {
        assert_eq!(cbor::encode_bool(true), vec![0xf5]);
        assert_eq!(cbor::encode_bool(false), vec![0xf4]);
    }

    #[test]
    fn test_encode_text_empty() {
        assert_eq!(cbor::encode_text(""), vec![0x60]);
    }

    #[test]
    fn test_encode_text_short() {
        let encoded = cbor::encode_text("a");
        assert_eq!(encoded, vec![0x61, 0x61]);
    }

    #[test]
    fn test_encode_text_medium() {
        let encoded = cbor::encode_text("test-agent");
        assert_eq!(encoded[0], 0x6a);
        assert_eq!(&encoded[1..], b"test-agent");
    }

    #[test]
    fn test_encode_text_long() {
        let text = "a".repeat(24);
        let encoded = cbor::encode_text(&text);
        assert_eq!(encoded[0], 0x78);
        assert_eq!(encoded[1], 24);
        assert_eq!(&encoded[2..], text.as_bytes());
    }

    #[test]
    fn test_encode_byte_string() {
        let data = vec![0x01, 0x02, 0x03];
        let encoded = cbor::encode_byte_string(&data);
        assert_eq!(encoded, vec![0x43, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_encode_array_empty() {
        assert_eq!(cbor::encode_array(&[]), vec![0x80]);
    }

    #[test]
    fn test_encode_array_of_uints() {
        let items = vec![cbor::encode_uint(1), cbor::encode_uint(2)];
        let encoded = cbor::encode_array(&items);
        assert_eq!(encoded, vec![0x82, 0x01, 0x02]);
    }

    #[test]
    fn test_encode_text_array() {
        let encoded = cbor::encode_text_array(&["a", "bb"]);
        assert_eq!(encoded, vec![0x82, 0x61, 0x61, 0x62, 0x62, 0x62]);
    }

    #[test]
    fn test_encode_map_sorted_order() {
        let keys = cbor::sorted_keys_for_policy();
        assert_eq!(keys[0], "mode");
        assert_eq!(keys[1], "rules");

        for i in 1..keys.len() {
            assert!(keys[i - 1].len() <= keys[i].len());
            if keys[i - 1].len() == keys[i].len() {
                assert!(keys[i - 1] <= keys[i]);
            }
        }
    }

    #[test]
    fn test_encode_map_sorted_deterministic() {
        let entries1 = vec![
            ("b".to_string(), cbor::encode_uint(2)),
            ("a".to_string(), cbor::encode_uint(1)),
        ];
        let entries2 = vec![
            ("a".to_string(), cbor::encode_uint(1)),
            ("b".to_string(), cbor::encode_uint(2)),
        ];
        let encoded1 = cbor::encode_map_sorted(&entries1);
        let encoded2 = cbor::encode_map_sorted(&entries2);
        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn test_encode_map_sorted_by_length_then_byte() {
        let entries = vec![
            ("cc".to_string(), cbor::encode_uint(3)),
            ("b".to_string(), cbor::encode_uint(2)),
            ("aa".to_string(), cbor::encode_uint(4)),
        ];
        let encoded = cbor::encode_map_sorted(&entries);
        assert_eq!(encoded[0], 0xa3);

        let expected = cbor::encode_map_sorted(&[
            ("b".to_string(), cbor::encode_uint(2)),
            ("aa".to_string(), cbor::encode_uint(4)),
            ("cc".to_string(), cbor::encode_uint(3)),
        ]);
        assert_eq!(encoded, expected);
    }

    #[test]
    fn test_policy_creation() {
        let policy = test_policy();
        assert_eq!(policy.version, CURRENT_POLICY_VERSION);
        assert_eq!(policy.profile_id, "test-agent");
        assert_eq!(policy.allowed_actions.len(), 2);
        assert_eq!(policy.max_concurrent_grants, 3);
        assert!(policy.require_uv);
        assert_eq!(policy.max_grant_ttl, 300);
    }

    #[test]
    fn test_policy_validation_empty_actions() {
        let result = Policy::new(&test_profile_id(), vec![], 3, true, 300);
        assert!(matches!(result, Err(PolicyError::EmptyActions)));
    }

    #[test]
    fn test_policy_validation_zero_ttl() {
        let result = Policy::new(&test_profile_id(), vec!["act".to_string()], 3, true, 0);
        assert!(matches!(result, Err(PolicyError::InvalidTtl(0))));
    }

    #[test]
    fn test_policy_validation_excessive_ttl() {
        let result = Policy::new(
            &test_profile_id(),
            vec!["act".to_string()],
            3,
            true,
            MAX_TTL + 1,
        );
        assert!(matches!(result, Err(PolicyError::InvalidTtl(_))));
    }

    #[test]
    fn test_policy_validation_excessive_session_ttl() {
        let mut policy = test_policy();
        policy.max_session_ttl = MAX_TTL + 1;

        assert!(matches!(policy.validate(), Err(PolicyError::InvalidTtl(_))));
    }

    #[test]
    fn test_policy_deterministic_cbor() {
        let policy = test_policy();
        let cbor1 = policy.to_deterministic_cbor();
        let cbor2 = policy.to_deterministic_cbor();
        assert_eq!(cbor1, cbor2);
    }

    #[test]
    fn test_policy_cbor_starts_with_map_header() {
        let policy = test_policy();
        let cbor = policy.to_deterministic_cbor();
        assert_eq!(cbor[0] & 0xe0, 0xa0);
        assert_eq!(cbor[0] & 0x1f, 24);
        assert_eq!(cbor[1], 25);
    }

    #[test]
    fn test_policy_digest_deterministic() {
        let policy = test_policy();
        let digest1 = policy.digest();
        let digest2 = policy.digest();
        assert_eq!(digest1, digest2);
    }

    #[test]
    fn test_policy_digest_length() {
        let policy = test_policy();
        let digest = policy.digest();
        assert_eq!(digest.as_bytes().len(), 32);
    }

    #[test]
    fn test_policy_digest_hex_length() {
        let policy = test_policy();
        let digest = policy.digest();
        assert_eq!(digest.to_hex().len(), 64);
    }

    #[test]
    fn test_policy_digest_hex_roundtrip() {
        let policy = test_policy();
        let digest = policy.digest();
        let hex = digest.to_hex();
        let parsed = PolicyDigest::from_hex(&hex).unwrap();
        assert_eq!(digest, parsed);
    }

    #[test]
    fn test_policy_digest_verify() {
        let policy = test_policy();
        let digest = policy.digest();
        assert!(digest.verify(&policy));
    }

    #[test]
    fn test_policy_digest_verify_different_policy() {
        let policy1 = test_policy();
        let mut policy2 = test_policy();
        policy2.max_concurrent_grants = 5;
        let digest1 = policy1.digest();
        assert!(!digest1.verify(&policy2));
    }

    #[test]
    fn test_different_policies_different_digests() {
        let policy1 = test_policy();
        let mut policy2 = test_policy();
        policy2.max_concurrent_grants = 5;
        assert_ne!(policy1.digest(), policy2.digest());
    }

    #[test]
    fn test_different_profile_ids_different_digests() {
        let policy1 = Policy::new(
            &ProfileId::new("agent-a").unwrap(),
            vec!["act".to_string()],
            1,
            true,
            60,
        )
        .unwrap();
        let policy2 = Policy::new(
            &ProfileId::new("agent-b").unwrap(),
            vec!["act".to_string()],
            1,
            true,
            60,
        )
        .unwrap();
        assert_ne!(policy1.digest(), policy2.digest());
    }

    #[test]
    fn test_different_actions_different_digests() {
        let policy1 = Policy::new(
            &test_profile_id(),
            vec!["make_credential".to_string()],
            1,
            true,
            60,
        )
        .unwrap();
        let policy2 = Policy::new(
            &test_profile_id(),
            vec!["get_assertion".to_string()],
            1,
            true,
            60,
        )
        .unwrap();
        assert_ne!(policy1.digest(), policy2.digest());
    }

    #[test]
    fn test_different_browser_user_different_digests() {
        let p1 = Policy::from_params(PolicyParams {
            profile_id: test_profile_id(),
            mode: "isolated".to_string(),
            normalized_rp_ids: vec![],
            credential_refs: vec![],
            allowed_actions: vec!["act".to_string()],
            registration_allowed: false,
            require_uv: true,
            max_concurrent_grants: 1,
            max_grant_ttl: 60,
            max_session_ttl: 0,
            principal_user: String::new(),
            device_name: String::new(),
            device_phys: String::new(),
            device_uniq: String::new(),
            device_vendor_id: 0,
            device_product_id: 0,
            start_url: None,
            browser_argv: vec![],
            storage_backend: String::new(),
            storage_path: String::new(),
            browser_user: "alice".to_string(),
            browser_runtime_root: String::new(),
            rules: vec![],
            delegated_registration_storage: String::new(),
        })
        .unwrap();
        let p2 = Policy::from_params(PolicyParams {
            profile_id: test_profile_id(),
            mode: "isolated".to_string(),
            normalized_rp_ids: vec![],
            credential_refs: vec![],
            allowed_actions: vec!["act".to_string()],
            registration_allowed: false,
            require_uv: true,
            max_concurrent_grants: 1,
            max_grant_ttl: 60,
            max_session_ttl: 0,
            principal_user: String::new(),
            device_name: String::new(),
            device_phys: String::new(),
            device_uniq: String::new(),
            device_vendor_id: 0,
            device_product_id: 0,
            start_url: None,
            browser_argv: vec![],
            storage_backend: String::new(),
            storage_path: String::new(),
            browser_user: "bob".to_string(),
            browser_runtime_root: String::new(),
            rules: vec![],
            delegated_registration_storage: String::new(),
        })
        .unwrap();
        assert_ne!(p1.digest(), p2.digest());
        let _ = p1.browser_user;
    }

    #[test]
    fn test_different_browser_runtime_root_different_digests() {
        let p1 = Policy::from_params(PolicyParams {
            profile_id: test_profile_id(),
            mode: "isolated".to_string(),
            normalized_rp_ids: vec![],
            credential_refs: vec![],
            allowed_actions: vec!["act".to_string()],
            registration_allowed: false,
            require_uv: true,
            max_concurrent_grants: 1,
            max_grant_ttl: 60,
            max_session_ttl: 0,
            principal_user: String::new(),
            device_name: String::new(),
            device_phys: String::new(),
            device_uniq: String::new(),
            device_vendor_id: 0,
            device_product_id: 0,
            start_url: None,
            browser_argv: vec![],
            storage_backend: String::new(),
            storage_path: String::new(),
            browser_user: String::new(),
            browser_runtime_root: "/run/browser-a".to_string(),
            rules: vec![],
            delegated_registration_storage: String::new(),
        })
        .unwrap();
        let p2 = Policy::from_params(PolicyParams {
            profile_id: test_profile_id(),
            mode: "isolated".to_string(),
            normalized_rp_ids: vec![],
            credential_refs: vec![],
            allowed_actions: vec!["act".to_string()],
            registration_allowed: false,
            require_uv: true,
            max_concurrent_grants: 1,
            max_grant_ttl: 60,
            max_session_ttl: 0,
            principal_user: String::new(),
            device_name: String::new(),
            device_phys: String::new(),
            device_uniq: String::new(),
            device_vendor_id: 0,
            device_product_id: 0,
            start_url: None,
            browser_argv: vec![],
            storage_backend: String::new(),
            storage_path: String::new(),
            browser_user: String::new(),
            browser_runtime_root: "/run/browser-b".to_string(),
            rules: vec![],
            delegated_registration_storage: String::new(),
        })
        .unwrap();
        assert_ne!(p1.digest(), p2.digest());
    }

    #[test]
    fn test_rule_decision_changes_policy_digest() {
        let mut confirm = test_policy();
        confirm.rules = vec![AgentRpRule {
            rp_id: "example.com".to_string(),
            register: AgentCeremonyPolicy::deny(),
            authenticate: AgentCeremonyPolicy {
                authorization: AgentAuthorization::Confirm,
                user_presence: UserPresenceSource::Human,
                user_verification: UserVerificationSource::Human,
            },
        }];
        let mut allow = confirm.clone();
        allow.rules[0].authenticate = AgentCeremonyPolicy {
            authorization: AgentAuthorization::Allow,
            user_presence: UserPresenceSource::Policy,
            user_verification: UserVerificationSource::Policy,
        };

        assert_ne!(confirm.digest(), allow.digest());
    }

    #[test]
    fn test_action_order_does_not_matter() {
        let policy1 = Policy::new(
            &test_profile_id(),
            vec!["a".to_string(), "b".to_string()],
            1,
            true,
            60,
        )
        .unwrap();
        let policy2 = Policy::new(
            &test_profile_id(),
            vec!["b".to_string(), "a".to_string()],
            1,
            true,
            60,
        )
        .unwrap();
        assert_eq!(policy1.digest(), policy2.digest());
    }

    #[test]
    fn test_uv_flag_matters() {
        let policy1 =
            Policy::new(&test_profile_id(), vec!["act".to_string()], 1, true, 60).unwrap();
        let policy2 =
            Policy::new(&test_profile_id(), vec!["act".to_string()], 1, false, 60).unwrap();
        assert_ne!(policy1.digest(), policy2.digest());
    }

    #[test]
    fn test_policy_digest_from_cbor_bytes() {
        let policy = test_policy();
        let cbor_bytes = policy.to_deterministic_cbor();
        let digest1 = PolicyDigest::from_cbor_bytes(&cbor_bytes);
        let digest2 = policy.digest();
        assert_eq!(digest1, digest2);
    }

    #[test]
    fn test_policy_digest_display() {
        let policy = test_policy();
        let digest = policy.digest();
        let display = digest.to_string();
        assert_eq!(display.len(), 64);
        assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_policy_digest_serde_roundtrip() {
        let policy = test_policy();
        let digest = policy.digest();
        let json = serde_json::to_string(&digest).unwrap();
        let parsed: PolicyDigest = serde_json::from_str(&json).unwrap();
        assert_eq!(digest, parsed);
    }

    #[test]
    fn test_policy_serde_roundtrip() {
        let policy = test_policy();
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: Policy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, parsed);
    }

    #[test]
    fn test_golden_fixture_minimal_policy_cbor() {
        let policy = minimal_policy();
        let cbor_bytes = policy.to_deterministic_cbor();

        assert_eq!(cbor_bytes[0] & 0xe0, 0xa0);
        assert_eq!(cbor_bytes[0] & 0x1f, 24);
        assert_eq!(cbor_bytes[1], 25);
        assert!(!cbor_bytes.is_empty());
        assert_ne!(cbor_bytes[0], 0xbf);
    }

    #[test]
    fn test_golden_fixture_minimal_policy_digest() {
        let policy = minimal_policy();
        let digest = policy.digest();
        let hex = digest.to_hex();

        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));

        let cbor_bytes = policy.to_deterministic_cbor();
        let mut hasher = Sha256::new();
        hasher.update(&cbor_bytes);
        let result = hasher.finalize();
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&result);
        assert_eq!(*digest.as_bytes(), expected);
    }

    #[test]
    fn test_golden_fixture_standard_policy_cbor() {
        let policy = test_policy();
        let cbor_bytes = policy.to_deterministic_cbor();

        assert_eq!(cbor_bytes[0] & 0xe0, 0xa0);
        assert_eq!(cbor_bytes[0] & 0x1f, 24);
        assert_eq!(cbor_bytes[1], 25);
        assert!(!cbor_bytes.is_empty());
    }

    #[test]
    fn test_golden_fixture_standard_policy_digest() {
        let policy = test_policy();
        let digest = policy.digest();
        let hex = digest.to_hex();

        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_golden_fixture_cbor_structure() {
        let policy = Policy::new(
            &ProfileId::new("golden").unwrap(),
            vec!["sign".to_string()],
            1,
            false,
            60,
        )
        .unwrap();
        let cbor_bytes = policy.to_deterministic_cbor();

        assert_eq!(cbor_bytes[0] & 0xe0, 0xa0);
        assert_eq!(cbor_bytes[0] & 0x1f, 24);
        assert_eq!(cbor_bytes[1], 25);
    }

    #[test]
    fn test_golden_fixture_cross_policy_consistency() {
        let policies = [
            minimal_policy(),
            test_policy(),
            Policy::new(
                &ProfileId::new("prod-agent").unwrap(),
                vec![
                    "make_credential".to_string(),
                    "get_assertion".to_string(),
                    "management".to_string(),
                ],
                10,
                true,
                3600,
            )
            .unwrap(),
        ];

        let digests: Vec<String> = policies.iter().map(|p| p.digest().to_hex()).collect();
        let unique: std::collections::HashSet<_> = digests.iter().collect();
        assert_eq!(digests.len(), unique.len());

        for (i, policy) in policies.iter().enumerate() {
            let digest1 = policy.digest().to_hex();
            let digest2 = policy.digest().to_hex();
            assert_eq!(digest1, digest2, "policy {} digest not stable", i);
        }
    }

    #[test]
    fn test_golden_fixture_exact_digest_minimal() {
        let policy = minimal_policy();
        let cbor_bytes = policy.to_deterministic_cbor();
        let digest = PolicyDigest::from_cbor_bytes(&cbor_bytes);

        let mut hasher = Sha256::new();
        hasher.update(&cbor_bytes);
        let expected = hasher.finalize();
        let mut expected_bytes = [0u8; 32];
        expected_bytes.copy_from_slice(&expected);

        assert_eq!(*digest.as_bytes(), expected_bytes);
    }

    #[test]
    fn test_golden_fixture_exact_digest_standard() {
        let policy = test_policy();
        let cbor_bytes = policy.to_deterministic_cbor();
        let digest = PolicyDigest::from_cbor_bytes(&cbor_bytes);

        let mut hasher = Sha256::new();
        hasher.update(&cbor_bytes);
        let expected = hasher.finalize();
        let mut expected_bytes = [0u8; 32];
        expected_bytes.copy_from_slice(&expected);

        assert_eq!(*digest.as_bytes(), expected_bytes);
    }

    #[test]
    fn test_cbor_encoding_canonical_no_indefinite_lengths() {
        let policy = test_policy();
        let cbor = policy.to_deterministic_cbor();

        assert!(!cbor.is_empty());
        assert_eq!(cbor[0] & 0xe0, 0xa0, "policy must encode as a CBOR map");
        assert_ne!(cbor[0], 0xbf, "must not use indefinite-length map");

        let minimal = minimal_policy();
        let cbor_min = minimal.to_deterministic_cbor();
        assert_ne!(cbor_min[0], 0xbf, "must not use indefinite-length map");
    }

    #[test]
    fn test_cbor_uint_shortest_form() {
        assert_eq!(cbor::encode_uint(0).len(), 1);
        assert_eq!(cbor::encode_uint(23).len(), 1);
        assert_eq!(cbor::encode_uint(24).len(), 2);
        assert_eq!(cbor::encode_uint(255).len(), 2);
        assert_eq!(cbor::encode_uint(256).len(), 3);
    }

    #[test]
    fn test_policy_digest_from_hex_invalid() {
        assert!(PolicyDigest::from_hex("not-hex").is_err());
        assert!(PolicyDigest::from_hex("0123456789abcdef").is_err());
    }

    #[test]
    fn test_sorted_keys_complete() {
        let keys = cbor::sorted_keys_for_policy();
        assert_eq!(keys.len(), 25);
        assert!(keys.contains(&"version"));
        assert!(keys.contains(&"profile_id"));
        assert!(keys.contains(&"mode"));
        assert!(keys.contains(&"normalized_rp_ids"));
        assert!(keys.contains(&"credential_refs"));
        assert!(keys.contains(&"allowed_actions"));
        assert!(keys.contains(&"registration_allowed"));
        assert!(keys.contains(&"require_uv"));
        assert!(keys.contains(&"max_concurrent_grants"));
        assert!(keys.contains(&"max_grant_ttl"));
        assert!(keys.contains(&"max_session_ttl"));
        assert!(keys.contains(&"principal_user"));
        assert!(keys.contains(&"device_name"));
        assert!(keys.contains(&"device_phys"));
        assert!(keys.contains(&"device_uniq"));
        assert!(keys.contains(&"device_vendor_id"));
        assert!(keys.contains(&"device_product_id"));
        assert!(keys.contains(&"start_url"));
        assert!(keys.contains(&"browser_argv"));
        assert!(keys.contains(&"storage_backend"));
        assert!(keys.contains(&"storage_path"));
        assert!(keys.contains(&"browser_user"));
        assert!(keys.contains(&"browser_runtime_root"));
        assert!(keys.contains(&"rules"));
        assert!(keys.contains(&"delegated_registration_storage"));
    }

    #[test]
    fn test_sorted_keys_deterministic_order() {
        let keys1 = cbor::sorted_keys_for_policy();
        let keys2 = cbor::sorted_keys_for_policy();
        assert_eq!(keys1, keys2);
    }

    #[test]
    fn test_sorted_keys_exact_order() {
        let keys = cbor::sorted_keys_for_policy();
        assert_eq!(
            keys,
            vec![
                "mode",
                "rules",
                "version",
                "start_url",
                "profile_id",
                "require_uv",
                "device_name",
                "device_phys",
                "device_uniq",
                "browser_argv",
                "browser_user",
                "storage_path",
                "max_grant_ttl",
                "principal_user",
                "allowed_actions",
                "credential_refs",
                "max_session_ttl",
                "storage_backend",
                "device_vendor_id",
                "device_product_id",
                "normalized_rp_ids",
                "browser_runtime_root",
                "registration_allowed",
                "max_concurrent_grants",
                "delegated_registration_storage",
            ]
        );
    }

    #[test]
    fn test_policy_version_constant() {
        assert_eq!(CURRENT_POLICY_VERSION, 3);
    }

    #[test]
    fn test_max_ttl_constant() {
        assert_eq!(MAX_TTL, 86400 * 365);
    }
}
