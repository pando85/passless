use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const OPAQUE_ID_BYTES: usize = 32;
const MAX_PROFILE_ID_LEN: usize = 128;
const CREDENTIAL_REF_DOMAIN_SEPARATOR: &str = "passless/credential-ref/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdError {
    Empty(String),
    PathTraversal(String),
    PathSeparator(String),
    NullByte(String),
    ControlCharacter(String),
    TooLong(String, usize),
    Whitespace(String),
    InvalidFormat(String),
    InvalidHex(String),
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdError::Empty(t) => write!(f, "{} cannot be empty", t),
            IdError::PathTraversal(s) => write!(f, "path traversal not allowed: {}", s),
            IdError::PathSeparator(s) => write!(f, "path separators not allowed: {}", s),
            IdError::NullByte(s) => write!(f, "null bytes not allowed: {}", s),
            IdError::ControlCharacter(s) => write!(f, "control characters not allowed: {}", s),
            IdError::TooLong(t, max) => write!(f, "{} exceeds maximum length of {}", t, max),
            IdError::Whitespace(s) => write!(f, "leading/trailing whitespace not allowed: {}", s),
            IdError::InvalidFormat(s) => write!(f, "invalid format: {}", s),
            IdError::InvalidHex(s) => write!(f, "invalid hex encoding: {}", s),
        }
    }
}

impl std::error::Error for IdError {}

macro_rules! opaque_id {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new() -> Self {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                let bytes: Vec<u8> = (0..OPAQUE_ID_BYTES).map(|_| rng.r#gen()).collect();
                Self(hex::encode(bytes))
            }

            #[cfg(test)]
            pub fn from_string_unchecked(s: String) -> Self {
                Self(s)
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }

        impl FromStr for $name {
            type Err = IdError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                if s.is_empty() {
                    return Err(IdError::Empty(stringify!($name).to_string()));
                }
                if s.len() != OPAQUE_ID_BYTES * 2 {
                    return Err(IdError::InvalidHex(format!(
                        "{} must be {} hex characters, got {}",
                        stringify!($name),
                        OPAQUE_ID_BYTES * 2,
                        s.len()
                    )));
                }
                if !s
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                {
                    return Err(IdError::InvalidHex(format!(
                        "{} must be lowercase hex, got: {}",
                        stringify!($name),
                        s
                    )));
                }
                if hex::decode(s).is_err() {
                    return Err(IdError::InvalidHex(format!(
                        "{} contains invalid hex characters: {}",
                        stringify!($name),
                        s
                    )));
                }
                Ok(Self(s.to_string()))
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

opaque_id!(
    PrincipalSessionId,
    "Opaque identifier for a principal's session."
);
opaque_id!(EndpointId, "Opaque identifier for an agent endpoint.");
opaque_id!(
    PolicyGenerationId,
    "Opaque identifier for a policy generation."
);
opaque_id!(IntentId, "Opaque identifier for an agent intent.");
opaque_id!(GrantId, "Opaque identifier for a permission grant.");
opaque_id!(BrowserLeaseId, "Opaque identifier for a browser lease.");
opaque_id!(
    PendingRequestId,
    "Opaque identifier for a pending principal request."
);
opaque_id!(
    RegistrationGrantId,
    "Opaque identifier for a registration grant."
);

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProfileId(String);

impl ProfileId {
    pub fn new(s: impl Into<String>) -> Result<Self, IdError> {
        let s = s.into();
        Self::validate(&s)?;
        Ok(Self(s))
    }

    #[cfg(test)]
    pub fn from_string_unchecked(s: String) -> Self {
        Self(s)
    }

    fn validate(s: &str) -> Result<(), IdError> {
        if s.is_empty() {
            return Err(IdError::Empty("ProfileId".to_string()));
        }

        if s.len() > MAX_PROFILE_ID_LEN {
            return Err(IdError::TooLong(
                "ProfileId".to_string(),
                MAX_PROFILE_ID_LEN,
            ));
        }

        if s != s.trim() {
            return Err(IdError::Whitespace(s.to_string()));
        }

        if s.contains('\0') {
            return Err(IdError::NullByte(s.to_string()));
        }

        if s.contains("..") {
            return Err(IdError::PathTraversal(s.to_string()));
        }

        if s.contains('/') || s.contains('\\') {
            return Err(IdError::PathSeparator(s.to_string()));
        }

        if s.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(IdError::ControlCharacter(s.to_string()));
        }

        if s == "." {
            return Err(IdError::PathTraversal(s.to_string()));
        }

        Ok(())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for ProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for ProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ProfileId").field(&self.0).finish()
    }
}

impl FromStr for ProfileId {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl AsRef<str> for ProfileId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CredentialRef([u8; 32]);

impl Serialize for CredentialRef {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for CredentialRef {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        CredentialRef::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl CredentialRef {
    pub fn new(domain_separator: &str, credential_id: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(domain_separator.as_bytes());
        hasher.update(credential_id);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    pub fn with_default_domain(credential_id: &[u8]) -> Self {
        Self::new(CREDENTIAL_REF_DOMAIN_SEPARATOR, credential_id)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, IdError> {
        let bytes =
            hex::decode(s).map_err(|_| IdError::InvalidHex(format!("invalid hex: {}", s)))?;
        if bytes.len() != 32 {
            return Err(IdError::InvalidHex(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl fmt::Display for CredentialRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for CredentialRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CredentialRef")
            .field(&self.to_hex())
            .finish()
    }
}

impl AsRef<[u8]> for CredentialRef {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_principal_session_id_creation() {
        let id1 = PrincipalSessionId::new();
        let id2 = PrincipalSessionId::new();
        assert_ne!(id1, id2);
        assert_eq!(id1.as_str().len(), 64);
    }

    #[test]
    fn test_principal_session_id_display() {
        let id = PrincipalSessionId::from_string_unchecked("test-session".to_string());
        assert_eq!(id.to_string(), "test-session");
    }

    #[test]
    fn test_principal_session_id_parse() {
        let hex_id = "a".repeat(64);
        let id: PrincipalSessionId = hex_id.parse().unwrap();
        assert_eq!(id.as_str(), hex_id);
    }

    #[test]
    fn test_principal_session_id_parse_empty() {
        let result: Result<PrincipalSessionId, _> = "".parse();
        assert!(matches!(result, Err(IdError::Empty(_))));
    }

    #[test]
    fn test_principal_session_id_parse_rejects_non_hex() {
        let result: Result<PrincipalSessionId, _> = "test-session".parse();
        assert!(matches!(result, Err(IdError::InvalidHex(_))));
    }

    #[test]
    fn test_principal_session_id_parse_rejects_uppercase_hex() {
        let hex_id = "A".repeat(64);
        let result: Result<PrincipalSessionId, _> = hex_id.parse();
        assert!(matches!(result, Err(IdError::InvalidHex(_))));
    }

    #[test]
    fn test_principal_session_id_parse_rejects_wrong_length() {
        let result: Result<PrincipalSessionId, _> = "abcd".parse();
        assert!(matches!(result, Err(IdError::InvalidHex(_))));
    }

    #[test]
    fn test_endpoint_id_creation() {
        let id = EndpointId::new();
        assert_eq!(id.as_str().len(), 64);
    }

    #[test]
    fn test_endpoint_id_equality() {
        let id1 = EndpointId::from_string_unchecked("endpoint-1".to_string());
        let id2 = EndpointId::from_string_unchecked("endpoint-1".to_string());
        let id3 = EndpointId::from_string_unchecked("endpoint-2".to_string());
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_policy_generation_id() {
        let id = PolicyGenerationId::new();
        assert_eq!(id.as_str().len(), 64);
    }

    #[test]
    fn test_intent_id() {
        let id = IntentId::new();
        assert_eq!(id.as_str().len(), 64);
    }

    #[test]
    fn test_grant_id() {
        let id = GrantId::new();
        assert_eq!(id.as_str().len(), 64);
    }

    #[test]
    fn test_browser_lease_id() {
        let id = BrowserLeaseId::new();
        assert_eq!(id.as_str().len(), 64);
    }

    #[test]
    fn test_profile_id_valid() {
        assert!(ProfileId::new("test-agent").is_ok());
        assert!(ProfileId::new("agent-123").is_ok());
        assert!(ProfileId::new("my_agent").is_ok());
        assert!(ProfileId::new("agent.test").is_ok());
        assert!(ProfileId::new("a").is_ok());
    }

    #[test]
    fn test_profile_id_empty() {
        let result = ProfileId::new("");
        assert!(matches!(result, Err(IdError::Empty(_))));
    }

    #[test]
    fn test_profile_id_path_traversal() {
        assert!(matches!(
            ProfileId::new(".."),
            Err(IdError::PathTraversal(_))
        ));
        assert!(matches!(
            ProfileId::new("agent..test"),
            Err(IdError::PathTraversal(_))
        ));
        assert!(matches!(
            ProfileId::new("../etc"),
            Err(IdError::PathTraversal(_))
        ));
    }

    #[test]
    fn test_profile_id_path_separator() {
        assert!(matches!(
            ProfileId::new("agent/test"),
            Err(IdError::PathSeparator(_))
        ));
        assert!(matches!(
            ProfileId::new("agent\\test"),
            Err(IdError::PathSeparator(_))
        ));
        assert!(matches!(
            ProfileId::new("/agent"),
            Err(IdError::PathSeparator(_))
        ));
        assert!(matches!(
            ProfileId::new("agent/"),
            Err(IdError::PathSeparator(_))
        ));
    }

    #[test]
    fn test_profile_id_null_byte() {
        assert!(matches!(
            ProfileId::new("agent\0test"),
            Err(IdError::NullByte(_))
        ));
    }

    #[test]
    fn test_profile_id_control_characters() {
        assert!(matches!(
            ProfileId::new("agent\x01test"),
            Err(IdError::ControlCharacter(_))
        ));
        assert!(matches!(
            ProfileId::new("agent\ntest"),
            Err(IdError::ControlCharacter(_))
        ));
        assert!(matches!(
            ProfileId::new("agent\ttest"),
            Err(IdError::ControlCharacter(_))
        ));
        assert!(matches!(
            ProfileId::new("agent\x7ftest"),
            Err(IdError::ControlCharacter(_))
        ));
    }

    #[test]
    fn test_profile_id_too_long() {
        let long_id = "a".repeat(MAX_PROFILE_ID_LEN + 1);
        assert!(matches!(
            ProfileId::new(long_id),
            Err(IdError::TooLong(_, _))
        ));
    }

    #[test]
    fn test_profile_id_max_length() {
        let max_id = "a".repeat(MAX_PROFILE_ID_LEN);
        assert!(ProfileId::new(max_id).is_ok());
    }

    #[test]
    fn test_profile_id_whitespace() {
        assert!(matches!(
            ProfileId::new(" agent"),
            Err(IdError::Whitespace(_))
        ));
        assert!(matches!(
            ProfileId::new("agent "),
            Err(IdError::Whitespace(_))
        ));
        assert!(matches!(
            ProfileId::new(" agent "),
            Err(IdError::Whitespace(_))
        ));
    }

    #[test]
    fn test_profile_id_dot() {
        assert!(matches!(
            ProfileId::new("."),
            Err(IdError::PathTraversal(_))
        ));
    }

    #[test]
    fn test_profile_id_display() {
        let id = ProfileId::new("test-agent").unwrap();
        assert_eq!(id.to_string(), "test-agent");
    }

    #[test]
    fn test_profile_id_parse() {
        let id: ProfileId = "test-agent".parse().unwrap();
        assert_eq!(id.as_str(), "test-agent");
    }

    #[test]
    fn test_profile_id_parse_invalid() {
        let result: Result<ProfileId, _> = "agent/test".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_credential_ref_creation() {
        let cred_id = b"test-credential-id";
        let cred_ref = CredentialRef::new("test-domain", cred_id);
        assert_eq!(cred_ref.as_bytes().len(), 32);
    }

    #[test]
    fn test_credential_ref_default_domain() {
        let cred_id = b"test-credential-id";
        let ref1 = CredentialRef::with_default_domain(cred_id);
        let ref2 = CredentialRef::new(CREDENTIAL_REF_DOMAIN_SEPARATOR, cred_id);
        assert_eq!(ref1, ref2);
    }

    #[test]
    fn test_credential_ref_deterministic() {
        let cred_id = b"test-credential-id";
        let ref1 = CredentialRef::new("domain", cred_id);
        let ref2 = CredentialRef::new("domain", cred_id);
        assert_eq!(ref1, ref2);
    }

    #[test]
    fn test_credential_ref_different_domains() {
        let cred_id = b"test-credential-id";
        let ref1 = CredentialRef::new("domain1", cred_id);
        let ref2 = CredentialRef::new("domain2", cred_id);
        assert_ne!(ref1, ref2);
    }

    #[test]
    fn test_credential_ref_different_credentials() {
        let ref1 = CredentialRef::new("domain", b"cred1");
        let ref2 = CredentialRef::new("domain", b"cred2");
        assert_ne!(ref1, ref2);
    }

    #[test]
    fn test_credential_ref_hex_roundtrip() {
        let cred_ref = CredentialRef::new("domain", b"test");
        let hex = cred_ref.to_hex();
        let parsed = CredentialRef::from_hex(&hex).unwrap();
        assert_eq!(cred_ref, parsed);
    }

    #[test]
    fn test_credential_ref_from_hex_invalid() {
        assert!(CredentialRef::from_hex("not-hex").is_err());
        assert!(CredentialRef::from_hex("0123456789abcdef").is_err());
    }

    #[test]
    fn test_credential_ref_display() {
        let cred_ref = CredentialRef::new("domain", b"test");
        let display = cred_ref.to_string();
        assert_eq!(display.len(), 64);
        assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_id_types_not_interchangeable() {
        let session = PrincipalSessionId::from_string_unchecked("test".to_string());
        let endpoint = EndpointId::from_string_unchecked("test".to_string());
        let grant = GrantId::from_string_unchecked("test".to_string());

        assert_ne!(
            std::any::TypeId::of::<PrincipalSessionId>(),
            std::any::TypeId::of::<EndpointId>()
        );
        assert_ne!(
            std::any::TypeId::of::<EndpointId>(),
            std::any::TypeId::of::<GrantId>()
        );

        assert_eq!(session.as_str(), endpoint.as_str());
        assert_eq!(endpoint.as_str(), grant.as_str());
    }

    #[test]
    fn test_id_serde_roundtrip() {
        let id = PrincipalSessionId::from_string_unchecked("test-session".to_string());
        let json = serde_json::to_string(&id).unwrap();
        let parsed: PrincipalSessionId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn test_profile_id_serde_roundtrip() {
        let id = ProfileId::new("test-agent").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        let parsed: ProfileId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn test_credential_ref_serde_roundtrip() {
        let cred_ref = CredentialRef::new("domain", b"test");
        let json = serde_json::to_string(&cred_ref).unwrap();
        let parsed: CredentialRef = serde_json::from_str(&json).unwrap();
        assert_eq!(cred_ref, parsed);
    }

    #[test]
    fn test_credential_ref_known_hash() {
        let cred_ref = CredentialRef::new("", b"");
        let hex = cred_ref.to_hex();
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_credential_ref_known_hash_with_data() {
        let cred_ref = CredentialRef::new("domain", b"credential");
        let hex = cred_ref.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_all_opaque_ids_unique() {
        let ids: Vec<String> = (0..100)
            .map(|_| PrincipalSessionId::new().to_string())
            .collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len());
    }
}
