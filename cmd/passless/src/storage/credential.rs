//! Storage credential types with stable serialization
//!
//! These types are used **only for disk storage** and never exposed outside this module.
//! The runtime always uses `soft_fido2::Credential`.
//!
//! ## Storage Format
//!
//! Our format is frozen and will never change:
//! - Vec<u8> fields as CBOR arrays of integers (not byte strings)
//! - snake_case field names (not camelCase)
//! - Based on original soft-fido2 pre-serde_bytes format
//!
//! This decouples storage from soft-fido2's serialization changes.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐
//! │  Authenticator  │ ← soft_fido2::Credential (runtime)
//! └────────┬────────┘
//!          │
//!   read() returns soft_fido2::Credential
//!          │
//! ┌────────▼────────┐
//! │Storage Backends │ ← Credential (disk only)
//! │ local/pass/tpm  │   • from_bytes() to read
//! └─────────────────┘   • to_bytes() to write
//! ```

use soft_fido2_ctap::SecBytes;

use serde::{Deserialize, Serialize};

/// Relying Party information (storage-only)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelyingParty<'a> {
    /// Relying party identifier (e.g., "example.com")
    #[serde(borrow)]
    pub id: std::borrow::Cow<'a, str>,

    /// Human-readable name (optional)
    #[serde(borrow)]
    pub name: Option<std::borrow::Cow<'a, str>>,
}

impl<'a> RelyingParty<'a> {
    /// Create a new RelyingParty from a soft_fido2 RelyingParty (zero-copy)
    #[inline]
    pub fn from_soft_fido2(rp: &'a soft_fido2_ctap::types::RelyingParty) -> Self {
        Self {
            id: std::borrow::Cow::Borrowed(&rp.id),
            name: rp
                .name
                .as_ref()
                .map(|n| std::borrow::Cow::Borrowed(n.as_str())),
        }
    }

    /// Convert to owned soft_fido2 RelyingParty
    pub fn to_soft_fido2(&self) -> soft_fido2_ctap::types::RelyingParty {
        soft_fido2_ctap::types::RelyingParty {
            id: self.id.to_string(),
            name: self.name.as_ref().map(|n| n.to_string()),
        }
    }

    /// Convert to owned version
    #[allow(dead_code)]
    pub fn into_owned(self) -> RelyingParty<'static> {
        RelyingParty {
            id: std::borrow::Cow::Owned(self.id.into_owned()),
            name: self.name.map(|n| std::borrow::Cow::Owned(n.into_owned())),
        }
    }
}

/// User information (storage-only)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User<'a> {
    #[serde(borrow)]
    pub id: std::borrow::Cow<'a, [u8]>,

    #[serde(borrow)]
    pub name: Option<std::borrow::Cow<'a, str>>,

    #[serde(borrow)]
    pub display_name: Option<std::borrow::Cow<'a, str>>,
}

impl<'a> User<'a> {
    /// Create a new User from a soft_fido2 User (zero-copy)
    #[inline]
    pub fn from_soft_fido2(user: &'a soft_fido2_ctap::types::User) -> Self {
        Self {
            id: std::borrow::Cow::Borrowed(&user.id),
            name: user
                .name
                .as_ref()
                .map(|n| std::borrow::Cow::Borrowed(n.as_str())),
            display_name: user
                .display_name
                .as_ref()
                .map(|n| std::borrow::Cow::Borrowed(n.as_str())),
        }
    }

    /// Convert to owned soft_fido2 User
    pub fn to_soft_fido2(&self) -> soft_fido2_ctap::types::User {
        soft_fido2_ctap::types::User {
            id: self.id.to_vec(),
            name: self.name.as_ref().map(|n| n.to_string()),
            display_name: self.display_name.as_ref().map(|n| n.to_string()),
        }
    }

    /// Convert to owned version
    #[allow(dead_code)]
    pub fn into_owned(self) -> User<'static> {
        User {
            id: std::borrow::Cow::Owned(self.id.into_owned()),
            name: self.name.map(|n| std::borrow::Cow::Owned(n.into_owned())),
            display_name: self
                .display_name
                .map(|n| std::borrow::Cow::Owned(n.into_owned())),
        }
    }
}

/// Credential extension data
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Extensions {
    /// Credential protection level
    pub cred_protect: Option<u8>,
    /// HMAC secret extension
    pub hmac_secret: Option<bool>,
    /// HMAC secret credential random (32 bytes)
    /// Used to compute HMAC outputs for the hmac-secret extension
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cred_random: Option<Vec<u8>>,
}

/// Storage credential (internal to storage module)
///
/// Zero-copy wrapper for disk serialization. Never exposed outside storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential<'a> {
    #[serde(borrow)]
    pub id: std::borrow::Cow<'a, [u8]>,

    #[serde(borrow)]
    pub rp: RelyingParty<'a>,

    #[serde(borrow)]
    pub user: User<'a>,

    pub sign_count: u32,

    pub alg: i32,

    #[serde(with = "sec_bytes_serde")]
    pub private_key: SecBytes,

    pub created: i64,

    pub discoverable: bool,

    #[serde(default)]
    pub extensions: Extensions,
}

impl<'a> Credential<'a> {
    /// Create a new Credential from a soft_fido2::Credential (zero-copy)
    #[inline]
    pub fn from_soft_fido2(cred: &'a soft_fido2::Credential) -> Self {
        Self {
            id: std::borrow::Cow::Borrowed(&cred.id),
            rp: RelyingParty::from_soft_fido2(&cred.rp),
            user: User::from_soft_fido2(&cred.user),
            sign_count: cred.sign_count,
            alg: cred.alg,
            private_key: cred.key.material.clone(),
            created: cred.created,
            discoverable: cred.discoverable,
            extensions: Extensions {
                cred_protect: cred.extensions.cred_protect,
                hmac_secret: cred.extensions.hmac_secret,
                cred_random: cred.extensions.cred_random.as_ref().map(|cr| cr.to_vec()),
            },
        }
    }

    /// Create a new Credential from a soft_fido2::CredentialRef (zero-copy)
    #[inline]
    #[allow(dead_code)]
    pub fn from_soft_fido2_ref(cred_ref: soft_fido2::CredentialRef<'a>) -> Self {
        Self {
            id: std::borrow::Cow::Borrowed(cred_ref.id),
            rp: RelyingParty {
                id: std::borrow::Cow::Borrowed(cred_ref.rp_id),
                name: cred_ref.rp_name.map(std::borrow::Cow::Borrowed),
            },
            user: User {
                id: std::borrow::Cow::Borrowed(cred_ref.user_id),
                name: cred_ref.user_name.map(std::borrow::Cow::Borrowed),
                display_name: cred_ref.user_display_name.map(std::borrow::Cow::Borrowed),
            },
            sign_count: *cred_ref.sign_count,
            alg: *cred_ref.alg,
            private_key: cred_ref.key.material.clone(),
            created: *cred_ref.created,
            discoverable: *cred_ref.discoverable,
            extensions: Extensions {
                cred_protect: cred_ref.cred_protect.copied(),
                hmac_secret: None,
                cred_random: cred_ref.cred_random.map(|cr| cr.to_vec()),
            },
        }
    }

    /// Convert to owned soft_fido2::Credential
    pub fn to_soft_fido2(&self) -> soft_fido2::Credential {
        soft_fido2::Credential {
            id: self.id.to_vec(),
            rp: self.rp.to_soft_fido2(),
            user: self.user.to_soft_fido2(),
            sign_count: self.sign_count,
            alg: self.alg,
            key: soft_fido2_ctap::CredentialKey::software(self.private_key.clone()),
            created: self.created,
            discoverable: self.discoverable,
            extensions: soft_fido2::Extensions {
                cred_protect: self.extensions.cred_protect,
                hmac_secret: self.extensions.hmac_secret,
                cred_random: self
                    .extensions
                    .cred_random
                    .as_ref()
                    .map(|cr| soft_fido2_ctap::SecBytes::from_slice(cr)),
            },
        }
    }

    /// Convert to owned version
    #[allow(dead_code)]
    pub fn into_owned(self) -> Credential<'static> {
        Credential {
            id: std::borrow::Cow::Owned(self.id.into_owned()),
            rp: self.rp.into_owned(),
            user: self.user.into_owned(),
            sign_count: self.sign_count,
            alg: self.alg,
            private_key: self.private_key,
            created: self.created,
            discoverable: self.discoverable,
            extensions: self.extensions,
        }
    }

    /// Serialize to our stable storage format
    pub fn to_bytes(&self) -> Result<Vec<u8>, soft_fido2::Error> {
        let mut buf = Vec::new();
        soft_fido2_ctap::cbor::into_writer(self, &mut buf).map_err(|_| soft_fido2::Error::Other)?;
        Ok(buf)
    }

    /// Deserialize from our stable storage format
    ///
    /// Format: Vec<u8> as CBOR arrays of integers (original soft-fido2 pre-serde_bytes format)
    pub fn from_bytes(data: &[u8]) -> Result<Credential<'static>, soft_fido2::Error> {
        #[derive(serde::Deserialize)]
        struct OwnedCredential {
            #[serde(deserialize_with = "flexible_bytes::deserialize")]
            id: Vec<u8>,
            rp: OwnedRelyingParty,
            user: OwnedUser,
            sign_count: u32,
            alg: i32,
            #[serde(deserialize_with = "flexible_bytes::deserialize")]
            private_key: Vec<u8>,
            created: i64,
            discoverable: bool,
            #[serde(default)]
            extensions: Extensions,
        }

        #[derive(serde::Deserialize)]
        struct OwnedRelyingParty {
            id: String,
            name: Option<String>,
        }

        #[derive(serde::Deserialize)]
        struct OwnedUser {
            #[serde(deserialize_with = "flexible_bytes::deserialize")]
            id: Vec<u8>,
            name: Option<String>,
            display_name: Option<String>,
        }

        let owned: OwnedCredential =
            soft_fido2_ctap::cbor::decode(data).map_err(|_| soft_fido2::Error::Other)?;

        Ok(Credential {
            id: std::borrow::Cow::Owned(owned.id),
            rp: RelyingParty {
                id: std::borrow::Cow::Owned(owned.rp.id),
                name: owned.rp.name.map(std::borrow::Cow::Owned),
            },
            user: User {
                id: std::borrow::Cow::Owned(owned.user.id),
                name: owned.user.name.map(std::borrow::Cow::Owned),
                display_name: owned.user.display_name.map(std::borrow::Cow::Owned),
            },
            sign_count: owned.sign_count,
            alg: owned.alg,
            private_key: SecBytes::new(owned.private_key),
            created: owned.created,
            discoverable: owned.discoverable,
            extensions: owned.extensions,
        })
    }
}

/// Flexible Vec<u8> deserializer
///
/// Accepts both CBOR byte strings and arrays of integers.
/// This ensures compatibility with the original soft-fido2 format.
mod flexible_bytes {
    use serde::de::{Deserializer, SeqAccess, Visitor};

    struct BytesVisitor;

    impl<'de> Visitor<'de> for BytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("byte string or array of integers")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(v.to_vec())
        }

        fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(v)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut bytes = Vec::new();
            while let Some(value) = seq.next_element::<u8>()? {
                bytes.push(value);
            }
            Ok(bytes)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(BytesVisitor)
    }
}

/// SecBytes serialization (as CBOR array)
mod sec_bytes_serde {
    use soft_fido2_ctap::SecBytes;

    use serde::{Deserializer, Serialize, Serializer};

    pub fn serialize<S>(sec_bytes: &SecBytes, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes: Vec<u8> = sec_bytes.as_slice().to_vec();
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SecBytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = super::flexible_bytes::deserialize(deserializer)?;
        Ok(SecBytes::new(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relying_party_zero_copy() {
        let soft_rp = soft_fido2_ctap::types::RelyingParty {
            id: "example.com".to_string(),
            name: Some("Example".to_string()),
        };

        let our_rp = RelyingParty::from_soft_fido2(&soft_rp);

        assert_eq!(our_rp.id, "example.com");
        assert_eq!(our_rp.name.as_ref().map(|s| s.as_ref()), Some("Example"));

        // Verify zero-copy by checking pointer equality
        match our_rp.id {
            std::borrow::Cow::Borrowed(s) => assert_eq!(s, soft_rp.id.as_str()),
            std::borrow::Cow::Owned(_) => panic!("Expected borrowed data"),
        }
    }

    #[test]
    fn test_user_zero_copy() {
        let soft_user = soft_fido2_ctap::types::User {
            id: vec![1, 2, 3, 4],
            name: Some("user@example.com".to_string()),
            display_name: Some("User Name".to_string()),
        };

        let our_user = User::from_soft_fido2(&soft_user);

        assert_eq!(our_user.id.as_ref(), &[1, 2, 3, 4]);
        assert_eq!(
            our_user.name.as_ref().map(|s| s.as_ref()),
            Some("user@example.com")
        );

        // Verify zero-copy by checking pointer equality
        match our_user.id {
            std::borrow::Cow::Borrowed(s) => assert_eq!(s, soft_user.id.as_slice()),
            std::borrow::Cow::Owned(_) => panic!("Expected borrowed data"),
        }
    }

    #[test]
    fn test_credential_serialization_roundtrip() {
        let soft_cred = soft_fido2::Credential {
            id: vec![1, 2, 3, 4],
            rp: soft_fido2_ctap::types::RelyingParty {
                id: "example.com".to_string(),
                name: Some("Example".to_string()),
            },
            user: soft_fido2_ctap::types::User {
                id: vec![5, 6, 7, 8],
                name: Some("user@example.com".to_string()),
                display_name: Some("User Name".to_string()),
            },
            sign_count: 42,
            alg: -7,
            key: soft_fido2_ctap::CredentialKey::software(SecBytes::new(vec![0u8; 32])),
            created: 1234567890,
            discoverable: true,
            extensions: soft_fido2::Extensions {
                cred_protect: Some(1),
                hmac_secret: None,
                cred_random: None,
            },
        };

        let our_cred = Credential::from_soft_fido2(&soft_cred);

        let our_bytes = our_cred.to_bytes().expect("Serialization should succeed");
        let deserialized =
            Credential::from_bytes(&our_bytes).expect("Should deserialize our format");

        // Verify all fields match
        assert_eq!(deserialized.id.as_ref(), &[1, 2, 3, 4]);
        assert_eq!(deserialized.rp.id, "example.com");
        assert_eq!(deserialized.user.id.as_ref(), &[5, 6, 7, 8]);
        assert_eq!(deserialized.sign_count, 42);
        assert_eq!(deserialized.alg, -7);
        assert_eq!(deserialized.created, 1234567890);
        assert!(deserialized.discoverable);
    }

    #[test]
    fn test_minimal_credential_roundtrip() {
        let our_cred = Credential {
            id: std::borrow::Cow::Owned(vec![1, 2, 3, 4]),
            rp: RelyingParty {
                id: std::borrow::Cow::Owned("example.com".to_string()),
                name: None,
            },
            user: User {
                id: std::borrow::Cow::Owned(vec![5, 6, 7, 8]),
                name: Some(std::borrow::Cow::Owned("user".to_string())),
                display_name: None,
            },
            sign_count: 0,
            alg: -7,
            private_key: SecBytes::new(vec![0u8; 32]),
            created: 0,
            discoverable: true,
            extensions: Extensions::default(),
        };

        let our_bytes = our_cred.to_bytes().expect("Should serialize our format");
        let deserialized =
            Credential::from_bytes(&our_bytes).expect("Should deserialize our format");

        assert_eq!(deserialized.id.as_ref(), &[1, 2, 3, 4]);
        assert_eq!(deserialized.rp.id, "example.com");
        assert_eq!(deserialized.user.id.as_ref(), &[5, 6, 7, 8]);
    }

    #[test]
    fn test_serialization_roundtrip() {
        // Create a credential
        let soft_cred = soft_fido2::Credential {
            id: vec![1, 2, 3, 4],
            rp: soft_fido2_ctap::types::RelyingParty {
                id: "example.com".to_string(),
                name: Some("Example".to_string()),
            },
            user: soft_fido2_ctap::types::User {
                id: vec![5, 6, 7, 8],
                name: Some("user@example.com".to_string()),
                display_name: Some("User Name".to_string()),
            },
            sign_count: 42,
            alg: -7,
            key: soft_fido2_ctap::CredentialKey::software(SecBytes::new(vec![0u8; 32])),
            created: 1234567890,
            discoverable: true,
            extensions: soft_fido2::Extensions {
                cred_protect: Some(1),
                hmac_secret: None,
                cred_random: None,
            },
        };

        // Serialize with our format
        let our_cred = Credential::from_soft_fido2(&soft_cred);
        let our_bytes = our_cred
            .to_bytes()
            .expect("Should be able to serialize our credential format");

        // Deserialize and verify
        let deserialized =
            Credential::from_bytes(&our_bytes).expect("Should deserialize our own format");

        assert_eq!(deserialized.id.as_ref(), &[1, 2, 3, 4]);
        assert_eq!(deserialized.rp.id, "example.com");
        assert_eq!(deserialized.user.id.as_ref(), &[5, 6, 7, 8]);
        assert_eq!(
            deserialized.user.name.as_ref().map(|s| s.as_ref()),
            Some("user@example.com")
        );
        assert_eq!(
            deserialized.user.display_name.as_ref().map(|s| s.as_ref()),
            Some("User Name")
        );
        assert_eq!(deserialized.sign_count, 42);
        assert_eq!(deserialized.alg, -7);
        assert_eq!(deserialized.created, 1234567890);
        assert!(deserialized.discoverable);
    }
}
