//! Portable parent key management
//!
//! Handles deterministic derivation and import of the portable storage parent
//! that enables credential key portability across TPMs.

use super::kdf;

use soft_fido2::Result;

use std::path::PathBuf;

use log::{debug, error, info};
use tss_esapi::Context;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::interface_types::algorithm::PublicAlgorithm;
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Provision;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy};
use tss_esapi::structures::{
    EccParameter, EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, Public,
    PublicBuilder, PublicEccParametersBuilder, Sensitive, SensitiveBuffer,
    SymmetricDefinitionObject,
};
use tss_esapi::traits::{Marshall, UnMarshall};
use zeroize::Zeroizing;

/// Provider identifier for portable TPM credentials
pub const PROVIDER_ID: &[u8] = b"tpm-portable-v1";

/// Format version for portable TPM credential keys
pub const FORMAT_VERSION: u16 = 1;

/// Persistent handle for the portable parent key
const PARENT_PERSISTENT_HANDLE: u32 = 0x81000001;

/// P-256 curve order
const P256_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

/// Portable parent key metadata stored on disk
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PortableParentMetadata {
    /// Format version
    pub version: u16,
    /// Expected parent public area (TPMT_PUBLIC marshalled, no size prefix)
    pub public_blob: Vec<u8>,
    /// Expected parent name (for verification)
    pub parent_name: Vec<u8>,
    /// Persistent handle where parent is stored
    pub persistent_handle: u32,
}

/// Portable parent key manager
pub struct PortableParent {
    /// Storage directory for metadata
    storage_dir: PathBuf,
    /// TPM context
    context: std::sync::Mutex<Context>,
}

impl PortableParent {
    /// Create a new portable parent manager
    pub fn new(storage_dir: PathBuf, tcti: Option<String>) -> Result<Self> {
        let tcti_conf = if let Some(ref tcti_str) = tcti {
            info!("Using TCTI configuration: {}", tcti_str);
            std::str::FromStr::from_str(tcti_str).map_err(|e| {
                error!("Failed to parse TCTI configuration '{}': {}", tcti_str, e);
                soft_fido2::Error::Other
            })?
        } else {
            info!("Using default TCTI: device:/dev/tpmrm0");
            tss_esapi::Tcti::Device(Default::default())
        };

        let context = Context::new(tcti_conf).map_err(|e| {
            error!("Failed to create TPM context: {}", e);
            soft_fido2::Error::Other
        })?;

        Ok(Self {
            storage_dir,
            context: std::sync::Mutex::new(context),
        })
    }

    /// Check if portable parent is provisioned
    pub fn is_provisioned(&self) -> bool {
        let metadata_path = self.storage_dir.join("portable_parent.json");
        metadata_path.exists()
    }

    /// Load parent metadata
    pub fn load_metadata(&self) -> Result<PortableParentMetadata> {
        let metadata_path = self.storage_dir.join("portable_parent.json");
        let data = std::fs::read(&metadata_path).map_err(|e| {
            error!("Failed to read parent metadata: {}", e);
            soft_fido2::Error::Other
        })?;

        serde_json::from_slice(&data).map_err(|e| {
            error!("Failed to parse parent metadata: {}", e);
            soft_fido2::Error::Other
        })
    }

    /// Verify the provisioned parent matches expected metadata
    pub fn verify_parent(&self, metadata: &PortableParentMetadata) -> Result<()> {
        let mut context = self.context.lock().map_err(|e| {
            error!("Failed to lock TPM context: {}", e);
            soft_fido2::Error::Other
        })?;

        let persistent_tpm_handle = tss_esapi::handles::PersistentTpmHandle::new(
            metadata.persistent_handle,
        )
        .map_err(|e| {
            error!("Failed to create persistent TPM handle: {}", e);
            soft_fido2::Error::Other
        })?;
        let persistent_handle = context
            .tr_from_tpm_public(persistent_tpm_handle.into())
            .map_err(|e| {
                error!(
                    "Failed to register persistent handle in ESYS context: {}",
                    e
                );
                soft_fido2::Error::Other
            })?;
        let persistent_key_handle = tss_esapi::handles::KeyHandle::from(persistent_handle);

        let (public_area, name, _) = context.read_public(persistent_key_handle).map_err(|e| {
            error!("Failed to read persistent parent public area: {}", e);
            soft_fido2::Error::Other
        })?;

        let expected_public = Public::unmarshall(&metadata.public_blob).map_err(|e| {
            error!("Failed to unmarshall expected public area: {}", e);
            soft_fido2::Error::Other
        })?;

        if public_area != expected_public {
            error!("Parent public area mismatch");
            return Err(soft_fido2::Error::Other);
        }

        if name.value() != metadata.parent_name {
            error!("Parent name mismatch");
            return Err(soft_fido2::Error::Other);
        }

        debug!("Parent verification successful");
        Ok(())
    }

    /// Provision a new portable parent from a recovery seed
    pub fn provision(&self, seed: &[u8]) -> Result<()> {
        info!("Provisioning portable TPM parent");

        let material = derive_parent_material(seed)?;

        let mut context = self.context.lock().map_err(|e| {
            error!("Failed to lock TPM context: {}", e);
            soft_fido2::Error::Other
        })?;

        let temp_primary = create_temp_primary(&mut context)?;

        let (temp_pub, _, _) = context.read_public(temp_primary).map_err(|e| {
            error!("Failed to read temp primary public: {}", e);
            soft_fido2::Error::Other
        })?;

        let (prim_x, prim_y) = match temp_pub {
            Public::Ecc { unique, .. } => {
                let x = unique.x().value().to_vec();
                let y = unique.y().value().to_vec();
                let mut x_padded = vec![0u8; 32];
                let x_start = 32 - x.len();
                x_padded[x_start..].copy_from_slice(&x);
                let mut y_padded = vec![0u8; 32];
                let y_start = 32 - y.len();
                y_padded[y_start..].copy_from_slice(&y);
                (Zeroizing::new(x_padded), Zeroizing::new(y_padded))
            }
            _ => {
                error!("Expected ECC public key from temp primary");
                return Err(soft_fido2::Error::Other);
            }
        };

        let parent_public = build_parent_public(&material.pub_x, &material.pub_y)?;

        let (duplicate, in_sym_seed) =
            wrap_for_import(&material, &prim_x, &prim_y, &parent_public)?;

        let imported_private = context
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.import(
                    temp_primary.into(),
                    None,
                    parent_public.clone(),
                    duplicate,
                    in_sym_seed,
                    SymmetricDefinitionObject::Null,
                )
            })
            .map_err(|e| {
                error!("Failed to import parent key: {}", e);
                soft_fido2::Error::Other
            })?;

        let loaded_handle = context
            .execute_with_nullauth_session(|ctx| {
                ctx.load(temp_primary, imported_private, parent_public.clone())
            })
            .map_err(|e| {
                error!("Failed to load imported parent key: {}", e);
                soft_fido2::Error::Other
            })?;

        let persistent_tpm_handle = tss_esapi::handles::PersistentTpmHandle::new(
            PARENT_PERSISTENT_HANDLE,
        )
        .map_err(|e| {
            error!("Failed to create persistent TPM handle: {}", e);
            soft_fido2::Error::Other
        })?;
        let persistent = Persistent::from(persistent_tpm_handle);

        context
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.evict_control(Provision::Owner, loaded_handle.into(), persistent)
            })
            .map_err(|e| {
                error!("Failed to persist parent key: {}", e);
                soft_fido2::Error::Other
            })?;

        let _ = context.flush_context(temp_primary.into());

        let persistent_handle = context
            .tr_from_tpm_public(persistent_tpm_handle.into())
            .map_err(|e| {
                error!(
                    "Failed to register persistent handle in ESYS context: {}",
                    e
                );
                soft_fido2::Error::Other
            })?;
        let persistent_key_handle = tss_esapi::handles::KeyHandle::from(persistent_handle);

        let (pub_read, name, _) = context.read_public(persistent_key_handle).map_err(|e| {
            error!("Failed to read persistent parent public area: {}", e);
            soft_fido2::Error::Other
        })?;

        let public_blob = pub_read.marshall().map_err(|e| {
            error!("Failed to marshall parent public: {}", e);
            soft_fido2::Error::Other
        })?;

        let metadata = PortableParentMetadata {
            version: FORMAT_VERSION,
            public_blob,
            parent_name: name.value().to_vec(),
            persistent_handle: PARENT_PERSISTENT_HANDLE,
        };

        let metadata_path = self.storage_dir.join("portable_parent.json");
        let metadata_json = serde_json::to_vec(&metadata).map_err(|e| {
            error!("Failed to serialize parent metadata: {}", e);
            soft_fido2::Error::Other
        })?;

        std::fs::write(&metadata_path, metadata_json).map_err(|e| {
            error!("Failed to write parent metadata: {}", e);
            soft_fido2::Error::Other
        })?;

        info!(
            "Portable parent provisioned at persistent handle 0x{:08X}",
            PARENT_PERSISTENT_HANDLE
        );

        Ok(())
    }

    /// Remove the provisioned portable parent from the TPM
    pub fn remove(&self) -> Result<()> {
        let metadata = self.load_metadata()?;

        let mut context = self.context.lock().map_err(|e| {
            error!("Failed to lock TPM context: {}", e);
            soft_fido2::Error::Other
        })?;

        let persistent_tpm_handle = tss_esapi::handles::PersistentTpmHandle::new(
            metadata.persistent_handle,
        )
        .map_err(|e| {
            error!("Failed to create persistent TPM handle: {}", e);
            soft_fido2::Error::Other
        })?;
        let persistent_handle = context
            .tr_from_tpm_public(persistent_tpm_handle.into())
            .map_err(|e| {
                error!(
                    "Failed to register persistent handle in ESYS context: {}",
                    e
                );
                soft_fido2::Error::Other
            })?;

        let persistent = Persistent::from(persistent_tpm_handle);

        context
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.evict_control(Provision::Owner, persistent_handle, persistent)
            })
            .map_err(|e| {
                error!("Failed to evict persistent parent key: {}", e);
                soft_fido2::Error::Other
            })?;

        info!(
            "Portable parent evicted from persistent handle 0x{:08X}",
            metadata.persistent_handle
        );

        Ok(())
    }
}

/// Derived parent key material
pub struct ParentMaterial {
    pub private: Zeroizing<Vec<u8>>,
    pub pub_x: Zeroizing<Vec<u8>>,
    pub pub_y: Zeroizing<Vec<u8>>,
    pub seed_value: Zeroizing<Vec<u8>>,
}

/// Derive deterministic parent key material from seed
pub fn derive_parent_material(seed: &[u8]) -> Result<ParentMaterial> {
    use hkdf::Hkdf;
    use p256::elliptic_curve::PrimeField;
    use p256::elliptic_curve::bigint::ArrayEncoding;
    use p256::elliptic_curve::sec1::ToSec1Point;
    use p256::{ProjectivePoint, Scalar};
    use sha2::Sha256;

    let hkdf = Hkdf::<Sha256>::new(Some(b"passless.portable.v1"), seed);

    let mut scalar_bytes = Zeroizing::new(vec![0u8; 32]);
    hkdf.expand(b"parent-ecc-key", &mut scalar_bytes)
        .map_err(|e| {
            error!("HKDF expand failed for parent-ecc-key: {}", e);
            soft_fido2::Error::Other
        })?;

    let n = p256::U256::from_be_slice(&P256_ORDER);
    let scalar_int = p256::U256::from_be_slice(&scalar_bytes);
    let n_minus_1 = n - p256::U256::ONE;
    let reduced = scalar_int % n_minus_1;
    let scalar_value = reduced + p256::U256::ONE;

    let scalar_bytes_be: [u8; 32] = scalar_value.to_be_byte_array().into();

    let field_bytes = p256::FieldBytes::try_from(scalar_bytes_be.as_slice()).map_err(|_| {
        error!("Failed to create FieldBytes from scalar");
        soft_fido2::Error::Other
    })?;
    let scalar = Scalar::from_repr(field_bytes)
        .into_option()
        .ok_or_else(|| {
            error!("Failed to create scalar from bytes");
            soft_fido2::Error::Other
        })?;

    let public_point = ProjectivePoint::GENERATOR * scalar;
    let affine = public_point.to_affine();
    let point = affine.to_sec1_point(false);

    let pub_x = Zeroizing::new(point.x().unwrap().to_vec());
    let pub_y = Zeroizing::new(point.y().unwrap().to_vec());

    let hkdf2 = Hkdf::<Sha256>::new(Some(b"passless.portable.v1"), seed);
    let mut seed_value = Zeroizing::new(vec![0u8; 32]);
    hkdf2
        .expand(b"parent-seed-value", &mut seed_value)
        .map_err(|e| {
            error!("HKDF expand failed for parent-seed-value: {}", e);
            soft_fido2::Error::Other
        })?;

    Ok(ParentMaterial {
        private: Zeroizing::new(scalar_bytes_be.to_vec()),
        pub_x,
        pub_y,
        seed_value,
    })
}

/// Build the public template for the portable parent
pub fn build_parent_public(pub_x: &[u8], pub_y: &[u8]) -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(false)
        .with_fixed_parent(false)
        .with_sensitive_data_origin(false)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_restricted(true)
        .build()
        .map_err(|e| {
            error!("Failed to build parent object attributes: {}", e);
            soft_fido2::Error::Other
        })?;

    let ecc_params = PublicEccParametersBuilder::new()
        .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
        .with_ecc_scheme(EccScheme::Null)
        .with_curve(EccCurve::NistP256)
        .with_is_signing_key(false)
        .with_is_decryption_key(true)
        .with_restricted(true)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()
        .map_err(|e| {
            error!("Failed to build parent ECC parameters: {}", e);
            soft_fido2::Error::Other
        })?;

    let x_param = EccParameter::try_from(pub_x.to_vec()).map_err(|e| {
        error!("Failed to create EccParameter for x: {}", e);
        soft_fido2::Error::Other
    })?;

    let y_param = EccParameter::try_from(pub_y.to_vec()).map_err(|e| {
        error!("Failed to create EccParameter for y: {}", e);
        soft_fido2::Error::Other
    })?;

    let unique = EccPoint::new(x_param, y_param);

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(unique)
        .build()
        .map_err(|e| {
            error!("Failed to build parent public: {}", e);
            soft_fido2::Error::Other
        })
}

/// Wrap sensitive data for TPM2_Import
pub fn wrap_for_import(
    material: &ParentMaterial,
    primary_pub_x: &[u8],
    primary_pub_y: &[u8],
    parent_public: &Public,
) -> Result<(
    tss_esapi::structures::Private,
    tss_esapi::structures::EncryptedSecret,
)> {
    use p256::PublicKey;
    use p256::ecdh::EphemeralSecret;
    use p256::elliptic_curve::Generate;
    use p256::elliptic_curve::sec1::ToSec1Point;

    let eph_secret = EphemeralSecret::generate();
    let eph_public = eph_secret.public_key();
    let eph_point = eph_public.to_sec1_point(false);
    let eph_x = eph_point.x().unwrap();
    let eph_y = eph_point.y().unwrap();

    let primary_pub_key = PublicKey::from_sec1_bytes(&{
        let mut bytes = vec![0x04];
        bytes.extend_from_slice(primary_pub_x);
        bytes.extend_from_slice(primary_pub_y);
        bytes
    })
    .map_err(|e| {
        error!("Failed to parse primary public key: {}", e);
        soft_fido2::Error::Other
    })?;

    let shared_secret = eph_secret.diffie_hellman(&primary_pub_key);
    let z = shared_secret.raw_secret_bytes();

    let label = b"DUPLICATE\x00";
    let seed = kdf::kdfe(z, label, eph_x, primary_pub_x, 256);

    let parent_tpmt = parent_public.marshall().map_err(|e| {
        error!("Failed to marshall parent public: {}", e);
        soft_fido2::Error::Other
    })?;

    let name = compute_name(&parent_tpmt);

    let sensitive = Sensitive::Ecc {
        auth_value: tss_esapi::structures::Auth::default(),
        seed_value: tss_esapi::structures::Digest::try_from(material.seed_value.as_slice())
            .map_err(|e| {
                error!("Failed to create Digest for seed_value: {}", e);
                soft_fido2::Error::Other
            })?,
        sensitive: EccParameter::try_from(material.private.as_slice()).map_err(|e| {
            error!("Failed to create EccParameter for private: {}", e);
            soft_fido2::Error::Other
        })?,
    };

    let sensb = SensitiveBuffer::try_from(sensitive)
        .map_err(|e| {
            error!("Failed to create SensitiveBuffer: {}", e);
            soft_fido2::Error::Other
        })?
        .marshall()
        .map_err(|e| {
            error!("Failed to marshall SensitiveBuffer: {}", e);
            soft_fido2::Error::Other
        })?;

    let outerkey = kdf::kdfa(&seed, b"STORAGE", &name, b"", 128);
    let dupsens = kdf::aes_128_cfb_encrypt(&outerkey, &sensb);

    let hmackey = kdf::kdfa(&seed, b"INTEGRITY", b"", b"", 256);
    let hmac_data = kdf::hmac_sha256(&hmackey, &[dupsens.as_slice(), &name].concat());

    let mut duplicate_bytes = Vec::new();
    duplicate_bytes.extend_from_slice(&(hmac_data.len() as u16).to_be_bytes());
    duplicate_bytes.extend_from_slice(&hmac_data);
    duplicate_bytes.extend_from_slice(&dupsens);

    let duplicate =
        tss_esapi::structures::Private::try_from(duplicate_bytes.clone()).map_err(|e| {
            error!("Failed to create Private from duplicate: {}", e);
            soft_fido2::Error::Other
        })?;

    let mut in_sym_seed_content = Vec::new();
    in_sym_seed_content.extend_from_slice(&(eph_x.len() as u16).to_be_bytes());
    in_sym_seed_content.extend_from_slice(eph_x);
    in_sym_seed_content.extend_from_slice(&(eph_y.len() as u16).to_be_bytes());
    in_sym_seed_content.extend_from_slice(eph_y);

    let in_sym_seed = tss_esapi::structures::EncryptedSecret::try_from(in_sym_seed_content.clone())
        .map_err(|e| {
            error!("Failed to create EncryptedSecret: {}", e);
            soft_fido2::Error::Other
        })?;

    Ok((duplicate, in_sym_seed))
}

/// Compute TPM name from TPMT_PUBLIC
pub fn compute_name(tpmt_public: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let mut name = Vec::with_capacity(2 + 32);
    name.extend_from_slice(&0x000Bu16.to_be_bytes());
    name.extend_from_slice(&sha2::Sha256::digest(tpmt_public));
    name
}

#[allow(dead_code)]
pub fn build_import_child_public(pub_x: &[u8], pub_y: &[u8]) -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(false)
        .with_fixed_parent(false)
        .with_sensitive_data_origin(false)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_restricted(false)
        .build()
        .map_err(|e| {
            error!("Failed to build import child object attributes: {}", e);
            soft_fido2::Error::Other
        })?;

    let ecc_params = PublicEccParametersBuilder::new()
        .with_symmetric(SymmetricDefinitionObject::Null)
        .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_curve(EccCurve::NistP256)
        .with_is_signing_key(true)
        .with_is_decryption_key(false)
        .with_restricted(false)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()
        .map_err(|e| {
            error!("Failed to build import child ECC parameters: {}", e);
            soft_fido2::Error::Other
        })?;

    let x_param = EccParameter::try_from(pub_x.to_vec()).map_err(|e| {
        error!("Failed to create EccParameter for x: {}", e);
        soft_fido2::Error::Other
    })?;

    let y_param = EccParameter::try_from(pub_y.to_vec()).map_err(|e| {
        error!("Failed to create EccParameter for y: {}", e);
        soft_fido2::Error::Other
    })?;

    let unique = EccPoint::new(x_param, y_param);

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(unique)
        .build()
        .map_err(|e| {
            error!("Failed to build import child public: {}", e);
            soft_fido2::Error::Other
        })
}

#[allow(dead_code)]
pub fn wrap_child_for_import(
    private_scalar: &[u8],
    seed_value: &[u8],
    parent_pub_x: &[u8],
    parent_pub_y: &[u8],
    child_public: &Public,
) -> Result<(
    tss_esapi::structures::Private,
    tss_esapi::structures::EncryptedSecret,
)> {
    use p256::PublicKey;
    use p256::ecdh::EphemeralSecret;
    use p256::elliptic_curve::Generate;
    use p256::elliptic_curve::sec1::ToSec1Point;

    let eph_secret = EphemeralSecret::generate();
    let eph_public = eph_secret.public_key();
    let eph_point = eph_public.to_sec1_point(false);
    let eph_x = eph_point.x().unwrap();
    let eph_y = eph_point.y().unwrap();

    let parent_pub_key = PublicKey::from_sec1_bytes(&{
        let mut bytes = vec![0x04];
        bytes.extend_from_slice(parent_pub_x);
        bytes.extend_from_slice(parent_pub_y);
        bytes
    })
    .map_err(|e| {
        error!("Failed to parse parent public key for child import: {}", e);
        soft_fido2::Error::Other
    })?;

    let shared_secret = eph_secret.diffie_hellman(&parent_pub_key);
    let z = shared_secret.raw_secret_bytes();

    let label = b"DUPLICATE\x00";
    let seed = kdf::kdfe(z, label, eph_x, parent_pub_x, 256);

    let child_tpmt = child_public.marshall().map_err(|e| {
        error!("Failed to marshall child public: {}", e);
        soft_fido2::Error::Other
    })?;

    let name = compute_name(&child_tpmt);

    let sensitive = Sensitive::Ecc {
        auth_value: tss_esapi::structures::Auth::default(),
        seed_value: tss_esapi::structures::Digest::try_from(seed_value).map_err(|e| {
            error!("Failed to create Digest for child seed_value: {}", e);
            soft_fido2::Error::Other
        })?,
        sensitive: EccParameter::try_from(private_scalar.to_vec()).map_err(|e| {
            error!("Failed to create EccParameter for child scalar: {}", e);
            soft_fido2::Error::Other
        })?,
    };

    let sensb = SensitiveBuffer::try_from(sensitive)
        .map_err(|e| {
            error!("Failed to create SensitiveBuffer for child: {}", e);
            soft_fido2::Error::Other
        })?
        .marshall()
        .map_err(|e| {
            error!("Failed to marshall child SensitiveBuffer: {}", e);
            soft_fido2::Error::Other
        })?;

    let outerkey = kdf::kdfa(&seed, b"STORAGE", &name, b"", 128);
    let dupsens = kdf::aes_128_cfb_encrypt(&outerkey, &sensb);

    let hmackey = kdf::kdfa(&seed, b"INTEGRITY", b"", b"", 256);
    let hmac_data = kdf::hmac_sha256(&hmackey, &[dupsens.as_slice(), &name].concat());

    let mut duplicate_bytes = Vec::new();
    duplicate_bytes.extend_from_slice(&(hmac_data.len() as u16).to_be_bytes());
    duplicate_bytes.extend_from_slice(&hmac_data);
    duplicate_bytes.extend_from_slice(&dupsens);

    let duplicate = tss_esapi::structures::Private::try_from(duplicate_bytes).map_err(|e| {
        error!("Failed to create Private from child duplicate: {}", e);
        soft_fido2::Error::Other
    })?;

    let mut in_sym_seed_content = Vec::new();
    in_sym_seed_content.extend_from_slice(&(eph_x.len() as u16).to_be_bytes());
    in_sym_seed_content.extend_from_slice(eph_x);
    in_sym_seed_content.extend_from_slice(&(eph_y.len() as u16).to_be_bytes());
    in_sym_seed_content.extend_from_slice(eph_y);

    let in_sym_seed = tss_esapi::structures::EncryptedSecret::try_from(in_sym_seed_content)
        .map_err(|e| {
            error!("Failed to create EncryptedSecret for child: {}", e);
            soft_fido2::Error::Other
        })?;

    Ok((duplicate, in_sym_seed))
}

/// Create a temporary primary key for import operations
pub fn create_temp_primary(context: &mut Context) -> Result<tss_esapi::handles::KeyHandle> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_restricted(true)
        .build()
        .map_err(|e| {
            error!("Failed to build object attributes: {}", e);
            soft_fido2::Error::Other
        })?;

    let ecc_params = PublicEccParametersBuilder::new()
        .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
        .with_ecc_scheme(EccScheme::Null)
        .with_curve(EccCurve::NistP256)
        .with_is_signing_key(false)
        .with_is_decryption_key(true)
        .with_restricted(true)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()
        .map_err(|e| {
            error!("Failed to build ECC parameters: {}", e);
            soft_fido2::Error::Other
        })?;

    let primary_pub = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| {
            error!("Failed to build primary key public: {}", e);
            soft_fido2::Error::Other
        })?;

    let primary_result = context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, primary_pub, None, None, None, None)
        })
        .map_err(|e| {
            error!("Failed to create temporary primary key: {}", e);
            soft_fido2::Error::Other
        })?;

    Ok(primary_result.key_handle)
}
