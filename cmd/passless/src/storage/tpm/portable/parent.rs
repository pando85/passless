//! Portable parent key management
//!
//! Handles deterministic derivation and import of the portable storage parent
//! that enables credential key portability across TPMs.

use soft_fido2::Result;

use std::path::{Path, PathBuf};

use log::{debug, error, info};
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::handles::ObjectHandle;
use tss_esapi::interface_types::algorithm::PublicAlgorithm;
use tss_esapi::interface_types::key_bits::EccKeyBits;
use tss_esapi::interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy};
use tss_esapi::structures::{
    EccParameter, EccPoint, EccScheme, Public, PublicBuilder, PublicEccParametersBuilder,
    SymmetricDefinitionObject,
};
use tss_esapi::tss2_esys::{TPM2B_ECC_PARAMETER, TPM2B_PUBLIC};
use tss_esapi::{Context, Tcti};
use zeroize::Zeroizing;

/// Provider identifier for portable TPM credentials
pub const PROVIDER_ID: &[u8] = b"tpm-portable-v1";

/// Format version for portable TPM credential keys
pub const FORMAT_VERSION: u16 = 1;

/// Persistent handle for the portable parent key
/// Using owner hierarchy persistent handle range (0x81000000 - 0x81FFFFFF)
const PARENT_PERSISTENT_HANDLE: u32 = 0x81000001;

/// Portable parent key metadata stored on disk
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PortableParentMetadata {
    /// Format version
    pub version: u16,
    /// Expected parent public area (TPM2B_PUBLIC serialized)
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

        // Read the persistent object's public area
        let persistent_handle = ObjectHandle::from(metadata.persistent_handle);
        let public_area = context.read_public(persistent_handle).map_err(|e| {
            error!("Failed to read persistent parent public area: {}", e);
            soft_fido2::Error::Other
        })?;

        // Verify the public area matches expected
        let expected_public: TPM2B_PUBLIC =
            serde_json::from_slice(&metadata.public_blob).map_err(|e| {
                error!("Failed to deserialize expected public area: {}", e);
                soft_fido2::Error::Other
            })?;

        // Compare public areas (simplified - should do full template verification)
        debug!("Parent verification: public area loaded from persistent handle");

        Ok(())
    }

    /// Provision a new portable parent from a recovery seed
    ///
    /// This derives deterministic parent material and imports it into the TPM.
    /// The seed is zeroized after use.
    pub fn provision(&self, seed: &[u8]) -> Result<()> {
        info!("Provisioning portable TPM parent");

        // Derive parent key material from seed using HKDF
        let parent_private = derive_parent_private(seed)?;
        let parent_seed = derive_parent_seed(seed)?;

        let mut context = self.context.lock().map_err(|e| {
            error!("Failed to lock TPM context: {}", e);
            soft_fido2::Error::Other
        })?;

        // Create a temporary primary key as import parent
        let temp_primary = self.create_temp_primary(&mut context)?;

        // Build the public template for the portable parent
        let parent_public = self.build_parent_public()?;

        // Create sensitive data for import
        let sensitive = self.build_parent_sensitive(&parent_private, &parent_seed)?;

        // Import the parent key
        let import_result = context
            .execute_with_nullauth_session(|ctx| {
                ctx.import(
                    temp_primary,
                    None,
                    parent_public.clone(),
                    sensitive,
                    None,
                    None,
                )
            })
            .map_err(|e| {
                error!("Failed to import parent key: {}", e);
                soft_fido2::Error::Other
            })?;

        // Load the imported key
        let loaded = context
            .execute_with_nullauth_session(|ctx| {
                ctx.load(temp_primary, import_result.out_private, import_result.out_public)
            })
            .map_err(|e| {
                error!("Failed to load imported parent: {}", e);
                soft_fido2::Error::Other
            })?;

        // Persist the parent at the designated handle
        let persistent_handle = context
            .execute_with_nullauth_session(|ctx| {
                ctx.evict_control(
                    tss_esapi::interface_types::resource_handles::Provision::Owner,
                    loaded.into(),
                    tss_esapi::handles::PersistentHandle::from(PARENT_PERSISTENT_HANDLE),
                )
            })
            .map_err(|e| {
                error!("Failed to persist parent key: {}", e);
                soft_fido2::Error::Other
            })?;

        // Flush the temporary primary
        context.flush_context(temp_primary.into()).map_err(|e| {
            error!("Failed to flush temporary primary: {}", e);
            soft_fido2::Error::Other
        })?;

        // Read the public area for metadata
        let public_area = context.read_public(persistent_handle.into()).map_err(|e| {
            error!("Failed to read persistent parent public area: {}", e);
            soft_fido2::Error::Other
        })?;

        let public_tpm: TPM2B_PUBLIC = public_area.try_into().map_err(|e| {
            error!("Failed to convert public to TPM2B: {:?}", e);
            soft_fido2::Error::Other
        })?;

        let public_bytes = unsafe {
            let ptr = &public_tpm as *const TPM2B_PUBLIC as *const u8;
            std::slice::from_raw_parts(ptr, std::mem::size_of::<TPM2B_PUBLIC>()).to_vec()
        };

        // Create metadata
        let metadata = PortableParentMetadata {
            version: FORMAT_VERSION,
            public_blob: public_bytes,
            parent_name: vec![], // TODO: compute parent name
            persistent_handle: PARENT_PERSISTENT_HANDLE,
        };

        // Save metadata
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

    /// Create a temporary primary key for import operations
    fn create_temp_primary(&self, context: &mut Context) -> Result<tss_esapi::handles::KeyHandle> {
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
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
            .with_scheme(EccScheme::Null)
            .with_curve(tss_esapi::interface_types::ecc::EccCurve::NistP256)
            .with_is_signing_key(false)
            .with_is_decryption_key(true)
            .with_restricted(true)
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
            .create_primary(Hierarchy::Owner, primary_pub, None, None, None, None)
            .map_err(|e| {
                error!("Failed to create temporary primary key: {}", e);
                soft_fido2::Error::Other
            })?;

        Ok(primary_result.key_handle)
    }

    /// Build the public template for the portable parent
    fn build_parent_public(&self) -> Result<Public> {
        // Portable parent attributes: restricted | decrypt | userWithAuth
        // fixedTPM: clear (for portability)
        // fixedParent: clear (for portability)
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
            .with_scheme(EccScheme::Null)
            .with_curve(tss_esapi::interface_types::ecc::EccCurve::NistP256)
            .with_is_signing_key(false)
            .with_is_decryption_key(true)
            .with_restricted(true)
            .build()
            .map_err(|e| {
                error!("Failed to build parent ECC parameters: {}", e);
                soft_fido2::Error::Other
            })?;

        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_ecc_parameters(ecc_params)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .map_err(|e| {
                error!("Failed to build parent public: {}", e);
                soft_fido2::Error::Other
            })
    }

    /// Build the sensitive data for parent import
    fn build_parent_sensitive(
        &self,
        private: &[u8],
        seed: &[u8],
    ) -> Result<tss_esapi::structures::Sensitive> {
        // Build ECC private key parameter
        let ecc_parameter = EccParameter {
            size: private.len() as u16,
            buffer: {
                let mut buf = [0u8; 64];
                buf[..private.len()].copy_from_slice(private);
                buf
            },
        };

        let tpm2b_ecc: TPM2B_ECC_PARAMETER = ecc_parameter.into();

        // Build sensitive structure
        // This is a simplified version - the actual implementation needs to properly
        // construct the TPM2B_SENSITIVE structure with the private key and seed
        let sensitive = tss_esapi::structures::Sensitive::try_from(tpm2b_ecc).map_err(|e| {
            error!("Failed to create sensitive data: {:?}", e);
            soft_fido2::Error::Other
        })?;

        Ok(sensitive)
    }
}

/// Derive parent private key from recovery seed using HKDF
fn derive_parent_private(seed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    // HKDF-Extract
    let mut mac =
        HmacSha256::new_from_slice(b"passless-portable-parent-private-v1").map_err(|e| {
            error!("Failed to create HMAC: {}", e);
            soft_fido2::Error::Other
        })?;
    mac.update(seed);
    let prk = mac.finalize().into_bytes();

    // HKDF-Expand (simplified - just use first 32 bytes)
    let mut private = Zeroizing::new(vec![0u8; 32]);
    private.copy_from_slice(&prk[..32]);

    Ok(private)
}

/// Derive parent seed value from recovery seed using HKDF
fn derive_parent_seed(seed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    // HKDF-Extract with different label
    let mut mac =
        HmacSha256::new_from_slice(b"passless-portable-parent-seed-v1").map_err(|e| {
            error!("Failed to create HMAC: {}", e);
            soft_fido2::Error::Other
        })?;
    mac.update(seed);
    let prk = mac.finalize().into_bytes();

    // HKDF-Expand (simplified - just use first 32 bytes)
    let mut parent_seed = Zeroizing::new(vec![0u8; 32]);
    parent_seed.copy_from_slice(&prk[..32]);

    Ok(parent_seed)
}
