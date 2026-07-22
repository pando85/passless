//! TPM credential key provider implementation
//!
//! Implements the `CredentialKeyProvider` trait for TPM-resident credential keys.

use super::parent::{FORMAT_VERSION, PROVIDER_ID, PortableParent};

use soft_fido2::Result;
use soft_fido2_ctap::key_provider::{
    CredentialKey, CredentialKeyError, CredentialKeyProvider, CredentialKeyProviderId,
    GeneratedCredentialKey,
};
use soft_fido2_ctap::SecBytes;

use std::path::PathBuf;
use std::sync::Mutex;

use log::{debug, error, info};
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::handles::ObjectHandle;
use tss_esapi::interface_types::algorithm::PublicAlgorithm;
use tss_esapi::interface_types::key_bits::EccKeyBits;
use tss_esapi::interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy};
use tss_esapi::structures::{
    EccPoint, EccScheme, Public, PublicBuilder, PublicEccParametersBuilder,
    SymmetricDefinitionObject,
};
use tss_esapi::tss2_esys::{TPM2B_PRIVATE, TPM2B_PUBLIC};
use tss_esapi::Context;
use zeroize::Zeroizing;

/// COSE algorithm identifier for ES256 (ECDSA w/ SHA-256)
const COSE_ALG_ES256: i32 = -7;

/// TPM credential key provider
///
/// Generates and uses TPM-resident credential signing keys that can be
/// synchronized across multiple TPMs provisioned from the same recovery seed.
pub struct TpmCredentialKeyProvider {
    /// Portable parent manager
    parent: PortableParent,
    /// TPM context for key operations
    context: Mutex<Context>,
}

/// Opaque material format for TPM credential keys
///
/// Contains the TPM2B_PUBLIC and TPM2B_PRIVATE blobs for the credential signing key.
#[derive(serde::Serialize, serde::Deserialize)]
struct TpmKeyMaterial {
    /// TPM public area (TPM2B_PUBLIC serialized)
    public_blob: Vec<u8>,
    /// TPM private area (TPM2B_PRIVATE serialized)
    private_blob: Vec<u8>,
    /// COSE-encoded public key (for quick access without loading)
    cose_public_key: Vec<u8>,
}

impl TpmCredentialKeyProvider {
    /// Create a new TPM credential key provider
    pub fn new(storage_dir: PathBuf, tcti: Option<String>) -> Result<Self> {
        let parent = PortableParent::new(storage_dir, tcti)?;

        // Get a fresh context for key operations
        let tcti_conf = if let Some(ref tcti_str) = tcti {
            std::str::FromStr::from_str(tcti_str).map_err(|e| {
                error!("Failed to parse TCTI configuration: {}", e);
                soft_fido2::Error::Other
            })?
        } else {
            tss_esapi::Tcti::Device(Default::default())
        };

        let context = Context::new(tcti_conf).map_err(|e| {
            error!("Failed to create TPM context: {}", e);
            soft_fido2::Error::Other
        })?;

        Ok(Self {
            parent,
            context: Mutex::new(context),
        })
    }

    /// Check if the provider is ready (parent is provisioned)
    pub fn is_ready(&self) -> bool {
        self.parent.is_provisioned()
    }

    /// Generate a new ES256 credential key inside the TPM
    fn generate_es256_key(&self) -> Result<GeneratedCredentialKey> {
        debug!("Generating ES256 credential key in TPM");

        // Load parent metadata
        let metadata = self.parent.load_metadata()?;

        // Verify parent is still valid
        self.parent.verify_parent(&metadata)?;

        let mut context = self.context.lock().map_err(|e| {
            error!("Failed to lock TPM context: {}", e);
            soft_fido2::Error::Other
        })?;

        // Get the persistent parent handle
        let parent_handle = ObjectHandle::from(metadata.persistent_handle);

        // Build the public template for the credential signing key
        let key_public = self.build_signing_key_public()?;

        // Create the signing key under the portable parent
        let create_result = context
            .execute_with_nullauth_session(|ctx| {
                ctx.create(parent_handle, key_public, None, None, None, None)
            })
            .map_err(|e| {
                error!("Failed to create signing key: {}", e);
                soft_fido2::Error::Other
            })?;

        // Extract the public and private blobs
        let private_tpm: TPM2B_PRIVATE = create_result.out_private.into();
        let private_bytes = private_tpm.buffer[..private_tpm.size as usize].to_vec();

        let public_tpm: TPM2B_PUBLIC = create_result.out_public.try_into().map_err(|e| {
            error!("Failed to convert public to TPM2B: {:?}", e);
            soft_fido2::Error::Other
        })?;

        let public_bytes = unsafe {
            let ptr = &public_tpm as *const TPM2B_PUBLIC as *const u8;
            std::slice::from_raw_parts(ptr, std::mem::size_of::<TPM2B_PUBLIC>()).to_vec()
        };

        // Extract the public key point for COSE encoding
        let cose_public_key = self.extract_cose_public_key(&create_result.out_public)?;

        // Build the opaque material
        let material = TpmKeyMaterial {
            public_blob: public_bytes,
            private_blob: private_bytes,
            cose_public_key: cose_public_key.clone(),
        };

        let material_bytes = serde_json::to_vec(&material).map_err(|e| {
            error!("Failed to serialize key material: {}", e);
            soft_fido2::Error::Other
        })?;

        let key = CredentialKey::new(
            CredentialKeyProviderId::new(PROVIDER_ID),
            FORMAT_VERSION,
            SecBytes::from_slice(&material_bytes),
        );

        info!("Generated ES256 credential key in TPM");

        Ok(GeneratedCredentialKey {
            key,
            cose_public_key,
        })
    }

    /// Build the public template for a credential signing key
    fn build_signing_key_public(&self) -> Result<Public> {
        // Signing key attributes: sensitiveDataOrigin | sign | userWithAuth
        // fixedTPM and fixedParent should be set to prevent re-parenting
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_sign_encrypt(true)
            .with_restricted(false)
            .build()
            .map_err(|e| {
                error!("Failed to build signing key attributes: {}", e);
                soft_fido2::Error::Other
            })?;

        let ecc_params = PublicEccParametersBuilder::new()
            .with_symmetric(SymmetricDefinitionObject::Null)
            .with_scheme(EccScheme::EcDsa(
                tss_esapi::structures::SignatureScheme::Sha256,
            ))
            .with_curve(tss_esapi::interface_types::ecc::EccCurve::NistP256)
            .with_is_signing_key(true)
            .with_is_decryption_key(false)
            .with_restricted(false)
            .build()
            .map_err(|e| {
                error!("Failed to build signing key ECC parameters: {}", e);
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
                error!("Failed to build signing key public: {}", e);
                soft_fido2::Error::Other
            })
    }

    /// Extract the COSE-encoded public key from a TPM public area
    fn extract_cose_public_key(&self, public: &Public) -> Result<Vec<u8>> {
        // Extract the ECC point from the public area
        // This is a simplified implementation - needs proper COSE_Key encoding
        match public {
            Public::Ecc {
                parameters: _,
                unique,
            } => {
                // COSE_Key for ECDSA P-256:
                // 1: 2 (kty: EC2)
                // -1: 1 (crv: P-256)
                // -2: x-coordinate
                // -3: y-coordinate
                let mut cose_key = Vec::new();

                // This is a placeholder - proper COSE encoding needed
                // For now, return uncompressed point format (0x04 || x || y)
                let mut uncompressed = vec![0x04];
                uncompressed.extend_from_slice(&unique.x.buffer[..unique.x.size as usize]);
                uncompressed.extend_from_slice(&unique.y.buffer[..unique.y.size as usize]);

                Ok(uncompressed)
            }
            _ => {
                error!("Expected ECC public key");
                Err(soft_fido2::Error::Other)
            }
        }
    }

    /// Sign a message with a TPM credential key
    fn sign_with_tpm_key(
        &self,
        key_material: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>, CredentialKeyError> {
        debug!("Signing message with TPM credential key");

        // Deserialize the key material
        let material: TpmKeyMaterial = serde_json::from_slice(key_material).map_err(|e| {
            error!("Failed to deserialize key material: {}", e);
            CredentialKeyError::InvalidKeyMaterial
        })?;

        let mut context = self.context.lock().map_err(|e| {
            error!("Failed to lock TPM context: {}", e);
            CredentialKeyError::TransientFailure("Failed to lock TPM context".to_string())
        })?;

        // Load parent metadata
        let metadata = self.parent.load_metadata().map_err(|e| {
            error!("Failed to load parent metadata: {}", e);
            CredentialKeyError::TransientFailure("Failed to load parent".to_string())
        })?;

        // Get the persistent parent handle
        let parent_handle = ObjectHandle::from(metadata.persistent_handle);

        // Deserialize the private and public blobs
        let private_blob = TPM2B_PRIVATE {
            size: material.private_blob.len() as u16,
            buffer: {
                let mut buf = [0u8; 256];
                buf[..material.private_blob.len()].copy_from_slice(&material.private_blob);
                buf
            },
        };

        let public_blob: TPM2B_PUBLIC =
            unsafe { std::ptr::read(material.public_blob.as_ptr() as *const TPM2B_PUBLIC) };

        // Load the signing key under the portable parent
        let loaded_key = context
            .execute_with_nullauth_session(|ctx| {
                ctx.load(parent_handle, private_blob.into(), public_blob.into())
            })
            .map_err(|e| {
                error!("Failed to load signing key: {}", e);
                CredentialKeyError::InvalidKeyMaterial
            })?;

        // Sign the message, ensuring we flush the key even on failure
        let signature = match context.execute_with_nullauth_session(|ctx| {
            ctx.sign(
                loaded_key.into(),
                message,
                tss_esapi::structures::SignatureScheme::EcDsa(
                    tss_esapi::structures::HashScheme::Sha256,
                ),
                tss_esapi::structures::HashValue::from_sha256(&{
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(message);
                    hasher.finalize().to_vec()
                }),
            )
        }) {
            Ok(sig) => sig,
            Err(e) => {
                // Flush the key before returning error
                let _ = context.flush_context(loaded_key.into());
                error!("Failed to sign with TPM: {}", e);
                return Err(CredentialKeyError::TransientFailure(
                    "TPM signing failed".to_string(),
                ));
            }
        };

        // Convert TPM signature to DER-encoded ECDSA signature
        let der_signature = self.tpm_signature_to_der(&signature)?;

        Ok(der_signature)
    }

    /// Convert a TPM signature to DER-encoded ECDSA signature
    fn tpm_signature_to_der(
        &self,
        signature: &tss_esapi::structures::Signature,
    ) -> Result<Vec<u8>, CredentialKeyError> {
        match signature {
            tss_esapi::structures::Signature::EcDsa(ecdsa_sig) => {
                // Extract r and s values
                let r = &ecdsa_sig.signature_r.buffer[..ecdsa_sig.signature_r.size as usize];
                let s = &ecdsa_sig.signature_s.buffer[..ecdsa_sig.signature_s.size as usize];

                // DER encode: SEQUENCE { INTEGER r, INTEGER s }
                let mut der = Vec::new();

                // Encode r
                let r_der = Self::encode_der_integer(r);
                // Encode s
                let s_der = Self::encode_der_integer(s);

                // SEQUENCE header
                let seq_len = r_der.len() + s_der.len();
                der.push(0x30); // SEQUENCE tag
                der.push(seq_len as u8);
                der.extend_from_slice(&r_der);
                der.extend_from_slice(&s_der);

                Ok(der)
            }
            _ => {
                error!("Expected ECDSA signature");
                Err(CredentialKeyError::TransientFailure(
                    "Invalid signature type".to_string(),
                ))
            }
        }
    }

    /// Encode an integer as DER INTEGER
    fn encode_der_integer(value: &[u8]) -> Vec<u8> {
        let mut der = Vec::new();
        der.push(0x02); // INTEGER tag

        // Remove leading zeros but keep one if high bit is set
        let mut start = 0;
        while start < value.len() - 1 && value[start] == 0 {
            start += 1;
        }

        let needs_padding = value[start] & 0x80 != 0;
        let len = value.len() - start + if needs_padding { 1 } else { 0 };

        der.push(len as u8);
        if needs_padding {
            der.push(0x00);
        }
        der.extend_from_slice(&value[start..]);

        der
    }
}

impl CredentialKeyProvider for TpmCredentialKeyProvider {
    fn provider_id(&self) -> CredentialKeyProviderId {
        CredentialKeyProviderId::new(PROVIDER_ID)
    }

    fn supports_algorithm(&self, algorithm: i32) -> bool {
        algorithm == COSE_ALG_ES256
    }

    fn generate(&self, algorithm: i32) -> Result<GeneratedCredentialKey, CredentialKeyError> {
        if !self.supports_algorithm(algorithm) {
            return Err(CredentialKeyError::UnsupportedAlgorithm);
        }

        if !self.is_ready() {
            error!("TPM portable parent not provisioned");
            return Err(CredentialKeyError::TransientFailure(
                "TPM portable parent not provisioned".to_string(),
            ));
        }

        match algorithm {
            COSE_ALG_ES256 => self.generate_es256_key().map_err(|e| {
                error!("Failed to generate ES256 key: {:?}", e);
                CredentialKeyError::TransientFailure("Key generation failed".to_string())
            }),
            _ => Err(CredentialKeyError::UnsupportedAlgorithm),
        }
    }

    fn sign(
        &self,
        key: &CredentialKey,
        algorithm: i32,
        message: &[u8],
    ) -> Result<Vec<u8>, CredentialKeyError> {
        if key.provider.as_bytes() != PROVIDER_ID {
            return Err(CredentialKeyError::UnsupportedProvider);
        }

        if key.format_version != FORMAT_VERSION {
            return Err(CredentialKeyError::UnsupportedFormatVersion);
        }

        if !self.supports_algorithm(algorithm) {
            return Err(CredentialKeyError::UnsupportedAlgorithm);
        }

        if !self.is_ready() {
            error!("TPM portable parent not provisioned");
            return Err(CredentialKeyError::TransientFailure(
                "TPM portable parent not provisioned".to_string(),
            ));
        }

        self.sign_with_tpm_key(key.material.as_slice(), message)
    }

    fn delete(&self, _key: &CredentialKey) -> Result<(), CredentialKeyError> {
        // TPM keys are deleted when the credential file is deleted
        // No separate cleanup needed
        Ok(())
    }
}
