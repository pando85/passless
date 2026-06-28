//! TPM 2.0 PIN storage

use crate::pin_storage::{PinStorage, SerializablePinState};

use soft_fido2::{PinState, StatusCode};

use std::path::PathBuf;

use log::{debug, info, warn};

const PIN_STATE_FILENAME: &str = "pin_state.json.tpm";

/// TPM 2.0 PIN storage
///
/// Stores PIN state as TPM-sealed data.
pub struct TpmPinStorage {
    path: PathBuf,
    #[allow(dead_code)]
    tcti: String,
}

impl TpmPinStorage {
    /// Create a new TPM PIN storage
    pub fn new(storage_dir: PathBuf, tcti: Option<String>) -> Self {
        let path = storage_dir.join(PIN_STATE_FILENAME);
        let tcti = tcti.unwrap_or_else(|| "device:/dev/tpmrm0".to_string());
        debug!("TPM PIN storage path: {}, TCTI: {}", path.display(), tcti);
        Self { path, tcti }
    }
}

impl PinStorage for TpmPinStorage {
    fn load_pin_state(&self) -> Result<PinState, StatusCode> {
        if !self.path.exists() {
            debug!(
                "PIN state file does not exist, returning default state (no TPM operation needed)"
            );
            return Ok(PinState::new());
        }

        debug!(
            "Loading PIN state from TPM storage: {}",
            self.path.display()
        );

        let sealed_data = std::fs::read(&self.path).map_err(|e| {
            warn!("Failed to read sealed PIN state: {}", e);
            StatusCode::Other
        })?;

        let json_bytes = self.unseal(&sealed_data)?;

        let state: SerializablePinState = serde_json::from_slice(&json_bytes).map_err(|e| {
            warn!("Failed to parse PIN state: {}", e);
            StatusCode::InvalidParameter
        })?;

        Ok(state.into())
    }

    fn save_pin_state(&self, state: &PinState) -> Result<(), StatusCode> {
        if state.is_pin_set() {
            info!(
                "Saving PIN state (PIN is set, {} retries remaining)",
                state.retries
            );
        } else {
            info!("Skipping PIN state save (no PIN set, no changes needed)");
            return Ok(());
        }

        debug!("Saving PIN state to TPM storage: {}", self.path.display());

        let serializable = SerializablePinState::from(state);
        let json_bytes = serde_json::to_vec(&serializable).map_err(|_| StatusCode::Other)?;

        let sealed_data = self.seal(&json_bytes)?;

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                warn!("Failed to create directory: {}", e);
                StatusCode::Other
            })?;
        }

        std::fs::write(&self.path, &sealed_data).map_err(|e| {
            warn!("Failed to write sealed PIN state: {}", e);
            StatusCode::Other
        })?;

        debug!("PIN state saved successfully");
        Ok(())
    }
}

impl TpmPinStorage {
    fn seal(&self, data: &[u8]) -> Result<Vec<u8>, StatusCode> {
        #[cfg(feature = "tpm")]
        {
            use std::str::FromStr;

            use aes_gcm::Aes256Gcm;
            use aes_gcm::Nonce;
            use aes_gcm::aead::{Aead, KeyInit};
            use rand::RngCore;
            use rand::rngs::OsRng;
            use tss_esapi::attributes::ObjectAttributesBuilder;
            use tss_esapi::constants::SessionType;
            use tss_esapi::interface_types::algorithm::PublicAlgorithm;
            use tss_esapi::interface_types::key_bits::RsaKeyBits;
            use tss_esapi::interface_types::{
                algorithm::HashingAlgorithm, resource_handles::Hierarchy,
            };
            use tss_esapi::structures::{
                KeyedHashScheme, PublicBuilder, PublicKeyRsa, PublicKeyedHashParameters,
                PublicRsaParametersBuilder, RsaExponent, RsaScheme, SensitiveData,
                SymmetricDefinitionObject,
            };
            use tss_esapi::tss2_esys::{TPM2B_PRIVATE, TPM2B_PUBLIC};
            use tss_esapi::{Context, Tcti};
            use zeroize::Zeroizing;

            let tcti_conf = Tcti::from_str(&self.tcti).map_err(|e| {
                warn!(
                    "Failed to parse TCTI configuration '{}': {:?}",
                    self.tcti, e
                );
                StatusCode::Other
            })?;

            let mut context = Context::new(tcti_conf).map_err(|e| {
                warn!("Failed to connect to TPM: {:?}", e);
                StatusCode::Other
            })?;

            let session = context
                .start_auth_session(
                    None,
                    None,
                    None,
                    SessionType::Hmac,
                    SymmetricDefinitionObject::AES_128_CFB.into(),
                    HashingAlgorithm::Sha256,
                )
                .map_err(|e| {
                    warn!("Failed to start TPM auth session: {:?}", e);
                    StatusCode::Other
                })?
                .ok_or_else(|| {
                    warn!("TPM auth session returned None");
                    StatusCode::Other
                })?;

            context.set_sessions((Some(session), None, None));

            let object_attributes = ObjectAttributesBuilder::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(true)
                .with_decrypt(true)
                .with_restricted(true)
                .build()
                .map_err(|e| {
                    warn!("Failed to build object attributes: {:?}", e);
                    StatusCode::Other
                })?;

            let rsa_params = PublicRsaParametersBuilder::new()
                .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
                .with_scheme(RsaScheme::Null)
                .with_key_bits(RsaKeyBits::Rsa2048)
                .with_exponent(RsaExponent::default())
                .with_is_signing_key(false)
                .with_is_decryption_key(true)
                .with_restricted(true)
                .build()
                .map_err(|e| {
                    warn!("Failed to build RSA parameters: {:?}", e);
                    StatusCode::Other
                })?;

            let primary_pub = PublicBuilder::new()
                .with_public_algorithm(PublicAlgorithm::Rsa)
                .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                .with_object_attributes(object_attributes)
                .with_rsa_parameters(rsa_params)
                .with_rsa_unique_identifier(PublicKeyRsa::default())
                .build()
                .map_err(|e| {
                    warn!("Failed to build primary key public: {:?}", e);
                    StatusCode::Other
                })?;

            let primary_key_result = context
                .create_primary(Hierarchy::Owner, primary_pub, None, None, None, None)
                .map_err(|e| {
                    warn!("Failed to create primary key: {:?}", e);
                    StatusCode::Other
                })?;

            let primary_key = primary_key_result.key_handle;

            let sealing_attributes = ObjectAttributesBuilder::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_user_with_auth(true)
                .build()
                .map_err(|e| {
                    warn!("Failed to build sealing object attributes: {:?}", e);
                    StatusCode::Other
                })?;

            let sealing_pub = PublicBuilder::new()
                .with_public_algorithm(PublicAlgorithm::KeyedHash)
                .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                .with_object_attributes(sealing_attributes)
                .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
                .with_keyed_hash_unique_identifier(tss_esapi::structures::Digest::default())
                .build()
                .map_err(|e| {
                    warn!("Failed to build sealing object public: {:?}", e);
                    StatusCode::Other
                })?;

            let mut aes_key = [0u8; 32];
            OsRng.fill_bytes(&mut aes_key);

            let mut nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            let cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|e| {
                warn!("Failed to create AES cipher: {:?}", e);
                StatusCode::Other
            })?;

            let encrypted_data = cipher.encrypt(nonce, data).map_err(|e| {
                warn!("Failed to encrypt data with AES-GCM: {:?}", e);
                StatusCode::Other
            })?;

            let sensitive_data = SensitiveData::try_from(aes_key.to_vec()).map_err(|e| {
                warn!("Failed to create sensitive data for AES key: {:?}", e);
                StatusCode::Other
            })?;

            let create_result = context
                .create(
                    primary_key,
                    sealing_pub,
                    None,
                    Some(sensitive_data),
                    None,
                    None,
                )
                .map_err(|e| {
                    warn!("Failed to create sealed object: {:?}", e);
                    StatusCode::Other
                })?;

            context.flush_context(primary_key.into()).map_err(|e| {
                warn!("Failed to flush primary key: {:?}", e);
                StatusCode::Other
            })?;

            let private_tpm: TPM2B_PRIVATE = create_result.out_private.into();
            let private_bytes = private_tpm.buffer[..private_tpm.size as usize].to_vec();

            let public_tpm: TPM2B_PUBLIC = create_result.out_public.try_into().map_err(|e| {
                warn!("Failed to convert public to TPM2B: {:?}", e);
                StatusCode::Other
            })?;

            let public_bytes = unsafe {
                let ptr = &public_tpm as *const TPM2B_PUBLIC as *const u8;
                std::slice::from_raw_parts(ptr, std::mem::size_of::<TPM2B_PUBLIC>()).to_vec()
            };

            #[derive(serde::Serialize, serde::Deserialize)]
            struct SealedBlob {
                encrypted_data: Vec<u8>,
                nonce: Vec<u8>,
                tpm_private: Vec<u8>,
                tpm_public: Vec<u8>,
            }

            let sealed_blob = SealedBlob {
                encrypted_data,
                nonce: nonce_bytes.to_vec(),
                tpm_private: private_bytes,
                tpm_public: public_bytes,
            };

            let serialized = Zeroizing::new(serde_json::to_vec(&sealed_blob).map_err(|e| {
                warn!("Failed to serialize sealed blob: {:?}", e);
                StatusCode::Other
            })?);

            Ok(serialized.to_vec())
        }

        #[cfg(not(feature = "tpm"))]
        {
            warn!("TPM feature not enabled, storing unencrypted (not recommended)");
            Ok(data.to_vec())
        }
    }

    fn unseal(&self, sealed_data: &[u8]) -> Result<Vec<u8>, StatusCode> {
        #[cfg(feature = "tpm")]
        {
            use std::str::FromStr;

            use aes_gcm::aead::{Aead, KeyInit};
            use aes_gcm::{Aes256Gcm, Nonce};
            use tss_esapi::constants::SessionType;
            use tss_esapi::interface_types::algorithm::HashingAlgorithm;
            use tss_esapi::structures::{Private, Public, SymmetricDefinitionObject};
            use tss_esapi::tss2_esys::{TPM2B_PRIVATE, TPM2B_PUBLIC};
            use tss_esapi::{Context, Tcti};

            #[derive(serde::Serialize, serde::Deserialize)]
            struct SealedBlob {
                encrypted_data: Vec<u8>,
                nonce: Vec<u8>,
                tpm_private: Vec<u8>,
                tpm_public: Vec<u8>,
            }

            let tcti_conf = Tcti::from_str(&self.tcti).map_err(|e| {
                warn!(
                    "Failed to parse TCTI configuration '{}': {:?}",
                    self.tcti, e
                );
                StatusCode::Other
            })?;

            let mut context = Context::new(tcti_conf).map_err(|e| {
                warn!("Failed to connect to TPM: {:?}", e);
                StatusCode::Other
            })?;

            let session = context
                .start_auth_session(
                    None,
                    None,
                    None,
                    SessionType::Hmac,
                    SymmetricDefinitionObject::AES_128_CFB.into(),
                    HashingAlgorithm::Sha256,
                )
                .map_err(|e| {
                    warn!("Failed to start TPM auth session: {:?}", e);
                    StatusCode::Other
                })?
                .ok_or_else(|| {
                    warn!("TPM auth session returned None");
                    StatusCode::Other
                })?;

            context.set_sessions((Some(session), None, None));

            let sealed_blob: SealedBlob = serde_json::from_slice(sealed_data).map_err(|e| {
                warn!("Failed to deserialize sealed blob: {:?}", e);
                StatusCode::Other
            })?;

            let object_attributes = tss_esapi::attributes::ObjectAttributesBuilder::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(true)
                .with_decrypt(true)
                .with_restricted(true)
                .build()
                .map_err(|e| {
                    warn!("Failed to build object attributes: {:?}", e);
                    StatusCode::Other
                })?;

            use tss_esapi::interface_types::algorithm::PublicAlgorithm;
            use tss_esapi::interface_types::key_bits::RsaKeyBits;
            use tss_esapi::interface_types::resource_handles::Hierarchy;
            use tss_esapi::structures::{
                PublicKeyRsa, PublicRsaParametersBuilder, RsaExponent, RsaScheme,
            };

            let rsa_params = PublicRsaParametersBuilder::new()
                .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
                .with_scheme(RsaScheme::Null)
                .with_key_bits(RsaKeyBits::Rsa2048)
                .with_exponent(RsaExponent::default())
                .with_is_signing_key(false)
                .with_is_decryption_key(true)
                .with_restricted(true)
                .build()
                .map_err(|e| {
                    warn!("Failed to build RSA parameters: {:?}", e);
                    StatusCode::Other
                })?;

            let primary_pub = tss_esapi::structures::PublicBuilder::new()
                .with_public_algorithm(PublicAlgorithm::Rsa)
                .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                .with_object_attributes(object_attributes)
                .with_rsa_parameters(rsa_params)
                .with_rsa_unique_identifier(PublicKeyRsa::default())
                .build()
                .map_err(|e| {
                    warn!("Failed to build primary key public: {:?}", e);
                    StatusCode::Other
                })?;

            let primary_key_result = context
                .create_primary(Hierarchy::Owner, primary_pub, None, None, None, None)
                .map_err(|e| {
                    warn!("Failed to create primary key: {:?}", e);
                    StatusCode::Other
                })?;

            let primary_key = primary_key_result.key_handle;

            let mut private_tpm = TPM2B_PRIVATE {
                size: sealed_blob.tpm_private.len() as u16,
                buffer: [0u8; 1550],
            };
            private_tpm.buffer[..sealed_blob.tpm_private.len()]
                .copy_from_slice(&sealed_blob.tpm_private);

            let public_tpm: TPM2B_PUBLIC = unsafe {
                let mut public_struct: TPM2B_PUBLIC = std::mem::zeroed();
                let ptr = &mut public_struct as *mut TPM2B_PUBLIC as *mut u8;
                std::ptr::copy_nonoverlapping(
                    sealed_blob.tpm_public.as_ptr(),
                    ptr,
                    std::cmp::min(
                        sealed_blob.tpm_public.len(),
                        std::mem::size_of::<TPM2B_PUBLIC>(),
                    ),
                );
                public_struct
            };

            let private = Private::try_from(private_tpm).map_err(|e| {
                warn!("Failed to convert TPM2B_PRIVATE to Private: {:?}", e);
                StatusCode::Other
            })?;

            let public = Public::try_from(public_tpm).map_err(|e| {
                warn!("Failed to convert TPM2B_PUBLIC to Public: {:?}", e);
                StatusCode::Other
            })?;

            let sealed_handle = context.load(primary_key, private, public).map_err(|e| {
                warn!("Failed to load sealed object: {:?}", e);
                StatusCode::Other
            })?;

            let unsealed_key = context.unseal(sealed_handle.into()).map_err(|e| {
                warn!("Failed to unseal AES key: {:?}", e);
                StatusCode::Other
            })?;

            context.flush_context(sealed_handle.into()).map_err(|e| {
                warn!("Failed to flush sealed handle: {:?}", e);
                StatusCode::Other
            })?;

            context.flush_context(primary_key.into()).map_err(|e| {
                warn!("Failed to flush primary key: {:?}", e);
                StatusCode::Other
            })?;

            let aes_key = unsealed_key.value();
            if aes_key.len() != 32 {
                warn!(
                    "Unsealed key has wrong size: {} (expected 32)",
                    aes_key.len()
                );
                return Err(StatusCode::Other);
            }

            let nonce = Nonce::from_slice(&sealed_blob.nonce);
            let cipher = Aes256Gcm::new_from_slice(aes_key).map_err(|e| {
                warn!("Failed to create AES cipher: {:?}", e);
                StatusCode::Other
            })?;

            let decrypted_data = cipher
                .decrypt(nonce, sealed_blob.encrypted_data.as_ref())
                .map_err(|e| {
                    warn!("Failed to decrypt data with AES-GCM: {:?}", e);
                    StatusCode::Other
                })?;

            Ok(decrypted_data)
        }

        #[cfg(not(feature = "tpm"))]
        {
            Ok(sealed_data.to_vec())
        }
    }
}
