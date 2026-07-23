//! TPM 2.0 PIN storage

use crate::pin_storage::{PinStorage, SerializablePinState};
use crate::util::{create_secure_dir_all, create_secure_file};

use soft_fido2::{PinState, StatusCode};

use std::io::Write;
use std::path::PathBuf;

use log::{debug, info, warn};

const PIN_STATE_FILENAME: &str = "pin_state.json.tpm";
const PORTABLE_PIN_STATE_FILENAME: &str = "pin_state.json.tpm.portable";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TpmPinStorageMode {
    Legacy,
    Portable,
}

/// TPM 2.0 PIN storage
///
/// Stores PIN state as TPM-sealed data.
pub struct TpmPinStorage {
    path: PathBuf,
    storage_dir: PathBuf,
    tcti: String,
    mode: TpmPinStorageMode,
}

impl TpmPinStorage {
    /// Create a new device-local (legacy) TPM PIN storage.
    pub fn new(storage_dir: PathBuf, tcti: Option<String>) -> Self {
        let path = storage_dir.join(PIN_STATE_FILENAME);
        let tcti = tcti.unwrap_or_else(|| "device:/dev/tpmrm0".to_string());
        debug!("TPM PIN storage path: {}, TCTI: {}", path.display(), tcti);
        Self {
            path,
            storage_dir: storage_dir.clone(),
            tcti,
            mode: TpmPinStorageMode::Legacy,
        }
    }

    /// Create a portable TPM PIN storage that seals under the portable parent.
    ///
    /// Requires the portable parent to be provisioned (via `passless tpm provision`).
    /// Returns an error at seal/unseal time if `portable_parent.json` is missing.
    pub fn new_portable(storage_dir: PathBuf, tcti: Option<String>) -> Self {
        let path = storage_dir.join(PORTABLE_PIN_STATE_FILENAME);
        let tcti = tcti.unwrap_or_else(|| "device:/dev/tpmrm0".to_string());
        debug!(
            "TPM PIN storage (portable) path: {}, TCTI: {}",
            path.display(),
            tcti
        );
        Self {
            path,
            storage_dir,
            tcti,
            mode: TpmPinStorageMode::Portable,
        }
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
            create_secure_dir_all(parent).map_err(|e| {
                warn!("Failed to create directory: {}", e);
                StatusCode::Other
            })?;
        }

        let mut file = create_secure_file(&self.path).map_err(|e| {
            warn!("Failed to create sealed PIN state file: {}", e);
            StatusCode::Other
        })?;

        file.write_all(&sealed_data).map_err(|e| {
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
            use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
            use tss_esapi::structures::{
                KeyedHashScheme, PublicBuilder, PublicKeyedHashParameters, SensitiveData,
                SymmetricDefinitionObject,
            };
            use tss_esapi::traits::Marshall;
            use tss_esapi::tss2_esys::{TPM2B_PRIVATE, TPM2B_PUBLIC};
            use tss_esapi::{Context, Tcti};
            use zeroize::Zeroizing;

            #[derive(serde::Serialize, serde::Deserialize)]
            struct SealedBlob {
                #[serde(default, skip_serializing_if = "Option::is_none")]
                mode: Option<String>,
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

            let (parent_key, is_portable_parent) = if self.mode == TpmPinStorageMode::Portable {
                (self.load_portable_parent(&mut context)?, true)
            } else {
                (self.create_legacy_primary(&mut context)?, false)
            };

            let fixed_tpm = !is_portable_parent;
            let fixed_parent = !is_portable_parent;

            let sealing_attributes = ObjectAttributesBuilder::new()
                .with_fixed_tpm(fixed_tpm)
                .with_fixed_parent(fixed_parent)
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
            let nonce = Nonce::try_from(&nonce_bytes[..]).expect("valid nonce length");

            let cipher = Aes256Gcm::new_from_slice(&aes_key).map_err(|e| {
                warn!("Failed to create AES cipher: {:?}", e);
                StatusCode::Other
            })?;

            let encrypted_data = cipher.encrypt(&nonce, data).map_err(|e| {
                warn!("Failed to encrypt data with AES-GCM: {:?}", e);
                StatusCode::Other
            })?;

            let sensitive_data = SensitiveData::try_from(aes_key.to_vec()).map_err(|e| {
                warn!("Failed to create sensitive data for AES key: {:?}", e);
                StatusCode::Other
            })?;

            let create_result = context
                .create(
                    parent_key,
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

            if !is_portable_parent {
                context.flush_context(parent_key.into()).map_err(|e| {
                    warn!("Failed to flush parent key: {:?}", e);
                    StatusCode::Other
                })?;
            }

            let private_tpm: TPM2B_PRIVATE = create_result.out_private.into();
            let private_bytes = private_tpm.buffer[..private_tpm.size as usize].to_vec();

            let public_bytes = if is_portable_parent {
                create_result.out_public.marshall().map_err(|e| {
                    warn!("Failed to marshall public area: {:?}", e);
                    StatusCode::Other
                })?
            } else {
                #[allow(clippy::unnecessary_fallible_conversions)]
                let public_tpm: TPM2B_PUBLIC =
                    create_result.out_public.try_into().map_err(|e| {
                        warn!("Failed to convert public to TPM2B: {:?}", e);
                        StatusCode::Other
                    })?;

                unsafe {
                    let ptr = &public_tpm as *const TPM2B_PUBLIC as *const u8;
                    std::slice::from_raw_parts(ptr, std::mem::size_of::<TPM2B_PUBLIC>()).to_vec()
                }
            };

            let mode_str = if is_portable_parent {
                Some("portable".to_string())
            } else {
                None
            };

            let sealed_blob = SealedBlob {
                mode: mode_str,
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
            use tss_esapi::traits::UnMarshall;
            use tss_esapi::tss2_esys::{TPM2B_PRIVATE, TPM2B_PUBLIC};
            use tss_esapi::{Context, Tcti};

            #[derive(serde::Serialize, serde::Deserialize)]
            struct SealedBlob {
                #[serde(default)]
                mode: Option<String>,
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

            let blob_is_portable = sealed_blob.mode.as_deref() == Some("portable");

            let (parent_key, is_portable_parent) = if blob_is_portable {
                (self.load_portable_parent(&mut context)?, true)
            } else {
                (self.create_legacy_primary(&mut context)?, false)
            };

            let mut private_tpm = TPM2B_PRIVATE {
                size: sealed_blob.tpm_private.len() as u16,
                buffer: [0u8; 1550],
            };
            private_tpm.buffer[..sealed_blob.tpm_private.len()]
                .copy_from_slice(&sealed_blob.tpm_private);

            let private = Private::try_from(private_tpm).map_err(|e| {
                warn!("Failed to convert TPM2B_PRIVATE to Private: {:?}", e);
                StatusCode::Other
            })?;

            let public = if is_portable_parent {
                Public::unmarshall(&sealed_blob.tpm_public).map_err(|e| {
                    warn!("Failed to unmarshall public area: {:?}", e);
                    StatusCode::Other
                })?
            } else {
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

                Public::try_from(public_tpm).map_err(|e| {
                    warn!("Failed to convert TPM2B_PUBLIC to Public: {:?}", e);
                    StatusCode::Other
                })?
            };

            let sealed_handle = context.load(parent_key, private, public).map_err(|e| {
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

            if !is_portable_parent {
                context.flush_context(parent_key.into()).map_err(|e| {
                    warn!("Failed to flush parent key: {:?}", e);
                    StatusCode::Other
                })?;
            }

            let aes_key = unsealed_key.value();
            if aes_key.len() != 32 {
                warn!(
                    "Unsealed key has wrong size: {} (expected 32)",
                    aes_key.len()
                );
                return Err(StatusCode::Other);
            }

            let nonce = Nonce::try_from(sealed_blob.nonce.as_slice()).expect("valid nonce length");
            let cipher = Aes256Gcm::new_from_slice(aes_key).map_err(|e| {
                warn!("Failed to create AES cipher: {:?}", e);
                StatusCode::Other
            })?;

            let decrypted_data = cipher
                .decrypt(&nonce, sealed_blob.encrypted_data.as_ref())
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

    #[cfg(feature = "tpm")]
    fn load_portable_parent(
        &self,
        context: &mut tss_esapi::Context,
    ) -> Result<tss_esapi::handles::KeyHandle, StatusCode> {
        use crate::storage::tpm::portable::parent::PortableParentMetadata;

        let metadata_path = self.storage_dir.join("portable_parent.json");
        let metadata_bytes = std::fs::read(&metadata_path).map_err(|e| {
            warn!(
                "Portable parent not provisioned (missing {}). Run `passless tpm provision` first: {}",
                metadata_path.display(),
                e
            );
            StatusCode::Other
        })?;
        let metadata: PortableParentMetadata =
            serde_json::from_slice(&metadata_bytes).map_err(|e| {
                warn!("Failed to parse portable parent metadata: {:?}", e);
                StatusCode::Other
            })?;

        let persistent_tpm_handle = tss_esapi::handles::PersistentTpmHandle::new(
            metadata.persistent_handle,
        )
        .map_err(|e| {
            warn!("Failed to create persistent TPM handle: {:?}", e);
            StatusCode::Other
        })?;

        let saved_sessions = context.sessions();
        context.set_sessions((None, None, None));

        let persistent_handle = context
            .tr_from_tpm_public(persistent_tpm_handle.into())
            .map_err(|e| {
                warn!(
                    "Failed to register persistent handle in ESYS context: {:?}",
                    e
                );
                StatusCode::Other
            })?;

        context.set_sessions(saved_sessions);

        Ok(tss_esapi::handles::KeyHandle::from(persistent_handle))
    }

    #[cfg(feature = "tpm")]
    fn create_legacy_primary(
        &self,
        context: &mut tss_esapi::Context,
    ) -> Result<tss_esapi::handles::KeyHandle, StatusCode> {
        use tss_esapi::attributes::ObjectAttributesBuilder;
        use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
        use tss_esapi::interface_types::key_bits::RsaKeyBits;
        use tss_esapi::interface_types::resource_handles::Hierarchy;
        use tss_esapi::structures::{
            PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaExponent, RsaScheme,
            SymmetricDefinitionObject,
        };

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

        Ok(primary_key_result.key_handle)
    }
}
