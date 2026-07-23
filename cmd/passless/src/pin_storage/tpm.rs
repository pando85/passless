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
            self.seal_tpm(data)
        }

        #[cfg(not(feature = "tpm"))]
        {
            warn!("TPM feature not enabled, storing unencrypted (not recommended)");
            Ok(data.to_vec())
        }
    }

    #[cfg(feature = "tpm")]
    fn seal_tpm(&self, data: &[u8]) -> Result<Vec<u8>, StatusCode> {
        use aes_gcm::Aes256Gcm;
        use aes_gcm::Nonce;
        use aes_gcm::aead::{Aead, KeyInit};
        use rand::RngCore;
        use rand::rngs::OsRng;
        use tss_esapi::structures::SensitiveData;
        use zeroize::Zeroizing;

        use crate::storage::tpm::SealedBlob;

        let mut context = crate::storage::tpm::portable::context::create_tpm_context(Some(
            &self.tcti,
        ))
        .map_err(|e| {
            warn!("Failed to connect to TPM: {:?}", e);
            StatusCode::Other
        })?;

        self.setup_encrypted_session(&mut context)?;

        let (parent_key, is_portable_parent) = self.load_parent_key(&mut context)?;
        let sealing_pub = self.build_sealing_template(is_portable_parent)?;

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

        let private_bytes = self.serialize_private(create_result.out_private);
        let public_bytes = self.serialize_public(create_result.out_public, is_portable_parent)?;

        let sealed_blob = SealedBlob {
            mode: if is_portable_parent {
                Some("portable".to_string())
            } else {
                None
            },
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

    fn unseal(&self, sealed_data: &[u8]) -> Result<Vec<u8>, StatusCode> {
        #[cfg(feature = "tpm")]
        {
            self.unseal_tpm(sealed_data)
        }

        #[cfg(not(feature = "tpm"))]
        {
            Ok(sealed_data.to_vec())
        }
    }

    #[cfg(feature = "tpm")]
    fn unseal_tpm(&self, sealed_data: &[u8]) -> Result<Vec<u8>, StatusCode> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};

        use crate::storage::tpm::SealedBlob;

        let mut context = crate::storage::tpm::portable::context::create_tpm_context(Some(
            &self.tcti,
        ))
        .map_err(|e| {
            warn!("Failed to connect to TPM: {:?}", e);
            StatusCode::Other
        })?;

        self.setup_encrypted_session(&mut context)?;

        let sealed_blob: SealedBlob = serde_json::from_slice(sealed_data).map_err(|e| {
            warn!("Failed to deserialize sealed blob: {:?}", e);
            StatusCode::Other
        })?;

        let is_portable_parent = sealed_blob.mode.as_deref() == Some("portable");
        let (parent_key, _) = self.load_parent_key_for_mode(&mut context, is_portable_parent)?;

        let private = self.deserialize_private(&sealed_blob.tpm_private)?;
        let public = self.deserialize_public(&sealed_blob.tpm_public, is_portable_parent)?;

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

    #[cfg(feature = "tpm")]
    fn setup_encrypted_session(&self, context: &mut tss_esapi::Context) -> Result<(), StatusCode> {
        use tss_esapi::constants::SessionType;
        use tss_esapi::interface_types::algorithm::HashingAlgorithm;
        use tss_esapi::structures::SymmetricDefinitionObject;

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
        Ok(())
    }

    #[cfg(feature = "tpm")]
    fn load_parent_key(
        &self,
        context: &mut tss_esapi::Context,
    ) -> Result<(tss_esapi::handles::KeyHandle, bool), StatusCode> {
        let is_portable = self.mode == TpmPinStorageMode::Portable;
        let key = if is_portable {
            self.load_portable_parent(context)?
        } else {
            self.create_legacy_primary(context)?
        };
        Ok((key, is_portable))
    }

    #[cfg(feature = "tpm")]
    fn load_parent_key_for_mode(
        &self,
        context: &mut tss_esapi::Context,
        is_portable: bool,
    ) -> Result<(tss_esapi::handles::KeyHandle, bool), StatusCode> {
        let key = if is_portable {
            self.load_portable_parent(context)?
        } else {
            self.create_legacy_primary(context)?
        };
        Ok((key, is_portable))
    }

    #[cfg(feature = "tpm")]
    fn build_sealing_template(
        &self,
        is_portable: bool,
    ) -> Result<tss_esapi::structures::Public, StatusCode> {
        use tss_esapi::attributes::ObjectAttributesBuilder;
        use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
        use tss_esapi::structures::{KeyedHashScheme, PublicBuilder, PublicKeyedHashParameters};

        let fixed_tpm = !is_portable;
        let fixed_parent = !is_portable;

        let sealing_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(fixed_tpm)
            .with_fixed_parent(fixed_parent)
            .with_user_with_auth(true)
            .build()
            .map_err(|e| {
                warn!("Failed to build sealing object attributes: {:?}", e);
                StatusCode::Other
            })?;

        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(sealing_attributes)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
            .with_keyed_hash_unique_identifier(tss_esapi::structures::Digest::default())
            .build()
            .map_err(|e| {
                warn!("Failed to build sealing object public: {:?}", e);
                StatusCode::Other
            })
    }

    #[cfg(feature = "tpm")]
    fn serialize_private(&self, out_private: tss_esapi::structures::Private) -> Vec<u8> {
        use tss_esapi::tss2_esys::TPM2B_PRIVATE;

        let private_tpm: TPM2B_PRIVATE = out_private.into();
        private_tpm.buffer[..private_tpm.size as usize].to_vec()
    }

    #[cfg(feature = "tpm")]
    fn serialize_public(
        &self,
        out_public: tss_esapi::structures::Public,
        is_portable: bool,
    ) -> Result<Vec<u8>, StatusCode> {
        use tss_esapi::traits::Marshall;
        use tss_esapi::tss2_esys::TPM2B_PUBLIC;

        if is_portable {
            out_public.marshall().map_err(|e| {
                warn!("Failed to marshall public area: {:?}", e);
                StatusCode::Other
            })
        } else {
            #[allow(clippy::unnecessary_fallible_conversions)]
            let public_tpm: TPM2B_PUBLIC = out_public.try_into().map_err(|e| {
                warn!("Failed to convert public to TPM2B: {:?}", e);
                StatusCode::Other
            })?;

            Ok(unsafe {
                let ptr = &public_tpm as *const TPM2B_PUBLIC as *const u8;
                std::slice::from_raw_parts(ptr, std::mem::size_of::<TPM2B_PUBLIC>()).to_vec()
            })
        }
    }

    #[cfg(feature = "tpm")]
    fn deserialize_private(
        &self,
        tpm_private: &[u8],
    ) -> Result<tss_esapi::structures::Private, StatusCode> {
        use tss_esapi::structures::Private;
        use tss_esapi::tss2_esys::TPM2B_PRIVATE;

        let mut private_tpm = TPM2B_PRIVATE {
            size: tpm_private.len() as u16,
            buffer: [0u8; 1550],
        };
        private_tpm.buffer[..tpm_private.len()].copy_from_slice(tpm_private);

        Private::try_from(private_tpm).map_err(|e| {
            warn!("Failed to convert TPM2B_PRIVATE to Private: {:?}", e);
            StatusCode::Other
        })
    }

    #[cfg(feature = "tpm")]
    fn deserialize_public(
        &self,
        tpm_public: &[u8],
        is_portable: bool,
    ) -> Result<tss_esapi::structures::Public, StatusCode> {
        use tss_esapi::structures::Public;
        use tss_esapi::traits::UnMarshall;
        use tss_esapi::tss2_esys::TPM2B_PUBLIC;

        if is_portable {
            Public::unmarshall(tpm_public).map_err(|e| {
                warn!("Failed to unmarshall public area: {:?}", e);
                StatusCode::Other
            })
        } else {
            let public_tpm: TPM2B_PUBLIC = unsafe {
                let mut public_struct: TPM2B_PUBLIC = std::mem::zeroed();
                let ptr = &mut public_struct as *mut TPM2B_PUBLIC as *mut u8;
                std::ptr::copy_nonoverlapping(
                    tpm_public.as_ptr(),
                    ptr,
                    std::cmp::min(tpm_public.len(), std::mem::size_of::<TPM2B_PUBLIC>()),
                );
                public_struct
            };

            Public::try_from(public_tpm).map_err(|e| {
                warn!("Failed to convert TPM2B_PUBLIC to Public: {:?}", e);
                StatusCode::Other
            })
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
        use tss_esapi::interface_types::resource_handles::Hierarchy;

        crate::storage::tpm::create_rsa_primary(context, Hierarchy::Owner).map_err(|e| {
            warn!("Failed to create primary key: {:?}", e);
            StatusCode::Other
        })
    }
}
