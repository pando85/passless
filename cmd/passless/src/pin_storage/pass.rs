//! Pass (password-store) PIN storage

use crate::pin_storage::{PinStorage, SerializablePinState};
use crate::storage::pass::GpgBackend;

use passless_core::error::{Error, Result};

use std::path::PathBuf;

use log::{debug, warn};
use prs_lib::crypto::IsContext;
use prs_lib::{Ciphertext, Plaintext};

const PIN_STATE_ENTRY: &str = "pin_state";

/// Pass (password-store) PIN storage
///
/// Stores PIN state as a GPG-encrypted entry in the password store.
pub struct PassPinStorage {
    store_path: PathBuf,
    fido2_path: PathBuf,
    gpg_backend: GpgBackend,
}

impl PassPinStorage {
    /// Create a new Pass PIN storage
    pub fn new(store_path: PathBuf, fido2_path: PathBuf, gpg_backend: GpgBackend) -> Self {
        debug!(
            "Pass PIN storage: store={}, path={}",
            store_path.display(),
            fido2_path.display()
        );
        Self {
            store_path,
            fido2_path,
            gpg_backend,
        }
    }

    fn get_entry_path(&self) -> PathBuf {
        self.store_path
            .join(&self.fido2_path)
            .join(format!("{}.gpg", PIN_STATE_ENTRY))
    }

    fn create_crypto_context(&self) -> Result<prs_lib::crypto::Context> {
        let proto = match self.gpg_backend {
            GpgBackend::Gpgme | GpgBackend::GnupgBin => prs_lib::crypto::Proto::Gpg,
        };

        let config = prs_lib::crypto::Config::from(proto);
        prs_lib::crypto::context(&config).map_err(|e| {
            warn!("Failed to create crypto context: {:?}", e);
            Error::Storage(format!("Failed to create crypto context: {:?}", e))
        })
    }

    fn load_recipients_from_gpg_id(&self) -> Result<prs_lib::Recipients> {
        let gpg_id_path = self.store_path.join(".gpg-id");
        match std::fs::read_to_string(&gpg_id_path) {
            Ok(content) => {
                let keys: Vec<prs_lib::Key> = content
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty() && !line.starts_with('#'))
                    .map(|key_id| {
                        let gpg_key = prs_lib::crypto::proto::gpg::Key {
                            fingerprint: key_id.to_string(),
                            user_ids: vec![],
                        };
                        prs_lib::Key::Gpg(gpg_key)
                    })
                    .collect();

                if keys.is_empty() {
                    return Err(Error::Storage(format!(
                        "No GPG key IDs found in {:?}",
                        gpg_id_path
                    )));
                }

                Ok(prs_lib::Recipients::from(keys))
            }
            Err(e) => Err(Error::Storage(format!(
                "Failed to read {:?}: {}",
                gpg_id_path, e
            ))),
        }
    }

    fn load_state(&self) -> std::result::Result<SerializablePinState, soft_fido2::StatusCode> {
        debug!("Loading PIN state from pass store");

        let path = self.get_entry_path();

        if !path.exists() {
            debug!("PIN state entry does not exist, returning default state");
            return Ok(SerializablePinState::default());
        }

        let encrypted_data = std::fs::read(&path).map_err(|e| {
            warn!("Failed to read PIN state entry: {}", e);
            soft_fido2::StatusCode::Other
        })?;

        let mut context = self.create_crypto_context().map_err(|e| {
            warn!("Failed to create crypto context: {:?}", e);
            soft_fido2::StatusCode::Other
        })?;

        let ciphertext = Ciphertext::from(encrypted_data);
        let plaintext = context.decrypt(ciphertext).map_err(|e| {
            warn!("Failed to decrypt PIN state: {:?}", e);
            soft_fido2::StatusCode::Other
        })?;

        SerializablePinState::from_json_bytes(plaintext.unsecure_ref()).map_err(|e| {
            warn!("Failed to parse PIN state: {:?}", e);
            soft_fido2::StatusCode::InvalidParameter
        })
    }

    fn save_state(
        &self,
        state: &SerializablePinState,
    ) -> std::result::Result<(), soft_fido2::StatusCode> {
        debug!("Saving PIN state to pass store");

        let bytes = state.to_json_bytes()?;

        let recipients = self.load_recipients_from_gpg_id().map_err(|e| {
            warn!("Failed to load GPG recipients: {:?}", e);
            soft_fido2::StatusCode::Other
        })?;

        let mut context = self.create_crypto_context().map_err(|e| {
            warn!("Failed to create crypto context: {:?}", e);
            soft_fido2::StatusCode::Other
        })?;

        let path = self.get_entry_path();

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                warn!("Failed to create directory: {}", e);
                soft_fido2::StatusCode::Other
            })?;
        }

        let plaintext = Plaintext::from(bytes);
        context
            .encrypt_file(&recipients, plaintext, &path)
            .map_err(|e| {
                warn!("Failed to encrypt PIN state: {:?}", e);
                soft_fido2::StatusCode::Other
            })?;

        debug!("PIN state saved successfully");
        Ok(())
    }
}

impl PinStorage for PassPinStorage {
    fn load_pin_state(&self) -> std::result::Result<soft_fido2::PinState, soft_fido2::StatusCode> {
        self.load_state().map(|s| s.into())
    }

    fn save_pin_state(
        &self,
        state: &soft_fido2::PinState,
    ) -> std::result::Result<(), soft_fido2::StatusCode> {
        let serializable = SerializablePinState::from(state);
        self.save_state(&serializable)
    }
}
