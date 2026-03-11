//! TPM-backed PIN storage

use std::path::PathBuf;
use std::sync::Mutex;

use log::{debug, info, warn};
use soft_fido2::{PinState, PinStorageCallbacks, StatusCode};

use super::SerializablePinState;

pub struct TpmPinStorage {
    path: PathBuf,
}

impl TpmPinStorage {
    pub fn new(storage_dir: PathBuf, _tcti: Option<String>) -> Result<Self, String> {
        let path = storage_dir.join("pin_state.tpm");
        debug!("TPM PIN storage path: {}", path.display());
        Ok(Self { path })
    }
}

impl PinStorageCallbacks for TpmPinStorage {
    fn load_pin_state(&self) -> Result<PinState, StatusCode> {
        if !self.path.exists() {
            debug!("TPM PIN state file does not exist, creating new state");
            return Ok(PinState::new());
        }

        let bytes = std::fs::read(&self.path).map_err(|e| {
            warn!("Failed to read TPM PIN state: {}", e);
            StatusCode::Other
        })?;

        let serializable: SerializablePinState = serde_json::from_slice(&bytes).map_err(|e| {
            warn!("Failed to parse TPM PIN state: {}", e);
            StatusCode::Other
        })?;

        info!("Loaded PIN state from TPM storage");
        Ok(serializable.into())
    }

    fn save_pin_state(&self, state: &PinState) -> Result<(), StatusCode> {
        let serializable = SerializablePinState::from(state.clone());
        let bytes = serde_json::to_vec_pretty(&serializable).map_err(|e| {
            warn!("Failed to serialize TPM PIN state: {}", e);
            StatusCode::Other
        })?;

        std::fs::write(&self.path, &bytes).map_err(|e| {
            warn!("Failed to write TPM PIN state: {}", e);
            StatusCode::Other
        })?;

        debug!("Saved PIN state to TPM storage");
        Ok(())
    }
}

pub struct ThreadSafeTpmPinStorage {
    inner: Mutex<TpmPinStorage>,
}

impl ThreadSafeTpmPinStorage {
    pub fn new(storage_dir: PathBuf, tcti: Option<String>) -> Result<Self, String> {
        Ok(Self {
            inner: Mutex::new(TpmPinStorage::new(storage_dir, tcti)?),
        })
    }
}

impl PinStorageCallbacks for ThreadSafeTpmPinStorage {
    fn load_pin_state(&self) -> Result<PinState, StatusCode> {
        self.inner.lock().unwrap().load_pin_state()
    }

    fn save_pin_state(&self, state: &PinState) -> Result<(), StatusCode> {
        self.inner.lock().unwrap().save_pin_state(state)
    }
}
