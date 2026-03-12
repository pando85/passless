//! Local file system PIN storage

use crate::pin_storage::{PinStorage, SerializablePinState};
use crate::util::create_secure_file;

use soft_fido2::{PinState, StatusCode};

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use log::{debug, info, warn};

const PIN_STATE_FILENAME: &str = "pin_state.json";

/// Local file system PIN storage
///
/// Stores PIN state as a JSON file in the storage directory.
pub struct LocalPinStorage {
    path: PathBuf,
}

impl LocalPinStorage {
    /// Create a new local PIN storage
    pub fn new(storage_dir: PathBuf) -> Self {
        let path = storage_dir.join(PIN_STATE_FILENAME);
        debug!("Local PIN storage path: {}", path.display());
        Self { path }
    }

    fn load_state(&self) -> Result<SerializablePinState, StatusCode> {
        debug!("Loading PIN state from: {}", self.path.display());

        if !self.path.exists() {
            debug!("PIN state file does not exist, returning default state");
            return Ok(SerializablePinState::default());
        }

        let mut file = fs::File::open(&self.path).map_err(|e| {
            warn!("Failed to open PIN state file: {}", e);
            StatusCode::Other
        })?;

        let mut contents = Vec::new();
        file.read_to_end(&mut contents).map_err(|e| {
            warn!("Failed to read PIN state file: {}", e);
            StatusCode::Other
        })?;

        SerializablePinState::from_json_bytes(&contents).map_err(|e| {
            warn!("Failed to parse PIN state: {:?}", e);
            StatusCode::InvalidParameter
        })
    }

    fn save_state(&self, state: &SerializablePinState) -> Result<(), StatusCode> {
        debug!("Saving PIN state to: {}", self.path.display());

        let bytes = state.to_json_bytes()?;

        let mut file = create_secure_file(&self.path).map_err(|e| {
            warn!("Failed to create PIN state file: {}", e);
            StatusCode::Other
        })?;

        file.write_all(&bytes).map_err(|e| {
            warn!("Failed to write PIN state file: {}", e);
            StatusCode::Other
        })?;

        debug!("PIN state saved successfully");
        Ok(())
    }
}

impl PinStorage for LocalPinStorage {
    fn load_pin_state(&self) -> Result<PinState, StatusCode> {
        self.load_state().map(|s| s.into())
    }

    fn save_pin_state(&self, state: &PinState) -> Result<(), StatusCode> {
        let serializable = SerializablePinState::from(state);

        if state.is_pin_set() {
            info!(
                "Saving PIN state (PIN is set, {} retries remaining)",
                state.retries
            );
        } else {
            info!("Saving PIN state (no PIN set)");
        }

        self.save_state(&serializable)
    }
}
