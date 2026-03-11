//! Pass (password-store) PIN storage

use std::path::PathBuf;
use std::sync::Mutex;

use log::{debug, info, warn};
use prs_lib::Store;
use soft_fido2::{PinState, PinStorageCallbacks, StatusCode};

use super::SerializablePinState;

pub struct PassPinStorage {
    store: Store,
    path: String,
}

impl PassPinStorage {
    pub fn new(store_path: PathBuf, path: String) -> Result<Self, String> {
        let store = Store::open(store_path).map_err(|e| format!("Failed to open store: {}", e))?;
        debug!("Pass PIN storage path: {}/{}", store_path.display(), path);
        Ok(Self { store, path })
    }
}

impl PinStorageCallbacks for PassPinStorage {
    fn load_pin_state(&self) -> Result<PinState, StatusCode> {
        let secret_path = format!("{}/pin_state", self.path);

        let secret = match self.store.secret_at(&secret_path) {
            Ok(Some(s)) => s,
            Ok(None) => {
                debug!("PIN state does not exist in pass store, creating new state");
                return Ok(PinState::new());
            }
            Err(e) => {
                warn!("Failed to read PIN state from pass store: {}", e);
                return Err(StatusCode::Other);
            }
        };

        let content = secret.to_string_lossy();
        let serializable: SerializablePinState = serde_json::from_str(&content).map_err(|e| {
            warn!("Failed to parse PIN state from pass store: {}", e);
            StatusCode::Other
        })?;

        info!("Loaded PIN state from pass store");
        Ok(serializable.into())
    }

    fn save_pin_state(&self, state: &PinState) -> Result<(), StatusCode> {
        let secret_path = format!("{}/pin_state", self.path);
        let serializable = SerializablePinState::from(state.clone());
        let content = serde_json::to_string_pretty(&serializable).map_err(|e| {
            warn!("Failed to serialize PIN state: {}", e);
            StatusCode::Other
        })?;

        let secret = prs_lib::Secret::new(content);

        self.store
            .insert(&secret_path, &secret, false)
            .map_err(|e| {
                warn!("Failed to save PIN state to pass store: {}", e);
                StatusCode::Other
            })?;

        if self.store.has_git() {
            if let Err(e) = self.store.git_add_and_commit(&format!("Update PIN state")) {
                warn!("Failed to commit PIN state to git: {}", e);
            }
            if let Err(e) = self.store.git_push() {
                warn!("Failed to push PIN state to git: {}", e);
            }
        }

        debug!("Saved PIN state to pass store");
        Ok(())
    }
}

pub struct ThreadSafePassPinStorage {
    inner: Mutex<PassPinStorage>,
}

impl ThreadSafePassPinStorage {
    pub fn new(store_path: PathBuf, path: String) -> Result<Self, String> {
        Ok(Self {
            inner: Mutex::new(PassPinStorage::new(store_path, path)?),
        })
    }
}

impl PinStorageCallbacks for ThreadSafePassPinStorage {
    fn load_pin_state(&self) -> Result<PinState, StatusCode> {
        self.inner.lock().unwrap().load_pin_state()
    }

    fn save_pin_state(&self, state: &PinState) -> Result<(), StatusCode> {
        self.inner.lock().unwrap().save_pin_state(state)
    }
}
