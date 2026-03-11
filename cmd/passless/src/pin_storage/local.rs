//! Local file system PIN storage

use std::path::PathBuf;
use std::sync::Mutex;

use log::debug;
use soft_fido2::{PinState, PinStorageCallbacks, StatusCode};

use super::{load_pin_state_from_file, save_pin_state_to_file};

pub struct LocalPinStorage {
    path: PathBuf,
}

impl LocalPinStorage {
    pub fn new(storage_dir: PathBuf) -> Self {
        let path = storage_dir.join("pin_state.json");
        debug!("Local PIN storage path: {}", path.display());
        Self { path }
    }
}

impl PinStorageCallbacks for LocalPinStorage {
    fn load_pin_state(&self) -> Result<PinState, StatusCode> {
        load_pin_state_from_file(&self.path)
    }

    fn save_pin_state(&self, state: &PinState) -> Result<(), StatusCode> {
        save_pin_state_to_file(&self.path, state)
    }
}

pub struct ThreadSafeLocalPinStorage {
    inner: Mutex<LocalPinStorage>,
}

impl ThreadSafeLocalPinStorage {
    pub fn new(storage_dir: PathBuf) -> Self {
        Self {
            inner: Mutex::new(LocalPinStorage::new(storage_dir)),
        }
    }
}

impl PinStorageCallbacks for ThreadSafeLocalPinStorage {
    fn load_pin_state(&self) -> Result<PinState, StatusCode> {
        self.inner.lock().unwrap().load_pin_state()
    }

    fn save_pin_state(&self, state: &PinState) -> Result<(), StatusCode> {
        self.inner.lock().unwrap().save_pin_state(state)
    }
}
