//! GPG key selected, ready to write .gpg-id file

use super::store_initialized::StoreInitialized;

use crate::notification::show_error_notification;

use passless_core::error::{Error, Result};

use std::fs;
use std::path::PathBuf;

use log::info;

pub struct GpgKeySelected {
    pub(super) store_path: PathBuf,
    pub(super) fingerprint: String,
    pub(super) allow_create_without_prompt: bool,
}

impl GpgKeySelected {
    pub fn write_gpg_id(self) -> Result<StoreInitialized> {
        let gpg_id_file = self.store_path.join(".gpg-id");

        fs::write(&gpg_id_file, format!("{}\n", self.fingerprint)).map_err(|e| {
            let msg = format!("Failed to write .gpg-id file: {}", e);
            let _ = show_error_notification("Initialization Failed", &msg);
            Error::Storage(msg)
        })?;

        info!("Wrote GPG key fingerprint to {:?}", gpg_id_file);

        Ok(StoreInitialized {
            store_path: self.store_path,
            fingerprint: self.fingerprint,
            allow_create_without_prompt: self.allow_create_without_prompt,
        })
    }
}
