//! Initial uninitialized state

use super::directory_created::DirectoryCreated;

use crate::notification::{YesNoResult, show_info_notification, show_yes_no_notification};
use crate::storage::pass::GpgBackend;

use passless_core::error::{Error, Result};

use std::fs;
use std::path::PathBuf;

use log::{debug, info, warn};

pub struct Uninitialized {
    pub(super) store_path: PathBuf,
    pub(super) gpg_backend: GpgBackend,
}

impl Uninitialized {
    pub fn new(store_path: PathBuf, gpg_backend: GpgBackend) -> Self {
        Self {
            store_path,
            gpg_backend,
        }
    }

    /// Check if already initialized; returns special error if yes (success case)
    pub fn check_if_initialized(self) -> Result<Self> {
        let gpg_id_file = self.store_path.join(".gpg-id");

        if gpg_id_file.exists() {
            debug!(
                "Password store already initialized at {:?}",
                self.store_path
            );
            return Err(Error::Config("ALREADY_INITIALIZED".to_string()));
        }

        info!("Password store not initialized at {:?}", self.store_path);
        Ok(self)
    }

    pub fn prompt_user(self) -> Result<DirectoryCreated> {
        match show_yes_no_notification(
            "Password Store Not Initialized",
            &format!(
                "The password store directory does not exist at:\n{}\n\nWould you like to initialize it now?",
                self.store_path.display()
            ),
        ) {
            Ok(YesNoResult::Accepted) => info!("User agreed to initialize"),
            Ok(YesNoResult::Denied) => {
                warn!("Initialization cancelled by user");
                let _ = show_info_notification(
                    "Initialization Cancelled",
                    "Password store initialization cancelled by user",
                );
                return Err(Error::Config("Initialization cancelled".to_string()));
            }
            Err(e) => {
                warn!("Failed to show initialization prompt: {}", e);
                return Err(Error::Config(format!("Failed to prompt: {}", e)));
            }
        }

        if !self.store_path.exists() {
            fs::create_dir_all(&self.store_path).map_err(|e| {
                let msg = format!("Failed to create store directory: {}", e);
                let _ = crate::notification::show_error_notification("Initialization Failed", &msg);
                Error::Storage(msg)
            })?;
            info!("Created store directory at {:?}", self.store_path);
        }

        Ok(DirectoryCreated {
            store_path: self.store_path,
            gpg_backend: self.gpg_backend,
        })
    }
}
