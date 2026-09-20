//! Initial uninitialized state

use super::directory_created::DirectoryCreated;

use crate::notification::{YesNoResult, show_info_notification, show_yes_no_notification};
use crate::storage::pass::{GpgBackend, gpg_id};
use crate::util::create_secure_dir_all;

use passless_core::error::{Error, Result};

use std::path::PathBuf;

use log::{debug, info, warn};

pub struct Uninitialized {
    pub(super) store_path: PathBuf,
    pub(super) scope_path: PathBuf,
    pub(super) gpg_backend: GpgBackend,
}

impl Uninitialized {
    pub fn new(store_path: PathBuf, scope_path: PathBuf, gpg_backend: GpgBackend) -> Self {
        Self {
            store_path,
            scope_path,
            gpg_backend,
        }
    }

    /// Check whether an effective recipient policy already applies to the
    /// configured Passless scope; returns a special error if yes (success case).
    pub fn check_if_initialized(self) -> Result<Self> {
        if let Some((gpg_id_file, _)) =
            gpg_id::find_nearest_gpg_id_for_dir(&self.store_path, &self.scope_path)?
        {
            debug!(
                "Password store scope {:?} already initialized by {:?}",
                self.scope_path, gpg_id_file
            );
            return Err(Error::Config("ALREADY_INITIALIZED".to_string()));
        }

        info!(
            "Password store scope not initialized at {:?}",
            self.scope_path
        );
        Ok(self)
    }

    pub fn prompt_user(self, allow_create_without_prompt: bool) -> Result<DirectoryCreated> {
        if !allow_create_without_prompt {
            match show_yes_no_notification(
                "Password Store Not Initialized",
                &format!(
                    "The Passless password-store scope is not initialized at:\n{}\n\nWould you like to initialize it now?",
                    self.scope_path.display()
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
        }

        if !self.scope_path.exists() {
            create_secure_dir_all(&self.scope_path).map_err(|e| {
                let msg = format!("Failed to create password store scope: {}", e);
                let _ = crate::notification::show_error_notification("Initialization Failed", &msg);
                Error::Storage(msg)
            })?;
            info!("Created password store scope at {:?}", self.scope_path);
        }

        Ok(DirectoryCreated {
            store_path: self.store_path,
            scope_path: self.scope_path,
            gpg_backend: self.gpg_backend,
            allow_create_without_prompt,
        })
    }
}
