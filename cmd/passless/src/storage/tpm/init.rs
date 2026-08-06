//! TPM storage initialization
//!
//! Simple initialization that prompts user if storage directory doesn't exist.

use crate::notification::{
    YesNoResult, show_error_notification, show_info_notification, show_yes_no_notification,
};
use crate::util::create_secure_dir_all;
use passless_core::error::{Error, Result};

use std::path::Path;

use log::{info, warn};

/// Ensure TPM storage directory is initialized
///
/// If the directory doesn't exist, prompts the user via desktop notification
/// to confirm creation.
pub fn ensure_initialized(storage_path: &Path, allow_create_without_prompt: bool) -> Result<()> {
    if storage_path.exists() {
        return Ok(());
    }

    info!("TPM storage directory does not exist at {:?}", storage_path);

    if !allow_create_without_prompt {
        match show_yes_no_notification(
            "TPM Storage Not Initialized",
            &format!(
                "The TPM storage directory does not exist at:\n{}\n\nWould you like to create it now?",
                storage_path.display()
            ),
        ) {
            Ok(YesNoResult::Accepted) => {
                info!("User agreed to create TPM storage directory");
            }
            Ok(YesNoResult::Denied) => {
                warn!("TPM storage initialization cancelled by user");
                let _ = show_info_notification(
                    "Initialization Cancelled",
                    "TPM storage initialization cancelled by user",
                );
                return Err(Error::Config("Initialization cancelled".to_string()));
            }
            Err(e) => {
                warn!("Failed to show initialization prompt: {}", e);
                return Err(Error::Config(format!(
                    "Failed to show initialization prompt: {}",
                    e
                )));
            }
        }
    }

    create_secure_dir_all(storage_path).map_err(|e| {
        let msg = format!("Failed to create storage directory: {}", e);
        let _ = show_error_notification("Initialization Failed", &msg);
        Error::Storage(msg)
    })?;

    info!("Created TPM storage directory at {:?}", storage_path);

    if !allow_create_without_prompt {
        let _ = show_info_notification(
            "✅ TPM Storage Initialized",
            &format!(
                "Successfully created TPM storage directory at:\n{}",
                storage_path.display()
            ),
        );
    }

    Ok(())
}
