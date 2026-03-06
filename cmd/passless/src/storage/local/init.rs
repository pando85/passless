//! Local storage initialization
//!
//! Simple initialization that prompts user if storage directory doesn't exist.

use crate::notification::{
    show_error_notification, show_info_notification, show_yes_no_notification, YesNoResult,
};
use crate::util::create_secure_dir_all;
use passless_core::error::{Error, Result};

use std::path::Path;

use log::{info, warn};

/// Ensure local storage directory is initialized
///
/// If the directory doesn't exist, prompts the user via desktop notification
/// to confirm creation.
pub fn ensure_initialized(storage_path: &Path) -> Result<()> {
    if storage_path.exists() {
        return Ok(());
    }

    info!(
        "Local storage directory does not exist at {:?}",
        storage_path
    );

    match show_yes_no_notification(
        "Local Storage Not Initialized",
        &format!(
            "The local storage directory does not exist at:\n{}\n\nWould you like to create it now?",
            storage_path.display()
        ),
    ) {
        Ok(YesNoResult::Accepted) => {
            info!("User agreed to create local storage directory");
        }
        Ok(YesNoResult::Denied) => {
            warn!("Local storage initialization cancelled by user");
            let _ = show_info_notification(
                "Initialization Cancelled",
                "Local storage initialization cancelled by user",
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

    create_secure_dir_all(storage_path).map_err(|e| {
        let msg = format!("Failed to create storage directory: {}", e);
        let _ = show_error_notification("Initialization Failed", &msg);
        Error::Storage(msg)
    })?;

    info!("Created local storage directory at {:?}", storage_path);

    let _ = show_info_notification(
        "✅ Local Storage Initialized",
        &format!(
            "Successfully created local storage directory at:\n{}",
            storage_path.display()
        ),
    );

    Ok(())
}
