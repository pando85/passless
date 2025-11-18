//! Initialization complete

use crate::error::Result;
use crate::notification::show_info_notification;

use std::path::PathBuf;

pub struct Complete {
    pub(super) store_path: PathBuf,
    pub(super) fingerprint: String,
}

impl Complete {
    pub fn finish(self) -> Result<()> {
        let _ = show_info_notification(
            "✅ Password Store Initialized",
            &format!(
                "Password store successfully initialized at:\n{}\n\nGPG Key: {}",
                self.store_path.display(),
                self.fingerprint
            ),
        );

        Ok(())
    }
}
