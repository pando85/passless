//! Directory created, ready for GPG key selection

use super::gpg_key_selected::GpgKeySelected;
use crate::notification::{
    YesNoResult, show_error_notification, show_info_notification, show_yes_no_notification,
};

use crate::storage::pass::GpgBackend;

use passless_core::error::{Error, Result};

use std::path::PathBuf;

use log::{debug, info, warn};
use prs_lib::crypto::{self, Config, IsContext, Proto};

pub struct DirectoryCreated {
    pub(super) store_path: PathBuf,
    pub(super) gpg_backend: GpgBackend,
}

impl DirectoryCreated {
    pub fn select_gpg_key(self) -> Result<GpgKeySelected> {
        let fingerprint = select_gpg_key_interactive(self.gpg_backend)?;

        Ok(GpgKeySelected {
            store_path: self.store_path,
            fingerprint,
        })
    }
}

fn select_gpg_key_interactive(_gpg_backend: GpgBackend) -> Result<String> {
    let config = Config {
        proto: Proto::Gpg,
        gpg_tty: false,
        verbose: false,
    };

    let mut context = crypto::context(&config).map_err(|e| {
        let msg = format!("Failed to create crypto context: {:?}", e);
        let _ = show_error_notification("GPG Error", &msg);
        Error::Storage(msg)
    })?;

    let private_keys = context.keys_private().map_err(|e| {
        let msg = format!("Failed to list GPG keys: {:?}", e);
        let _ = show_error_notification("GPG Error", &msg);
        Error::Storage(msg)
    })?;

    if private_keys.is_empty() {
        warn!("No GPG keys found");
        let _ = show_error_notification(
            "No GPG Keys Found",
            "No GPG keys found on your system.\n\n\
             Please generate a GPG key first using:\n\
             gpg --full-generate-key\n\n\
             Then restart passless to complete initialization.",
        );
        return Err(Error::Config("No GPG keys found".to_string()));
    }

    if private_keys.len() == 1 {
        let key = &private_keys[0];
        let fingerprint = key.fingerprint(false);
        info!("Using only available GPG key: {}", fingerprint);

        return match show_yes_no_notification(
            "GPG Key Selection",
            &format!(
                "Found GPG key:\n{}\n\nUse this key for the password store?",
                key
            ),
        ) {
            Ok(YesNoResult::Accepted) => Ok(fingerprint),
            Ok(YesNoResult::Denied) => Err(Error::Config("Key selection cancelled".to_string())),
            Err(e) => Err(Error::Config(format!(
                "Failed to show key selection: {}",
                e
            ))),
        };
    }

    info!("Multiple GPG keys found, prompting user to select");

    let key_list: String = private_keys
        .iter()
        .enumerate()
        .map(|(i, k)| format!("{}. {}", i + 1, k))
        .collect::<Vec<_>>()
        .join("\n");

    let _ = show_info_notification(
        "Multiple GPG Keys Found",
        &format!(
            "Found {} GPG keys on your system:\n\n{}\n\nYou will be asked to select one.",
            private_keys.len(),
            key_list
        ),
    );

    for (i, key) in private_keys.iter().enumerate() {
        let fingerprint = key.fingerprint(false);
        let short_fingerprint = key.fingerprint(true);

        match show_yes_no_notification(
            &format!("GPG Key Selection ({}/{})", i + 1, private_keys.len()),
            &format!(
                "Use this GPG key?\n\n{}\n\nFingerprint: {}",
                key, short_fingerprint
            ),
        ) {
            Ok(YesNoResult::Accepted) => {
                info!("User selected GPG key: {}", fingerprint);
                return Ok(fingerprint);
            }
            Ok(YesNoResult::Denied) => {
                debug!("User declined key {}, showing next", i + 1);
                continue;
            }
            Err(e) => {
                warn!("Failed to show key selection: {}", e);
                return Err(Error::Config(format!(
                    "Failed to show key selection: {}",
                    e
                )));
            }
        }
    }

    warn!("No GPG key was selected");
    let _ = show_error_notification(
        "No Key Selected",
        "No GPG key was selected. Initialization cancelled.",
    );
    Err(Error::Config("No key selected".to_string()))
}
