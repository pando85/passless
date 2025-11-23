//! Store initialized, ready for optional git setup

use super::complete::Complete;

use crate::notification::{show_error_notification, show_info_notification};

use passless_core::error::{Error, Result};

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use log::{info, warn};

pub struct StoreInitialized {
    pub(super) store_path: PathBuf,
    pub(super) fingerprint: String,
}

impl StoreInitialized {
    pub fn setup_git(self) -> Result<Complete> {
        info!("Setting up git");
        initialize_git_repo(&self.store_path)?;
        Ok(Complete {
            store_path: self.store_path,
            fingerprint: self.fingerprint,
        })
    }
}

fn initialize_git_repo(store_path: &PathBuf) -> Result<()> {
    let output = Command::new("git")
        .arg("init")
        .current_dir(store_path)
        .output()
        .map_err(|e| {
            let msg = format!("Failed to run git init: {}", e);
            let _ = show_error_notification("Git Initialization Failed", &msg);
            Error::Storage(msg)
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let msg = format!("Git init failed: {}", stderr);
        warn!("{}", msg);
        let _ = show_error_notification("Git Initialization Failed", &msg);
        return Err(Error::Storage(msg));
    }

    info!("Initialized git repository in {:?}", store_path);

    let gitattributes = store_path.join(".gitattributes");
    let _ = fs::write(
        &gitattributes,
        "*.gpg diff=gpg\n[attr]binary -diff -merge -text\n",
    );

    let _ = Command::new("git")
        .args(["add", ".gpg-id", ".gitattributes"])
        .current_dir(store_path)
        .output();

    let _ = Command::new("git")
        .args(["commit", "-m", "Initialize password store with passless"])
        .current_dir(store_path)
        .output();

    let _ = show_info_notification(
        "Git Initialized",
        &format!(
            "Git repository initialized in password store.\n\n\
             To add a remote repository, run:\n\
             cd {}\n\
             git remote add origin <your-git-url>\n\
             git push -u origin master",
            store_path.display()
        ),
    );

    Ok(())
}
