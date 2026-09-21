//! Store initialized, ready for optional git setup

use super::complete::Complete;

use crate::notification::{show_error_notification, show_info_notification};

use passless_core::error::{Error, Result};

use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use log::{info, warn};

pub struct StoreInitialized {
    pub(super) store_path: PathBuf,
    pub(super) scope_path: PathBuf,
    pub(super) gpg_id_path: PathBuf,
    pub(super) fingerprint: String,
    pub(super) allow_create_without_prompt: bool,
}

impl StoreInitialized {
    pub fn setup_git(self) -> Result<Complete> {
        info!("Setting up git");
        initialize_git_repo(
            &self.store_path,
            &self.gpg_id_path,
            self.allow_create_without_prompt,
        )?;
        Ok(Complete {
            scope_path: self.scope_path,
            fingerprint: self.fingerprint,
            allow_create_without_prompt: self.allow_create_without_prompt,
        })
    }
}

fn initialize_git_repo(
    store_path: &PathBuf,
    gpg_id_path: &Path,
    allow_create_without_prompt: bool,
) -> Result<()> {
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

    let gpg_id_relative = gpg_id_path.strip_prefix(store_path).map_err(|_| {
        Error::Storage(format!(
            "GPG policy path '{}' is outside password store root '{}'",
            gpg_id_path.display(),
            store_path.display()
        ))
    })?;

    let _ = Command::new("git")
        .arg("add")
        .arg(gpg_id_relative)
        .arg(".gitattributes")
        .current_dir(store_path)
        .output();

    let _ = Command::new("git")
        .args(["commit", "-m", "Initialize password store with passless"])
        .current_dir(store_path)
        .output();

    if !allow_create_without_prompt {
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
    }

    Ok(())
}
