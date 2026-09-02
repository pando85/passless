//! Operation-scoped Git synchronization for the pass backend.
//!
//! Credential and PIN storage share this coordinator. A logical authenticator
//! operation opens a transaction, individual storage accesses lazily prepare
//! (pull) at most once, and all Git-visible writes are finalized in one commit
//! and push when the outer operation ends.

use git2::Repository;
use log::{debug, warn};
use prs_lib::Store;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

const PASS_GIT_SSH_AUTH_SOCK_ENV: &str = "PASSLESS_PASS_GIT_SSH_AUTH_SOCK";
const SSH_AUTH_SOCK_ENV: &str = "SSH_AUTH_SOCK";
#[cfg(not(windows))]
const PASS_GIT_SYNC_HELPER_BIN: &str = "passless-git-sync";
#[cfg(windows)]
const PASS_GIT_SYNC_HELPER_BIN: &str = "passless-git-sync.exe";

#[derive(Debug, Clone)]
pub struct PassGitSync {
    state: Arc<Mutex<SyncState>>,
}

#[derive(Debug)]
struct SyncState {
    store_path: PathBuf,
    enabled: bool,
    depth: usize,
    prepared: bool,
    dirty: bool,
    messages: Vec<String>,
}

impl PassGitSync {
    pub fn new(store_path: PathBuf, enabled: bool) -> Self {
        Self {
            state: Arc::new(Mutex::new(SyncState {
                store_path,
                enabled,
                depth: 0,
                prepared: false,
                dirty: false,
                messages: Vec::new(),
            })),
        }
    }

    /// Pull once during backend construction so the initial credential index
    /// and PIN state are loaded from the latest local/remote Git state.
    pub fn prepare_startup(&self) {
        let Ok(state) = self.state.lock() else {
            warn!("Failed to acquire pass Git sync lock during startup");
            return;
        };
        if !state.enabled {
            return;
        }
        if let Err(error) = Self::prepare_store(&state.store_path) {
            warn!("Failed to prepare password-store Git sync during startup: {error}");
        }
    }

    /// Begin a logical Passless operation. Network I/O is lazy and only occurs
    /// if this operation actually touches synchronized pass state.
    pub fn begin_operation(&self) {
        let Ok(mut state) = self.state.lock() else {
            warn!("Failed to acquire pass Git sync lock while beginning operation");
            return;
        };
        if !state.enabled {
            return;
        }
        if state.depth == 0 {
            state.prepared = false;
        }
        state.depth += 1;
    }

    /// Begin a one-storage-call transaction when code accesses pass storage
    /// outside the normal CTAP operation boundary (for example agent paths).
    /// Returns true when the caller owns the implicit transaction and must end it.
    pub fn begin_implicit_operation(&self) -> bool {
        let Ok(mut state) = self.state.lock() else {
            warn!("Failed to acquire pass Git sync lock for implicit operation");
            return false;
        };
        if !state.enabled || state.depth != 0 {
            return false;
        }
        state.depth = 1;
        state.prepared = false;
        true
    }

    /// Pull at most once for the active operation.
    pub fn prepare_if_needed(&self) {
        let Ok(mut state) = self.state.lock() else {
            warn!("Failed to acquire pass Git sync lock while preparing operation");
            return;
        };
        if !state.enabled || state.depth == 0 || state.prepared {
            return;
        }

        if let Err(error) = Self::prepare_store(&state.store_path) {
            warn!("Failed to prepare password-store Git sync: {error}");
        }
        // Do not hammer a failing/slow remote repeatedly inside one operation.
        state.prepared = true;
    }

    /// Mark a synchronized file change. Local-only state must never call this.
    pub fn mark_dirty(&self, message: impl Into<String>) {
        let Ok(mut state) = self.state.lock() else {
            warn!("Failed to acquire pass Git sync lock while marking dirty state");
            return;
        };
        if !state.enabled {
            return;
        }
        state.dirty = true;
        let message = message.into();
        if !state.messages.contains(&message) {
            state.messages.push(message);
        }
    }

    /// Finish a logical operation. The outermost operation produces at most one
    /// Git commit and push, irrespective of how many credential/PIN writes occurred.
    pub fn end_operation(&self) {
        let Ok(mut state) = self.state.lock() else {
            warn!("Failed to acquire pass Git sync lock while ending operation");
            return;
        };
        if !state.enabled {
            return;
        }
        if state.depth == 0 {
            warn!("Ignoring unmatched pass Git sync end_operation");
            return;
        }

        state.depth -= 1;
        if state.depth != 0 {
            return;
        }

        if !state.dirty {
            state.prepared = false;
            state.messages.clear();
            return;
        }

        if !state.prepared {
            if let Err(error) = Self::prepare_store(&state.store_path) {
                warn!("Failed to prepare password-store Git sync before finalize: {error}");
            }
            state.prepared = true;
        }

        let message = match state.messages.as_slice() {
            [only] => only.clone(),
            _ => "Update Passless authenticator state.".to_string(),
        };

        match Self::finalize_store(&state.store_path, &message) {
            Ok(()) => {
                state.dirty = false;
                state.messages.clear();
            }
            Err(error) => {
                // Keep dirty state so a later operation can retry finalization.
                warn!("Failed to finalize password-store Git sync: {error}");
            }
        }
        state.prepared = false;
    }

    /// Add a machine-local path to the repository-local exclude file. This is
    /// intentionally not committed and therefore applies independently per clone.
    pub fn ensure_local_only_path(&self, path: &Path) {
        let store_path = match self.state.lock() {
            Ok(state) => state.store_path.clone(),
            Err(_) => {
                warn!("Failed to acquire pass Git sync lock while configuring local-only path");
                return;
            }
        };

        let Ok(repo) = Repository::discover(&store_path) else {
            debug!("No Git repository found while configuring local-only pass state");
            return;
        };
        let Some(workdir) = repo.workdir() else {
            warn!("Password-store Git repository has no working directory");
            return;
        };
        let Ok(relative) = path.strip_prefix(workdir) else {
            warn!(
                "Local-only pass path {} is outside Git worktree {}",
                path.display(),
                workdir.display()
            );
            return;
        };

        let pattern = format!("/{}", relative.to_string_lossy().replace('\\', "/"));
        let exclude_path = repo.path().join("info").join("exclude");
        let mut contents = fs::read_to_string(&exclude_path).unwrap_or_default();
        if contents.lines().any(|line| line.trim() == pattern) {
            return;
        }
        if !contents.is_empty() && !contents.ends_with('\n') {
            contents.push('\n');
        }
        contents.push_str(&pattern);
        contents.push('\n');
        if let Some(parent) = exclude_path.parent()
            && let Err(error) = fs::create_dir_all(parent)
        {
            warn!("Failed to create Git info directory: {error}");
            return;
        }
        if let Err(error) = fs::write(&exclude_path, contents) {
            warn!("Failed to exclude local-only pass state from Git: {error}");
        }
    }

    fn prepare_store(store_path: &Path) -> Result<(), String> {
        debug!("Preparing password-store Git sync");
        if let Some(ssh_auth_sock) = configured_ssh_auth_sock() {
            return run_sync_helper(
                store_path,
                SyncHelperAction::Prepare,
                None,
                ssh_auth_sock.as_os_str(),
            );
        }

        let store = Store::open(store_path.to_string_lossy().as_ref())
            .map_err(|error| format!("failed to open store: {error:?}"))?;
        store
            .sync()
            .prepare()
            .map_err(|error| format!("prepare failed: {error:?}"))
    }

    fn finalize_store(store_path: &Path, message: &str) -> Result<(), String> {
        debug!("Finalizing password-store Git sync: {message}");
        if let Some(ssh_auth_sock) = configured_ssh_auth_sock() {
            return run_sync_helper(
                store_path,
                SyncHelperAction::Finalize,
                Some(message),
                ssh_auth_sock.as_os_str(),
            );
        }

        let store = Store::open(store_path.to_string_lossy().as_ref())
            .map_err(|error| format!("failed to open store: {error:?}"))?;
        store
            .sync()
            .finalize(message)
            .map_err(|error| format!("finalize failed: {error:?}"))
    }
}

#[derive(Debug, Clone, Copy)]
enum SyncHelperAction {
    Prepare,
    Finalize,
}

impl SyncHelperAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::Finalize => "finalize",
        }
    }
}

fn configured_ssh_auth_sock() -> Option<OsString> {
    std::env::var_os(PASS_GIT_SSH_AUTH_SOCK_ENV).filter(|value| !value.is_empty())
}

fn sync_helper_path() -> Result<PathBuf, String> {
    let current_exe = std::env::current_exe()
        .map_err(|error| format!("failed to resolve Passless executable: {error}"))?;
    Ok(sync_helper_path_from_exe(&current_exe))
}

fn sync_helper_path_from_exe(current_exe: &Path) -> PathBuf {
    current_exe.with_file_name(PASS_GIT_SYNC_HELPER_BIN)
}

fn sync_helper_command(
    helper_path: &Path,
    store_path: &Path,
    action: SyncHelperAction,
    message: Option<&str>,
    ssh_auth_sock: &OsStr,
) -> Command {
    let mut command = Command::new(helper_path);
    command.arg(action.as_str()).arg(store_path);
    if let Some(message) = message {
        command.arg(message);
    }
    command.env(SSH_AUTH_SOCK_ENV, ssh_auth_sock);
    command
}

fn run_sync_helper(
    store_path: &Path,
    action: SyncHelperAction,
    message: Option<&str>,
    ssh_auth_sock: &OsStr,
) -> Result<(), String> {
    let helper_path = sync_helper_path()?;
    let output = sync_helper_command(
        &helper_path,
        store_path,
        action,
        message,
        ssh_auth_sock,
    )
    .output()
    .map_err(|error| {
        format!(
            "failed to invoke {}: {error}",
            helper_path.to_string_lossy()
        )
    })?;

    if output.status.success() {
        return Ok(());
    }

    Err(sync_helper_failure(&helper_path, &output))
}

fn sync_helper_failure(helper_path: &Path, output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        format!(
            "{} exited with {}",
            helper_path.to_string_lossy(),
            output.status
        )
    } else {
        format!(
            "{} exited with {}: {stderr}",
            helper_path.to_string_lossy(),
            output.status
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_operations_do_not_finalize_inner_boundary() {
        let temp = tempfile::tempdir().unwrap();
        let sync = PassGitSync::new(temp.path().to_path_buf(), true);

        sync.begin_operation();
        sync.begin_operation();
        sync.mark_dirty("first");
        sync.end_operation();

        let state = sync.state.lock().unwrap();
        assert_eq!(state.depth, 1);
        assert!(state.dirty);
        assert_eq!(state.messages, vec!["first"]);
    }

    #[test]
    fn local_only_path_is_written_to_repository_exclude() {
        let temp = tempfile::tempdir().unwrap();
        let repo = Repository::init(temp.path()).unwrap();
        let local = temp.path().join("fido2/pin_retries.local.gpg");
        let sync = PassGitSync::new(temp.path().to_path_buf(), false);

        sync.ensure_local_only_path(&local);

        let exclude = fs::read_to_string(repo.path().join("info/exclude")).unwrap();
        assert!(
            exclude
                .lines()
                .any(|line| line == "/fido2/pin_retries.local.gpg")
        );
    }

    #[test]
    fn helper_is_resolved_next_to_passless_binary() {
        let current = Path::new("/usr/bin/passless");
        assert_eq!(
            sync_helper_path_from_exe(current),
            Path::new("/usr/bin").join(PASS_GIT_SYNC_HELPER_BIN)
        );
    }

    #[test]
    fn helper_command_scopes_ssh_auth_sock_to_child() {
        let command = sync_helper_command(
            Path::new("/usr/bin/passless-git-sync"),
            Path::new("/tmp/password-store"),
            SyncHelperAction::Finalize,
            Some("Update credential"),
            OsStr::new("/tmp/passless-agent.sock"),
        );

        assert_eq!(command.get_program(), OsStr::new("/usr/bin/passless-git-sync"));
        assert!(command.get_envs().any(|(key, value)| {
            key == OsStr::new(SSH_AUTH_SOCK_ENV)
                && value == Some(OsStr::new("/tmp/passless-agent.sock"))
        }));
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            vec![
                OsStr::new("finalize"),
                OsStr::new("/tmp/password-store"),
                OsStr::new("Update credential"),
            ]
        );
    }
}
