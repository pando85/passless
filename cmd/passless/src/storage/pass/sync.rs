//! Operation-scoped Git synchronization for the pass backend.
//!
//! Credential and PIN storage share this coordinator. A logical authenticator
//! operation opens a transaction, individual storage accesses lazily prepare
//! (pull) at most once, and all Git-visible writes are finalized in one commit
//! and push when the outer operation ends.

use git2::Repository;
use log::{debug, warn};
use prs_lib::Store;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

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
        ensure_ssh_auth_sock();
        let store = Store::open(store_path.to_string_lossy().as_ref())
            .map_err(|error| format!("failed to open store: {error:?}"))?;
        store
            .sync()
            .prepare()
            .map_err(|error| format!("prepare failed: {error:?}"))
    }

    fn finalize_store(store_path: &Path, message: &str) -> Result<(), String> {
        debug!("Finalizing password-store Git sync: {message}");
        ensure_ssh_auth_sock();
        let store = Store::open(store_path.to_string_lossy().as_ref())
            .map_err(|error| format!("failed to open store: {error:?}"))?;
        store
            .sync()
            .finalize(message)
            .map_err(|error| format!("finalize failed: {error:?}"))
    }
}

/// Ensure `SSH_AUTH_SOCK` points at a live agent socket before Git sync
/// shells out. `prs_lib` spawns `git` inheriting the process environment
/// as-is, so this re-resolves and overwrites it fresh on every prepare/
/// finalize call rather than trusting whatever passless itself inherited
/// once at startup (see #467: that snapshot is never refreshed later, even
/// once the agent becomes available).
fn ensure_ssh_auth_sock() {
    let Some(socket) = resolve_ssh_auth_sock() else {
        return;
    };
    // SAFETY: mutating the process environment races with any concurrent
    // env read/write on another thread. passless's other std::env::var(_os)
    // call sites (agent runtime dir, E2E test flags, test vendor/product
    // IDs) are one-time reads of unrelated keys made at startup or from
    // request handlers that never overlap with a pass Git sync, so this is
    // safe in practice for passless's current call graph even though the
    // type system cannot prove it.
    unsafe {
        std::env::set_var("SSH_AUTH_SOCK", socket);
    }
}

/// Resolve a live SSH agent socket for Git operations against the password
/// store. Sources are tried in order, each covering a different class of
/// agent (gpg-agent's SSH support, plain ssh-agent, KeePassXC, 1Password,
/// ...) without hard-coding a dependency on any single one.
fn resolve_ssh_auth_sock() -> Option<PathBuf> {
    systemd_user_environment_ssh_auth_sock()
        .or_else(inherited_ssh_auth_sock)
        .or_else(gpg_agent_ssh_socket)
}

/// Query the systemd user manager's own environment table. Autostart
/// scripts for ssh-agent, KeePassXC, 1Password, etc. commonly update it
/// (via `systemctl --user import-environment` or
/// `dbus-update-activation-environment`) after passless.service has
/// already started, which is exactly the case a one-time startup snapshot
/// misses. This is the most distro/agent-agnostic source since it does not
/// depend on ordering against any specific systemd unit.
fn systemd_user_environment_ssh_auth_sock() -> Option<PathBuf> {
    let output = Command::new("systemctl")
        .args(["--user", "show-environment"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value = stdout
        .lines()
        .find_map(|line| line.strip_prefix("SSH_AUTH_SOCK="))?;
    let path = PathBuf::from(value);
    path.exists().then_some(path)
}

/// Fall back to whatever passless's own process environment already has,
/// for setups without a systemd user manager (e.g. run from a login shell).
fn inherited_ssh_auth_sock() -> Option<PathBuf> {
    let path = PathBuf::from(std::env::var_os("SSH_AUTH_SOCK")?);
    path.exists().then_some(path)
}

/// Fall back to gpg-agent's configured SSH support socket. `gpgconf`
/// reports the configured path even before the agent has been contacted;
/// connecting to it triggers systemd socket activation where
/// `gpg-agent.socket` is managed that way, so this does not require the
/// agent to already be running.
fn gpg_agent_ssh_socket() -> Option<PathBuf> {
    let output = Command::new("gpgconf")
        .args(["--list-dirs", "agent-ssh-socket"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    path.exists().then_some(path)
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
}
