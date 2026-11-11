//! Native-path containment of the managed browser (ADR 0014 section 7, invariant 25; plan D6
//! layer 3).
//!
//! No Chromium switch disables CTAP over HID, so a WebAuthn request that the passless extension
//! does not handle (an unloaded extension, a lost attachment, a context without the extension)
//! would reach every `/dev/hidraw*` node the browser's UID can open, including the human
//! authenticator's. Containment is therefore filesystem and UID based:
//!
//! - whenever `bwrap` works for the browser's user (it is installed and unprivileged user
//!   namespaces are available), the managed browser runs in a private `/dev` that has no
//!   `hidraw*` and no `uhid`: `bwrap --dev-bind / / --dev /dev --die-with-parent <browser> ...`;
//! - otherwise the launch-time check `faccessat(AT_EACCESS, R_OK | W_OK)` over every
//!   `/dev/hidraw*` runs in the child that will exec the browser, after the credential drop, so it
//!   is evaluated as the browser's UID and groups; if any node is accessible the child refuses to
//!   exec and the launch fails with an actionable error.
//!
//! [`assess`] reports which case applies (required and in place, in place as defence in depth,
//! not required, refused) for `passless doctor`.
//!
//! Side effects of the private `/dev` (spike Q8, `tests/agent-e2e/spikes/RESULTS-env.md`):
//! supplementary groups are dropped inside the namespace and the UID is unchanged; the host
//! `/dev/shm` is replaced by a private one (bound through when a path the browser needs lives
//! there); `/dev/dri` is hidden, so the browser renders without the GPU; the X and Wayland sockets
//! stay reachable through `--dev-bind / /`. A hidraw node that appears after launch never appears
//! in the private `/dev`; without it, the launch-time check does not see it (ADR 0014 section 15).

use std::ffi::CString;
use std::fmt;
use std::fs;
use std::io;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::launcher::HardenedChildSetup;

/// The `bwrap` options that give the browser a private `/dev` and tie it to its parent.
pub const BWRAP_PRIVATE_DEV_ARGS: [&str; 6] =
    ["--dev-bind", "/", "/", "--dev", "/dev", "--die-with-parent"];

/// The errno with which the pre-exec hidraw check fails when the browser's UID can open a hidraw
/// node. No other pre-exec step or `execve` returns it, so the spawn error identifies the refusal.
pub(crate) const HIDRAW_ACCESSIBLE_ERRNO: i32 = libc::ENOTUNIQ;

/// How long the `bwrap` usability probe may take.
const BWRAP_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Where `bwrap` is looked for, before the daemon's `PATH`.
const BWRAP_CANDIDATES: [&str; 3] = ["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"];

/// Debug builds only: pretend `bwrap` is unavailable, so that E2E tests can exercise the refusal.
const DISABLE_BWRAP_ENV: &str = "PASSLESS_E2E_DISABLE_BWRAP";

/// Which containment case applies to a managed browser (ADR 0014 section 7, plan D6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainmentCase {
    /// The browser's UID can open a hidraw node, and the browser runs in a private `/dev`.
    RequiredInPlace,
    /// The browser's UID cannot open any hidraw node; the private `/dev` is applied anyway.
    DefenceInDepth,
    /// The browser's UID cannot open any hidraw node and `bwrap` is unavailable.
    NotRequired,
    /// The browser's UID can open a hidraw node and `bwrap` is unavailable: launches are refused.
    Refused,
}

impl ContainmentCase {
    /// The case for a private `/dev` that is (or is not) available, and hidraw nodes that the
    /// browser's UID can (or cannot) open.
    pub fn of(private_dev: bool, hidraw_accessible: bool) -> Self {
        match (private_dev, hidraw_accessible) {
            (true, true) => Self::RequiredInPlace,
            (true, false) => Self::DefenceInDepth,
            (false, false) => Self::NotRequired,
            (false, true) => Self::Refused,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::RequiredInPlace => "required and in place",
            Self::DefenceInDepth => "in place as defence in depth",
            Self::NotRequired => "not required",
            Self::Refused => "refused",
        }
    }
}

impl fmt::Display for ContainmentCase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where the launcher finds `bwrap` and the hidraw nodes.
#[derive(Clone, Debug, Default)]
pub enum ContainmentPolicy {
    /// Production: `bwrap` from the well-known locations or `PATH`, hidraw nodes under `/dev`.
    #[default]
    Auto,
    /// Tests: this `bwrap` (`None`: unavailable) and hidraw nodes under `dev_dir`.
    #[cfg(test)]
    Injected {
        bwrap: Option<PathBuf>,
        dev_dir: PathBuf,
    },
    /// Tests with fake browsers only: no containment at all.
    #[cfg(test)]
    Off,
}

impl ContainmentPolicy {
    fn dev_dir(&self) -> PathBuf {
        match self {
            #[cfg(test)]
            Self::Injected { dev_dir, .. } => dev_dir.clone(),
            _ => PathBuf::from("/dev"),
        }
    }

    /// The `bwrap` executable to use, or why there is none.
    fn bwrap(&self, daemon_uid: u32) -> Result<PathBuf, String> {
        match self {
            #[cfg(test)]
            Self::Injected { bwrap, .. } => bwrap
                .clone()
                .ok_or_else(|| "bwrap is not installed (test)".to_string()),
            #[cfg(test)]
            Self::Off => Err("containment is off (test)".to_string()),
            Self::Auto => find_bwrap(daemon_uid),
        }
    }
}

/// `bwrap` from the well-known locations, then the daemon's `PATH`. A root daemon accepts only a
/// root-owned binary that neither group nor others can write.
pub fn find_bwrap(daemon_uid: u32) -> Result<PathBuf, String> {
    if cfg!(debug_assertions) && std::env::var_os(DISABLE_BWRAP_ENV).is_some() {
        return Err(format!(
            "bwrap is disabled by {DISABLE_BWRAP_ENV} (debug builds only)"
        ));
    }
    let path_dirs = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .unwrap_or_default();
    let candidates = BWRAP_CANDIDATES.iter().map(PathBuf::from).chain(
        path_dirs
            .into_iter()
            .filter(|dir| dir.is_absolute())
            .map(|dir| dir.join("bwrap")),
    );
    let mut rejected = Vec::new();
    for candidate in candidates {
        let Ok(meta) = fs::metadata(&candidate) else {
            continue;
        };
        if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
            continue;
        }
        if daemon_uid == 0 && (meta.uid() != 0 || meta.mode() & 0o022 != 0) {
            rejected.push(candidate.display().to_string());
            continue;
        }
        return Ok(candidate);
    }
    if rejected.is_empty() {
        Err("bwrap (bubblewrap) is not installed".to_string())
    } else {
        Err(format!(
            "bwrap at {} is not root-owned or is writable by others",
            rejected.join(", ")
        ))
    }
}

/// The hidraw device nodes under `dev_dir`, as C strings built before any fork.
fn hidraw_nodes(dev_dir: &Path) -> Vec<CString> {
    let Ok(entries) = fs::read_dir(dev_dir) else {
        return Vec::new();
    };
    let mut nodes: Vec<CString> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().as_bytes().starts_with(b"hidraw"))
        .filter_map(|entry| CString::new(entry.path().as_os_str().as_bytes()).ok())
        .collect();
    nodes.sort();
    nodes
}

/// Fail with [`HIDRAW_ACCESSIBLE_ERRNO`] if this process, with its effective IDs and groups,
/// could open any of `nodes` for reading and writing. Async-signal-safe; allocates nothing.
///
/// # Safety
///
/// `nodes` must stay valid; safe to call in a forked child before `exec`.
pub(crate) unsafe fn refuse_if_hidraw_accessible(nodes: &[CString]) -> Result<(), io::Error> {
    for node in nodes {
        // SAFETY: `node` is a valid NUL-terminated path.
        let ret = unsafe {
            libc::faccessat(
                libc::AT_FDCWD,
                node.as_ptr(),
                libc::R_OK | libc::W_OK,
                libc::AT_EACCESS,
            )
        };
        if ret == 0 {
            return Err(io::Error::from_raw_os_error(HIDRAW_ACCESSIBLE_ERRNO));
        }
    }
    Ok(())
}

/// Wait up to `timeout` for `child`; kill it if it is still running then.
fn wait_with_timeout(child: &mut Child, timeout: Duration) -> io::Result<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("did not finish within {} s", timeout.as_secs()),
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Whether `bwrap` can build the private `/dev` for the browser's user: it runs `true` in it,
/// with the browser's hardening (`setup`, `None` for the trusted same-user spawn), so a missing
/// user-namespace permission of that user is seen here, not by the browser launch.
fn probe_bwrap(bwrap: &Path, setup: Option<&HardenedChildSetup>) -> Result<(), String> {
    let mut command = Command::new(bwrap);
    command
        .args(BWRAP_PRIVATE_DEV_ARGS)
        .args(["--", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(setup) = setup {
        let setup = HardenedChildSetup {
            bind_parent_death: false,
            ..setup.clone()
        };
        let parent = std::process::id() as libc::pid_t;
        // SAFETY: `apply` is async-signal-safe and runs pre-exec.
        unsafe {
            command.pre_exec(move || setup.apply(&[0, 1, 2], parent));
        }
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("cannot run {}: {e}", bwrap.display()))?;
    let mut stderr = child.stderr.take();
    let status = wait_with_timeout(&mut child, BWRAP_PROBE_TIMEOUT)
        .map_err(|e| format!("{} {e}", bwrap.display()))?;
    if status.success() {
        return Ok(());
    }
    let mut output = String::new();
    if let Some(stderr) = stderr.as_mut() {
        let _ = stderr.take(4096).read_to_string(&mut output);
    }
    let detail = output.lines().next().unwrap_or("").trim();
    Err(format!(
        "{} cannot create a private /dev ({status}{}{}); unprivileged user namespaces may be \
         disabled",
        bwrap.display(),
        if detail.is_empty() { "" } else { ": " },
        detail
    ))
}

/// How one launch is contained, decided before the spawn (see the module documentation).
#[derive(Debug)]
pub struct ContainmentPlan {
    /// `Some`: the browser runs under this `bwrap` in a private `/dev`.
    bwrap: Option<PathBuf>,
    /// Bind the host `/dev/shm` into the private `/dev` (a path the browser needs lives there).
    bind_dev_shm: bool,
    /// Without `bwrap`: the hidraw nodes the child checks before it execs the browser.
    hidraw_nodes: Vec<CString>,
    /// Without `bwrap`: why it is unavailable.
    unavailable: Option<String>,
    /// The browser's UID, for messages.
    browser_uid: u32,
    /// No containment at all (tests with fake browsers).
    off: bool,
}

impl ContainmentPlan {
    /// Decide the containment of one launch. `setup` is the browser's hardening and
    /// `trusted_same_user` whether the spawn skips it (same-UID port mode). `needs_dev_shm` says
    /// that the browser, its profile or the relay lives under `/dev/shm`.
    pub fn for_launch(
        policy: &ContainmentPolicy,
        setup: &HardenedChildSetup,
        trusted_same_user: bool,
        needs_dev_shm: bool,
    ) -> Self {
        #[cfg(test)]
        if matches!(policy, ContainmentPolicy::Off) {
            return Self {
                bwrap: None,
                bind_dev_shm: false,
                hidraw_nodes: Vec::new(),
                unavailable: None,
                browser_uid: setup.target_uid,
                off: true,
            };
        }
        let probe_setup = (!trusted_same_user).then_some(setup);
        let bwrap = policy
            .bwrap(setup.daemon_uid)
            .and_then(|bwrap| probe_bwrap(&bwrap, probe_setup).map(|()| bwrap));
        match bwrap {
            Ok(bwrap) => Self {
                bwrap: Some(bwrap),
                bind_dev_shm: needs_dev_shm,
                hidraw_nodes: Vec::new(),
                unavailable: None,
                browser_uid: setup.target_uid,
                off: false,
            },
            Err(why) => Self {
                bwrap: None,
                bind_dev_shm: false,
                hidraw_nodes: hidraw_nodes(&policy.dev_dir()),
                unavailable: Some(why),
                browser_uid: setup.target_uid,
                off: false,
            },
        }
    }

    /// Whether the browser runs in a private `/dev`.
    pub fn private_dev(&self) -> bool {
        self.bwrap.is_some()
    }

    /// The hidraw nodes the child must find inaccessible before it execs the browser (none when
    /// the browser runs in a private `/dev`). Built before the fork; the child only reads them.
    pub fn hidraw_nodes_to_check(&self) -> &[CString] {
        &self.hidraw_nodes
    }

    /// Wrap the browser command in `bwrap` when the plan has a private `/dev`; otherwise return it
    /// unchanged. The environment is inherited either way; stdio is reset to null.
    pub fn wrap(&self, command: Command) -> Command {
        let Some(bwrap) = &self.bwrap else {
            return command;
        };
        let mut wrapped = Command::new(bwrap);
        wrapped.args(BWRAP_PRIVATE_DEV_ARGS);
        if self.bind_dev_shm {
            wrapped.args(["--bind", "/dev/shm", "/dev/shm"]);
        }
        wrapped
            .arg("--")
            .arg(command.get_program())
            .args(command.get_args());
        for (key, value) in command.get_envs() {
            match value {
                Some(value) => wrapped.env(key, value),
                None => wrapped.env_remove(key),
            };
        }
        if let Some(dir) = command.get_current_dir() {
            wrapped.current_dir(dir);
        }
        wrapped
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        wrapped
    }

    /// The actionable launch error for a spawn that failed with `error`, if the failure is the
    /// child's hidraw refusal.
    pub fn refusal(&self, error: &io::Error) -> Option<String> {
        if error.raw_os_error() != Some(HIDRAW_ACCESSIBLE_ERRNO) || self.off {
            return None;
        }
        let nodes = self
            .hidraw_nodes
            .iter()
            .map(|node| node.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(", ");
        Some(refusal_message(
            self.browser_uid,
            &nodes,
            self.unavailable
                .as_deref()
                .unwrap_or("bwrap is unavailable"),
        ))
    }

    /// The case this launch is in, as far as the launcher knows without probing as another user:
    /// with a private `/dev`, a same-UID browser's hidraw access is checked here; a distinct-UID
    /// browser's is not (reported as required, the conservative reading). Without it, a launch
    /// that got this far passed the child's check.
    pub fn case_for_log(&self, same_user: bool) -> Option<ContainmentCase> {
        if self.off {
            return None;
        }
        Some(if self.private_dev() {
            if same_user {
                // SAFETY: plain syscalls in this process.
                let accessible = unsafe {
                    refuse_if_hidraw_accessible(&hidraw_nodes(Path::new("/dev"))).is_err()
                };
                ContainmentCase::of(true, accessible)
            } else {
                ContainmentCase::RequiredInPlace
            }
        } else {
            ContainmentCase::NotRequired
        })
    }
}

fn refusal_message(browser_uid: u32, nodes: &str, unavailable: &str) -> String {
    format!(
        "refusing to launch the managed browser: its user (uid {browser_uid}) can open a hidraw \
         device ({nodes}), so a WebAuthn request that the passless extension does not handle \
         could reach the human authenticator, and the browser must run in a private /dev, which \
         needs bubblewrap; {unavailable}. Install bubblewrap (bwrap) and allow unprivileged user \
         namespaces (user.max_user_namespaces > 0; kernel.unprivileged_userns_clone = 1 where \
         that sysctl exists; or the distribution's AppArmor user-namespace policy for bwrap), or \
         run the browser as a user that cannot open any hidraw device \
         (agents.profiles.<name>.browser_user)"
    )
}

/// What `passless doctor` reports about the containment of a profile's managed browser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainmentReport {
    pub case: ContainmentCase,
    /// The `bwrap` that works for the browser's user, or why there is none.
    pub bwrap: Result<PathBuf, String>,
    /// Whether the browser's UID can open a hidraw node; `None` when it cannot be evaluated (a
    /// non-root daemon asked about another user), which counts as accessible.
    pub hidraw_accessible: Option<bool>,
}

/// Which containment case applies to a browser launched with `setup` (`trusted_same_user`: the
/// same-UID port-mode spawn, which skips the hardening). It probes `bwrap` as the browser's user
/// and evaluates hidraw access as that user: in this process for a same-UID browser, in a child
/// that drops to the browser's user for a distinct one (root daemons only).
pub fn assess(
    policy: &ContainmentPolicy,
    setup: &HardenedChildSetup,
    trusted_same_user: bool,
) -> ContainmentReport {
    let probe_setup = (!trusted_same_user).then_some(setup);
    let bwrap = policy
        .bwrap(setup.daemon_uid)
        .and_then(|bwrap| probe_bwrap(&bwrap, probe_setup).map(|()| bwrap));
    let nodes = hidraw_nodes(&policy.dev_dir());
    let hidraw_accessible = hidraw_accessible_as(setup, &nodes);
    ContainmentReport {
        case: ContainmentCase::of(bwrap.is_ok(), hidraw_accessible.unwrap_or(true)),
        bwrap,
        hidraw_accessible,
    }
}

/// Whether the browser's user can open any of `nodes`, evaluated as that user.
fn hidraw_accessible_as(setup: &HardenedChildSetup, nodes: &[CString]) -> Option<bool> {
    if nodes.is_empty() {
        return Some(false);
    }
    let same_user = setup.target_uid == setup.daemon_uid && setup.target_gid == setup.daemon_gid;
    if same_user {
        // SAFETY: plain syscalls in this process.
        return Some(unsafe { refuse_if_hidraw_accessible(nodes).is_err() });
    }
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    let (uid, gid) = (setup.target_uid, setup.target_gid);
    let nodes = nodes.to_vec();
    let mut command = Command::new("true");
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: plain async-signal-safe syscalls, pre-exec.
    unsafe {
        command.pre_exec(move || {
            if libc::setgroups(0, std::ptr::null()) < 0
                || libc::setresgid(gid, gid, gid) < 0
                || libc::setresuid(uid, uid, uid) < 0
            {
                return Err(io::Error::last_os_error());
            }
            refuse_if_hidraw_accessible(&nodes)
        });
    }
    match command.spawn() {
        Ok(mut child) => {
            let _ = wait_with_timeout(&mut child, BWRAP_PROBE_TIMEOUT);
            Some(false)
        }
        Err(e) if e.raw_os_error() == Some(HIDRAW_ACCESSIBLE_ERRNO) => Some(true),
        Err(_) => None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::os::unix::fs::OpenOptionsExt;

    use super::*;

    fn same_user_setup() -> HardenedChildSetup {
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        HardenedChildSetup {
            target_uid: uid,
            target_gid: gid,
            daemon_uid: uid,
            daemon_gid: gid,
            rlimit_nofile: 256,
            rlimit_nproc: 64,
            rlimit_core: 0,
            rlimit_as: 0,
            bind_parent_death: true,
        }
    }

    /// A device directory with one `hidraw0` file of `mode`.
    fn dev_dir(mode: u32) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(dir.path().join("hidraw0"))
            .unwrap();
        fs::write(dir.path().join("null"), b"").unwrap();
        dir
    }

    /// A stand-in for `bwrap` that checks its private-/dev options and runs the command after
    /// `--`, recording the arguments it got.
    pub(crate) fn fake_bwrap(dir: &Path) -> PathBuf {
        let path = dir.join("bwrap");
        let log = dir.join("bwrap.args");
        fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" >> '{}'\n\
                 [ \"$1 $2 $3 $4 $5 $6\" = '--dev-bind / / --dev /dev --die-with-parent' ] || exit 97\n\
                 while [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"\n",
                log.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn the_case_follows_the_private_dev_and_hidraw_access() {
        assert_eq!(
            ContainmentCase::of(true, true),
            ContainmentCase::RequiredInPlace
        );
        assert_eq!(
            ContainmentCase::of(true, false),
            ContainmentCase::DefenceInDepth
        );
        assert_eq!(
            ContainmentCase::of(false, false),
            ContainmentCase::NotRequired
        );
        assert_eq!(ContainmentCase::of(false, true), ContainmentCase::Refused);
        assert_eq!(ContainmentCase::Refused.to_string(), "refused");
    }

    #[test]
    fn the_hidraw_check_sees_only_nodes_this_user_can_read_and_write() {
        let open = dev_dir(0o600);
        let nodes = hidraw_nodes(open.path());
        assert_eq!(nodes.len(), 1, "only hidraw* nodes are listed");
        let err = unsafe { refuse_if_hidraw_accessible(&nodes) }.unwrap_err();
        assert_eq!(err.raw_os_error(), Some(HIDRAW_ACCESSIBLE_ERRNO));

        // Readable but not writable is not enough to talk CTAP (root bypasses the mode bits).
        if unsafe { libc::geteuid() } != 0 {
            let read_only = dev_dir(0o400);
            assert!(
                unsafe { refuse_if_hidraw_accessible(&hidraw_nodes(read_only.path())) }.is_ok()
            );
        }
        let none = tempfile::tempdir().unwrap();
        assert!(hidraw_nodes(none.path()).is_empty());
    }

    #[test]
    fn without_bwrap_an_accessible_hidraw_node_refuses_the_spawn_with_an_actionable_error() {
        let dev = dev_dir(0o600);
        let policy = ContainmentPolicy::Injected {
            bwrap: None,
            dev_dir: dev.path().to_path_buf(),
        };
        let setup = same_user_setup();
        let plan = ContainmentPlan::for_launch(&policy, &setup, false, false);
        assert!(!plan.private_dev());
        assert_eq!(plan.hidraw_nodes_to_check().len(), 1);

        let nodes = plan.hidraw_nodes_to_check().to_vec();
        let parent = std::process::id() as libc::pid_t;
        let mut command = plan.wrap(Command::new("/bin/true"));
        // SAFETY: async-signal-safe pre-exec steps, as in the browser spawn.
        unsafe {
            command.pre_exec(move || {
                setup.apply(&[0, 1, 2], parent)?;
                refuse_if_hidraw_accessible(&nodes)
            });
        }
        let err = command.spawn().expect_err("the child refuses to exec");
        let message = plan
            .refusal(&err)
            .expect("recognized as the containment refusal");
        assert!(message.contains("hidraw0"), "{message}");
        assert!(message.contains("bubblewrap"), "{message}");
        assert!(message.contains("browser_user"), "{message}");
        assert_eq!(
            plan.refusal(&io::Error::from_raw_os_error(libc::ENOENT)),
            None,
            "another spawn failure is not reported as the refusal"
        );

        let report = assess(&policy, &same_user_setup(), false);
        assert_eq!(report.case, ContainmentCase::Refused);
        assert_eq!(report.hidraw_accessible, Some(true));
    }

    #[test]
    fn with_bwrap_the_browser_runs_in_the_private_dev() {
        let dev = dev_dir(0o600);
        let bin = tempfile::tempdir().unwrap();
        let bwrap = fake_bwrap(bin.path());
        let policy = ContainmentPolicy::Injected {
            bwrap: Some(bwrap.clone()),
            dev_dir: dev.path().to_path_buf(),
        };
        let plan = ContainmentPlan::for_launch(&policy, &same_user_setup(), false, true);
        assert!(
            plan.private_dev(),
            "the probe ran the fake bwrap successfully"
        );
        assert!(
            plan.hidraw_nodes_to_check().is_empty(),
            "no child check under bwrap"
        );

        let mut inner = Command::new("/bin/sh");
        inner
            .args(["-c", "exit 7"])
            .env("PASSLESS_CONTAINMENT_TEST", "1");
        let wrapped = plan.wrap(inner);
        assert_eq!(wrapped.get_program(), bwrap.as_os_str());
        let args: Vec<_> = wrapped
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            [
                "--dev-bind",
                "/",
                "/",
                "--dev",
                "/dev",
                "--die-with-parent",
                "--bind",
                "/dev/shm",
                "/dev/shm",
                "--",
                "/bin/sh",
                "-c",
                "exit 7"
            ]
        );
        assert!(
            wrapped
                .get_envs()
                .any(|(k, v)| k == "PASSLESS_CONTAINMENT_TEST" && v.is_some()),
            "the browser's environment is kept"
        );
        let mut wrapped = wrapped;
        assert_eq!(wrapped.status().unwrap().code(), Some(7));

        let report = assess(&policy, &same_user_setup(), false);
        assert_eq!(report.case, ContainmentCase::RequiredInPlace);
        assert_eq!(report.bwrap, Ok(bwrap));
    }

    #[test]
    fn a_bwrap_that_cannot_build_the_private_dev_counts_as_unavailable() {
        let bin = tempfile::tempdir().unwrap();
        let bwrap = bin.path().join("bwrap");
        fs::write(
            &bwrap,
            "#!/bin/sh\necho 'bwrap: No permissions to create a new namespace' >&2\nexit 1\n",
        )
        .unwrap();
        fs::set_permissions(&bwrap, fs::Permissions::from_mode(0o755)).unwrap();
        let empty_dev = tempfile::tempdir().unwrap();
        let policy = ContainmentPolicy::Injected {
            bwrap: Some(bwrap),
            dev_dir: empty_dev.path().to_path_buf(),
        };
        let report = assess(&policy, &same_user_setup(), true);
        let why = report.bwrap.unwrap_err();
        assert!(why.contains("No permissions"), "{why}");
        assert_eq!(report.case, ContainmentCase::NotRequired);
        assert_eq!(report.hidraw_accessible, Some(false));
    }
}
