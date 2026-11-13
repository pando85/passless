use std::collections::HashMap;
use std::collections::VecDeque;
use std::ffi::CString;
use std::fmt;
use std::fs;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
#[cfg(test)]
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use passless_core::agent::config::{CdpExposeMode, LOCALHOST_RP_ID};
use passless_core::agent::{AgentRpRule, BrowserLeaseId, ProfileId, RuleAction, rule_for_host};

use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json;

use super::cdp_filter::{ExtensionCdpFilter, Inbound, RequestVerdict, TARGET_DENIED};
use super::containment::{ContainmentPlan, ContainmentPolicy, refuse_if_hidraw_accessible};
use super::launcher::{
    DEFAULT_RLIMIT_CORE, HardenedChildSetup, bind_parent_death, cloexec_except,
    spawn_on_launcher_thread,
};
use super::safe_fs::{Dir, chown_file};
use super::transport::{BearerReadiness, ReadinessRegistry};

const RUNTIME_DIR_MODE: u32 = 0o700;
/// A lease directory: owned by the daemon, traversable by the browser's group only. The daemon
/// writes into it; the browser user cannot add, replace or rename entries in it (review H1).
const LEASE_DIR_MODE: u32 = 0o710;
/// Most bytes read from Chromium's `DevToolsActivePort`.
const DEVTOOLS_ACTIVE_PORT_LIMIT: u64 = 512;
const EXTENSION_DIR_MODE: u32 = 0o755;
const DEFAULT_SIGTERM_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_SIGKILL_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_TTL_CLAMP_SECS: u64 = 86_400;
const MIN_TTL_SECS: u64 = 1;
const MAX_LOGIN_TIMEOUT_SECS: u64 = 600;
const MIN_LOGIN_TIMEOUT_SECS: u64 = 10;
const MANIFEST_FILENAME: &str = "browser-manifest.json";
const QUARANTINE_PREFIX: &str = "quarantine";
const AGENT_EXTENSION_DIR: &str = "agent-extension";
const CDP_FD_READ: RawFd = 3;
const CDP_FD_WRITE: RawFd = 4;
#[cfg(test)]
const RLIMIT_NOFILE_CUR: u64 = 256;
/// Resource limits of a managed browser that runs as another user (a root daemon sets them after
/// the credential drop; a same-user browser keeps the daemon's). The principal defaults of
/// `launcher.rs` (256 MiB address space, 32 processes, 64 descriptors) break Chromium, which maps
/// gigabytes of address space for V8 and its sandboxes, runs a process per renderer, utility and
/// zygote, and keeps many descriptors open (review M2). `RLIMIT_NPROC` counts every process of
/// the browser user. Core dumps stay off.
const BROWSER_RLIMIT_NOFILE: u64 = 8192;
const BROWSER_RLIMIT_NPROC: u64 = 4096;
const BROWSER_RLIMIT_AS: u64 = libc::RLIM_INFINITY;

pub const CDP_MAX_REQUEST_BYTES: usize = 8 * 1024;
pub const CDP_MAX_RESPONSE_MESSAGES: usize = 64;
pub const CDP_MAX_RESPONSE_TOTAL_BYTES: usize = 64 * 1024;
pub const CDP_MAX_TIMEOUT: Duration = Duration::from_secs(30);
pub const CDP_MIN_TIMEOUT: Duration = Duration::from_millis(100);
const CDP_READ_BUF_SIZE: usize = 16 * 1024;
/// The interception extension's manifest. It carries the committed public `key` that fixes the
/// extension ID ([`AGENT_EXTENSION_ID`]); it is written verbatim, never edited.
const EXTENSION_MANIFEST_TEMPLATE: &str =
    include_str!("../../assets/agent-extension/manifest.json");
/// The interception extension's service worker; its placeholders are filled in per lease.
const EXTENSION_WORKER_TEMPLATE: &str = include_str!("../../assets/agent-extension/worker.js");
/// The placeholder prefix of `worker.js`; none may survive rendering.
const EXTENSION_PLACEHOLDER_PREFIX: &str = "__PASSLESS_";
/// The extension ID that the committed manifest `key` gives (checked by a unit test). The native
/// messaging host admits only this origin.
pub const AGENT_EXTENSION_ID: &str = "lfbahamapdlbimlffmhiomfdemnjhjkc";
/// Request id of the daemon's own `Target.createTarget` that opens a deferred start URL in pipe
/// mode. The launch sends it before any principal can reach the pipe.
const START_URL_CDP_ID: u64 = 2_000_000_001;
/// The page an intercepted browser starts on, before its start URL is opened.
const BLANK_START_URL: &str = "about:blank";

fn process_epoch() -> &'static Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseState {
    AuthenticationPending,
    Active,
    Revoked,
    BrowserExit,
    PrincipalExit,
    DaemonShutdown,
}

impl LeaseState {
    pub fn is_terminal(self) -> bool {
        !matches!(self, LeaseState::AuthenticationPending | LeaseState::Active)
    }
}

impl fmt::Display for LeaseState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LeaseState::AuthenticationPending => write!(f, "authentication-pending"),
            LeaseState::Active => write!(f, "active"),
            LeaseState::Revoked => write!(f, "revoked"),
            LeaseState::BrowserExit => write!(f, "browser-exit"),
            LeaseState::PrincipalExit => write!(f, "principal-exit"),
            LeaseState::DaemonShutdown => write!(f, "daemon-shutdown"),
        }
    }
}

pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
    fn monotonic_secs(&self) -> u64;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn monotonic_secs(&self) -> u64 {
        process_epoch().elapsed().as_secs()
    }
}

#[cfg(test)]
use std::sync::Mutex;

#[cfg(test)]
pub struct MockClock {
    inner: Mutex<MockClockInner>,
}

#[cfg(test)]
struct MockClockInner {
    base: Instant,
    offset: Duration,
}

#[cfg(test)]
impl MockClock {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(MockClockInner {
                base: Instant::now(),
                offset: Duration::ZERO,
            }),
        }
    }

    pub fn advance(&self, d: Duration) {
        self.inner.lock().unwrap().offset += d;
    }

    pub fn set_offset(&self, d: Duration) {
        self.inner.lock().unwrap().offset = d;
    }
}

#[cfg(test)]
impl Default for MockClock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl Clock for MockClock {
    fn now(&self) -> Instant {
        let inner = self.inner.lock().unwrap();
        inner.base + inner.offset
    }

    fn monotonic_secs(&self) -> u64 {
        let inner = self.inner.lock().unwrap();
        inner.offset.as_secs()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_time_ticks: u64,
    pub cgroup: String,
}

impl ProcessIdentity {
    pub fn is_valid(&self) -> bool {
        self.start_time_ticks != 0 && !self.cgroup.trim().is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileFingerprint {
    pub inode: u64,
    pub dev: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserManifest {
    pub lease_id: String,
    pub profile_id: String,
    pub pid: u32,
    pub pgid: u32,
    pub process_identity: ProcessIdentity,
    pub profile_fingerprint: ProfileFingerprint,
    pub runtime_dir: PathBuf,
    pub profile_dir: PathBuf,
    pub created_monotonic_secs: u64,
    pub ttl_monotonic_secs: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentEndpointMetadata {
    pub socket_path: String,
    pub bearer_token: String,
}

/// The bearer authorizes ceremonies for its session, so it never reaches a log or a panic message
/// through `{:?}` (ADR 0014 section 12: records never contain bearers).
impl std::fmt::Debug for AgentEndpointMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentEndpointMetadata")
            .field("socket_path", &self.socket_path)
            .field("bearer_token", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct BrowserConfig {
    pub executable: PathBuf,
    pub start_url: Option<String>,
    pub extra_args: Vec<String>,
    pub runtime_root: PathBuf,
    #[allow(dead_code)]
    pub ttl: Duration,
    pub login_timeout: Duration,
    pub rp_ids: Vec<String>,
    /// The profile's rules, used to validate the launch URL (`validate_start_url`).
    pub start_url_rules: Vec<AgentRpRule>,
    pub target_uid: u32,
    pub target_gid: u32,
    pub daemon_uid: u32,
    pub daemon_gid: u32,
    pub cdp_expose: CdpExposeMode,
    pub cdp_port: u16,
    pub bind_parent_death: bool,
}

/// Removes a lease's runtime directory (which holds `worker.js` with the bearer token) when a launch
/// fails. Disarmed once the lease is registered; from then on `cleanup` owns the directory.
struct LaunchDirGuard {
    runtime_dir: PathBuf,
    armed: bool,
}

impl LaunchDirGuard {
    fn new(runtime_dir: PathBuf) -> Self {
        Self {
            runtime_dir,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for LaunchDirGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Never follow a symlink; `remove_dir_all` does not follow symlinks inside the tree either.
        match fs::symlink_metadata(&self.runtime_dir) {
            Ok(meta) if meta.file_type().is_dir() => {
                if let Err(e) = fs::remove_dir_all(&self.runtime_dir) {
                    log::warn!(
                        "failed to remove runtime dir {} after a failed launch: {}",
                        self.runtime_dir.display(),
                        e
                    );
                }
            }
            _ => {}
        }
    }
}

pub trait ChildSpawner: Send + Sync {
    /// Spawn the pipe-mode browser. `containment` is the launch's native-path containment (ADR
    /// 0014 section 7): the production spawner runs the browser in its private `/dev`, or makes
    /// the child refuse to exec when its user could open a hidraw node.
    fn spawn_browser(
        &self,
        config: &BrowserConfig,
        profile_dir: &Path,
        cdp: &CdpPipes,
        containment: &ContainmentPlan,
    ) -> Result<Child, LaunchError>;
}

pub struct ProductionSpawner;

impl ChildSpawner for ProductionSpawner {
    fn spawn_browser(
        &self,
        config: &BrowserConfig,
        profile_dir: &Path,
        cdp: &CdpPipes,
        containment: &ContainmentPlan,
    ) -> Result<Child, LaunchError> {
        spawn_browser_hardened(config, profile_dir, cdp, containment)
    }
}

#[cfg(test)]
pub struct FakeSpawner;

#[cfg(test)]
impl ChildSpawner for FakeSpawner {
    fn spawn_browser(
        &self,
        config: &BrowserConfig,
        profile_dir: &Path,
        cdp: &CdpPipes,
        _containment: &ContainmentPlan,
    ) -> Result<Child, LaunchError> {
        spawn_browser_unhardened(config, profile_dir, cdp)
    }
}

#[cfg(test)]
pub struct TestSpawner;

#[cfg(test)]
impl ChildSpawner for TestSpawner {
    fn spawn_browser(
        &self,
        _config: &BrowserConfig,
        _profile_dir: &Path,
        _cdp: &CdpPipes,
        _containment: &ContainmentPlan,
    ) -> Result<Child, LaunchError> {
        Command::new("/bin/true")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| LaunchError::SpawnFailed(e.to_string()))
    }
}

#[cfg(test)]
pub struct DirectExecSpawner;

#[cfg(test)]
impl ChildSpawner for DirectExecSpawner {
    fn spawn_browser(
        &self,
        config: &BrowserConfig,
        _profile_dir: &Path,
        _cdp: &CdpPipes,
        _containment: &ContainmentPlan,
    ) -> Result<Child, LaunchError> {
        let mut cmd = Command::new(&config.executable);
        for arg in &config.extra_args {
            cmd.arg(arg);
        }
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| LaunchError::SpawnFailed(e.to_string()))
    }
}

impl BrowserConfig {
    pub fn hardening(&self) -> HardenedChildSetup {
        HardenedChildSetup {
            target_uid: self.target_uid,
            target_gid: self.target_gid,
            daemon_uid: self.daemon_uid,
            daemon_gid: self.daemon_gid,
            rlimit_nofile: BROWSER_RLIMIT_NOFILE,
            rlimit_nproc: BROWSER_RLIMIT_NPROC,
            rlimit_core: DEFAULT_RLIMIT_CORE,
            rlimit_as: BROWSER_RLIMIT_AS,
            bind_parent_death: self.bind_parent_death,
        }
    }
}

/// CDP (Chrome DevTools Protocol) pipe endpoints for browser communication.
///
/// The daemon maintains sole authority over the CDP connection:
/// - `daemon_to_browser_write` / `browser_from_daemon_read`: daemon → browser (fd 3 in child)
/// - `daemon_from_browser_read` / `browser_to_daemon_write`: browser → daemon (fd 4 in child)
///
/// All pipe endpoints are created with O_CLOEXEC to prevent fd leakage to unrelated children.
/// The daemon is the sole controller of the CDP session; the browser child cannot redirect
/// or intercept the pipe endpoints. The child's pipe ends are placed on fixed fds 3 and 4
/// with O_CLOEXEC cleared so they survive exec; all other fds are closed via close_range.
#[derive(Debug)]
pub struct CdpPipes {
    pub daemon_to_browser_write: RawFd,
    pub browser_from_daemon_read: RawFd,
    pub daemon_from_browser_read: RawFd,
    pub browser_to_daemon_write: RawFd,
}

impl Drop for CdpPipes {
    fn drop(&mut self) {
        for fd in [
            self.daemon_to_browser_write,
            self.browser_from_daemon_read,
            self.daemon_from_browser_read,
            self.browser_to_daemon_write,
        ] {
            if fd >= 0 {
                unsafe { libc::close(fd) };
            }
        }
    }
}

#[derive(Debug)]
pub struct DaemonCdpEndpoints {
    pub to_browser: fs::File,
    pub from_browser: fs::File,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionError {
    InvalidTransition { from: LeaseState, to: LeaseState },
    NotFound,
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransitionError::InvalidTransition { from, to } => {
                write!(f, "invalid lease transition: {} → {}", from, to)
            }
            TransitionError::NotFound => write!(f, "lease not found"),
        }
    }
}

impl std::error::Error for TransitionError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivationError {
    NotFound,
    NotPending { current: LeaseState },
    LoginDeadlineExpired,
}

impl fmt::Display for ActivationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActivationError::NotFound => write!(f, "lease not found"),
            ActivationError::NotPending { current } => {
                write!(f, "lease not pending (current state: {})", current)
            }
            ActivationError::LoginDeadlineExpired => write!(f, "login deadline expired"),
        }
    }
}

impl std::error::Error for ActivationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchError {
    DirCreationFailed(String, String),
    PipeCreationFailed(String),
    SpawnFailed(String),
    ManifestWriteFailed(String, String),
    InvalidStartUrl(String),
    RuntimeRootInvalid(String),
    HardeningFailed(String),
    CdpDiscoveryTimeout,
    BrowserExitedBeforeCdp(String),
    InvalidArg(String),
    EndpointFileWriteFailed(String, String),
    ExtensionSetupFailed(String),
    InvalidCdpEndpoint(String),
    /// The extension worker did not report the WebAuthn proxy attached in time (plan D6 layer 1).
    InterceptionNotAttached(String),
    /// The extension worker attached the proxy but is not allowed in incognito, so off-the-record
    /// and CDP-created contexts would not be intercepted (plan D4, R13).
    IncognitoNotAllowed(String),
    /// The browser's user could open a hidraw device and no private `/dev` is available (ADR 0014
    /// section 7, invariant 25). The message says how to fix it.
    ContainmentRefused(String),
    /// The profile's fixed `browser_cdp_port` is already held on `127.0.0.1` (by `holder`), so
    /// whatever answered there would not be the managed browser. Nothing was started.
    CdpPortInUse {
        port: u16,
        holder: String,
    },
    /// The CDP listener on `127.0.0.1:<port>` could not be proven to belong to the launched
    /// browser; the browser was stopped and no endpoint was handed out.
    CdpEndpointNotOwned {
        port: u16,
        reason: String,
    },
}

/// The fix for a fixed `browser_cdp_port` that someone else holds.
const CDP_PORT_FIX: &str = "remove browser_cdp_port from the profile to use an ephemeral port \
                            (recommended), or choose a free one";

impl fmt::Display for LaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LaunchError::DirCreationFailed(path, e) => {
                write!(f, "failed to create directory '{}': {}", path, e)
            }
            LaunchError::PipeCreationFailed(e) => {
                write!(f, "failed to create CDP pipes: {}", e)
            }
            LaunchError::SpawnFailed(e) => write!(f, "failed to spawn browser: {}", e),
            LaunchError::ManifestWriteFailed(path, e) => {
                write!(f, "failed to write manifest '{}': {}", path, e)
            }
            LaunchError::InvalidStartUrl(url) => write!(f, "invalid start URL: {}", url),
            LaunchError::RuntimeRootInvalid(msg) => {
                write!(f, "invalid runtime root: {}", msg)
            }
            LaunchError::HardeningFailed(msg) => {
                write!(f, "browser hardening failed: {}", msg)
            }
            LaunchError::CdpDiscoveryTimeout => {
                write!(
                    f,
                    "timed out waiting for browser CDP endpoint: the browser never opened its \
                     debugging port and was stopped. Likely causes: a browser that could not \
                     load the passless agent extension (headed Chromium shows a blocking \"Error \
                     Loading Extension\" dialog before it opens the port), a fixed \
                     browser_cdp_port the browser could not bind (remove browser_cdp_port to use \
                     an ephemeral port), or a browser that failed to start; check that the \
                     browser is Chromium 116 or later, that its display is usable, and the \
                     daemon log"
                )
            }
            LaunchError::BrowserExitedBeforeCdp(status) => {
                write!(f, "browser exited before CDP became ready: {}", status)
            }
            LaunchError::InvalidArg(msg) => {
                write!(f, "invalid browser argument: {}", msg)
            }
            LaunchError::EndpointFileWriteFailed(path, e) => {
                write!(f, "failed to write CDP endpoint file '{}': {}", path, e)
            }
            LaunchError::ExtensionSetupFailed(msg) => {
                write!(f, "extension setup failed: {}", msg)
            }
            LaunchError::InvalidCdpEndpoint(msg) => {
                write!(f, "invalid CDP endpoint: {}", msg)
            }
            LaunchError::InterceptionNotAttached(msg) => write!(
                f,
                "the passless agent extension did not attach the WebAuthn proxy ({}); the \
                 browser was stopped so that no WebAuthn request reaches the human \
                 authenticator. Check that the browser supports chrome.webAuthenticationProxy \
                 (Chromium 116 or later), that sign-proxy is installed next to passless, and \
                 the daemon log for sign transport errors",
                msg
            ),
            LaunchError::IncognitoNotAllowed(msg) => write!(
                f,
                "the passless agent extension is not allowed in incognito ({}), so off-the-record \
                 and CDP-created browser contexts would not be intercepted and their WebAuthn \
                 requests could reach the human authenticator; the browser was stopped. The \
                 launcher seeds Default/Preferences with incognito access for the extension; \
                 this browser did not honour it (an unsupported browser, or one that enforces \
                 preference MACs). Use Chromium or Chrome for Testing",
                msg
            ),
            LaunchError::ContainmentRefused(msg) => f.write_str(msg),
            LaunchError::CdpPortInUse { port, holder } => write!(
                f,
                "browser_cdp_port {port} on 127.0.0.1 is already in use ({holder}); the managed \
                 browser was not started, because the endpoint on that port would not be its. \
                 {CDP_PORT_FIX}"
            ),
            LaunchError::CdpEndpointNotOwned { port, reason } => write!(
                f,
                "the CDP endpoint on 127.0.0.1:{port} does not belong to the launched browser \
                 ({reason}); the browser was stopped and no endpoint was handed out. If \
                 browser_cdp_port is set, {CDP_PORT_FIX}"
            ),
        }
    }
}

impl std::error::Error for LaunchError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupSafety {
    Clean,
    Quarantined {
        reason: String,
        quarantine_path: PathBuf,
    },
    Failed {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdpError {
    InvalidRequest(String),
    LeaseNotFound,
    NoCdpEndpoints,
    BrowserExited,
    WriteFailed(String),
    ReadFailed(String),
    Timeout,
    ResponseTooLarge,
    TooManyMessages,
    /// The pipe-mode extension filter refused the request (`cdp_filter.rs`, review M3).
    Denied(String),
    /// Another `browser-control` call of this lease is still waiting for its answer. The pipe is
    /// one stream: two calls would take each other's responses.
    Busy,
}

impl fmt::Display for CdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(msg) => write!(f, "invalid CDP request: {}", msg),
            Self::LeaseNotFound => write!(f, "lease not found"),
            Self::NoCdpEndpoints => write!(f, "no CDP endpoints available"),
            Self::BrowserExited => write!(f, "browser process has exited"),
            Self::WriteFailed(e) => write!(f, "CDP write failed: {}", e),
            Self::ReadFailed(e) => write!(f, "CDP read failed: {}", e),
            Self::Timeout => write!(f, "CDP round-trip timed out"),
            Self::ResponseTooLarge => write!(f, "CDP response exceeds size limit"),
            Self::TooManyMessages => write!(f, "CDP response exceeds message count limit"),
            Self::Denied(reason) => write!(f, "CDP request denied: {}", reason),
            Self::Busy => write!(
                f,
                "another browser-control call of this browser is still running"
            ),
        }
    }
}

impl std::error::Error for CdpError {}

#[derive(Debug)]
pub struct CdpRoundTripResult {
    pub messages: Vec<String>,
}

/// A `browser-control` call that has written its request and is collecting the answer
/// ([`BrowserProcessManager::cdp_begin`], [`BrowserProcessManager::cdp_step`]).
#[derive(Debug)]
pub struct CdpCall {
    request_id: Option<serde_json::Number>,
    deadline: Instant,
    messages: Vec<String>,
    total_bytes: usize,
}

/// How long one [`cdp_round_trip_shared`] step holds the browser manager before it lets go.
const CDP_STEP_SLICE: Duration = Duration::from_millis(50);
/// The pause between two steps, so that a thread waiting for the manager gets it.
const CDP_STEP_GAP: Duration = Duration::from_millis(2);

/// One `browser-control` round trip that does not hold the browser manager while it waits.
///
/// The browser's answer can take as long as the agent's timeout (a `Runtime.evaluate` with
/// `awaitPromise` waits for a WebAuthn ceremony), and that ceremony needs the manager to activate
/// the lease after its first assertion. So the call takes the manager only for its steps (the
/// request, then slices of at most [`CDP_STEP_SLICE`] reading the pipe) and releases it in
/// between, as the runtime loop and every other launch, status and activation need it too. The
/// lease's `cdp_busy` flag keeps a second call from reading the first one's answer meanwhile.
pub fn cdp_round_trip_shared(
    manager: &std::sync::Mutex<BrowserProcessManager>,
    lease_id: &BrowserLeaseId,
    request_json: &str,
    timeout: Duration,
) -> Result<CdpRoundTripResult, CdpError> {
    let lock = || {
        crate::agent::lock_order::lock(manager, crate::agent::lock_order::LockLevel::BrowserManager)
    };
    let mut call = lock().cdp_begin(lease_id, request_json, timeout, true)?;
    let result = loop {
        match lock().cdp_step(lease_id, &mut call, CDP_STEP_SLICE) {
            Ok(Some(result)) => break Ok(result),
            Ok(None) => std::thread::sleep(CDP_STEP_GAP),
            Err(e) => break Err(e),
        }
    };
    lock().cdp_end(lease_id);
    result
}

#[derive(Debug)]
pub struct BrowserExitInfo {
    pub lease_id: BrowserLeaseId,
    #[allow(dead_code)]
    pub pid: u32,
    pub exit_code: Option<i32>,
}

#[derive(Debug)]
pub struct TerminateResult {
    #[allow(dead_code)]
    pub exit_status: Option<ExitStatus>,
    #[allow(dead_code)]
    pub sigkill_sent: bool,
    #[allow(dead_code)]
    pub elapsed: Duration,
}

#[derive(Debug)]
pub struct BrowserLease {
    pub id: BrowserLeaseId,
    pub profile_id: ProfileId,
    pub state: LeaseState,
    pub manifest: BrowserManifest,
    pub login_deadline: Instant,
    pub ttl_deadline: Instant,
    pub child: Option<Child>,
    /// The lease directory, pinned when it was created: the daemon's later writes into it (the
    /// `cdp-endpoint` file) go through this handle, never through the path (review H1).
    runtime_dir_handle: Option<Dir>,
    pub cdp: Option<DaemonCdpEndpoints>,
    pub cdp_buffer: VecDeque<String>,
    pub cdp_read_buf: Vec<u8>,
    /// A `browser-control` call is waiting for its answer on the pipe.
    cdp_busy: bool,
    /// Keeps the agent's pipe-mode CDP traffic away from the Passless extension (review M3).
    cdp_filter: ExtensionCdpFilter,
    pub child_reaped: bool,
    pub cdp_endpoint: Option<String>,
    pub start_url: Option<String>,
    /// The start URL of an intercepted lease, held back until its extension worker attached the
    /// WebAuthn proxy (defect B2); `open_deferred_start_url` takes it.
    deferred_start_url: Option<String>,
    /// The interception state of a lease launched with the agent extension.
    interception: Option<LeaseInterception>,
}

/// What the manager tracks about a lease's WebAuthn interception (plan D6 layer 1). The readiness
/// itself lives in the sign transport's `ReadinessRegistry`, keyed by the bearer.
struct LeaseInterception {
    /// The bearer templated into the lease's `worker.js`; the worker says hello with it.
    bearer: String,
    /// The launch saw the worker attach (`await_interception` succeeded).
    confirmed: bool,
    /// The lease was reported (logged and audited) as degraded and has not re-attached since.
    degraded_reported: bool,
    /// Owner of the lease's `cdp-endpoint` file (port mode), written while attached.
    endpoint_file_owner: (u32, u32),
}

impl fmt::Debug for LeaseInterception {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeaseInterception")
            .field("bearer", &"<redacted>")
            .field("confirmed", &self.confirmed)
            .field("degraded_reported", &self.degraded_reported)
            .finish()
    }
}

/// How long a launch waits for the extension worker to report the WebAuthn proxy attached before
/// it fails closed (plan D6 layer 1). Headed Chrome for Testing under Xvfb can take a while.
pub const INTERCEPTION_ATTACH_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a launched lease may stay unattached (worker reconnecting) before it is degraded.
pub const INTERCEPTION_DEGRADED_GRACE: Duration = Duration::from_secs(10);

/// Whether a lease's WebAuthn requests are intercepted (plan D6 layer 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterceptionState {
    /// The worker is connected, reports the WebAuthn proxy attached and is allowed in incognito
    /// ([`BearerReadiness::intercepting`]).
    Attached,
    /// Not attached, but for less than the grace period (the worker is reconnecting), or the
    /// launch has not seen the worker attach yet.
    Pending,
    /// Not attached for longer than the grace period. The endpoint is not handed out.
    Degraded,
}

impl InterceptionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attached => "attached",
            Self::Pending => "pending",
            Self::Degraded => "degraded",
        }
    }

    /// The state of a lease whose launch saw its worker attach, from the bearer's last reported
    /// readiness. A missing record is degraded (fail closed).
    pub fn of_confirmed(
        readiness: Option<&BearerReadiness>,
        now: Instant,
        grace: Duration,
    ) -> Self {
        let Some(readiness) = readiness else {
            return Self::Degraded;
        };
        if readiness.intercepting() {
            return Self::Attached;
        }
        match readiness.detached_since {
            Some(since) if now.saturating_duration_since(since) < grace => Self::Pending,
            _ => Self::Degraded,
        }
    }
}

impl fmt::Display for InterceptionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a wait for a lease's worker to intercept failed.
enum AttachFailure {
    /// Attached, but not allowed in incognito (plan D4: the seed did not take effect).
    IncognitoNotAllowed(String),
    Other(String),
}

/// An interception state change that the runtime logs and audits once (see
/// `BrowserProcessManager::poll_interception`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterceptionTransition {
    pub lease_id: BrowserLeaseId,
    pub profile_id: ProfileId,
    pub degraded: bool,
}

/// Opens a lease's deferred start URL once its interception is ready. Injectable for tests.
pub trait StartUrlOpener: Send + Sync {
    fn open(
        &self,
        manager: &mut BrowserProcessManager,
        lease_id: &BrowserLeaseId,
        url: &str,
    ) -> Result<(), String>;
}

/// Opens the URL in a new tab over CDP: `Target.createTarget` on the daemon's pipe in pipe mode,
/// `PUT /json/new` on the loopback DevTools port in port mode.
pub struct CdpStartUrlOpener;

impl StartUrlOpener for CdpStartUrlOpener {
    fn open(
        &self,
        manager: &mut BrowserProcessManager,
        lease_id: &BrowserLeaseId,
        url: &str,
    ) -> Result<(), String> {
        match manager.lease_has_cdp_pipes(lease_id) {
            None => Err("lease not found".to_string()),
            Some(true) => {
                let request = serde_json::json!({
                    "id": START_URL_CDP_ID,
                    "method": "Target.createTarget",
                    "params": {"url": url},
                })
                .to_string();
                let result = manager
                    .daemon_cdp_round_trip(lease_id, &request, START_URL_OPEN_TIMEOUT)
                    .map_err(|e| e.to_string())?;
                let id = serde_json::Number::from(START_URL_CDP_ID);
                let reply = result
                    .messages
                    .iter()
                    .find(|m| cdp_message_has_id(m, &id))
                    .ok_or("no reply to Target.createTarget")?;
                match serde_json::from_str::<serde_json::Value>(reply) {
                    Ok(v) if v.get("error").is_none() => Ok(()),
                    _ => Err(format!("Target.createTarget failed: {reply}")),
                }
            }
            Some(false) => {
                let endpoint = manager
                    .lease_cdp_endpoint(lease_id)
                    .flatten()
                    .ok_or("the lease has no CDP endpoint")?;
                open_url_over_devtools_http(&endpoint, url)
            }
        }
    }
}

/// How long opening a deferred start URL may take.
const START_URL_OPEN_TIMEOUT: Duration = Duration::from_secs(5);

/// `PUT http://127.0.0.1:<port>/json/new?<url>` on the DevTools HTTP endpoint of a port-mode
/// browser, whose port is taken from its (already loopback-validated) WebSocket URL.
fn open_url_over_devtools_http(ws_endpoint: &str, url: &str) -> Result<(), String> {
    validate_loopback_ws_url(ws_endpoint).map_err(|e| e.to_string())?;
    let port = url::Url::parse(ws_endpoint)
        .ok()
        .and_then(|u| u.port())
        .ok_or("the CDP endpoint has no port")?;
    let encoded: String = url::form_urlencoded::byte_serialize(url.as_bytes()).collect();
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = std::net::TcpStream::connect_timeout(&addr, START_URL_OPEN_TIMEOUT)
        .map_err(|e| format!("connect to the DevTools port: {e}"))?;
    let _ = stream.set_read_timeout(Some(START_URL_OPEN_TIMEOUT));
    let _ = stream.set_write_timeout(Some(START_URL_OPEN_TIMEOUT));
    let request = format!(
        "PUT /json/new?{encoded} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write to the DevTools port: {e}"))?;
    let mut status = [0u8; 12];
    stream
        .read_exact(&mut status)
        .map_err(|e| format!("read the DevTools reply: {e}"))?;
    if status.starts_with(b"HTTP/1.1 200") || status.starts_with(b"HTTP/1.0 200") {
        Ok(())
    } else {
        Err(format!(
            "DevTools /json/new answered {}",
            String::from_utf8_lossy(&status)
        ))
    }
}

#[derive(Debug, Clone)]
pub struct LeaseSnapshot {
    #[allow(dead_code)]
    pub id: BrowserLeaseId,
    pub profile_id: ProfileId,
    pub state: LeaseState,
    #[allow(dead_code)]
    pub pid: u32,
    #[allow(dead_code)]
    pub ttl_remaining_secs: u64,
    pub start_url: Option<String>,
}

pub struct BrowserProcessManager {
    leases: HashMap<BrowserLeaseId, BrowserLease>,
    clock: Arc<dyn Clock>,
    sigterm_timeout: Duration,
    sigkill_timeout: Duration,
    spawner: Arc<dyn ChildSpawner>,
    start_url_opener: Arc<dyn StartUrlOpener>,
    /// Where the `sign-proxy` relay is; `None` means next to the running executable
    /// (`installed_sign_proxy_path`). Tests point it elsewhere.
    sign_proxy_path: Option<PathBuf>,
    /// Native-path containment of the browsers it launches (ADR 0014 section 7). Production
    /// managers use `Auto`; the test constructors turn it off for their fake browsers.
    containment: ContainmentPolicy,
}

#[allow(dead_code)]
impl BrowserProcessManager {
    #[cfg(test)]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            leases: HashMap::new(),
            clock,
            sigterm_timeout: DEFAULT_SIGTERM_TIMEOUT,
            sigkill_timeout: DEFAULT_SIGKILL_TIMEOUT,
            spawner: Arc::new(FakeSpawner),
            start_url_opener: Arc::new(CdpStartUrlOpener),
            sign_proxy_path: Some(tests::test_sign_proxy_path()),
            containment: ContainmentPolicy::Off,
        }
    }

    #[cfg(test)]
    pub fn with_spawner(clock: Arc<dyn Clock>, spawner: Arc<dyn ChildSpawner>) -> Self {
        Self {
            leases: HashMap::new(),
            clock,
            sigterm_timeout: DEFAULT_SIGTERM_TIMEOUT,
            sigkill_timeout: DEFAULT_SIGKILL_TIMEOUT,
            spawner,
            start_url_opener: Arc::new(CdpStartUrlOpener),
            sign_proxy_path: Some(tests::test_sign_proxy_path()),
            containment: ContainmentPolicy::Off,
        }
    }

    #[cfg(test)]
    pub fn with_timeouts(
        clock: Arc<dyn Clock>,
        sigterm_timeout: Duration,
        sigkill_timeout: Duration,
    ) -> Self {
        Self {
            leases: HashMap::new(),
            clock,
            sigterm_timeout,
            sigkill_timeout,
            spawner: Arc::new(FakeSpawner),
            start_url_opener: Arc::new(CdpStartUrlOpener),
            sign_proxy_path: Some(tests::test_sign_proxy_path()),
            containment: ContainmentPolicy::Off,
        }
    }

    pub fn production(clock: Arc<dyn Clock>) -> Self {
        Self {
            leases: HashMap::new(),
            clock,
            sigterm_timeout: DEFAULT_SIGTERM_TIMEOUT,
            sigkill_timeout: DEFAULT_SIGKILL_TIMEOUT,
            spawner: Arc::new(ProductionSpawner),
            start_url_opener: Arc::new(CdpStartUrlOpener),
            sign_proxy_path: None,
            containment: ContainmentPolicy::Auto,
        }
    }

    pub fn launch(
        &mut self,
        config: &BrowserConfig,
        profile_id: ProfileId,
    ) -> Result<BrowserLeaseId, LaunchError> {
        let lease_id = self.launch_pending(config, profile_id)?;
        let session_ttl = clamp_ttl(config.ttl);
        self.activate_after_assertion(&lease_id, session_ttl)
            .map_err(|e| LaunchError::SpawnFailed(format!("immediate activation failed: {}", e)))?;
        Ok(lease_id)
    }

    pub fn launch_pending(
        &mut self,
        config: &BrowserConfig,
        profile_id: ProfileId,
    ) -> Result<BrowserLeaseId, LaunchError> {
        self.launch_pending_with_agent_endpoint(config, profile_id, None)
    }

    pub fn launch_pending_with_agent_endpoint(
        &mut self,
        config: &BrowserConfig,
        profile_id: ProfileId,
        agent_endpoint: Option<&AgentEndpointMetadata>,
    ) -> Result<BrowserLeaseId, LaunchError> {
        config
            .hardening()
            .validate()
            .map_err(|e| LaunchError::HardeningFailed(e.to_string()))?;

        // A fixed CDP port that something already holds is refused before anything is created:
        // Chromium would not fail but listen on `[::1]` instead, and the holder would answer on
        // `127.0.0.1`. A holder that appears after this probe is caught by the ownership check
        // after the launch (`await_owned_cdp_endpoint`).
        if config.cdp_expose == CdpExposeMode::Port && config.cdp_port > 0 && !skip_cdp_port_probe()
        {
            super::cdp_owner::ensure_port_free(config.cdp_port).map_err(|holder| {
                LaunchError::CdpPortInUse {
                    port: config.cdp_port,
                    holder,
                }
            })?;
        }

        let lease_id = BrowserLeaseId::new();
        let now = self.clock.now();
        let monotonic_secs = self.clock.monotonic_secs();
        let login_clamped = clamp_login_timeout(config.login_timeout);

        // Every daemon write below goes through pinned directory handles (`safe_fs`): the runtime
        // root may belong to the browser user, so no path the daemon writes through may contain a
        // component that user could swap for a symlink (review H1).
        ensure_runtime_root(&config.runtime_root, config.target_uid, config.target_gid).map_err(
            |e| {
                LaunchError::RuntimeRootInvalid(format!("{}: {}", config.runtime_root.display(), e))
            },
        )?;
        let root = open_runtime_root(&config.runtime_root, config.target_uid).map_err(|e| {
            LaunchError::RuntimeRootInvalid(format!("{}: {}", config.runtime_root.display(), e))
        })?;

        let lease_name = format!("lease-{}", lease_id.as_str());
        let runtime_dir = config.runtime_root.join(&lease_name);
        let profile_dir = runtime_dir.join("profile");

        // Every error path below removes the runtime dir (it holds the extension worker's bearer token).
        let mut dir_guard = LaunchDirGuard::new(runtime_dir.clone());

        // The lease directory stays the daemon's (group: the browser's, traverse only), so the
        // browser user can neither plant nor swap anything the daemon writes or rewrites in it.
        let lease_dir = root
            .create_dir(&lease_name, LEASE_DIR_MODE)
            .and_then(|dir| {
                // SAFETY: no preconditions.
                dir.chown(unsafe { libc::geteuid() }, config.target_gid)?;
                Ok(dir)
            })
            .map_err(|e| {
                LaunchError::DirCreationFailed(runtime_dir.display().to_string(), e.to_string())
            })?;
        let profile = lease_dir
            .create_dir("profile", RUNTIME_DIR_MODE)
            .map_err(|e| {
                LaunchError::DirCreationFailed(profile_dir.display().to_string(), e.to_string())
            })?;

        let mut relay_path = None;
        if let Some(metadata) = agent_endpoint {
            let ext_dir = generate_agent_extension_in(
                &lease_dir,
                &runtime_dir,
                metadata,
                config.target_uid,
                config.target_gid,
            )?;
            // Verified before anything is spawned: a missing or unreadable extension is a launch
            // error, never a browser without interception.
            let ext_pinned = lease_dir.open_dir(AGENT_EXTENSION_DIR).map_err(|e| {
                extension_check_failure(format!(
                    "extension directory {} is unavailable: {e}",
                    ext_dir.display()
                ))
            })?;
            verify_extension_dir_in(&ext_pinned, &ext_dir, config.target_uid)?;
            // Without the relay the worker cannot reach the daemon, so nothing is intercepted: a
            // missing relay is a launch error too.
            let sign_proxy = self
                .sign_proxy_path
                .clone()
                .or_else(installed_sign_proxy_path)
                .ok_or_else(|| {
                    LaunchError::ExtensionSetupFailed(
                        "cannot locate the sign-proxy relay (the executable path is unknown)"
                            .into(),
                    )
                })?;
            if !sign_proxy.is_file() {
                return Err(LaunchError::ExtensionSetupFailed(format!(
                    "the sign-proxy relay is missing at {}; refusing to launch the managed \
                     browser without WebAuthn interception. Reinstall passless so that \
                     sign-proxy is installed next to the passless executable",
                    sign_proxy.display()
                )));
            }
            install_native_messaging_manifest_in(&profile, &sign_proxy)?;
            // The extension must also run in off-the-record and CDP-created contexts, or their
            // requests would go native (ADR 0014 section 4.2); the worker's hello reports whether
            // this took effect, and the launch fails closed if it did not.
            seed_incognito_access_in(&profile, config.target_uid, config.target_gid)?;
            relay_path = Some(sign_proxy);
        }

        // The profile is the only directory the browser user owns: handed over after the daemon's
        // writes into it and before the browser starts. The daemon never writes into it again; it
        // only reads `DevToolsActivePort` from it (`O_NOFOLLOW`, owner-checked) and unlinks that.
        profile
            .chown(config.target_uid, config.target_gid)
            .map_err(|e| {
                LaunchError::DirCreationFailed(profile_dir.display().to_string(), e.to_string())
            })?;
        let profile_fp = profile
            .stat()
            .map(|st| ProfileFingerprint {
                inode: st.st_ino,
                dev: st.st_dev,
            })
            .map_err(|e| {
                LaunchError::DirCreationFailed(profile_dir.display().to_string(), e.to_string())
            })?;

        if let Some(ref url) = config.start_url {
            validate_start_url(url, &config.start_url_rules)
                .map_err(|_| LaunchError::InvalidStartUrl(url.clone()))?;
        }

        // An intercepted browser starts on a blank page; its start URL is opened only once its
        // worker reported the WebAuthn proxy attached (`open_deferred_start_url`, defect B2):
        // a page loaded earlier could reach the native authenticator.
        let deferred_config;
        let (config, deferred_start_url) = if agent_endpoint.is_some() {
            let mut spawn_config = config.clone();
            let deferred = spawn_config.start_url.replace(BLANK_START_URL.to_string());
            deferred_config = spawn_config;
            (&deferred_config, deferred)
        } else {
            (config, None)
        };

        let is_port_mode = config.cdp_expose == CdpExposeMode::Port;

        // Native-path containment (ADR 0014 section 7, invariant 25): a private /dev through
        // bwrap whenever it works for the browser's user, else a refusal when that user could
        // open a hidraw node.
        let needs_dev_shm = [
            Some(config.executable.as_path()),
            Some(config.runtime_root.as_path()),
            relay_path.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|path| path.starts_with("/dev/shm"));
        let hardening = config.hardening();
        let containment = ContainmentPlan::for_launch(
            &self.containment,
            &hardening,
            is_port_mode && is_trusted_same_user_port_launch(config),
            needs_dev_shm,
        );

        let (cdp_pipes, mut child, cdp_endpoint_url) = if is_port_mode {
            let mut child = spawn_browser_port_mode(config, &profile_dir, &containment)?;
            // Never an endpoint the launched browser is not proven to own: a fixed port is
            // verified through the socket tables alone (Chromium writes no `DevToolsActivePort`
            // for it), an ephemeral one also against the browser's own `DevToolsActivePort`.
            let discovered = if config.cdp_port > 0 {
                await_owned_cdp_endpoint(
                    &mut child,
                    config.cdp_port,
                    config.target_uid,
                    None,
                    Duration::from_secs(30),
                )
            } else {
                discover_cdp_endpoint_with_child(
                    &mut child,
                    &profile,
                    config.target_uid,
                    Duration::from_secs(30),
                )
                .and_then(|(port, path)| {
                    await_owned_cdp_endpoint(
                        &mut child,
                        port,
                        config.target_uid,
                        Some(&path),
                        Duration::from_secs(10),
                    )
                })
            };
            let discovered = match discovered {
                Ok(discovered) => discovered,
                Err(err) => {
                    terminate_failed_browser_spawn(&mut child);
                    return Err(err);
                }
            };
            // The daemon hands out the endpoint, and withholds it while the lease is degraded;
            // Chromium's own discovery file would let a same-UID agent find the port anyway.
            hide_devtools_active_port(&profile, &profile_dir);
            // An intercepted lease's `cdp-endpoint` file is written only once its worker attached
            // (`await_interception`) and removed while it is degraded; see `sync_cdp_endpoint_file`.
            if agent_endpoint.is_none()
                && let Err(err) = write_cdp_endpoint(
                    &lease_dir,
                    &runtime_dir,
                    &discovered,
                    config.target_uid,
                    config.target_gid,
                )
            {
                terminate_failed_browser_spawn(&mut child);
                return Err(err);
            }
            (None, child, Some(discovered))
        } else {
            let cdp =
                create_cdp_pipes().map_err(|e| LaunchError::PipeCreationFailed(e.to_string()))?;
            let child = self
                .spawner
                .spawn_browser(config, &profile_dir, &cdp, &containment)?;
            (Some(cdp), child, None)
        };

        let pid = child.id();
        let pgid = pid;
        if let Some(case) = containment.case_for_log(hardening.target_uid == hardening.daemon_uid) {
            if containment.private_dev() {
                log::info!(
                    "browser lease {} (pid {}): native-path containment {} (private /dev through \
                     bwrap)",
                    lease_id,
                    pid,
                    case
                );
            } else {
                // Not silent: a bwrap probe that failed (for example on a resource limit) left
                // the browser without a private /dev; the child's hidraw check passed.
                log::warn!(
                    "browser lease {} (pid {}): native-path containment {}: running without a \
                     private /dev because {}; the browser user cannot open any hidraw device \
                     now, but one that appears later would be reachable",
                    lease_id,
                    pid,
                    case,
                    containment
                        .unavailable_reason()
                        .unwrap_or("bwrap is unavailable")
                );
            }
        }
        let proc_identity = read_process_identity(pid).ok_or_else(|| {
            LaunchError::SpawnFailed(format!(
                "failed to read identity of spawned pid {} (cgroup/start_time unavailable)",
                pid
            ))
        })?;

        if !proc_identity.is_valid() {
            let _ = unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
            let _ = child.wait();
            return Err(LaunchError::SpawnFailed(format!(
                "spawned pid {} has invalid identity (empty cgroup or zero start_time)",
                pid
            )));
        }

        let login_deadline = now + login_clamped;

        let manifest = BrowserManifest {
            lease_id: lease_id.as_str().to_string(),
            profile_id: profile_id.as_str().to_string(),
            pid,
            pgid,
            process_identity: proc_identity,
            profile_fingerprint: profile_fp,
            runtime_dir: runtime_dir.clone(),
            profile_dir: profile_dir.clone(),
            created_monotonic_secs: monotonic_secs,
            ttl_monotonic_secs: login_clamped.as_secs(),
        };

        write_manifest_atomic(&lease_dir, &runtime_dir, &manifest)?;

        let (daemon_endpoints, consumed_pipes) = if let Some(cdp) = cdp_pipes {
            let endpoints = DaemonCdpEndpoints {
                to_browser: unsafe { fs::File::from_raw_fd(cdp.daemon_to_browser_write) },
                from_browser: unsafe { fs::File::from_raw_fd(cdp.daemon_from_browser_read) },
            };
            (Some(endpoints), Some(cdp))
        } else {
            (None, None)
        };

        let lease = BrowserLease {
            id: lease_id.clone(),
            profile_id,
            state: LeaseState::AuthenticationPending,
            manifest,
            login_deadline,
            ttl_deadline: login_deadline,
            child: Some(child),
            runtime_dir_handle: Some(lease_dir),
            cdp: daemon_endpoints,
            cdp_buffer: VecDeque::new(),
            cdp_read_buf: Vec::with_capacity(CDP_READ_BUF_SIZE),
            cdp_busy: false,
            cdp_filter: ExtensionCdpFilter::new(AGENT_EXTENSION_ID),
            child_reaped: false,
            cdp_endpoint: cdp_endpoint_url,
            start_url: if agent_endpoint.is_some() {
                deferred_start_url.clone()
            } else {
                config.start_url.clone()
            },
            deferred_start_url,
            interception: agent_endpoint.map(|metadata| LeaseInterception {
                bearer: metadata.bearer_token.clone(),
                confirmed: false,
                degraded_reported: false,
                endpoint_file_owner: (config.target_uid, config.target_gid),
            }),
        };

        if let Some(mut consumed) = consumed_pipes {
            consumed.daemon_to_browser_write = -1;
            consumed.daemon_from_browser_read = -1;
        }

        self.leases.insert(lease_id.clone(), lease);
        dir_guard.disarm();

        Ok(lease_id)
    }

    pub fn activate_after_assertion(
        &mut self,
        lease_id: &BrowserLeaseId,
        clamped_session_ttl: Duration,
    ) -> Result<LeaseState, ActivationError> {
        let entry = self
            .leases
            .get_mut(lease_id)
            .ok_or(ActivationError::NotFound)?;

        if entry.state != LeaseState::AuthenticationPending {
            return Err(ActivationError::NotPending {
                current: entry.state,
            });
        }

        let now = self.clock.now();
        if now >= entry.login_deadline {
            return Err(ActivationError::LoginDeadlineExpired);
        }

        let session_ttl = clamp_ttl(clamped_session_ttl);
        entry.state = LeaseState::Active;
        entry.ttl_deadline = now + session_ttl;

        Ok(LeaseState::Active)
    }

    pub fn revoke(&mut self, lease_id: &BrowserLeaseId) -> Result<LeaseState, TransitionError> {
        self.transition(lease_id, LeaseState::Revoked)
    }

    pub fn principal_exit(
        &mut self,
        lease_id: &BrowserLeaseId,
    ) -> Result<LeaseState, TransitionError> {
        self.transition(lease_id, LeaseState::PrincipalExit)
    }

    pub fn daemon_shutdown(
        &mut self,
        lease_id: &BrowserLeaseId,
    ) -> Result<LeaseState, TransitionError> {
        self.transition(lease_id, LeaseState::DaemonShutdown)
    }

    pub fn mark_browser_exit(
        &mut self,
        lease_id: &BrowserLeaseId,
    ) -> Result<LeaseState, TransitionError> {
        self.transition(lease_id, LeaseState::BrowserExit)
    }

    fn transition(
        &mut self,
        lease_id: &BrowserLeaseId,
        target: LeaseState,
    ) -> Result<LeaseState, TransitionError> {
        let entry = self
            .leases
            .get_mut(lease_id)
            .ok_or(TransitionError::NotFound)?;

        let current = entry.state;

        if !is_valid_lease_transition(current, target) {
            return Err(TransitionError::InvalidTransition {
                from: current,
                to: target,
            });
        }

        entry.state = target;
        Ok(target)
    }

    pub fn terminate(
        &mut self,
        lease_id: &BrowserLeaseId,
    ) -> Result<TerminateResult, TransitionError> {
        let entry = self
            .leases
            .get_mut(lease_id)
            .ok_or(TransitionError::NotFound)?;

        let child = match entry.child.as_mut() {
            Some(c) => c,
            None => {
                return Ok(TerminateResult {
                    exit_status: None,
                    sigkill_sent: false,
                    elapsed: Duration::ZERO,
                });
            }
        };

        let pid = child.id();
        let expected = &entry.manifest.process_identity;

        if !reverify_identity(pid, expected) {
            entry.child = None;
            entry.cdp = None;
            return Ok(TerminateResult {
                exit_status: None,
                sigkill_sent: false,
                elapsed: Duration::ZERO,
            });
        }

        let pgid = entry.manifest.pgid;
        let start = Instant::now();

        signal_process_group(pgid, libc::SIGTERM);

        let sigterm_deadline = start + self.sigterm_timeout;
        let mut exit_status = None;

        // Wait for the main process to exit
        loop {
            let mut status: libc::c_int = 0;
            let ret = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
            if ret > 0 {
                exit_status = decode_wait_status(status);
                break;
            }
            if ret < 0 {
                break;
            }
            if Instant::now() >= sigterm_deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        let mut sigkill_sent = false;

        if exit_status.is_none() {
            if reverify_identity(pid, expected) {
                signal_process_group(pgid, libc::SIGKILL);
            }
            sigkill_sent = true;

            let sigkill_deadline = Instant::now() + self.sigkill_timeout;
            loop {
                let mut status: libc::c_int = 0;
                let ret = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
                if ret > 0 {
                    exit_status = decode_wait_status(status);
                    break;
                }
                if ret < 0 {
                    break;
                }
                if Instant::now() >= sigkill_deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }

        // Wait for the entire process group to exit (children like zygote, crashpad, etc.)
        // This prevents orphaned processes from surviving after the main browser exits.
        let group_cleanup_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut status: libc::c_int = 0;
            // Wait for any process in the process group
            let ret = unsafe { libc::waitpid(-(pgid as i32), &mut status, libc::WNOHANG) };
            if ret <= 0 {
                // No more processes in the group (ret == 0 means none exited yet, ret < 0 with ECHILD means all gone)
                let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if ret < 0 && errno == libc::ECHILD {
                    break; // All processes in the group have exited
                }
                if ret == 0 {
                    // Some processes still exist but haven't exited yet
                    if Instant::now() >= group_cleanup_deadline {
                        break; // Timeout waiting for stragglers
                    }
                    std::thread::sleep(Duration::from_millis(25));
                    continue;
                }
                break; // Other error
            }
            // A process in the group exited, continue waiting for others
        }

        entry.child = None;
        entry.cdp = None;

        Ok(TerminateResult {
            exit_status,
            sigkill_sent,
            elapsed: start.elapsed(),
        })
    }

    pub fn cleanup(&mut self, lease_id: &BrowserLeaseId) -> Result<CleanupSafety, TransitionError> {
        let entry = self.leases.get(lease_id).ok_or(TransitionError::NotFound)?;

        let manifest = &entry.manifest;
        let profile_dir = &manifest.profile_dir;
        let runtime_dir = &manifest.runtime_dir;
        let expected_fp = &manifest.profile_fingerprint;
        let expected_pid = manifest.pid;
        let expected_identity = &manifest.process_identity;

        if let Some(mismatch) = check_identity_mismatch(expected_pid, expected_identity) {
            return quarantine_runtime_dir(runtime_dir, &mismatch);
        }

        let profile_safety = verify_path_safety(profile_dir, expected_fp);
        if !matches!(profile_safety, CleanupSafety::Clean) {
            return quarantine_runtime_dir(
                runtime_dir,
                "profile directory fingerprint mismatch or symlink detected",
            );
        }

        let runtime_meta = match fs::symlink_metadata(runtime_dir) {
            Ok(m) => m,
            Err(_) => return Ok(CleanupSafety::Clean),
        };
        if runtime_meta.file_type().is_symlink() {
            return quarantine_runtime_dir(runtime_dir, "runtime dir is a symlink");
        }

        let parent = runtime_dir.parent().unwrap_or(Path::new("/tmp"));
        let parent_fd = match open_dir_fd(parent) {
            Ok(fd) => fd,
            Err(_) => {
                return quarantine_runtime_dir(runtime_dir, "failed to open parent directory");
            }
        };

        let parent_safe = verify_dir_fd_identity(parent_fd, parent);
        if !parent_safe {
            unsafe { libc::close(parent_fd) };
            return quarantine_runtime_dir(runtime_dir, "parent directory identity mismatch");
        }

        let dir_name = runtime_dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let q_name = generate_quarantine_name(&dir_name);

        let c_old = match CString::new(dir_name.as_bytes()) {
            Ok(c) => c,
            Err(_) => {
                unsafe { libc::close(parent_fd) };
                return quarantine_runtime_dir(runtime_dir, "invalid dir name");
            }
        };
        let c_new = match CString::new(q_name.as_bytes()) {
            Ok(c) => c,
            Err(_) => {
                unsafe { libc::close(parent_fd) };
                return quarantine_runtime_dir(runtime_dir, "invalid quarantine name");
            }
        };

        let rename_ret =
            unsafe { libc::renameat(parent_fd, c_old.as_ptr(), parent_fd, c_new.as_ptr()) };
        unsafe { libc::close(parent_fd) };

        if rename_ret != 0 {
            return Ok(CleanupSafety::Failed {
                reason: format!(
                    "failed to rename runtime dir to quarantine: {}",
                    io::Error::last_os_error()
                ),
            });
        }

        let quarantine_full = parent.join(&q_name);
        match fs::remove_dir_all(&quarantine_full) {
            Ok(()) => Ok(CleanupSafety::Clean),
            Err(e) => Ok(CleanupSafety::Quarantined {
                reason: format!("quarantined but deletion failed: {}", e),
                quarantine_path: quarantine_full,
            }),
        }
    }

    pub fn remove(&mut self, lease_id: &BrowserLeaseId) -> Option<BrowserLease> {
        self.leases.remove(lease_id)
    }

    pub fn lease_cdp_endpoint(&self, lease_id: &BrowserLeaseId) -> Option<Option<String>> {
        self.leases.get(lease_id).map(|l| l.cdp_endpoint.clone())
    }

    pub fn lease_has_cdp_pipes(&self, lease_id: &BrowserLeaseId) -> Option<bool> {
        self.leases.get(lease_id).map(|l| l.cdp.is_some())
    }

    #[cfg(test)]
    pub(crate) fn set_start_url_opener(&mut self, opener: Arc<dyn StartUrlOpener>) {
        self.start_url_opener = opener;
    }

    #[cfg(test)]
    pub(crate) fn set_sign_proxy_path(&mut self, path: PathBuf) {
        self.sign_proxy_path = Some(path);
    }

    #[cfg(test)]
    pub(crate) fn set_containment(&mut self, containment: ContainmentPolicy) {
        self.containment = containment;
    }

    /// Blocks until the extension worker of `lease_id` said hello with `attached = true`, or
    /// `timeout` passed (plan D6 layer 1). A launch reports success only after this returns `Ok`;
    /// it marks the lease's interception confirmed.
    ///
    /// It holds the browser manager (the caller's guard) but takes only the readiness leaf lock,
    /// which the transport's hello path also takes alone (LOCKING.md).
    pub fn await_interception(
        &mut self,
        lease_id: &BrowserLeaseId,
        readiness: &ReadinessRegistry,
        timeout: Duration,
    ) -> Result<BearerReadiness, LaunchError> {
        let state = self
            .wait_for_attach(lease_id, readiness, timeout)
            .map_err(|failure| match failure {
                AttachFailure::IncognitoNotAllowed(why) => LaunchError::IncognitoNotAllowed(why),
                AttachFailure::Other(why) => LaunchError::InterceptionNotAttached(why),
            })?;
        if let Some(lease) = self.leases.get_mut(lease_id)
            && let Some(interception) = lease.interception.as_mut()
        {
            interception.confirmed = true;
            sync_cdp_endpoint_file(lease, true)?;
        }
        Ok(state)
    }

    /// Waits up to `timeout` for a confirmed lease whose worker is reconnecting to re-attach.
    pub fn await_reattach(
        &mut self,
        lease_id: &BrowserLeaseId,
        readiness: &ReadinessRegistry,
        timeout: Duration,
    ) -> Result<BearerReadiness, String> {
        self.wait_for_attach(lease_id, readiness, timeout)
            .map_err(|failure| match failure {
                AttachFailure::IncognitoNotAllowed(why) | AttachFailure::Other(why) => why,
            })
    }

    /// Waits in short slices so a browser that exits during the wait ends it at once. A worker
    /// that attached but stays without incognito access for `INCOGNITO_SETTLE` fails the wait
    /// early: its probe has finished, and the seed did not take effect.
    fn wait_for_attach(
        &mut self,
        lease_id: &BrowserLeaseId,
        readiness: &ReadinessRegistry,
        timeout: Duration,
    ) -> Result<BearerReadiness, AttachFailure> {
        const SLICE: Duration = Duration::from_millis(250);
        const INCOGNITO_SETTLE: Duration = Duration::from_secs(3);
        let bearer = self
            .leases
            .get(lease_id)
            .and_then(|lease| lease.interception.as_ref())
            .map(|interception| interception.bearer.clone())
            .ok_or_else(|| {
                AttachFailure::Other("the lease was launched without the extension".to_string())
            })?;
        let deadline = Instant::now() + timeout;
        let mut without_incognito_since: Option<Instant> = None;
        loop {
            let slice = deadline
                .saturating_duration_since(Instant::now())
                .min(SLICE);
            if let Some(state) = readiness.wait_attached(&bearer, slice) {
                return Ok(state);
            }
            if let Some(child) = self
                .leases
                .get_mut(lease_id)
                .and_then(|lease| lease.child.as_mut())
                && let Ok(Some(status)) = child.try_wait()
            {
                return Err(AttachFailure::Other(format!(
                    "the browser exited first ({status})"
                )));
            }
            let status = readiness.status(&bearer);
            let attached_without_incognito = status
                .as_ref()
                .is_some_and(|s| s.connected && s.attached && !s.incognito_allowed);
            if attached_without_incognito {
                let since = *without_incognito_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= INCOGNITO_SETTLE || Instant::now() >= deadline {
                    return Err(AttachFailure::IncognitoNotAllowed(
                        "the extension worker reported isAllowedIncognitoAccess() = false"
                            .to_string(),
                    ));
                }
            } else {
                without_incognito_since = None;
            }
            if Instant::now() >= deadline {
                let why = match status {
                    None => "the extension worker never connected to the daemon",
                    Some(state) if !state.connected => "the extension worker's connection closed",
                    Some(_) => "the extension worker reported attached = false",
                };
                return Err(AttachFailure::Other(format!(
                    "{why} within {:.1} s",
                    timeout.as_secs_f32()
                )));
            }
        }
    }

    /// Opens the start URL that the launch held back until interception was ready (defect B2).
    /// Refused unless `await_interception` succeeded; does nothing if there is none, or if it was
    /// already opened. Returns the URL it opened.
    pub fn open_deferred_start_url(
        &mut self,
        lease_id: &BrowserLeaseId,
    ) -> Result<Option<String>, String> {
        let lease = self.leases.get_mut(lease_id).ok_or("lease not found")?;
        if !lease.interception.as_ref().is_some_and(|i| i.confirmed) {
            return Err("interception is not confirmed for this lease".to_string());
        }
        let Some(url) = lease.deferred_start_url.take() else {
            return Ok(None);
        };
        let opener = self.start_url_opener.clone();
        opener.open(self, lease_id, &url)?;
        Ok(Some(url))
    }

    /// The interception state of `lease_id` (`None` for a lease without the extension). A lease
    /// whose launch has not seen the worker attach yet is `Pending`.
    pub fn interception_state(
        &self,
        lease_id: &BrowserLeaseId,
        readiness: &ReadinessRegistry,
        grace: Duration,
    ) -> Option<(InterceptionState, Option<BearerReadiness>)> {
        let interception = self.leases.get(lease_id)?.interception.as_ref()?;
        let status = readiness.status(&interception.bearer);
        let state = if interception.confirmed {
            InterceptionState::of_confirmed(status.as_ref(), Instant::now(), grace)
        } else {
            InterceptionState::Pending
        };
        Some((state, status))
    }

    /// Re-evaluates the interception of every confirmed, live lease and returns the leases whose
    /// degraded state changed since the last call: each episode is reported once when it starts
    /// and once when the worker re-attaches. The runtime loop calls it and logs and audits them.
    pub fn poll_interception(
        &mut self,
        readiness: &ReadinessRegistry,
        grace: Duration,
    ) -> Vec<InterceptionTransition> {
        let now = Instant::now();
        let mut transitions = Vec::new();
        for lease in self.leases.values_mut() {
            if lease.state.is_terminal() {
                continue;
            }
            let Some(interception) = lease.interception.as_mut() else {
                continue;
            };
            if !interception.confirmed {
                continue;
            }
            let status = readiness.status(&interception.bearer);
            let state = InterceptionState::of_confirmed(status.as_ref(), now, grace);
            let degraded = match state {
                InterceptionState::Degraded => true,
                InterceptionState::Attached => false,
                // Within the grace period nothing changes yet.
                InterceptionState::Pending => continue,
            };
            if degraded != interception.degraded_reported {
                interception.degraded_reported = degraded;
                if let Err(e) = sync_cdp_endpoint_file(lease, !degraded) {
                    log::warn!("browser lease {}: {}", lease.id, e);
                }
                transitions.push(InterceptionTransition {
                    lease_id: lease.id.clone(),
                    profile_id: lease.profile_id.clone(),
                    degraded,
                });
            }
        }
        transitions
    }

    pub fn snapshot(&self, lease_id: &BrowserLeaseId) -> Option<LeaseSnapshot> {
        let lease = self.leases.get(lease_id)?;
        let now = self.clock.now();
        let remaining = lease.ttl_deadline.saturating_duration_since(now).as_secs();

        Some(LeaseSnapshot {
            id: lease.id.clone(),
            profile_id: lease.profile_id.clone(),
            state: lease.state,
            pid: lease.manifest.pid,
            ttl_remaining_secs: remaining,
            start_url: lease.start_url.clone(),
        })
    }

    pub fn list_snapshots(&self) -> Vec<LeaseSnapshot> {
        let ids: Vec<BrowserLeaseId> = self.leases.keys().cloned().collect();
        ids.iter().filter_map(|id| self.snapshot(id)).collect()
    }

    pub fn find_live_lease_for_profile(&mut self, profile_id: &ProfileId) -> Option<LeaseSnapshot> {
        let lease_ids: Vec<BrowserLeaseId> = self.leases.keys().cloned().collect();
        for id in lease_ids {
            let lease = self.leases.get_mut(&id)?;
            if &lease.profile_id == profile_id
                && matches!(
                    lease.state,
                    LeaseState::Active | LeaseState::AuthenticationPending
                )
            {
                if let Some(ref mut child) = lease.child {
                    match child.try_wait() {
                        Ok(Some(_)) => {
                            lease.child_reaped = true;
                            continue;
                        }
                        Ok(None) => {}
                        Err(_) => {
                            continue;
                        }
                    }
                }
                if let Some(snapshot) = self.snapshot(&id) {
                    return Some(snapshot);
                }
            }
        }
        None
    }

    pub fn check_expired(&mut self) -> Vec<BrowserLeaseId> {
        let now = self.clock.now();
        let mut expired = Vec::new();

        for (id, entry) in &self.leases {
            if matches!(
                entry.state,
                LeaseState::Active | LeaseState::AuthenticationPending
            ) && now >= entry.ttl_deadline
            {
                expired.push(id.clone());
            }
        }

        for id in &expired {
            let _ = self.terminate(id);
            let _ = self.cleanup(id);
            if let Some(entry) = self.leases.get_mut(id)
                && matches!(
                    entry.state,
                    LeaseState::Active | LeaseState::AuthenticationPending
                )
            {
                entry.state = LeaseState::Revoked;
            }
        }

        expired
    }

    pub fn terminate_all(&mut self) {
        let lease_ids: Vec<BrowserLeaseId> = self.leases.keys().cloned().collect();
        for id in lease_ids {
            let _ = self.terminate(&id);
        }
    }

    pub fn restart_recovery_kill(
        &self,
        target_pid: u32,
        expected_identity: &ProcessIdentity,
    ) -> bool {
        if !expected_identity.is_valid() {
            return false;
        }

        let actual_identity = match read_process_identity(target_pid) {
            Some(id) => id,
            None => return false,
        };

        if !actual_identity.is_valid() {
            return false;
        }

        if actual_identity.pid != expected_identity.pid {
            return false;
        }

        if actual_identity.start_time_ticks != expected_identity.start_time_ticks {
            return false;
        }

        if !cgroup_matches(&actual_identity.cgroup, &expected_identity.cgroup) {
            return false;
        }

        signal_process_group(target_pid, libc::SIGTERM);
        true
    }

    pub fn lease_count(&self) -> usize {
        self.leases.len()
    }

    /// The ids of every lease the manager holds (live or not yet removed).
    pub fn lease_ids(&self) -> Vec<BrowserLeaseId> {
        self.leases.keys().cloned().collect()
    }

    pub fn active_count(&self) -> usize {
        self.leases
            .values()
            .filter(|e| e.state == LeaseState::Active)
            .count()
    }

    pub fn pending_count(&self) -> usize {
        self.leases
            .values()
            .filter(|e| e.state == LeaseState::AuthenticationPending)
            .count()
    }

    /// One `browser-control` round trip for the agent: the request passes the extension filter
    /// (`cdp_filter.rs`) and so does everything the agent receives.
    pub fn cdp_round_trip(
        &mut self,
        lease_id: &BrowserLeaseId,
        request_json: &str,
        timeout: Duration,
    ) -> Result<CdpRoundTripResult, CdpError> {
        self.round_trip(lease_id, request_json, timeout, true)
    }

    /// A round trip of the daemon's own (the start URL). The request is not checked; the messages
    /// read still pass the filter, so its view of the extension's sessions stays complete.
    pub fn daemon_cdp_round_trip(
        &mut self,
        lease_id: &BrowserLeaseId,
        request_json: &str,
        timeout: Duration,
    ) -> Result<CdpRoundTripResult, CdpError> {
        self.round_trip(lease_id, request_json, timeout, false)
    }

    fn round_trip(
        &mut self,
        lease_id: &BrowserLeaseId,
        request_json: &str,
        timeout: Duration,
        from_agent: bool,
    ) -> Result<CdpRoundTripResult, CdpError> {
        let mut call = self.cdp_begin(lease_id, request_json, timeout, from_agent)?;
        let result = loop {
            match self.cdp_step(lease_id, &mut call, Duration::MAX) {
                Ok(Some(result)) => break Ok(result),
                Ok(None) => {}
                Err(e) => break Err(e),
            }
        };
        self.cdp_end(lease_id);
        result
    }

    /// Check and write a CDP request and mark the lease busy; [`Self::cdp_step`] collects the
    /// answer and [`Self::cdp_end`] must follow, whatever the outcome.
    pub fn cdp_begin(
        &mut self,
        lease_id: &BrowserLeaseId,
        request_json: &str,
        timeout: Duration,
        from_agent: bool,
    ) -> Result<CdpCall, CdpError> {
        validate_cdp_request(request_json)?;

        let timeout = clamp_cdp_timeout(timeout);

        let entry = self
            .leases
            .get_mut(lease_id)
            .ok_or(CdpError::LeaseNotFound)?;

        if entry.state.is_terminal() {
            return Err(CdpError::BrowserExited);
        }
        if entry.cdp.is_none() {
            return Err(CdpError::NoCdpEndpoints);
        }
        if entry.cdp_busy {
            return Err(CdpError::Busy);
        }

        let deadline = Instant::now() + timeout;

        // What goes to the browser. For the agent it is the request the filter checked,
        // re-serialized: never the raw text, which another JSON parser could read differently
        // (duplicate keys, escapes; review M-b).
        let forwarded = if from_agent {
            let request: serde_json::Value = serde_json::from_str(request_json)
                .map_err(|e| CdpError::InvalidRequest(format!("invalid JSON: {}", e)))?;
            let verdict = entry.cdp_filter.check_request(&request);
            let lookups = match verdict {
                RequestVerdict::Forward => Vec::new(),
                RequestVerdict::Deny(reason) => return Err(CdpError::Denied(reason)),
                RequestVerdict::LookupTargets(targets) => targets,
            };
            for target in lookups {
                let hostile = lookup_hostile_target(entry, &target, deadline)?;
                // A target found to be hostile (the extension's or a browser-internal one) has
                // its sessions detached now.
                for command in entry.cdp_filter.take_commands() {
                    write_cdp_frame(entry, &command)?;
                }
                if hostile {
                    return Err(CdpError::Denied(TARGET_DENIED.to_string()));
                }
            }
            entry.cdp_filter.note_forwarded(&request);
            request.to_string()
        } else {
            request_json.to_string()
        };

        write_cdp_frame(entry, &forwarded)?;
        entry.cdp_busy = true;

        Ok(CdpCall {
            request_id: extract_cdp_id(&forwarded),
            deadline,
            messages: Vec::new(),
            total_bytes: 0,
        })
    }

    /// Read the answer of `call` for at most `slice` (and until its deadline). `Ok(None)`: not
    /// answered yet. Everything the agent receives passes the extension filter.
    pub fn cdp_step(
        &mut self,
        lease_id: &BrowserLeaseId,
        call: &mut CdpCall,
        slice: Duration,
    ) -> Result<Option<CdpRoundTripResult>, CdpError> {
        let entry = self
            .leases
            .get_mut(lease_id)
            .ok_or(CdpError::LeaseNotFound)?;
        if entry.state.is_terminal() {
            return Err(CdpError::BrowserExited);
        }
        let step_deadline = Instant::now()
            .checked_add(slice)
            .map_or(call.deadline, |end| end.min(call.deadline));

        loop {
            let raw = match entry.cdp_buffer.pop_front() {
                Some(buffered) => buffered,
                None => match read_cdp_message(entry, step_deadline)? {
                    Some(message) => message,
                    None if Instant::now() >= call.deadline => return Err(CdpError::Timeout),
                    None => return Ok(None),
                },
            };
            let inbound = entry.cdp_filter.inbound(&raw);
            for command in entry.cdp_filter.take_commands() {
                write_cdp_frame(entry, &command)?;
            }
            let message = match inbound {
                Inbound::Deliver(message) => message,
                Inbound::Drop => continue,
            };
            if call.messages.len() >= CDP_MAX_RESPONSE_MESSAGES {
                return Err(CdpError::TooManyMessages);
            }
            if call.total_bytes + message.len() > CDP_MAX_RESPONSE_TOTAL_BYTES {
                return Err(CdpError::ResponseTooLarge);
            }
            let found_response = call
                .request_id
                .as_ref()
                .is_some_and(|rid| cdp_message_has_id(&message, rid));
            call.total_bytes += message.len();
            call.messages.push(message);
            if found_response {
                return Ok(Some(CdpRoundTripResult {
                    messages: std::mem::take(&mut call.messages),
                }));
            }
        }
    }

    /// Release the lease for the next call (also after a failed one).
    pub fn cdp_end(&mut self, lease_id: &BrowserLeaseId) {
        if let Some(entry) = self.leases.get_mut(lease_id) {
            entry.cdp_busy = false;
        }
    }

    pub fn check_exits(&mut self) -> Vec<BrowserExitInfo> {
        let mut exited = Vec::new();
        let lease_ids: Vec<BrowserLeaseId> = self.leases.keys().cloned().collect();

        for lease_id in lease_ids {
            let entry = match self.leases.get_mut(&lease_id) {
                Some(e) => e,
                None => continue,
            };

            if entry.child_reaped || entry.state.is_terminal() {
                continue;
            }

            let child = match entry.child.as_mut() {
                Some(c) => c,
                None => continue,
            };

            match child.try_wait() {
                Ok(Some(status)) => {
                    let pid = entry.manifest.pid;
                    let exit_code = status.code();
                    entry.child_reaped = true;
                    entry.child = None;
                    entry.cdp = None;
                    exited.push(BrowserExitInfo {
                        lease_id: lease_id.clone(),
                        pid,
                        exit_code,
                    });
                }
                Ok(None) => {}
                Err(_) => {
                    let pid = entry.manifest.pid;
                    entry.child_reaped = true;
                    entry.child = None;
                    entry.cdp = None;
                    exited.push(BrowserExitInfo {
                        lease_id: lease_id.clone(),
                        pid,
                        exit_code: None,
                    });
                }
            }
        }

        for info in &exited {
            let _ = self.mark_browser_exit(&info.lease_id);
        }

        exited
    }
}

fn is_valid_lease_transition(from: LeaseState, to: LeaseState) -> bool {
    matches!(
        (from, to),
        (LeaseState::AuthenticationPending, LeaseState::Revoked)
            | (LeaseState::AuthenticationPending, LeaseState::BrowserExit)
            | (LeaseState::AuthenticationPending, LeaseState::PrincipalExit)
            | (
                LeaseState::AuthenticationPending,
                LeaseState::DaemonShutdown
            )
            | (LeaseState::Active, LeaseState::Revoked)
            | (LeaseState::Active, LeaseState::BrowserExit)
            | (LeaseState::Active, LeaseState::PrincipalExit)
            | (LeaseState::Active, LeaseState::DaemonShutdown)
            | (LeaseState::Revoked, LeaseState::BrowserExit)
            | (LeaseState::Revoked, LeaseState::PrincipalExit)
            | (LeaseState::Revoked, LeaseState::DaemonShutdown)
            | (LeaseState::PrincipalExit, LeaseState::DaemonShutdown)
            | (LeaseState::BrowserExit, LeaseState::DaemonShutdown)
    )
}

fn clamp_ttl(ttl: Duration) -> Duration {
    let secs = ttl.as_secs();
    if secs < MIN_TTL_SECS {
        Duration::from_secs(MIN_TTL_SECS)
    } else if secs > MAX_TTL_CLAMP_SECS {
        Duration::from_secs(MAX_TTL_CLAMP_SECS)
    } else {
        ttl
    }
}

fn clamp_login_timeout(timeout: Duration) -> Duration {
    let secs = timeout.as_secs();
    if secs < MIN_LOGIN_TIMEOUT_SECS {
        Duration::from_secs(MIN_LOGIN_TIMEOUT_SECS)
    } else if secs > MAX_LOGIN_TIMEOUT_SECS {
        Duration::from_secs(MAX_LOGIN_TIMEOUT_SECS)
    } else {
        timeout
    }
}

/// The runtime root a profile without `browser_runtime_root` uses, and the system directory it
/// lives below (`$XDG_RUNTIME_DIR`, else `/tmp`).
pub fn default_runtime_root() -> (PathBuf, PathBuf) {
    let base = dirs::runtime_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    let root = base.join("passless").join("browser");
    (base, root)
}

/// Creates the browser runtime root when it is missing, so that a fresh machine can launch a
/// browser without a manual `mkdir`. A root that exists is left alone (its owner, mode and type
/// are judged by [`open_runtime_root`], which refuses a wrong one or a symlink); this never
/// chmods or chowns an existing entry.
///
/// - The default root (`$XDG_RUNTIME_DIR/passless/browser`) is created, with its missing parents,
///   through [`Dir::open_or_create_path`]: mode 0700, owned by the daemon, no symlink followed.
///   That is only done when the browser runs as the daemon's own user, the one case in which the
///   daemon's directory is the browser user's: for another browser user the root has to be
///   owned by that user and its parents traversable by it, which the daemon cannot assume under
///   its own runtime directory, so the error says to create it or to set `browser_runtime_root`.
/// - A configured `browser_runtime_root` is created only as its final component: its parent must
///   exist, be reached without a symlink, belong to the daemon, root or the browser user, and not
///   be writable by anyone else (or be sticky). The new directory is 0700 and, for another
///   browser user, handed to that user (which needs root); a failed hand-over removes it again.
///   Parents are never created for a configured root, so a typo does not litter the disk.
pub fn ensure_runtime_root(path: &Path, target_uid: u32, target_gid: u32) -> io::Result<()> {
    let (default_base, default_root) = default_runtime_root();
    ensure_runtime_root_with(path, target_uid, target_gid, &default_base, &default_root)
}

/// [`ensure_runtime_root`] with the default root given (tests do not touch the environment).
fn ensure_runtime_root_with(
    path: &Path,
    target_uid: u32,
    target_gid: u32,
    default_base: &Path,
    default_root: &Path,
) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => return Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    // SAFETY: no preconditions.
    let euid = unsafe { libc::geteuid() };
    if path == default_root {
        if target_uid != euid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "the default runtime root does not exist, and the browser runs as uid \
                     {target_uid}, not as the daemon (uid {euid}): create it owned by that user \
                     with mode 0700, or set browser_runtime_root"
                ),
            ));
        }
        let base = fs::canonicalize(default_base)?;
        let relative = path.strip_prefix(default_base).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime root is not below its base",
            )
        })?;
        return Dir::open_or_create_path(&base.join(relative), RUNTIME_DIR_MODE, &base).map(|_| ());
    }
    create_final_component(path, euid, target_uid, target_gid)
}

/// The configured-root half of [`ensure_runtime_root`]: create only the last component of `path`.
fn create_final_component(
    path: &Path,
    euid: u32,
    target_uid: u32,
    target_gid: u32,
) -> io::Result<()> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str()))
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime root has no parent directory or name",
        ));
    };
    let resolved_parent = fs::canonicalize(parent).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "its parent directory {} is not usable ({e}); create the parent, the daemon only \
                 creates the last component of browser_runtime_root",
                parent.display()
            ),
        )
    })?;
    let parent_dir = Dir::open_path(&resolved_parent)?;
    let st = parent_dir.stat()?;
    let mode = st.st_mode & 0o7777;
    let trusted_owner = [euid, 0, target_uid].contains(&st.st_uid);
    let others_can_write = mode & 0o022 != 0 && mode & libc::S_ISVTX == 0;
    if !trusted_owner || others_can_write {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "its parent directory {} (uid {}, mode {:o}) is not safe to create it in: it must \
                 belong to the daemon, root or the browser user and not be writable by others",
                resolved_parent.display(),
                st.st_uid,
                mode & 0o777
            ),
        ));
    }
    let dir = match parent_dir.create_dir(name, RUNTIME_DIR_MODE) {
        Ok(dir) => dir,
        // Created by someone else in the meantime: judged by `open_runtime_root`.
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
        Err(e) => return Err(e),
    };
    if target_uid != euid
        && let Err(e) = dir.chown(target_uid, target_gid)
    {
        let _ = parent_dir.remove_tree(name);
        return Err(io::Error::new(
            e.kind(),
            format!("cannot hand the new runtime root to uid {target_uid}: {e}"),
        ));
    }
    Ok(())
}

/// Opens the browser runtime root as a pinned directory (review H1). Its last component must not
/// be a symlink; symlinks among its system ancestors (for example `/var/run`) are resolved first,
/// and the resolved path is then opened component by component without following any symlink, so
/// a component swapped afterwards is refused. The opened directory must be owned by the browser
/// user with mode 0700: lease directories are created inside it through this handle.
fn open_runtime_root(path: &Path, expected_uid: u32) -> io::Result<Dir> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "runtime root is a symlink",
        ));
    }
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "runtime root has no file name")
    })?;
    let parent = path.parent().unwrap_or(Path::new("/"));
    let resolved = fs::canonicalize(parent)?.join(name);
    let dir = Dir::open_path(&resolved)?;
    let st = dir.stat()?;
    if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "runtime root is not a directory",
        ));
    }
    let mode = st.st_mode & 0o777;
    if mode != RUNTIME_DIR_MODE {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "runtime root mode is {:o}, expected {:o}",
                mode, RUNTIME_DIR_MODE
            ),
        ));
    }
    if st.st_uid != expected_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "runtime root not owned by target uid {} (owned by {})",
                expected_uid, st.st_uid
            ),
        ));
    }
    Ok(dir)
}

#[cfg(test)]
fn validate_runtime_root(path: &Path, expected_uid: u32) -> io::Result<()> {
    open_runtime_root(path, expected_uid).map(|_| ())
}

/// Test helper: creates the directory `path` (its parent opened without following symlinks) and
/// chowns it, as the launcher does through its pinned handles.
#[cfg(test)]
fn create_lease_dir(path: &Path, mode: u32, target_uid: u32, target_gid: u32) -> io::Result<()> {
    let parent = Dir::open_path(path.parent().unwrap_or(Path::new("/")))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    parent.create_dir(name, mode)?.chown(target_uid, target_gid)
}

#[cfg(test)]
fn fingerprint_path(path: &Path) -> io::Result<ProfileFingerprint> {
    let meta = fs::metadata(path)?;
    Ok(ProfileFingerprint {
        inode: meta.ino(),
        dev: meta.dev(),
    })
}

/// Validate a launch URL against the profile's rules (ADR 0014 sections 6.1 and 6.3, plan R15).
///
/// The URL is parsed with `url::Url`; credentials in the URL (`http://localhost:1@evil.com/`) are
/// rejected and the host is compared exactly. `https` is required, except `http://localhost`.
/// The most specific rule for the host decides (`rule_for_host`), and the navigation is allowed
/// only if that rule is not `deny` for both actions: a denied RP is never a launch target, while a
/// subdomain deny does not break an allowed parent domain.
fn validate_start_url(url: &str, rules: &[AgentRpRule]) -> Result<(), ()> {
    let parsed = url::Url::parse(url).map_err(|_| ())?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(());
    }
    let plain_http = match parsed.scheme() {
        "https" => false,
        "http" => true,
        _ => return Err(()),
    };
    let host = match parsed.host() {
        Some(url::Host::Domain(domain)) => domain.to_ascii_lowercase(),
        _ => return Err(()),
    };
    if plain_http && host != LOCALHOST_RP_ID {
        return Err(());
    }
    match rule_for_host(rules, &host) {
        Some(rule)
            if rule.authenticate != RuleAction::Deny || rule.register != RuleAction::Deny =>
        {
            Ok(())
        }
        _ => Err(()),
    }
}

fn create_cdp_pipes() -> io::Result<CdpPipes> {
    let mut daemon_write: [RawFd; 2] = [-1, -1];
    let mut daemon_read: [RawFd; 2] = [-1, -1];

    let ret = unsafe { libc::pipe2(daemon_write.as_mut_ptr(), libc::O_CLOEXEC) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    let ret = unsafe { libc::pipe2(daemon_read.as_mut_ptr(), libc::O_CLOEXEC) };
    if ret != 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(daemon_write[0]);
            libc::close(daemon_write[1]);
        }
        return Err(err);
    }

    Ok(CdpPipes {
        daemon_to_browser_write: daemon_write[1],
        browser_from_daemon_read: daemon_write[0],
        daemon_from_browser_read: daemon_read[0],
        browser_to_daemon_write: daemon_read[1],
    })
}

/// Renders `worker.js` for one lease: each placeholder becomes a JSON string literal. The worker
/// throws before it registers any listener if a placeholder survives, so `verify_extension_dir`
/// rejects such a file before launch.
fn render_worker_script(template: &str, metadata: &AgentEndpointMetadata) -> String {
    let literal = |value: &str| serde_json::to_string(value).expect("a string serializes");
    template
        .replace("__PASSLESS_BEARER__", &literal(&metadata.bearer_token))
        .replace("__PASSLESS_SOCKET_PATH__", &literal(&metadata.socket_path))
        .replace(
            "__PASSLESS_BUILD_VERSION__",
            &literal(&super::transport::build_version()),
        )
}

/// Writes the lease's interception extension through the pinned lease directory: a daemon-owned
/// `agent-extension` directory (0755) with `manifest.json` (0644, the daemon's, verbatim from the
/// assets: its committed `key` fixes the extension ID) and `worker.js` with the lease's bearer, sign
/// socket and build version. The worker file holds the bearer, so it is created exclusively and
/// then handed to the browser user with mode 0600. Returns the directory's path.
fn generate_agent_extension_in(
    lease_dir: &Dir,
    runtime_dir: &Path,
    metadata: &AgentEndpointMetadata,
    target_uid: u32,
    target_gid: u32,
) -> Result<PathBuf, LaunchError> {
    let fail = |what: &str, e: io::Error| LaunchError::ExtensionSetupFailed(format!("{what}: {e}"));
    let ext = lease_dir
        .create_dir(AGENT_EXTENSION_DIR, EXTENSION_DIR_MODE)
        .map_err(|e| fail("extension dir", e))?;
    ext.create_file("manifest.json", 0o644, extension_manifest().as_bytes())
        .map_err(|e| fail("create manifest.json", e))?;
    let worker = ext
        .create_file(
            "worker.js",
            0o600,
            extension_worker_source(metadata).as_bytes(),
        )
        .map_err(|e| fail("create worker.js", e))?;
    chown_file(&worker, target_uid, target_gid).map_err(|e| fail("chown worker.js", e))?;

    let ext_dir = runtime_dir.join(AGENT_EXTENSION_DIR);
    if simulate_missing_extension() {
        let _ = fs::remove_dir_all(&ext_dir);
    }
    Ok(ext_dir)
}

/// Test helper: [`generate_agent_extension_in`] for the lease directory at `runtime_dir`.
#[cfg(test)]
fn generate_agent_extension(
    runtime_dir: &Path,
    metadata: &AgentEndpointMetadata,
    target_uid: u32,
    target_gid: u32,
) -> Result<PathBuf, LaunchError> {
    let lease_dir = Dir::open_path(runtime_dir)
        .map_err(|e| LaunchError::ExtensionSetupFailed(format!("open lease dir: {e}")))?;
    generate_agent_extension_in(&lease_dir, runtime_dir, metadata, target_uid, target_gid)
}

/// The manifest to write: the committed one, verbatim.
fn extension_manifest() -> String {
    EXTENSION_MANIFEST_TEMPLATE.to_string()
}

/// The service worker source to write for one lease. Debug builds only: with
/// `PASSLESS_E2E_UNLOADABLE_AGENT_EXTENSION` set the extension still loads, but its worker does
/// nothing, so it never connects or attaches the proxy (E2E-47/unloadable): the launcher's checks
/// pass, the browser starts in headed and headless mode alike, and the launch must fail closed with
/// the attach error. (A manifest the browser refuses to load would not do: headed Chromium answers
/// it with a blocking "Error Loading Extension" dialog before it opens its debugging port.)
/// Release builds have no such hook.
fn extension_worker_source(metadata: &AgentEndpointMetadata) -> String {
    #[cfg(debug_assertions)]
    if std::env::var_os("PASSLESS_E2E_UNLOADABLE_AGENT_EXTENSION").is_some() {
        return "// passless E2E-47/unloadable: this worker never connects and attaches nothing.\n"
            .to_string();
    }
    render_worker_script(EXTENSION_WORKER_TEMPLATE, metadata)
}

/// Debug and test builds only: lets E2E-47 and the unit tests simulate an extension directory that is
/// missing after generation. Release builds have no such hook.
fn simulate_missing_extension() -> bool {
    #[cfg(test)]
    if tests::OMIT_EXTENSION.with(|c| c.get()) {
        return true;
    }
    cfg!(debug_assertions) && std::env::var_os("PASSLESS_E2E_OMIT_AGENT_EXTENSION").is_some()
}

pub const NATIVE_MESSAGING_HOST_NAME: &str = "rs.passless.sign_proxy";

/// The Chromium extension ID of an unpacked extension whose manifest carries `key`: the SHA-256 of
/// the key's SubjectPublicKeyInfo DER, first 16 bytes, each nibble mapped to `a`..`p`.
pub fn compute_extension_id(manifest_json: &str) -> Result<String, LaunchError> {
    use base64::Engine;
    use sha2::Digest;

    let manifest: serde_json::Value = serde_json::from_str(manifest_json)
        .map_err(|e| LaunchError::ExtensionSetupFailed(format!("parse manifest: {}", e)))?;
    let key = manifest
        .get("key")
        .and_then(|v| v.as_str())
        .filter(|k| !k.is_empty())
        .ok_or_else(|| LaunchError::ExtensionSetupFailed("manifest has no key".into()))?;
    let der = base64::engine::general_purpose::STANDARD
        .decode(key)
        .map_err(|e| LaunchError::ExtensionSetupFailed(format!("decode manifest key: {}", e)))?;
    let hash = sha2::Sha256::digest(&der);
    Ok(hash
        .iter()
        .take(16)
        .flat_map(|b| [(b'a' + (b >> 4)) as char, (b'a' + (b & 0x0F)) as char])
        .collect())
}

/// The most `manifest.json` the daemon reads from an extension directory.
const EXTENSION_MANIFEST_LIMIT: u64 = 64 * 1024;
/// The most `worker.js` the daemon reads from an extension directory.
const EXTENSION_WORKER_LIMIT: u64 = 1024 * 1024;

/// The ID of the extension in `ext_dir`, from its `manifest.json`, read through the pinned
/// directory (never by path, never through a symlink; a regular file the daemon owns).
pub fn extension_id_of_dir(ext_dir: &Path) -> Result<String, LaunchError> {
    let fail = |e: io::Error| {
        LaunchError::ExtensionSetupFailed(format!(
            "read {}: {}",
            ext_dir.join("manifest.json").display(),
            e
        ))
    };
    let dir = Dir::open_path(ext_dir).map_err(fail)?;
    // SAFETY: no preconditions.
    let daemon = unsafe { libc::geteuid() };
    let manifest = dir
        .read_whole_file("manifest.json", &[daemon], EXTENSION_MANIFEST_LIMIT)
        .map_err(fail)?;
    compute_extension_id(&String::from_utf8_lossy(&manifest))
}

/// What [`extension_self_check`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExtensionSelfCheck {
    /// The extension ID the committed manifest key gives (the one the native host admits).
    pub id: String,
    /// The `minimum_chrome_version` of the manifest, as a major version.
    pub minimum_chrome_major: Option<u64>,
}

/// `passless doctor --agents`: render the interception extension and the native messaging host
/// manifest the way a launch does, into the fresh directory `scratch`, and verify them
/// (`verify_extension_dir`, the manifest's key and ID, the host manifest for `sign_proxy`). It
/// starts no browser. Nothing is written outside `scratch`.
pub(crate) fn extension_self_check(
    scratch: &Path,
    sign_proxy: &Path,
) -> Result<ExtensionSelfCheck, String> {
    let fail = |what: &str, e: &dyn fmt::Display| format!("{what}: {e}");
    let lease = Dir::open_path(scratch).map_err(|e| fail("open the scratch directory", &e))?;
    // SAFETY: no preconditions.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    let metadata = AgentEndpointMetadata {
        socket_path: "/nonexistent/passless-doctor/sock".into(),
        bearer_token: "doctor".into(),
    };
    let ext_dir = generate_agent_extension_in(&lease, scratch, &metadata, uid, gid)
        .map_err(|e| fail("render the extension", &e))?;
    let ext = lease
        .open_dir(AGENT_EXTENSION_DIR)
        .map_err(|e| fail("open the rendered extension", &e))?;
    verify_extension_dir_in(&ext, &ext_dir, uid)
        .map_err(|e| fail("verify the rendered extension", &e))?;
    let id = extension_id_of_dir(&ext_dir).map_err(|e| fail("compute the extension ID", &e))?;
    if id != AGENT_EXTENSION_ID {
        return Err(format!(
            "the extension ID is {id}, not the {AGENT_EXTENSION_ID} the native host and the \
             incognito seed expect; reinstall passless"
        ));
    }
    let profile = lease
        .create_dir("profile", RUNTIME_DIR_MODE)
        .map_err(|e| fail("create the scratch profile", &e))?;
    install_native_messaging_manifest_in(&profile, sign_proxy)
        .map_err(|e| fail("render the native messaging host manifest", &e))?;
    let minimum_chrome_major =
        serde_json::from_str::<serde_json::Value>(EXTENSION_MANIFEST_TEMPLATE)
            .ok()
            .and_then(|manifest| {
                manifest
                    .get("minimum_chrome_version")?
                    .as_str()?
                    .split('.')
                    .next()?
                    .parse()
                    .ok()
            });
    Ok(ExtensionSelfCheck {
        id,
        minimum_chrome_major,
    })
}

/// Where the launcher expects the `sign-proxy` relay: next to the running executable. `None` if
/// the executable's path is unknown.
pub(crate) fn installed_sign_proxy_path() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("sign-proxy")))
}

/// Writes the native messaging host manifest into the lease's profile (`--user-data-dir`), never
/// into the user's own browser configuration: it admits only the committed extension ID and runs
/// `sign_proxy_path`. Written through the pinned profile directory before the profile is handed to
/// the browser user: `NativeMessagingHosts` (0755) and the manifest (0644) stay the daemon's.
fn install_native_messaging_manifest_in(
    profile: &Dir,
    sign_proxy_path: &Path,
) -> Result<(), LaunchError> {
    let ext_id = compute_extension_id(&extension_manifest())?;
    let manifest = serde_json::json!({
        "name": NATIVE_MESSAGING_HOST_NAME,
        "description": "Passless agent sign proxy",
        "path": sign_proxy_path,
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{}/", ext_id)]
    });
    let contents = serde_json::to_vec_pretty(&manifest).map_err(|e| {
        LaunchError::ExtensionSetupFailed(format!("write native messaging manifest: {}", e))
    })?;
    let hosts = profile
        .create_dir("NativeMessagingHosts", 0o755)
        .map_err(|e| {
            LaunchError::ExtensionSetupFailed(format!("create native messaging dir: {}", e))
        })?;
    hosts
        .create_file(
            &format!("{}.json", NATIVE_MESSAGING_HOST_NAME),
            0o644,
            &contents,
        )
        .map_err(|e| {
            LaunchError::ExtensionSetupFailed(format!("create native messaging manifest: {}", e))
        })?;
    Ok(())
}

/// Test helper: [`install_native_messaging_manifest_in`] for `profile_dir` (created if missing,
/// its parent opened without following symlinks). Returns the manifest's path.
#[cfg(test)]
fn install_native_messaging_manifest(
    _ext_dir: &Path,
    sign_proxy_path: &Path,
    profile_dir: &Path,
) -> Result<PathBuf, LaunchError> {
    let fail = |e: io::Error| LaunchError::ExtensionSetupFailed(e.to_string());
    let parent = Dir::open_path(profile_dir.parent().unwrap()).map_err(fail)?;
    let name = profile_dir.file_name().unwrap().to_str().unwrap();
    let profile = parent
        .open_dir(name)
        .or_else(|_| parent.create_dir(name, RUNTIME_DIR_MODE))
        .map_err(fail)?;
    install_native_messaging_manifest_in(&profile, sign_proxy_path)?;
    Ok(profile_dir
        .join("NativeMessagingHosts")
        .join(format!("{}.json", NATIVE_MESSAGING_HOST_NAME)))
}

/// The service worker file the extension consists of, besides `manifest.json`.
const EXTENSION_WORKER: &str = "worker.js";

/// Checks that the agent extension can be loaded and still intercepts WebAuthn (plan D6 layer 2):
///
/// - the directory exists;
/// - `manifest.json` is a JSON object with the `webAuthenticationProxy` and `nativeMessaging`
///   permissions, `worker.js` as its service worker, a non-empty `key` (it fixes the extension ID
///   the native messaging host admits) and no content scripts;
/// - `worker.js` is non-empty and has no unreplaced `__PASSLESS_` placeholder (the worker throws
///   before registering its listeners if one is left, and requests would go native).
///
/// A failure is a launch error with an actionable message; the caller must not start any browser.
pub(crate) fn verify_extension_dir(ext_dir: &Path, worker_owner: u32) -> Result<(), LaunchError> {
    let dir = Dir::open_path(ext_dir).map_err(|e| {
        extension_check_failure(format!(
            "extension directory {} is unavailable: {e}",
            ext_dir.display()
        ))
    })?;
    verify_extension_dir_in(&dir, ext_dir, worker_owner)
}

fn extension_check_failure(why: String) -> LaunchError {
    LaunchError::ExtensionSetupFailed(format!(
        "{why}; refusing to launch the managed browser without the passless agent extension \
         (it is required so that WebAuthn requests never reach the human authenticator). \
         Check that the browser runtime root is writable and has free space, then retry; \
         if it persists, reinstall passless"
    ))
}

/// [`verify_extension_dir`] on an already pinned directory (`label` is only for messages). The
/// files are read through the descriptor: `O_NOFOLLOW`, regular files only (a planted symlink to
/// `/dev/zero` or a FIFO is refused, never read), owned by the daemon (`manifest.json`) or by the
/// daemon or the browser user (`worker.js`, handed to the browser user), and bounded.
pub(crate) fn verify_extension_dir_in(
    ext: &Dir,
    label: &Path,
    worker_owner: u32,
) -> Result<(), LaunchError> {
    let fail = extension_check_failure;
    // SAFETY: no preconditions.
    let daemon = unsafe { libc::geteuid() };
    let manifest_path = label.join("manifest.json");
    let manifest = ext
        .read_whole_file("manifest.json", &[daemon], EXTENSION_MANIFEST_LIMIT)
        .map_err(|e| {
            fail(format!(
                "extension manifest {} is not readable: {e}",
                manifest_path.display()
            ))
        })?;
    let manifest: serde_json::Value = match serde_json::from_slice(&manifest) {
        Ok(v @ serde_json::Value::Object(_)) => v,
        _ => {
            return Err(fail(format!(
                "extension manifest {} is not a valid JSON object",
                manifest_path.display()
            )));
        }
    };

    let has_permission = |name: &str| {
        manifest
            .get("permissions")
            .and_then(|v| v.as_array())
            .is_some_and(|p| p.iter().any(|v| v.as_str() == Some(name)))
    };
    for permission in ["webAuthenticationProxy", "nativeMessaging"] {
        if !has_permission(permission) {
            return Err(fail(format!(
                "extension manifest lacks the {permission} permission"
            )));
        }
    }
    if manifest
        .pointer("/background/service_worker")
        .and_then(|v| v.as_str())
        != Some(EXTENSION_WORKER)
    {
        return Err(fail(format!(
            "extension manifest does not declare {EXTENSION_WORKER} as its service worker"
        )));
    }
    if !manifest
        .get("key")
        .and_then(|v| v.as_str())
        .is_some_and(|k| !k.is_empty())
    {
        return Err(fail(
            "extension manifest has no key, so its extension ID is not the one the native \
             messaging host admits"
                .to_string(),
        ));
    }
    if manifest.get("content_scripts").is_some() {
        return Err(fail(
            "extension manifest declares content scripts; the interception extension is \
             worker-only"
                .to_string(),
        ));
    }

    let worker_path = label.join(EXTENSION_WORKER);
    let worker = ext
        .read_whole_file(
            EXTENSION_WORKER,
            &[daemon, worker_owner],
            EXTENSION_WORKER_LIMIT,
        )
        .map_err(|e| {
            fail(format!(
                "extension script {} is missing, unreadable or not a regular file: {e}",
                worker_path.display()
            ))
        })?;
    if worker.is_empty() {
        return Err(fail(format!(
            "extension script {} is empty",
            worker_path.display()
        )));
    }
    let worker = String::from_utf8_lossy(&worker);
    if worker.contains(EXTENSION_PLACEHOLDER_PREFIX) {
        return Err(fail(format!(
            "extension script {} has an unreplaced {EXTENSION_PLACEHOLDER_PREFIX} placeholder",
            worker_path.display()
        )));
    }
    Ok(())
}

pub(crate) fn build_browser_command(
    config: &BrowserConfig,
    profile_dir: &Path,
) -> Result<Command, LaunchError> {
    build_browser_command_inner(config, profile_dir, true)
}

/// Test-only: builds the command without requiring the extension, for fake spawners and flag tests.
#[cfg(test)]
fn build_browser_command_unverified(
    config: &BrowserConfig,
    profile_dir: &Path,
) -> Result<Command, LaunchError> {
    build_browser_command_inner(config, profile_dir, false)
}

fn build_browser_command_inner(
    config: &BrowserConfig,
    profile_dir: &Path,
    require_extension: bool,
) -> Result<Command, LaunchError> {
    for arg in &config.extra_args {
        if arg.starts_with("--remote-debugging-pipe")
            || arg.starts_with("--remote-debugging-port")
            || arg.starts_with("--remote-debugging-address")
            || arg.starts_with("--remote-allow-origins")
        {
            return Err(LaunchError::InvalidArg(
                "remote debugging flags are managed by passless; remove from browser_command"
                    .into(),
            ));
        }
        if is_managed_extension_or_profile_flag(arg) {
            return Err(LaunchError::InvalidArg(
                "extension and profile flags are managed by passless; remove from browser_command"
                    .into(),
            ));
        }
    }

    let mut cmd = Command::new(&config.executable);

    cmd.arg(format!("--user-data-dir={}", profile_dir.display()));
    cmd.arg("--no-first-run");
    cmd.arg("--no-default-browser-check");
    cmd.arg("--disable-sync");
    // The managed browser is never launched without the interception extension, and never with
    // `--disable-extensions`: without it WebAuthn requests would reach the human authenticator
    // (ADR 0014 §7, invariant 25).
    let ext_dir = profile_dir
        .parent()
        .unwrap_or(profile_dir)
        .join(AGENT_EXTENSION_DIR);
    if require_extension {
        verify_extension_dir(&ext_dir, config.target_uid)?;
    }
    cmd.arg(format!("--load-extension={}", ext_dir.display()));
    cmd.arg("--disable-save-password-bubble");
    cmd.arg("--disable-client-side-phishing-detection");
    cmd.arg("--password-store=basic");
    cmd.arg("--disable-background-networking");
    cmd.arg("--disable-breakpad");
    cmd.arg("--disable-component-update");
    cmd.arg("--no-pings");
    cmd.arg("--safebrowsing-disable-auto-update");
    cmd.arg("--metrics-recording-only");
    cmd.arg("--disable-features=TranslateUI");

    match config.cdp_expose {
        CdpExposeMode::Pipe => {
            cmd.arg("--remote-debugging-pipe");
        }
        CdpExposeMode::Port => {
            cmd.arg(format!("--remote-debugging-port={}", config.cdp_port));
            cmd.arg("--remote-debugging-address=127.0.0.1");
            cmd.arg("--remote-allow-origins=*");
        }
    }

    for arg in &config.extra_args {
        cmd.arg(arg);
    }

    if let Some(ref url) = config.start_url {
        cmd.arg(url);
    }

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());

    Ok(cmd)
}

fn is_managed_extension_or_profile_flag(arg: &str) -> bool {
    let flag = arg.split('=').next().unwrap_or(arg);
    matches!(
        flag,
        "--load-extension"
            | "--disable-extensions"
            | "--disable-extensions-except"
            | "--user-data-dir"
            | "--allowlisted-extension-id"
            | "--disable-extensions-file-access-check"
    )
}

fn spawn_browser_hardened(
    config: &BrowserConfig,
    profile_dir: &Path,
    cdp: &CdpPipes,
    containment: &ContainmentPlan,
) -> Result<Child, LaunchError> {
    let setup = config.hardening();
    setup
        .validate()
        .map_err(|e| LaunchError::HardeningFailed(e.to_string()))?;

    let mut cmd = containment.wrap(build_browser_command(config, profile_dir)?);

    let fd_read = cdp.browser_from_daemon_read;
    let fd_write = cdp.browser_to_daemon_write;
    let hidraw_dir = containment.hidraw_dir_to_check();
    let parent = std::process::id() as libc::pid_t;

    unsafe {
        cmd.pre_exec(move || {
            if fd_read != CDP_FD_READ {
                if libc::dup2(fd_read, CDP_FD_READ) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if fd_read != CDP_FD_READ {
                    libc::close(fd_read);
                }
            }
            if fd_write != CDP_FD_WRITE {
                if libc::dup2(fd_write, CDP_FD_WRITE) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if fd_write != CDP_FD_WRITE {
                    libc::close(fd_write);
                }
            }

            if libc::fcntl(CDP_FD_READ, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(CDP_FD_WRITE, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }

            setup.apply(&[0, 1, 2, CDP_FD_READ, CDP_FD_WRITE], parent)?;
            // Evaluated as the browser's UID, after the drop (not needed under bwrap).
            match &hidraw_dir {
                Some(dir) => refuse_if_hidraw_accessible(dir),
                None => Ok(()),
            }
        });
    }

    spawn_contained(cmd, containment)
}

/// Spawn a browser command from the long-lived launcher thread (defect B1: its parent-death
/// signal must mean "the daemon died", not "the request thread returned"), and turn the child's
/// containment refusal into its actionable launch error.
fn spawn_contained(cmd: Command, containment: &ContainmentPlan) -> Result<Child, LaunchError> {
    spawn_on_launcher_thread(cmd).map_err(|e| match containment.refusal(&e) {
        Some(message) => LaunchError::ContainmentRefused(message),
        None => LaunchError::SpawnFailed(e.to_string()),
    })
}

#[cfg(test)]
const CLOSE_RANGE_FALLBACK_MAX: RawFd = 256;

#[cfg(test)]
fn spawn_browser_unhardened(
    config: &BrowserConfig,
    profile_dir: &Path,
    cdp: &CdpPipes,
) -> Result<Child, LaunchError> {
    let mut cmd = build_browser_command_unverified(config, profile_dir)?;

    let fd_read = cdp.browser_from_daemon_read;
    let fd_write = cdp.browser_to_daemon_write;

    unsafe {
        cmd.pre_exec(move || {
            if fd_read != CDP_FD_READ {
                if libc::dup2(fd_read, CDP_FD_READ) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if fd_read != CDP_FD_READ {
                    libc::close(fd_read);
                }
            }
            if fd_write != CDP_FD_WRITE {
                if libc::dup2(fd_write, CDP_FD_WRITE) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if fd_write != CDP_FD_WRITE {
                    libc::close(fd_write);
                }
            }

            if libc::fcntl(CDP_FD_READ, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(CDP_FD_WRITE, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }

            let cr_ret =
                libc::close_range((CDP_FD_WRITE + 1) as libc::c_uint, libc::c_uint::MAX, 0);
            if cr_ret < 0 {
                for fd in (CDP_FD_WRITE + 1)..CLOSE_RANGE_FALLBACK_MAX {
                    libc::close(fd);
                }
            }

            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }

            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
                return Err(io::Error::last_os_error());
            }

            let core_rlim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &core_rlim) < 0 {
                return Err(io::Error::last_os_error());
            }

            let nofile_rlim = libc::rlimit {
                rlim_cur: RLIMIT_NOFILE_CUR,
                rlim_max: RLIMIT_NOFILE_CUR,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &nofile_rlim) < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        });
    }

    cmd.spawn()
        .map_err(|e| LaunchError::SpawnFailed(e.to_string()))
}

fn is_trusted_same_user_port_launch(config: &BrowserConfig) -> bool {
    config.daemon_uid != 0
        && config.target_uid == config.daemon_uid
        && config.target_gid == config.daemon_gid
}

fn spawn_browser_port_mode(
    config: &BrowserConfig,
    profile_dir: &Path,
    containment: &ContainmentPlan,
) -> Result<Child, LaunchError> {
    let setup = config.hardening();
    setup
        .validate()
        .map_err(|e| LaunchError::HardeningFailed(e.to_string()))?;

    let trusted_same_user = is_trusted_same_user_port_launch(config);
    let mut cmd = containment.wrap(build_browser_command(config, profile_dir)?);
    cmd.stderr(Stdio::inherit());

    let bind_parent_death_signal = config.bind_parent_death;
    let hidraw_dir = containment.hidraw_dir_to_check();
    let parent = std::process::id() as libc::pid_t;

    unsafe {
        cmd.pre_exec(move || {
            if trusted_same_user {
                cloexec_except(&[0, 1, 2])?;

                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }

                if bind_parent_death_signal {
                    bind_parent_death(libc::SIGTERM, parent)?;
                }
            } else {
                setup.apply(&[0, 1, 2], parent)?;
            }
            // Evaluated as the browser's UID (not needed under bwrap).
            match &hidraw_dir {
                Some(dir) => refuse_if_hidraw_accessible(dir),
                None => Ok(()),
            }
        });
    }

    spawn_contained(cmd, containment)
}

/// Removes Chromium's `DevToolsActivePort` from a port-mode profile once the daemon has read the
/// endpoint (plan P10, D6.1): the daemon hands the endpoint out only while the lease is attached,
/// and the file would let a same-UID agent find the loopback port without asking. This is
/// discovery hygiene, not a boundary: a same-UID process can still find the browser's listening
/// socket (`/proc/net/tcp` and its own processes' descriptors), and the file exists from the
/// browser's start until this call (ADR 0014 section 7). The profile belongs to the browser user, so
/// the entry is unlinked through the pinned profile handle and never followed.
fn hide_devtools_active_port(profile: &Dir, profile_dir: &Path) {
    if let Err(e) = profile.remove_file("DevToolsActivePort") {
        log::warn!(
            "cannot remove {}: {e}",
            profile_dir.join("DevToolsActivePort").display()
        );
    }
}

/// Seeds the fresh profile so that the interception extension is allowed in incognito, before
/// the browser's first launch (ADR 0014 section 4.2, plan D4 R13): `Default/Preferences` with
/// `extensions.settings.<id>.incognito = true`, `<id>` being the ID that the manifest `key` fixes.
/// Without it, off-the-record profiles and `Target.createBrowserContext` contexts (Playwright
/// `newContext()`, Playwright MCP `--isolated`, chrome-devtools-mcp `isolatedContext`) are not
/// intercepted and their requests go native. The worker reports
/// `chrome.extension.isAllowedIncognitoAccess()` in its hello, and the launch fails closed unless
/// it is true, so a seed that did not take effect is a launch error.
///
/// Written through the pinned profile handle while the profile is still the daemon's; `Default`
/// and `Preferences` are then handed to the browser user, which Chromium needs to rewrite them.
fn seed_incognito_access_in(
    profile: &Dir,
    target_uid: u32,
    target_gid: u32,
) -> Result<(), LaunchError> {
    let fail = |what: &str, e: io::Error| {
        LaunchError::ExtensionSetupFailed(format!(
            "{what}: {e}; cannot seed incognito access for the passless agent extension"
        ))
    };
    let extension_id = compute_extension_id(EXTENSION_MANIFEST_TEMPLATE)?;
    let preferences = serde_json::json!({
        "extensions": {"settings": {extension_id: {"incognito": true}}}
    })
    .to_string();
    let default = profile
        .create_dir("Default", RUNTIME_DIR_MODE)
        .map_err(|e| fail("create Default", e))?;
    let file = default
        .create_file("Preferences", 0o600, preferences.as_bytes())
        .map_err(|e| fail("create Default/Preferences", e))?;
    chown_file(&file, target_uid, target_gid).map_err(|e| fail("chown Preferences", e))?;
    default
        .chown(target_uid, target_gid)
        .map_err(|e| fail("chown Default", e))
}

fn ensure_browser_running(child: &mut Child) -> Result<(), LaunchError> {
    match child.try_wait() {
        Ok(Some(status)) => Err(LaunchError::BrowserExitedBeforeCdp(status.to_string())),
        Ok(None) => Ok(()),
        Err(e) => Err(LaunchError::SpawnFailed(format!(
            "failed to query browser process during CDP discovery: {}",
            e
        ))),
    }
}

fn terminate_failed_browser_spawn(child: &mut Child) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    signal_process_group(child.id(), libc::SIGKILL);
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
pub(crate) fn discover_cdp_endpoint(
    profile_dir: &Path,
    timeout: Duration,
) -> Result<String, LaunchError> {
    let port_file = profile_dir.join("DevToolsActivePort");
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(content) = fs::read_to_string(&port_file) {
            let lines: Vec<&str> = content.lines().collect();
            if lines.len() >= 2 {
                let port = lines[0].trim();
                let ws_path = lines[1].trim();
                let port_num: u16 = port.parse().map_err(|_| {
                    LaunchError::InvalidCdpEndpoint(format!("invalid port '{}'", port))
                })?;
                if port_num == 0 {
                    return Err(LaunchError::InvalidCdpEndpoint("port must not be 0".into()));
                }
                if !ws_path.starts_with("/devtools/browser/") {
                    return Err(LaunchError::InvalidCdpEndpoint(format!(
                        "invalid devtools path '{}'",
                        ws_path
                    )));
                }
                let url = format!("ws://127.0.0.1:{}{}", port, ws_path);
                validate_loopback_ws_url(&url)?;
                return Ok(url);
            }
        }
        if Instant::now() >= deadline {
            return Err(LaunchError::CdpDiscoveryTimeout);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Waits for Chromium's `DevToolsActivePort` in the profile, read through the pinned profile
/// handle: a regular file owned by the browser user, opened without following a symlink and read
/// up to a bound, so a file planted there cannot make the daemon read anything else (review H1).
/// Its content is never echoed into an error. Returns the port and the `/devtools/browser/<id>`
/// path it names; the caller verifies that the listener there is the browser's.
fn discover_cdp_endpoint_with_child(
    child: &mut Child,
    profile: &Dir,
    owner: u32,
    timeout: Duration,
) -> Result<(u16, String), LaunchError> {
    let deadline = Instant::now() + timeout;
    loop {
        ensure_browser_running(child)?;
        if let Ok(content) =
            profile.read_owned_file("DevToolsActivePort", owner, DEVTOOLS_ACTIVE_PORT_LIMIT)
        {
            let content = String::from_utf8_lossy(&content);
            let lines: Vec<&str> = content.lines().collect();
            if lines.len() >= 2 {
                let port = lines[0].trim();
                let ws_path = lines[1].trim();
                let port_num: u16 = port.parse().map_err(|_| {
                    LaunchError::InvalidCdpEndpoint("DevToolsActivePort has no valid port".into())
                })?;
                if port_num == 0 {
                    return Err(LaunchError::InvalidCdpEndpoint("port must not be 0".into()));
                }
                if !ws_path.starts_with("/devtools/browser/")
                    || !ws_path[1..]
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'/' || b == b'-')
                {
                    return Err(LaunchError::InvalidCdpEndpoint(
                        "DevToolsActivePort has no valid devtools path".into(),
                    ));
                }
                let url = format!("ws://127.0.0.1:{}{}", port_num, ws_path);
                validate_loopback_ws_url(&url)?;
                return Ok((port_num, ws_path.to_string()));
            }
        }
        if Instant::now() >= deadline {
            return Err(LaunchError::CdpDiscoveryTimeout);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Debug and test builds only: lets the E2E suite skip the pre-launch probe of a fixed CDP port,
/// so that the ownership check after the launch meets a real Chromium that fell back to `[::1]`.
/// Release builds have no such hook.
fn skip_cdp_port_probe() -> bool {
    cfg!(debug_assertions) && std::env::var_os("PASSLESS_E2E_SKIP_CDP_PORT_PROBE").is_some()
}

/// How long an unverifiable listener (one this daemon cannot attribute either way) is waited on
/// before the launch is refused.
const CDP_OWNERSHIP_GRACE: Duration = Duration::from_secs(5);

/// Waits until the launched browser (the process tree rooted at `child`, running as
/// `browser_uid`) listens on `127.0.0.1:<port>` and returns its `ws://` endpoint, or refuses as
/// soon as anything else is found there (ADR 0014 section 4.3).
///
/// Proof of ownership, in layers:
/// 1. Every listener a connection to `127.0.0.1:<port>` can reach must be held by the browser's
///    process tree (`/proc/net/tcp{,6}` inode among its `/proc/<pid>/fd`; a different socket UID
///    is foreign at once). A foreign listener, or the browser listening on `[::1]:<port>` only
///    (Chromium's silent fallback when its `127.0.0.1` bind fails), refuses the launch at once.
/// 2. `/json/version` on that listener must name `ws://127.0.0.1:<port>/devtools/browser/<id>`,
///    and, when the browser reported its endpoint itself (`reported_path`, from its
///    `DevToolsActivePort`), exactly that path: its random browser GUID.
/// 3. After that request the same listener must still be the browser's: a listener cannot change
///    hands while the browser holds it, so the endpoint stays the browser's for the lease.
///
/// A listener the daemon cannot attribute (part of the tree's descriptors unreadable) counts only
/// when the browser's own report matches it (layer 2 with `reported_path`); a fixed port has no
/// such report, so it is refused after [`CDP_OWNERSHIP_GRACE`].
fn await_owned_cdp_endpoint(
    child: &mut Child,
    port: u16,
    browser_uid: u32,
    reported_path: Option<&str>,
    timeout: Duration,
) -> Result<String, LaunchError> {
    use super::cdp_owner::{Ownership, ownership};

    let not_owned = |reason: String| LaunchError::CdpEndpointNotOwned { port, reason };
    let deadline = Instant::now() + timeout;
    let mut unverifiable_since: Option<(Instant, String)> = None;
    loop {
        ensure_browser_running(child)?;
        match ownership(child.id(), port, browser_uid) {
            Ownership::NotListening => unverifiable_since = None,
            Ownership::Ipv6Fallback => {
                return Err(not_owned(
                    "the browser could not bind 127.0.0.1 and fell back to [::1]: another \
                     process holds the port"
                        .into(),
                ));
            }
            Ownership::Foreign(holder) => {
                return Err(not_owned(format!("it is held by {holder}")));
            }
            Ownership::Owned(inodes) => {
                if let Some(url) = fetch_ws_debugger_url(port) {
                    check_served_endpoint(&url, port, reported_path).map_err(not_owned)?;
                    return match ownership(child.id(), port, browser_uid) {
                        Ownership::Owned(after) if after == inodes => Ok(url),
                        other => Err(not_owned(format!(
                            "the listener changed while it was queried ({other:?})"
                        ))),
                    };
                }
            }
            Ownership::Unverifiable(why) => {
                if let Some(path) = reported_path
                    && let Some(url) = fetch_ws_debugger_url(port)
                {
                    check_served_endpoint(&url, port, Some(path)).map_err(not_owned)?;
                    log::warn!(
                        "CDP listener on 127.0.0.1:{port}: {why}; accepted because it serves the \
                         browser GUID of the launched browser's DevToolsActivePort"
                    );
                    return Ok(url);
                }
                let since = unverifiable_since.get_or_insert_with(|| (Instant::now(), why.clone()));
                since.1 = why;
                if since.0.elapsed() >= CDP_OWNERSHIP_GRACE {
                    return Err(not_owned(format!(
                        "its owner cannot be verified: {}",
                        since.1
                    )));
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(match unverifiable_since {
                Some((_, why)) => not_owned(format!("its owner cannot be verified: {why}")),
                None => LaunchError::CdpDiscoveryTimeout,
            });
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The served `webSocketDebuggerUrl` must be `ws://127.0.0.1:<port>/devtools/browser/<id>` (never
/// another host or port, such as `[::1]`), and its path the one the browser reported, if any.
fn check_served_endpoint(url: &str, port: u16, reported_path: Option<&str>) -> Result<(), String> {
    let prefix = format!("ws://127.0.0.1:{port}");
    let path = url
        .strip_prefix(&prefix)
        .filter(|path| {
            path.strip_prefix("/devtools/browser/").is_some_and(|id| {
                !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        })
        .ok_or_else(|| {
            format!("it serves an endpoint that is not ws://127.0.0.1:{port}/devtools/browser/<id>")
        })?;
    match reported_path {
        Some(reported) if reported != path => Err(
            "it serves a browser GUID other than the one in the launched browser's \
             DevToolsActivePort"
                .into(),
        ),
        _ => Ok(()),
    }
}

/// `GET /json/version` on `127.0.0.1:<port>`: its `webSocketDebuggerUrl`, or `None` when nothing
/// usable answered (yet). The response is bounded and parsed as JSON.
fn fetch_ws_debugger_url(port: u16) -> Option<String> {
    use std::net::{Ipv4Addr, SocketAddr, TcpStream};

    const LIMIT: usize = 64 * 1024;
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(500)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .ok()?;
    let request =
        format!("GET /json/version HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).ok()?;
    let mut response = Vec::new();
    let _ = (&mut stream).take(LIMIT as u64).read_to_end(&mut response);
    let response = String::from_utf8_lossy(&response);
    let (head, body) = response.split_once("\r\n\r\n")?;
    if !head.starts_with("HTTP/1.1 200") {
        return None;
    }
    // A complete body, if the length is declared (the read may have stopped at the timeout).
    let body = match head.lines().find_map(|l| {
        let (name, value) = l.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    }) {
        Some(len) => body.get(..len)?,
        None => body,
    };
    let json: serde_json::Value = serde_json::from_str(body).ok()?;
    json.get("webSocketDebuggerUrl")?
        .as_str()
        .map(ToOwned::to_owned)
}

fn validate_loopback_ws_url(url: &str) -> Result<(), LaunchError> {
    let rest = url
        .strip_prefix("ws://")
        .ok_or_else(|| LaunchError::InvalidCdpEndpoint("scheme must be ws://".into()))?;

    let (host_port, path) = rest
        .split_once('/')
        .ok_or_else(|| LaunchError::InvalidCdpEndpoint("missing path after host".into()))?;

    let (host, port_str) = if host_port.starts_with('[') {
        let bracket_end = host_port
            .find(']')
            .ok_or_else(|| LaunchError::InvalidCdpEndpoint("malformed IPv6 address".into()))?;
        let host = &host_port[1..bracket_end];
        let port_str = &host_port[bracket_end + 1..];
        let port_str = port_str.strip_prefix(':').unwrap_or(port_str);
        (host, port_str)
    } else {
        host_port
            .rsplit_once(':')
            .ok_or_else(|| LaunchError::InvalidCdpEndpoint("missing port".into()))?
    };

    if host != "127.0.0.1" && host != "::1" && host != "localhost" {
        return Err(LaunchError::InvalidCdpEndpoint(format!(
            "host must be loopback, got '{}'",
            host
        )));
    }

    let port: u16 = port_str
        .parse()
        .map_err(|_| LaunchError::InvalidCdpEndpoint(format!("invalid port '{}'", port_str)))?;
    if port == 0 {
        return Err(LaunchError::InvalidCdpEndpoint("port must not be 0".into()));
    }

    if !path.starts_with("devtools/browser/") {
        return Err(LaunchError::InvalidCdpEndpoint(format!(
            "path must start with /devtools/browser/, got '/{}'",
            path
        )));
    }

    Ok(())
}

/// Keeps an intercepted port-mode lease's `cdp-endpoint` file in step with its interception: it
/// exists only while the worker is attached (finding: it used to be written before the attach and
/// left behind on degrade). Pipe-mode leases have no such file.
fn sync_cdp_endpoint_file(lease: &BrowserLease, attached: bool) -> Result<(), LaunchError> {
    let (Some(endpoint), Some(interception)) = (&lease.cdp_endpoint, &lease.interception) else {
        return Ok(());
    };
    let runtime_dir = &lease.manifest.runtime_dir;
    let Some(dir) = &lease.runtime_dir_handle else {
        return Err(LaunchError::EndpointFileWriteFailed(
            runtime_dir.join("cdp-endpoint").display().to_string(),
            "the lease directory is not open".to_string(),
        ));
    };
    if attached {
        let (uid, gid) = interception.endpoint_file_owner;
        write_cdp_endpoint(dir, runtime_dir, endpoint, uid, gid)
    } else {
        dir.remove_file("cdp-endpoint").map_err(|e| {
            LaunchError::EndpointFileWriteFailed(
                runtime_dir.join("cdp-endpoint").display().to_string(),
                e.to_string(),
            )
        })
    }
}

/// (Re)writes the lease's `cdp-endpoint` file through the pinned lease directory: whatever entry
/// has that name is removed, never followed, and a fresh file is created exclusively and handed to
/// the browser user, who reads it.
fn write_cdp_endpoint(
    lease_dir: &Dir,
    runtime_dir: &Path,
    url: &str,
    target_uid: u32,
    target_gid: u32,
) -> Result<(), LaunchError> {
    let fail = |e: io::Error| {
        LaunchError::EndpointFileWriteFailed(
            runtime_dir.join("cdp-endpoint").display().to_string(),
            e.to_string(),
        )
    };
    let file = lease_dir
        .replace_file("cdp-endpoint", 0o600, url.as_bytes())
        .map_err(fail)?;
    chown_file(&file, target_uid, target_gid).map_err(fail)
}

fn read_process_identity(pid: u32) -> Option<ProcessIdentity> {
    let stat_path = format!("/proc/{}/stat", pid);
    let stat_content = fs::read_to_string(&stat_path).ok()?;
    let start_time_ticks = parse_start_time_from_stat(&stat_content)?;

    if start_time_ticks == 0 {
        return None;
    }

    let cgroup_path = format!("/proc/{}/cgroup", pid);
    let cgroup = fs::read_to_string(&cgroup_path).ok()?;

    if cgroup.trim().is_empty() {
        return None;
    }

    Some(ProcessIdentity {
        pid,
        start_time_ticks,
        cgroup,
    })
}

fn parse_start_time_from_stat(stat: &str) -> Option<u64> {
    let close_paren = stat.rfind(')')?;
    let after_comm = &stat[close_paren + 2..];
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    if fields.len() < 20 {
        return None;
    }
    fields[19].parse::<u64>().ok()
}

fn cgroup_matches(actual: &str, expected: &str) -> bool {
    let actual_trimmed = actual.trim();
    let expected_trimmed = expected.trim();

    if actual_trimmed.is_empty() || expected_trimmed.is_empty() {
        return false;
    }

    let actual_scope = extract_scope(actual_trimmed);
    let expected_scope = extract_scope(expected_trimmed);

    match (actual_scope, expected_scope) {
        (Some(a), Some(e)) => a == e,
        _ => actual_trimmed == expected_trimmed,
    }
}

fn extract_scope(cgroup: &str) -> Option<&str> {
    for line in cgroup.lines() {
        if line.contains(".scope")
            && let Some(pos) = line.rfind('/')
        {
            return Some(&line[pos + 1..]);
        }
    }
    None
}

fn reverify_identity(pid: u32, expected: &ProcessIdentity) -> bool {
    if !expected.is_valid() {
        return false;
    }

    let _pidfd = try_open_pidfd(pid);

    let actual = match read_process_identity(pid) {
        Some(id) => id,
        None => return false,
    };

    if !actual.is_valid() {
        return false;
    }

    actual.start_time_ticks == expected.start_time_ticks
        && cgroup_matches(&actual.cgroup, &expected.cgroup)
}

fn check_identity_mismatch(pid: u32, expected: &ProcessIdentity) -> Option<String> {
    if !expected.is_valid() {
        return Some("expected identity is invalid".to_string());
    }

    let stat_path = format!("/proc/{}/stat", pid);
    if !Path::new(&stat_path).exists() {
        return None;
    }

    let actual = match read_process_identity(pid) {
        Some(identity) => identity,
        None => return Some(format!("cannot read process identity for pid {}", pid)),
    };

    if !actual.is_valid() {
        return Some(format!(
            "actual process identity for pid {} is invalid",
            pid
        ));
    }

    if actual.start_time_ticks != expected.start_time_ticks
        || !cgroup_matches(&actual.cgroup, &expected.cgroup)
    {
        return Some(format!(
            "process identity mismatch: expected start_time={} cgroup={}, got start_time={} cgroup={}",
            expected.start_time_ticks,
            expected.cgroup.trim(),
            actual.start_time_ticks,
            actual.cgroup.trim(),
        ));
    }

    None
}

fn try_open_pidfd(pid: u32) -> Option<RawFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::c_int, 0 as libc::c_uint) };
    if fd < 0 { None } else { Some(fd as RawFd) }
}

fn signal_process_group(pgid: u32, sig: libc::c_int) {
    unsafe { libc::kill(-(pgid as i32), sig) };
}

fn verify_path_safety(path: &Path, expected_fp: &ProfileFingerprint) -> CleanupSafety {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return CleanupSafety::Clean,
    };

    if meta.file_type().is_symlink() {
        return CleanupSafety::Quarantined {
            reason: "path is a symlink".to_string(),
            quarantine_path: path.to_path_buf(),
        };
    }

    let current_fp = ProfileFingerprint {
        inode: meta.ino(),
        dev: meta.dev(),
    };

    if current_fp != *expected_fp {
        return CleanupSafety::Quarantined {
            reason: format!(
                "fingerprint mismatch: expected inode={} dev={}, got inode={} dev={}",
                expected_fp.inode, expected_fp.dev, current_fp.inode, current_fp.dev
            ),
            quarantine_path: path.to_path_buf(),
        };
    }

    CleanupSafety::Clean
}

fn quarantine_runtime_dir(
    runtime_dir: &Path,
    reason: &str,
) -> Result<CleanupSafety, TransitionError> {
    let parent = runtime_dir.parent().unwrap_or(Path::new("/tmp"));
    let dir_name = runtime_dir
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let q_name = generate_quarantine_name(&dir_name);
    let q_path = parent.join(&q_name);

    match fs::rename(runtime_dir, &q_path) {
        Ok(()) => Ok(CleanupSafety::Quarantined {
            reason: reason.to_string(),
            quarantine_path: q_path,
        }),
        Err(_) => Ok(CleanupSafety::Failed {
            reason: format!(
                "failed to quarantine runtime dir at {}: {}",
                runtime_dir.display(),
                reason
            ),
        }),
    }
}

fn generate_quarantine_name(original_name: &str) -> String {
    let mut rng = rand::thread_rng();
    let random_suffix: u64 = rng.r#gen();
    format!(
        "{}-{:016x}-{}",
        QUARANTINE_PREFIX, random_suffix, original_name
    )
}

fn open_dir_fd(path: &Path) -> io::Result<RawFd> {
    let c_path = path_to_cstring(path)?;
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_RDONLY,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

fn verify_dir_fd_identity(dir_fd: RawFd, expected_path: &Path) -> bool {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::fstat(dir_fd, &mut stat) };
    if ret != 0 {
        return false;
    }

    let expected_meta = match fs::metadata(expected_path) {
        Ok(m) => m,
        Err(_) => return false,
    };

    stat.st_ino == expected_meta.ino() && stat.st_dev == expected_meta.dev()
}

fn path_to_cstring(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL byte"))
}

/// Writes `browser-manifest.json` atomically through the pinned lease directory: an exclusive
/// temporary file (`O_EXCL | O_NOFOLLOW`), fsync, `renameat` over the final name, fsync of the
/// directory.
fn write_manifest_atomic(
    lease_dir: &Dir,
    runtime_dir: &Path,
    manifest: &BrowserManifest,
) -> Result<(), LaunchError> {
    let manifest_path = runtime_dir.join(MANIFEST_FILENAME);
    let tmp_name = format!(
        ".{}.tmp.{:016x}",
        MANIFEST_FILENAME,
        rand::thread_rng().r#gen::<u64>()
    );
    let fail = |e: io::Error| {
        LaunchError::ManifestWriteFailed(manifest_path.display().to_string(), e.to_string())
    };
    let manifest_json = serde_json::to_string_pretty(manifest).map_err(|e| {
        LaunchError::ManifestWriteFailed(manifest_path.display().to_string(), e.to_string())
    })?;
    let tmp_file = lease_dir
        .create_file(&tmp_name, 0o600, manifest_json.as_bytes())
        .map_err(fail)?;
    let synced = tmp_file.sync_all();
    drop(tmp_file);
    if let Err(e) = synced.and_then(|()| lease_dir.rename(&tmp_name, MANIFEST_FILENAME)) {
        let _ = lease_dir.remove_file(&tmp_name);
        return Err(fail(e));
    }
    let _ = lease_dir.sync();
    Ok(())
}

/// Test helper: [`write_manifest_atomic`] for the directory at `dir`.
#[cfg(test)]
fn write_manifest_atomic_at(dir: &Path, manifest: &BrowserManifest) -> Result<(), LaunchError> {
    let lease_dir = Dir::open_path(dir)
        .map_err(|e| LaunchError::ManifestWriteFailed(dir.display().to_string(), e.to_string()))?;
    write_manifest_atomic(&lease_dir, dir, manifest)
}

fn decode_wait_status(status: libc::c_int) -> Option<ExitStatus> {
    use std::os::unix::process::ExitStatusExt;
    Some(ExitStatus::from_raw(status))
}

/// Write one NUL-terminated frame to the browser's CDP pipe.
fn write_cdp_frame(entry: &mut BrowserLease, json: &str) -> Result<(), CdpError> {
    let cdp = entry.cdp.as_mut().ok_or(CdpError::NoCdpEndpoints)?;
    let mut frame = json.as_bytes().to_vec();
    frame.push(0);
    cdp.to_browser
        .write_all(&frame)
        .map_err(|e| CdpError::WriteFailed(e.to_string()))?;
    cdp.to_browser
        .flush()
        .map_err(|e| CdpError::WriteFailed(e.to_string()))
}

/// The next complete message from the browser's CDP pipe, or `None` once `deadline` passes.
fn read_cdp_message(
    entry: &mut BrowserLease,
    deadline: Instant,
) -> Result<Option<String>, CdpError> {
    loop {
        if let Some(nul_pos) = entry.cdp_read_buf.iter().position(|&b| b == 0) {
            let mut message = entry.cdp_read_buf.drain(..=nul_pos).collect::<Vec<_>>();
            message.pop();
            if message.is_empty() {
                continue;
            }
            return Ok(Some(String::from_utf8_lossy(&message).into_owned()));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }

        let cdp = entry.cdp.as_mut().ok_or(CdpError::NoCdpEndpoints)?;
        let fd = cdp.from_browser.as_raw_fd();
        set_nonblocking(fd, true);
        let mut buf = vec![0u8; CDP_READ_BUF_SIZE];
        let read = cdp.from_browser.read(&mut buf);
        set_nonblocking(fd, false);
        match read {
            Ok(0) => return Err(CdpError::BrowserExited),
            Ok(n) => entry
                .cdp_read_buf
                .extend_from_slice(buf.get(..n).unwrap_or_default()),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                std::thread::sleep(remaining.min(Duration::from_millis(10)));
            }
            Err(e) => return Err(CdpError::ReadFailed(e.to_string())),
        }
    }
}

/// Ask the browser what `target` is before an agent command that names it is forwarded; true when
/// it is hostile (the extension's or a browser-internal target). Messages
/// read meanwhile are kept for the agent (they pass the filter when delivered). Fails closed: a
/// lookup without an answer by `deadline` refuses the command.
fn lookup_hostile_target(
    entry: &mut BrowserLease,
    target: &str,
    deadline: Instant,
) -> Result<bool, CdpError> {
    let (lookup_id, command) = entry.cdp_filter.lookup_command(target);
    write_cdp_frame(entry, &command)?;
    loop {
        let Some(raw) = read_cdp_message(entry, deadline)? else {
            return Err(CdpError::Denied(
                "the target could not be checked in time".to_string(),
            ));
        };
        let id = serde_json::from_str::<serde_json::Value>(&raw)
            .ok()
            .and_then(|message| {
                let id = message.get("id")?.as_u64()?;
                Some((id, message))
            });
        match id {
            Some((id, response)) if id == lookup_id => {
                return Ok(entry.cdp_filter.lookup_result(target, &response));
            }
            // A stale answer to an earlier daemon command of the filter.
            Some((id, _)) if ExtensionCdpFilter::is_internal_id(id) => {}
            _ => {
                if entry.cdp_buffer.len() >= CDP_MAX_RESPONSE_MESSAGES {
                    return Err(CdpError::TooManyMessages);
                }
                entry.cdp_buffer.push_back(raw);
            }
        }
    }
}

fn validate_cdp_request(json: &str) -> Result<(), CdpError> {
    if json.len() > CDP_MAX_REQUEST_BYTES {
        return Err(CdpError::InvalidRequest(format!(
            "request exceeds maximum size {} (got {})",
            CDP_MAX_REQUEST_BYTES,
            json.len()
        )));
    }

    if json.contains('\0') {
        return Err(CdpError::InvalidRequest(
            "request must not contain NUL bytes".to_string(),
        ));
    }

    let parsed: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| CdpError::InvalidRequest(format!("invalid JSON: {}", e)))?;

    let obj = parsed
        .as_object()
        .ok_or_else(|| CdpError::InvalidRequest("request must be a JSON object".to_string()))?;

    let id = obj
        .get("id")
        .ok_or_else(|| CdpError::InvalidRequest("request must have an 'id' field".to_string()))?;
    if !id.is_number() {
        return Err(CdpError::InvalidRequest(
            "'id' must be a number".to_string(),
        ));
    }
    let id_num = id.as_f64().unwrap();
    if id_num <= 0.0 || id_num != id_num.floor() {
        return Err(CdpError::InvalidRequest(
            "'id' must be a positive integer".to_string(),
        ));
    }

    let method = obj.get("method").ok_or_else(|| {
        CdpError::InvalidRequest("request must have a 'method' field".to_string())
    })?;
    if !method.is_string() {
        return Err(CdpError::InvalidRequest(
            "'method' must be a string".to_string(),
        ));
    }

    if let Some(params) = obj.get("params")
        && !params.is_object()
    {
        return Err(CdpError::InvalidRequest(
            "'params' must be an object".to_string(),
        ));
    }

    if let Some(sid) = obj.get("sessionId")
        && !sid.is_string()
    {
        return Err(CdpError::InvalidRequest(
            "'sessionId' must be a string".to_string(),
        ));
    }

    for key in obj.keys() {
        match key.as_str() {
            "id" | "method" | "params" | "sessionId" => {}
            other => {
                return Err(CdpError::InvalidRequest(format!(
                    "unknown field '{}': only id, method, params, sessionId allowed",
                    other
                )));
            }
        }
    }

    Ok(())
}

fn extract_cdp_id(json: &str) -> Option<serde_json::Number> {
    let parsed: serde_json::Value = serde_json::from_str(json).ok()?;
    parsed.as_object()?.get("id")?.as_number().cloned()
}

fn cdp_message_has_id(json: &str, target_id: &serde_json::Number) -> bool {
    let parsed: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let obj = match parsed.as_object() {
        Some(o) => o,
        None => return false,
    };
    match obj.get("id") {
        Some(id) => id.as_number() == Some(target_id),
        None => false,
    }
}

fn clamp_cdp_timeout(timeout: Duration) -> Duration {
    if timeout < CDP_MIN_TIMEOUT {
        CDP_MIN_TIMEOUT
    } else if timeout > CDP_MAX_TIMEOUT {
        CDP_MAX_TIMEOUT
    } else {
        timeout
    }
}

fn set_nonblocking(fd: RawFd, nonblocking: bool) {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return;
    }
    let new_flags = if nonblocking {
        flags | libc::O_NONBLOCK
    } else {
        flags & !libc::O_NONBLOCK
    };
    unsafe { libc::fcntl(fd, libc::F_SETFL, new_flags) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs as unix_fs;

    use super::super::launcher::ProbeResult;

    thread_local! {
        /// Makes `generate_agent_extension` drop the extension directory (see `simulate_missing_extension`).
        pub(super) static OMIT_EXTENSION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// The relay path test managers use: any existing file will do, nothing runs it.
    pub(super) fn test_sign_proxy_path() -> PathBuf {
        PathBuf::from("/bin/true")
    }

    const DEFAULT_LOGIN_TIMEOUT: Duration = Duration::from_secs(120);

    fn test_clock() -> Arc<MockClock> {
        Arc::new(MockClock::new())
    }

    fn test_config(dir: &Path) -> BrowserConfig {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        BrowserConfig {
            executable: PathBuf::from("/bin/true"),
            start_url: None,
            extra_args: Vec::new(),
            runtime_root: setup_runtime_root(dir),
            ttl: Duration::from_secs(300),
            login_timeout: DEFAULT_LOGIN_TIMEOUT,
            rp_ids: vec!["example.com".to_string()],
            start_url_rules: start_url_test_rules(&[("example.com", RuleAction::Allow)]),
            target_uid: uid,
            target_gid: gid,
            daemon_uid: 0,
            daemon_gid: 0,
            cdp_expose: CdpExposeMode::default(),
            cdp_port: 9222,
            bind_parent_death: true,
        }
    }

    fn setup_runtime_root(parent: &Path) -> PathBuf {
        let root = parent.join("runtime-root");
        fs::create_dir_all(&root).unwrap();
        let perms = fs::Permissions::from_mode(RUNTIME_DIR_MODE);
        fs::set_permissions(&root, perms).unwrap();
        root
    }

    fn test_profile_id() -> ProfileId {
        ProfileId::new("test-profile").unwrap()
    }

    #[test]
    fn test_lease_state_display() {
        assert_eq!(
            LeaseState::AuthenticationPending.to_string(),
            "authentication-pending"
        );
        assert_eq!(LeaseState::Active.to_string(), "active");
        assert_eq!(LeaseState::Revoked.to_string(), "revoked");
        assert_eq!(LeaseState::BrowserExit.to_string(), "browser-exit");
        assert_eq!(LeaseState::PrincipalExit.to_string(), "principal-exit");
        assert_eq!(LeaseState::DaemonShutdown.to_string(), "daemon-shutdown");
    }

    #[test]
    fn test_lease_state_is_terminal() {
        assert!(!LeaseState::AuthenticationPending.is_terminal());
        assert!(!LeaseState::Active.is_terminal());
        assert!(LeaseState::Revoked.is_terminal());
        assert!(LeaseState::BrowserExit.is_terminal());
        assert!(LeaseState::PrincipalExit.is_terminal());
        assert!(LeaseState::DaemonShutdown.is_terminal());
    }

    #[test]
    fn test_valid_lease_transitions() {
        assert!(is_valid_lease_transition(
            LeaseState::AuthenticationPending,
            LeaseState::Revoked
        ));
        assert!(is_valid_lease_transition(
            LeaseState::AuthenticationPending,
            LeaseState::BrowserExit
        ));
        assert!(is_valid_lease_transition(
            LeaseState::AuthenticationPending,
            LeaseState::PrincipalExit
        ));
        assert!(is_valid_lease_transition(
            LeaseState::AuthenticationPending,
            LeaseState::DaemonShutdown
        ));
        assert!(is_valid_lease_transition(
            LeaseState::Active,
            LeaseState::Revoked
        ));
        assert!(is_valid_lease_transition(
            LeaseState::Active,
            LeaseState::BrowserExit
        ));
        assert!(is_valid_lease_transition(
            LeaseState::Active,
            LeaseState::PrincipalExit
        ));
        assert!(is_valid_lease_transition(
            LeaseState::Active,
            LeaseState::DaemonShutdown
        ));
        assert!(is_valid_lease_transition(
            LeaseState::Revoked,
            LeaseState::BrowserExit
        ));
        assert!(is_valid_lease_transition(
            LeaseState::Revoked,
            LeaseState::PrincipalExit
        ));
        assert!(is_valid_lease_transition(
            LeaseState::Revoked,
            LeaseState::DaemonShutdown
        ));
        assert!(is_valid_lease_transition(
            LeaseState::PrincipalExit,
            LeaseState::DaemonShutdown
        ));
        assert!(is_valid_lease_transition(
            LeaseState::BrowserExit,
            LeaseState::DaemonShutdown
        ));
    }

    #[test]
    fn test_invalid_lease_transitions() {
        assert!(!is_valid_lease_transition(
            LeaseState::AuthenticationPending,
            LeaseState::Active
        ));
        assert!(!is_valid_lease_transition(
            LeaseState::Revoked,
            LeaseState::Active
        ));
        assert!(!is_valid_lease_transition(
            LeaseState::Revoked,
            LeaseState::AuthenticationPending
        ));
        assert!(!is_valid_lease_transition(
            LeaseState::BrowserExit,
            LeaseState::Active
        ));
        assert!(!is_valid_lease_transition(
            LeaseState::PrincipalExit,
            LeaseState::Active
        ));
        assert!(!is_valid_lease_transition(
            LeaseState::DaemonShutdown,
            LeaseState::Active
        ));
        assert!(!is_valid_lease_transition(
            LeaseState::DaemonShutdown,
            LeaseState::Revoked
        ));
        assert!(!is_valid_lease_transition(
            LeaseState::BrowserExit,
            LeaseState::Revoked
        ));
        assert!(!is_valid_lease_transition(
            LeaseState::PrincipalExit,
            LeaseState::Revoked
        ));
        assert!(!is_valid_lease_transition(
            LeaseState::BrowserExit,
            LeaseState::PrincipalExit
        ));
        assert!(!is_valid_lease_transition(
            LeaseState::PrincipalExit,
            LeaseState::BrowserExit
        ));
    }

    #[test]
    fn test_system_clock_monotonic() {
        let clock = SystemClock;
        let t1 = clock.monotonic_secs();
        std::thread::sleep(Duration::from_millis(50));
        let t2 = clock.monotonic_secs();
        assert!(t2 >= t1);
    }

    #[test]
    fn test_mock_clock_advance() {
        let clock = MockClock::new();
        assert_eq!(clock.monotonic_secs(), 0);
        clock.advance(Duration::from_secs(10));
        assert_eq!(clock.monotonic_secs(), 10);
        clock.advance(Duration::from_secs(5));
        assert_eq!(clock.monotonic_secs(), 15);
    }

    #[test]
    fn test_mock_clock_set_offset() {
        let clock = MockClock::new();
        clock.set_offset(Duration::from_secs(42));
        assert_eq!(clock.monotonic_secs(), 42);
    }

    #[test]
    fn test_mock_clock_concurrent_advance() {
        let clock = Arc::new(MockClock::new());
        let mut handles = Vec::new();
        for _ in 0..10 {
            let c = Arc::clone(&clock);
            handles.push(std::thread::spawn(move || {
                c.advance(Duration::from_secs(1));
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(clock.monotonic_secs(), 10);
    }

    #[test]
    fn test_clamp_ttl_normal() {
        assert_eq!(
            clamp_ttl(Duration::from_secs(300)),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn test_clamp_ttl_below_minimum() {
        assert_eq!(
            clamp_ttl(Duration::from_millis(500)),
            Duration::from_secs(MIN_TTL_SECS)
        );
    }

    #[test]
    fn test_clamp_ttl_above_maximum() {
        assert_eq!(
            clamp_ttl(Duration::from_secs(MAX_TTL_CLAMP_SECS + 1000)),
            Duration::from_secs(MAX_TTL_CLAMP_SECS)
        );
    }

    #[test]
    fn test_clamp_ttl_at_boundaries() {
        assert_eq!(
            clamp_ttl(Duration::from_secs(MIN_TTL_SECS)),
            Duration::from_secs(MIN_TTL_SECS)
        );
        assert_eq!(
            clamp_ttl(Duration::from_secs(MAX_TTL_CLAMP_SECS)),
            Duration::from_secs(MAX_TTL_CLAMP_SECS)
        );
    }

    #[test]
    fn test_validate_start_url_valid() {
        let rp_ids = start_url_test_rules(&[("example.com", RuleAction::Allow)]);
        assert!(validate_start_url("https://example.com", &rp_ids).is_ok());
        assert!(validate_start_url("https://example.com/path", &rp_ids).is_ok());
        assert!(validate_start_url("https://sub.example.com:443/path", &rp_ids).is_ok());
        assert!(validate_start_url("https://example.com?query=1", &rp_ids).is_ok());
    }

    fn start_url_test_rules(rules: &[(&str, RuleAction)]) -> Vec<AgentRpRule> {
        rules
            .iter()
            .map(|(rp_id, action)| AgentRpRule {
                rp_id: (*rp_id).to_string(),
                register: RuleAction::Deny,
                authenticate: *action,
                credential_selection: None,
            })
            .collect()
    }

    #[test]
    fn test_validate_start_url_localhost_exact_rule_only() {
        let exact = start_url_test_rules(&[("localhost", RuleAction::Allow)]);
        assert!(validate_start_url("http://localhost", &exact).is_ok());
        assert!(validate_start_url("http://localhost:8080/path", &exact).is_ok());
        assert!(validate_start_url("https://localhost", &exact).is_ok());
        // Never through the wildcard, never another http host, never a subdomain of localhost.
        let wildcard = start_url_test_rules(&[("*", RuleAction::Allow)]);
        assert!(validate_start_url("http://localhost", &wildcard).is_err());
        assert!(validate_start_url("https://localhost", &wildcard).is_err());
        let example = start_url_test_rules(&[("example.com", RuleAction::Allow)]);
        assert!(validate_start_url("http://example.com", &example).is_err());
        assert!(validate_start_url("http://foo.localhost", &exact).is_err());
        assert!(validate_start_url("https://foo.localhost", &exact).is_err());
        // A trailing dot is a different host.
        assert!(validate_start_url("http://localhost./", &exact).is_err());
    }

    #[test]
    fn test_validate_start_url_rejects_userinfo_and_confused_hosts() {
        let exact = start_url_test_rules(&[("localhost", RuleAction::Allow)]);
        // `localhost:1` is userinfo here and the real host is evil.com.
        assert!(validate_start_url("http://localhost:1@evil.com/", &exact).is_err());
        assert!(validate_start_url("http://user@localhost/", &exact).is_err());
        assert!(
            validate_start_url(
                "https://user:pw@example.com/",
                &start_url_test_rules(&[("example.com", RuleAction::Allow)])
            )
            .is_err()
        );
        let wildcard = start_url_test_rules(&[("*", RuleAction::Allow)]);
        assert!(validate_start_url("https://example.com:443@evil.com/", &wildcard).is_err());
        assert!(validate_start_url("https://example.com@evil.com/", &wildcard).is_err());
        assert!(
            validate_start_url("https://evil.com\\@example.com/", &wildcard).is_ok(),
            "backslash is a path separator for https: the host is evil.com, matched by the wildcard"
        );
    }

    #[test]
    fn test_validate_start_url_ports_and_ip_hosts() {
        let exact = start_url_test_rules(&[("localhost", RuleAction::Allow)]);
        assert!(validate_start_url("http://localhost:3000", &exact).is_ok());
        assert!(validate_start_url("http://localhost:99999", &exact).is_err());
        assert!(validate_start_url("http://localhost:abc", &exact).is_err());
        let wildcard = start_url_test_rules(&[("*", RuleAction::Allow)]);
        // IP literals are never valid RP hosts.
        assert!(validate_start_url("https://127.0.0.1/", &wildcard).is_err());
        assert!(validate_start_url("https://[::1]/", &wildcard).is_err());
        assert!(validate_start_url("https://[::1]:8443/", &exact).is_err());
        assert!(validate_start_url("http://[::1]/", &exact).is_err());
        assert!(validate_start_url("http://127.0.0.1/", &exact).is_err());
    }

    #[test]
    fn test_validate_start_url_most_specific_rule_decides() {
        // A subdomain deny must not break the allowed parent domain, and a denied host is never a
        // launch target.
        let rules = start_url_test_rules(&[
            ("example.com", RuleAction::Allow),
            ("login.example.com", RuleAction::Deny),
        ]);
        assert!(validate_start_url("https://example.com/", &rules).is_ok());
        assert!(validate_start_url("https://app.example.com/", &rules).is_ok());
        assert!(validate_start_url("https://login.example.com/", &rules).is_err());
        assert!(validate_start_url("https://sso.login.example.com/", &rules).is_err());
        // The reverse: an allowed subdomain under a denied parent.
        let rules = start_url_test_rules(&[
            ("example.com", RuleAction::Deny),
            ("login.example.com", RuleAction::Request),
        ]);
        assert!(validate_start_url("https://login.example.com/", &rules).is_ok());
        assert!(validate_start_url("https://example.com/", &rules).is_err());
        // An exact deny beats the wildcard.
        let rules =
            start_url_test_rules(&[("*", RuleAction::Allow), ("bad.com", RuleAction::Deny)]);
        assert!(validate_start_url("https://good.com/", &rules).is_ok());
        assert!(validate_start_url("https://bad.com/", &rules).is_err());
        assert!(validate_start_url("https://x.bad.com/", &rules).is_err());
    }

    #[test]
    fn test_validate_start_url_invalid_scheme() {
        let rp_ids = start_url_test_rules(&[("example.com", RuleAction::Allow)]);
        assert!(validate_start_url("http://example.com", &rp_ids).is_err());
        assert!(validate_start_url("ftp://example.com", &rp_ids).is_err());
        assert!(validate_start_url("", &rp_ids).is_err());
        assert!(validate_start_url("https://", &rp_ids).is_err());
    }

    #[test]
    fn test_validate_start_url_host_must_match_rp_id() {
        let rp_ids = start_url_test_rules(&[("example.com", RuleAction::Allow)]);
        assert!(validate_start_url("https://other.com/path", &rp_ids).is_err());
        assert!(validate_start_url("https://notexample.com/path", &rp_ids).is_err());
    }

    #[test]
    fn test_validate_start_url_matches_exactly_one_rp_id() {
        let rp_ids = start_url_test_rules(&[
            ("example.com", RuleAction::Allow),
            ("example.org", RuleAction::Allow),
        ]);
        assert!(validate_start_url("https://other.com/path", &rp_ids).is_err());
        assert!(validate_start_url("https://example.com/path", &rp_ids).is_ok());
    }

    #[test]
    fn test_validate_start_url_no_rp_match() {
        let rp_ids: Vec<AgentRpRule> = vec![];
        assert!(validate_start_url("https://example.com", &rp_ids).is_err());
    }

    #[test]
    fn test_validate_runtime_root_valid() {
        let dir = tempfile::tempdir().unwrap();
        let root = setup_runtime_root(dir.path());
        let uid = unsafe { libc::getuid() };
        assert!(validate_runtime_root(&root, uid).is_ok());
    }

    #[test]
    fn test_validate_runtime_root_symlink_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let root = setup_runtime_root(dir.path());
        let link = dir.path().join("link");
        unix_fs::symlink(&root, &link).unwrap();
        let uid = unsafe { libc::getuid() };
        assert!(validate_runtime_root(&link, uid).is_err());
    }

    #[test]
    fn test_validate_runtime_root_wrong_mode_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("bad-root");
        fs::create_dir_all(&root).unwrap();
        let perms = fs::Permissions::from_mode(0o755);
        fs::set_permissions(&root, perms).unwrap();
        let uid = unsafe { libc::getuid() };
        assert!(validate_runtime_root(&root, uid).is_err());
    }

    #[test]
    fn test_validate_runtime_root_wrong_owner_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let root = setup_runtime_root(dir.path());
        assert!(validate_runtime_root(&root, 99999).is_err());
    }

    fn ids() -> (u32, u32) {
        // SAFETY: no preconditions.
        unsafe { (libc::geteuid(), libc::getegid()) }
    }

    fn mode_of(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// A fresh machine: `$XDG_RUNTIME_DIR` exists, `passless/browser` does not. The first launch
    /// used to fail with "No such file or directory".
    #[test]
    fn test_default_runtime_root_is_created_0700_and_then_validates() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("xdg-runtime");
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let root = base.join("passless").join("browser");
        let (uid, gid) = ids();
        assert!(!root.exists());

        ensure_runtime_root_with(&root, uid, gid, &base, &root).unwrap();
        assert_eq!(mode_of(&root), 0o700);
        assert_eq!(mode_of(&base.join("passless")), 0o700);
        assert_eq!(fs::metadata(&root).unwrap().uid(), uid);
        validate_runtime_root(&root, uid).unwrap();

        // Idempotent, and a lease can be created in it afterwards.
        ensure_runtime_root_with(&root, uid, gid, &base, &root).unwrap();
        assert_eq!(mode_of(&root), 0o700);
    }

    #[test]
    fn test_default_runtime_root_is_not_created_for_another_browser_user() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("passless").join("browser");
        let (uid, gid) = ids();
        let err = ensure_runtime_root_with(&root, uid.wrapping_add(1), gid, tmp.path(), &root)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
        assert!(err.to_string().contains("browser_runtime_root"), "{err}");
        assert!(!tmp.path().join("passless").exists(), "nothing was created");
    }

    /// A pre-existing root is never repaired: the wrong mode, a symlink and a foreign owner stay
    /// refused by the launch validation.
    #[test]
    fn test_existing_runtime_roots_are_left_alone_and_still_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let (uid, gid) = ids();

        let wide = tmp.path().join("wide");
        fs::create_dir(&wide).unwrap();
        fs::set_permissions(&wide, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_runtime_root_with(&wide, uid, gid, tmp.path(), &wide).unwrap();
        assert_eq!(mode_of(&wide), 0o755, "not chmodded");
        assert!(validate_runtime_root(&wide, uid).is_err());

        let real = setup_runtime_root(tmp.path());
        let link = tmp.path().join("link");
        unix_fs::symlink(&real, &link).unwrap();
        ensure_runtime_root_with(&link, uid, gid, tmp.path(), &link).unwrap();
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(validate_runtime_root(&link, uid).is_err());

        // Owned by someone else (as if the browser user were another one): left, then refused.
        let owned = setup_runtime_root(tmp.path());
        ensure_runtime_root_with(&owned, uid, gid, tmp.path(), &owned).unwrap();
        assert!(validate_runtime_root(&owned, uid.wrapping_add(1)).is_err());
    }

    /// A symlink planted where a missing parent of the default root would go is not followed.
    #[test]
    fn test_default_runtime_root_refuses_a_symlinked_parent() {
        let tmp = tempfile::tempdir().unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        let base = tmp.path().join("xdg-runtime");
        fs::create_dir(&base).unwrap();
        unix_fs::symlink(&elsewhere, base.join("passless")).unwrap();
        let root = base.join("passless").join("browser");
        let (uid, gid) = ids();
        assert!(ensure_runtime_root_with(&root, uid, gid, &base, &root).is_err());
        assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
    }

    #[test]
    fn test_configured_runtime_root_creates_only_its_final_component() {
        let tmp = tempfile::tempdir().unwrap();
        let (uid, gid) = ids();
        let other_default = tmp.path().join("default");
        let parent = tmp.path().join("parent");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
        let root = parent.join("browser-root");

        ensure_runtime_root_with(&root, uid, gid, tmp.path(), &other_default).unwrap();
        assert_eq!(mode_of(&root), 0o700);
        assert_eq!(fs::metadata(&root).unwrap().uid(), uid);
        validate_runtime_root(&root, uid).unwrap();

        // A missing parent is not created.
        let deep = tmp.path().join("absent").join("browser-root");
        let err =
            ensure_runtime_root_with(&deep, uid, gid, tmp.path(), &other_default).unwrap_err();
        assert!(err.to_string().contains("create the parent"), "{err}");
        assert!(!tmp.path().join("absent").exists());

        // A parent others can write to is refused; a sticky one (like /tmp) is not.
        let shared = tmp.path().join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        let in_shared = shared.join("browser-root");
        let err =
            ensure_runtime_root_with(&in_shared, uid, gid, tmp.path(), &other_default).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
        assert!(!in_shared.exists());
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();
        ensure_runtime_root_with(&in_shared, uid, gid, tmp.path(), &other_default).unwrap();
        assert_eq!(mode_of(&in_shared), 0o700);

        // A symlinked parent resolves like a system symlink (`/var/run`), a symlink at the root
        // itself is left for the validation to refuse.
        let alias = tmp.path().join("alias");
        unix_fs::symlink(&parent, &alias).unwrap();
        ensure_runtime_root_with(&alias.join("second"), uid, gid, tmp.path(), &other_default)
            .unwrap();
        assert_eq!(mode_of(&parent.join("second")), 0o700);
    }

    /// Handing a new root to another user needs root; without it the half-made directory is
    /// removed again and the launch reports why.
    #[test]
    fn test_configured_runtime_root_for_another_user_is_not_left_behind_without_root() {
        // SAFETY: no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let (uid, gid) = ids();
        let root = tmp.path().join("browser-root");
        let err = ensure_runtime_root_with(
            &root,
            uid.wrapping_add(1),
            gid.wrapping_add(1),
            tmp.path(),
            &tmp.path().join("default"),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("hand the new runtime root"),
            "{err}"
        );
        assert!(!root.exists());
    }

    /// The launch itself: a missing root is created, so the launch no longer fails with "invalid
    /// runtime root".
    #[test]
    fn test_launch_creates_a_missing_runtime_root() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = test_config(tmp.path());
        let root = tmp.path().join("fresh-root");
        config.runtime_root = root.clone();
        let mut mgr = BrowserProcessManager::new(test_clock());
        let result = mgr.launch(&config, test_profile_id());
        assert!(
            !matches!(result, Err(LaunchError::RuntimeRootInvalid(_))),
            "{result:?}"
        );
        assert_eq!(mode_of(&root), 0o700);
        mgr.terminate_all();
    }

    #[test]
    fn test_create_lease_dir_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let root = setup_runtime_root(dir.path());
        let target = root.join("lease-test");
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        create_lease_dir(&target, RUNTIME_DIR_MODE, uid, gid).unwrap();
        let meta = fs::symlink_metadata(&target).unwrap();
        assert!(meta.is_dir());
        assert_eq!(meta.permissions().mode() & 0o777, RUNTIME_DIR_MODE);
        assert_eq!(meta.uid(), uid);
        assert_eq!(meta.gid(), gid);
        assert!(create_lease_dir(&target, RUNTIME_DIR_MODE, uid, gid).is_err());
    }

    #[test]
    fn test_fingerprint_path() {
        let dir = tempfile::tempdir().unwrap();
        let fp = fingerprint_path(dir.path()).unwrap();
        assert_ne!(fp.inode, 0);
        assert_ne!(fp.dev, 0);
    }

    #[test]
    fn test_fingerprint_stable() {
        let dir = tempfile::tempdir().unwrap();
        let fp1 = fingerprint_path(dir.path()).unwrap();
        let fp2 = fingerprint_path(dir.path()).unwrap();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_differs_for_different_dirs() {
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();
        let fp1 = fingerprint_path(dir1.path()).unwrap();
        let fp2 = fingerprint_path(dir2.path()).unwrap();
        assert_ne!(fp1.inode, fp2.inode);
    }

    #[test]
    fn test_create_cdp_pipes() {
        let pipes = create_cdp_pipes().unwrap();
        assert!(pipes.daemon_to_browser_write >= 0);
        assert!(pipes.browser_from_daemon_read >= 0);
        assert!(pipes.daemon_from_browser_read >= 0);
        assert!(pipes.browser_to_daemon_write >= 0);
    }

    #[test]
    fn test_cdp_pipes_drop_closes_fds() {
        // Verify that CdpPipes can be created and dropped without panic.
        // Testing actual FD closure is racy in parallel test execution because
        // other threads may reuse the same FD numbers between drop() and verification.
        let pipes = create_cdp_pipes().unwrap();
        assert!(pipes.daemon_to_browser_write >= 0);
        assert!(pipes.browser_from_daemon_read >= 0);
        assert!(pipes.daemon_from_browser_read >= 0);
        assert!(pipes.browser_to_daemon_write >= 0);
        drop(pipes);
    }

    #[test]
    fn test_cdp_pipes_have_cloexec() {
        let pipes = create_cdp_pipes().unwrap();
        for fd in [
            pipes.daemon_to_browser_write,
            pipes.browser_from_daemon_read,
            pipes.daemon_from_browser_read,
            pipes.browser_to_daemon_write,
        ] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(flags >= 0);
            assert_ne!(flags & libc::FD_CLOEXEC, 0);
        }
    }

    #[test]
    fn test_parse_start_time_from_stat() {
        let stat = "1234 (comm) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";
        let result = parse_start_time_from_stat(stat);
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_start_time_from_stat_with_parens_in_comm() {
        let stat = "1234 (comm (with) parens) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";
        let result = parse_start_time_from_stat(stat);
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_start_time_invalid() {
        assert!(parse_start_time_from_stat("").is_none());
        assert!(parse_start_time_from_stat("garbage").is_none());
    }

    #[test]
    fn test_cgroup_matches_identical() {
        assert!(cgroup_matches(
            "0::/user.slice/user-1000.slice/session-1.scope",
            "0::/user.slice/user-1000.slice/session-1.scope"
        ));
    }

    #[test]
    fn test_cgroup_matches_same_scope() {
        let a = "0::/user.slice/session-1.scope";
        let b = "1:name=systemd:/user.slice/session-1.scope";
        assert!(cgroup_matches(a, b));
    }

    #[test]
    fn test_cgroup_matches_different_scope() {
        let a = "0::/user.slice/session-1.scope";
        let b = "0::/user.slice/session-2.scope";
        assert!(!cgroup_matches(a, b));
    }

    #[test]
    fn test_cgroup_matches_empty_rejected() {
        assert!(!cgroup_matches("", ""));
        assert!(!cgroup_matches("0::/scope", ""));
        assert!(!cgroup_matches("", "0::/scope"));
    }

    #[test]
    fn test_extract_scope() {
        assert_eq!(
            extract_scope("0::/user.slice/session-1.scope"),
            Some("session-1.scope")
        );
        assert_eq!(extract_scope("no-scope-here"), None);
    }

    #[test]
    fn test_process_identity_is_valid() {
        let valid = ProcessIdentity {
            pid: 1,
            start_time_ticks: 100,
            cgroup: "0::/scope".to_string(),
        };
        assert!(valid.is_valid());

        let no_start = ProcessIdentity {
            pid: 1,
            start_time_ticks: 0,
            cgroup: "0::/scope".to_string(),
        };
        assert!(!no_start.is_valid());

        let no_cgroup = ProcessIdentity {
            pid: 1,
            start_time_ticks: 100,
            cgroup: String::new(),
        };
        assert!(!no_cgroup.is_valid());

        let empty_cgroup = ProcessIdentity {
            pid: 1,
            start_time_ticks: 100,
            cgroup: "  \n  ".to_string(),
        };
        assert!(!empty_cgroup.is_valid());
    }

    #[test]
    fn test_verify_path_safety_clean() {
        let dir = tempfile::tempdir().unwrap();
        let fp = fingerprint_path(dir.path()).unwrap();
        let result = verify_path_safety(dir.path(), &fp);
        assert!(matches!(result, CleanupSafety::Clean));
    }

    #[test]
    fn test_verify_path_safety_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        unix_fs::symlink(&real, &link).unwrap();
        let fp = ProfileFingerprint {
            inode: 99999,
            dev: 99999,
        };
        let result = verify_path_safety(&link, &fp);
        assert!(matches!(result, CleanupSafety::Quarantined { .. }));
    }

    #[test]
    fn test_verify_path_safety_inode_mismatch() {
        let dir1 = tempfile::tempdir().unwrap();
        let dir2 = tempfile::tempdir().unwrap();
        let fp_wrong = fingerprint_path(dir2.path()).unwrap();
        let result = verify_path_safety(dir1.path(), &fp_wrong);
        assert!(matches!(result, CleanupSafety::Quarantined { .. }));
    }

    #[test]
    fn test_verify_path_safety_nonexistent_is_clean() {
        let fp = ProfileFingerprint { inode: 1, dev: 1 };
        let result = verify_path_safety(Path::new("/nonexistent/path/xyz"), &fp);
        assert!(matches!(result, CleanupSafety::Clean));
    }

    #[test]
    fn test_quarantine_path_format() {
        let name = generate_quarantine_name("lease-abc");
        assert!(name.starts_with(QUARANTINE_PREFIX));
        assert!(name.contains("lease-abc"));
    }

    #[test]
    fn test_quarantine_path_unique() {
        let n1 = generate_quarantine_name("lease-abc");
        let n2 = generate_quarantine_name("lease-abc");
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_manifest_serialization_roundtrip() {
        let manifest = BrowserManifest {
            lease_id: "abc123".to_string(),
            profile_id: "prof1".to_string(),
            pid: 12345,
            pgid: 12345,
            process_identity: ProcessIdentity {
                pid: 12345,
                start_time_ticks: 100,
                cgroup: "0::/session-1.scope".to_string(),
            },
            profile_fingerprint: ProfileFingerprint {
                inode: 1000,
                dev: 2000,
            },
            runtime_dir: PathBuf::from("/tmp/runtime"),
            profile_dir: PathBuf::from("/tmp/runtime/profile"),
            created_monotonic_secs: 42,
            ttl_monotonic_secs: 300,
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: BrowserManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.pid, 12345);
        assert_eq!(parsed.pgid, 12345);
        assert_eq!(parsed.profile_fingerprint.inode, 1000);
        assert_eq!(parsed.process_identity.start_time_ticks, 100);
    }

    #[test]
    fn test_process_identity_equality() {
        let a = ProcessIdentity {
            pid: 100,
            start_time_ticks: 50,
            cgroup: "0::/scope".to_string(),
        };
        let b = ProcessIdentity {
            pid: 100,
            start_time_ticks: 50,
            cgroup: "0::/scope".to_string(),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn test_process_identity_inequality() {
        let a = ProcessIdentity {
            pid: 100,
            start_time_ticks: 50,
            cgroup: "0::/scope".to_string(),
        };
        let b = ProcessIdentity {
            pid: 100,
            start_time_ticks: 51,
            cgroup: "0::/scope".to_string(),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn test_manager_launch_creates_dirs_and_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();

        let snap = mgr.snapshot(&lease_id).unwrap();
        assert_eq!(snap.state, LeaseState::Active);
        assert!(snap.pid > 0);

        let lease = &mgr.leases[&lease_id];
        let manifest_path = lease.manifest.runtime_dir.join(MANIFEST_FILENAME);
        assert!(manifest_path.exists());

        let manifest_content = fs::read_to_string(&manifest_path).unwrap();
        let parsed: BrowserManifest = serde_json::from_str(&manifest_content).unwrap();
        assert_eq!(parsed.pid, snap.pid);
        assert_eq!(parsed.pgid, snap.pid);
    }

    #[test]
    fn test_manager_revoke_active() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        let result = mgr.revoke(&lease_id).unwrap();
        assert_eq!(result, LeaseState::Revoked);
        assert_eq!(mgr.snapshot(&lease_id).unwrap().state, LeaseState::Revoked);
    }

    #[test]
    fn test_manager_cannot_revoke_revoked() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        mgr.revoke(&lease_id).unwrap();
        let result = mgr.revoke(&lease_id);
        assert!(matches!(
            result,
            Err(TransitionError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn test_manager_principal_exit() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        let result = mgr.principal_exit(&lease_id).unwrap();
        assert_eq!(result, LeaseState::PrincipalExit);
    }

    #[test]
    fn test_manager_daemon_shutdown_from_active() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        let result = mgr.daemon_shutdown(&lease_id).unwrap();
        assert_eq!(result, LeaseState::DaemonShutdown);
    }

    #[test]
    fn test_manager_daemon_shutdown_from_revoked() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        mgr.revoke(&lease_id).unwrap();
        let result = mgr.daemon_shutdown(&lease_id).unwrap();
        assert_eq!(result, LeaseState::DaemonShutdown);
    }

    #[test]
    fn test_manager_browser_exit() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        let result = mgr.mark_browser_exit(&lease_id).unwrap();
        assert_eq!(result, LeaseState::BrowserExit);
    }

    #[test]
    fn test_manager_transition_not_found() {
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let fake_id = BrowserLeaseId::new();
        let result = mgr.revoke(&fake_id);
        assert!(matches!(result, Err(TransitionError::NotFound)));
    }

    #[test]
    fn test_manager_terminate_active_lease() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(Arc::clone(&clock) as Arc<dyn Clock>);
        let config = test_config(dir.path());

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        let result = mgr.terminate(&lease_id).unwrap();
        assert!(result.elapsed < Duration::from_secs(30));
    }

    #[test]
    fn test_manager_terminate_already_terminated() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        mgr.terminate(&lease_id).unwrap();
        let result = mgr.terminate(&lease_id).unwrap();
        assert!(result.exit_status.is_none());
        assert!(!result.sigkill_sent);
    }

    #[test]
    fn test_manager_cleanup_after_terminate() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        let runtime_dir = mgr.leases[&lease_id].manifest.runtime_dir.clone();
        assert!(runtime_dir.exists());

        mgr.terminate(&lease_id).unwrap();
        let safety = mgr.cleanup(&lease_id).unwrap();
        assert!(matches!(safety, CleanupSafety::Clean));
        assert!(!runtime_dir.exists());
    }

    #[test]
    fn test_manager_cleanup_detects_symlink_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        let profile_dir = mgr.leases[&lease_id].manifest.profile_dir.clone();
        let runtime_dir = mgr.leases[&lease_id].manifest.runtime_dir.clone();

        mgr.terminate(&lease_id).unwrap();

        let _ = fs::remove_dir_all(&profile_dir);
        let real_elsewhere = dir.path().join("elsewhere");
        fs::create_dir(&real_elsewhere).unwrap();
        unix_fs::symlink(&real_elsewhere, &profile_dir).unwrap();

        let safety = mgr.cleanup(&lease_id).unwrap();
        assert!(matches!(safety, CleanupSafety::Quarantined { .. }));
        assert!(!runtime_dir.exists());
    }

    #[test]
    fn test_manager_cleanup_detects_inode_change() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        let profile_dir = mgr.leases[&lease_id].manifest.profile_dir.clone();

        mgr.terminate(&lease_id).unwrap();

        let _ = fs::remove_dir_all(&profile_dir);
        fs::create_dir(&profile_dir).unwrap();

        let safety = mgr.cleanup(&lease_id).unwrap();
        assert!(matches!(safety, CleanupSafety::Quarantined { .. }));
    }

    #[test]
    fn test_manager_check_expired() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(Arc::clone(&clock) as Arc<dyn Clock>);
        let mut config = test_config(dir.path());
        config.ttl = Duration::from_secs(10);

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        assert_eq!(mgr.active_count(), 1);

        clock.advance(Duration::from_secs(11));
        let expired = mgr.check_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], lease_id);
        assert_eq!(mgr.active_count(), 0);
        assert_eq!(mgr.snapshot(&lease_id).unwrap().state, LeaseState::Revoked);
    }

    #[test]
    fn test_manager_check_expired_does_not_affect_non_active() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(Arc::clone(&clock) as Arc<dyn Clock>);
        let mut config = test_config(dir.path());
        config.ttl = Duration::from_secs(10);

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        mgr.revoke(&lease_id).unwrap();

        clock.advance(Duration::from_secs(11));
        let expired = mgr.check_expired();
        assert!(expired.is_empty());
        assert_eq!(mgr.snapshot(&lease_id).unwrap().state, LeaseState::Revoked);
    }

    #[test]
    fn test_manager_ttl_remaining_decreases() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(Arc::clone(&clock) as Arc<dyn Clock>);
        let mut config = test_config(dir.path());
        config.ttl = Duration::from_secs(100);

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        let remaining1 = mgr.snapshot(&lease_id).unwrap().ttl_remaining_secs;

        clock.advance(Duration::from_secs(30));
        let remaining2 = mgr.snapshot(&lease_id).unwrap().ttl_remaining_secs;
        assert!(remaining2 < remaining1);
    }

    #[test]
    fn test_manager_list_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let _id1 = mgr.launch(&config, test_profile_id()).unwrap();
        let _id2 = mgr.launch(&config, test_profile_id()).unwrap();
        assert_eq!(mgr.list_snapshots().len(), 2);
    }

    #[test]
    fn test_find_live_lease_for_profile_returns_active_lease() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let spawner: Arc<dyn ChildSpawner> = Arc::new(DirectExecSpawner);
        let mut mgr = BrowserProcessManager::with_spawner(clock, spawner);
        let mut config = test_config(dir.path());
        config.executable = std::path::PathBuf::from("/bin/sleep");
        config.extra_args = vec!["60".to_string()];

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();

        let snapshot = mgr.find_live_lease_for_profile(&test_profile_id());
        assert!(snapshot.is_some());
        let snapshot = snapshot.unwrap();
        assert_eq!(snapshot.id, lease_id);
        assert_eq!(snapshot.profile_id, test_profile_id());
        assert!(matches!(
            snapshot.state,
            LeaseState::Active | LeaseState::AuthenticationPending
        ));

        mgr.terminate(&lease_id).ok();
        mgr.cleanup(&lease_id).ok();
    }

    #[test]
    fn test_find_live_lease_for_profile_returns_none_for_different_profile() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let spawner: Arc<dyn ChildSpawner> = Arc::new(DirectExecSpawner);
        let mut mgr = BrowserProcessManager::with_spawner(clock, spawner);
        let mut config = test_config(dir.path());
        config.executable = std::path::PathBuf::from("/bin/sleep");
        config.extra_args = vec!["60".to_string()];

        let _lease_id = mgr.launch(&config, test_profile_id()).unwrap();

        let other_profile = ProfileId::new("other-profile").unwrap();
        let snapshot = mgr.find_live_lease_for_profile(&other_profile);
        assert!(snapshot.is_none());

        mgr.terminate(&_lease_id).ok();
        mgr.cleanup(&_lease_id).ok();
    }

    #[test]
    fn test_find_live_lease_for_profile_skips_terminal_leases() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        mgr.revoke(&lease_id).unwrap();

        let snapshot = mgr.find_live_lease_for_profile(&test_profile_id());
        assert!(snapshot.is_none());
    }

    #[test]
    fn test_find_live_lease_for_profile_skips_exited_child() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let mut config = test_config(dir.path());
        config.executable = std::path::PathBuf::from("/bin/true");
        config.start_url = None;
        config.extra_args = vec![];

        let _lease_id = mgr.launch(&config, test_profile_id()).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(100));

        let snapshot = mgr.find_live_lease_for_profile(&test_profile_id());
        assert!(snapshot.is_none());
    }

    #[test]
    fn test_find_live_lease_for_profile_reuses_sleeping_child() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let spawner: Arc<dyn ChildSpawner> = Arc::new(DirectExecSpawner);
        let mut mgr = BrowserProcessManager::with_spawner(clock, spawner);
        let mut config = test_config(dir.path());
        config.executable = std::path::PathBuf::from("/bin/sleep");
        config.start_url = None;
        config.extra_args = vec!["60".to_string()];

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();

        let snapshot = mgr.find_live_lease_for_profile(&test_profile_id());
        assert!(snapshot.is_some());
        assert_eq!(snapshot.unwrap().id, lease_id);

        mgr.terminate(&lease_id).ok();
        mgr.cleanup(&lease_id).ok();
    }

    #[test]
    fn test_idempotent_launch_reuses_existing_lease() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let spawner: Arc<dyn ChildSpawner> = Arc::new(DirectExecSpawner);
        let mut mgr = BrowserProcessManager::with_spawner(clock, spawner);
        let mut config = test_config(dir.path());
        config.executable = std::path::PathBuf::from("/bin/sleep");
        config.start_url = Some("https://example.com".to_string());
        config.extra_args = vec!["60".to_string()];

        let first_lease_id = mgr.launch(&config, test_profile_id()).unwrap();

        let first_snapshot = mgr.find_live_lease_for_profile(&test_profile_id());
        assert!(first_snapshot.is_some());
        let first_snapshot = first_snapshot.unwrap();
        assert_eq!(first_snapshot.id, first_lease_id);
        assert_eq!(
            first_snapshot.start_url,
            Some("https://example.com".to_string())
        );

        let second_snapshot = mgr.find_live_lease_for_profile(&test_profile_id());
        assert!(second_snapshot.is_some());
        let second_snapshot = second_snapshot.unwrap();
        assert_eq!(second_snapshot.id, first_lease_id);
        assert_eq!(second_snapshot.pid, first_snapshot.pid);

        assert_eq!(mgr.lease_count(), 1);

        mgr.terminate(&first_lease_id).ok();
        mgr.cleanup(&first_lease_id).ok();
    }

    #[test]
    fn test_manager_remove() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        assert_eq!(mgr.lease_count(), 1);
        let removed = mgr.remove(&lease_id);
        assert!(removed.is_some());
        assert_eq!(mgr.lease_count(), 0);
    }

    #[test]
    fn test_manager_remove_nonexistent() {
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let fake_id = BrowserLeaseId::new();
        assert!(mgr.remove(&fake_id).is_none());
    }

    #[test]
    fn test_manager_restart_recovery_kill_identity_match() {
        let clock = test_clock();
        let mgr = BrowserProcessManager::new(clock);

        let mut child = Command::new("sleep").arg("60").spawn().unwrap();
        let child_pid = child.id();

        let identity = read_process_identity(child_pid).unwrap();
        assert!(identity.is_valid());

        let result = mgr.restart_recovery_kill(child_pid, &identity);
        assert!(result);

        let _ = child.wait();
    }

    #[test]
    fn test_manager_restart_recovery_kill_pid_mismatch() {
        let clock = test_clock();
        let mgr = BrowserProcessManager::new(clock);

        let fake_identity = ProcessIdentity {
            pid: 99999,
            start_time_ticks: 0,
            cgroup: String::new(),
        };

        let result = mgr.restart_recovery_kill(1, &fake_identity);
        assert!(!result);
    }

    #[test]
    fn test_manager_restart_recovery_kill_start_time_mismatch() {
        let clock = test_clock();
        let mgr = BrowserProcessManager::new(clock);

        let mut child = Command::new("sleep").arg("60").spawn().unwrap();
        let child_pid = child.id();

        let mut identity = read_process_identity(child_pid).unwrap();
        identity.start_time_ticks = identity.start_time_ticks.wrapping_add(1);

        let result = mgr.restart_recovery_kill(child_pid, &identity);
        assert!(!result);

        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn test_manager_restart_recovery_kill_nonexistent_pid() {
        let clock = test_clock();
        let mgr = BrowserProcessManager::new(clock);

        let fake_identity = ProcessIdentity {
            pid: 999999,
            start_time_ticks: 0,
            cgroup: String::new(),
        };

        let result = mgr.restart_recovery_kill(999999, &fake_identity);
        assert!(!result);
    }

    #[test]
    fn test_manager_restart_recovery_rejects_empty_identity() {
        let clock = test_clock();
        let mgr = BrowserProcessManager::new(clock);

        let empty_identity = ProcessIdentity {
            pid: 1,
            start_time_ticks: 0,
            cgroup: String::new(),
        };
        assert!(!mgr.restart_recovery_kill(1, &empty_identity));

        let empty_cgroup = ProcessIdentity {
            pid: 1,
            start_time_ticks: 100,
            cgroup: String::new(),
        };
        assert!(!mgr.restart_recovery_kill(1, &empty_cgroup));
    }

    #[test]
    fn test_launch_error_display() {
        let e = LaunchError::InvalidStartUrl("bad".to_string());
        assert!(e.to_string().contains("bad"));

        let e = LaunchError::DirCreationFailed(
            "/tmp/x".to_string(),
            io::Error::from_raw_os_error(13).to_string(),
        );
        assert!(e.to_string().contains("/tmp/x"));

        let e = LaunchError::RuntimeRootInvalid("bad root".to_string());
        assert!(e.to_string().contains("bad root"));

        let e = LaunchError::BrowserExitedBeforeCdp("exit status: 1".to_string());
        assert!(e.to_string().contains("exited before CDP"));
        assert!(e.to_string().contains("exit status: 1"));
    }

    #[test]
    fn test_transition_error_display() {
        let e = TransitionError::InvalidTransition {
            from: LeaseState::Active,
            to: LeaseState::Active,
        };
        assert!(e.to_string().contains("invalid"));

        let e = TransitionError::NotFound;
        assert!(e.to_string().contains("not found"));
    }

    #[test]
    fn test_concurrent_launch_and_revoke() {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(MockClock::new());
        let mgr = Arc::new(Mutex::new(BrowserProcessManager::new(
            Arc::clone(&clock) as Arc<dyn Clock>
        )));
        let config = test_config(dir.path());

        let mut handles = Vec::new();
        for _ in 0..5 {
            let m = Arc::clone(&mgr);
            let c = config.clone();
            handles.push(std::thread::spawn(move || {
                let mut mgr = m.lock().unwrap();
                mgr.launch(&c, test_profile_id())
            }));
        }

        let mut lease_ids = Vec::new();
        for h in handles {
            let result = h.join().unwrap();
            if let Ok(id) = result {
                lease_ids.push(id);
            }
        }

        assert_eq!(lease_ids.len(), 5);

        let mut revoke_handles = Vec::new();
        for id in lease_ids {
            let m = Arc::clone(&mgr);
            revoke_handles.push(std::thread::spawn(move || {
                let mut mgr = m.lock().unwrap();
                mgr.revoke(&id)
            }));
        }

        for h in revoke_handles {
            let result = h.join().unwrap();
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_race_terminate_and_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        assert!(mgr.terminate(&lease_id).is_ok());
        assert!(mgr.cleanup(&lease_id).is_ok());
    }

    #[test]
    fn test_race_multiple_revokes() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        assert!(mgr.revoke(&lease_id).is_ok());
        let second = mgr.revoke(&lease_id);
        assert!(matches!(
            second,
            Err(TransitionError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn test_race_expire_and_manual_revoke() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(Arc::clone(&clock) as Arc<dyn Clock>);
        let mut config = test_config(dir.path());
        config.ttl = Duration::from_secs(5);

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();

        clock.advance(Duration::from_secs(6));
        let expired = mgr.check_expired();
        assert_eq!(expired.len(), 1);

        let result = mgr.revoke(&lease_id);
        assert!(matches!(
            result,
            Err(TransitionError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn test_full_lifecycle_launch_revoke_terminate_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        assert_eq!(mgr.snapshot(&lease_id).unwrap().state, LeaseState::Active);

        mgr.revoke(&lease_id).unwrap();
        assert_eq!(mgr.snapshot(&lease_id).unwrap().state, LeaseState::Revoked);

        mgr.terminate(&lease_id).unwrap();
        let safety = mgr.cleanup(&lease_id).unwrap();
        assert!(matches!(safety, CleanupSafety::Clean));

        mgr.remove(&lease_id);
        assert!(mgr.snapshot(&lease_id).is_none());
    }

    #[test]
    fn test_full_lifecycle_browser_exit_then_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        mgr.mark_browser_exit(&lease_id).unwrap();
        assert_eq!(
            mgr.snapshot(&lease_id).unwrap().state,
            LeaseState::BrowserExit
        );

        mgr.terminate(&lease_id).unwrap();
        let safety = mgr.cleanup(&lease_id).unwrap();
        assert!(matches!(safety, CleanupSafety::Clean));
    }

    #[test]
    fn test_full_lifecycle_principal_exit_daemon_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        mgr.principal_exit(&lease_id).unwrap();
        assert_eq!(
            mgr.snapshot(&lease_id).unwrap().state,
            LeaseState::PrincipalExit
        );

        mgr.daemon_shutdown(&lease_id).unwrap();
        assert_eq!(
            mgr.snapshot(&lease_id).unwrap().state,
            LeaseState::DaemonShutdown
        );
    }

    #[test]
    fn test_launch_invalid_start_url() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let mut config = test_config(dir.path());
        config.start_url = Some("http://insecure.example.com".to_string());

        let result = mgr.launch(&config, test_profile_id());
        assert!(matches!(result, Err(LaunchError::InvalidStartUrl(_))));
    }

    #[test]
    fn test_launch_with_start_url() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let mut config = test_config(dir.path());
        config.start_url = Some("https://example.com/dashboard".to_string());

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        assert_eq!(mgr.snapshot(&lease_id).unwrap().state, LeaseState::Active);
    }

    #[test]
    fn test_launch_start_url_no_rp_match() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let mut config = test_config(dir.path());
        config.rp_ids = vec!["other.com".to_string()];
        config.start_url_rules = start_url_test_rules(&[("other.com", RuleAction::Allow)]);
        config.start_url = Some("https://example.com/dashboard".to_string());

        let result = mgr.launch(&config, test_profile_id());
        assert!(matches!(result, Err(LaunchError::InvalidStartUrl(_))));
    }

    #[test]
    fn test_active_count_and_lease_count() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        assert_eq!(mgr.lease_count(), 0);
        assert_eq!(mgr.active_count(), 0);

        let id1 = mgr.launch(&config, test_profile_id()).unwrap();
        let id2 = mgr.launch(&config, test_profile_id()).unwrap();

        assert_eq!(mgr.lease_count(), 2);
        assert_eq!(mgr.active_count(), 2);

        mgr.revoke(&id1).unwrap();
        assert_eq!(mgr.lease_count(), 2);
        assert_eq!(mgr.active_count(), 1);

        mgr.remove(&id2);
        assert_eq!(mgr.lease_count(), 1);
        assert_eq!(mgr.active_count(), 0);

        let _ = id1;
    }

    #[test]
    fn test_with_custom_timeouts() {
        let clock = test_clock();
        let mgr = BrowserProcessManager::with_timeouts(
            clock,
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        assert_eq!(mgr.sigterm_timeout, Duration::from_secs(1));
        assert_eq!(mgr.sigkill_timeout, Duration::from_secs(1));
    }

    #[test]
    fn test_decode_wait_status() {
        let status = decode_wait_status(0);
        assert!(status.is_some());
        assert!(status.unwrap().success());
    }

    #[test]
    fn test_profile_fingerprint_serde() {
        let fp = ProfileFingerprint { inode: 42, dev: 7 };
        let json = serde_json::to_string(&fp).unwrap();
        let parsed: ProfileFingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(fp, parsed);
    }

    #[test]
    fn test_process_identity_serde() {
        let pi = ProcessIdentity {
            pid: 1234,
            start_time_ticks: 5678,
            cgroup: "0::/scope".to_string(),
        };
        let json = serde_json::to_string(&pi).unwrap();
        let parsed: ProcessIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(pi, parsed);
    }

    #[test]
    fn test_long_lived_child_stays_alive() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let spawner: Arc<dyn ChildSpawner> = Arc::new(DirectExecSpawner);
        let mut mgr = BrowserProcessManager::with_spawner(clock, spawner);
        let mut config = test_config(dir.path());
        config.executable = PathBuf::from("/bin/sleep");
        config.extra_args = vec!["60".to_string()];

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        let pid = mgr.leases[&lease_id].manifest.pid;

        std::thread::sleep(Duration::from_millis(200));

        let stat_path = format!("/proc/{}/stat", pid);
        assert!(
            Path::new(&stat_path).exists(),
            "child pid {} should still be alive",
            pid
        );

        mgr.terminate(&lease_id).unwrap();
    }

    #[test]
    fn test_child_in_separate_process_group() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let spawner: Arc<dyn ChildSpawner> = Arc::new(DirectExecSpawner);
        let mut mgr = BrowserProcessManager::with_spawner(clock, spawner);
        let mut config = test_config(dir.path());
        config.executable = PathBuf::from("/bin/sleep");
        config.extra_args = vec!["60".to_string()];

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        let pid = mgr.leases[&lease_id].manifest.pid;

        // Give the process a moment to fully initialize
        std::thread::sleep(std::time::Duration::from_millis(50));

        let stat_path = format!("/proc/{}/stat", pid);
        let stat_content =
            fs::read_to_string(&stat_path).expect("should be able to read /proc/{pid}/stat");
        let close_paren = stat_content
            .rfind(')')
            .expect("stat should contain comm in parens");
        let after_comm = &stat_content[close_paren + 2..];
        let fields: Vec<&str> = after_comm.split_whitespace().collect();

        // fields[0] = state, fields[1] = ppid, fields[2] = pgrp
        assert!(
            fields.len() > 2,
            "stat should have at least 3 fields after comm, got {}",
            fields.len()
        );

        let child_pgid: u32 = fields[2].parse().expect("pgrp field should be a valid u32");

        assert_eq!(
            child_pgid, pid,
            "child pgid should equal child pid (setsid)"
        );

        let my_pgid = unsafe { libc::getpgid(0) };
        assert_ne!(
            child_pgid as i32, my_pgid,
            "child should be in different process group"
        );

        mgr.terminate(&lease_id).unwrap();
    }

    #[test]
    fn test_no_fd_leakage_to_child() {
        // Verify that CdpPipes can be created and dropped without leaking FDs.
        // Testing actual FD closure is racy in parallel test execution because
        // other threads may reuse the same FD numbers between drop() and verification.
        let pipes_before = create_cdp_pipes().unwrap();
        assert!(pipes_before.daemon_to_browser_write >= 0);
        assert!(pipes_before.daemon_from_browser_read >= 0);
        drop(pipes_before);

        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let spawner: Arc<dyn ChildSpawner> = Arc::new(DirectExecSpawner);
        let mut mgr = BrowserProcessManager::with_spawner(clock, spawner);
        let mut config = test_config(dir.path());
        config.executable = PathBuf::from("/bin/sleep");
        config.extra_args = vec!["5".to_string()];

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();

        let lease = &mgr.leases[&lease_id];
        let cdp = lease.cdp.as_ref().unwrap();
        let daemon_write_fd = {
            use std::os::unix::io::AsRawFd;
            cdp.to_browser.as_raw_fd()
        };
        let daemon_read_fd = {
            use std::os::unix::io::AsRawFd;
            cdp.from_browser.as_raw_fd()
        };

        let flags_w = unsafe { libc::fcntl(daemon_write_fd, libc::F_GETFD) };
        let flags_r = unsafe { libc::fcntl(daemon_read_fd, libc::F_GETFD) };
        assert!(flags_w >= 0, "daemon write fd should be open");
        assert!(flags_r >= 0, "daemon read fd should be open");
        assert_ne!(
            flags_w & libc::FD_CLOEXEC,
            0,
            "daemon fds should have CLOEXEC"
        );

        let _ = mgr.terminate(&lease_id);
    }

    #[test]
    fn test_manifest_atomic_write() {
        let dir = tempfile::tempdir().unwrap();
        let root = setup_runtime_root(dir.path());
        let lease_dir = root.join("lease-test");
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        create_lease_dir(&lease_dir, RUNTIME_DIR_MODE, uid, gid).unwrap();

        let manifest = BrowserManifest {
            lease_id: "test".to_string(),
            profile_id: "prof".to_string(),
            pid: 42,
            pgid: 42,
            process_identity: ProcessIdentity {
                pid: 42,
                start_time_ticks: 100,
                cgroup: "0::/scope".to_string(),
            },
            profile_fingerprint: ProfileFingerprint { inode: 1, dev: 2 },
            runtime_dir: lease_dir.clone(),
            profile_dir: lease_dir.join("profile"),
            created_monotonic_secs: 0,
            ttl_monotonic_secs: 300,
        };

        write_manifest_atomic_at(&lease_dir, &manifest).unwrap();

        let manifest_path = lease_dir.join(MANIFEST_FILENAME);
        assert!(manifest_path.exists());

        let tmp_files: Vec<_> = fs::read_dir(&lease_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(&format!(".{}", MANIFEST_FILENAME))
            })
            .collect();
        assert!(tmp_files.is_empty(), "no temp files should remain");

        let content = fs::read_to_string(&manifest_path).unwrap();
        let parsed: BrowserManifest = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed.pid, 42);
    }

    #[test]
    fn test_pid_mismatch_cleanup_quarantines() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let spawner: Arc<dyn ChildSpawner> = Arc::new(DirectExecSpawner);
        let mut mgr = BrowserProcessManager::with_spawner(clock, spawner);
        let mut config = test_config(dir.path());
        config.executable = PathBuf::from("/bin/sleep");
        config.extra_args = vec!["60".to_string()];

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();

        std::thread::sleep(Duration::from_millis(100));

        let entry = mgr.leases.get_mut(&lease_id).unwrap();
        entry.manifest.process_identity.start_time_ticks = 999999999;

        let safety = mgr.cleanup(&lease_id).unwrap();
        assert!(
            matches!(
                safety,
                CleanupSafety::Quarantined { .. } | CleanupSafety::Failed { .. }
            ),
            "PID mismatch should quarantine or fail, got {:?}",
            safety
        );

        let quarantine_path = match safety {
            CleanupSafety::Quarantined {
                quarantine_path, ..
            } => Some(quarantine_path),
            _ => None,
        };
        if let Some(qp) = quarantine_path {
            let _ = fs::remove_dir_all(&qp);
        }

        let _ = mgr.terminate(&lease_id);
    }

    #[test]
    fn test_cleanup_runtime_dir_replaced_with_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        let runtime_dir = mgr.leases[&lease_id].manifest.runtime_dir.clone();
        let profile_dir = mgr.leases[&lease_id].manifest.profile_dir.clone();

        mgr.terminate(&lease_id).unwrap();

        let _ = fs::remove_dir_all(&runtime_dir);
        let target = dir.path().join("evil-target");
        fs::create_dir_all(&target).unwrap();
        unix_fs::symlink(&target, &runtime_dir).unwrap();

        let safety = mgr.cleanup(&lease_id).unwrap();
        assert!(
            matches!(
                safety,
                CleanupSafety::Quarantined { .. } | CleanupSafety::Failed { .. }
            ),
            "symlink replacement should quarantine or fail, got {:?}",
            safety
        );

        let _ = profile_dir;
    }

    #[test]
    fn test_launch_runtime_root_not_0700_fails() {
        let dir = tempfile::tempdir().unwrap();
        let bad_root = dir.path().join("bad-root");
        fs::create_dir_all(&bad_root).unwrap();
        let perms = fs::Permissions::from_mode(0o755);
        fs::set_permissions(&bad_root, perms).unwrap();

        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = BrowserConfig {
            executable: PathBuf::from("/bin/true"),
            start_url: None,
            extra_args: Vec::new(),
            runtime_root: bad_root,
            ttl: Duration::from_secs(300),
            login_timeout: DEFAULT_LOGIN_TIMEOUT,
            rp_ids: vec!["example.com".to_string()],
            start_url_rules: start_url_test_rules(&[("example.com", RuleAction::Allow)]),
            target_uid: 1001,
            target_gid: 1001,
            daemon_uid: 0,
            daemon_gid: 0,
            cdp_expose: CdpExposeMode::default(),
            cdp_port: 9222,
            bind_parent_death: true,
        };

        let result = mgr.launch(&config, test_profile_id());
        assert!(matches!(result, Err(LaunchError::RuntimeRootInvalid(_))));
    }

    #[test]
    fn test_launch_runtime_root_symlink_fails() {
        let dir = tempfile::tempdir().unwrap();
        let real_root = setup_runtime_root(dir.path());
        let link = dir.path().join("link-root");
        unix_fs::symlink(&real_root, &link).unwrap();

        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = BrowserConfig {
            executable: PathBuf::from("/bin/true"),
            start_url: None,
            extra_args: Vec::new(),
            runtime_root: link,
            ttl: Duration::from_secs(300),
            login_timeout: DEFAULT_LOGIN_TIMEOUT,
            rp_ids: vec!["example.com".to_string()],
            start_url_rules: start_url_test_rules(&[("example.com", RuleAction::Allow)]),
            target_uid: 1001,
            target_gid: 1001,
            daemon_uid: 0,
            daemon_gid: 0,
            cdp_expose: CdpExposeMode::default(),
            cdp_port: 9222,
            bind_parent_death: true,
        };

        let result = mgr.launch(&config, test_profile_id());
        assert!(matches!(result, Err(LaunchError::RuntimeRootInvalid(_))));
    }

    #[test]
    fn test_open_dir_fd_and_verify() {
        let dir = tempfile::tempdir().unwrap();
        let fd = open_dir_fd(dir.path()).unwrap();
        assert!(fd >= 0);
        assert!(verify_dir_fd_identity(fd, dir.path()));
        assert!(!verify_dir_fd_identity(fd, Path::new("/tmp")));
        unsafe { libc::close(fd) };
    }

    #[test]
    fn test_reverify_identity_self() {
        let pid = std::process::id();
        let identity = read_process_identity(pid);
        if let Some(id) = identity {
            assert!(id.is_valid());
            assert!(reverify_identity(pid, &id));
        }
    }

    #[test]
    fn test_reverify_identity_rejects_invalid_expected() {
        let invalid = ProcessIdentity {
            pid: 1,
            start_time_ticks: 0,
            cgroup: String::new(),
        };
        assert!(!reverify_identity(1, &invalid));
    }

    #[test]
    fn test_try_open_pidfd_self() {
        let pid = std::process::id();
        let pidfd = try_open_pidfd(pid);
        if let Some(fd) = pidfd {
            assert!(fd >= 0);
            unsafe { libc::close(fd) };
        }
    }

    #[test]
    fn test_signal_process_group_does_not_crash() {
        let mut child = Command::new("sleep")
            .arg("60")
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id();
        signal_process_group(pid, libc::SIGTERM);
        let _ = child.wait();
    }

    #[test]
    fn test_browser_hardening_non_root_fails_closed() {
        let my_uid = unsafe { libc::getuid() };
        if my_uid == 0 {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::with_spawner(clock, Arc::new(ProductionSpawner));
        let mut config = test_config(dir.path());
        config.daemon_uid = my_uid;
        config.daemon_gid = my_uid;
        config.target_uid = my_uid + 1;
        config.target_gid = my_uid + 1;

        let result = mgr.launch(&config, test_profile_id());
        assert!(matches!(result, Err(LaunchError::HardeningFailed(_))));
    }

    #[test]
    fn test_browser_hardening_same_uid_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::with_spawner(clock, Arc::new(ProductionSpawner));
        let mut config = test_config(dir.path());
        config.target_uid = 0;
        config.daemon_uid = 0;
        config.target_gid = 1001;
        config.daemon_gid = 0;

        let result = mgr.launch(&config, test_profile_id());
        assert!(matches!(
            result,
            Err(LaunchError::HardeningFailed(_)) | Err(LaunchError::RuntimeRootInvalid(_))
        ));
    }

    #[test]
    fn test_browser_config_hardening_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        let setup = config.hardening();
        assert_eq!(setup.target_uid, config.target_uid);
        assert_eq!(setup.target_gid, config.target_gid);
        assert_eq!(setup.daemon_uid, config.daemon_uid);
        assert_eq!(setup.daemon_gid, config.daemon_gid);
    }

    #[test]
    fn test_trusted_same_user_port_launch_detection() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = test_config(dir.path());
        config.cdp_expose = CdpExposeMode::Port;
        config.daemon_uid = 1000;
        config.daemon_gid = 1000;
        config.target_uid = 1000;
        config.target_gid = 1000;
        assert!(is_trusted_same_user_port_launch(&config));

        config.target_uid = 1001;
        assert!(!is_trusted_same_user_port_launch(&config));

        config.target_uid = 0;
        config.target_gid = 1000;
        config.daemon_uid = 0;
        assert!(!is_trusted_same_user_port_launch(&config));
    }

    #[test]
    fn test_browser_probe_protected_node_deterministic_policy() {
        use super::super::launcher::probe_protected_node_access;
        let result = probe_protected_node_access(Path::new("/dev/uhid"));
        match &result {
            ProbeResult::Allowed { path } => assert_eq!(path, "/dev/uhid"),
            ProbeResult::Denied { path, .. } => assert_eq!(path, "/dev/uhid"),
        }
    }

    #[test]
    fn test_fake_spawner_allows_launch_without_root() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::with_spawner(clock, Arc::new(FakeSpawner));
        let config = test_config(dir.path());

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        let snap = mgr.snapshot(&lease_id).unwrap();
        assert_eq!(snap.state, LeaseState::Active);
        assert!(snap.pid > 0);
    }

    #[test]
    fn test_launch_error_hardening_failed_display() {
        let e = LaunchError::HardeningFailed("not root".to_string());
        assert!(e.to_string().contains("hardening"));
        assert!(e.to_string().contains("not root"));
    }

    #[test]
    fn test_production_spawner_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ProductionSpawner>();
        assert_send_sync::<FakeSpawner>();
    }

    #[test]
    fn test_clamp_login_timeout_normal() {
        assert_eq!(
            clamp_login_timeout(Duration::from_secs(120)),
            Duration::from_secs(120)
        );
    }

    #[test]
    fn test_clamp_login_timeout_below_minimum() {
        assert_eq!(
            clamp_login_timeout(Duration::from_secs(1)),
            Duration::from_secs(MIN_LOGIN_TIMEOUT_SECS)
        );
    }

    #[test]
    fn test_clamp_login_timeout_above_maximum() {
        assert_eq!(
            clamp_login_timeout(Duration::from_secs(9999)),
            Duration::from_secs(MAX_LOGIN_TIMEOUT_SECS)
        );
    }

    #[test]
    fn test_activation_error_display() {
        let e = ActivationError::NotFound;
        assert!(e.to_string().contains("not found"));

        let e = ActivationError::NotPending {
            current: LeaseState::Active,
        };
        assert!(e.to_string().contains("not pending"));
        assert!(e.to_string().contains("active"));

        let e = ActivationError::LoginDeadlineExpired;
        assert!(e.to_string().contains("login deadline"));
    }

    #[test]
    fn test_launch_pending_creates_pending_lease() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch_pending(&config, test_profile_id()).unwrap();

        let snap = mgr.snapshot(&lease_id).unwrap();
        assert_eq!(snap.state, LeaseState::AuthenticationPending);
        assert!(snap.pid > 0);
        assert_eq!(mgr.pending_count(), 1);
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn test_launch_pending_creates_dirs_and_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch_pending(&config, test_profile_id()).unwrap();

        let snap = mgr.snapshot(&lease_id).unwrap();
        let lease = &mgr.leases[&lease_id];
        let manifest_path = lease.manifest.runtime_dir.join(MANIFEST_FILENAME);
        assert!(manifest_path.exists());

        let manifest_content = fs::read_to_string(&manifest_path).unwrap();
        let parsed: BrowserManifest = serde_json::from_str(&manifest_content).unwrap();
        assert_eq!(parsed.pid, snap.pid);
    }

    #[test]
    fn test_activate_after_assertion_transitions_to_active() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(Arc::clone(&clock) as Arc<dyn Clock>);
        let config = test_config(dir.path());

        let lease_id = mgr.launch_pending(&config, test_profile_id()).unwrap();
        assert_eq!(
            mgr.snapshot(&lease_id).unwrap().state,
            LeaseState::AuthenticationPending
        );

        let result = mgr
            .activate_after_assertion(&lease_id, Duration::from_secs(300))
            .unwrap();
        assert_eq!(result, LeaseState::Active);
        assert_eq!(mgr.snapshot(&lease_id).unwrap().state, LeaseState::Active);
        assert_eq!(mgr.pending_count(), 0);
        assert_eq!(mgr.active_count(), 1);
    }

    #[test]
    fn test_activate_after_assertion_sets_session_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(Arc::clone(&clock) as Arc<dyn Clock>);
        let config = test_config(dir.path());

        let lease_id = mgr.launch_pending(&config, test_profile_id()).unwrap();

        clock.advance(Duration::from_secs(10));
        let remaining_before = mgr.snapshot(&lease_id).unwrap().ttl_remaining_secs;

        mgr.activate_after_assertion(&lease_id, Duration::from_secs(300))
            .unwrap();

        let remaining_after = mgr.snapshot(&lease_id).unwrap().ttl_remaining_secs;
        assert!(remaining_after > remaining_before);
    }

    #[test]
    fn test_activate_not_found() {
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let fake_id = BrowserLeaseId::new();

        let result = mgr.activate_after_assertion(&fake_id, Duration::from_secs(300));
        assert!(matches!(result, Err(ActivationError::NotFound)));
    }

    #[test]
    fn test_activate_not_pending_active() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        assert_eq!(mgr.snapshot(&lease_id).unwrap().state, LeaseState::Active);

        let result = mgr.activate_after_assertion(&lease_id, Duration::from_secs(300));
        assert!(matches!(
            result,
            Err(ActivationError::NotPending {
                current: LeaseState::Active
            })
        ));
    }

    #[test]
    fn test_double_activation_denied() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch_pending(&config, test_profile_id()).unwrap();

        let first = mgr.activate_after_assertion(&lease_id, Duration::from_secs(300));
        assert!(first.is_ok());

        let second = mgr.activate_after_assertion(&lease_id, Duration::from_secs(300));
        assert!(matches!(
            second,
            Err(ActivationError::NotPending {
                current: LeaseState::Active
            })
        ));
    }

    #[test]
    fn test_activation_after_login_timeout_denied() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(Arc::clone(&clock) as Arc<dyn Clock>);
        let mut config = test_config(dir.path());
        config.login_timeout = Duration::from_secs(30);

        let lease_id = mgr.launch_pending(&config, test_profile_id()).unwrap();
        assert_eq!(
            mgr.snapshot(&lease_id).unwrap().state,
            LeaseState::AuthenticationPending
        );

        clock.advance(Duration::from_secs(31));

        let result = mgr.activate_after_assertion(&lease_id, Duration::from_secs(300));
        assert!(matches!(result, Err(ActivationError::LoginDeadlineExpired)));
    }

    #[test]
    fn test_login_timeout_expires_pending_lease() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(Arc::clone(&clock) as Arc<dyn Clock>);
        let mut config = test_config(dir.path());
        config.login_timeout = Duration::from_secs(15);

        let lease_id = mgr.launch_pending(&config, test_profile_id()).unwrap();
        assert_eq!(mgr.pending_count(), 1);

        clock.advance(Duration::from_secs(16));
        let expired = mgr.check_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], lease_id);
        assert_eq!(mgr.snapshot(&lease_id).unwrap().state, LeaseState::Revoked);
        assert_eq!(mgr.pending_count(), 0);
    }

    #[test]
    fn test_wall_jump_clock_advance_past_login_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(Arc::clone(&clock) as Arc<dyn Clock>);
        let mut config = test_config(dir.path());
        config.login_timeout = Duration::from_secs(60);

        let lease_id = mgr.launch_pending(&config, test_profile_id()).unwrap();

        clock.advance(Duration::from_secs(61));

        let result = mgr.activate_after_assertion(&lease_id, Duration::from_secs(300));
        assert!(matches!(result, Err(ActivationError::LoginDeadlineExpired)));

        let expired = mgr.check_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(mgr.snapshot(&lease_id).unwrap().state, LeaseState::Revoked);
    }

    #[test]
    fn test_activation_race_only_one_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(MockClock::new());
        let mgr = Arc::new(Mutex::new(BrowserProcessManager::new(
            Arc::clone(&clock) as Arc<dyn Clock>
        )));
        let config = test_config(dir.path());

        let lease_id = {
            let mut m = mgr.lock().unwrap();
            m.launch_pending(&config, test_profile_id()).unwrap()
        };

        let mut handles = Vec::new();
        for _ in 0..10 {
            let m = Arc::clone(&mgr);
            let lid = lease_id.clone();
            handles.push(std::thread::spawn(move || {
                let mut mgr = m.lock().unwrap();
                mgr.activate_after_assertion(&lid, Duration::from_secs(300))
            }));
        }

        let mut successes = 0;
        let mut failures = 0;
        for h in handles {
            match h.join().unwrap() {
                Ok(_) => successes += 1,
                Err(_) => failures += 1,
            }
        }

        assert_eq!(successes, 1);
        assert_eq!(failures, 9);
    }

    #[test]
    fn test_principal_cannot_extend_activated_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(Arc::clone(&clock) as Arc<dyn Clock>);
        let config = test_config(dir.path());

        let lease_id = mgr.launch_pending(&config, test_profile_id()).unwrap();
        mgr.activate_after_assertion(&lease_id, Duration::from_secs(60))
            .unwrap();

        let deadline_1 = mgr.leases[&lease_id].ttl_deadline;

        let result = mgr.activate_after_assertion(&lease_id, Duration::from_secs(600));
        assert!(result.is_err());

        let deadline_2 = mgr.leases[&lease_id].ttl_deadline;
        assert_eq!(deadline_1, deadline_2);
    }

    #[test]
    fn test_pending_lease_revoke_terminate_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch_pending(&config, test_profile_id()).unwrap();
        assert_eq!(
            mgr.snapshot(&lease_id).unwrap().state,
            LeaseState::AuthenticationPending
        );

        mgr.revoke(&lease_id).unwrap();
        assert_eq!(mgr.snapshot(&lease_id).unwrap().state, LeaseState::Revoked);

        mgr.terminate(&lease_id).unwrap();
        let safety = mgr.cleanup(&lease_id).unwrap();
        assert!(matches!(safety, CleanupSafety::Clean));
    }

    #[test]
    fn test_pending_lease_browser_exit() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch_pending(&config, test_profile_id()).unwrap();

        let result = mgr.mark_browser_exit(&lease_id).unwrap();
        assert_eq!(result, LeaseState::BrowserExit);
    }

    #[test]
    fn test_pending_lease_principal_exit() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch_pending(&config, test_profile_id()).unwrap();

        let result = mgr.principal_exit(&lease_id).unwrap();
        assert_eq!(result, LeaseState::PrincipalExit);
    }

    #[test]
    fn test_pending_lease_daemon_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch_pending(&config, test_profile_id()).unwrap();

        let result = mgr.daemon_shutdown(&lease_id).unwrap();
        assert_eq!(result, LeaseState::DaemonShutdown);
    }

    #[test]
    fn test_activation_after_revoke_fails() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch_pending(&config, test_profile_id()).unwrap();
        mgr.revoke(&lease_id).unwrap();

        let result = mgr.activate_after_assertion(&lease_id, Duration::from_secs(300));
        assert!(matches!(
            result,
            Err(ActivationError::NotPending {
                current: LeaseState::Revoked
            })
        ));
    }

    #[test]
    fn test_transport_failure_pending_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch_pending(&config, test_profile_id()).unwrap();
        let runtime_dir = mgr.leases[&lease_id].manifest.runtime_dir.clone();
        assert!(runtime_dir.exists());

        mgr.revoke(&lease_id).unwrap();
        mgr.terminate(&lease_id).unwrap();
        let safety = mgr.cleanup(&lease_id).unwrap();
        assert!(matches!(safety, CleanupSafety::Clean));
        assert!(!runtime_dir.exists());
    }

    #[test]
    fn test_launch_composes_pending_and_activate() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();

        let snap = mgr.snapshot(&lease_id).unwrap();
        assert_eq!(snap.state, LeaseState::Active);
        assert_eq!(mgr.pending_count(), 0);
        assert_eq!(mgr.active_count(), 1);
    }

    #[test]
    fn test_session_ttl_clamped_on_activation() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(Arc::clone(&clock) as Arc<dyn Clock>);
        let config = test_config(dir.path());

        let lease_id = mgr.launch_pending(&config, test_profile_id()).unwrap();

        mgr.activate_after_assertion(&lease_id, Duration::from_secs(0))
            .unwrap();

        let remaining = mgr.snapshot(&lease_id).unwrap().ttl_remaining_secs;
        assert!(remaining >= MIN_TTL_SECS);
    }

    #[test]
    fn test_session_ttl_max_clamped_on_activation() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(Arc::clone(&clock) as Arc<dyn Clock>);
        let config = test_config(dir.path());

        let lease_id = mgr.launch_pending(&config, test_profile_id()).unwrap();

        mgr.activate_after_assertion(&lease_id, Duration::from_secs(MAX_TTL_CLAMP_SECS + 9999))
            .unwrap();

        let remaining = mgr.snapshot(&lease_id).unwrap().ttl_remaining_secs;
        assert!(remaining <= MAX_TTL_CLAMP_SECS);
    }

    #[test]
    fn test_pending_does_not_count_as_active() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let id1 = mgr.launch_pending(&config, test_profile_id()).unwrap();
        let id2 = mgr.launch(&config, test_profile_id()).unwrap();

        assert_eq!(mgr.lease_count(), 2);
        assert_eq!(mgr.active_count(), 1);
        assert_eq!(mgr.pending_count(), 1);

        mgr.activate_after_assertion(&id1, Duration::from_secs(300))
            .unwrap();
        assert_eq!(mgr.active_count(), 2);
        assert_eq!(mgr.pending_count(), 0);

        let _ = id2;
    }

    #[test]
    fn test_activation_after_assertion_error_is_std_error() {
        fn assert_error<T: std::error::Error>() {}
        assert_error::<ActivationError>();
        assert_error::<TransitionError>();
        assert_error::<LaunchError>();
    }

    fn make_cdp_request(id: u64, method: &str) -> String {
        format!(r#"{{"id":{},"method":"{}"}}"#, id, method)
    }

    fn make_cdp_request_with_params(id: u64, method: &str, params: &str) -> String {
        format!(
            r#"{{"id":{},"method":"{}","params":{}}}"#,
            id, method, params
        )
    }

    fn make_cdp_response(id: u64, result: &str) -> String {
        format!(r#"{{"id":{},"result":{}}}"#, id, result)
    }

    fn make_cdp_event(method: &str, params: &str) -> String {
        format!(r#"{{"method":"{}","params":{}}}"#, method, params)
    }

    fn create_fake_cdp_pair() -> (fs::File, fs::File, fs::File, fs::File) {
        let mut to_browser_fds: [RawFd; 2] = [-1, -1];
        let mut from_browser_fds: [RawFd; 2] = [-1, -1];
        unsafe {
            libc::pipe2(to_browser_fds.as_mut_ptr(), 0);
            libc::pipe2(from_browser_fds.as_mut_ptr(), 0);
        }
        let daemon_write = unsafe { fs::File::from_raw_fd(to_browser_fds[1]) };
        let fake_browser_read = unsafe { fs::File::from_raw_fd(to_browser_fds[0]) };
        let daemon_read = unsafe { fs::File::from_raw_fd(from_browser_fds[0]) };
        let fake_browser_write = unsafe { fs::File::from_raw_fd(from_browser_fds[1]) };
        (
            daemon_write,
            daemon_read,
            fake_browser_read,
            fake_browser_write,
        )
    }

    fn inject_lease_with_fake_cdp(
        mgr: &mut BrowserProcessManager,
        daemon_write: fs::File,
        daemon_read: fs::File,
    ) -> BrowserLeaseId {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();

        let entry = mgr.leases.get_mut(&lease_id).unwrap();
        entry.cdp = Some(DaemonCdpEndpoints {
            to_browser: daemon_write,
            from_browser: daemon_read,
        });
        lease_id
    }

    #[test]
    fn test_validate_cdp_request_valid() {
        let req = make_cdp_request(1, "Page.navigate");
        assert!(validate_cdp_request(&req).is_ok());
    }

    #[test]
    fn test_validate_cdp_request_with_params() {
        let req =
            make_cdp_request_with_params(1, "Page.navigate", r#"{"url":"https://example.com"}"#);
        assert!(validate_cdp_request(&req).is_ok());
    }

    #[test]
    fn test_validate_cdp_request_with_session_id() {
        let req = r#"{"id":1,"method":"Page.navigate","sessionId":"abc123"}"#;
        assert!(validate_cdp_request(req).is_ok());
    }

    #[test]
    fn test_validate_cdp_request_rejects_non_object() {
        assert!(validate_cdp_request("[]").is_err());
        assert!(validate_cdp_request(r#""string""#).is_err());
        assert!(validate_cdp_request("42").is_err());
    }

    #[test]
    fn test_validate_cdp_request_rejects_missing_id() {
        let req = r#"{"method":"Page.navigate"}"#;
        let err = validate_cdp_request(req).unwrap_err();
        assert!(matches!(err, CdpError::InvalidRequest(_)));
    }

    #[test]
    fn test_validate_cdp_request_rejects_missing_method() {
        let req = r#"{"id":1}"#;
        let err = validate_cdp_request(req).unwrap_err();
        assert!(matches!(err, CdpError::InvalidRequest(_)));
    }

    #[test]
    fn test_validate_cdp_request_rejects_non_numeric_id() {
        let req = r#"{"id":"abc","method":"Page.navigate"}"#;
        assert!(validate_cdp_request(req).is_err());
    }

    #[test]
    fn test_validate_cdp_request_rejects_zero_id() {
        let req = r#"{"id":0,"method":"Page.navigate"}"#;
        assert!(validate_cdp_request(req).is_err());
    }

    #[test]
    fn test_validate_cdp_request_rejects_negative_id() {
        let req = r#"{"id":-1,"method":"Page.navigate"}"#;
        assert!(validate_cdp_request(req).is_err());
    }

    #[test]
    fn test_validate_cdp_request_rejects_float_id() {
        let req = r#"{"id":1.5,"method":"Page.navigate"}"#;
        assert!(validate_cdp_request(req).is_err());
    }

    #[test]
    fn test_validate_cdp_request_rejects_nul_byte() {
        let req = "{\"id\":1,\"method\":\"Page.nav\u{0}igate\"}";
        assert!(validate_cdp_request(req).is_err());
    }

    #[test]
    fn test_validate_cdp_request_rejects_oversized() {
        let big = "x".repeat(CDP_MAX_REQUEST_BYTES + 1);
        let req = format!(r#"{{"id":1,"method":"{}"}}"#, big);
        assert!(validate_cdp_request(&req).is_err());
    }

    #[test]
    fn test_validate_cdp_request_rejects_unknown_fields() {
        let req = r#"{"id":1,"method":"Page.navigate","extra":"bad"}"#;
        assert!(validate_cdp_request(req).is_err());
    }

    #[test]
    fn test_validate_cdp_request_rejects_non_object_params() {
        let req = r#"{"id":1,"method":"Page.navigate","params":"bad"}"#;
        assert!(validate_cdp_request(req).is_err());
    }

    #[test]
    fn test_validate_cdp_request_rejects_non_string_session_id() {
        let req = r#"{"id":1,"method":"Page.navigate","sessionId":42}"#;
        assert!(validate_cdp_request(req).is_err());
    }

    #[test]
    fn test_extract_cdp_id_valid() {
        let req = make_cdp_request(42, "Page.navigate");
        let id = extract_cdp_id(&req).unwrap();
        assert_eq!(id, serde_json::Number::from(42));
    }

    #[test]
    fn test_extract_cdp_id_invalid_json() {
        assert!(extract_cdp_id("not json").is_none());
    }

    #[test]
    fn test_cdp_message_has_id_match() {
        let resp = make_cdp_response(1, r#"{"frameId":"abc"}"#);
        let id = serde_json::Number::from(1);
        assert!(cdp_message_has_id(&resp, &id));
    }

    #[test]
    fn test_cdp_message_has_id_no_match() {
        let resp = make_cdp_response(2, r#"{}"#);
        let id = serde_json::Number::from(1);
        assert!(!cdp_message_has_id(&resp, &id));
    }

    #[test]
    fn test_cdp_message_has_id_event_no_id() {
        let event = make_cdp_event("Page.loadEventFired", "{}");
        let id = serde_json::Number::from(1);
        assert!(!cdp_message_has_id(&event, &id));
    }

    #[test]
    fn test_clamp_cdp_timeout_normal() {
        assert_eq!(
            clamp_cdp_timeout(Duration::from_secs(3)),
            Duration::from_secs(3)
        );
    }

    #[test]
    fn test_clamp_cdp_timeout_below_min() {
        assert_eq!(
            clamp_cdp_timeout(Duration::from_millis(10)),
            CDP_MIN_TIMEOUT
        );
    }

    #[test]
    fn test_clamp_cdp_timeout_above_max() {
        assert_eq!(clamp_cdp_timeout(Duration::from_secs(60)), CDP_MAX_TIMEOUT);
    }

    #[test]
    fn test_cdp_round_trip_not_found_lease() {
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let fake_id = BrowserLeaseId::new();
        let req = make_cdp_request(1, "Page.navigate");
        let result = mgr.cdp_round_trip(&fake_id, &req, Duration::from_secs(1));
        assert!(matches!(result, Err(CdpError::LeaseNotFound)));
    }

    #[test]
    fn test_cdp_round_trip_rejects_invalid_request() {
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let fake_id = BrowserLeaseId::new();
        let result = mgr.cdp_round_trip(&fake_id, "not json", Duration::from_secs(1));
        assert!(matches!(result, Err(CdpError::InvalidRequest(_))));
    }

    #[test]
    fn test_cdp_round_trip_terminal_state() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();
        mgr.revoke(&lease_id).unwrap();

        let req = make_cdp_request(1, "Page.navigate");
        let result = mgr.cdp_round_trip(&lease_id, &req, Duration::from_secs(1));
        assert!(matches!(result, Err(CdpError::BrowserExited)));
    }

    #[test]
    fn test_cdp_round_trip_basic_response() {
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);

        let (daemon_write, daemon_read, mut fake_browser_read, mut fake_browser_write) =
            create_fake_cdp_pair();

        let lease_id = inject_lease_with_fake_cdp(&mut mgr, daemon_write, daemon_read);

        let req = make_cdp_request(1, "Page.navigate");

        let responder = std::thread::spawn(move || {
            let mut read_buf = vec![0u8; 4096];
            let mut total = 0;
            loop {
                let n = fake_browser_read.read(&mut read_buf[total..]).unwrap();
                if n == 0 {
                    break;
                }
                total += n;
                if read_buf[..total].contains(&0) {
                    break;
                }
            }

            let response = make_cdp_response(1, r#"{"frameId":"abc"}"#);
            let mut frame = response.into_bytes();
            frame.push(0);
            fake_browser_write.write_all(&frame).unwrap();
            fake_browser_write.flush().unwrap();
        });

        let result = mgr.cdp_round_trip(&lease_id, &req, Duration::from_secs(5));
        responder.join().unwrap();

        assert!(result.is_ok());
        let cdp_result = result.unwrap();
        assert_eq!(cdp_result.messages.len(), 1);
        assert!(cdp_result.messages[0].contains(r#""id":1"#));
    }

    #[test]
    fn test_cdp_round_trip_events_before_response() {
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);

        let (daemon_write, daemon_read, mut fake_browser_read, mut fake_browser_write) =
            create_fake_cdp_pair();

        let lease_id = inject_lease_with_fake_cdp(&mut mgr, daemon_write, daemon_read);

        let req = make_cdp_request(1, "Page.navigate");

        let responder = std::thread::spawn(move || {
            let mut read_buf = vec![0u8; 4096];
            let mut total = 0;
            loop {
                let n = fake_browser_read.read(&mut read_buf[total..]).unwrap();
                if n == 0 {
                    break;
                }
                total += n;
                if read_buf[..total].contains(&0) {
                    break;
                }
            }

            let event1 = make_cdp_event("Page.frameStartedLoading", r#"{"frameId":"abc"}"#);
            let mut frame1 = event1.into_bytes();
            frame1.push(0);
            fake_browser_write.write_all(&frame1).unwrap();
            fake_browser_write.flush().unwrap();

            let event2 = make_cdp_event("Page.frameNavigated", r#"{"frame":{}}"#);
            let mut frame2 = event2.into_bytes();
            frame2.push(0);
            fake_browser_write.write_all(&frame2).unwrap();
            fake_browser_write.flush().unwrap();

            std::thread::sleep(Duration::from_millis(50));

            let response = make_cdp_response(1, r#"{"frameId":"abc"}"#);
            let mut frame3 = response.into_bytes();
            frame3.push(0);
            fake_browser_write.write_all(&frame3).unwrap();
            fake_browser_write.flush().unwrap();
        });

        let result = mgr.cdp_round_trip(&lease_id, &req, Duration::from_secs(5));
        responder.join().unwrap();

        assert!(result.is_ok());
        let cdp_result = result.unwrap();
        assert_eq!(cdp_result.messages.len(), 3);
        assert!(cdp_result.messages[0].contains("frameStartedLoading"));
        assert!(cdp_result.messages[1].contains("frameNavigated"));
        assert!(cdp_result.messages[2].contains(r#""id":1"#));
    }

    #[test]
    fn test_cdp_round_trip_timeout() {
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);

        let (daemon_write, daemon_read, _fake_browser_read, _fake_browser_write) =
            create_fake_cdp_pair();

        let lease_id = inject_lease_with_fake_cdp(&mut mgr, daemon_write, daemon_read);

        let req = make_cdp_request(1, "Page.navigate");

        let result = mgr.cdp_round_trip(&lease_id, &req, Duration::from_millis(200));
        assert!(matches!(result, Err(CdpError::Timeout)));
    }

    #[test]
    fn test_cdp_round_trip_eof_marks_browser_exit() {
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);

        let (daemon_write, daemon_read, _fake_browser_read, fake_browser_write) =
            create_fake_cdp_pair();

        let lease_id = inject_lease_with_fake_cdp(&mut mgr, daemon_write, daemon_read);

        drop(fake_browser_write);

        let req = make_cdp_request(1, "Page.navigate");
        let result = mgr.cdp_round_trip(&lease_id, &req, Duration::from_secs(2));
        assert!(matches!(result, Err(CdpError::BrowserExited)));
    }

    #[test]
    fn test_cdp_round_trip_buffered_messages_persist() {
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);

        let (daemon_write, daemon_read, mut fake_browser_read, mut fake_browser_write) =
            create_fake_cdp_pair();

        let lease_id = inject_lease_with_fake_cdp(&mut mgr, daemon_write, daemon_read);

        let event = make_cdp_event("Page.loadEventFired", "{}");
        let mut frame = event.into_bytes();
        frame.push(0);
        fake_browser_write.write_all(&frame).unwrap();
        fake_browser_write.flush().unwrap();

        std::thread::sleep(Duration::from_millis(50));

        let req = make_cdp_request(1, "Runtime.evaluate");

        let responder = std::thread::spawn(move || {
            let mut read_buf = vec![0u8; 4096];
            let mut total = 0;
            loop {
                let n = fake_browser_read.read(&mut read_buf[total..]).unwrap();
                if n == 0 {
                    break;
                }
                total += n;
                if read_buf[..total].contains(&0) {
                    break;
                }
            }

            let response = make_cdp_response(1, r#"{"result":{"type":"undefined"}}"#);
            let mut frame = response.into_bytes();
            frame.push(0);
            fake_browser_write.write_all(&frame).unwrap();
            fake_browser_write.flush().unwrap();
        });

        let result = mgr.cdp_round_trip(&lease_id, &req, Duration::from_secs(5));
        responder.join().unwrap();

        assert!(result.is_ok());
        let cdp_result = result.unwrap();
        assert_eq!(cdp_result.messages.len(), 2);
        assert!(cdp_result.messages[0].contains("loadEventFired"));
        assert!(cdp_result.messages[1].contains(r#""id":1"#));
    }

    /// Read `count` NUL-terminated frames the daemon wrote to the fake browser.
    fn read_frames(reader: &mut fs::File, count: usize) -> Vec<serde_json::Value> {
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 4096];
        while bytes.iter().filter(|&&b| b == 0).count() < count {
            let n = reader.read(&mut chunk).unwrap();
            assert!(n > 0, "the daemon closed the pipe");
            bytes.extend_from_slice(&chunk[..n]);
        }
        bytes
            .split(|&b| b == 0)
            .filter(|frame| !frame.is_empty())
            .map(|frame| serde_json::from_slice(frame).unwrap())
            .collect()
    }

    fn write_frame(writer: &mut fs::File, message: &serde_json::Value) {
        let mut frame = message.to_string().into_bytes();
        frame.push(0);
        writer.write_all(&frame).unwrap();
        writer.flush().unwrap();
    }

    fn assert_nothing_written(reader: &fs::File) {
        set_nonblocking(reader.as_raw_fd(), true);
        let mut probe = [0u8; 64];
        let read = (&*reader).read(&mut probe);
        set_nonblocking(reader.as_raw_fd(), false);
        assert!(
            matches!(&read, Err(e) if e.kind() == io::ErrorKind::WouldBlock),
            "the daemon wrote to the browser: {read:?}"
        );
    }

    fn worker_target_info(target_id: &str) -> serde_json::Value {
        serde_json::json!({
            "targetId": target_id,
            "type": "service_worker",
            "title": "",
            "url": format!("chrome-extension://{AGENT_EXTENSION_ID}/worker.js"),
            "attached": false,
            "canAccessOpener": false,
        })
    }

    #[test]
    fn test_shared_cdp_round_trip_does_not_hold_the_manager_while_it_waits() {
        // `Runtime.evaluate` with `awaitPromise` waits for a WebAuthn ceremony, and the ceremony
        // needs the browser manager (lease activation) before the browser can answer. The wait
        // must not hold the manager, and a second call meanwhile is refused as busy.
        let mut mgr = BrowserProcessManager::new(test_clock());
        let (daemon_write, daemon_read, mut fake_browser_read, mut fake_browser_write) =
            create_fake_cdp_pair();
        let lease_id = inject_lease_with_fake_cdp(&mut mgr, daemon_write, daemon_read);
        let manager = Arc::new(Mutex::new(mgr));

        let (manager_taken_tx, manager_taken_rx) = std::sync::mpsc::channel();
        let browser = {
            let manager = manager.clone();
            let lease_id = lease_id.clone();
            std::thread::spawn(move || {
                let request = read_frames(&mut fake_browser_read, 1).remove(0);
                // The "ceremony": it takes the manager, as `BrowserLeaseActivation` does, and the
                // browser answers only afterwards.
                let guard = manager.lock().unwrap();
                assert!(guard.snapshot(&lease_id).is_some());
                // A second call while the first waits is refused, not mixed up with it.
                let second = make_cdp_request(8, "Page.reload");
                let mut guard = guard;
                assert!(matches!(
                    guard.cdp_begin(&lease_id, &second, Duration::from_secs(1), true),
                    Err(CdpError::Busy)
                ));
                drop(guard);
                manager_taken_tx.send(()).unwrap();
                write_frame(
                    &mut fake_browser_write,
                    &serde_json::json!({"id": request["id"], "result": {"result": {"value": 1}}}),
                );
            })
        };
        let evaluate = make_cdp_request(7, "Runtime.evaluate");
        let messages =
            cdp_round_trip_shared(&manager, &lease_id, &evaluate, Duration::from_secs(10))
                .unwrap()
                .messages;
        browser.join().unwrap();
        manager_taken_rx.try_recv().unwrap();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains(r#""id":7"#));
        // The lease is free again (the fake browser is gone, so a new call fails on the pipe,
        // not as busy).
        let next = make_cdp_request(9, "Page.reload");
        assert!(!matches!(
            manager
                .lock()
                .unwrap()
                .cdp_begin(&lease_id, &next, Duration::from_secs(1), true),
            Err(CdpError::Busy)
        ));
    }

    #[test]
    fn test_cdp_round_trip_denies_attaching_to_the_extension_worker() {
        // Review M3: the agent names the worker's target; the daemon looks it up itself and
        // refuses the attach without forwarding it.
        let mut mgr = BrowserProcessManager::new(test_clock());
        let (daemon_write, daemon_read, mut fake_browser_read, mut fake_browser_write) =
            create_fake_cdp_pair();
        let lease_id = inject_lease_with_fake_cdp(&mut mgr, daemon_write, daemon_read);

        let browser = std::thread::spawn(move || {
            let lookup = read_frames(&mut fake_browser_read, 1).remove(0);
            assert_eq!(lookup["method"], "Target.getTargetInfo");
            assert_eq!(lookup["params"]["targetId"], "WORKER");
            // An unrelated event arrives before the answer; it is kept for the agent.
            write_frame(
                &mut fake_browser_write,
                &serde_json::json!({"method": "Page.loadEventFired", "params": {}}),
            );
            write_frame(
                &mut fake_browser_write,
                &serde_json::json!({"id": lookup["id"], "result": {"targetInfo": worker_target_info("WORKER")}}),
            );
            (fake_browser_read, fake_browser_write)
        });
        let attach = make_cdp_request_with_params(
            1,
            "Target.attachToTarget",
            r#"{"targetId":"WORKER","flatten":true}"#,
        );
        let result = mgr.cdp_round_trip(&lease_id, &attach, Duration::from_secs(5));
        let (fake_browser_read, mut fake_browser_write) = browser.join().unwrap();
        assert!(matches!(&result, Err(CdpError::Denied(_))), "{result:?}");
        assert_nothing_written(&fake_browser_read);

        // Known now: closing it is refused without another lookup, and nothing is written.
        let close =
            make_cdp_request_with_params(2, "Target.closeTarget", r#"{"targetId":"WORKER"}"#);
        assert!(matches!(
            mgr.cdp_round_trip(&lease_id, &close, Duration::from_secs(1)),
            Err(CdpError::Denied(_))
        ));
        assert_nothing_written(&fake_browser_read);

        // The event read during the lookup reaches the agent with its next response.
        let browser = std::thread::spawn(move || {
            let mut reader = fake_browser_read;
            let request = read_frames(&mut reader, 1).remove(0);
            write_frame(
                &mut fake_browser_write,
                &serde_json::json!({"id": request["id"], "result": {}}),
            );
        });
        let reload = make_cdp_request(3, "Page.reload");
        let messages = mgr
            .cdp_round_trip(&lease_id, &reload, Duration::from_secs(5))
            .unwrap()
            .messages;
        browser.join().unwrap();
        assert_eq!(messages.len(), 2);
        assert!(messages[0].contains("loadEventFired"));
        assert!(messages[1].contains(r#""id":3"#));
    }

    #[test]
    fn test_cdp_round_trip_hides_and_detaches_an_auto_attached_extension_worker() {
        // Review M3: Playwright-style `Target.setAutoAttach {flatten: true}` attaches to every
        // target. The worker's attach event never reaches the agent, the daemon detaches that
        // session (resuming the paused worker first), and the session is refused afterwards.
        let mut mgr = BrowserProcessManager::new(test_clock());
        let (daemon_write, daemon_read, mut fake_browser_read, mut fake_browser_write) =
            create_fake_cdp_pair();
        let lease_id = inject_lease_with_fake_cdp(&mut mgr, daemon_write, daemon_read);

        let browser = std::thread::spawn(move || {
            let request = read_frames(&mut fake_browser_read, 1).remove(0);
            assert_eq!(request["method"], "Target.setAutoAttach");
            write_frame(
                &mut fake_browser_write,
                &serde_json::json!({"method": "Target.attachedToTarget", "params": {
                    "sessionId": "WORKER-SESSION",
                    "targetInfo": worker_target_info("WORKER"),
                    "waitingForDebugger": true,
                }}),
            );
            write_frame(
                &mut fake_browser_write,
                &serde_json::json!({"id": request["id"], "result": {}}),
            );
            read_frames(&mut fake_browser_read, 2)
        });
        let auto_attach = make_cdp_request_with_params(
            1,
            "Target.setAutoAttach",
            r#"{"autoAttach":true,"waitForDebuggerOnStart":true,"flatten":true}"#,
        );
        let messages = mgr
            .cdp_round_trip(&lease_id, &auto_attach, Duration::from_secs(5))
            .unwrap()
            .messages;
        let daemon_commands = browser.join().unwrap();
        assert_eq!(messages.len(), 1, "{messages:?}");
        assert!(messages[0].contains(r#""id":1"#));
        assert_eq!(
            daemon_commands[0]["method"],
            "Runtime.runIfWaitingForDebugger"
        );
        assert_eq!(daemon_commands[0]["sessionId"], "WORKER-SESSION");
        assert_eq!(daemon_commands[1]["method"], "Target.detachFromTarget");
        assert_eq!(daemon_commands[1]["params"]["sessionId"], "WORKER-SESSION");

        let evaluate = r#"{"id":2,"method":"Runtime.evaluate","params":{"expression":"1"},"sessionId":"WORKER-SESSION"}"#;
        assert!(matches!(
            mgr.cdp_round_trip(&lease_id, evaluate, Duration::from_secs(1)),
            Err(CdpError::Denied(_))
        ));
    }

    #[test]
    fn test_cdp_round_trip_forwards_the_checked_request_not_the_raw_text() {
        // Review M-b: duplicate keys. serde_json keeps the last `params`, a parser that keeps the
        // first would see `chrome://extensions`. The browser receives the request the filter
        // checked, re-serialized, so both read the same thing.
        let mut mgr = BrowserProcessManager::new(test_clock());
        let (daemon_write, daemon_read, mut fake_browser_read, mut fake_browser_write) =
            create_fake_cdp_pair();
        let lease_id = inject_lease_with_fake_cdp(&mut mgr, daemon_write, daemon_read);
        let browser = std::thread::spawn(move || {
            let mut raw = Vec::new();
            let mut chunk = [0u8; 4096];
            while !raw.contains(&0) {
                let n = fake_browser_read.read(&mut chunk).unwrap();
                assert!(n > 0);
                raw.extend_from_slice(&chunk[..n]);
            }
            raw.pop();
            write_frame(
                &mut fake_browser_write,
                &serde_json::json!({"id": 1, "result": {"frameId": "F"}}),
            );
            String::from_utf8(raw).unwrap()
        });
        let duplicate = r#"{"id":1,"method":"Page.navigate","params":{"url":"chrome://extensions"},"params":{"url":"https://rp.test/"}}"#;
        mgr.cdp_round_trip(&lease_id, duplicate, Duration::from_secs(5))
            .unwrap();
        let forwarded = browser.join().unwrap();
        assert!(!forwarded.contains("chrome://"), "{forwarded}");
        assert_eq!(forwarded.matches("\"params\"").count(), 1, "{forwarded}");
        let forwarded: serde_json::Value = serde_json::from_str(&forwarded).unwrap();
        assert_eq!(forwarded["params"]["url"], "https://rp.test/");
    }

    #[test]
    fn test_cdp_round_trip_refuses_a_session_whose_target_became_the_extension() {
        // Review H2: page `PAGE` was auto-attached as session `S`; it then turned into an
        // extension page. A command on `S` makes the daemon look the session's target up, which
        // refuses it and detaches `S`; the command never reaches the browser.
        let mut mgr = BrowserProcessManager::new(test_clock());
        let (daemon_write, daemon_read, mut fake_browser_read, mut fake_browser_write) =
            create_fake_cdp_pair();
        let lease_id = inject_lease_with_fake_cdp(&mut mgr, daemon_write, daemon_read);
        let mut page = serde_json::json!({"targetId": "PAGE", "type": "page", "title": "",
                                          "url": "https://rp.test/", "attached": true});
        let attached = serde_json::json!({"method": "Target.attachedToTarget", "params": {
            "sessionId": "S", "targetInfo": page.clone(), "waitingForDebugger": false}});
        let browser = std::thread::spawn(move || {
            let request = read_frames(&mut fake_browser_read, 1).remove(0);
            write_frame(&mut fake_browser_write, &attached);
            write_frame(
                &mut fake_browser_write,
                &serde_json::json!({"id": request["id"], "result": {}}),
            );
            (fake_browser_read, fake_browser_write)
        });
        let auto_attach = make_cdp_request_with_params(
            1,
            "Target.setAutoAttach",
            r#"{"autoAttach":true,"waitForDebuggerOnStart":false,"flatten":true}"#,
        );
        let messages = mgr
            .cdp_round_trip(&lease_id, &auto_attach, Duration::from_secs(5))
            .unwrap()
            .messages;
        assert_eq!(
            messages.len(),
            2,
            "the page session is the agent's: {messages:?}"
        );
        let (mut fake_browser_read, mut fake_browser_write) = browser.join().unwrap();

        page["url"] =
            serde_json::Value::String(format!("chrome-extension://{AGENT_EXTENSION_ID}/x.html"));
        let browser = std::thread::spawn(move || {
            let lookup = read_frames(&mut fake_browser_read, 1).remove(0);
            assert_eq!(lookup["method"], "Target.getTargetInfo");
            assert_eq!(lookup["params"]["targetId"], "PAGE");
            write_frame(
                &mut fake_browser_write,
                &serde_json::json!({"id": lookup["id"], "result": {"targetInfo": page}}),
            );
            read_frames(&mut fake_browser_read, 1).remove(0)
        });
        let evaluate =
            r#"{"id":2,"method":"Runtime.evaluate","params":{"expression":"1"},"sessionId":"S"}"#;
        let result = mgr.cdp_round_trip(&lease_id, evaluate, Duration::from_secs(5));
        let detach = browser.join().unwrap();
        assert!(matches!(&result, Err(CdpError::Denied(_))), "{result:?}");
        assert_eq!(detach["method"], "Target.detachFromTarget");
        assert_eq!(detach["params"]["sessionId"], "S");
        // Refused from now on without another lookup.
        assert!(matches!(
            mgr.cdp_round_trip(&lease_id, evaluate, Duration::from_secs(1)),
            Err(CdpError::Denied(_))
        ));
    }

    #[test]
    fn test_cdp_error_display() {
        assert!(CdpError::LeaseNotFound.to_string().contains("not found"));
        assert!(CdpError::Timeout.to_string().contains("timed out"));
        assert!(CdpError::BrowserExited.to_string().contains("exited"));
        assert!(
            CdpError::ResponseTooLarge
                .to_string()
                .contains("size limit")
        );
        assert!(
            CdpError::TooManyMessages
                .to_string()
                .contains("message count")
        );
    }

    #[test]
    fn test_cdp_error_is_std_error() {
        fn assert_error<T: std::error::Error>() {}
        assert_error::<CdpError>();
    }

    #[test]
    fn test_check_exits_detects_exited_child() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let mut config = test_config(dir.path());
        config.executable = PathBuf::from("/bin/true");

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();

        std::thread::sleep(Duration::from_millis(200));

        let exits = mgr.check_exits();
        assert_eq!(exits.len(), 1);
        assert_eq!(exits[0].lease_id, lease_id);
        assert_eq!(
            mgr.snapshot(&lease_id).unwrap().state,
            LeaseState::BrowserExit
        );
    }

    #[test]
    fn test_check_exits_skips_already_reaped() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let mut config = test_config(dir.path());
        config.executable = PathBuf::from("/bin/true");

        let _lease_id = mgr.launch(&config, test_profile_id()).unwrap();

        std::thread::sleep(Duration::from_millis(200));

        let exits1 = mgr.check_exits();
        assert_eq!(exits1.len(), 1);

        let exits2 = mgr.check_exits();
        assert!(exits2.is_empty());
    }

    #[test]
    fn test_check_exits_does_not_double_reap() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let mut config = test_config(dir.path());
        config.executable = PathBuf::from("/bin/true");

        let _lease_id = mgr.launch(&config, test_profile_id()).unwrap();

        std::thread::sleep(Duration::from_millis(200));

        let exits1 = mgr.check_exits();
        assert_eq!(exits1.len(), 1);

        let exits2 = mgr.check_exits();
        assert!(exits2.is_empty());
    }

    #[test]
    fn test_check_exits_skips_terminal_leases() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let mut config = test_config(dir.path());
        config.executable = PathBuf::from("/bin/true");

        let lease_id = mgr.launch(&config, test_profile_id()).unwrap();

        mgr.revoke(&lease_id).unwrap();

        std::thread::sleep(Duration::from_millis(200));

        let exits = mgr.check_exits();
        assert!(exits.is_empty());
    }

    #[test]
    fn test_discover_cdp_endpoint_with_mock_file() {
        let dir = tempfile::tempdir().unwrap();
        let profile_dir = dir.path().join("profile");
        fs::create_dir_all(&profile_dir).unwrap();
        fs::write(
            profile_dir.join("DevToolsActivePort"),
            "9222\n/devtools/browser/abc-123\n",
        )
        .unwrap();

        let result = discover_cdp_endpoint(&profile_dir, Duration::from_secs(1)).unwrap();
        assert_eq!(result, "ws://127.0.0.1:9222/devtools/browser/abc-123");
    }

    #[test]
    fn test_discover_cdp_endpoint_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let nonexistent = dir.path().join("no-such-dir");

        let result = discover_cdp_endpoint(&nonexistent, Duration::from_millis(100));
        assert!(matches!(result, Err(LaunchError::CdpDiscoveryTimeout)));
    }

    #[test]
    fn test_discover_cdp_endpoint_detects_browser_exit() {
        let dir = tempfile::tempdir().unwrap();
        let profile_dir = dir.path().join("profile");
        fs::create_dir_all(&profile_dir).unwrap();
        let mut child = Command::new("/bin/false").spawn().unwrap();

        let profile = Dir::open_path(&profile_dir).unwrap();
        let uid = unsafe { libc::geteuid() };
        let result =
            discover_cdp_endpoint_with_child(&mut child, &profile, uid, Duration::from_secs(5));
        assert!(matches!(
            result,
            Err(LaunchError::BrowserExitedBeforeCdp(_))
        ));
    }

    /// Review H1: `DevToolsActivePort` is read through the pinned profile handle; a symlink
    /// planted in its place (for example to a secret file) is never followed, and the discovery
    /// times out instead of reading, or echoing, the target.
    #[test]
    fn test_discover_cdp_endpoint_does_not_follow_a_planted_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret");
        fs::write(&secret, "9222\n/devtools/browser/stolen\n").unwrap();
        let profile_dir = dir.path().join("profile");
        fs::create_dir_all(&profile_dir).unwrap();
        unix_fs::symlink(&secret, profile_dir.join("DevToolsActivePort")).unwrap();
        let profile = Dir::open_path(&profile_dir).unwrap();
        let mut child = Command::new("sleep").arg("5").spawn().unwrap();
        let uid = unsafe { libc::geteuid() };
        let result =
            discover_cdp_endpoint_with_child(&mut child, &profile, uid, Duration::from_millis(300));
        let _ = child.kill();
        let _ = child.wait();
        assert!(
            matches!(result, Err(LaunchError::CdpDiscoveryTimeout)),
            "{result:?}"
        );

        // A real file is read; invalid content is reported without echoing it.
        fs::remove_file(profile_dir.join("DevToolsActivePort")).unwrap();
        fs::write(
            profile_dir.join("DevToolsActivePort"),
            "root:x:0:0\nsecret\n",
        )
        .unwrap();
        let mut child = Command::new("sleep").arg("5").spawn().unwrap();
        let err =
            discover_cdp_endpoint_with_child(&mut child, &profile, uid, Duration::from_secs(2))
                .unwrap_err();
        let _ = child.kill();
        let _ = child.wait();
        assert!(!err.to_string().contains("root:x"), "{err}");
    }

    #[test]
    fn test_await_owned_cdp_endpoint_detects_browser_exit() {
        let mut child = Command::new("/bin/false").spawn().unwrap();
        let started = Instant::now();
        let uid = unsafe { libc::geteuid() };
        let result = await_owned_cdp_endpoint(&mut child, 1, uid, None, Duration::from_secs(5));
        assert!(matches!(
            result,
            Err(LaunchError::BrowserExitedBeforeCdp(_))
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    /// A loopback listener that answers every request with a `/json/version` naming
    /// `ws_url`. It accepts until the test ends.
    fn serve_json_version(listener: std::net::TcpListener, ws_url: String) {
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut buf = [0u8; 2048];
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = stream.read(&mut buf);
                let body = serde_json::json!({
                    "Browser": "Chrome/156.0.0.0",
                    "Protocol-Version": "1.3",
                    "webSocketDebuggerUrl": ws_url,
                })
                .to_string();
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \
                     {}\r\n\r\n{body}",
                    body.len()
                );
            }
        });
    }

    /// A stand-in "browser" that holds the listening socket `listener` (as its fd 3, the way a
    /// browser holds its DevTools listener), while the test keeps serving on its own copy.
    fn browser_holding(listener: &std::net::TcpListener) -> Child {
        let fd = listener.as_raw_fd();
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        unsafe {
            cmd.pre_exec(move || {
                // `dup2(3, 3)` is a no-op that leaves FD_CLOEXEC set, so a listener that is
                // already fd 3 (a test run alone) would vanish at exec: clear the flag then.
                let rc = if fd == 3 {
                    libc::fcntl(3, libc::F_SETFD, 0)
                } else {
                    libc::dup2(fd, 3)
                };
                if rc < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        cmd.spawn().unwrap()
    }

    fn stop(mut child: Child) {
        let _ = child.kill();
        let _ = child.wait();
    }

    const GUID_A: &str = "/devtools/browser/0b4d6ad2-5d1e-4f1a-9a0e-1f2a3b4c5d6e";
    const GUID_B: &str = "/devtools/browser/c0ffee00-1111-2222-3333-444455556666";

    /// The finding: another process holds the fixed port and answers `/json/version` with a
    /// well-formed endpoint. The launched browser does not hold that listener, so the launch is
    /// refused at once (not after the 30 s discovery timeout) and the endpoint never returned.
    #[test]
    fn test_a_foreign_listener_on_the_cdp_port_is_refused() {
        let foreign = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = foreign.local_addr().unwrap().port();
        serve_json_version(foreign, format!("ws://127.0.0.1:{port}{GUID_A}"));
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let uid = unsafe { libc::geteuid() };
        let started = Instant::now();
        let result = await_owned_cdp_endpoint(&mut child, port, uid, None, Duration::from_secs(30));
        stop(child);
        match result {
            Err(LaunchError::CdpEndpointNotOwned { port: p, reason }) => {
                assert_eq!(p, port);
                assert!(
                    reason.contains(&format!("pid {}", std::process::id())),
                    "the holder is named: {reason}"
                );
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(started.elapsed() < Duration::from_secs(3));

        // The same with the browser's own report (the ephemeral path): its GUID being served
        // does not make someone else's listener the browser's.
        let foreign = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = foreign.local_addr().unwrap().port();
        serve_json_version(foreign, format!("ws://127.0.0.1:{port}{GUID_A}"));
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let result =
            await_owned_cdp_endpoint(&mut child, port, uid, Some(GUID_A), Duration::from_secs(5));
        stop(child);
        assert!(
            matches!(result, Err(LaunchError::CdpEndpointNotOwned { .. })),
            "{result:?}"
        );
    }

    /// The pre-launch probe: a held fixed port refuses the launch before anything is created or
    /// started, and names the holder.
    #[test]
    fn test_launch_with_a_held_fixed_cdp_port_is_refused_before_spawning() {
        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = held.local_addr().unwrap().port();
        let dir = tempfile::tempdir().unwrap();
        let mut config = test_config(dir.path());
        config.cdp_expose = CdpExposeMode::Port;
        config.cdp_port = port;
        let runtime_root = config.runtime_root.clone();
        let mut mgr = BrowserProcessManager::with_spawner(test_clock(), Arc::new(TestSpawner));
        let err = mgr.launch(&config, test_profile_id()).unwrap_err();
        let text = err.to_string();
        assert!(
            matches!(err, LaunchError::CdpPortInUse { port: p, .. } if p == port),
            "{err:?}"
        );
        assert!(
            text.contains(&format!(
                "browser_cdp_port {port} on 127.0.0.1 is already in use"
            )),
            "{text}"
        );
        assert!(
            text.contains(&format!("pid {}", std::process::id())),
            "{text}"
        );
        assert!(text.contains("remove browser_cdp_port"), "{text}");
        assert_eq!(
            fs::read_dir(&runtime_root).unwrap().count(),
            0,
            "no lease directory was created"
        );
        assert_eq!(mgr.lease_count(), 0);
    }

    /// The listener is the browser's, but it serves a GUID other than the one the browser wrote
    /// to `DevToolsActivePort`: refused.
    #[test]
    fn test_a_guid_mismatch_is_refused() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut child = browser_holding(&listener);
        serve_json_version(listener, format!("ws://127.0.0.1:{port}{GUID_B}"));
        let uid = unsafe { libc::geteuid() };
        let result =
            await_owned_cdp_endpoint(&mut child, port, uid, Some(GUID_A), Duration::from_secs(5));
        stop(child);
        match result {
            Err(LaunchError::CdpEndpointNotOwned { reason, .. }) => {
                assert!(reason.contains("GUID"), "{reason}")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// The served endpoint names another port (or host) than the one that was verified:
    /// refused, whether or not the browser reported a path.
    #[test]
    fn test_a_served_endpoint_on_another_port_or_host_is_refused() {
        let uid = unsafe { libc::geteuid() };
        for (served, reported) in [
            ("ws://127.0.0.1:{other}{GUID_A}", None),
            ("ws://127.0.0.1:{other}{GUID_A}", Some(GUID_A)),
            ("ws://[::1]:{port}{GUID_A}", None),
            ("ws://localhost:{port}{GUID_A}", Some(GUID_A)),
            ("ws://127.0.0.1:{port}/devtools/page/x", None),
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let served = served
                .replace("{other}", &(port.wrapping_add(1)).to_string())
                .replace("{port}", &port.to_string())
                .replace("{GUID_A}", GUID_A);
            let mut child = browser_holding(&listener);
            serve_json_version(listener, served.clone());
            let result =
                await_owned_cdp_endpoint(&mut child, port, uid, reported, Duration::from_secs(5));
            stop(child);
            assert!(
                matches!(result, Err(LaunchError::CdpEndpointNotOwned { .. })),
                "{served}: {result:?}"
            );
        }
    }

    /// `DevToolsActivePort` names a port whose listener is not the browser's (here: someone
    /// else's, serving the browser's GUID as a relay would): refused.
    #[test]
    fn test_a_devtools_active_port_naming_a_foreign_port_is_refused() {
        let foreign = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let foreign_port = foreign.local_addr().unwrap().port();
        serve_json_version(foreign, format!("ws://127.0.0.1:{foreign_port}{GUID_A}"));
        let own = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut child = browser_holding(&own);

        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("DevToolsActivePort"),
            format!("{foreign_port}\n{GUID_A}\n"),
        )
        .unwrap();
        let profile = Dir::open_path(dir.path()).unwrap();
        let uid = unsafe { libc::geteuid() };
        let (port, path) =
            discover_cdp_endpoint_with_child(&mut child, &profile, uid, Duration::from_secs(2))
                .unwrap();
        assert_eq!(port, foreign_port);
        let result =
            await_owned_cdp_endpoint(&mut child, port, uid, Some(&path), Duration::from_secs(5));
        stop(child);
        drop(own);
        assert!(
            matches!(result, Err(LaunchError::CdpEndpointNotOwned { .. })),
            "{result:?}"
        );
    }

    /// Happy path, fixed port: the browser holds the listener and serves its endpoint.
    #[test]
    fn test_the_browser_own_fixed_port_endpoint_is_accepted() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut child = browser_holding(&listener);
        let url = format!("ws://127.0.0.1:{port}{GUID_A}");
        serve_json_version(listener, url.clone());
        let uid = unsafe { libc::geteuid() };
        let result = await_owned_cdp_endpoint(&mut child, port, uid, None, Duration::from_secs(5));
        stop(child);
        assert_eq!(result.unwrap(), url);
    }

    /// Happy path, ephemeral port: `DevToolsActivePort` names the browser's own listener and the
    /// GUID it serves.
    #[test]
    fn test_the_browser_own_ephemeral_endpoint_is_accepted() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut child = browser_holding(&listener);
        let url = format!("ws://127.0.0.1:{port}{GUID_A}");
        serve_json_version(listener, url.clone());

        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("DevToolsActivePort"),
            format!("{port}\n{GUID_A}\n"),
        )
        .unwrap();
        let profile = Dir::open_path(dir.path()).unwrap();
        let uid = unsafe { libc::geteuid() };
        let result =
            discover_cdp_endpoint_with_child(&mut child, &profile, uid, Duration::from_secs(2))
                .and_then(|(p, path)| {
                    await_owned_cdp_endpoint(
                        &mut child,
                        p,
                        uid,
                        Some(&path),
                        Duration::from_secs(5),
                    )
                });
        stop(child);
        assert_eq!(result.unwrap(), url);
    }

    /// Chromium's silent fallback: its `127.0.0.1` bind failed and it listens on `[::1]` only.
    /// Refused at once, before anything could take `127.0.0.1:<port>`.
    #[test]
    fn test_a_browser_that_fell_back_to_ipv6_loopback_is_refused() {
        let Ok(listener) = std::net::TcpListener::bind("[::1]:0") else {
            eprintln!("no IPv6 loopback; skipped");
            return;
        };
        let port = listener.local_addr().unwrap().port();
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_err() {
            eprintln!("127.0.0.1:{port} is taken; skipped");
            return;
        }
        let mut child = browser_holding(&listener);
        let uid = unsafe { libc::geteuid() };
        let started = Instant::now();
        let result = await_owned_cdp_endpoint(&mut child, port, uid, None, Duration::from_secs(30));
        stop(child);
        match result {
            Err(LaunchError::CdpEndpointNotOwned { reason, .. }) => {
                assert!(reason.contains("[::1]"), "{reason}")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn test_the_cdp_port_errors_say_how_to_fix_it() {
        for err in [
            LaunchError::CdpPortInUse {
                port: 9333,
                holder: "firefox, pid 64598".into(),
            },
            LaunchError::CdpEndpointNotOwned {
                port: 9333,
                reason: "it is held by firefox, pid 64598".into(),
            },
        ] {
            let text = err.to_string();
            assert!(text.contains("firefox, pid 64598"), "{text}");
            assert!(text.contains("remove browser_cdp_port"), "{text}");
            assert!(!text.contains("extension"), "not the extension: {text}");
        }
    }

    #[test]
    fn test_build_browser_command_pipe_mode() {
        let dir = tempfile::tempdir().unwrap();
        let config = BrowserConfig {
            executable: PathBuf::from("/usr/bin/chromium"),
            start_url: None,
            extra_args: Vec::new(),
            runtime_root: dir.path().to_path_buf(),
            ttl: Duration::from_secs(300),
            login_timeout: DEFAULT_LOGIN_TIMEOUT,
            rp_ids: vec!["example.com".to_string()],
            start_url_rules: start_url_test_rules(&[("example.com", RuleAction::Allow)]),
            target_uid: 1000,
            target_gid: 1000,
            daemon_uid: 0,
            daemon_gid: 0,
            cdp_expose: CdpExposeMode::Pipe,
            cdp_port: 9222,
            bind_parent_death: true,
        };

        let cmd = build_browser_command_unverified(&config, dir.path()).unwrap();
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();

        assert!(args.iter().any(|a| a == "--remote-debugging-pipe"));
        assert!(
            !args
                .iter()
                .any(|a| a.starts_with("--remote-debugging-port"))
        );
        assert!(
            !args
                .iter()
                .any(|a| a.starts_with("--remote-debugging-address"))
        );
        assert!(!args.iter().any(|a| a.starts_with("--remote-allow-origins")));
    }

    #[test]
    fn test_build_browser_command_port_mode() {
        let dir = tempfile::tempdir().unwrap();
        let config = BrowserConfig {
            executable: PathBuf::from("/usr/bin/chromium"),
            start_url: None,
            extra_args: Vec::new(),
            runtime_root: dir.path().to_path_buf(),
            ttl: Duration::from_secs(300),
            login_timeout: DEFAULT_LOGIN_TIMEOUT,
            rp_ids: vec!["example.com".to_string()],
            start_url_rules: start_url_test_rules(&[("example.com", RuleAction::Allow)]),
            target_uid: 1000,
            target_gid: 1000,
            daemon_uid: 0,
            daemon_gid: 0,
            cdp_expose: CdpExposeMode::Port,
            cdp_port: 9222,
            bind_parent_death: true,
        };

        let cmd = build_browser_command_unverified(&config, dir.path()).unwrap();
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();

        assert!(args.iter().any(|a| a == "--remote-debugging-port=9222"));
        assert!(
            args.iter()
                .any(|a| a == "--remote-debugging-address=127.0.0.1")
        );
        assert!(args.iter().any(|a| a == "--remote-allow-origins=*"));
        assert!(!args.iter().any(|a| a == "--remote-debugging-pipe"));
    }

    #[test]
    fn test_build_browser_command_rejects_remote_debugging_port_in_extra_args() {
        let dir = tempfile::tempdir().unwrap();
        let config = BrowserConfig {
            executable: PathBuf::from("/usr/bin/chromium"),
            start_url: None,
            extra_args: vec!["--remote-debugging-port=9999".to_string()],
            runtime_root: dir.path().to_path_buf(),
            ttl: Duration::from_secs(300),
            login_timeout: DEFAULT_LOGIN_TIMEOUT,
            rp_ids: vec!["example.com".to_string()],
            start_url_rules: start_url_test_rules(&[("example.com", RuleAction::Allow)]),
            target_uid: 1000,
            target_gid: 1000,
            daemon_uid: 0,
            daemon_gid: 0,
            cdp_expose: CdpExposeMode::Pipe,
            cdp_port: 9222,
            bind_parent_death: true,
        };

        let result = build_browser_command(&config, dir.path());
        assert!(matches!(result, Err(LaunchError::InvalidArg(_))));
    }

    #[test]
    fn test_build_browser_command_rejects_remote_debugging_pipe_in_extra_args() {
        let dir = tempfile::tempdir().unwrap();
        let config = BrowserConfig {
            executable: PathBuf::from("/usr/bin/chromium"),
            start_url: None,
            extra_args: vec!["--remote-debugging-pipe".to_string()],
            runtime_root: dir.path().to_path_buf(),
            ttl: Duration::from_secs(300),
            login_timeout: DEFAULT_LOGIN_TIMEOUT,
            rp_ids: vec!["example.com".to_string()],
            start_url_rules: start_url_test_rules(&[("example.com", RuleAction::Allow)]),
            target_uid: 1000,
            target_gid: 1000,
            daemon_uid: 0,
            daemon_gid: 0,
            cdp_expose: CdpExposeMode::Pipe,
            cdp_port: 9222,
            bind_parent_death: true,
        };

        let result = build_browser_command(&config, dir.path());
        assert!(matches!(result, Err(LaunchError::InvalidArg(_))));
    }

    #[test]
    fn test_build_browser_command_rejects_remote_debugging_address_in_extra_args() {
        let dir = tempfile::tempdir().unwrap();
        let config = BrowserConfig {
            executable: PathBuf::from("/usr/bin/chromium"),
            start_url: None,
            extra_args: vec!["--remote-debugging-address=0.0.0.0".to_string()],
            runtime_root: dir.path().to_path_buf(),
            ttl: Duration::from_secs(300),
            login_timeout: DEFAULT_LOGIN_TIMEOUT,
            rp_ids: vec!["example.com".to_string()],
            start_url_rules: start_url_test_rules(&[("example.com", RuleAction::Allow)]),
            target_uid: 1000,
            target_gid: 1000,
            daemon_uid: 0,
            daemon_gid: 0,
            cdp_expose: CdpExposeMode::Pipe,
            cdp_port: 9222,
            bind_parent_death: true,
        };

        let result = build_browser_command(&config, dir.path());
        assert!(matches!(result, Err(LaunchError::InvalidArg(_))));
    }

    fn make_reject_config(dir: &Path, extra: &str) -> BrowserConfig {
        BrowserConfig {
            executable: PathBuf::from("/usr/bin/chromium"),
            start_url: None,
            extra_args: vec![extra.to_string()],
            runtime_root: dir.to_path_buf(),
            ttl: Duration::from_secs(300),
            login_timeout: DEFAULT_LOGIN_TIMEOUT,
            rp_ids: vec!["example.com".to_string()],
            start_url_rules: start_url_test_rules(&[("example.com", RuleAction::Allow)]),
            target_uid: 1000,
            target_gid: 1000,
            daemon_uid: 0,
            daemon_gid: 0,
            cdp_expose: CdpExposeMode::Pipe,
            cdp_port: 9222,
            bind_parent_death: true,
        }
    }

    #[test]
    fn test_build_browser_command_rejects_remote_allow_origins_in_extra_args() {
        let dir = tempfile::tempdir().unwrap();
        let config = make_reject_config(dir.path(), "--remote-allow-origins=*");
        assert!(matches!(
            build_browser_command(&config, dir.path()),
            Err(LaunchError::InvalidArg(_))
        ));
    }

    #[test]
    fn test_build_browser_command_rejects_load_extension_bare() {
        let dir = tempfile::tempdir().unwrap();
        let config = make_reject_config(dir.path(), "--load-extension=/tmp/ext");
        assert!(matches!(
            build_browser_command(&config, dir.path()),
            Err(LaunchError::InvalidArg(_))
        ));
    }

    #[test]
    fn test_build_browser_command_rejects_load_extension_space_form() {
        let dir = tempfile::tempdir().unwrap();
        let config = make_reject_config(dir.path(), "--load-extension");
        assert!(matches!(
            build_browser_command(&config, dir.path()),
            Err(LaunchError::InvalidArg(_))
        ));
    }

    #[test]
    fn test_build_browser_command_rejects_disable_extensions_bare() {
        let dir = tempfile::tempdir().unwrap();
        let config = make_reject_config(dir.path(), "--disable-extensions");
        assert!(matches!(
            build_browser_command(&config, dir.path()),
            Err(LaunchError::InvalidArg(_))
        ));
    }

    #[test]
    fn test_build_browser_command_rejects_disable_extensions_except() {
        let dir = tempfile::tempdir().unwrap();
        let config = make_reject_config(dir.path(), "--disable-extensions-except=/tmp/ext");
        assert!(matches!(
            build_browser_command(&config, dir.path()),
            Err(LaunchError::InvalidArg(_))
        ));
    }

    #[test]
    fn test_build_browser_command_rejects_user_data_dir_bare() {
        let dir = tempfile::tempdir().unwrap();
        let config = make_reject_config(dir.path(), "--user-data-dir=/tmp/profile");
        assert!(matches!(
            build_browser_command(&config, dir.path()),
            Err(LaunchError::InvalidArg(_))
        ));
    }

    #[test]
    fn test_build_browser_command_rejects_user_data_dir_space_form() {
        let dir = tempfile::tempdir().unwrap();
        let config = make_reject_config(dir.path(), "--user-data-dir");
        assert!(matches!(
            build_browser_command(&config, dir.path()),
            Err(LaunchError::InvalidArg(_))
        ));
    }

    #[test]
    fn test_build_browser_command_rejects_allowlisted_extension_id() {
        let dir = tempfile::tempdir().unwrap();
        let config = make_reject_config(dir.path(), "--allowlisted-extension-id=abcdef");
        assert!(matches!(
            build_browser_command(&config, dir.path()),
            Err(LaunchError::InvalidArg(_))
        ));
    }

    #[test]
    fn test_build_browser_command_rejects_disable_extensions_file_access_check() {
        let dir = tempfile::tempdir().unwrap();
        let config = make_reject_config(dir.path(), "--disable-extensions-file-access-check");
        assert!(matches!(
            build_browser_command(&config, dir.path()),
            Err(LaunchError::InvalidArg(_))
        ));
    }

    #[test]
    fn test_build_browser_command_allows_unrelated_extra_args() {
        let dir = tempfile::tempdir().unwrap();
        let config = BrowserConfig {
            executable: PathBuf::from("/usr/bin/chromium"),
            start_url: None,
            extra_args: vec![
                "--window-size=800,600".to_string(),
                "--incognito".to_string(),
            ],
            runtime_root: dir.path().to_path_buf(),
            ttl: Duration::from_secs(300),
            login_timeout: DEFAULT_LOGIN_TIMEOUT,
            rp_ids: vec!["example.com".to_string()],
            start_url_rules: start_url_test_rules(&[("example.com", RuleAction::Allow)]),
            target_uid: 1000,
            target_gid: 1000,
            daemon_uid: 0,
            daemon_gid: 0,
            cdp_expose: CdpExposeMode::Pipe,
            cdp_port: 9222,
            bind_parent_death: true,
        };
        assert!(build_browser_command_unverified(&config, dir.path()).is_ok());
    }

    #[test]
    fn test_render_worker_script_replaces_all_placeholders() {
        let template = r#"(function(b,s,v){})(__PASSLESS_BEARER__, __PASSLESS_SOCKET_PATH__, __PASSLESS_BUILD_VERSION__);"#;
        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "secrettoken".to_string(),
        };
        let result = render_worker_script(template, &metadata);
        assert_eq!(
            result,
            format!(
                r#"(function(b,s,v){{}})("secrettoken", "/tmp/test/sock", {});"#,
                serde_json::to_string(&super::super::transport::build_version()).unwrap()
            )
        );
    }

    #[test]
    fn test_agent_endpoint_metadata_debug_redacts_the_bearer() {
        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "s3cr3t-bearer-value".to_string(),
        };
        let shown = format!("{metadata:?} {metadata:#?}");
        assert!(!shown.contains("s3cr3t-bearer-value"), "{shown}");
        assert!(shown.contains("<redacted>"));
        assert!(shown.contains("/tmp/test/sock"));
    }

    #[test]
    fn test_worker_template_has_exactly_the_three_placeholders() {
        let found: Vec<&str> = EXTENSION_WORKER_TEMPLATE
            .match_indices(EXTENSION_PLACEHOLDER_PREFIX)
            .map(|(at, _)| {
                let rest = &EXTENSION_WORKER_TEMPLATE[at..];
                let end = rest
                    .find(|c: char| !(c.is_ascii_uppercase() || c == '_'))
                    .unwrap_or(rest.len());
                &rest[..end]
            })
            .collect();
        assert_eq!(
            found,
            [
                "__PASSLESS_BEARER__",
                "__PASSLESS_SOCKET_PATH__",
                "__PASSLESS_BUILD_VERSION__"
            ]
        );
    }

    #[test]
    fn test_render_worker_script_contains_endpoint_secrets() {
        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "beartoken99".to_string(),
        };
        let rendered = render_worker_script(EXTENSION_WORKER_TEMPLATE, &metadata);
        assert!(rendered.contains("\"/tmp/test/sock\""));
        assert!(rendered.contains("\"beartoken99\""));
        assert!(rendered.contains(&super::super::transport::build_version()));
        assert!(!rendered.contains(EXTENSION_PLACEHOLDER_PREFIX));
    }

    #[test]
    fn test_generate_agent_extension_creates_correct_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = setup_runtime_root(dir.path());
        let lease_dir = root.join("lease-ext");
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        create_lease_dir(&lease_dir, RUNTIME_DIR_MODE, uid, gid).unwrap();

        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "deadbeef".to_string(),
        };
        let ext_dir = generate_agent_extension(&lease_dir, &metadata, uid, gid).unwrap();
        assert!(ext_dir.is_dir());
        let mut files: Vec<String> = fs::read_dir(&ext_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        files.sort();
        assert_eq!(files, ["manifest.json", "worker.js"]);
        // The manifest is the committed one, byte for byte: its key is never replaced.
        assert_eq!(
            fs::read_to_string(ext_dir.join("manifest.json")).unwrap(),
            EXTENSION_MANIFEST_TEMPLATE
        );
        assert_eq!(extension_id_of_dir(&ext_dir).unwrap(), AGENT_EXTENSION_ID);
    }

    #[test]
    fn test_committed_manifest_key_gives_the_fixed_extension_id() {
        assert_eq!(
            compute_extension_id(EXTENSION_MANIFEST_TEMPLATE).unwrap(),
            "lfbahamapdlbimlffmhiomfdemnjhjkc"
        );
        assert_eq!(AGENT_EXTENSION_ID, "lfbahamapdlbimlffmhiomfdemnjhjkc");
    }

    #[test]
    fn test_compute_extension_id_requires_a_key() {
        assert!(compute_extension_id(r#"{"name":"x"}"#).is_err());
        assert!(compute_extension_id(r#"{"key":""}"#).is_err());
        assert!(compute_extension_id(r#"{"key":"not base64!"}"#).is_err());
        assert!(compute_extension_id("not json").is_err());
    }

    #[test]
    fn test_native_messaging_manifest_admits_only_the_fixed_extension_id() {
        let dir = tempfile::tempdir().unwrap();
        let root = setup_runtime_root(dir.path());
        let lease_dir = root.join("lease-nm");
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        create_lease_dir(&lease_dir, RUNTIME_DIR_MODE, uid, gid).unwrap();
        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "tok".to_string(),
        };
        let ext_dir = generate_agent_extension(&lease_dir, &metadata, uid, gid).unwrap();
        let profile_dir = lease_dir.join("profile");
        let path = install_native_messaging_manifest(
            &ext_dir,
            Path::new("/opt/passless/sign-proxy"),
            &profile_dir,
        )
        .unwrap();
        assert!(path.starts_with(&profile_dir), "stays inside the profile");
        let manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(manifest["name"], NATIVE_MESSAGING_HOST_NAME);
        assert_eq!(manifest["path"], "/opt/passless/sign-proxy");
        assert_eq!(
            manifest["allowed_origins"],
            serde_json::json!([format!("chrome-extension://{AGENT_EXTENSION_ID}/")])
        );
    }

    #[test]
    fn test_extension_dir_permissions_are_0755() {
        let dir = tempfile::tempdir().unwrap();
        let root = setup_runtime_root(dir.path());
        let lease_dir = root.join("lease-perm");
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        create_lease_dir(&lease_dir, RUNTIME_DIR_MODE, uid, gid).unwrap();

        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "tok".to_string(),
        };
        let ext_dir = generate_agent_extension(&lease_dir, &metadata, uid, gid).unwrap();
        let mode = fs::symlink_metadata(&ext_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }

    #[test]
    fn test_worker_js_permissions_are_0600() {
        let dir = tempfile::tempdir().unwrap();
        let root = setup_runtime_root(dir.path());
        let lease_dir = root.join("lease-wperm");
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        create_lease_dir(&lease_dir, RUNTIME_DIR_MODE, uid, gid).unwrap();

        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "tok".to_string(),
        };
        let ext_dir = generate_agent_extension(&lease_dir, &metadata, uid, gid).unwrap();
        let mode = fs::symlink_metadata(ext_dir.join("worker.js"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn test_manifest_json_permissions_are_0644() {
        let dir = tempfile::tempdir().unwrap();
        let root = setup_runtime_root(dir.path());
        let lease_dir = root.join("lease-mperm");
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        create_lease_dir(&lease_dir, RUNTIME_DIR_MODE, uid, gid).unwrap();

        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "tok".to_string(),
        };
        let ext_dir = generate_agent_extension(&lease_dir, &metadata, uid, gid).unwrap();
        let manifest_mode = fs::symlink_metadata(ext_dir.join("manifest.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(manifest_mode, 0o644);
    }

    #[test]
    fn test_generated_scripts_have_no_unresolved_placeholders() {
        let dir = tempfile::tempdir().unwrap();
        let root = setup_runtime_root(dir.path());
        let lease_dir = root.join("lease-noplace");
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        create_lease_dir(&lease_dir, RUNTIME_DIR_MODE, uid, gid).unwrap();

        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "tok".to_string(),
        };
        let ext_dir = generate_agent_extension(&lease_dir, &metadata, uid, gid).unwrap();
        let content = fs::read_to_string(ext_dir.join("worker.js")).unwrap();
        assert!(
            !content.contains(EXTENSION_PLACEHOLDER_PREFIX),
            "worker.js has an unresolved placeholder"
        );
    }

    #[test]
    fn test_no_metadata_file_written() {
        let dir = tempfile::tempdir().unwrap();
        let root = setup_runtime_root(dir.path());
        let lease_dir = root.join("lease-nometa");
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        create_lease_dir(&lease_dir, RUNTIME_DIR_MODE, uid, gid).unwrap();

        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "tok".to_string(),
        };
        let ext_dir = generate_agent_extension(&lease_dir, &metadata, uid, gid).unwrap();
        for entry in fs::read_dir(&lease_dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().to_string();
            assert!(!name.contains("metadata"), "found metadata file: {}", name);
        }
        for entry in fs::read_dir(&ext_dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().to_string();
            assert!(
                !name.contains("metadata"),
                "found metadata file in ext dir: {}",
                name
            );
        }
    }

    #[test]
    fn test_manifest_json_is_valid_mv3() {
        let manifest_str = include_str!("../../assets/agent-extension/manifest.json");
        let parsed: serde_json::Value = serde_json::from_str(manifest_str).unwrap();
        assert_eq!(parsed["manifest_version"], 3);
        assert_eq!(parsed["name"], "passless-agent");
    }

    #[test]
    fn test_manifest_has_service_worker() {
        let manifest_str = include_str!("../../assets/agent-extension/manifest.json");
        let parsed: serde_json::Value = serde_json::from_str(manifest_str).unwrap();
        assert_eq!(parsed["background"]["service_worker"], "worker.js");
    }

    #[test]
    fn test_manifest_is_a_worker_only_webauthn_proxy() {
        let parsed: serde_json::Value = serde_json::from_str(EXTENSION_MANIFEST_TEMPLATE).unwrap();
        let permissions: Vec<&str> = parsed["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap())
            .collect();
        assert_eq!(
            permissions,
            ["webAuthenticationProxy", "nativeMessaging", "storage"]
        );
        assert!(parsed.get("content_scripts").is_none());
        assert!(parsed.get("host_permissions").is_none());
        assert_eq!(parsed["incognito"], "spanning");
        assert!(!parsed["key"].as_str().unwrap().is_empty());
    }

    #[test]
    fn test_worker_js_template_syntax_valid() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let path = format!("{}/assets/agent-extension/worker.js", manifest_dir);
        let status = std::process::Command::new("node")
            .arg("--check")
            .arg(&path)
            .status();
        if let Ok(s) = status {
            assert!(s.success(), "worker.js has syntax errors");
        }
    }

    #[test]
    fn test_generated_scripts_pass_node_check() {
        let dir = tempfile::tempdir().unwrap();
        let root = setup_runtime_root(dir.path());
        let lease_dir = root.join("lease-nodecheck");
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        create_lease_dir(&lease_dir, RUNTIME_DIR_MODE, uid, gid).unwrap();

        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "tok".to_string(),
        };
        let ext_dir = generate_agent_extension(&lease_dir, &metadata, uid, gid).unwrap();
        let status = std::process::Command::new("node")
            .arg("--check")
            .arg(ext_dir.join("worker.js"))
            .status();
        if let Ok(s) = status {
            assert!(s.success(), "generated worker.js has syntax errors");
        }
    }

    #[test]
    fn test_launch_pending_without_agent_endpoint_skips_extension() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch_pending(&config, test_profile_id()).unwrap();

        let lease = &mgr.leases[&lease_id];
        let runtime_dir = &lease.manifest.runtime_dir;
        assert!(
            !runtime_dir.join(AGENT_EXTENSION_DIR).exists(),
            "extension dir should not exist without agent endpoint"
        );
    }

    #[test]
    fn test_launch_pending_with_none_agent_endpoint_skips_extension() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr
            .launch_pending_with_agent_endpoint(&config, test_profile_id(), None)
            .unwrap();

        let lease = &mgr.leases[&lease_id];
        let runtime_dir = &lease.manifest.runtime_dir;
        assert!(!runtime_dir.join(AGENT_EXTENSION_DIR).exists());
    }

    #[test]
    fn test_launch_pending_with_agent_endpoint_creates_extension() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "deadbeef".to_string(),
        };
        let lease_id = mgr
            .launch_pending_with_agent_endpoint(&config, test_profile_id(), Some(&metadata))
            .unwrap();

        let lease = &mgr.leases[&lease_id];
        let runtime_dir = &lease.manifest.runtime_dir;
        let ext_dir = runtime_dir.join(AGENT_EXTENSION_DIR);
        assert!(ext_dir.is_dir());
        assert!(ext_dir.join("manifest.json").exists());
        assert!(ext_dir.join("worker.js").exists());

        let worker_content = fs::read_to_string(ext_dir.join("worker.js")).unwrap();
        assert!(worker_content.contains("/tmp/test/sock"));
        assert!(worker_content.contains("deadbeef"));
    }

    #[test]
    fn test_launch_pending_with_agent_endpoint_no_metadata_file() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "tok".to_string(),
        };
        let lease_id = mgr
            .launch_pending_with_agent_endpoint(&config, test_profile_id(), Some(&metadata))
            .unwrap();

        let lease = &mgr.leases[&lease_id];
        let runtime_dir = &lease.manifest.runtime_dir;
        for entry in fs::read_dir(runtime_dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().to_string();
            assert!(
                !name.contains("metadata"),
                "no metadata file should be written, found: {}",
                name
            );
        }
    }

    #[test]
    fn test_browser_command_uses_generated_extension_dir() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "tok".to_string(),
        };
        let lease_id = mgr
            .launch_pending_with_agent_endpoint(&config, test_profile_id(), Some(&metadata))
            .unwrap();

        let lease = &mgr.leases[&lease_id];
        let profile_dir = &lease.manifest.profile_dir;
        let cmd = build_browser_command(&config, profile_dir).unwrap();
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert!(
            args.iter().any(|a| a.starts_with("--load-extension=")),
            "should load extension when metadata provided"
        );
        assert!(!args.iter().any(|a| a == "--disable-extensions"));
    }

    #[test]
    fn test_browser_command_fails_closed_without_extension() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr.launch_pending(&config, test_profile_id()).unwrap();

        let lease = &mgr.leases[&lease_id];
        let profile_dir = &lease.manifest.profile_dir;
        let err = build_browser_command(&config, profile_dir).unwrap_err();
        assert!(matches!(err, LaunchError::ExtensionSetupFailed(_)));
    }

    #[test]
    fn test_agent_extension_behavioral_node_suite() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let test_path = format!("{manifest_dir}/tests/agent_extension_behavioral.js");
        let status = std::process::Command::new("node").arg(&test_path).status();
        if let Ok(s) = status {
            assert!(s.success(), "agent extension behavioral suite failed");
        }
    }

    #[test]
    fn test_generated_worker_js_parses_with_special_character_bearer() {
        let dir = tempfile::tempdir().unwrap();
        let root = setup_runtime_root(dir.path());
        let lease_dir = root.join("lease-bearer-special");
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        create_lease_dir(&lease_dir, RUNTIME_DIR_MODE, uid, gid).unwrap();

        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "tok\"en\\with\nspecial\u{00e9}".to_string(),
        };
        let ext_dir = generate_agent_extension(&lease_dir, &metadata, uid, gid).unwrap();
        let path = ext_dir.join("worker.js");
        let status = std::process::Command::new("node")
            .arg("--check")
            .arg(&path)
            .status();
        if let Ok(s) = status {
            assert!(
                s.success(),
                "generated worker.js with special bearer has syntax errors"
            );
        }
    }

    #[test]
    fn test_generated_bearer_is_only_in_the_worker() {
        let dir = tempfile::tempdir().unwrap();
        let root = setup_runtime_root(dir.path());
        let lease_dir = root.join("lease-bearer-iso");
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        create_lease_dir(&lease_dir, RUNTIME_DIR_MODE, uid, gid).unwrap();

        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "supersecretbearertoken".to_string(),
        };
        let ext_dir = generate_agent_extension(&lease_dir, &metadata, uid, gid).unwrap();
        let manifest = fs::read_to_string(ext_dir.join("manifest.json")).unwrap();
        assert!(!manifest.contains("supersecretbearertoken"));
        let worker = fs::read_to_string(ext_dir.join("worker.js")).unwrap();
        assert!(worker.contains("supersecretbearertoken"));
    }

    #[test]
    fn test_extension_cleanup_removes_worker_token() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let spawner: Arc<dyn ChildSpawner> = Arc::new(DirectExecSpawner);
        let mut mgr = BrowserProcessManager::with_spawner(clock, spawner);
        let mut config = test_config(dir.path());

        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "cleanup-test-token-xyz".to_string(),
        };
        config.executable = PathBuf::from("/bin/sleep");
        config.extra_args = vec!["60".to_string()];

        let lease_id = mgr
            .launch_pending_with_agent_endpoint(&config, test_profile_id(), Some(&metadata))
            .unwrap();
        let runtime_dir = mgr.leases[&lease_id].manifest.runtime_dir.clone();
        let ext_dir = runtime_dir.join(AGENT_EXTENSION_DIR);
        let worker_path = ext_dir.join("worker.js");
        let worker_content = fs::read_to_string(&worker_path).unwrap();
        assert!(worker_content.contains("cleanup-test-token-xyz"));

        mgr.terminate(&lease_id).unwrap();
        let safety = mgr.cleanup(&lease_id).unwrap();
        assert!(matches!(safety, CleanupSafety::Clean));
        assert!(!runtime_dir.exists());
    }

    #[test]
    fn test_extension_quarantine_contains_worker_token_on_cleanup_failure() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let spawner: Arc<dyn ChildSpawner> = Arc::new(DirectExecSpawner);
        let mut mgr = BrowserProcessManager::with_spawner(clock, spawner);
        let mut config = test_config(dir.path());
        config.executable = PathBuf::from("/bin/sleep");
        config.extra_args = vec!["60".to_string()];

        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "quarantine-token-abc".to_string(),
        };
        let lease_id = mgr
            .launch_pending_with_agent_endpoint(&config, test_profile_id(), Some(&metadata))
            .unwrap();
        let _runtime_dir = mgr.leases[&lease_id].manifest.runtime_dir.clone();
        let profile_dir = mgr.leases[&lease_id].manifest.profile_dir.clone();

        mgr.terminate(&lease_id).unwrap();

        let _ = fs::remove_dir_all(&profile_dir);
        let real_elsewhere = dir.path().join("elsewhere");
        fs::create_dir(&real_elsewhere).unwrap();
        unix_fs::symlink(&real_elsewhere, &profile_dir).unwrap();

        let safety = mgr.cleanup(&lease_id).unwrap();
        match safety {
            CleanupSafety::Quarantined {
                ref quarantine_path,
                ..
            } => {
                let ext_dir = quarantine_path.join(AGENT_EXTENSION_DIR);
                let worker_path = ext_dir.join("worker.js");
                if worker_path.exists() {
                    let content = fs::read_to_string(&worker_path).unwrap();
                    assert!(
                        content.contains("quarantine-token-abc"),
                        "quarantined worker should still contain the bearer token"
                    );
                }
                let _ = fs::remove_dir_all(quarantine_path);
            }
            CleanupSafety::Failed { .. } => {}
            CleanupSafety::Clean => panic!("expected quarantine or failure"),
        }
    }

    #[test]
    fn test_build_browser_command_loads_extension_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let runtime_dir = dir.path().join("runtime");
        let profile_dir = runtime_dir.join("profile");
        let ext_dir = runtime_dir.join(AGENT_EXTENSION_DIR);
        fs::create_dir_all(&profile_dir).unwrap();
        write_valid_extension(&ext_dir);

        let config = BrowserConfig {
            executable: PathBuf::from("/usr/bin/chromium"),
            start_url: None,
            extra_args: Vec::new(),
            runtime_root: dir.path().to_path_buf(),
            ttl: Duration::from_secs(300),
            login_timeout: DEFAULT_LOGIN_TIMEOUT,
            rp_ids: vec!["example.com".to_string()],
            start_url_rules: start_url_test_rules(&[("example.com", RuleAction::Allow)]),
            target_uid: 1000,
            target_gid: 1000,
            daemon_uid: 0,
            daemon_gid: 0,
            cdp_expose: CdpExposeMode::Pipe,
            cdp_port: 9222,
            bind_parent_death: true,
        };

        let cmd = build_browser_command(&config, &profile_dir).unwrap();
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert!(args.iter().any(|a| a.starts_with("--load-extension=")));
        assert!(!args.iter().any(|a| a == "--disable-extensions"));
    }

    fn extension_test_config(dir: &Path) -> BrowserConfig {
        let mut config = test_config(dir);
        config.executable = PathBuf::from("/usr/bin/chromium");
        config
    }

    #[test]
    fn test_build_browser_command_fails_closed_when_no_dir() {
        let dir = tempfile::tempdir().unwrap();
        let profile_dir = dir.path().join("no-ext").join("profile");
        fs::create_dir_all(&profile_dir).unwrap();
        let config = extension_test_config(dir.path());

        let err = build_browser_command(&config, &profile_dir).unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, LaunchError::ExtensionSetupFailed(_)), "{msg}");
        assert!(msg.contains("agent extension"), "{msg}");
        assert!(msg.contains("refusing to launch"), "{msg}");
    }

    /// [`verify_extension_dir`] with the test user as the worker's owner.
    fn verify_ext(ext_dir: &Path) -> Result<(), LaunchError> {
        verify_extension_dir(ext_dir, unsafe { libc::geteuid() })
    }

    /// A planted `manifest.json` or `worker.js` symlink to an endless device or a FIFO must be
    /// refused promptly, not read (the daemon runs as root and would hang or exhaust memory).
    #[test]
    fn test_verify_extension_dir_never_reads_a_planted_device_symlink_or_fifo() {
        for victim in [EXTENSION_WORKER, "manifest.json"] {
            for kind in ["symlink", "fifo", "oversize"] {
                let dir = tempfile::tempdir().unwrap();
                let ext = dir.path().join("ext");
                write_valid_extension(&ext);
                let planted = ext.join(victim);
                fs::remove_file(&planted).unwrap();
                match kind {
                    "symlink" => std::os::unix::fs::symlink("/dev/zero", &planted).unwrap(),
                    "fifo" => {
                        let c = std::ffi::CString::new(planted.as_os_str().as_bytes()).unwrap();
                        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
                    }
                    _ => fs::write(&planted, vec![b' '; 2 * 1024 * 1024]).unwrap(),
                }
                let started = std::time::Instant::now();
                let err = verify_ext(&ext).unwrap_err();
                assert!(
                    started.elapsed() < Duration::from_secs(5),
                    "{victim} {kind}"
                );
                assert!(
                    matches!(err, LaunchError::ExtensionSetupFailed(_)),
                    "{victim} {kind}: {err}"
                );
                if kind != "oversize" {
                    assert!(extension_id_of_dir(&ext).is_err() || victim == EXTENSION_WORKER);
                }
            }
        }
        // The extension directory itself must not be a symlink either.
        let dir = tempfile::tempdir().unwrap();
        write_valid_extension(&dir.path().join("real"));
        std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("ext")).unwrap();
        assert!(verify_ext(&dir.path().join("ext")).is_err());
    }

    /// Writes an extension directory that has what the generator emits: the real manifest template
    /// and a rendered worker.
    fn write_valid_extension(ext_dir: &Path) {
        fs::create_dir_all(ext_dir).unwrap();
        fs::write(ext_dir.join("manifest.json"), EXTENSION_MANIFEST_TEMPLATE).unwrap();
        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "tok".to_string(),
        };
        fs::write(
            ext_dir.join(EXTENSION_WORKER),
            render_worker_script(EXTENSION_WORKER_TEMPLATE, &metadata),
        )
        .unwrap();
    }

    fn manifest_with(edit: impl FnOnce(&mut serde_json::Value)) -> String {
        let mut manifest: serde_json::Value =
            serde_json::from_str(include_str!("../../assets/agent-extension/manifest.json"))
                .unwrap();
        edit(&mut manifest);
        manifest.to_string()
    }

    #[test]
    fn test_verify_extension_dir_accepts_the_generated_extension() {
        let dir = tempfile::tempdir().unwrap();
        write_valid_extension(&dir.path().join("ext"));
        verify_ext(&dir.path().join("ext")).unwrap();

        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "tok".to_string(),
        };
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let generated = generate_agent_extension(dir.path(), &metadata, uid, gid).unwrap();
        verify_ext(&generated).unwrap();
    }

    #[test]
    fn test_verify_extension_dir_rejects_unusable_directories() {
        let dir = tempfile::tempdir().unwrap();

        // Missing directory.
        assert!(verify_ext(&dir.path().join("missing")).is_err());

        // A file instead of a directory.
        let file = dir.path().join("file");
        fs::write(&file, "{}").unwrap();
        assert!(verify_ext(&file).is_err());

        // Directory without a manifest.
        let empty = dir.path().join("empty");
        fs::create_dir(&empty).unwrap();
        assert!(verify_ext(&empty).is_err());

        // Unreadable manifest (a directory where the file should be).
        let unreadable = dir.path().join("unreadable");
        fs::create_dir_all(unreadable.join("manifest.json")).unwrap();
        assert!(verify_ext(&unreadable).is_err());

        // Manifest that is not a JSON object.
        let garbage = dir.path().join("garbage");
        fs::create_dir(&garbage).unwrap();
        fs::write(garbage.join("manifest.json"), "not json").unwrap();
        assert!(verify_ext(&garbage).is_err());
    }

    #[test]
    fn test_verify_extension_dir_requires_a_non_empty_rendered_worker() {
        let dir = tempfile::tempdir().unwrap();
        let ext = dir.path().join("ext");
        write_valid_extension(&ext);
        let worker = ext.join(EXTENSION_WORKER);

        fs::remove_file(&worker).unwrap();
        let err = verify_ext(&ext).unwrap_err().to_string();
        assert!(err.contains("worker.js"), "missing worker: {err}");

        fs::write(&worker, "").unwrap();
        let err = verify_ext(&ext).unwrap_err().to_string();
        assert!(err.contains("worker.js"), "empty worker: {err}");

        // The unrendered template: every placeholder is still there.
        fs::write(&worker, EXTENSION_WORKER_TEMPLATE).unwrap();
        let err = verify_ext(&ext).unwrap_err().to_string();
        assert!(err.contains("placeholder"), "template worker: {err}");

        // A single placeholder left behind is enough to refuse.
        for placeholder in [
            "__PASSLESS_BEARER__",
            "__PASSLESS_SOCKET_PATH__",
            "__PASSLESS_BUILD_VERSION__",
        ] {
            fs::write(&worker, format!("f(\"tok\", {placeholder});")).unwrap();
            let err = verify_ext(&ext).unwrap_err();
            assert!(
                matches!(err, LaunchError::ExtensionSetupFailed(_)),
                "{placeholder}: {err}"
            );
            assert!(err.to_string().contains("refusing to launch"), "{err}");
        }

        fs::write(&worker, "// ok").unwrap();
        verify_ext(&ext).unwrap();
    }

    #[test]
    fn test_verify_extension_dir_requires_interception_in_the_manifest() {
        type ManifestEdit = Box<dyn Fn(&mut serde_json::Value)>;
        let cases: Vec<(&str, ManifestEdit)> = vec![
            (
                "webAuthenticationProxy permission",
                Box::new(|m| m["permissions"] = serde_json::json!(["nativeMessaging", "storage"])),
            ),
            (
                "nativeMessaging permission",
                Box::new(|m| {
                    m["permissions"] = serde_json::json!(["webAuthenticationProxy", "storage"])
                }),
            ),
            (
                "no permissions",
                Box::new(|m| {
                    m.as_object_mut().unwrap().remove("permissions");
                }),
            ),
            (
                "service worker",
                Box::new(|m| m["background"]["service_worker"] = serde_json::json!("other.js")),
            ),
            (
                "no background",
                Box::new(|m| {
                    m.as_object_mut().unwrap().remove("background");
                }),
            ),
            (
                "missing key",
                Box::new(|m| {
                    m.as_object_mut().unwrap().remove("key");
                }),
            ),
            ("empty key", Box::new(|m| m["key"] = serde_json::json!(""))),
            (
                "content scripts present",
                Box::new(|m| {
                    m["content_scripts"] = serde_json::json!([{
                        "matches": ["https://*/*"],
                        "js": ["main.js"],
                        "world": "MAIN",
                    }])
                }),
            ),
            (
                "empty content scripts",
                Box::new(|m| m["content_scripts"] = serde_json::json!([])),
            ),
        ];
        for (name, edit) in cases {
            let dir = tempfile::tempdir().unwrap();
            let ext = dir.path().join("ext");
            write_valid_extension(&ext);
            fs::write(ext.join("manifest.json"), manifest_with(edit)).unwrap();
            let err = verify_ext(&ext);
            assert!(
                matches!(err, Err(LaunchError::ExtensionSetupFailed(_))),
                "{name} must be rejected"
            );
        }
    }

    struct CountingSpawner(Arc<std::sync::atomic::AtomicUsize>);

    impl ChildSpawner for CountingSpawner {
        fn spawn_browser(
            &self,
            _config: &BrowserConfig,
            _profile_dir: &Path,
            _cdp: &CdpPipes,
            _containment: &ContainmentPlan,
        ) -> Result<Child, LaunchError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Command::new("/bin/true")
                .spawn()
                .map_err(|e| LaunchError::SpawnFailed(e.to_string()))
        }
    }

    #[test]
    fn test_launch_with_missing_extension_is_an_error_and_spawns_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let spawned = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut mgr = BrowserProcessManager::with_spawner(
            test_clock(),
            Arc::new(CountingSpawner(spawned.clone())),
        );
        let config = test_config(dir.path());
        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "tok".to_string(),
        };

        OMIT_EXTENSION.with(|c| c.set(true));
        let result =
            mgr.launch_pending_with_agent_endpoint(&config, test_profile_id(), Some(&metadata));
        OMIT_EXTENSION.with(|c| c.set(false));

        let err = result.unwrap_err();
        assert!(matches!(err, LaunchError::ExtensionSetupFailed(_)), "{err}");
        assert!(err.to_string().contains("agent extension"), "{err}");
        assert_eq!(spawned.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(mgr.leases.is_empty(), "no lease for a launch that failed");
        assert_no_lease_dirs(&config.runtime_root);
    }

    fn assert_no_lease_dirs(runtime_root: &Path) {
        let left: Vec<_> = fs::read_dir(runtime_root)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(
            left.is_empty(),
            "a failed launch must remove the lease runtime dir (it holds the worker token): {left:?}"
        );
    }

    #[test]
    fn test_failed_launch_after_extension_generation_removes_runtime_dir() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = BrowserProcessManager::new(test_clock());
        let mut config = test_config(dir.path());
        // Fails after the extension (and its bearer token) was written.
        config.start_url = Some("https://not-in-scope.invalid/".to_string());
        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "secret-token".to_string(),
        };

        let err = mgr
            .launch_pending_with_agent_endpoint(&config, test_profile_id(), Some(&metadata))
            .unwrap_err();
        assert!(matches!(err, LaunchError::InvalidStartUrl(_)), "{err}");
        assert_no_lease_dirs(&config.runtime_root);
    }

    #[test]
    fn test_successful_launch_keeps_runtime_dir() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = BrowserProcessManager::new(test_clock());
        let config = test_config(dir.path());
        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "tok".to_string(),
        };
        let lease_id = mgr
            .launch_pending_with_agent_endpoint(&config, test_profile_id(), Some(&metadata))
            .unwrap();
        assert!(mgr.leases[&lease_id].manifest.runtime_dir.is_dir());
    }

    #[test]
    fn test_agent_endpoint_metadata_serde_roundtrip() {
        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "abc123".to_string(),
        };
        let json = serde_json::to_string(&metadata).unwrap();
        let parsed: AgentEndpointMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, metadata);
    }

    #[test]
    fn test_extension_setup_failed_display() {
        let e = LaunchError::ExtensionSetupFailed("test error".to_string());
        assert!(e.to_string().contains("extension setup failed"));
        assert!(e.to_string().contains("test error"));
    }

    #[test]
    fn test_is_managed_extension_or_profile_flag() {
        assert!(is_managed_extension_or_profile_flag(
            "--load-extension=/tmp/ext"
        ));
        assert!(is_managed_extension_or_profile_flag("--load-extension"));
        assert!(is_managed_extension_or_profile_flag("--disable-extensions"));
        assert!(is_managed_extension_or_profile_flag(
            "--disable-extensions-except=/tmp/ext"
        ));
        assert!(is_managed_extension_or_profile_flag(
            "--disable-extensions-except"
        ));
        assert!(is_managed_extension_or_profile_flag(
            "--user-data-dir=/tmp/profile"
        ));
        assert!(is_managed_extension_or_profile_flag("--user-data-dir"));
        assert!(is_managed_extension_or_profile_flag(
            "--allowlisted-extension-id=abc"
        ));
        assert!(is_managed_extension_or_profile_flag(
            "--disable-extensions-file-access-check"
        ));
        assert!(!is_managed_extension_or_profile_flag("--incognito"));
        assert!(!is_managed_extension_or_profile_flag(
            "--window-size=800,600"
        ));
        assert!(!is_managed_extension_or_profile_flag("--disable-sync"));
    }

    /// Review M2: a browser that runs as another user gets limits Chromium can live with.
    #[test]
    fn test_browser_hardening_rlimits_fit_chromium() {
        let dir = tempfile::tempdir().unwrap();
        let hardening = test_config(dir.path()).hardening();
        assert_eq!(hardening.rlimit_as, libc::RLIM_INFINITY);
        assert!(hardening.rlimit_nproc >= 1024);
        assert!(hardening.rlimit_nofile >= 4096);
        assert_eq!(hardening.rlimit_core, 0);
    }

    #[test]
    fn test_browser_config_hardening_preserves_bind_parent_death_true() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = test_config(dir.path());
        config.bind_parent_death = true;
        let setup = config.hardening();
        assert!(setup.bind_parent_death);
    }

    #[test]
    fn test_browser_config_hardening_preserves_bind_parent_death_false() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = test_config(dir.path());
        config.bind_parent_death = false;
        let setup = config.hardening();
        assert!(!setup.bind_parent_death);
    }

    #[test]
    fn test_cdp_discovery_timeout_names_the_extension_and_says_the_browser_was_stopped() {
        let message = LaunchError::CdpDiscoveryTimeout.to_string();
        assert!(message.contains("timed out waiting for browser CDP endpoint"));
        assert!(message.contains("extension"), "{message}");
        assert!(message.contains("was stopped"), "{message}");
    }

    /// A failed launch (the CDP wait timed out) kills the whole process tree: the wrapper that is
    /// the lease's pid (bwrap) and the browser it forked, not only the direct child.
    #[test]
    fn test_terminate_failed_browser_spawn_kills_the_whole_process_group() {
        use std::os::unix::process::CommandExt;

        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("grandchild.pid");
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(format!("sleep 60 & echo $! > {}; wait", pid_file.display()));
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let grandchild: i32 = loop {
            if let Some(pid) = fs::read_to_string(&pid_file)
                .ok()
                .and_then(|s| s.trim().parse().ok())
            {
                break pid;
            }
            assert!(Instant::now() < deadline, "the grandchild never started");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(unsafe { libc::kill(grandchild, 0) }, 0, "grandchild alive");

        terminate_failed_browser_spawn(&mut child);

        let deadline = Instant::now() + Duration::from_secs(5);
        while unsafe { libc::kill(grandchild, 0) } == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        // The orphaned grandchild is reparented and reaped by init; a zombie still answers kill(0).
        let state = fs::read_to_string(format!("/proc/{grandchild}/stat"))
            .ok()
            .and_then(|s| s.rsplit(')').next().map(|r| r.trim_start().chars().next()))
            .flatten();
        assert!(
            matches!(state, None | Some('Z')),
            "the grandchild survived the failed launch: state {state:?}"
        );
    }

    #[test]
    fn test_child_survives_spawning_thread_exit_without_pdeathsig() {
        use std::os::unix::process::CommandExt;

        let child = std::thread::spawn(|| {
            let mut cmd = Command::new("/bin/sh");
            cmd.arg("-c").arg("sleep 60");
            cmd.stdin(Stdio::null());
            cmd.stdout(Stdio::null());
            cmd.stderr(Stdio::null());
            unsafe {
                cmd.pre_exec(|| {
                    if libc::setsid() < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            cmd.spawn().unwrap()
        });

        let mut child = child.join().unwrap();
        std::thread::sleep(Duration::from_millis(200));

        let exit = child.try_wait().unwrap();
        assert!(
            exit.is_none(),
            "child should survive spawning thread exit when PDEATHSIG is not set"
        );

        unsafe { libc::kill(child.id() as i32, libc::SIGKILL) };
        let _ = child.wait();
    }

    #[test]
    fn test_child_killed_by_pdeathsig_when_spawning_thread_exits() {
        use std::os::unix::process::CommandExt;

        let child = std::thread::spawn(|| {
            let mut cmd = Command::new("/bin/sh");
            cmd.arg("-c").arg("sleep 60");
            cmd.stdin(Stdio::null());
            cmd.stdout(Stdio::null());
            cmd.stderr(Stdio::null());
            unsafe {
                cmd.pre_exec(|| {
                    if libc::setsid() < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            cmd.spawn().unwrap()
        });

        let mut child = child.join().unwrap();
        std::thread::sleep(Duration::from_millis(500));

        let exit = child.try_wait().unwrap();
        assert!(
            exit.is_some(),
            "child should be killed by PDEATHSIG when spawning thread exits"
        );
    }

    // --- P6: interception readiness (plan D6 layer 1) and defect B2 -------------------------------

    /// Records the argv the real command builder makes, then runs a long-lived stand-in browser in
    /// its own process group.
    struct ArgvRecordingSpawner(Arc<std::sync::Mutex<Vec<String>>>);

    impl ChildSpawner for ArgvRecordingSpawner {
        fn spawn_browser(
            &self,
            config: &BrowserConfig,
            profile_dir: &Path,
            _cdp: &CdpPipes,
            _containment: &ContainmentPlan,
        ) -> Result<Child, LaunchError> {
            let cmd = build_browser_command(config, profile_dir)?;
            *self.0.lock().unwrap() = cmd
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            let mut stand_in = Command::new("/bin/sleep");
            stand_in.arg("60");
            unsafe {
                stand_in.pre_exec(|| {
                    if libc::setsid() < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            stand_in
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| LaunchError::SpawnFailed(e.to_string()))
        }
    }

    /// Records every start URL it is asked to open, with the readiness seen at that moment.
    #[derive(Default)]
    struct RecordingOpener {
        opened: std::sync::Mutex<Vec<(String, bool)>>,
        readiness: std::sync::Mutex<Option<(Arc<ReadinessRegistry>, String)>>,
    }

    impl StartUrlOpener for RecordingOpener {
        fn open(
            &self,
            _manager: &mut BrowserProcessManager,
            _lease_id: &BrowserLeaseId,
            url: &str,
        ) -> Result<(), String> {
            let attached = self
                .readiness
                .lock()
                .unwrap()
                .as_ref()
                .and_then(|(registry, bearer)| registry.status(bearer))
                .is_some_and(|s| s.connected && s.attached);
            self.opened
                .lock()
                .unwrap()
                .push((url.to_string(), attached));
            Ok(())
        }
    }

    const START_URL: &str = "https://example.com/login";
    const BEARER: &str = "interception-test-bearer";

    struct InterceptedLaunch {
        _dir: tempfile::TempDir,
        mgr: BrowserProcessManager,
        lease_id: BrowserLeaseId,
        argv: Vec<String>,
        opener: Arc<RecordingOpener>,
        readiness: Arc<ReadinessRegistry>,
        runtime_root: PathBuf,
    }

    fn intercepted_launch() -> InterceptedLaunch {
        let dir = tempfile::tempdir().unwrap();
        let argv = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut mgr = BrowserProcessManager::with_spawner(
            test_clock(),
            Arc::new(ArgvRecordingSpawner(argv.clone())),
        );
        let readiness = Arc::new(ReadinessRegistry::new());
        let opener = Arc::new(RecordingOpener::default());
        *opener.readiness.lock().unwrap() = Some((readiness.clone(), BEARER.to_string()));
        mgr.set_start_url_opener(opener.clone());
        let mut config = test_config(dir.path());
        config.executable = PathBuf::from("/usr/bin/chromium");
        config.start_url = Some(START_URL.to_string());
        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: BEARER.to_string(),
        };
        let lease_id = mgr
            .launch_pending_with_agent_endpoint(&config, test_profile_id(), Some(&metadata))
            .unwrap();
        let argv = argv.lock().unwrap().clone();
        InterceptedLaunch {
            _dir: dir,
            mgr,
            lease_id,
            argv,
            opener,
            readiness,
            runtime_root: config.runtime_root,
        }
    }

    impl Drop for InterceptedLaunch {
        fn drop(&mut self) {
            let _ = self.mgr.terminate(&self.lease_id);
        }
    }

    /// B2 regression: the intercepted browser is spawned on a blank page, never on the start URL.
    #[test]
    fn test_b2_intercepted_launch_spawns_without_the_start_url() {
        let mut launch = intercepted_launch();
        assert!(!launch.argv.is_empty(), "the spawner saw the real argv");
        assert!(
            !launch.argv.iter().any(|a| a.contains("example.com")),
            "the start URL must not be in the spawn argv: {:?}",
            launch.argv
        );
        assert_eq!(
            launch.argv.last().map(String::as_str),
            Some(BLANK_START_URL)
        );
        assert!(
            launch
                .argv
                .iter()
                .any(|a| a.starts_with("--load-extension="))
        );
        // The lease still reports the URL it will open.
        let snapshot = launch.mgr.snapshot(&launch.lease_id).unwrap();
        assert_eq!(snapshot.start_url.as_deref(), Some(START_URL));
        // Nothing opens it before the worker attached.
        assert!(
            launch
                .mgr
                .open_deferred_start_url(&launch.lease_id)
                .is_err()
        );
        assert!(launch.opener.opened.lock().unwrap().is_empty());
    }

    #[test]
    fn test_launch_without_extension_keeps_the_start_url_in_argv() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = test_config(dir.path());
        config.start_url = Some(START_URL.to_string());
        let cmd = build_browser_command_unverified(&config, dir.path()).unwrap();
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args.last().map(String::as_str), Some(START_URL));
    }

    /// B2 regression: the start URL is opened only after the worker said hello with
    /// `attached = true`, and only once.
    #[test]
    fn test_b2_start_url_opens_only_after_the_worker_attached() {
        let mut launch = intercepted_launch();
        let readiness = launch.readiness.clone();
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            // The worker connects before attach() resolved, then reports the attachment.
            readiness.simulate_hello(BEARER, 1, false, false);
            std::thread::sleep(Duration::from_millis(200));
            readiness.simulate_hello(BEARER, 1, true, true);
        });
        let state = launch
            .mgr
            .await_interception(&launch.lease_id, &launch.readiness, Duration::from_secs(10))
            .unwrap();
        worker.join().unwrap();
        assert!(state.connected && state.attached);
        assert!(state.incognito_allowed);
        assert!(launch.opener.opened.lock().unwrap().is_empty());

        let opened = launch.mgr.open_deferred_start_url(&launch.lease_id);
        assert_eq!(opened, Ok(Some(START_URL.to_string())));
        assert_eq!(
            *launch.opener.opened.lock().unwrap(),
            [(START_URL.to_string(), true)],
            "opened once, with interception attached"
        );
        assert_eq!(
            launch.mgr.open_deferred_start_url(&launch.lease_id),
            Ok(None)
        );
        assert_eq!(launch.opener.opened.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_launch_fails_closed_when_the_worker_never_attaches() {
        let mut launch = intercepted_launch();
        // A worker that connects but whose attach() failed is not ready either.
        launch.readiness.simulate_hello(BEARER, 1, false, true);
        let started = Instant::now();
        let err = launch
            .mgr
            .await_interception(
                &launch.lease_id,
                &launch.readiness,
                Duration::from_millis(400),
            )
            .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(
            matches!(err, LaunchError::InterceptionNotAttached(_)),
            "{err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("did not attach the WebAuthn proxy"),
            "actionable: {msg}"
        );
        assert!(msg.contains("attached = false"), "{msg}");
        assert!(launch.opener.opened.lock().unwrap().is_empty());
        assert!(
            launch
                .mgr
                .open_deferred_start_url(&launch.lease_id)
                .is_err()
        );

        // The runtime's failure path: the browser is stopped and its runtime dir (with the
        // worker's bearer) removed.
        let lease_id = launch.lease_id.clone();
        let _ = launch.mgr.revoke(&lease_id);
        launch.mgr.terminate(&lease_id).unwrap();
        assert!(matches!(
            launch.mgr.cleanup(&lease_id).unwrap(),
            CleanupSafety::Clean
        ));
        launch.mgr.remove(&lease_id);
        assert_no_lease_dirs(&launch.runtime_root);
    }

    #[test]
    fn test_launch_fails_closed_when_the_worker_never_connects() {
        let mut launch = intercepted_launch();
        let err = launch
            .mgr
            .await_interception(
                &launch.lease_id,
                &launch.readiness,
                Duration::from_millis(300),
            )
            .unwrap_err();
        assert!(err.to_string().contains("never connected"), "{err}");
    }

    #[test]
    fn test_await_interception_ends_when_the_browser_exits() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = BrowserProcessManager::with_spawner(test_clock(), Arc::new(TestSpawner));
        let config = test_config(dir.path());
        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: BEARER.to_string(),
        };
        let lease_id = mgr
            .launch_pending_with_agent_endpoint(&config, test_profile_id(), Some(&metadata))
            .unwrap();
        let readiness = ReadinessRegistry::new();
        let started = Instant::now();
        let err = mgr
            .await_interception(&lease_id, &readiness, Duration::from_secs(20))
            .unwrap_err();
        assert!(err.to_string().contains("exited"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn test_await_interception_refuses_a_lease_without_the_extension() {
        let dir = tempfile::tempdir().unwrap();
        let mut mgr = BrowserProcessManager::new(test_clock());
        let lease_id = mgr
            .launch_pending(&test_config(dir.path()), test_profile_id())
            .unwrap();
        let readiness = ReadinessRegistry::new();
        assert!(
            mgr.await_interception(&lease_id, &readiness, Duration::from_millis(10))
                .is_err()
        );
        assert!(
            mgr.interception_state(&lease_id, &readiness, INTERCEPTION_DEGRADED_GRACE)
                .is_none()
        );
    }

    #[test]
    fn test_interception_degrades_after_the_grace_period_and_is_reported_once() {
        let mut launch = intercepted_launch();
        let grace = INTERCEPTION_DEGRADED_GRACE;
        let state = |launch: &InterceptedLaunch| {
            launch
                .mgr
                .interception_state(&launch.lease_id, &launch.readiness, grace)
                .unwrap()
                .0
        };
        // Before the launch saw the worker attach the lease is pending, and nothing is polled.
        assert_eq!(state(&launch), InterceptionState::Pending);
        launch.readiness.simulate_hello(BEARER, 1, true, true);
        assert!(
            launch
                .mgr
                .poll_interception(&launch.readiness, grace)
                .is_empty()
        );
        launch
            .mgr
            .await_interception(&launch.lease_id, &launch.readiness, Duration::from_secs(1))
            .unwrap();
        assert_eq!(state(&launch), InterceptionState::Attached);

        // The port drops: within the grace period the lease is pending, not degraded.
        launch.readiness.simulate_disconnect(BEARER, 1);
        assert_eq!(state(&launch), InterceptionState::Pending);
        assert!(
            launch
                .mgr
                .poll_interception(&launch.readiness, grace)
                .is_empty()
        );

        // Past the grace period it is degraded, and the change is reported exactly once.
        launch
            .readiness
            .backdate_detached(BEARER, grace + Duration::from_secs(1));
        assert_eq!(state(&launch), InterceptionState::Degraded);
        let transitions = launch.mgr.poll_interception(&launch.readiness, grace);
        assert_eq!(
            transitions,
            [InterceptionTransition {
                lease_id: launch.lease_id.clone(),
                profile_id: test_profile_id(),
                degraded: true,
            }]
        );
        assert!(
            launch
                .mgr
                .poll_interception(&launch.readiness, grace)
                .is_empty()
        );

        // A reconnect that is not attached yet does not end the episode.
        launch.readiness.simulate_hello(BEARER, 2, false, false);
        assert!(
            launch
                .mgr
                .poll_interception(&launch.readiness, grace)
                .is_empty()
        );

        // Attached without incognito access does not end it either (plan D4: off-the-record
        // contexts would not be intercepted).
        launch.readiness.simulate_hello(BEARER, 2, true, false);
        assert_eq!(state(&launch), InterceptionState::Degraded);
        assert!(
            launch
                .mgr
                .poll_interception(&launch.readiness, grace)
                .is_empty()
        );

        // The worker re-attaches: attached again, reported once.
        launch.readiness.simulate_hello(BEARER, 2, true, true);
        assert_eq!(state(&launch), InterceptionState::Attached);
        let transitions = launch.mgr.poll_interception(&launch.readiness, grace);
        assert_eq!(transitions.len(), 1);
        assert!(!transitions[0].degraded);
        assert!(
            launch
                .mgr
                .poll_interception(&launch.readiness, grace)
                .is_empty()
        );
    }

    #[test]
    fn test_connected_but_detached_worker_also_degrades() {
        let now = Instant::now();
        let grace = Duration::from_secs(10);
        let readiness = |connected, attached, detached_for: Option<u64>| BearerReadiness {
            connected,
            attached,
            incognito_allowed: true,
            build_version: None,
            relay_version: None,
            last_disconnect: None,
            detached_since: detached_for.map(|s| now - Duration::from_secs(s)),
        };
        let of =
            |r: Option<BearerReadiness>| InterceptionState::of_confirmed(r.as_ref(), now, grace);
        assert_eq!(
            of(Some(readiness(true, true, None))),
            InterceptionState::Attached
        );
        assert_eq!(
            of(Some(readiness(true, false, Some(1)))),
            InterceptionState::Pending
        );
        assert_eq!(
            of(Some(readiness(true, false, Some(11)))),
            InterceptionState::Degraded
        );
        assert_eq!(
            of(Some(readiness(false, true, Some(1)))),
            InterceptionState::Pending
        );
        assert_eq!(
            of(Some(readiness(false, true, Some(11)))),
            InterceptionState::Degraded
        );
        // Without a detach time or a record at all it fails closed.
        assert_eq!(
            of(Some(readiness(false, false, None))),
            InterceptionState::Degraded
        );
        assert_eq!(of(None), InterceptionState::Degraded);
        // Attached without incognito access is not attached (plan D4).
        let no_incognito = BearerReadiness {
            incognito_allowed: false,
            ..readiness(true, true, None)
        };
        assert_eq!(of(Some(no_incognito)), InterceptionState::Degraded);
    }

    /// Plan D4 fail-closed verification: a worker that attached the proxy but is not allowed in
    /// incognito fails the launch with the incognito error, early, and the CDP endpoint file is
    /// never written.
    #[test]
    fn test_launch_fails_closed_when_the_extension_is_not_allowed_in_incognito() {
        let mut launch = intercepted_launch();
        launch
            .mgr
            .leases
            .get_mut(&launch.lease_id)
            .unwrap()
            .cdp_endpoint = Some("ws://127.0.0.1:9333/devtools/browser/abc".to_string());
        launch.readiness.simulate_hello(BEARER, 1, true, false);
        let started = Instant::now();
        let err = launch
            .mgr
            .await_interception(&launch.lease_id, &launch.readiness, Duration::from_secs(20))
            .unwrap_err();
        assert!(
            matches!(err, LaunchError::IncognitoNotAllowed(_)),
            "{err:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "fails once the worker's state settled, not at the attach timeout"
        );
        assert!(err.to_string().contains("incognito"), "{err}");
        let file = launch.mgr.leases[&launch.lease_id]
            .manifest
            .runtime_dir
            .join("cdp-endpoint");
        assert!(!file.exists(), "no endpoint for a worker without incognito");

        // A worker whose incognito probe finished a moment after its attach is ready.
        let mut launch = intercepted_launch();
        let readiness = launch.readiness.clone();
        let worker = std::thread::spawn(move || {
            readiness.simulate_hello(BEARER, 1, true, false);
            std::thread::sleep(Duration::from_millis(300));
            readiness.simulate_hello(BEARER, 1, true, true);
        });
        let state = launch
            .mgr
            .await_interception(&launch.lease_id, &launch.readiness, Duration::from_secs(10))
            .unwrap();
        worker.join().unwrap();
        assert!(state.intercepting());
    }

    /// A pipe-mode launch through the production spawner, as the daemon does, of a stand-in
    /// browser (`exec sleep 60`) for the current user, under `containment`.
    fn production_launch(
        dir: &Path,
        containment: ContainmentPolicy,
    ) -> (BrowserProcessManager, Result<BrowserLeaseId, LaunchError>) {
        let fake = dir.join("fake-browser");
        fs::write(&fake, "#!/bin/sh\nexec sleep 60\n").unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let mut config = test_config(dir);
        config.executable = fake;
        config.daemon_uid = uid;
        config.daemon_gid = gid;
        config.cdp_expose = CdpExposeMode::Pipe;
        config.bind_parent_death = true;
        let mut mgr =
            BrowserProcessManager::with_spawner(test_clock(), Arc::new(ProductionSpawner));
        mgr.set_containment(containment);
        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: BEARER.to_string(),
        };
        let launched =
            mgr.launch_pending_with_agent_endpoint(&config, test_profile_id(), Some(&metadata));
        (mgr, launched)
    }

    /// Defect B1 regression (`browser_scope = "session"`): a browser launched with a parent-death
    /// signal from a short-lived request thread keeps running once that thread has returned,
    /// because the production spawn forks it on the long-lived launcher thread.
    #[test]
    fn test_b1_browser_outlives_the_request_thread_that_launched_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let (mut mgr, lease_id) =
            std::thread::spawn(move || production_launch(&path, ContainmentPolicy::Off))
                .join()
                .unwrap();
        let lease_id = lease_id.expect("the launch succeeds");
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            mgr.check_exits().is_empty(),
            "the browser must survive the exit of the thread that launched it"
        );
        let pid = mgr.snapshot(&lease_id).unwrap().pid;
        let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        let ppid = format!("{}", std::process::id());
        assert!(
            status
                .lines()
                .any(|l| l.starts_with("PPid:") && l.split_whitespace().nth(1) == Some(&ppid)),
            "the browser is the daemon's child"
        );
        let _ = mgr.terminate(&lease_id);
    }

    /// ADR 0014 section 7: with bwrap the production spawn runs the browser in a private /dev.
    #[test]
    fn test_production_launch_runs_the_browser_under_bwrap() {
        let dir = tempfile::tempdir().unwrap();
        let bin = tempfile::tempdir().unwrap();
        let bwrap = crate::agent::containment::tests::fake_bwrap(bin.path());
        let dev = tempfile::tempdir().unwrap();
        fs::write(dev.path().join("hidraw0"), b"").unwrap();
        let (mut mgr, lease_id) = production_launch(
            dir.path(),
            ContainmentPolicy::Injected {
                bwrap: Some(bwrap),
                dev_dir: dev.path().to_path_buf(),
            },
        );
        let lease_id = lease_id.expect("the launch succeeds under bwrap");
        // The probe ran `true` (8 arguments); wait for the launch's own run to be recorded.
        let log = bin.path().join("bwrap.args");
        let deadline = Instant::now() + Duration::from_secs(10);
        let recorded = loop {
            let recorded = fs::read_to_string(&log).unwrap_or_default();
            if recorded.lines().count() > 8 + 7 || Instant::now() >= deadline {
                break recorded;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let launch_args: Vec<&str> = recorded.lines().skip(8).collect();
        assert_eq!(
            &launch_args[..7],
            [
                "--dev-bind",
                "/",
                "/",
                "--dev",
                "/dev",
                "--die-with-parent",
                "--"
            ],
            "{recorded}"
        );
        assert!(launch_args[7].ends_with("fake-browser"), "{recorded}");
        assert!(launch_args.contains(&"--remote-debugging-pipe"));
        std::thread::sleep(Duration::from_millis(200));
        assert!(mgr.check_exits().is_empty(), "the wrapped browser runs");
        let _ = mgr.terminate(&lease_id);
    }

    /// ADR 0014 section 7: without bwrap, a browser user that can open a hidraw node is refused
    /// with an actionable error, and nothing of the launch is left behind.
    #[test]
    fn test_production_launch_is_refused_without_bwrap_when_hidraw_is_accessible() {
        let dir = tempfile::tempdir().unwrap();
        let dev = tempfile::tempdir().unwrap();
        fs::write(dev.path().join("hidraw3"), b"").unwrap();
        let (mgr, launched) = production_launch(
            dir.path(),
            ContainmentPolicy::Injected {
                bwrap: None,
                dev_dir: dev.path().to_path_buf(),
            },
        );
        let err = launched.expect_err("refused");
        let LaunchError::ContainmentRefused(message) = &err else {
            panic!("expected the containment refusal, got {err:?}");
        };
        assert!(message.contains("hidraw3"), "{message}");
        assert!(message.contains("bubblewrap"), "{message}");
        assert_eq!(mgr.lease_count(), 0);
        let leftovers: Vec<_> = fs::read_dir(dir.path().join("runtime-root"))
            .unwrap()
            .collect();
        assert!(leftovers.is_empty(), "the runtime dir is removed");

        // With no accessible hidraw node, containment is not required and the launch proceeds.
        let dir = tempfile::tempdir().unwrap();
        let empty_dev = tempfile::tempdir().unwrap();
        let (mut mgr, launched) = production_launch(
            dir.path(),
            ContainmentPolicy::Injected {
                bwrap: None,
                dev_dir: empty_dev.path().to_path_buf(),
            },
        );
        let lease_id = launched.expect("not required");
        let _ = mgr.terminate(&lease_id);
    }

    /// Plan P10 (D6.1): Chromium's DevToolsActivePort is removed once the daemon read it.
    #[test]
    fn test_hide_devtools_active_port_removes_the_discovery_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("DevToolsActivePort");
        fs::write(&file, "9222\n/devtools/browser/x\n").unwrap();
        let profile = Dir::open_path(dir.path()).unwrap();
        hide_devtools_active_port(&profile, dir.path());
        assert!(!file.exists());
        hide_devtools_active_port(&profile, dir.path());
        // A symlink in its place is removed itself; its target is untouched.
        let target = dir.path().join("target");
        fs::write(&target, "keep").unwrap();
        unix_fs::symlink(&target, &file).unwrap();
        hide_devtools_active_port(&profile, dir.path());
        assert!(fs::symlink_metadata(&file).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep");
    }

    /// Plan D4 seeding: the fresh profile allows the extension in incognito before the first
    /// launch, keyed by the ID that the manifest `key` fixes.
    #[test]
    fn test_launch_seeds_incognito_access_for_the_extension() {
        let launch = intercepted_launch();
        let profile_dir = &launch.mgr.leases[&launch.lease_id].manifest.profile_dir;
        let preferences = profile_dir.join("Default").join("Preferences");
        let seeded: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&preferences).unwrap()).unwrap();
        assert_eq!(
            seeded,
            serde_json::json!({"extensions": {"settings": {AGENT_EXTENSION_ID: {"incognito": true}}}})
        );
        assert_eq!(
            fs::metadata(&preferences).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(profile_dir.join("Default"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn test_missing_sign_proxy_is_a_launch_error_and_spawns_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let spawned = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut mgr = BrowserProcessManager::with_spawner(
            test_clock(),
            Arc::new(CountingSpawner(spawned.clone())),
        );
        mgr.set_sign_proxy_path(dir.path().join("no-such-sign-proxy"));
        let config = test_config(dir.path());
        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "tok".to_string(),
        };
        let err = mgr
            .launch_pending_with_agent_endpoint(&config, test_profile_id(), Some(&metadata))
            .unwrap_err();
        assert!(matches!(err, LaunchError::ExtensionSetupFailed(_)), "{err}");
        assert!(err.to_string().contains("sign-proxy"), "{err}");
        assert_eq!(spawned.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(mgr.leases.is_empty());
        assert_no_lease_dirs(&config.runtime_root);
    }

    #[test]
    fn test_devtools_http_open_refuses_a_non_loopback_endpoint() {
        assert!(
            open_url_over_devtools_http("ws://203.0.113.1:9222/devtools/browser/x", START_URL)
                .is_err()
        );
    }

    #[test]
    fn test_devtools_http_open_sends_put_json_new_with_the_encoded_url() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .unwrap();
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        open_url_over_devtools_http(
            &format!("ws://127.0.0.1:{port}/devtools/browser/abc"),
            "https://example.com/login?next=/a&b=c",
        )
        .unwrap();
        let request = server.join().unwrap();
        assert!(
            request.starts_with(
                "PUT /json/new?https%3A%2F%2Fexample.com%2Flogin%3Fnext%3D%2Fa%26b%3Dc HTTP/1.1\r\n"
            ),
            "{request}"
        );
    }

    /// Review H1: the lease directory stays the daemon's (0710, the browser's group), the extension
    /// directory and manifest are the daemon's, only the profile subtree and the worker file are
    /// handed to the browser user.
    #[test]
    fn test_lease_layout_keeps_daemon_written_directories_daemon_owned() {
        let launch = intercepted_launch();
        let lease = &launch.mgr.leases[&launch.lease_id];
        let runtime_dir = &lease.manifest.runtime_dir;
        let mode = |p: &Path| fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(runtime_dir), LEASE_DIR_MODE);
        assert_eq!(
            mode(&runtime_dir.join(AGENT_EXTENSION_DIR)),
            EXTENSION_DIR_MODE
        );
        assert_eq!(
            mode(&runtime_dir.join(AGENT_EXTENSION_DIR).join("manifest.json")),
            0o644
        );
        assert_eq!(
            mode(&runtime_dir.join(AGENT_EXTENSION_DIR).join("worker.js")),
            0o600
        );
        assert_eq!(mode(&runtime_dir.join(MANIFEST_FILENAME)), 0o600);
        assert_eq!(mode(&lease.manifest.profile_dir), RUNTIME_DIR_MODE);
        let hosts = lease.manifest.profile_dir.join("NativeMessagingHosts");
        assert_eq!(mode(&hosts), 0o755);
        assert_eq!(
            mode(&hosts.join(format!("{NATIVE_MESSAGING_HOST_NAME}.json"))),
            0o644
        );
        let euid = unsafe { libc::geteuid() };
        assert_eq!(fs::symlink_metadata(runtime_dir).unwrap().uid(), euid);
    }

    /// Review H1: a symlink planted where the daemon rewrites the `cdp-endpoint` file (it is
    /// removed on degrade and rewritten on re-attach) is removed, never followed: its target is
    /// untouched and the endpoint lands in a fresh regular file.
    #[test]
    fn test_cdp_endpoint_rewrite_does_not_follow_a_planted_symlink() {
        let mut launch = intercepted_launch();
        let endpoint = "ws://127.0.0.1:9333/devtools/browser/abc";
        launch
            .mgr
            .leases
            .get_mut(&launch.lease_id)
            .unwrap()
            .cdp_endpoint = Some(endpoint.to_string());
        let runtime_dir = launch.mgr.leases[&launch.lease_id]
            .manifest
            .runtime_dir
            .clone();
        let victim = launch._dir.path().join("victim");
        fs::write(&victim, "precious").unwrap();
        unix_fs::symlink(&victim, runtime_dir.join("cdp-endpoint")).unwrap();

        launch.readiness.simulate_hello(BEARER, 1, true, true);
        launch
            .mgr
            .await_interception(&launch.lease_id, &launch.readiness, Duration::from_secs(1))
            .unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
        let file = runtime_dir.join("cdp-endpoint");
        assert!(fs::symlink_metadata(&file).unwrap().is_file());
        assert_eq!(fs::read_to_string(&file).unwrap(), endpoint);

        // The lease directory is pinned: renaming it away and planting a symlink to elsewhere in
        // its place does not redirect the next rewrite.
        let elsewhere = launch._dir.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        let moved = runtime_dir.with_file_name("moved-lease");
        fs::rename(&runtime_dir, &moved).unwrap();
        unix_fs::symlink(&elsewhere, &runtime_dir).unwrap();
        let grace = INTERCEPTION_DEGRADED_GRACE;
        launch.readiness.simulate_disconnect(BEARER, 1);
        launch
            .readiness
            .backdate_detached(BEARER, grace + Duration::from_secs(1));
        launch.mgr.poll_interception(&launch.readiness, grace);
        launch.readiness.simulate_hello(BEARER, 2, true, true);
        launch.mgr.poll_interception(&launch.readiness, grace);
        assert_eq!(
            fs::read_dir(&elsewhere).unwrap().count(),
            0,
            "nothing written there"
        );
        assert_eq!(
            fs::read_to_string(moved.join("cdp-endpoint")).unwrap(),
            endpoint
        );
        fs::remove_file(&runtime_dir).unwrap();
        fs::rename(&moved, &runtime_dir).unwrap();
    }

    #[test]
    fn test_runtime_root_with_a_symlinked_component_resolves_system_ancestors_only() {
        let dir = tempfile::tempdir().unwrap();
        let root = setup_runtime_root(dir.path());
        let uid = unsafe { libc::getuid() };
        // A symlinked ancestor is resolved before the pinned open (like /var/run -> /run).
        let alias = dir.path().join("alias");
        unix_fs::symlink(dir.path(), &alias).unwrap();
        assert!(validate_runtime_root(&alias.join("runtime-root"), uid).is_ok());
        // The runtime root itself may not be a symlink.
        let link = dir.path().join("root-link");
        unix_fs::symlink(&root, &link).unwrap();
        assert!(validate_runtime_root(&link, uid).is_err());
    }

    #[test]
    fn test_cdp_endpoint_file_exists_only_while_interception_is_attached() {
        let mut launch = intercepted_launch();
        let endpoint = "ws://127.0.0.1:9333/devtools/browser/abc";
        // As a port-mode launch leaves it: the endpoint is known, no file is written yet.
        launch
            .mgr
            .leases
            .get_mut(&launch.lease_id)
            .unwrap()
            .cdp_endpoint = Some(endpoint.to_string());
        let file = launch.mgr.leases[&launch.lease_id]
            .manifest
            .runtime_dir
            .join("cdp-endpoint");
        assert!(!file.exists(), "not before the worker attached");

        launch.readiness.simulate_hello(BEARER, 1, true, true);
        launch
            .mgr
            .await_interception(&launch.lease_id, &launch.readiness, Duration::from_secs(1))
            .unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap(), endpoint);
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let grace = INTERCEPTION_DEGRADED_GRACE;
        launch.readiness.simulate_disconnect(BEARER, 1);
        launch
            .readiness
            .backdate_detached(BEARER, grace + Duration::from_secs(1));
        assert_eq!(
            launch.mgr.poll_interception(&launch.readiness, grace).len(),
            1
        );
        assert!(!file.exists(), "removed while degraded");

        launch.readiness.simulate_hello(BEARER, 2, true, true);
        assert_eq!(
            launch.mgr.poll_interception(&launch.readiness, grace).len(),
            1
        );
        assert_eq!(fs::read_to_string(&file).unwrap(), endpoint);
    }
}
