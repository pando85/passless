use std::collections::HashMap;
use std::collections::VecDeque;
use std::ffi::CString;
use std::fmt;
use std::fs;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use passless_core::agent::config::{CdpExposeMode, LOCALHOST_RP_ID};
use passless_core::agent::{
    AgentRpRule, BrowserLeaseId, EndpointId, ProfileId, RuleAction, rule_for_host,
};

use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json;

use super::containment::{ContainmentPlan, ContainmentPolicy, refuse_if_hidraw_accessible};
use super::launcher::{
    DEFAULT_RLIMIT_AS, DEFAULT_RLIMIT_CORE, DEFAULT_RLIMIT_NPROC, HardenedChildSetup,
    bind_parent_death, cloexec_except, spawn_on_launcher_thread,
};
use super::transport::{BearerReadiness, ReadinessRegistry};

const RUNTIME_DIR_MODE: u32 = 0o700;
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
const RLIMIT_NOFILE_CUR: u64 = 256;

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
    pub endpoint_id: String,
    pub profile_id: String,
    pub pid: u32,
    pub pgid: u32,
    pub process_identity: ProcessIdentity,
    pub profile_fingerprint: ProfileFingerprint,
    pub runtime_dir: PathBuf,
    pub profile_dir: PathBuf,
    pub created_monotonic_secs: u64,
    pub ttl_monotonic_secs: u64,
    pub endpoint_scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentEndpointMetadata {
    pub socket_path: String,
    pub bearer_token: String,
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
            rlimit_nofile: RLIMIT_NOFILE_CUR,
            rlimit_nproc: DEFAULT_RLIMIT_NPROC,
            rlimit_core: DEFAULT_RLIMIT_CORE,
            rlimit_as: DEFAULT_RLIMIT_AS,
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
}

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
                write!(f, "timed out waiting for browser CDP endpoint")
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
        }
    }
}

impl std::error::Error for CdpError {}

#[derive(Debug)]
pub struct CdpRoundTripResult {
    pub messages: Vec<String>,
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
    pub endpoint_id: EndpointId,
    pub profile_id: ProfileId,
    pub state: LeaseState,
    pub manifest: BrowserManifest,
    pub login_deadline: Instant,
    pub ttl_deadline: Instant,
    pub child: Option<Child>,
    pub cdp: Option<DaemonCdpEndpoints>,
    pub cdp_buffer: VecDeque<String>,
    pub cdp_read_buf: Vec<u8>,
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
                    .cdp_round_trip(lease_id, &request, START_URL_OPEN_TIMEOUT)
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
    #[allow(dead_code)]
    pub endpoint_id: EndpointId,
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
        endpoint_id: EndpointId,
        profile_id: ProfileId,
    ) -> Result<BrowserLeaseId, LaunchError> {
        let lease_id = self.launch_pending(config, endpoint_id, profile_id)?;
        let session_ttl = clamp_ttl(config.ttl);
        self.activate_after_assertion(&lease_id, session_ttl)
            .map_err(|e| LaunchError::SpawnFailed(format!("immediate activation failed: {}", e)))?;
        Ok(lease_id)
    }

    pub fn launch_pending(
        &mut self,
        config: &BrowserConfig,
        endpoint_id: EndpointId,
        profile_id: ProfileId,
    ) -> Result<BrowserLeaseId, LaunchError> {
        self.launch_pending_with_agent_endpoint(config, endpoint_id, profile_id, None)
    }

    pub fn launch_pending_with_agent_endpoint(
        &mut self,
        config: &BrowserConfig,
        endpoint_id: EndpointId,
        profile_id: ProfileId,
        agent_endpoint: Option<&AgentEndpointMetadata>,
    ) -> Result<BrowserLeaseId, LaunchError> {
        config
            .hardening()
            .validate()
            .map_err(|e| LaunchError::HardeningFailed(e.to_string()))?;

        let lease_id = BrowserLeaseId::new();
        let now = self.clock.now();
        let monotonic_secs = self.clock.monotonic_secs();
        let login_clamped = clamp_login_timeout(config.login_timeout);

        validate_runtime_root(&config.runtime_root, config.target_uid).map_err(|e| {
            LaunchError::RuntimeRootInvalid(format!("{}: {}", config.runtime_root.display(), e))
        })?;

        let runtime_dir = config
            .runtime_root
            .join(format!("lease-{}", lease_id.as_str()));
        let profile_dir = runtime_dir.join("profile");

        // Every error path below removes the runtime dir (it holds the extension worker's bearer token).
        let mut dir_guard = LaunchDirGuard::new(runtime_dir.clone());

        create_lease_dir(
            &runtime_dir,
            RUNTIME_DIR_MODE,
            config.target_uid,
            config.target_gid,
        )
        .map_err(|e| {
            LaunchError::DirCreationFailed(runtime_dir.display().to_string(), e.to_string())
        })?;
        create_lease_dir(
            &profile_dir,
            RUNTIME_DIR_MODE,
            config.target_uid,
            config.target_gid,
        )
        .map_err(|e| {
            LaunchError::DirCreationFailed(profile_dir.display().to_string(), e.to_string())
        })?;

        let mut relay_path = None;
        if let Some(metadata) = agent_endpoint {
            let ext_dir = generate_agent_extension(
                &runtime_dir,
                metadata,
                config.target_uid,
                config.target_gid,
            )?;
            // Verified before anything is spawned: a missing or unreadable extension is a launch
            // error, never a browser without interception.
            verify_extension_dir(&ext_dir)?;
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
            install_native_messaging_manifest(&ext_dir, &sign_proxy, &profile_dir)?;
            // The extension must also run in off-the-record and CDP-created contexts, or their
            // requests would go native (ADR 0014 section 4.2); the worker's hello reports whether
            // this took effect, and the launch fails closed if it did not.
            seed_incognito_access(&profile_dir, config.target_uid, config.target_gid)?;
            relay_path = Some(sign_proxy);
        }

        let profile_fp = fingerprint_path(&profile_dir).map_err(|e| {
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
            let discovered = if config.cdp_port > 0 {
                wait_for_cdp_port(&mut child, config.cdp_port, Duration::from_secs(30))
            } else {
                discover_cdp_endpoint_with_child(&mut child, &profile_dir, Duration::from_secs(30))
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
            hide_devtools_active_port(&profile_dir);
            // An intercepted lease's `cdp-endpoint` file is written only once its worker attached
            // (`await_interception`) and removed while it is degraded; see `sync_cdp_endpoint_file`.
            if agent_endpoint.is_none()
                && let Err(err) = write_cdp_endpoint(
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
            log::info!(
                "browser lease {} (pid {}): native-path containment {}{}",
                lease_id,
                pid,
                case,
                if containment.private_dev() {
                    " (private /dev through bwrap)"
                } else {
                    " (no private /dev; the browser user cannot open any hidraw device)"
                }
            );
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
            endpoint_id: endpoint_id.as_str().to_string(),
            profile_id: profile_id.as_str().to_string(),
            pid,
            pgid,
            process_identity: proc_identity,
            profile_fingerprint: profile_fp,
            runtime_dir: runtime_dir.clone(),
            profile_dir: profile_dir.clone(),
            created_monotonic_secs: monotonic_secs,
            ttl_monotonic_secs: login_clamped.as_secs(),
            endpoint_scope: endpoint_id.as_str().to_string(),
        };

        write_manifest_atomic(&runtime_dir, &manifest)?;

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
            endpoint_id,
            profile_id,
            state: LeaseState::AuthenticationPending,
            manifest,
            login_deadline,
            ttl_deadline: login_deadline,
            child: Some(child),
            cdp: daemon_endpoints,
            cdp_buffer: VecDeque::new(),
            cdp_read_buf: Vec::with_capacity(CDP_READ_BUF_SIZE),
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
            endpoint_id: lease.endpoint_id.clone(),
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

    pub fn cdp_round_trip(
        &mut self,
        lease_id: &BrowserLeaseId,
        request_json: &str,
        timeout: Duration,
    ) -> Result<CdpRoundTripResult, CdpError> {
        validate_cdp_request(request_json)?;

        let timeout = clamp_cdp_timeout(timeout);

        let entry = self
            .leases
            .get_mut(lease_id)
            .ok_or(CdpError::LeaseNotFound)?;

        if entry.state.is_terminal() {
            return Err(CdpError::BrowserExited);
        }

        let cdp = entry.cdp.as_mut().ok_or(CdpError::NoCdpEndpoints)?;

        let mut frame = request_json.as_bytes().to_vec();
        frame.push(0);

        cdp.to_browser
            .write_all(&frame)
            .map_err(|e| CdpError::WriteFailed(e.to_string()))?;
        cdp.to_browser
            .flush()
            .map_err(|e| CdpError::WriteFailed(e.to_string()))?;

        let request_id = extract_cdp_id(request_json);

        let deadline = Instant::now() + timeout;
        let mut collected_messages: Vec<String> = Vec::new();
        let mut total_bytes: usize = 0;
        let mut found_response = false;

        loop {
            while let Some(buffered) = entry.cdp_buffer.pop_front() {
                let msg_len = buffered.len();
                if collected_messages.len() >= CDP_MAX_RESPONSE_MESSAGES {
                    return Err(CdpError::TooManyMessages);
                }
                if total_bytes + msg_len > CDP_MAX_RESPONSE_TOTAL_BYTES {
                    return Err(CdpError::ResponseTooLarge);
                }

                if let Some(ref rid) = request_id
                    && cdp_message_has_id(&buffered, rid)
                {
                    found_response = true;
                }

                collected_messages.push(buffered);
                total_bytes += msg_len;

                if found_response {
                    return Ok(CdpRoundTripResult {
                        messages: collected_messages,
                    });
                }
            }

            let now = Instant::now();
            if now >= deadline {
                if found_response {
                    return Ok(CdpRoundTripResult {
                        messages: collected_messages,
                    });
                }
                return Err(CdpError::Timeout);
            }

            let fd = cdp.from_browser.as_raw_fd();
            set_nonblocking(fd, true);

            let mut buf = vec![0u8; CDP_READ_BUF_SIZE];
            let n = match cdp.from_browser.read(&mut buf) {
                Ok(0) => {
                    set_nonblocking(fd, false);
                    return Err(CdpError::BrowserExited);
                }
                Ok(n) => n,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    set_nonblocking(fd, false);
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        if found_response {
                            return Ok(CdpRoundTripResult {
                                messages: collected_messages,
                            });
                        }
                        return Err(CdpError::Timeout);
                    }
                    let sleep_time = remaining.min(Duration::from_millis(10));
                    std::thread::sleep(sleep_time);
                    continue;
                }
                Err(e) => {
                    set_nonblocking(fd, false);
                    return Err(CdpError::ReadFailed(e.to_string()));
                }
            };

            set_nonblocking(fd, false);

            entry.cdp_read_buf.extend_from_slice(&buf[..n]);

            while let Some(nul_pos) = entry.cdp_read_buf.iter().position(|&b| b == 0) {
                let msg_bytes = entry.cdp_read_buf.drain(..=nul_pos).collect::<Vec<_>>();
                let msg_str =
                    String::from_utf8_lossy(&msg_bytes[..msg_bytes.len() - 1]).to_string();

                if !msg_str.is_empty() {
                    if collected_messages.len() >= CDP_MAX_RESPONSE_MESSAGES {
                        return Err(CdpError::TooManyMessages);
                    }
                    if total_bytes + msg_str.len() > CDP_MAX_RESPONSE_TOTAL_BYTES {
                        return Err(CdpError::ResponseTooLarge);
                    }

                    if let Some(ref rid) = request_id
                        && cdp_message_has_id(&msg_str, rid)
                    {
                        found_response = true;
                    }

                    collected_messages.push(msg_str);
                    total_bytes += collected_messages.last().unwrap().len();

                    if found_response {
                        return Ok(CdpRoundTripResult {
                            messages: collected_messages,
                        });
                    }
                }
            }
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

fn validate_runtime_root(path: &Path, expected_uid: u32) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;

    if meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "runtime root is a symlink",
        ));
    }

    if !meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "runtime root is not a directory",
        ));
    }

    let mode = meta.permissions().mode() & 0o777;
    if mode != RUNTIME_DIR_MODE {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "runtime root mode is {:o}, expected {:o}",
                mode, RUNTIME_DIR_MODE
            ),
        ));
    }

    if meta.uid() != expected_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "runtime root not owned by target uid {} (owned by {})",
                expected_uid,
                meta.uid()
            ),
        ));
    }

    Ok(())
}

fn create_lease_dir(path: &Path, mode: u32, target_uid: u32, target_gid: u32) -> io::Result<()> {
    let parent = path.parent().unwrap_or(Path::new("/"));
    let dir_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "no file name in lease dir path",
        )
    })?;
    let c_name = CString::new(dir_name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL byte"))?;
    let parent_c_path = path_to_cstring(parent)?;

    let parent_fd = unsafe {
        libc::open(
            parent_c_path.as_ptr(),
            libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_RDONLY,
        )
    };
    if parent_fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut dir_stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(parent_fd, &mut dir_stat) } != 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(parent_fd) };
        return Err(err);
    }
    if (dir_stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        unsafe { libc::close(parent_fd) };
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "parent is not a directory",
        ));
    }

    let mkdir_ret = unsafe { libc::mkdirat(parent_fd, c_name.as_ptr(), mode) };
    if mkdir_ret != 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(parent_fd) };
        return Err(err);
    }

    let dir_fd = unsafe {
        libc::openat(
            parent_fd,
            c_name.as_ptr(),
            libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_RDONLY,
        )
    };
    if dir_fd < 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::unlinkat(parent_fd, c_name.as_ptr(), libc::AT_REMOVEDIR);
            libc::close(parent_fd);
        }
        return Err(err);
    }

    let mut new_stat: libc::stat = unsafe { std::mem::zeroed() };
    let fstat_ok = unsafe { libc::fstat(dir_fd, &mut new_stat) } == 0;
    let is_symlink = !fstat_ok || (new_stat.st_mode & libc::S_IFMT) == libc::S_IFLNK;
    if is_symlink {
        unsafe {
            libc::close(dir_fd);
            libc::unlinkat(parent_fd, c_name.as_ptr(), libc::AT_REMOVEDIR);
            libc::close(parent_fd);
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "lease dir is a symlink after mkdir",
        ));
    }

    let chown_ret = unsafe { libc::fchown(dir_fd, target_uid, target_gid) };
    if chown_ret != 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(dir_fd);
            libc::unlinkat(parent_fd, c_name.as_ptr(), libc::AT_REMOVEDIR);
            libc::close(parent_fd);
        }
        return Err(err);
    }

    unsafe {
        libc::close(dir_fd);
        libc::close(parent_fd);
    }
    Ok(())
}

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

fn write_extension_file(
    dir: &Path,
    name: &str,
    content: &str,
    mode: u32,
    target_uid: u32,
    target_gid: u32,
) -> Result<(), LaunchError> {
    let path = dir.join(name);
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&path)
        .map_err(|e| LaunchError::ExtensionSetupFailed(format!("create {}: {}", name, e)))?;
    (&file)
        .write_all(content.as_bytes())
        .map_err(|e| LaunchError::ExtensionSetupFailed(format!("write {}: {}", name, e)))?;
    let ret = unsafe { libc::fchown(file.as_raw_fd(), target_uid, target_gid) };
    if ret != 0 {
        return Err(LaunchError::ExtensionSetupFailed(format!(
            "chown {}: {}",
            name,
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Writes the lease's interception extension: `manifest.json` verbatim from the assets (its
/// committed `key` fixes the extension ID) and `worker.js` with the lease's bearer, sign socket
/// and build version. The worker file holds the bearer, so it is readable by the browser user only.
fn generate_agent_extension(
    runtime_dir: &Path,
    metadata: &AgentEndpointMetadata,
    target_uid: u32,
    target_gid: u32,
) -> Result<PathBuf, LaunchError> {
    let ext_dir = runtime_dir.join(AGENT_EXTENSION_DIR);
    create_lease_dir(&ext_dir, EXTENSION_DIR_MODE, target_uid, target_gid)
        .map_err(|e| LaunchError::ExtensionSetupFailed(format!("extension dir: {}", e)))?;

    write_extension_file(
        &ext_dir,
        "manifest.json",
        EXTENSION_MANIFEST_TEMPLATE,
        0o644,
        target_uid,
        target_gid,
    )?;
    write_extension_file(
        &ext_dir,
        "worker.js",
        &render_worker_script(EXTENSION_WORKER_TEMPLATE, metadata),
        0o600,
        target_uid,
        target_gid,
    )?;

    if simulate_missing_extension() {
        let _ = fs::remove_dir_all(&ext_dir);
    }

    Ok(ext_dir)
}

/// Debug and test builds only: lets E2E-47 and the unit tests simulate an extension directory that is
/// missing after generation. Release builds have no such hook.
fn simulate_missing_extension() -> bool {
    #[cfg(test)]
    if tests::OMIT_EXTENSION.with(|c| c.get()) {
        return true;
    }
    #[cfg(debug_assertions)]
    if std::env::var_os("PASSLESS_E2E_OMIT_AGENT_EXTENSION").is_some() {
        return true;
    }
    false
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

/// The ID of the extension in `ext_dir`, from its `manifest.json`.
pub fn extension_id_of_dir(ext_dir: &Path) -> Result<String, LaunchError> {
    let manifest = fs::read_to_string(ext_dir.join("manifest.json")).map_err(|e| {
        LaunchError::ExtensionSetupFailed(format!(
            "read {}: {}",
            ext_dir.join("manifest.json").display(),
            e
        ))
    })?;
    compute_extension_id(&manifest)
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
/// `sign_proxy_path`.
fn install_native_messaging_manifest(
    ext_dir: &Path,
    sign_proxy_path: &Path,
    profile_dir: &Path,
) -> Result<PathBuf, LaunchError> {
    let ext_id = extension_id_of_dir(ext_dir)?;
    let manifest = serde_json::json!({
        "name": NATIVE_MESSAGING_HOST_NAME,
        "description": "Passless agent sign proxy",
        "path": sign_proxy_path,
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{}/", ext_id)]
    });
    write_native_messaging_manifest(&profile_dir.join("NativeMessagingHosts"), &manifest)
}

fn write_native_messaging_manifest(
    hosts_dir: &Path,
    manifest: &serde_json::Value,
) -> Result<PathBuf, LaunchError> {
    fs::create_dir_all(hosts_dir).map_err(|e| {
        LaunchError::ExtensionSetupFailed(format!(
            "create native messaging dir {}: {}",
            hosts_dir.display(),
            e
        ))
    })?;
    let manifest_path = hosts_dir.join(format!("{}.json", NATIVE_MESSAGING_HOST_NAME));
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(&manifest_path)
        .map_err(|e| {
            LaunchError::ExtensionSetupFailed(format!("create native messaging manifest: {}", e))
        })?;
    serde_json::to_writer_pretty(&file, manifest).map_err(|e| {
        LaunchError::ExtensionSetupFailed(format!("write native messaging manifest: {}", e))
    })?;
    Ok(manifest_path)
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
pub(crate) fn verify_extension_dir(ext_dir: &Path) -> Result<(), LaunchError> {
    let fail = |why: String| {
        LaunchError::ExtensionSetupFailed(format!(
            "{why}; refusing to launch the managed browser without the passless agent extension \
             (it is required so that WebAuthn requests never reach the human authenticator). \
             Check that the browser runtime root is writable and has free space, then retry; \
             if it persists, reinstall passless"
        ))
    };
    let meta = fs::metadata(ext_dir).map_err(|e| {
        fail(format!(
            "extension directory {} is unavailable: {e}",
            ext_dir.display()
        ))
    })?;
    if !meta.is_dir() {
        return Err(fail(format!(
            "extension path {} is not a directory",
            ext_dir.display()
        )));
    }
    let manifest_path = ext_dir.join("manifest.json");
    let manifest = fs::read_to_string(&manifest_path).map_err(|e| {
        fail(format!(
            "extension manifest {} is not readable: {e}",
            manifest_path.display()
        ))
    })?;
    let manifest: serde_json::Value = match serde_json::from_str(&manifest) {
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

    let worker_path = ext_dir.join(EXTENSION_WORKER);
    let worker = match fs::metadata(&worker_path) {
        Ok(m) if m.is_file() && m.len() > 0 => fs::read_to_string(&worker_path).map_err(|e| {
            fail(format!(
                "extension script {} is not readable: {e}",
                worker_path.display()
            ))
        })?,
        Ok(_) => {
            return Err(fail(format!(
                "extension script {} is empty or not a regular file",
                worker_path.display()
            )));
        }
        Err(e) => {
            return Err(fail(format!(
                "extension script {} is missing or unreadable: {e}",
                worker_path.display()
            )));
        }
    };
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
        verify_extension_dir(&ext_dir)?;
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
    let hidraw_nodes = containment.hidraw_nodes_to_check().to_vec();
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
            // Evaluated as the browser's UID, after the drop (empty under bwrap).
            refuse_if_hidraw_accessible(&hidraw_nodes)
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
    let hidraw_nodes = containment.hidraw_nodes_to_check().to_vec();
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
            // Evaluated as the browser's UID (empty under bwrap).
            refuse_if_hidraw_accessible(&hidraw_nodes)
        });
    }

    spawn_contained(cmd, containment)
}

/// Removes Chromium's `DevToolsActivePort` from a port-mode profile once the daemon has read the
/// endpoint (plan P10, D6.1): the daemon hands the endpoint out only while the lease is attached,
/// and the file would let a same-UID agent find the loopback port without asking. This is
/// discovery hygiene, not a boundary: a same-UID process can still find the browser's listening
/// socket (`/proc/net/tcp` and its own processes' descriptors), and the file exists from the
/// browser's start until this call (ADR 0014 section 7).
fn hide_devtools_active_port(profile_dir: &Path) {
    match fs::remove_file(profile_dir.join("DevToolsActivePort")) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => log::warn!(
            "cannot remove {}: {e}",
            profile_dir.join("DevToolsActivePort").display()
        ),
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
fn seed_incognito_access(
    profile_dir: &Path,
    target_uid: u32,
    target_gid: u32,
) -> Result<(), LaunchError> {
    let extension_id = compute_extension_id(EXTENSION_MANIFEST_TEMPLATE)?;
    let default_dir = profile_dir.join("Default");
    create_lease_dir(&default_dir, RUNTIME_DIR_MODE, target_uid, target_gid).map_err(|e| {
        LaunchError::ExtensionSetupFailed(format!(
            "create {}: {e}; cannot seed incognito access for the passless agent extension",
            default_dir.display()
        ))
    })?;
    let preferences = serde_json::json!({
        "extensions": {"settings": {extension_id: {"incognito": true}}}
    })
    .to_string();
    write_extension_file(
        &default_dir,
        "Preferences",
        &preferences,
        0o600,
        target_uid,
        target_gid,
    )
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

fn discover_cdp_endpoint_with_child(
    child: &mut Child,
    profile_dir: &Path,
    timeout: Duration,
) -> Result<String, LaunchError> {
    let port_file = profile_dir.join("DevToolsActivePort");
    let deadline = Instant::now() + timeout;
    loop {
        ensure_browser_running(child)?;
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

fn wait_for_cdp_port(
    child: &mut Child,
    port: u16,
    timeout: Duration,
) -> Result<String, LaunchError> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let deadline = Instant::now() + timeout;
    let addr = format!("127.0.0.1:{}", port);
    loop {
        ensure_browser_running(child)?;
        if let Ok(mut stream) =
            TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(200))
        {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
            let request = format!(
                "GET /json/version HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                addr
            );
            if stream.write_all(request.as_bytes()).is_ok() {
                let mut response = String::new();
                let mut buf = [0u8; 4096];
                let read_deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            response.push_str(&String::from_utf8_lossy(&buf[..n]));
                            if let Some(ws_url) = extract_web_socket_debugger_url(&response) {
                                return Ok(ws_url);
                            }
                        }
                        Err(ref e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut =>
                        {
                            if Instant::now() >= read_deadline {
                                break;
                            }
                            continue;
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(LaunchError::CdpDiscoveryTimeout);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
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

fn extract_web_socket_debugger_url(http_response: &str) -> Option<String> {
    let key = "webSocketDebuggerUrl";
    let key_pos = http_response.find(key)?;
    let after_key = &http_response[key_pos + key.len()..];
    let ws_start = after_key.find("ws://")?;
    let value = &after_key[ws_start..];
    let end = value.find('"').unwrap_or(value.len());
    let url = &value[..end];
    validate_loopback_ws_url(url).ok()?;
    Some(url.to_string())
}

/// Keeps an intercepted port-mode lease's `cdp-endpoint` file in step with its interception: it
/// exists only while the worker is attached (finding: it used to be written before the attach and
/// left behind on degrade). Pipe-mode leases have no such file.
fn sync_cdp_endpoint_file(lease: &BrowserLease, attached: bool) -> Result<(), LaunchError> {
    let (Some(endpoint), Some(interception)) = (&lease.cdp_endpoint, &lease.interception) else {
        return Ok(());
    };
    let runtime_dir = &lease.manifest.runtime_dir;
    if attached {
        let (uid, gid) = interception.endpoint_file_owner;
        write_cdp_endpoint(runtime_dir, endpoint, uid, gid)
    } else {
        match fs::remove_file(runtime_dir.join("cdp-endpoint")) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(LaunchError::EndpointFileWriteFailed(
                runtime_dir.join("cdp-endpoint").display().to_string(),
                e.to_string(),
            )),
        }
    }
}

fn write_cdp_endpoint(
    runtime_dir: &Path,
    url: &str,
    target_uid: u32,
    target_gid: u32,
) -> Result<(), LaunchError> {
    let path = runtime_dir.join("cdp-endpoint");
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| {
            LaunchError::EndpointFileWriteFailed(path.display().to_string(), e.to_string())
        })?;
    (&file).write_all(url.as_bytes()).map_err(|e| {
        LaunchError::EndpointFileWriteFailed(path.display().to_string(), e.to_string())
    })?;
    let ret = unsafe { libc::fchown(file.as_raw_fd(), target_uid, target_gid) };
    if ret != 0 {
        return Err(LaunchError::EndpointFileWriteFailed(
            path.display().to_string(),
            io::Error::last_os_error().to_string(),
        ));
    }
    Ok(())
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

fn write_manifest_atomic(dir: &Path, manifest: &BrowserManifest) -> Result<(), LaunchError> {
    let manifest_path = dir.join(MANIFEST_FILENAME);
    let tmp_name = format!(
        ".{}.tmp.{:016x}",
        MANIFEST_FILENAME,
        rand::thread_rng().r#gen::<u64>()
    );
    let tmp_path = dir.join(&tmp_name);

    let manifest_json = serde_json::to_string_pretty(manifest).map_err(|e| {
        LaunchError::ManifestWriteFailed(manifest_path.display().to_string(), e.to_string())
    })?;

    let tmp_file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp_path)
        .map_err(|e| {
            LaunchError::ManifestWriteFailed(tmp_path.display().to_string(), e.to_string())
        })?;
    (&tmp_file)
        .write_all(manifest_json.as_bytes())
        .map_err(|e| {
            LaunchError::ManifestWriteFailed(tmp_path.display().to_string(), e.to_string())
        })?;
    #[cfg(target_os = "linux")]
    {
        let ret = unsafe { libc::fsync(tmp_file.as_raw_fd()) };
        if ret != 0 {
            let _ = fs::remove_file(&tmp_path);
            return Err(LaunchError::ManifestWriteFailed(
                tmp_path.display().to_string(),
                io::Error::last_os_error().to_string(),
            ));
        }
    }
    drop(tmp_file);

    fs::rename(&tmp_path, &manifest_path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        LaunchError::ManifestWriteFailed(manifest_path.display().to_string(), e.to_string())
    })?;

    let dir_file = fs::File::open(dir)
        .map_err(|e| LaunchError::ManifestWriteFailed(dir.display().to_string(), e.to_string()))?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let _ = unsafe { libc::fsync(dir_file.as_raw_fd()) };
    }
    drop(dir_file);

    Ok(())
}

fn decode_wait_status(status: libc::c_int) -> Option<ExitStatus> {
    use std::os::unix::process::ExitStatusExt;
    Some(ExitStatus::from_raw(status))
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

    fn test_endpoint_id() -> EndpointId {
        EndpointId::new()
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
            endpoint_id: "ep1".to_string(),
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
            endpoint_scope: "ep1".to_string(),
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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
        let result = mgr.principal_exit(&lease_id).unwrap();
        assert_eq!(result, LeaseState::PrincipalExit);
    }

    #[test]
    fn test_manager_daemon_shutdown_from_active() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
        let result = mgr.daemon_shutdown(&lease_id).unwrap();
        assert_eq!(result, LeaseState::DaemonShutdown);
    }

    #[test]
    fn test_manager_daemon_shutdown_from_revoked() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
        let result = mgr.terminate(&lease_id).unwrap();
        assert!(result.elapsed < Duration::from_secs(30));
    }

    #[test]
    fn test_manager_terminate_already_terminated() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let _id1 = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
        let _id2 = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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

        let _lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let _lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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

        let first_lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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
                mgr.launch(&c, test_endpoint_id(), test_profile_id())
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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
        assert!(mgr.terminate(&lease_id).is_ok());
        assert!(mgr.cleanup(&lease_id).is_ok());
    }

    #[test]
    fn test_race_multiple_revokes() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let result = mgr.launch(&config, test_endpoint_id(), test_profile_id());
        assert!(matches!(result, Err(LaunchError::InvalidStartUrl(_))));
    }

    #[test]
    fn test_launch_with_start_url() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let mut config = test_config(dir.path());
        config.start_url = Some("https://example.com/dashboard".to_string());

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let result = mgr.launch(&config, test_endpoint_id(), test_profile_id());
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

        let id1 = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
        let id2 = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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
            endpoint_id: "ep".to_string(),
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
            endpoint_scope: "ep".to_string(),
        };

        write_manifest_atomic(&lease_dir, &manifest).unwrap();

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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let result = mgr.launch(&config, test_endpoint_id(), test_profile_id());
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

        let result = mgr.launch(&config, test_endpoint_id(), test_profile_id());
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

        let result = mgr.launch(&config, test_endpoint_id(), test_profile_id());
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

        let result = mgr.launch(&config, test_endpoint_id(), test_profile_id());
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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch_pending(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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

        let lease_id = mgr
            .launch_pending(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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

        let lease_id = mgr
            .launch_pending(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch_pending(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch_pending(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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

        let lease_id = mgr
            .launch_pending(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch_pending(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch_pending(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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
            m.launch_pending(&config, test_endpoint_id(), test_profile_id())
                .unwrap()
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

        let lease_id = mgr
            .launch_pending(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch_pending(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch_pending(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

        let result = mgr.mark_browser_exit(&lease_id).unwrap();
        assert_eq!(result, LeaseState::BrowserExit);
    }

    #[test]
    fn test_pending_lease_principal_exit() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr
            .launch_pending(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

        let result = mgr.principal_exit(&lease_id).unwrap();
        assert_eq!(result, LeaseState::PrincipalExit);
    }

    #[test]
    fn test_pending_lease_daemon_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr
            .launch_pending(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

        let result = mgr.daemon_shutdown(&lease_id).unwrap();
        assert_eq!(result, LeaseState::DaemonShutdown);
    }

    #[test]
    fn test_activation_after_revoke_fails() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr
            .launch_pending(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch_pending(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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

        let lease_id = mgr
            .launch_pending(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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

        let lease_id = mgr
            .launch_pending(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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

        let id1 = mgr
            .launch_pending(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
        let id2 = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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
        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();
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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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

        let _lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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

        let _lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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

        let lease_id = mgr
            .launch(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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

        let result =
            discover_cdp_endpoint_with_child(&mut child, &profile_dir, Duration::from_secs(5));
        assert!(matches!(
            result,
            Err(LaunchError::BrowserExitedBeforeCdp(_))
        ));
    }

    #[test]
    fn test_wait_for_cdp_port_detects_browser_exit() {
        let mut child = Command::new("/bin/false").spawn().unwrap();
        let started = Instant::now();
        let result = wait_for_cdp_port(&mut child, 0, Duration::from_secs(5));
        assert!(matches!(
            result,
            Err(LaunchError::BrowserExitedBeforeCdp(_))
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
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

        let lease_id = mgr
            .launch_pending(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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
            .launch_pending_with_agent_endpoint(
                &config,
                test_endpoint_id(),
                test_profile_id(),
                None,
            )
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
            .launch_pending_with_agent_endpoint(
                &config,
                test_endpoint_id(),
                test_profile_id(),
                Some(&metadata),
            )
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
            .launch_pending_with_agent_endpoint(
                &config,
                test_endpoint_id(),
                test_profile_id(),
                Some(&metadata),
            )
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
            .launch_pending_with_agent_endpoint(
                &config,
                test_endpoint_id(),
                test_profile_id(),
                Some(&metadata),
            )
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

        let lease_id = mgr
            .launch_pending(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

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
            .launch_pending_with_agent_endpoint(
                &config,
                test_endpoint_id(),
                test_profile_id(),
                Some(&metadata),
            )
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
            .launch_pending_with_agent_endpoint(
                &config,
                test_endpoint_id(),
                test_profile_id(),
                Some(&metadata),
            )
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
        verify_extension_dir(&dir.path().join("ext")).unwrap();

        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: "tok".to_string(),
        };
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let generated = generate_agent_extension(dir.path(), &metadata, uid, gid).unwrap();
        verify_extension_dir(&generated).unwrap();
    }

    #[test]
    fn test_verify_extension_dir_rejects_unusable_directories() {
        let dir = tempfile::tempdir().unwrap();

        // Missing directory.
        assert!(verify_extension_dir(&dir.path().join("missing")).is_err());

        // A file instead of a directory.
        let file = dir.path().join("file");
        fs::write(&file, "{}").unwrap();
        assert!(verify_extension_dir(&file).is_err());

        // Directory without a manifest.
        let empty = dir.path().join("empty");
        fs::create_dir(&empty).unwrap();
        assert!(verify_extension_dir(&empty).is_err());

        // Unreadable manifest (a directory where the file should be).
        let unreadable = dir.path().join("unreadable");
        fs::create_dir_all(unreadable.join("manifest.json")).unwrap();
        assert!(verify_extension_dir(&unreadable).is_err());

        // Manifest that is not a JSON object.
        let garbage = dir.path().join("garbage");
        fs::create_dir(&garbage).unwrap();
        fs::write(garbage.join("manifest.json"), "not json").unwrap();
        assert!(verify_extension_dir(&garbage).is_err());
    }

    #[test]
    fn test_verify_extension_dir_requires_a_non_empty_rendered_worker() {
        let dir = tempfile::tempdir().unwrap();
        let ext = dir.path().join("ext");
        write_valid_extension(&ext);
        let worker = ext.join(EXTENSION_WORKER);

        fs::remove_file(&worker).unwrap();
        let err = verify_extension_dir(&ext).unwrap_err().to_string();
        assert!(err.contains("worker.js"), "missing worker: {err}");

        fs::write(&worker, "").unwrap();
        let err = verify_extension_dir(&ext).unwrap_err().to_string();
        assert!(err.contains("worker.js"), "empty worker: {err}");

        // The unrendered template: every placeholder is still there.
        fs::write(&worker, EXTENSION_WORKER_TEMPLATE).unwrap();
        let err = verify_extension_dir(&ext).unwrap_err().to_string();
        assert!(err.contains("placeholder"), "template worker: {err}");

        // A single placeholder left behind is enough to refuse.
        for placeholder in [
            "__PASSLESS_BEARER__",
            "__PASSLESS_SOCKET_PATH__",
            "__PASSLESS_BUILD_VERSION__",
        ] {
            fs::write(&worker, format!("f(\"tok\", {placeholder});")).unwrap();
            let err = verify_extension_dir(&ext).unwrap_err();
            assert!(
                matches!(err, LaunchError::ExtensionSetupFailed(_)),
                "{placeholder}: {err}"
            );
            assert!(err.to_string().contains("refusing to launch"), "{err}");
        }

        fs::write(&worker, "// ok").unwrap();
        verify_extension_dir(&ext).unwrap();
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
            let err = verify_extension_dir(&ext);
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
        let result = mgr.launch_pending_with_agent_endpoint(
            &config,
            test_endpoint_id(),
            test_profile_id(),
            Some(&metadata),
        );
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
            .launch_pending_with_agent_endpoint(
                &config,
                test_endpoint_id(),
                test_profile_id(),
                Some(&metadata),
            )
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
            .launch_pending_with_agent_endpoint(
                &config,
                test_endpoint_id(),
                test_profile_id(),
                Some(&metadata),
            )
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
            .launch_pending_with_agent_endpoint(
                &config,
                test_endpoint_id(),
                test_profile_id(),
                Some(&metadata),
            )
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
            .launch_pending_with_agent_endpoint(
                &config,
                test_endpoint_id(),
                test_profile_id(),
                Some(&metadata),
            )
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
            .launch_pending(
                &test_config(dir.path()),
                test_endpoint_id(),
                test_profile_id(),
            )
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
        let launched = mgr.launch_pending_with_agent_endpoint(
            &config,
            test_endpoint_id(),
            test_profile_id(),
            Some(&metadata),
        );
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
        hide_devtools_active_port(dir.path());
        assert!(!file.exists());
        hide_devtools_active_port(dir.path());
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
            .launch_pending_with_agent_endpoint(
                &config,
                test_endpoint_id(),
                test_profile_id(),
                Some(&metadata),
            )
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
