use std::collections::HashMap;
use std::collections::VecDeque;
use std::ffi::CString;
use std::fmt;
use std::fs;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use passless_core::agent::config::{ANY_RP_ID, CdpExposeMode, validate_rp_id};
use passless_core::agent::{BrowserLeaseId, EndpointId, ProfileId};

use rand::Rng;
use serde::{Deserialize, Serialize};

use super::launcher::{
    DEFAULT_RLIMIT_AS, DEFAULT_RLIMIT_CORE, DEFAULT_RLIMIT_NPROC, HardenedChildSetup,
};

const RUNTIME_DIR_MODE: u32 = 0o700;
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
    pub port: u16,
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
    pub target_uid: u32,
    pub target_gid: u32,
    pub daemon_uid: u32,
    pub daemon_gid: u32,
    pub cdp_expose: CdpExposeMode,
    pub cdp_port: u16,
}

pub trait ChildSpawner: Send + Sync {
    fn spawn_browser(
        &self,
        config: &BrowserConfig,
        profile_dir: &Path,
        cdp: &CdpPipes,
    ) -> Result<Child, LaunchError>;
}

pub struct ProductionSpawner;

impl ChildSpawner for ProductionSpawner {
    fn spawn_browser(
        &self,
        config: &BrowserConfig,
        profile_dir: &Path,
        cdp: &CdpPipes,
    ) -> Result<Child, LaunchError> {
        spawn_browser_hardened(config, profile_dir, cdp)
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
    ) -> Result<Child, LaunchError> {
        Command::new("/bin/true")
            .stdin(Stdio::null())
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
        }
    }

    pub fn production(clock: Arc<dyn Clock>) -> Self {
        Self {
            leases: HashMap::new(),
            clock,
            sigterm_timeout: DEFAULT_SIGTERM_TIMEOUT,
            sigkill_timeout: DEFAULT_SIGKILL_TIMEOUT,
            spawner: Arc::new(ProductionSpawner),
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

        create_lease_dir(&runtime_dir, config.target_uid, config.target_gid).map_err(|e| {
            LaunchError::DirCreationFailed(runtime_dir.display().to_string(), e.to_string())
        })?;
        create_lease_dir(&profile_dir, config.target_uid, config.target_gid).map_err(|e| {
            LaunchError::DirCreationFailed(profile_dir.display().to_string(), e.to_string())
        })?;

        if let Some(metadata) = agent_endpoint {
            let _ext_dir = generate_agent_extension(
                &runtime_dir,
                metadata,
                config.target_uid,
                config.target_gid,
            )?;
        }

        let profile_fp = fingerprint_path(&profile_dir).map_err(|e| {
            LaunchError::DirCreationFailed(profile_dir.display().to_string(), e.to_string())
        })?;

        if let Some(ref url) = config.start_url {
            validate_start_url(url, &config.rp_ids)
                .map_err(|_| LaunchError::InvalidStartUrl(url.clone()))?;
        }

        let is_port_mode = config.cdp_expose == CdpExposeMode::Port;

        let (cdp_pipes, mut child, cdp_endpoint_url) = if is_port_mode {
            let mut child = spawn_browser_port_mode(config, &profile_dir)?;
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
            if let Err(err) = write_cdp_endpoint(
                &runtime_dir,
                &discovered,
                config.target_uid,
                config.target_gid,
            ) {
                terminate_failed_browser_spawn(&mut child);
                return Err(err);
            }
            (None, child, Some(discovered))
        } else {
            let cdp =
                create_cdp_pipes().map_err(|e| LaunchError::PipeCreationFailed(e.to_string()))?;
            let child = self.spawner.spawn_browser(config, &profile_dir, &cdp)?;
            (Some(cdp), child, None)
        };

        let pid = child.id();
        let pgid = pid;
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
            start_url: config.start_url.clone(),
        };

        if let Some(mut consumed) = consumed_pipes {
            consumed.daemon_to_browser_write = -1;
            consumed.daemon_from_browser_read = -1;
        }

        self.leases.insert(lease_id.clone(), lease);

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

fn create_lease_dir(path: &Path, target_uid: u32, target_gid: u32) -> io::Result<()> {
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

    let mkdir_ret = unsafe { libc::mkdirat(parent_fd, c_name.as_ptr(), RUNTIME_DIR_MODE) };
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

fn validate_start_url(url: &str, rp_ids: &[String]) -> Result<(), ()> {
    let rest = url.strip_prefix("https://").ok_or(())?;
    if rest.is_empty() {
        return Err(());
    }

    let host = rest
        .split('/')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");

    if host.is_empty() {
        return Err(());
    }

    if !is_valid_dns_name(host) && !is_ip_address(host) {
        return Err(());
    }

    let host_normalized = host.to_ascii_lowercase();

    if rp_ids.iter().any(|rp_id| rp_id.trim() == ANY_RP_ID) {
        return validate_rp_id(&host_normalized).map(|_| ()).map_err(|_| ());
    }

    let matching: Vec<&str> = rp_ids
        .iter()
        .filter(|rp_id| {
            let rp = rp_id.trim().to_ascii_lowercase();
            host_normalized == rp || host_normalized.ends_with(&format!(".{}", rp))
        })
        .map(|s| s.as_str())
        .collect();

    if matching.len() != 1 {
        return Err(());
    }

    Ok(())
}

fn is_valid_dns_name(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    if labels.is_empty() {
        return false;
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
    }
    true
}

fn is_ip_address(s: &str) -> bool {
    use std::net::IpAddr;
    s.parse::<IpAddr>().is_ok()
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

fn render_channel_script(template: &str, channel: &str) -> String {
    template.replace("__PASSLESS_CHANNEL__", channel)
}

fn render_worker_script(template: &str, channel: &str, metadata: &AgentEndpointMetadata) -> String {
    let bearer_literal = serde_json::to_string(&metadata.bearer_token).unwrap();
    template
        .replace("__PASSLESS_CHANNEL__", channel)
        .replace("__PASSLESS_PORT__", &metadata.port.to_string())
        .replace("__PASSLESS_BEARER__", &bearer_literal)
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
    fs::write(&path, content)
        .map_err(|e| LaunchError::ExtensionSetupFailed(format!("write {}: {}", name, e)))?;
    let file = fs::File::open(&path)
        .map_err(|e| LaunchError::ExtensionSetupFailed(format!("open {}: {}", name, e)))?;
    let ret = unsafe { libc::fchown(file.as_raw_fd(), target_uid, target_gid) };
    if ret != 0 {
        return Err(LaunchError::ExtensionSetupFailed(format!(
            "chown {}: {}",
            name,
            io::Error::last_os_error()
        )));
    }
    drop(file);
    fs::set_permissions(&path, fs::Permissions::from_mode(mode))
        .map_err(|e| LaunchError::ExtensionSetupFailed(format!("chmod {}: {}", name, e)))?;
    Ok(())
}

fn generate_agent_extension(
    runtime_dir: &Path,
    metadata: &AgentEndpointMetadata,
    target_uid: u32,
    target_gid: u32,
) -> Result<PathBuf, LaunchError> {
    let ext_dir = runtime_dir.join(AGENT_EXTENSION_DIR);
    create_lease_dir(&ext_dir, target_uid, target_gid)
        .map_err(|e| LaunchError::ExtensionSetupFailed(format!("extension dir: {}", e)))?;

    let channel_bytes: [u8; 32] = rand::thread_rng().r#gen();
    let channel: String = channel_bytes.iter().map(|b| format!("{:02x}", b)).collect();

    write_extension_file(
        &ext_dir,
        "manifest.json",
        include_str!("../../assets/agent-extension/manifest.json"),
        0o644,
        target_uid,
        target_gid,
    )?;
    write_extension_file(
        &ext_dir,
        "main.js",
        &render_channel_script(
            include_str!("../../assets/agent-extension/main.js"),
            &channel,
        ),
        0o644,
        target_uid,
        target_gid,
    )?;
    write_extension_file(
        &ext_dir,
        "broker.js",
        &render_channel_script(
            include_str!("../../assets/agent-extension/broker.js"),
            &channel,
        ),
        0o644,
        target_uid,
        target_gid,
    )?;
    write_extension_file(
        &ext_dir,
        "worker.js",
        &render_worker_script(
            include_str!("../../assets/agent-extension/worker.js"),
            &channel,
            metadata,
        ),
        0o600,
        target_uid,
        target_gid,
    )?;

    Ok(ext_dir)
}

pub(crate) fn build_browser_command(
    config: &BrowserConfig,
    profile_dir: &Path,
) -> Result<Command, LaunchError> {
    for arg in &config.extra_args {
        if arg.starts_with("--remote-debugging-pipe")
            || arg.starts_with("--remote-debugging-port")
            || arg.starts_with("--remote-debugging-address")
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
    let ext_dir = profile_dir
        .parent()
        .unwrap_or(profile_dir)
        .join(AGENT_EXTENSION_DIR);
    if ext_dir.is_dir() {
        cmd.arg(format!("--load-extension={}", ext_dir.display()));
    } else {
        cmd.arg("--disable-extensions");
    }
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
) -> Result<Child, LaunchError> {
    let setup = config.hardening();
    setup
        .validate()
        .map_err(|e| LaunchError::HardeningFailed(e.to_string()))?;

    let mut cmd = build_browser_command(config, profile_dir)?;

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

            setup.apply(&[0, 1, 2, CDP_FD_READ, CDP_FD_WRITE])
        });
    }

    cmd.spawn()
        .map_err(|e| LaunchError::SpawnFailed(e.to_string()))
}

#[cfg(test)]
const CLOSE_RANGE_FALLBACK_MAX: RawFd = 256;

#[cfg(test)]
fn spawn_browser_unhardened(
    config: &BrowserConfig,
    profile_dir: &Path,
    cdp: &CdpPipes,
) -> Result<Child, LaunchError> {
    let mut cmd = build_browser_command(config, profile_dir)?;

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
) -> Result<Child, LaunchError> {
    let setup = config.hardening();
    setup
        .validate()
        .map_err(|e| LaunchError::HardeningFailed(e.to_string()))?;

    let trusted_same_user = is_trusted_same_user_port_launch(config);
    let mut cmd = build_browser_command(config, profile_dir)?;
    // Port mode is explicitly the trusted-browser exposure mode. Preserve
    // Chromium's startup diagnostics in the daemon journal so sandbox/display
    // failures are actionable instead of looking like a CDP timeout.
    cmd.stderr(Stdio::inherit());

    unsafe {
        cmd.pre_exec(move || {
            if trusted_same_user {
                // Do not set PR_SET_NO_NEW_PRIVS before exec in trusted
                // same-user mode. Chromium may need its setuid sandbox helper
                // during startup. Keep a dedicated session/process group so
                // lifecycle cleanup can still terminate the complete browser.
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            } else {
                setup.apply(&[0, 1, 2])
            }
        });
    }

    cmd.spawn()
        .map_err(|e| LaunchError::SpawnFailed(e.to_string()))
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
                return Ok(format!("ws://127.0.0.1:{}{}", port, ws_path));
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
                return Ok(format!("ws://127.0.0.1:{}{}", port, ws_path));
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

fn extract_web_socket_debugger_url(http_response: &str) -> Option<String> {
    let key = "webSocketDebuggerUrl";
    let key_pos = http_response.find(key)?;
    let after_key = &http_response[key_pos + key.len()..];
    let ws_start = after_key.find("ws://")?;
    let value = &after_key[ws_start..];
    let end = value.find('"').unwrap_or(value.len());
    Some(value[..end].to_string())
}

fn write_cdp_endpoint(
    runtime_dir: &Path,
    url: &str,
    target_uid: u32,
    target_gid: u32,
) -> Result<(), LaunchError> {
    let path = runtime_dir.join("cdp-endpoint");
    fs::write(&path, url).map_err(|e| {
        LaunchError::EndpointFileWriteFailed(path.display().to_string(), e.to_string())
    })?;

    let file = fs::File::open(&path).map_err(|e| {
        LaunchError::EndpointFileWriteFailed(path.display().to_string(), e.to_string())
    })?;
    use std::os::unix::io::AsRawFd;
    let ret = unsafe { libc::fchown(file.as_raw_fd(), target_uid, target_gid) };
    if ret != 0 {
        return Err(LaunchError::EndpointFileWriteFailed(
            path.display().to_string(),
            io::Error::last_os_error().to_string(),
        ));
    }
    let perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(&path, perms).map_err(|e| {
        LaunchError::EndpointFileWriteFailed(path.display().to_string(), e.to_string())
    })?;
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
    let tmp_name = format!(".{}.tmp.{}", MANIFEST_FILENAME, std::process::id());
    let tmp_path = dir.join(&tmp_name);

    let manifest_json = serde_json::to_string_pretty(manifest).map_err(|e| {
        LaunchError::ManifestWriteFailed(manifest_path.display().to_string(), e.to_string())
    })?;

    fs::write(&tmp_path, &manifest_json).map_err(|e| {
        LaunchError::ManifestWriteFailed(tmp_path.display().to_string(), e.to_string())
    })?;

    let tmp_file = fs::File::open(&tmp_path).map_err(|e| {
        LaunchError::ManifestWriteFailed(tmp_path.display().to_string(), e.to_string())
    })?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
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
            target_uid: uid,
            target_gid: gid,
            daemon_uid: 0,
            daemon_gid: 0,
            cdp_expose: CdpExposeMode::default(),
            cdp_port: 0,
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
        let rp_ids = vec!["example.com".to_string()];
        assert!(validate_start_url("https://example.com", &rp_ids).is_ok());
        assert!(validate_start_url("https://example.com/path", &rp_ids).is_ok());
        assert!(validate_start_url("https://sub.example.com:443/path", &rp_ids).is_ok());
        assert!(validate_start_url("https://example.com?query=1", &rp_ids).is_ok());
    }

    #[test]
    fn test_validate_start_url_invalid_scheme() {
        let rp_ids = vec!["example.com".to_string()];
        assert!(validate_start_url("http://example.com", &rp_ids).is_err());
        assert!(validate_start_url("ftp://example.com", &rp_ids).is_err());
        assert!(validate_start_url("", &rp_ids).is_err());
        assert!(validate_start_url("https://", &rp_ids).is_err());
    }

    #[test]
    fn test_validate_start_url_host_must_match_rp_id() {
        let rp_ids = vec!["example.com".to_string()];
        assert!(validate_start_url("https://other.com/path", &rp_ids).is_err());
        assert!(validate_start_url("https://notexample.com/path", &rp_ids).is_err());
    }

    #[test]
    fn test_validate_start_url_matches_exactly_one_rp_id() {
        let rp_ids = vec!["example.com".to_string(), "example.org".to_string()];
        assert!(validate_start_url("https://other.com/path", &rp_ids).is_err());
        assert!(validate_start_url("https://example.com/path", &rp_ids).is_ok());
    }

    #[test]
    fn test_validate_start_url_no_rp_match() {
        let rp_ids: Vec<String> = vec![];
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
        create_lease_dir(&target, uid, gid).unwrap();
        let meta = fs::symlink_metadata(&target).unwrap();
        assert!(meta.is_dir());
        assert_eq!(meta.permissions().mode() & 0o777, RUNTIME_DIR_MODE);
        assert_eq!(meta.uid(), uid);
        assert_eq!(meta.gid(), gid);
        assert!(create_lease_dir(&target, uid, gid).is_err());
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
        let mut mgr = BrowserProcessManager::new(clock);
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
        let mut mgr = BrowserProcessManager::new(clock);
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
        let mut mgr = BrowserProcessManager::new(clock);
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
        let mut mgr = BrowserProcessManager::new(clock);
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
        let mut mgr = BrowserProcessManager::new(clock);
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
        let mut mgr = BrowserProcessManager::new(clock);
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
        let mut mgr = BrowserProcessManager::new(clock);
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
        create_lease_dir(&lease_dir, uid, gid).unwrap();

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
        let mut mgr = BrowserProcessManager::new(clock);
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
            target_uid: 1001,
            target_gid: 1001,
            daemon_uid: 0,
            daemon_gid: 0,
            cdp_expose: CdpExposeMode::default(),
            cdp_port: 0,
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
            target_uid: 1001,
            target_gid: 1001,
            daemon_uid: 0,
            daemon_gid: 0,
            cdp_expose: CdpExposeMode::default(),
            cdp_port: 0,
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
    fn test_browser_probe_uhid_deterministic_policy() {
        use super::super::launcher::probe_uhid_access;
        let result = probe_uhid_access();
        match &result {
            ProbeResult::Allowed { path } => assert_eq!(path, "/dev/uhid"),
            ProbeResult::Denied { path, .. } => assert_eq!(path, "/dev/uhid"),
        }
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
            target_uid: 1000,
            target_gid: 1000,
            daemon_uid: 0,
            daemon_gid: 0,
            cdp_expose: CdpExposeMode::Pipe,
            cdp_port: 0,
        };

        let cmd = build_browser_command(&config, dir.path()).unwrap();
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
            target_uid: 1000,
            target_gid: 1000,
            daemon_uid: 0,
            daemon_gid: 0,
            cdp_expose: CdpExposeMode::Port,
            cdp_port: 9222,
        };

        let cmd = build_browser_command(&config, dir.path()).unwrap();
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();

        assert!(args.iter().any(|a| a == "--remote-debugging-port=9222"));
        assert!(
            args.iter()
                .any(|a| a == "--remote-debugging-address=127.0.0.1")
        );
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
            target_uid: 1000,
            target_gid: 1000,
            daemon_uid: 0,
            daemon_gid: 0,
            cdp_expose: CdpExposeMode::Pipe,
            cdp_port: 0,
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
            target_uid: 1000,
            target_gid: 1000,
            daemon_uid: 0,
            daemon_gid: 0,
            cdp_expose: CdpExposeMode::Pipe,
            cdp_port: 0,
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
            target_uid: 1000,
            target_gid: 1000,
            daemon_uid: 0,
            daemon_gid: 0,
            cdp_expose: CdpExposeMode::Pipe,
            cdp_port: 0,
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
            target_uid: 1000,
            target_gid: 1000,
            daemon_uid: 0,
            daemon_gid: 0,
            cdp_expose: CdpExposeMode::Pipe,
            cdp_port: 0,
        }
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
            target_uid: 1000,
            target_gid: 1000,
            daemon_uid: 0,
            daemon_gid: 0,
            cdp_expose: CdpExposeMode::Pipe,
            cdp_port: 0,
        };
        assert!(build_browser_command(&config, dir.path()).is_ok());
    }

    #[test]
    fn test_render_channel_script_replaces_channel() {
        let template = r#"(function(ch){})("__PASSLESS_CHANNEL__");"#;
        let result = render_channel_script(template, "abc123");
        assert!(result.contains("abc123"));
        assert!(!result.contains("__PASSLESS_CHANNEL__"));
    }

    #[test]
    fn test_render_worker_script_replaces_all_placeholders() {
        let template =
            r#"(function(p,b){})("__PASSLESS_CHANNEL__",__PASSLESS_PORT__,__PASSLESS_BEARER__);"#;
        let metadata = AgentEndpointMetadata {
            port: 54321,
            bearer_token: "secrettoken".to_string(),
        };
        let result = render_worker_script(template, "chan123", &metadata);
        assert!(result.contains("chan123"));
        assert!(result.contains("54321"));
        assert!(result.contains("secrettoken"));
        assert!(!result.contains("__PASSLESS_CHANNEL__"));
        assert!(!result.contains("__PASSLESS_PORT__"));
        assert!(!result.contains("__PASSLESS_BEARER__"));
    }

    #[test]
    fn test_render_channel_script_does_not_expose_port_or_bearer() {
        let rendered = render_channel_script(
            include_str!("../../assets/agent-extension/main.js"),
            "testchannel",
        );
        assert!(!rendered.contains("__PASSLESS_PORT__"));
        assert!(!rendered.contains("__PASSLESS_BEARER__"));
        assert!(rendered.contains("testchannel"));
        assert!(!rendered.contains("__PASSLESS_CHANNEL__"));
    }

    #[test]
    fn test_render_channel_script_broker_no_port_or_bearer() {
        let rendered = render_channel_script(
            include_str!("../../assets/agent-extension/broker.js"),
            "testchannel",
        );
        assert!(!rendered.contains("__PASSLESS_PORT__"));
        assert!(!rendered.contains("__PASSLESS_BEARER__"));
        assert!(rendered.contains("testchannel"));
    }

    #[test]
    fn test_render_worker_script_contains_endpoint_secrets() {
        let metadata = AgentEndpointMetadata {
            port: 60000,
            bearer_token: "beartoken99".to_string(),
        };
        let rendered = render_worker_script(
            include_str!("../../assets/agent-extension/worker.js"),
            "wchan",
            &metadata,
        );
        assert!(rendered.contains("60000"));
        assert!(rendered.contains("beartoken99"));
        assert!(!rendered.contains("__PASSLESS_PORT__"));
        assert!(!rendered.contains("__PASSLESS_BEARER__"));
    }

    #[test]
    fn test_generate_agent_extension_creates_correct_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = setup_runtime_root(dir.path());
        let lease_dir = root.join("lease-ext");
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        create_lease_dir(&lease_dir, uid, gid).unwrap();

        let metadata = AgentEndpointMetadata {
            port: 55555,
            bearer_token: "deadbeef".to_string(),
        };
        let ext_dir = generate_agent_extension(&lease_dir, &metadata, uid, gid).unwrap();
        assert!(ext_dir.is_dir());
        assert!(ext_dir.join("manifest.json").exists());
        assert!(ext_dir.join("main.js").exists());
        assert!(ext_dir.join("broker.js").exists());
        assert!(ext_dir.join("worker.js").exists());
        assert!(!ext_dir.join("config.js").exists());
        assert!(!ext_dir.join("content.js").exists());
    }

    #[test]
    fn test_extension_dir_permissions_are_0700() {
        let dir = tempfile::tempdir().unwrap();
        let root = setup_runtime_root(dir.path());
        let lease_dir = root.join("lease-perm");
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        create_lease_dir(&lease_dir, uid, gid).unwrap();

        let metadata = AgentEndpointMetadata {
            port: 55555,
            bearer_token: "tok".to_string(),
        };
        let ext_dir = generate_agent_extension(&lease_dir, &metadata, uid, gid).unwrap();
        let mode = fs::symlink_metadata(&ext_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn test_worker_js_permissions_are_0600() {
        let dir = tempfile::tempdir().unwrap();
        let root = setup_runtime_root(dir.path());
        let lease_dir = root.join("lease-wperm");
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        create_lease_dir(&lease_dir, uid, gid).unwrap();

        let metadata = AgentEndpointMetadata {
            port: 55555,
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
    fn test_main_js_permissions_are_0644() {
        let dir = tempfile::tempdir().unwrap();
        let root = setup_runtime_root(dir.path());
        let lease_dir = root.join("lease-mperm");
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        create_lease_dir(&lease_dir, uid, gid).unwrap();

        let metadata = AgentEndpointMetadata {
            port: 55555,
            bearer_token: "tok".to_string(),
        };
        let ext_dir = generate_agent_extension(&lease_dir, &metadata, uid, gid).unwrap();
        let main_mode = fs::symlink_metadata(ext_dir.join("main.js"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(main_mode, 0o644);
        let broker_mode = fs::symlink_metadata(ext_dir.join("broker.js"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(broker_mode, 0o644);
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
        create_lease_dir(&lease_dir, uid, gid).unwrap();

        let metadata = AgentEndpointMetadata {
            port: 55555,
            bearer_token: "tok".to_string(),
        };
        let ext_dir = generate_agent_extension(&lease_dir, &metadata, uid, gid).unwrap();
        for name in &["main.js", "broker.js", "worker.js"] {
            let content = fs::read_to_string(ext_dir.join(name)).unwrap();
            assert!(
                !content.contains("__PASSLESS_CHANNEL__"),
                "{} has unresolved channel placeholder",
                name
            );
            assert!(
                !content.contains("__PASSLESS_PORT__"),
                "{} has unresolved port placeholder",
                name
            );
            assert!(
                !content.contains("__PASSLESS_BEARER__"),
                "{} has unresolved bearer placeholder",
                name
            );
        }
    }

    #[test]
    fn test_main_js_has_no_port_or_bearer_values() {
        let dir = tempfile::tempdir().unwrap();
        let root = setup_runtime_root(dir.path());
        let lease_dir = root.join("lease-nosec");
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        create_lease_dir(&lease_dir, uid, gid).unwrap();

        let metadata = AgentEndpointMetadata {
            port: 55555,
            bearer_token: "supersecretbearer".to_string(),
        };
        let ext_dir = generate_agent_extension(&lease_dir, &metadata, uid, gid).unwrap();
        let main_content = fs::read_to_string(ext_dir.join("main.js")).unwrap();
        assert!(!main_content.contains("55555"));
        assert!(!main_content.contains("supersecretbearer"));
        let broker_content = fs::read_to_string(ext_dir.join("broker.js")).unwrap();
        assert!(!broker_content.contains("55555"));
        assert!(!broker_content.contains("supersecretbearer"));
    }

    #[test]
    fn test_no_metadata_file_written() {
        let dir = tempfile::tempdir().unwrap();
        let root = setup_runtime_root(dir.path());
        let lease_dir = root.join("lease-nometa");
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        create_lease_dir(&lease_dir, uid, gid).unwrap();

        let metadata = AgentEndpointMetadata {
            port: 55555,
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
    fn test_manifest_has_main_world_content_script() {
        let manifest_str = include_str!("../../assets/agent-extension/manifest.json");
        let parsed: serde_json::Value = serde_json::from_str(manifest_str).unwrap();
        let scripts = parsed["content_scripts"].as_array().unwrap();
        let main_script = scripts
            .iter()
            .find(|s| s["world"] == "MAIN")
            .expect("MAIN world content script required");
        assert_eq!(main_script["run_at"], "document_start");
        assert_eq!(main_script["all_frames"], true);
        let js = main_script["js"].as_array().unwrap();
        assert!(js.iter().any(|j| j == "main.js"));
    }

    #[test]
    fn test_manifest_has_isolated_world_broker() {
        let manifest_str = include_str!("../../assets/agent-extension/manifest.json");
        let parsed: serde_json::Value = serde_json::from_str(manifest_str).unwrap();
        let scripts = parsed["content_scripts"].as_array().unwrap();
        let isolated_script = scripts
            .iter()
            .find(|s| s["world"] == "ISOLATED")
            .expect("ISOLATED world content script required");
        assert_eq!(isolated_script["run_at"], "document_start");
        assert_eq!(isolated_script["all_frames"], true);
        let js = isolated_script["js"].as_array().unwrap();
        assert!(js.iter().any(|j| j == "broker.js"));
    }

    #[test]
    fn test_manifest_has_service_worker() {
        let manifest_str = include_str!("../../assets/agent-extension/manifest.json");
        let parsed: serde_json::Value = serde_json::from_str(manifest_str).unwrap();
        assert_eq!(parsed["background"]["service_worker"], "worker.js");
    }

    #[test]
    fn test_manifest_has_loopback_host_permission() {
        let manifest_str = include_str!("../../assets/agent-extension/manifest.json");
        let parsed: serde_json::Value = serde_json::from_str(manifest_str).unwrap();
        let hosts = parsed["host_permissions"].as_array().unwrap();
        assert!(
            hosts.iter().any(|h| h == "http://127.0.0.1/*"),
            "host_permissions must include http://127.0.0.1/*"
        );
    }

    #[test]
    fn test_main_js_template_syntax_valid() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let path = format!("{}/assets/agent-extension/main.js", manifest_dir);
        let status = std::process::Command::new("node")
            .arg("--check")
            .arg(&path)
            .status();
        if let Ok(s) = status {
            assert!(s.success(), "main.js has syntax errors");
        }
    }

    #[test]
    fn test_broker_js_template_syntax_valid() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let path = format!("{}/assets/agent-extension/broker.js", manifest_dir);
        let status = std::process::Command::new("node")
            .arg("--check")
            .arg(&path)
            .status();
        if let Ok(s) = status {
            assert!(s.success(), "broker.js has syntax errors");
        }
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
        create_lease_dir(&lease_dir, uid, gid).unwrap();

        let metadata = AgentEndpointMetadata {
            port: 55555,
            bearer_token: "tok".to_string(),
        };
        let ext_dir = generate_agent_extension(&lease_dir, &metadata, uid, gid).unwrap();
        for name in &["main.js", "broker.js", "worker.js"] {
            let path = ext_dir.join(name);
            let status = std::process::Command::new("node")
                .arg("--check")
                .arg(&path)
                .status();
            if let Ok(s) = status {
                assert!(s.success(), "generated {} has syntax errors", name);
            }
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
            port: 55555,
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
        assert!(ext_dir.join("main.js").exists());
        assert!(ext_dir.join("broker.js").exists());
        assert!(ext_dir.join("worker.js").exists());

        let worker_content = fs::read_to_string(ext_dir.join("worker.js")).unwrap();
        assert!(worker_content.contains("55555"));
        assert!(worker_content.contains("deadbeef"));
    }

    #[test]
    fn test_launch_pending_with_agent_endpoint_no_metadata_file() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let metadata = AgentEndpointMetadata {
            port: 55555,
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
            port: 55555,
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
    fn test_browser_command_disables_extensions_without_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let config = test_config(dir.path());

        let lease_id = mgr
            .launch_pending(&config, test_endpoint_id(), test_profile_id())
            .unwrap();

        let lease = &mgr.leases[&lease_id];
        let profile_dir = &lease.manifest.profile_dir;
        let cmd = build_browser_command(&config, profile_dir).unwrap();
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert!(
            args.iter().any(|a| a == "--disable-extensions"),
            "should disable extensions when no metadata provided"
        );
        assert!(!args.iter().any(|a| a.starts_with("--load-extension=")));
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
        create_lease_dir(&lease_dir, uid, gid).unwrap();

        let metadata = AgentEndpointMetadata {
            port: 55555,
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
    fn test_generated_worker_bearer_not_in_main_or_broker() {
        let dir = tempfile::tempdir().unwrap();
        let root = setup_runtime_root(dir.path());
        let lease_dir = root.join("lease-bearer-iso");
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        create_lease_dir(&lease_dir, uid, gid).unwrap();

        let metadata = AgentEndpointMetadata {
            port: 55555,
            bearer_token: "supersecretbearertoken".to_string(),
        };
        let ext_dir = generate_agent_extension(&lease_dir, &metadata, uid, gid).unwrap();
        let main_content = fs::read_to_string(ext_dir.join("main.js")).unwrap();
        let broker_content = fs::read_to_string(ext_dir.join("broker.js")).unwrap();
        assert!(!main_content.contains("supersecretbearertoken"));
        assert!(!broker_content.contains("supersecretbearertoken"));
    }

    #[test]
    fn test_extension_cleanup_removes_worker_token() {
        let dir = tempfile::tempdir().unwrap();
        let clock = test_clock();
        let mut mgr = BrowserProcessManager::new(clock);
        let mut config = test_config(dir.path());

        let metadata = AgentEndpointMetadata {
            port: 55555,
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
        let mut mgr = BrowserProcessManager::new(clock);
        let mut config = test_config(dir.path());
        config.executable = PathBuf::from("/bin/sleep");
        config.extra_args = vec!["60".to_string()];

        let metadata = AgentEndpointMetadata {
            port: 55555,
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
        fs::create_dir_all(&ext_dir).unwrap();
        fs::write(ext_dir.join("manifest.json"), "{}").unwrap();

        let config = BrowserConfig {
            executable: PathBuf::from("/usr/bin/chromium"),
            start_url: None,
            extra_args: Vec::new(),
            runtime_root: dir.path().to_path_buf(),
            ttl: Duration::from_secs(300),
            login_timeout: DEFAULT_LOGIN_TIMEOUT,
            rp_ids: vec!["example.com".to_string()],
            target_uid: 1000,
            target_gid: 1000,
            daemon_uid: 0,
            daemon_gid: 0,
            cdp_expose: CdpExposeMode::Pipe,
            cdp_port: 0,
        };

        let cmd = build_browser_command(&config, &profile_dir).unwrap();
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert!(args.iter().any(|a| a.starts_with("--load-extension=")));
        assert!(!args.iter().any(|a| a == "--disable-extensions"));
    }

    #[test]
    fn test_build_browser_command_disables_extensions_when_no_dir() {
        let dir = tempfile::tempdir().unwrap();
        let profile_dir = dir.path().join("no-ext").join("profile");
        fs::create_dir_all(&profile_dir).unwrap();

        let config = BrowserConfig {
            executable: PathBuf::from("/usr/bin/chromium"),
            start_url: None,
            extra_args: Vec::new(),
            runtime_root: dir.path().to_path_buf(),
            ttl: Duration::from_secs(300),
            login_timeout: DEFAULT_LOGIN_TIMEOUT,
            rp_ids: vec!["example.com".to_string()],
            target_uid: 1000,
            target_gid: 1000,
            daemon_uid: 0,
            daemon_gid: 0,
            cdp_expose: CdpExposeMode::Pipe,
            cdp_port: 0,
        };

        let cmd = build_browser_command(&config, &profile_dir).unwrap();
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();
        assert!(args.iter().any(|a| a == "--disable-extensions"));
        assert!(!args.iter().any(|a| a.starts_with("--load-extension=")));
    }

    #[test]
    fn test_agent_endpoint_metadata_serde_roundtrip() {
        let metadata = AgentEndpointMetadata {
            port: 50000,
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
}
