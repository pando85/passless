use std::collections::{BTreeMap, HashMap};
use std::ffi::CString;
use std::os::unix::io::AsRawFd;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use log::{debug, info};

use passless_core::agent::protocol::{
    AdminRequest, AdminResponse, AuthorityBrowser, AuthorityCeremony, AuthorityCredentialScope,
    AuthorityIdentity, AuthorityRisk, AuthorityRpRule, AuthoritySession, DoctorResponse,
    EffectiveAuthority, ErrorCode, PeerCred, PrincipalCapabilities, PrincipalInstructions,
    PrincipalLaunchedResponse, PrincipalRequest, PrincipalResponse, PrincipalWaitResponse,
    ProtocolError, RecommendedAction,
};
use passless_core::agent::{
    AgentConfig, AgentMode, AgentProfileConfig, BrowserLeaseId, BrowserScope, DaemonStatus,
    EndpointId, EndpointStatusResponse, GrantId, PendingRequestId, PrincipalSessionId, ProfileId,
};
use passless_core::config::SecurityConfig;

use super::audit::AuditGate;
use super::audit_events::{
    BackendKind, DaemonStartBuilder, DaemonStopBuilder, FailReason, ProfileCreateBuilder,
    ProfileFailBuilder, StopReason,
};
use super::backend::CredentialBackendHandle;
use super::browser::{BrowserConfig, BrowserProcessManager, Clock, SystemClock};
use super::intent::SystemClock as IntentSystemClock;
use super::ipc::{AdminHandler, IpcServer, PrincipalHandler, ProfileAccess, RuntimeDir};
use super::launcher::{
    PrincipalSession, SessionCapability, SpawnConfig, dup_fd_cloexec, spawn_principal,
    verify_process_ancestry,
};
use super::policy_engine::PolicyRuntime;
use super::sign::{SignContextRegistry, SignHttpServer};
use super::storage_factory::{create_storage_bundle_with_options, key_provider_for_config};
use passless_core::agent::config::CdpExposeMode;

use crate::storage::CredentialStorage;
mod browser_ensure;

const MAX_WORKERS: usize = 16;
const MAX_COMPLETED_SESSIONS: usize = 256;
const COMPLETED_SESSION_TTL: Duration = Duration::from_secs(600);
const WAIT_PRINCIPAL_POLL_INTERVAL: Duration = Duration::from_millis(50);
const TERMINATE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct RuntimeStartParams<'a> {
    pub human_storage: Arc<Mutex<Box<dyn CredentialStorage>>>,
    pub human_pin_storage: Arc<Mutex<Box<dyn crate::pin_storage::PinStorage>>>,
    pub human_operation_lock: Arc<Mutex<()>>,
    pub human_key_provider: Arc<dyn soft_fido2::CredentialKeyProvider + Send + Sync>,
    pub agent_config: &'a AgentConfig,
    pub security_config: SecurityConfig,
    pub shutdown: Arc<AtomicBool>,
}

#[allow(dead_code)]
struct RequestDelegationParams<'a> {
    profile_id: &'a ProfileId,
    session_id: &'a PrincipalSessionId,
    endpoint_id: &'a EndpointId,
    rp_id: &'a str,
    credential_ref: &'a passless_core::agent::CredentialRef,
    max_session_ttl: u64,
    principal_reason: Option<String>,
    profile: &'a ProfileRuntime,
    session_digest: &'a super::intent::ProcessIdentityDigest,
}

fn extract_cdp_method_for_audit(json: &str) -> String {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()
        .and_then(|v| {
            v.as_object()?
                .get("method")?
                .as_str()
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| "<unknown>".to_string())
}

pub struct ActiveBrowserLease {
    pub lease_id: BrowserLeaseId,
    pub session_id: PrincipalSessionId,
}

pub struct SharedBrowserLease {
    pub lease_id: BrowserLeaseId,
    pub ref_count: usize,
    pub attached_sessions: std::collections::HashSet<PrincipalSessionId>,
}

pub enum SharedDetachOutcome {
    Keep,
    Terminate(BrowserLeaseId),
}

impl SharedBrowserLease {
    pub fn attach(&mut self, session_id: &PrincipalSessionId) -> bool {
        self.attached_sessions.insert(session_id.clone())
    }

    pub fn detach(&mut self, session_id: &PrincipalSessionId) -> bool {
        self.attached_sessions.remove(session_id)
    }

    pub fn sync_ref_count(&mut self) {
        self.ref_count = self.attached_sessions.len();
    }
}

fn detach_session_from_shared(
    shared: &mut HashMap<ProfileId, SharedBrowserLease>,
    profile_id: &ProfileId,
    session_id: &PrincipalSessionId,
) -> SharedDetachOutcome {
    let Some(lease) = shared.get_mut(profile_id) else {
        return SharedDetachOutcome::Keep;
    };
    if !lease.detach(session_id) {
        return SharedDetachOutcome::Keep;
    }
    lease.sync_ref_count();
    if lease.ref_count == 0 {
        let lease_id = lease.lease_id.clone();
        shared.remove(profile_id);
        SharedDetachOutcome::Terminate(lease_id)
    } else {
        SharedDetachOutcome::Keep
    }
}

fn cleanup_all_shared_for_profile(
    shared: &mut HashMap<ProfileId, SharedBrowserLease>,
    profile_id: &ProfileId,
) -> Option<BrowserLeaseId> {
    shared.remove(profile_id).map(|lease| lease.lease_id)
}

/// The wire form of a rule action. `allow` always uses agent evidence (ADR 0014 section 7), and
/// `deny` and `request` set no UP or UV at all.
///
/// The `user_presence` / `user_verification` wire fields remain for client compatibility until P8/P9
/// reshape the authority report.
fn authority_ceremony(action: passless_core::agent::RuleAction) -> AuthorityCeremony {
    let evidence = if action == passless_core::agent::RuleAction::Allow {
        "agent"
    } else {
        "none"
    };
    AuthorityCeremony {
        authorization: action.to_string(),
        user_presence: evidence.to_string(),
        user_verification: evidence.to_string(),
    }
}

pub struct ProfileRuntime {
    pub profile_name: String,
    pub profile_id: ProfileId,
    pub uid: u32,
    pub gid: u32,
    pub endpoint_id: Mutex<Option<EndpointId>>,
    pub lifecycle_lock: Mutex<()>,
    pub security_config: SecurityConfig,
    pub operation_lock: Arc<Mutex<()>>,
    pub mode: AgentMode,
    pub profile_config: AgentProfileConfig,
    pub active_browser: Mutex<HashMap<PrincipalSessionId, ActiveBrowserLease>>,
    pub shared_browsers: Mutex<HashMap<ProfileId, SharedBrowserLease>>,
    pub daemon_uid: u32,
    pub daemon_gid: u32,
    pub browser_uid: Option<u32>,
    pub browser_gid: Option<u32>,
    pub enabled: AtomicBool,
    pub backend: CredentialBackendHandle,
    pub credential_storage: Arc<Mutex<Box<dyn CredentialStorage>>>,
}

impl core::fmt::Debug for ProfileRuntime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let eid = self.endpoint_id.lock().unwrap().clone();
        f.debug_struct("ProfileRuntime")
            .field("profile_name", &self.profile_name)
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .field("endpoint_id", &eid)
            .field("mode", &self.mode)
            .field("daemon_uid", &self.daemon_uid)
            .field("daemon_gid", &self.daemon_gid)
            .field("browser_uid", &self.browser_uid)
            .field("browser_gid", &self.browser_gid)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum RuntimeError {
    Config(String),
    UserResolve { user: String, detail: String },
    Audit(String),
    Ipc(String),
    Endpoint(String),
    Storage(String),
    Policy(String),
    Service(String),
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(msg) => write!(f, "agent config error: {}", msg),
            Self::UserResolve { user, detail } => {
                write!(f, "failed to resolve user '{}': {}", user, detail)
            }
            Self::Audit(msg) => write!(f, "audit subsystem error: {}", msg),
            Self::Ipc(msg) => write!(f, "IPC error: {}", msg),
            Self::Endpoint(msg) => write!(f, "endpoint error: {}", msg),
            Self::Storage(msg) => write!(f, "storage error: {}", msg),
            Self::Policy(msg) => write!(f, "policy error: {}", msg),
            Self::Service(msg) => write!(f, "service error: {}", msg),
        }
    }
}

impl std::error::Error for RuntimeError {}

#[derive(Clone)]
struct ResolvedUser {
    uid: u32,
    gid: u32,
}

fn resolve_user(username: &str) -> Result<ResolvedUser, RuntimeError> {
    let c_name = CString::new(username).map_err(|e| RuntimeError::UserResolve {
        user: username.to_string(),
        detail: format!("invalid username: {}", e),
    })?;

    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0u8; 4096];

    let ret = unsafe {
        libc::getpwnam_r(
            c_name.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        )
    };

    if ret != 0 {
        return Err(RuntimeError::UserResolve {
            user: username.to_string(),
            detail: format!("getpwnam_r failed with errno {}", ret),
        });
    }

    if result.is_null() {
        return Err(RuntimeError::UserResolve {
            user: username.to_string(),
            detail: "user not found".to_string(),
        });
    }

    Ok(ResolvedUser {
        uid: unsafe { (*result).pw_uid },
        gid: unsafe { (*result).pw_gid },
    })
}

fn validate_browser_runtime_root_at_startup(
    path: &std::path::Path,
    expected_uid: u32,
    profile_name: &str,
) -> Result<(), RuntimeError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let meta = std::fs::symlink_metadata(path).map_err(|e| {
        RuntimeError::Config(format!(
            "profile '{}': browser_runtime_root '{}' does not exist: {}",
            profile_name,
            path.display(),
            e
        ))
    })?;

    if meta.file_type().is_symlink() {
        return Err(RuntimeError::Config(format!(
            "profile '{}': browser_runtime_root '{}' is a symlink",
            profile_name,
            path.display()
        )));
    }

    if !meta.is_dir() {
        return Err(RuntimeError::Config(format!(
            "profile '{}': browser_runtime_root '{}' is not a directory",
            profile_name,
            path.display()
        )));
    }

    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o700 {
        return Err(RuntimeError::Config(format!(
            "profile '{}': browser_runtime_root '{}' mode is {:o}, expected 700",
            profile_name,
            path.display(),
            mode
        )));
    }

    if meta.uid() != expected_uid {
        return Err(RuntimeError::Config(format!(
            "profile '{}': browser_runtime_root '{}' owned by uid {}, expected uid {}",
            profile_name,
            path.display(),
            meta.uid(),
            expected_uid
        )));
    }

    Ok(())
}

fn validate_principal_executable(
    path_str: &str,
    daemon_uid: u32,
) -> Result<std::path::PathBuf, ProtocolError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let path = std::path::Path::new(path_str);

    if !path.is_absolute() {
        return Err(ProtocolError::new(
            ErrorCode::Forbidden,
            format!("executable path must be absolute: '{}'", path_str),
            RecommendedAction::FixRequest,
        ));
    }

    let canonical = std::fs::canonicalize(path).map_err(|e| {
        ProtocolError::new(
            ErrorCode::Forbidden,
            format!("executable path '{}' cannot be resolved: {}", path_str, e),
            RecommendedAction::FixRequest,
        )
    })?;

    let meta = std::fs::symlink_metadata(&canonical).map_err(|e| {
        ProtocolError::new(
            ErrorCode::Forbidden,
            format!("executable '{}' metadata error: {}", canonical.display(), e),
            RecommendedAction::FixRequest,
        )
    })?;

    if !meta.is_file() {
        return Err(ProtocolError::new(
            ErrorCode::Forbidden,
            format!("executable '{}' is not a regular file", canonical.display()),
            RecommendedAction::FixRequest,
        ));
    }

    let owner = meta.uid();
    if owner != 0 && owner != daemon_uid {
        return Err(ProtocolError::new(
            ErrorCode::Forbidden,
            format!(
                "executable '{}' must be owned by root (uid 0) or daemon uid {}, owned by uid {}",
                canonical.display(),
                daemon_uid,
                owner
            ),
            RecommendedAction::FixRequest,
        ));
    }

    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(ProtocolError::new(
            ErrorCode::Forbidden,
            format!(
                "executable '{}' must not be group/world writable (mode {:o})",
                canonical.display(),
                mode
            ),
            RecommendedAction::FixRequest,
        ));
    }

    Ok(canonical)
}

struct WorkerTracker {
    handles: Mutex<Vec<JoinHandle<()>>>,
    active: AtomicUsize,
}

impl WorkerTracker {
    fn new() -> Self {
        Self {
            handles: Mutex::new(Vec::new()),
            active: AtomicUsize::new(0),
        }
    }

    fn try_acquire(&self) -> bool {
        loop {
            let current = self.active.load(Ordering::Acquire);
            if current >= MAX_WORKERS {
                return false;
            }
            if self
                .active
                .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }

    fn release(&self) {
        self.active.fetch_sub(1, Ordering::Release);
    }

    fn push_handle(&self, handle: JoinHandle<()>) {
        self.handles.lock().unwrap().push(handle);
    }

    fn reap_finished(&self) {
        let mut handles = self.handles.lock().unwrap();
        let mut remaining = Vec::with_capacity(handles.len());
        for h in handles.drain(..) {
            if h.is_finished() {
                let _ = h.join();
            } else {
                remaining.push(h);
            }
        }
        *handles = remaining;
    }

    fn join_all(&self) {
        let handles: Vec<_> = {
            let mut guard = self.handles.lock().unwrap();
            std::mem::take(&mut *guard)
        };
        for h in handles {
            let _ = h.join();
        }
    }
}

pub struct ManagedPrincipalSession {
    pub session_id: PrincipalSessionId,
    pub profile_id: ProfileId,
    pub session: PrincipalSession,
    pub process_digest: super::intent::ProcessIdentityDigest,
    pub created_at: Instant,
    pub deadline: Instant,
    pub client_pid: i32,
}

impl std::fmt::Debug for ManagedPrincipalSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedPrincipalSession")
            .field("session_id", &self.session_id)
            .field("profile_id", &self.profile_id)
            .field("pid", &self.session.child.id())
            .field("process_digest", &self.process_digest)
            .field("created_at", &self.created_at)
            .field("deadline", &self.deadline)
            .field("client_pid", &self.client_pid)
            .finish()
    }
}

pub struct CompletedSession {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub completed_at: Instant,
}

pub struct AgentRuntime {
    ipc_server: Arc<IpcServer>,
    audit_gate: Arc<AuditGate>,
    policy_runtime: Arc<PolicyRuntime>,
    browser_manager: Arc<Mutex<BrowserProcessManager>>,
    profiles: BTreeMap<ProfileId, ProfileRuntime>,
    managed_sessions: BTreeMap<ProfileId, Mutex<Vec<ManagedPrincipalSession>>>,
    completed_sessions: Mutex<BTreeMap<String, CompletedSession>>,
    shutdown: Arc<AtomicBool>,
    shutdown_requested: AtomicBool,
    runtime_cleanup_started: AtomicBool,
    runtime_loop: Mutex<Option<JoinHandle<()>>>,
    worker_tracker: WorkerTracker,
    daemon_uid: u32,
    daemon_gid: u32,
    agent_config: std::sync::RwLock<AgentConfig>,
    sign_registry: Arc<SignContextRegistry>,
    sign_server_shutdown: Arc<AtomicBool>,
    sign_server_handle: Mutex<Option<JoinHandle<()>>>,
    #[allow(dead_code)]
    sign_socket_path: std::path::PathBuf,
}

impl AgentRuntime {
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        human_storage: Arc<Mutex<Box<dyn CredentialStorage>>>,
        human_pin_storage: Arc<Mutex<Box<dyn crate::pin_storage::PinStorage>>>,
        human_operation_lock: Arc<Mutex<()>>,
        human_key_provider: Arc<dyn soft_fido2::CredentialKeyProvider + Send + Sync>,
        agent_config: &AgentConfig,
        security_config: SecurityConfig,
        shutdown: Arc<AtomicBool>,
    ) -> Result<Arc<Self>, RuntimeError> {
        Self::start_with_factories(RuntimeStartParams {
            human_storage,
            human_pin_storage,
            human_operation_lock,
            human_key_provider,
            agent_config,
            security_config,
            shutdown,
        })
    }

    pub fn start_with_factories(params: RuntimeStartParams<'_>) -> Result<Arc<Self>, RuntimeError> {
        let RuntimeStartParams {
            human_storage,
            human_pin_storage,
            human_operation_lock,
            human_key_provider,
            agent_config,
            security_config,
            shutdown,
        } = params;
        let human_backend = CredentialBackendHandle::human(
            human_storage,
            human_pin_storage,
            human_key_provider,
            human_operation_lock,
        );
        let daemon_uid = unsafe { libc::getuid() };
        let daemon_gid = unsafe { libc::getgid() };
        let _startup_mono = Instant::now();

        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let monotonic_clock: Arc<dyn super::intent::MonotonicClock> =
            Arc::new(IntentSystemClock::new());

        let audit_path = agent_config.audit_path.as_ref().ok_or_else(|| {
            RuntimeError::Config("agents.audit_path is required when agent is enabled".into())
        })?;
        let audit_gate = Arc::new(
            AuditGate::open(audit_path)
                .map_err(|e| RuntimeError::Audit(format!("failed to open audit gate: {}", e)))?,
        );

        let start_event = DaemonStartBuilder::new(std::process::id(), BackendKind::Local).build();
        let _ = audit_gate.record(start_event);

        let policy_runtime = Arc::new(
            PolicyRuntime::new(
                agent_config,
                clock.clone(),
                monotonic_clock.clone(),
                Some(audit_gate.clone()),
            )
            .map_err(|e| RuntimeError::Policy(format!("failed to create policy runtime: {}", e)))?,
        );

        let browser_manager =
            Arc::new(Mutex::new(BrowserProcessManager::production(clock.clone())));

        let mut profile_access = BTreeMap::new();
        let mut resolved_users: Vec<(String, ResolvedUser)> = Vec::new();
        let mut resolved_browser_users: Vec<(String, Option<ResolvedUser>)> = Vec::new();

        for (name, profile) in &agent_config.profiles {
            let user = resolve_user(&profile.principal_user)?;

            let is_root = unsafe { libc::geteuid() == 0 };
            if is_root {
                if user.uid == daemon_uid {
                    return Err(RuntimeError::Config(format!(
                        "profile '{}': principal uid {} must differ from daemon uid",
                        name, daemon_uid
                    )));
                }
                if user.uid == 0 {
                    return Err(RuntimeError::Config(format!(
                        "profile '{}': principal must not be root",
                        name
                    )));
                }
            }

            let cdp_port_mode = profile.browser_cdp_expose
                == Some(passless_core::agent::config::CdpExposeMode::Port);

            let browser_user_resolved = if let Some(ref browser_user) = profile.browser_user {
                let bu = resolve_user(browser_user)?;
                if is_root && !cdp_port_mode {
                    if bu.uid == user.uid {
                        return Err(RuntimeError::Config(format!(
                            "profile '{}': browser uid {} must differ from principal uid {}",
                            name, bu.uid, user.uid
                        )));
                    }
                    if bu.uid == daemon_uid {
                        return Err(RuntimeError::Config(format!(
                            "profile '{}': browser uid {} must differ from daemon uid {}",
                            name, bu.uid, daemon_uid
                        )));
                    }
                    if bu.uid == 0 {
                        return Err(RuntimeError::Config(format!(
                            "profile '{}': browser must not be root",
                            name
                        )));
                    }
                }
                if let Some(ref runtime_root) = profile.browser_runtime_root {
                    validate_browser_runtime_root_at_startup(runtime_root, bu.uid, name)?;
                }
                Some(bu)
            } else if cdp_port_mode {
                Some(user.clone())
            } else {
                None
            };

            profile_access.insert(
                name.clone(),
                ProfileAccess {
                    expected_uid: user.uid,
                    expected_gid: user.gid,
                },
            );
            resolved_users.push((name.clone(), user));
            resolved_browser_users.push((name.clone(), browser_user_resolved));
        }

        if !agent_config.profiles.is_empty() {
            let probes = super::doctor::ProductionProbes;
            let mut profile_startup_infos = Vec::new();

            for ((name, profile), resolved) in
                agent_config.profiles.iter().zip(resolved_users.iter())
            {
                let resolved = &resolved.1;
                let mut storage_roots = Vec::new();

                if let Some(ref storage) = profile.storage {
                    for (label, path) in storage.all_paths() {
                        storage_roots.push((label, path, daemon_uid));
                    }
                }

                let browser_runtime_root = if let (Some(_browser_user), Some(brt_path)) =
                    (&profile.browser_user, &profile.browser_runtime_root)
                {
                    let brt_uid = resolved_browser_users
                        .iter()
                        .find(|(n, _)| n == name)
                        .and_then(|(_, bu)| bu.as_ref())
                        .map(|bu| bu.uid)
                        .unwrap_or(resolved.uid);
                    Some(super::doctor::BrowserRuntimeRootInfo {
                        path: brt_path.clone(),
                        expected_uid: brt_uid,
                    })
                } else {
                    None
                };

                let mut uid_checks = Vec::new();
                let is_root = unsafe { libc::geteuid() == 0 };
                if is_root {
                    uid_checks.push(super::doctor::UidCheck {
                        label: "principal_vs_daemon".into(),
                        passed: resolved.uid != daemon_uid,
                        message: if resolved.uid != daemon_uid {
                            format!(
                                "principal uid {} differs from daemon uid {}",
                                resolved.uid, daemon_uid
                            )
                        } else {
                            format!(
                                "principal uid {} same as daemon uid {}",
                                resolved.uid, daemon_uid
                            )
                        },
                    });
                    uid_checks.push(super::doctor::UidCheck {
                        label: "principal_not_root".into(),
                        passed: resolved.uid != 0,
                        message: if resolved.uid != 0 {
                            "principal is not root".into()
                        } else {
                            "principal must not be root".into()
                        },
                    });
                    if let Some(bu) = resolved_browser_users
                        .iter()
                        .find(|(n, _)| n == name)
                        .and_then(|(_, bu)| bu.as_ref())
                    {
                        uid_checks.push(super::doctor::UidCheck {
                            label: "browser_vs_principal".into(),
                            passed: bu.uid != resolved.uid,
                            message: if bu.uid != resolved.uid {
                                format!(
                                    "browser uid {} differs from principal uid {}",
                                    bu.uid, resolved.uid
                                )
                            } else {
                                format!(
                                    "browser uid {} same as principal uid {}",
                                    bu.uid, resolved.uid
                                )
                            },
                        });
                        uid_checks.push(super::doctor::UidCheck {
                            label: "browser_vs_daemon".into(),
                            passed: bu.uid != daemon_uid,
                            message: if bu.uid != daemon_uid {
                                format!(
                                    "browser uid {} differs from daemon uid {}",
                                    bu.uid, daemon_uid
                                )
                            } else {
                                format!("browser uid {} same as daemon uid {}", bu.uid, daemon_uid)
                            },
                        });
                        uid_checks.push(super::doctor::UidCheck {
                            label: "browser_not_root".into(),
                            passed: bu.uid != 0,
                            message: if bu.uid != 0 {
                                "browser is not root".into()
                            } else {
                                "browser must not be root".into()
                            },
                        });
                    }
                }

                profile_startup_infos.push((name.clone(), {
                    super::doctor::ProfileStartupInfo {
                        storage_roots: storage_roots
                            .iter()
                            .map(|(l, p, u)| (l.clone(), p.clone(), *u))
                            .collect(),
                        browser_runtime_root: browser_runtime_root.map(|brt| {
                            super::doctor::BrowserRuntimeRootInfo {
                                path: brt.path,
                                expected_uid: brt.expected_uid,
                            }
                        }),
                        uid_checks: Vec::new(),
                    }
                }));
            }

            let mut final_infos: Vec<(String, super::doctor::ProfileStartupInfo)> = Vec::new();
            for (i, (name, info)) in profile_startup_infos.into_iter().enumerate() {
                let mut info = info;

                let resolved = &resolved_users[i].1;
                let is_root = unsafe { libc::geteuid() == 0 };
                if is_root {
                    info.uid_checks.push(super::doctor::UidCheck {
                        label: "principal_vs_daemon".into(),
                        passed: resolved.uid != daemon_uid,
                        message: if resolved.uid != daemon_uid {
                            format!(
                                "principal uid {} differs from daemon uid {}",
                                resolved.uid, daemon_uid
                            )
                        } else {
                            format!(
                                "principal uid {} same as daemon uid {}",
                                resolved.uid, daemon_uid
                            )
                        },
                    });
                    info.uid_checks.push(super::doctor::UidCheck {
                        label: "principal_not_root".into(),
                        passed: resolved.uid != 0,
                        message: if resolved.uid != 0 {
                            "principal is not root".into()
                        } else {
                            "principal must not be root".into()
                        },
                    });
                    if let Some(bu) = resolved_browser_users
                        .iter()
                        .find(|(n, _)| n == &name)
                        .and_then(|(_, bu)| bu.as_ref())
                    {
                        info.uid_checks.push(super::doctor::UidCheck {
                            label: "browser_vs_principal".into(),
                            passed: bu.uid != resolved.uid,
                            message: if bu.uid != resolved.uid {
                                format!(
                                    "browser uid {} differs from principal uid {}",
                                    bu.uid, resolved.uid
                                )
                            } else {
                                format!(
                                    "browser uid {} same as principal uid {}",
                                    bu.uid, resolved.uid
                                )
                            },
                        });
                        info.uid_checks.push(super::doctor::UidCheck {
                            label: "browser_vs_daemon".into(),
                            passed: bu.uid != daemon_uid,
                            message: if bu.uid != daemon_uid {
                                format!(
                                    "browser uid {} differs from daemon uid {}",
                                    bu.uid, daemon_uid
                                )
                            } else {
                                format!("browser uid {} same as daemon uid {}", bu.uid, daemon_uid)
                            },
                        });
                        info.uid_checks.push(super::doctor::UidCheck {
                            label: "browser_not_root".into(),
                            passed: bu.uid != 0,
                            message: if bu.uid != 0 {
                                "browser is not root".into()
                            } else {
                                "browser must not be root".into()
                            },
                        });
                    }
                }

                final_infos.push((name, info));
            }

            let diag = super::doctor::run_startup_diagnostics(
                &probes,
                true,
                agent_config.audit_path.as_deref(),
                &final_infos,
            );

            if !diag.is_ok() {
                for check in &diag.checks {
                    if !check.passed {
                        log::error!(
                            "startup diagnostic failed: {}: {}",
                            check.name,
                            check.message
                        );
                    }
                }
                return Err(RuntimeError::Config(format!(
                    "startup diagnostics failed: {}",
                    diag.fatal.join("; ")
                )));
            }

            for check in &diag.checks {
                log::info!(
                    "startup diagnostic: {} = {} ({})",
                    check.name,
                    if check.passed { "ok" } else { "FAIL" },
                    check.message
                );
            }
        }

        let ipc_server = if !agent_config.profiles.is_empty() {
            let runtime_base = dirs::runtime_dir()
                .or_else(|| {
                    let uid = unsafe { libc::getuid() };
                    Some(PathBuf::from(format!("/tmp/passless-agent-{}", uid)))
                })
                .ok_or_else(|| RuntimeError::Config("cannot resolve runtime directory".into()))?;

            let agent_runtime_dir = runtime_base.join("agent");
            let runtime_dir =
                RuntimeDir::create(&agent_runtime_dir, daemon_uid, daemon_gid, &profile_access)
                    .map_err(|e| {
                        RuntimeError::Ipc(format!("failed to create runtime dir: {}", e))
                    })?;

            let ipc_cancel = Arc::new(AtomicBool::new(false));
            Some(Arc::new(
                IpcServer::bind(
                    runtime_dir,
                    profile_access,
                    ipc_cancel,
                    PathBuf::from("/proc"),
                )
                .map_err(|e| RuntimeError::Ipc(format!("failed to bind IPC server: {}", e)))?,
            ))
        } else {
            None
        };

        let ipc_server = ipc_server.ok_or_else(|| {
            RuntimeError::Config("IPC server is required for agent runtime".into())
        })?;

        let sign_registry = Arc::new(SignContextRegistry::new());
        let sign_server_shutdown = Arc::new(AtomicBool::new(false));
        let sign_socket_base = dirs::runtime_dir()
            .or_else(|| {
                let uid = unsafe { libc::getuid() };
                Some(PathBuf::from(format!("/tmp/passless-agent-{}", uid)))
            })
            .ok_or_else(|| RuntimeError::Config("cannot resolve runtime directory".into()))?;
        let sign_socket_path = sign_socket_base.join("agent").join("sign").join("sock");
        let sign_server =
            SignHttpServer::bind(sign_socket_path.clone(), sign_server_shutdown.clone()).map_err(
                |e| RuntimeError::Service(format!("failed to bind sign HTTP server: {}", e)),
            )?;
        info!(
            "Sign HTTP server listening on {}",
            sign_socket_path.display()
        );
        let sign_server_handle = sign_server.serve(sign_registry.clone());

        let mut profiles = BTreeMap::new();

        for (((name, profile), resolved), browser_resolved) in agent_config
            .profiles
            .iter()
            .zip(resolved_users.iter())
            .zip(resolved_browser_users.iter())
        {
            let profile_id = ProfileId::new(name.clone()).map_err(|e| {
                RuntimeError::Config(format!("profile '{}': invalid profile id: {}", name, e))
            })?;
            let resolved = &resolved.1;
            let browser_uid = browser_resolved.1.as_ref().map(|bu| bu.uid);
            let browser_gid = browser_resolved.1.as_ref().map(|bu| bu.gid);

            let profile_create_event = ProfileCreateBuilder::new(profile_id.clone()).build();
            audit_gate.record(profile_create_event).map_err(|e| {
                RuntimeError::Audit(format!("profile '{}' create audit: {}", name, e))
            })?;

            let backend_result: Result<CredentialBackendHandle, RuntimeError> = match profile.mode {
                AgentMode::SameUser => Ok(human_backend.clone()),
                AgentMode::Isolated => {
                    let storage_config = profile.storage.as_ref().ok_or_else(|| {
                        RuntimeError::Config(format!(
                            "profile '{}': isolated mode requires storage configuration",
                            name
                        ))
                    })?;

                    let bundle = create_storage_bundle_with_options(storage_config.clone(), true)
                        .map_err(|e| {
                        RuntimeError::Storage(format!(
                            "profile '{}': failed to create storage bundle: {}",
                            name, e
                        ))
                    })?;
                    let key_provider = key_provider_for_config(storage_config).map_err(|e| {
                        RuntimeError::Storage(format!(
                            "profile '{}': failed to resolve credential key provider: {}",
                            name, e
                        ))
                    })?;
                    Ok(CredentialBackendHandle::isolated(
                        profile_id.clone(),
                        bundle.credential_storage.clone(),
                        bundle.pin_storage.clone(),
                        key_provider,
                        Arc::new(Mutex::new(())),
                    ))
                }
            };
            let backend = match backend_result {
                Ok(backend) => backend,
                Err(e) => {
                    let fail_event =
                        ProfileFailBuilder::new(profile_id.clone(), FailReason::InternalError)
                            .build();
                    let _ = audit_gate.record(fail_event);
                    return Err(e);
                }
            };

            // The endpoint id is a logical handle for grants and intents; no device backs it.
            profiles.insert(
                profile_id.clone(),
                ProfileRuntime {
                    profile_name: name.clone(),
                    profile_id: profile_id.clone(),
                    uid: resolved.uid,
                    gid: resolved.gid,
                    endpoint_id: Mutex::new(Some(EndpointId::new())),
                    lifecycle_lock: Mutex::new(()),
                    security_config: security_config.clone(),
                    operation_lock: backend.operation_lock.clone(),
                    mode: profile.mode,
                    profile_config: profile.clone(),
                    active_browser: Mutex::new(HashMap::new()),
                    shared_browsers: Mutex::new(HashMap::new()),
                    daemon_uid,
                    daemon_gid,
                    browser_uid,
                    browser_gid,
                    enabled: AtomicBool::new(true),
                    credential_storage: backend.credential_storage.clone(),
                    backend,
                },
            );
        }

        info!("Agent runtime started with {} profile(s)", profiles.len());

        let mut managed_sessions = BTreeMap::new();
        for profile_id in profiles.keys() {
            managed_sessions.insert(profile_id.clone(), Mutex::new(Vec::new()));
        }

        let runtime = Arc::new(Self {
            ipc_server: ipc_server.clone(),
            audit_gate,
            policy_runtime,
            browser_manager,
            profiles,
            managed_sessions,
            completed_sessions: Mutex::new(BTreeMap::new()),
            shutdown: shutdown.clone(),
            shutdown_requested: AtomicBool::new(false),
            runtime_cleanup_started: AtomicBool::new(false),
            runtime_loop: Mutex::new(None),
            worker_tracker: WorkerTracker::new(),
            daemon_uid,
            daemon_gid,
            agent_config: std::sync::RwLock::new(agent_config.clone()),
            sign_registry,
            sign_server_shutdown,
            sign_server_handle: Mutex::new(Some(sign_server_handle)),
            sign_socket_path,
        });

        let runtime_for_loop = Arc::clone(&runtime);
        let loop_handle = std::thread::Builder::new()
            .name("agent-runtime-loop".to_string())
            .spawn(move || {
                runtime_for_loop.runtime_loop();
            })
            .map_err(|e| RuntimeError::Service(format!("failed to spawn runtime loop: {}", e)))?;

        *runtime.runtime_loop.lock().unwrap() = Some(loop_handle);

        Ok(runtime)
    }

    fn runtime_loop(self: &Arc<Self>) {
        info!("Agent runtime loop started");
        let loop_sleep = Duration::from_millis(50);

        while !self.shutdown.load(Ordering::Acquire) {
            if self.shutdown_requested.load(Ordering::Acquire) {
                info!("Runtime shutdown requested via admin");
                self.shutdown.store(true, Ordering::Release);
                break;
            }

            if let Err(e) = self.accept_and_dispatch_admin() {
                debug!("Admin accept error: {}", e);
            }

            for profile_id in self.profiles.keys().cloned().collect::<Vec<_>>() {
                if let Err(e) = self.accept_and_dispatch_principal(&profile_id) {
                    debug!("Principal accept error for {}: {}", profile_id, e);
                }
            }

            self.worker_tracker.reap_finished();
            self.reap_expired_sessions();
            self.prune_completed_sessions();
            self.cleanup_expired_pending();

            {
                let mut browser_mgr = self.browser_manager.lock().unwrap();
                let exit_infos = browser_mgr.check_exits();
                for info in &exit_infos {
                    self.revoke_sign_context_for_lease(&info.lease_id);
                    let _ = self.audit_gate.record(
                        super::audit_events::BrowserLeaseCrashBuilder::new(
                            info.lease_id.clone(),
                            info.exit_code.unwrap_or(-1),
                        )
                        .build(),
                    );
                    for profile in self.profiles.values() {
                        let mut cleared = false;
                        {
                            let mut active = profile.active_browser.lock().unwrap();
                            let before = active.len();
                            active.retain(|_, lease| lease.lease_id != info.lease_id);
                            cleared |= active.len() != before;
                        }
                        {
                            let mut shared = profile.shared_browsers.lock().unwrap();
                            if let Some(lease) = shared.get(&profile.profile_id)
                                && lease.lease_id == info.lease_id
                            {
                                shared.remove(&profile.profile_id);
                                cleared = true;
                            }
                        }
                        if cleared {
                            let cleanup_result = browser_mgr.cleanup(&info.lease_id);
                            let _ = self.audit_gate.record(
                                super::audit_events::BrowserLeaseCleanupBuilder::new(
                                    info.lease_id.clone(),
                                )
                                .build(),
                            );
                            match cleanup_result {
                                Ok(super::browser::CleanupSafety::Clean) => {}
                                Ok(super::browser::CleanupSafety::Quarantined {
                                    ref reason,
                                    ..
                                }) => {
                                    let _ = self.audit_gate.record(
                                        super::audit_events::BrowserLeaseQuarantineBuilder::new(
                                            info.lease_id.clone(),
                                            super::audit_events::QuarantineReason::IntegrityViolation,
                                        )
                                        .build(),
                                    );
                                    let _ = reason;
                                }
                                Ok(super::browser::CleanupSafety::Failed { .. }) => {
                                    let _ = self.audit_gate.record(
                                        super::audit_events::BrowserLeaseQuarantineBuilder::new(
                                            info.lease_id.clone(),
                                            super::audit_events::QuarantineReason::ManifestTampered,
                                        )
                                        .build(),
                                    );
                                }
                                Err(_) => {
                                    let _ = self.audit_gate.record(
                                        super::audit_events::BrowserLeaseQuarantineBuilder::new(
                                            info.lease_id.clone(),
                                            super::audit_events::QuarantineReason::IntegrityViolation,
                                        )
                                        .build(),
                                    );
                                }
                            }
                            browser_mgr.remove(&info.lease_id);
                        }
                    }
                }
                let expired_leases = browser_mgr.check_expired();
                for lease_id in &expired_leases {
                    self.revoke_sign_context_for_lease(lease_id);
                    let _ = self.audit_gate.record(
                        super::audit_events::BrowserLeaseExpireBuilder::new(lease_id.clone())
                            .build(),
                    );
                    for profile in self.profiles.values() {
                        let mut cleared = false;
                        {
                            let mut active = profile.active_browser.lock().unwrap();
                            let before = active.len();
                            active.retain(|_, lease| lease.lease_id != *lease_id);
                            cleared |= active.len() != before;
                        }
                        {
                            let mut shared = profile.shared_browsers.lock().unwrap();
                            if let Some(lease) = shared.get(&profile.profile_id)
                                && lease.lease_id == *lease_id
                            {
                                shared.remove(&profile.profile_id);
                                cleared = true;
                            }
                        }
                        if cleared {
                            let cleanup_result = browser_mgr.cleanup(lease_id);
                            let _ = self.audit_gate.record(
                                super::audit_events::BrowserLeaseCleanupBuilder::new(
                                    lease_id.clone(),
                                )
                                .build(),
                            );
                            match cleanup_result {
                                Ok(super::browser::CleanupSafety::Clean) => {}
                                Ok(super::browser::CleanupSafety::Quarantined { .. }) => {
                                    let _ = self.audit_gate.record(
                                        super::audit_events::BrowserLeaseQuarantineBuilder::new(
                                            lease_id.clone(),
                                            super::audit_events::QuarantineReason::IntegrityViolation,
                                        )
                                        .build(),
                                    );
                                }
                                Ok(super::browser::CleanupSafety::Failed { .. }) => {
                                    let _ = self.audit_gate.record(
                                        super::audit_events::BrowserLeaseQuarantineBuilder::new(
                                            lease_id.clone(),
                                            super::audit_events::QuarantineReason::ManifestTampered,
                                        )
                                        .build(),
                                    );
                                }
                                Err(_) => {
                                    let _ = self.audit_gate.record(
                                        super::audit_events::BrowserLeaseQuarantineBuilder::new(
                                            lease_id.clone(),
                                            super::audit_events::QuarantineReason::IntegrityViolation,
                                        )
                                        .build(),
                                    );
                                }
                            }
                            browser_mgr.remove(lease_id);
                        }
                    }
                }
            }

            std::thread::sleep(loop_sleep);
        }

        info!("Agent runtime loop exiting");
    }

    fn accept_and_dispatch_admin(self: &Arc<Self>) -> Result<(), String> {
        let client_fd = match self.ipc_server.accept_admin_connection() {
            Ok(Some(fd)) => fd,
            Ok(None) => return Ok(()),
            Err(e) => return Err(format!("admin accept failed: {}", e)),
        };

        if !self.worker_tracker.try_acquire() {
            debug!("Worker limit reached, rejecting admin connection");
            drop(client_fd);
            return Ok(());
        }

        let ipc = Arc::clone(&self.ipc_server);
        let runtime = Arc::clone(self);

        let handle = std::thread::Builder::new()
            .name("admin-worker".to_string())
            .spawn(move || {
                struct WorkerExitGuard(Arc<AgentRuntime>);
                impl Drop for WorkerExitGuard {
                    fn drop(&mut self) {
                        self.0.worker_tracker.release();
                    }
                }
                let _guard = WorkerExitGuard(runtime.clone());
                match ipc.handle_one_admin(client_fd, &*runtime) {
                    Ok(Some(child_pid)) => {
                        // Keep this thread alive until the child exits.
                        // PR_SET_PDEATHSIG tracks the parent thread, so if this thread exits
                        // the kernel delivers SIGTERM to the child.  By waiting here we ensure
                        // the signal is only delivered when the daemon process itself dies.
                        // We use kill(pid, 0) to poll without reaping the child, so that
                        // handle_wait_principal can still reap it.
                        loop {
                            let ret = unsafe { libc::kill(child_pid, 0) };
                            if ret != 0 {
                                let errno = std::io::Error::last_os_error();
                                if errno.raw_os_error() == Some(libc::ESRCH) {
                                    break;
                                }
                                debug!("kill({}, 0) failed: {}", child_pid, errno);
                            }
                            std::thread::sleep(std::time::Duration::from_millis(100));
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        debug!("Admin handler error: {}", e);
                    }
                }
            })
            .map_err(|e| {
                self.worker_tracker.release();
                format!("failed to spawn admin worker: {}", e)
            })?;

        self.worker_tracker.push_handle(handle);
        Ok(())
    }

    fn accept_and_dispatch_principal(
        self: &Arc<Self>,
        profile_id: &ProfileId,
    ) -> Result<(), String> {
        let client_fd = match self.ipc_server.accept_principal_connection(profile_id) {
            Ok(Some(fd)) => fd,
            Ok(None) => return Ok(()),
            Err(e) => return Err(format!("principal accept failed: {}", e)),
        };

        if !self.worker_tracker.try_acquire() {
            debug!(
                "Worker limit reached, rejecting principal connection for {}",
                profile_id
            );
            drop(client_fd);
            return Ok(());
        }

        let ipc = Arc::clone(&self.ipc_server);
        let runtime = Arc::clone(self);
        let profile_id = profile_id.clone();

        let handle = std::thread::Builder::new()
            .name(format!("principal-worker-{}", profile_id))
            .spawn(move || {
                struct WorkerExitGuard(Arc<AgentRuntime>);
                impl Drop for WorkerExitGuard {
                    fn drop(&mut self) {
                        self.0.worker_tracker.release();
                    }
                }
                let _guard = WorkerExitGuard(runtime.clone());
                if let Err(e) = ipc.handle_one_principal(client_fd, &profile_id, &*runtime) {
                    debug!("Principal handler error for {}: {}", profile_id, e);
                }
            })
            .map_err(|e| {
                self.worker_tracker.release();
                format!("failed to spawn principal worker: {}", e)
            })?;

        self.worker_tracker.push_handle(handle);
        Ok(())
    }

    /// Credentials across the distinct backends the configured profiles use (a same-user profile
    /// shares the human backend, which is counted once).
    fn total_credential_count(&self) -> u32 {
        let mut seen: Vec<*const Mutex<Box<dyn CredentialStorage>>> = Vec::new();
        let mut total = 0usize;
        for profile in self.profiles.values() {
            let storage = &profile.backend.credential_storage;
            let ptr = Arc::as_ptr(storage);
            if seen.contains(&ptr) {
                continue;
            }
            seen.push(ptr);
            if let Ok(guard) = storage.lock() {
                total += guard.count_credentials();
            }
        }
        u32::try_from(total).unwrap_or(u32::MAX)
    }

    fn active_session_count(&self, profile_id: &ProfileId) -> usize {
        self.managed_sessions
            .get(profile_id)
            .and_then(|slot| slot.lock().ok().map(|sessions| sessions.len()))
            .unwrap_or(0)
    }

    fn cleanup_browser_for_session(
        &self,
        profile: &ProfileRuntime,
        session_id: &PrincipalSessionId,
    ) {
        let _lifecycle = profile.lifecycle_lock.lock().ok();

        let active = profile
            .active_browser
            .lock()
            .ok()
            .and_then(|mut active| active.remove(session_id));

        if profile.profile_config.browser_scope == BrowserScope::Profile {
            if active.is_none() {
                return;
            }
            let should_terminate = {
                let mut shared = profile.shared_browsers.lock().ok();
                if let Some(ref mut shared) = shared {
                    match detach_session_from_shared(shared, &profile.profile_id, session_id) {
                        SharedDetachOutcome::Terminate(lease_id) => Some(lease_id),
                        SharedDetachOutcome::Keep => None,
                    }
                } else {
                    None
                }
            };
            if let Some(lease_id) = should_terminate {
                self.revoke_sign_context_for_lease(&lease_id);
                let mut browser_mgr = self.browser_manager.lock().unwrap();
                let _ = browser_mgr.revoke(&lease_id);
                let _ = browser_mgr.terminate(&lease_id);
                let _ = browser_mgr.cleanup(&lease_id);
                browser_mgr.remove(&lease_id);
            }
            return;
        }

        if let Some(active) = active {
            self.revoke_sign_context_for_lease(&active.lease_id);
            let mut browser_mgr = self.browser_manager.lock().unwrap();
            let _ = browser_mgr.revoke(&active.lease_id);
            let _ = browser_mgr.terminate(&active.lease_id);
            let _ = browser_mgr.cleanup(&active.lease_id);
            browser_mgr.remove(&active.lease_id);
        }
    }

    fn cleanup_all_browsers_for_profile(&self, profile: &ProfileRuntime) {
        let mut leases: Vec<BrowserLeaseId> = profile
            .active_browser
            .lock()
            .map(|mut active| active.drain().map(|(_, lease)| lease.lease_id).collect())
            .unwrap_or_default();
        let shared_lease = {
            let mut shared = profile.shared_browsers.lock().ok();
            if let Some(ref mut shared) = shared {
                cleanup_all_shared_for_profile(shared, &profile.profile_id)
            } else {
                None
            }
        };
        if let Some(lease_id) = shared_lease {
            leases.push(lease_id);
        }
        if leases.is_empty() {
            return;
        }
        let mut seen = std::collections::HashSet::new();
        leases.retain(|id| seen.insert(id.clone()));
        let mut browser_mgr = self.browser_manager.lock().unwrap();
        for lease_id in leases {
            self.revoke_sign_context_for_lease(&lease_id);
            let _ = browser_mgr.revoke(&lease_id);
            let _ = browser_mgr.terminate(&lease_id);
            let _ = browser_mgr.cleanup(&lease_id);
            browser_mgr.remove(&lease_id);
        }
    }

    pub fn shutdown(&self) {
        if self
            .runtime_cleanup_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        info!("Agent runtime shutdown initiated");

        self.shutdown.store(true, Ordering::Release);

        self.sign_registry.revoke_all();
        self.sign_server_shutdown.store(true, Ordering::Release);
        if let Some(handle) = self.sign_server_handle.lock().unwrap().take() {
            let _ = handle.join();
        }

        self.ipc_server.cancel();

        if let Some(handle) = self.runtime_loop.lock().unwrap().take() {
            let _ = handle.join();
        }

        self.shutdown_all_sessions();

        {
            let mut browser_mgr = self.browser_manager.lock().unwrap();
            browser_mgr.terminate_all();
        }

        self.worker_tracker.join_all();

        let stop_event = DaemonStopBuilder::new(StopReason::GracefulShutdown, 0).build();
        let _ = self.audit_gate.record(stop_event);

        info!("Agent runtime shutdown complete");
    }

    fn revoke_sign_context_for_lease(&self, lease_id: &BrowserLeaseId) {
        self.sign_registry.revoke_by_lease(lease_id.as_str());
    }

    fn build_effective_authority(
        &self,
        profile_id: &ProfileId,
        profile: &ProfileRuntime,
        managed: &ManagedPrincipalSession,
    ) -> EffectiveAuthority {
        let acts_as_human = profile.mode == AgentMode::SameUser;
        let rules = &profile.profile_config.rules;
        let wildcard = rules.iter().any(|rule| rule.is_wildcard());
        let autonomous_authentication = rules
            .iter()
            .any(|rule| rule.authenticate == passless_core::agent::RuleAction::Allow);
        let human_backend_registration = acts_as_human
            && rules
                .iter()
                .any(|rule| rule.register != passless_core::agent::RuleAction::Deny);
        let direct_cdp = profile.profile_config.browser_cdp_expose == Some(CdpExposeMode::Port);
        let ambiguous_selection = matches!(
            profile.profile_config.credential_selection,
            passless_core::agent::config::CredentialSelection::FirstMatching
                | passless_core::agent::config::CredentialSelection::Newest
        );

        let mut risk_flags = Vec::new();
        if acts_as_human {
            risk_flags.push(AuthorityRisk::HumanIdentity);
        }
        if wildcard {
            risk_flags.push(AuthorityRisk::GlobalRpScope);
        }
        if autonomous_authentication {
            risk_flags.push(AuthorityRisk::AutonomousAuthentication);
        }
        if human_backend_registration {
            risk_flags.push(AuthorityRisk::HumanBackendRegistration);
        }
        if direct_cdp {
            risk_flags.push(AuthorityRisk::DirectCdpPort);
        }
        if ambiguous_selection {
            risk_flags.push(AuthorityRisk::AmbiguousCredentialSelection);
        }

        let active_lease = profile.active_browser.lock().ok().and_then(|active| {
            active
                .get(&managed.session_id)
                .map(|lease| lease.lease_id.clone())
        });
        let budget = active_lease.as_ref().and_then(|lease_id| {
            self.sign_registry
                .budget_snapshot_for_lease(lease_id.as_str())
        });
        let (operations_used, operations_remaining) = budget
            .map(|(used, max)| {
                (
                    Some(u16::try_from(used).unwrap_or(u16::MAX)),
                    Some(u16::try_from(max.saturating_sub(used)).unwrap_or(u16::MAX)),
                )
            })
            .unwrap_or((None, None));

        let selection = serde_json::to_value(&profile.profile_config.credential_selection)
            .ok()
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| "unknown".to_string());
        let generation = self.policy_runtime.current_generation();

        EffectiveAuthority {
            profile_id: profile_id.to_string(),
            mode: profile.mode.to_string(),
            identity: AuthorityIdentity {
                acts_as_human,
                credential_namespace: if acts_as_human { "human" } else { "isolated" }.into(),
                rp_identity: if acts_as_human { "human" } else { "agent" }.into(),
            },
            policy_generation: generation.generation.to_string(),
            rp_rules: rules
                .iter()
                .map(|rule| AuthorityRpRule {
                    wildcard: rule.is_wildcard(),
                    rp_id: rule.rp_id.clone(),
                    authenticate: authority_ceremony(rule.authenticate),
                    register: authority_ceremony(rule.register),
                })
                .collect(),
            credentials: AuthorityCredentialScope {
                dynamic_per_rp: profile.profile_config.credential_refs.is_none(),
                configured_reference_count: profile
                    .profile_config
                    .credential_refs
                    .as_ref()
                    .map_or(0, |refs| refs.len() as u32),
                selection,
            },
            session: AuthoritySession {
                max_session_ttl_secs: profile
                    .profile_config
                    .max_session_ttl
                    .map(|ttl| ttl.as_secs())
                    .unwrap_or(300),
                principal_remaining_ttl_secs: managed
                    .deadline
                    .saturating_duration_since(Instant::now())
                    .as_secs(),
                max_operations: profile.profile_config.max_operations,
                operations_used,
                operations_remaining,
            },
            browser: AuthorityBrowser {
                active: active_lease.is_some(),
                cdp_exposure: profile
                    .profile_config
                    .browser_cdp_expose
                    .unwrap_or(CdpExposeMode::Pipe)
                    .to_string(),
                direct_cdp,
                full_session_authority: active_lease.is_some(),
            },
            risk_flags,
        }
    }

    fn handle_launch_principal(
        &self,
        profile_id: &ProfileId,
        command: &[String],
        cred: &PeerCred,
        ctx: &super::ipc::AdminRequestContext,
    ) -> Result<AdminResponse, ProtocolError> {
        let profile = self.profiles.get(profile_id).ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::NotFound,
                format!("profile '{}' not found", profile_id),
                RecommendedAction::FixRequest,
            )
        })?;

        if !profile.enabled.load(Ordering::Acquire) {
            return Err(ProtocolError::new(
                ErrorCode::Forbidden,
                format!("profile '{}' is disabled", profile_id),
                RecommendedAction::FixRequest,
            ));
        }

        if command.is_empty() {
            return Err(ProtocolError::new(
                ErrorCode::BadRequest,
                "command must not be empty",
                RecommendedAction::FixRequest,
            ));
        }

        // Reap exited/expired principals before applying the configured live-session limit.
        self.reap_expired_sessions();

        let session_slot = self.managed_sessions.get(profile_id).ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::Internal,
                format!("no session collection for profile '{}'", profile_id),
                RecommendedAction::Abort,
            )
        })?;
        let mut sessions = session_slot.lock().map_err(|_| {
            ProtocolError::new(
                ErrorCode::Internal,
                "managed session lock poisoned",
                RecommendedAction::Abort,
            )
        })?;
        let limit = usize::from(profile.profile_config.max_concurrent_sessions);
        let unlimited = profile.profile_config.browser_scope == BrowserScope::Profile
            && profile.profile_config.max_concurrent_sessions == 0;
        if !unlimited && sessions.len() >= limit {
            return Err(ProtocolError::new(
                ErrorCode::Conflict,
                format!(
                    "profile '{}' reached max_concurrent_sessions ({})",
                    profile_id, limit
                ),
                RecommendedAction::RetryWithBackoff,
            ));
        }

        let program = validate_principal_executable(&command[0], self.daemon_uid)?;
        let args = if command.len() > 1 {
            command[1..].to_vec()
        } else {
            Vec::new()
        };

        let spawn_config = SpawnConfig {
            program,
            args,
            target_uid: profile.uid,
            target_gid: profile.gid,
            daemon_uid: self.daemon_uid,
            daemon_gid: self.daemon_gid,
            rlimit_nofile: super::launcher::DEFAULT_RLIMIT_NOFILE,
            rlimit_nproc: super::launcher::DEFAULT_RLIMIT_NPROC,
            rlimit_core: super::launcher::DEFAULT_RLIMIT_CORE,
            rlimit_as: super::launcher::DEFAULT_RLIMIT_AS,
            stdin_fd: ctx
                .stdio_fds
                .as_ref()
                .map(|fds| dup_fd_cloexec(fds.stdin.as_raw_fd()))
                .transpose()
                .map_err(|e| {
                    ProtocolError::new(
                        ErrorCode::Internal,
                        format!("failed to dup stdin fd: {}", e),
                        RecommendedAction::Retry,
                    )
                })?,
            stdout_fd: ctx
                .stdio_fds
                .as_ref()
                .map(|fds| dup_fd_cloexec(fds.stdout.as_raw_fd()))
                .transpose()
                .map_err(|e| {
                    ProtocolError::new(
                        ErrorCode::Internal,
                        format!("failed to dup stdout fd: {}", e),
                        RecommendedAction::Retry,
                    )
                })?,
            stderr_fd: ctx
                .stdio_fds
                .as_ref()
                .map(|fds| dup_fd_cloexec(fds.stderr.as_raw_fd()))
                .transpose()
                .map_err(|e| {
                    ProtocolError::new(
                        ErrorCode::Internal,
                        format!("failed to dup stderr fd: {}", e),
                        RecommendedAction::Retry,
                    )
                })?,
        };

        let session = spawn_principal(spawn_config).map_err(|e| {
            ProtocolError::new(
                ErrorCode::Internal,
                format!("failed to spawn principal: {}", e),
                RecommendedAction::Retry,
            )
        })?;

        let pid = session.child.id();
        let session_id = PrincipalSessionId::new();
        let now = Instant::now();
        let ttl_secs = profile
            .profile_config
            .max_session_ttl
            .map(|ttl| ttl.as_secs())
            .unwrap_or(3600);
        let deadline = now + Duration::from_secs(ttl_secs);

        let process_digest = super::intent::ProcessIdentityDigest::compute_from_session_identity(
            &super::intent::SessionIdentityParams {
                uid: session.identity.uid,
                gid: session.identity.gid,
                pid: session.identity.pid,
                start_time: session.identity.start_time,
                cgroup_path: session.identity.cgroup_path.clone(),
                ns_user: session.identity.ns_inodes.user,
                ns_pid: session.identity.ns_inodes.pid,
                ns_mnt: session.identity.ns_inodes.mnt,
            },
        );

        sessions.push(ManagedPrincipalSession {
            session_id: session_id.clone(),
            profile_id: profile_id.clone(),
            session,
            process_digest,
            created_at: now,
            deadline,
            client_pid: cred.pid,
        });

        info!(
            "Launched principal session {} for profile {} (pid {})",
            session_id, profile_id, pid
        );

        Ok(AdminResponse::PrincipalLaunched(
            PrincipalLaunchedResponse {
                session_id,
                pid,
                profile_id: profile_id.to_string(),
            },
        ))
    }

    fn handle_terminate_principal(
        &self,
        profile_id: &ProfileId,
    ) -> Result<AdminResponse, ProtocolError> {
        let session_slot = self.managed_sessions.get(profile_id).ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::NotFound,
                format!("no session collection for profile '{}'", profile_id),
                RecommendedAction::FixRequest,
            )
        })?;
        let mut sessions = session_slot.lock().map_err(|_| {
            ProtocolError::new(
                ErrorCode::Internal,
                "managed session lock poisoned",
                RecommendedAction::Abort,
            )
        })?;
        if sessions.is_empty() {
            return Err(ProtocolError::new(
                ErrorCode::NotFound,
                format!("no active session for profile '{}'", profile_id),
                RecommendedAction::FixRequest,
            ));
        }
        let terminating = std::mem::take(&mut *sessions);
        drop(sessions);

        for mut managed in terminating {
            info!(
                "Terminating principal session {} for profile {} (pid {})",
                managed.session_id,
                profile_id,
                managed.session.child.id()
            );
            if let Some(profile) = self.profiles.get(profile_id) {
                self.cleanup_browser_for_session(profile, &managed.session_id);
            }
            let exit_status = managed.session.terminate(TERMINATE_TIMEOUT);
            let (exit_code, signal) = match exit_status {
                Some(status) => {
                    if let Some(code) = status.code() {
                        (Some(code), None)
                    } else {
                        (None, status.signal())
                    }
                }
                None => (None, None),
            };
            let mut completed_map = self.completed_sessions.lock().unwrap();
            Self::prune_completed_before_insert(&mut completed_map);
            completed_map.insert(
                managed.session_id.to_string(),
                CompletedSession {
                    exit_code,
                    signal,
                    completed_at: Instant::now(),
                },
            );
        }

        Ok(AdminResponse::PrincipalTerminated)
    }

    fn handle_wait_principal(
        &self,
        session_id: &PrincipalSessionId,
        timeout_ms: u32,
    ) -> Result<AdminResponse, ProtocolError> {
        let timeout = Duration::from_millis(timeout_ms as u64).min(Duration::from_secs(30));
        let deadline = Instant::now() + timeout;

        loop {
            let mut found = false;
            for (profile_id, session_slot) in &self.managed_sessions {
                let mut sessions = session_slot.lock().unwrap();
                if let Some(pos) = sessions
                    .iter()
                    .position(|managed| managed.session_id == *session_id)
                {
                    found = true;
                    match sessions[pos].session.child.try_wait() {
                        Ok(Some(status)) => {
                            let managed = sessions.remove(pos);
                            drop(sessions);
                            let (exit_code, signal) = if let Some(code) = status.code() {
                                (Some(code), None)
                            } else {
                                (None, status.signal())
                            };
                            if let Some(profile) = self.profiles.get(profile_id) {
                                self.cleanup_browser_for_session(profile, session_id);
                            }
                            let mut completed_map = self.completed_sessions.lock().unwrap();
                            Self::prune_completed_before_insert(&mut completed_map);
                            completed_map.insert(
                                managed.session_id.to_string(),
                                CompletedSession {
                                    exit_code,
                                    signal,
                                    completed_at: Instant::now(),
                                },
                            );
                            return Ok(AdminResponse::PrincipalWait(PrincipalWaitResponse {
                                running: false,
                                exit_code,
                                signal,
                            }));
                        }
                        Ok(None) => {}
                        Err(e) => {
                            return Err(ProtocolError::new(
                                ErrorCode::Internal,
                                format!("try_wait failed: {}", e),
                                RecommendedAction::Retry,
                            ));
                        }
                    }
                    break;
                }
            }

            if !found {
                let mut completed_map = self.completed_sessions.lock().unwrap();
                if let Some(completed) = completed_map.remove(&session_id.to_string()) {
                    return Ok(AdminResponse::PrincipalWait(PrincipalWaitResponse {
                        running: false,
                        exit_code: completed.exit_code,
                        signal: completed.signal,
                    }));
                }
                return Err(ProtocolError::new(
                    ErrorCode::NotFound,
                    format!("session '{}' not found", session_id),
                    RecommendedAction::FixRequest,
                ));
            }

            if Instant::now() >= deadline {
                return Ok(AdminResponse::PrincipalWait(PrincipalWaitResponse {
                    running: true,
                    exit_code: None,
                    signal: None,
                }));
            }

            let remaining = deadline - Instant::now();
            std::thread::sleep(WAIT_PRINCIPAL_POLL_INTERVAL.min(remaining));
        }
    }

    fn is_pid_alive(pid: i32) -> bool {
        let stat_path = format!("/proc/{}/stat", pid);
        std::fs::metadata(&stat_path).is_ok()
    }

    fn prune_completed_before_insert(
        map: &mut std::collections::BTreeMap<String, CompletedSession>,
    ) {
        let now = Instant::now();
        let expired_keys: Vec<String> = map
            .iter()
            .filter(|(_, v)| now.duration_since(v.completed_at) >= COMPLETED_SESSION_TTL)
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired_keys {
            map.remove(&key);
        }
        while map.len() >= MAX_COMPLETED_SESSIONS {
            let oldest_key = map
                .iter()
                .min_by_key(|(_, v)| v.completed_at)
                .map(|(k, _)| k.clone());
            if let Some(key) = oldest_key {
                map.remove(&key);
            } else {
                break;
            }
        }
    }

    fn reap_expired_sessions(&self) {
        let now = Instant::now();
        let mut to_reap: Vec<(
            ProfileId,
            PrincipalSessionId,
            Option<std::process::ExitStatus>,
        )> = Vec::new();

        for (profile_id, session_slot) in &self.managed_sessions {
            let mut sessions = session_slot.lock().unwrap();
            let mut index = 0;
            while index < sessions.len() {
                let should_reap = if now >= sessions[index].deadline {
                    debug!(
                        "Session {} for profile {} expired, reaping",
                        sessions[index].session_id, profile_id
                    );
                    true
                } else if !Self::is_pid_alive(sessions[index].client_pid) {
                    debug!(
                        "Session {} for profile {} orphaned (client pid {} dead), reaping",
                        sessions[index].session_id, profile_id, sessions[index].client_pid
                    );
                    true
                } else {
                    match sessions[index].session.child.try_wait() {
                        Ok(Some(_)) => {
                            debug!(
                                "Session {} for profile {} exited, reaping",
                                sessions[index].session_id, profile_id
                            );
                            true
                        }
                        Ok(None) => false,
                        Err(_) => true,
                    }
                };

                if should_reap {
                    let mut taken = sessions.remove(index);
                    let exit_status = taken.session.child.try_wait().ok().flatten();
                    to_reap.push((profile_id.clone(), taken.session_id.clone(), exit_status));
                } else {
                    index += 1;
                }
            }
        }

        for (profile_id, session_id, exit_status) in to_reap {
            let (exit_code, signal) = match exit_status {
                Some(status) => {
                    if let Some(code) = status.code() {
                        (Some(code), None)
                    } else {
                        (None, status.signal())
                    }
                }
                None => (None, None),
            };
            {
                let mut completed_map = self.completed_sessions.lock().unwrap();
                Self::prune_completed_before_insert(&mut completed_map);
                completed_map.insert(
                    session_id.to_string(),
                    CompletedSession {
                        exit_code,
                        signal,
                        completed_at: Instant::now(),
                    },
                );
            }

            if let Some(profile) = self.profiles.get(&profile_id) {
                self.cleanup_browser_for_session(profile, &session_id);
            }
        }
    }

    fn cleanup_expired_pending(&self) {
        let _ = self.policy_runtime.cleanup_expired_pending();
    }

    fn prune_completed_sessions(&self) {
        let mut completed_map = self.completed_sessions.lock().unwrap();
        Self::prune_completed_before_insert(&mut completed_map);
    }

    fn shutdown_all_sessions(&self) {
        for (profile_id, session_slot) in &self.managed_sessions {
            let mut sessions = session_slot.lock().unwrap();
            for managed in sessions.drain(..) {
                info!(
                    "Shutting down principal session {} for profile {}",
                    managed.session_id, profile_id
                );
                if let Some(profile) = self.profiles.get(profile_id) {
                    self.cleanup_browser_for_session(profile, &managed.session_id);
                }
                drop(managed.session);
            }
        }
    }

    fn handle_show_intent(
        &self,
        _profile_id: &ProfileId,
        session_id: &PrincipalSessionId,
        request_id: &PendingRequestId,
        _profile: &ProfileRuntime,
    ) -> Result<PrincipalResponse, ProtocolError> {
        let status = self
            .policy_runtime
            .principal_pending_status(request_id, session_id)
            .map_err(|e| match e {
                super::policy_engine::PendingStatusError::NotFound => ProtocolError::new(
                    ErrorCode::NotFound,
                    "pending request not found",
                    RecommendedAction::FixRequest,
                ),
                super::policy_engine::PendingStatusError::SessionMismatch => ProtocolError::new(
                    ErrorCode::Unauthorized,
                    "session mismatch for pending request",
                    RecommendedAction::Abort,
                ),
            })?;

        if status.kind != super::policy_engine::PendingRequestKind::IsolatedIntent {
            return Err(ProtocolError::new(
                ErrorCode::BadRequest,
                "request is not an intent",
                RecommendedAction::FixRequest,
            ));
        }

        Ok(PrincipalResponse::IntentStatus {
            request_id: request_id.clone(),
            state: status.to_intent_state(),
        })
    }

    fn handle_cancel_intent(
        &self,
        _profile_id: &ProfileId,
        session_id: &PrincipalSessionId,
        request_id: &PendingRequestId,
        profile: &ProfileRuntime,
    ) -> Result<PrincipalResponse, ProtocolError> {
        let _lifecycle = profile.lifecycle_lock.lock().unwrap();
        let status = self
            .policy_runtime
            .principal_pending_status(request_id, session_id)
            .map_err(|e| match e {
                super::policy_engine::PendingStatusError::NotFound => ProtocolError::new(
                    ErrorCode::NotFound,
                    "pending request not found",
                    RecommendedAction::FixRequest,
                ),
                super::policy_engine::PendingStatusError::SessionMismatch => ProtocolError::new(
                    ErrorCode::Unauthorized,
                    "session mismatch for pending request",
                    RecommendedAction::Abort,
                ),
            })?;

        if status.kind != super::policy_engine::PendingRequestKind::IsolatedIntent {
            return Err(ProtocolError::new(
                ErrorCode::BadRequest,
                "request is not an intent",
                RecommendedAction::FixRequest,
            ));
        }

        let _ = self
            .policy_runtime
            .principal_cancel_pending(request_id, session_id);

        let cancel_event =
            super::audit_events::IntentCancelBuilder::new(status.intent_id.clone()).build();
        let _ = self.audit_gate.record(cancel_event);

        Ok(PrincipalResponse::IntentCancelled)
    }

    fn handle_request_delegation(
        &self,
        _params: RequestDelegationParams<'_>,
    ) -> Result<PrincipalResponse, ProtocolError> {
        Err(ProtocolError::new(
            ErrorCode::Forbidden,
            "request delegation is not supported; delegated mode has been removed",
            RecommendedAction::FixRequest,
        ))
    }

    fn handle_show_delegation(
        &self,
        _profile_id: &ProfileId,
        session_id: &PrincipalSessionId,
        request_id: &PendingRequestId,
        _profile: &ProfileRuntime,
    ) -> Result<PrincipalResponse, ProtocolError> {
        let status = self
            .policy_runtime
            .principal_pending_status(request_id, session_id)
            .map_err(|e| match e {
                super::policy_engine::PendingStatusError::NotFound => ProtocolError::new(
                    ErrorCode::NotFound,
                    "pending request not found",
                    RecommendedAction::FixRequest,
                ),
                super::policy_engine::PendingStatusError::SessionMismatch => ProtocolError::new(
                    ErrorCode::Unauthorized,
                    "session mismatch for pending request",
                    RecommendedAction::Abort,
                ),
            })?;

        if status.kind != super::policy_engine::PendingRequestKind::DelegatedAuth {
            return Err(ProtocolError::new(
                ErrorCode::BadRequest,
                "request is not a delegation",
                RecommendedAction::FixRequest,
            ));
        }

        Ok(PrincipalResponse::DelegationStatus {
            request_id: request_id.clone(),
            state: status.to_delegation_state(),
        })
    }

    fn handle_cancel_delegation(
        &self,
        _profile_id: &ProfileId,
        session_id: &PrincipalSessionId,
        request_id: &PendingRequestId,
        profile: &ProfileRuntime,
    ) -> Result<PrincipalResponse, ProtocolError> {
        let _lifecycle = profile.lifecycle_lock.lock().unwrap();
        let status = self
            .policy_runtime
            .principal_pending_status(request_id, session_id)
            .map_err(|e| match e {
                super::policy_engine::PendingStatusError::NotFound => ProtocolError::new(
                    ErrorCode::NotFound,
                    "pending request not found",
                    RecommendedAction::FixRequest,
                ),
                super::policy_engine::PendingStatusError::SessionMismatch => ProtocolError::new(
                    ErrorCode::Unauthorized,
                    "session mismatch for pending request",
                    RecommendedAction::Abort,
                ),
            })?;

        if status.kind != super::policy_engine::PendingRequestKind::DelegatedAuth {
            return Err(ProtocolError::new(
                ErrorCode::BadRequest,
                "request is not a delegation",
                RecommendedAction::FixRequest,
            ));
        }

        let grant_request_id = status.grant_request_id;

        if let Some(ref grant_req_id) = grant_request_id
            && let Some(grant_id) = self
                .policy_runtime
                .resolved_grant_id_for_request(&status.profile_id, grant_req_id)
        {
            let _ = self.policy_runtime.revoke_grant_by_id(&grant_id);
        }

        let _ = self
            .policy_runtime
            .principal_cancel_pending(request_id, session_id);

        let cancel_event =
            super::audit_events::IntentCancelBuilder::new(status.intent_id.clone()).build();
        let _ = self.audit_gate.record(cancel_event);

        Ok(PrincipalResponse::DelegationCancelled)
    }

    fn handle_list_credentials(
        &self,
        _profile_id: &ProfileId,
        profile: &ProfileRuntime,
    ) -> Result<PrincipalResponse, ProtocolError> {
        let config = &profile.profile_config;
        let allowed_refs = config.credential_refs.as_ref().cloned().unwrap_or_default();

        let credentials: Vec<passless_core::agent::PrincipalCredentialSummary> = allowed_refs
            .iter()
            .map(
                |cred_ref| passless_core::agent::PrincipalCredentialSummary {
                    credential_ref: cred_ref.clone(),
                    rp_id: config.allowed_rp_ids().first().cloned().unwrap_or_default(),
                    user_name: String::new(),
                    display_name: String::new(),
                },
            )
            .collect();

        let total = credentials.len() as u32;
        Ok(PrincipalResponse::CredentialList(
            passless_core::agent::PrincipalCredentialList { credentials, total },
        ))
    }

    fn handle_browser_status(
        &self,
        _profile_id: &ProfileId,
        session_id: &PrincipalSessionId,
        profile: &ProfileRuntime,
    ) -> Result<PrincipalResponse, ProtocolError> {
        let lease_id = profile
            .active_browser
            .lock()
            .unwrap()
            .get(session_id)
            .map(|lease| lease.lease_id.clone());

        if let Some(lease_id) = lease_id {
            let browser_mgr = self.browser_manager.lock().unwrap();
            if let Some(snapshot) = browser_mgr.snapshot(&lease_id) {
                let cdp_endpoint = browser_mgr.lease_cdp_endpoint(&lease_id).flatten();
                let shared_browser_context =
                    if profile.profile_config.browser_scope == BrowserScope::Profile {
                        let shared = profile.shared_browsers.lock().ok();
                        let is_shared = shared
                            .as_ref()
                            .is_some_and(|s| s.contains_key(&profile.profile_id));
                        if is_shared { Some(true) } else { None }
                    } else {
                        None
                    };
                return Ok(PrincipalResponse::BrowserStatus(
                    passless_core::agent::BrowserStatusResponse {
                        running: !snapshot.state.is_terminal(),
                        status: format!("{}", snapshot.state),
                        cdp_endpoint,
                        shared_browser_context,
                    },
                ));
            }
        }

        Ok(PrincipalResponse::BrowserStatus(
            passless_core::agent::BrowserStatusResponse {
                running: false,
                status: "no_browser".into(),
                cdp_endpoint: None,
                shared_browser_context: None,
            },
        ))
    }

    fn handle_browser_control(
        &self,
        profile_id: &ProfileId,
        session_id: &PrincipalSessionId,
        request_json: &str,
        timeout_ms: u32,
        profile: &ProfileRuntime,
    ) -> Result<PrincipalResponse, ProtocolError> {
        let lease_id = profile
            .active_browser
            .lock()
            .unwrap()
            .get(session_id)
            .map(|lease| lease.lease_id.clone())
            .ok_or_else(|| {
                ProtocolError::new(
                    ErrorCode::Forbidden,
                    "no browser lease associated with this principal session",
                    RecommendedAction::FixRequest,
                )
            })?;

        let cdp_method = extract_cdp_method_for_audit(request_json);

        {
            let browser_mgr = self.browser_manager.lock().unwrap();
            if let Some(false) = browser_mgr.lease_has_cdp_pipes(&lease_id) {
                let endpoint_msg = browser_mgr
                    .lease_cdp_endpoint(&lease_id)
                    .flatten()
                    .unwrap_or_else(|| "<endpoint not yet discovered>".to_string());
                return Err(ProtocolError::new(
                    ErrorCode::Forbidden,
                    format!(
                        "browser-control is unavailable in port mode; connect directly via CDP: {}",
                        endpoint_msg
                    ),
                    RecommendedAction::FixRequest,
                ));
            }
        }

        let pre_audit = self.audit_gate.record(
            super::audit_events::BrowserControlRequestBuilder::new(
                profile_id.clone(),
                lease_id.clone(),
                &cdp_method,
                super::audit_events::BrowserControlOutcome::Requested,
            )
            .build(),
        );

        if pre_audit.is_err() {
            return Err(ProtocolError::new(
                ErrorCode::Internal,
                "audit pre-write failed; refusing to send CDP command",
                RecommendedAction::Abort,
            ));
        }

        let timeout = Duration::from_millis(timeout_ms as u64);

        let result = {
            let mut browser_mgr = self.browser_manager.lock().unwrap();
            let snapshot = browser_mgr.snapshot(&lease_id);
            let state = snapshot
                .as_ref()
                .map(|s| s.state)
                .unwrap_or(super::browser::LeaseState::BrowserExit);

            if state.is_terminal() {
                let outcome = super::audit_events::BrowserControlOutcome::BrowserExit;
                let _ = self.audit_gate.record(
                    super::audit_events::BrowserControlRequestBuilder::new(
                        profile_id.clone(),
                        lease_id.clone(),
                        &cdp_method,
                        outcome,
                    )
                    .build(),
                );
                return Err(ProtocolError::new(
                    ErrorCode::Forbidden,
                    format!("browser lease is in terminal state: {}", state),
                    RecommendedAction::FixRequest,
                ));
            }

            if snapshot.as_ref().map(|s| s.profile_id.clone()) != Some(profile_id.clone()) {
                let outcome = super::audit_events::BrowserControlOutcome::Denied;
                let _ = self.audit_gate.record(
                    super::audit_events::BrowserControlRequestBuilder::new(
                        profile_id.clone(),
                        lease_id.clone(),
                        &cdp_method,
                        outcome,
                    )
                    .build(),
                );
                return Err(ProtocolError::new(
                    ErrorCode::Unauthorized,
                    "lease does not belong to this profile",
                    RecommendedAction::Abort,
                ));
            }

            browser_mgr.cdp_round_trip(&lease_id, request_json, timeout)
        };

        match result {
            Ok(cdp_result) => {
                let outcome = super::audit_events::BrowserControlOutcome::Success;
                let _ = self.audit_gate.record(
                    super::audit_events::BrowserControlRequestBuilder::new(
                        profile_id.clone(),
                        lease_id,
                        &cdp_method,
                        outcome,
                    )
                    .build(),
                );
                Ok(PrincipalResponse::BrowserControl {
                    messages: cdp_result.messages,
                })
            }
            Err(super::browser::CdpError::Timeout) => {
                let outcome = super::audit_events::BrowserControlOutcome::Timeout;
                let _ = self.audit_gate.record(
                    super::audit_events::BrowserControlRequestBuilder::new(
                        profile_id.clone(),
                        lease_id,
                        &cdp_method,
                        outcome,
                    )
                    .build(),
                );
                Err(ProtocolError::new(
                    ErrorCode::Internal,
                    "CDP round-trip timed out",
                    RecommendedAction::RetryWithBackoff,
                ))
            }
            Err(super::browser::CdpError::BrowserExited) => {
                let outcome = super::audit_events::BrowserControlOutcome::BrowserExit;
                let _ = self.audit_gate.record(
                    super::audit_events::BrowserControlRequestBuilder::new(
                        profile_id.clone(),
                        lease_id,
                        &cdp_method,
                        outcome,
                    )
                    .build(),
                );
                Err(ProtocolError::new(
                    ErrorCode::Forbidden,
                    "browser process has exited",
                    RecommendedAction::FixRequest,
                ))
            }
            Err(e) => {
                let outcome = super::audit_events::BrowserControlOutcome::Error;
                let _ = self.audit_gate.record(
                    super::audit_events::BrowserControlRequestBuilder::new(
                        profile_id.clone(),
                        lease_id,
                        &cdp_method,
                        outcome,
                    )
                    .build(),
                );
                Err(ProtocolError::new(
                    ErrorCode::Internal,
                    format!("CDP error: {}", e),
                    RecommendedAction::Retry,
                ))
            }
        }
    }

    fn handle_listprofiles(&self) -> Result<AdminResponse, ProtocolError> {
        let generation = self.policy_runtime.current_generation();
        let profiles: Vec<passless_core::agent::ProfileSummary> = self
            .profiles
            .values()
            .map(|p| {
                let mode_str = format!("{:?}", p.mode);
                passless_core::agent::ProfileSummary {
                    profile_id: p.profile_id.to_string(),
                    enabled: p.enabled.load(Ordering::Acquire),
                    mode: mode_str,
                }
            })
            .collect();
        let total = profiles.len() as u32;
        let _ = generation;
        Ok(AdminResponse::ProfileList(
            passless_core::agent::ProfileList { profiles, total },
        ))
    }

    fn handle_showprofile(&self, profile_id: &ProfileId) -> Result<AdminResponse, ProtocolError> {
        let profile = self.profiles.get(profile_id).ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::NotFound,
                format!("profile '{}' not found", profile_id),
                RecommendedAction::FixRequest,
            )
        })?;

        let generation = self.policy_runtime.current_generation();
        let policy_gen = generation
            .find_snapshot(profile_id)
            .map(|_| generation.generation)
            .unwrap_or(0);
        let active_grants = self
            .policy_runtime
            .active_grant_count_for_profile(profile_id);
        let pending_intents = self
            .policy_runtime
            .pending_intent_count_for_profile(profile_id);
        let active_sessions =
            u32::try_from(self.active_session_count(profile_id)).unwrap_or(u32::MAX);

        let mode_str = format!("{:?}", profile.mode);
        Ok(AdminResponse::ProfileInfo(
            passless_core::agent::ProfileInfo {
                profile_id: profile_id.to_string(),
                enabled: profile.enabled.load(Ordering::Acquire),
                mode: mode_str,
                policy_generation: policy_gen,
                active_grants,
                active_sessions,
                pending_intents,
            },
        ))
    }

    fn handle_profile_check(&self, profile_id: &ProfileId) -> Result<AdminResponse, ProtocolError> {
        let profile = self.profiles.get(profile_id).ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::NotFound,
                format!("profile '{}' not found", profile_id),
                RecommendedAction::FixRequest,
            )
        })?;

        let report = self.build_profile_report(profile_id, profile);
        Ok(AdminResponse::ProfileCheck(report))
    }

    fn build_profile_report(
        &self,
        profile_id: &ProfileId,
        profile: &ProfileRuntime,
    ) -> passless_core::agent::ProfileDiagnosticReport {
        let enabled = profile.enabled.load(Ordering::Acquire);
        let endpoint_has_id = profile.endpoint_id.lock().unwrap().is_some();

        let browser_lease_state = {
            let active = profile.active_browser.lock().unwrap();
            (!active.is_empty()).then(|| "active".to_string())
        };

        let generation = self.policy_runtime.current_generation();
        let policy_gen = generation
            .find_snapshot(profile_id)
            .map(|_| generation.generation)
            .unwrap_or(0);

        let (pin_storage_available, pin_set) = {
            let pin_storage =
                (profile.mode == AgentMode::Isolated).then(|| profile.backend.pin_storage.clone());

            match pin_storage {
                Some(ps) => {
                    let storage = ps.lock();
                    match storage {
                        Ok(s) => match s.load_pin_state() {
                            Ok(state) => (true, state.is_pin_set()),
                            Err(_) => (true, false),
                        },
                        Err(_) => (false, false),
                    }
                }
                None => (false, false),
            }
        };

        // Agent ceremonies carry no human UV evidence (ADR 0014 section 7), so no PIN is required.
        let require_uv = false;

        let mut report = super::doctor::build_profile_diagnostic_report(
            super::doctor::ProfileDiagnosticParams {
                profile_id,
                enabled,
                mode: profile.mode,
                endpoint_has_id,
                browser_lease_state: browser_lease_state.as_deref(),
                policy_generation: policy_gen,
                audit_gate: &self.audit_gate,
                pin_storage_available,
                pin_set,
                require_uv,
            },
        );
        // Deprecated config vocabulary is accepted with a warning for one minor release (plan R8):
        // a warning never makes the profile unhealthy, so the check passes and carries the text.
        for warning in profile.profile_config.deprecation_warnings(profile_id) {
            report.checks.push(passless_core::agent::DoctorCheck {
                name: "config_deprecation".into(),
                passed: true,
                message: format!("warning: {warning}"),
            });
        }
        report
    }

    fn handle_enableprofile(&self, profile_id: &ProfileId) -> Result<AdminResponse, ProtocolError> {
        let profile = self.profiles.get(profile_id).ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::NotFound,
                format!("profile '{}' not found", profile_id),
                RecommendedAction::FixRequest,
            )
        })?;

        {
            // The endpoint id is a logical handle for grants and intents; no device backs it.
            let mut eid_guard = profile.endpoint_id.lock().unwrap();
            if eid_guard.is_none() {
                *eid_guard = Some(EndpointId::new());
            }
        }

        profile.enabled.store(true, Ordering::Release);

        let enable_event =
            super::audit_events::AdminProfileEnableBuilder::new(profile_id.clone()).build();
        let _ = self.audit_gate.record(enable_event);

        Ok(AdminResponse::ProfileEnabled)
    }

    fn handle_disableprofile(
        &self,
        profile_id: &ProfileId,
    ) -> Result<AdminResponse, ProtocolError> {
        use super::audit_events::DisableRequestReason;

        let profile = self.profiles.get(profile_id).ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::NotFound,
                format!("profile '{}' not found", profile_id),
                RecommendedAction::FixRequest,
            )
        })?;

        let disable_request_event = super::audit_events::AdminProfileDisableRequestBuilder::new(
            profile_id.clone(),
            DisableRequestReason::AdminRequested,
        )
        .build();
        if let Err(e) = self.audit_gate.record(disable_request_event) {
            return Err(ProtocolError::new(
                ErrorCode::Internal,
                format!("audit record for disable request failed: {}", e),
                RecommendedAction::Abort,
            ));
        }

        profile.enabled.store(false, Ordering::Release);

        self.cleanup_all_browsers_for_profile(profile);

        if let Some(session_slot) = self.managed_sessions.get(profile_id) {
            let mut sessions = session_slot.lock().unwrap();
            for managed in sessions.drain(..) {
                info!(
                    "Disabling profile '{}' terminates session {} (pid {})",
                    profile_id,
                    managed.session_id,
                    managed.session.child.id()
                );
                drop(managed.session);
            }
        }

        let disable_event =
            super::audit_events::AdminProfileDisableBuilder::new(profile_id.clone()).build();
        let _ = self.audit_gate.record(disable_event);

        Ok(AdminResponse::ProfileDisabled)
    }

    fn handle_show_policy(&self, profile_id: &ProfileId) -> Result<AdminResponse, ProtocolError> {
        let profile = self.profiles.get(profile_id).ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::NotFound,
                format!("profile '{}' not found", profile_id),
                RecommendedAction::FixRequest,
            )
        })?;

        if !profile.enabled.load(Ordering::Acquire) {
            return Err(ProtocolError::new(
                ErrorCode::Forbidden,
                format!("profile '{}' is disabled", profile_id),
                RecommendedAction::FixRequest,
            ));
        }

        let generation = self.policy_runtime.current_generation();
        let snapshot = generation.find_snapshot(profile_id).ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::NotFound,
                format!(
                    "policy snapshot for profile '{}' not found in current generation",
                    profile_id
                ),
                RecommendedAction::FixRequest,
            )
        })?;

        let digest_hex = hex::encode(generation.digest.as_bytes());
        let gen_num = generation.generation;
        let _ = snapshot;

        Ok(AdminResponse::PolicyInfo(
            passless_core::agent::PolicyInfo {
                profile_id: profile_id.to_string(),
                policy_generation: gen_num,
                digest: digest_hex,
            },
        ))
    }

    fn handle_reload_policy(&self, profile_id: &ProfileId) -> Result<AdminResponse, ProtocolError> {
        let _profile = self.profiles.get(profile_id).ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::NotFound,
                format!("profile '{}' not found", profile_id),
                RecommendedAction::FixRequest,
            )
        })?;

        let config = self.agent_config.read().unwrap().clone();
        self.policy_runtime.reload(&config).map_err(|e| {
            ProtocolError::new(
                ErrorCode::Internal,
                format!("policy recompile failed: {}", e),
                RecommendedAction::Abort,
            )
        })?;

        let generation = self.policy_runtime.current_generation();
        let gen_event = super::audit_events::AdminPolicyRecompileBuilder::new(
            profile_id.clone(),
            generation.generation,
        )
        .build();
        let _ = self.audit_gate.record(gen_event);

        for profile in self.profiles.values() {
            self.cleanup_all_browsers_for_profile(profile);
        }

        Ok(AdminResponse::PolicyRecompiled)
    }

    fn handle_admin_list_credentials(
        &self,
        rp_id: &Option<String>,
    ) -> Result<AdminResponse, ProtocolError> {
        let mut all_credentials = Vec::new();

        for profile in self.profiles.values() {
            let _op = profile.operation_lock.lock().map_err(|e| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    format!("failed to acquire operation lock: {}", e),
                    RecommendedAction::Retry,
                )
            })?;

            let mut storage = profile.credential_storage.lock().map_err(|e| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    format!("failed to acquire storage lock: {}", e),
                    RecommendedAction::Retry,
                )
            })?;

            let filter = if let Some(rp) = rp_id {
                // Only RPs the profile has a rule for (exact, or through the wildcard).
                if self
                    .policy_runtime
                    .resolve(
                        &profile.profile_id,
                        &passless_core::agent::protocol::IntentAction::Authenticate,
                        rp,
                    )
                    .rule
                    == passless_core::agent::RuleIdentity::None
                {
                    continue;
                }
                crate::storage::CredentialFilter::ByRp(rp.trim().to_ascii_lowercase())
            } else {
                crate::storage::CredentialFilter::None
            };

            let mut has_more = true;
            let first_result = storage.read_first(filter);
            let mut cred = match first_result {
                Ok(c) => c,
                Err(_) => {
                    break;
                }
            };

            while has_more {
                let rp_match = if let Some(rp) = rp_id {
                    cred.rp.id.trim().eq_ignore_ascii_case(rp.trim())
                } else {
                    profile
                        .profile_config
                        .allowed_rp_ids()
                        .iter()
                        .any(|configured_rp| {
                            configured_rp.trim().eq_ignore_ascii_case(cred.rp.id.trim())
                        })
                };

                if rp_match {
                    let cred_ref =
                        passless_core::agent::CredentialRef::with_default_domain(&cred.id);
                    all_credentials.push(passless_core::agent::CredentialSummary {
                        credential_ref: cred_ref,
                        rp_id: cred.rp.id.clone(),
                        user_name: cred.user.name.clone().unwrap_or_default(),
                        display_name: cred.user.display_name.clone().unwrap_or_default(),
                        created_at: None,
                    });
                }

                match storage.read_next() {
                    Ok(next) => cred = next,
                    Err(_) => has_more = false,
                }
            }
        }

        let total = all_credentials.len() as u32;
        Ok(AdminResponse::CredentialList(
            passless_core::agent::CredentialList {
                credentials: all_credentials,
                total,
            },
        ))
    }

    fn handle_admin_show_credential(
        &self,
        credential_ref: &passless_core::agent::CredentialRef,
    ) -> Result<AdminResponse, ProtocolError> {
        for profile in self.profiles.values() {
            let is_in_profile = profile
                .profile_config
                .credential_refs
                .as_ref()
                .is_some_and(|refs| refs.iter().any(|r| r == credential_ref));

            if !is_in_profile {
                continue;
            }

            let _op = profile.operation_lock.lock().map_err(|e| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    format!("failed to acquire operation lock: {}", e),
                    RecommendedAction::Retry,
                )
            })?;

            let mut storage = profile.credential_storage.lock().map_err(|e| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    format!("failed to acquire storage lock: {}", e),
                    RecommendedAction::Retry,
                )
            })?;

            let mut has_more = true;
            let first_result = storage.read_first(crate::storage::CredentialFilter::None);
            let mut cred = match first_result {
                Ok(c) => c,
                Err(e) => {
                    return Err(ProtocolError::new(
                        ErrorCode::Internal,
                        format!("storage enumeration failed: {}", e),
                        RecommendedAction::Retry,
                    ));
                }
            };

            while has_more {
                let actual_ref = passless_core::agent::CredentialRef::with_default_domain(&cred.id);
                if actual_ref == *credential_ref {
                    return Ok(AdminResponse::CredentialInfo(
                        passless_core::agent::CredentialInfo {
                            credential_ref: credential_ref.clone(),
                            rp_id: cred.rp.id,
                            user_name: cred.user.name.unwrap_or_default(),
                            display_name: cred.user.display_name.unwrap_or_default(),
                        },
                    ));
                }

                match storage.read_next() {
                    Ok(next) => cred = next,
                    Err(_) => has_more = false,
                }
            }
        }

        Err(ProtocolError::new(
            ErrorCode::NotFound,
            "credential not found",
            RecommendedAction::FixRequest,
        ))
    }

    fn handle_admin_revoke_credential(
        &self,
        credential_ref: &passless_core::agent::CredentialRef,
    ) -> Result<AdminResponse, ProtocolError> {
        let affected_grants = self
            .policy_runtime
            .find_grants_by_credential(credential_ref);

        for grant_id in &affected_grants {
            let _ = self.policy_runtime.revoke_grant_by_id(grant_id);
        }

        for profile in self.profiles.values() {
            self.cleanup_all_browsers_for_profile(profile);
        }

        let revoke_event =
            super::audit_events::AdminCredentialRevokeBuilder::new(credential_ref.clone()).build();
        let _ = self.audit_gate.record(revoke_event);

        Ok(AdminResponse::CredentialRevoked)
    }

    fn handle_admin_delete_credential(
        &self,
        credential_ref: &passless_core::agent::CredentialRef,
    ) -> Result<AdminResponse, ProtocolError> {
        let mut _found_isolated = false;

        for profile in self.profiles.values() {
            if profile.mode != AgentMode::Isolated {
                continue;
            }

            let is_in_profile = profile
                .profile_config
                .credential_refs
                .as_ref()
                .is_some_and(|refs| refs.iter().any(|r| r == credential_ref));

            if !is_in_profile {
                continue;
            }

            _found_isolated = true;

            let _op = profile.operation_lock.lock().map_err(|e| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    format!("failed to acquire operation lock: {}", e),
                    RecommendedAction::Retry,
                )
            })?;

            let mut storage = profile.credential_storage.lock().map_err(|e| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    format!("failed to acquire storage lock: {}", e),
                    RecommendedAction::Retry,
                )
            })?;

            let first_result = storage.read_first(crate::storage::CredentialFilter::None);
            let mut cred = match first_result {
                Ok(c) => c,
                Err(e) => {
                    return Err(ProtocolError::new(
                        ErrorCode::Internal,
                        format!("storage enumeration failed: {}", e),
                        RecommendedAction::Retry,
                    ));
                }
            };

            loop {
                let actual_ref = passless_core::agent::CredentialRef::with_default_domain(&cred.id);
                if actual_ref == *credential_ref {
                    storage.delete(credential_ref.as_bytes()).map_err(|e| {
                        ProtocolError::new(
                            ErrorCode::Internal,
                            format!("failed to delete credential: {}", e),
                            RecommendedAction::Retry,
                        )
                    })?;

                    let delete_event = super::audit_events::AdminCredentialDeleteBuilder::new(
                        credential_ref.clone(),
                        &cred.rp.id,
                    )
                    .build();
                    let _ = self.audit_gate.record(delete_event);

                    return Ok(AdminResponse::Deleted);
                }

                match storage.read_next() {
                    Ok(next) => cred = next,
                    Err(_) => break,
                }
            }
        }

        if !_found_isolated {
            return Err(ProtocolError::new(
                ErrorCode::NotFound,
                "credential not found in any isolated profile",
                RecommendedAction::FixRequest,
            ));
        }

        Err(ProtocolError::new(
            ErrorCode::NotFound,
            "credential not found",
            RecommendedAction::FixRequest,
        ))
    }

    fn handle_admin_rename_credential(
        &self,
        credential_ref: &passless_core::agent::CredentialRef,
        _user_name: &Option<String>,
        _display_name: &Option<String>,
    ) -> Result<AdminResponse, ProtocolError> {
        let found_isolated = false;

        for profile in self.profiles.values() {
            if profile.mode != AgentMode::Isolated {
                continue;
            }

            let is_in_profile = profile
                .profile_config
                .credential_refs
                .as_ref()
                .is_some_and(|refs| refs.iter().any(|r| r == credential_ref));

            if !is_in_profile {
                continue;
            }

            let _op = profile.operation_lock.lock().map_err(|e| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    format!("failed to acquire operation lock: {}", e),
                    RecommendedAction::Retry,
                )
            })?;

            let _storage = profile.credential_storage.lock().map_err(|e| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    format!("failed to acquire storage lock: {}", e),
                    RecommendedAction::Retry,
                )
            })?;

            return Err(ProtocolError::new(
                ErrorCode::Internal,
                "credential rename is not yet supported by the storage backend",
                RecommendedAction::FixRequest,
            ));
        }

        if !found_isolated {
            return Err(ProtocolError::new(
                ErrorCode::NotFound,
                "credential not found in any isolated profile",
                RecommendedAction::FixRequest,
            ));
        }

        Err(ProtocolError::new(
            ErrorCode::NotFound,
            "credential not found",
            RecommendedAction::FixRequest,
        ))
    }

    fn handle_list_grants(
        &self,
        profile_filter: Option<&ProfileId>,
    ) -> Result<AdminResponse, ProtocolError> {
        let snapshots = self.policy_runtime.list_grants(profile_filter);
        let now_mono = self.policy_runtime_clock_mono();
        let wall_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let grants: Vec<passless_core::agent::GrantInfo> = snapshots
            .iter()
            .map(|s| {
                let state = match s.state {
                    super::grant::GrantState::Active => {
                        passless_core::agent::DelegationState::Pending
                    }
                    super::grant::GrantState::Revoked => {
                        passless_core::agent::DelegationState::Revoked
                    }
                    super::grant::GrantState::Expired => {
                        passless_core::agent::DelegationState::Expired
                    }
                };
                let details = self.policy_runtime.show_grant_details(&s.id);
                let (rp_id, cred_ref, created_at, expires_at) = if let Some(ref d) = details {
                    let offset = wall_now.saturating_sub(now_mono);
                    (
                        d.first_rp_id.clone(),
                        d.first_credential_ref.clone().unwrap_or_else(|| {
                            passless_core::agent::CredentialRef::with_default_domain(b"")
                        }),
                        d.issued_at_mono + offset,
                        d.expiry_mono + offset,
                    )
                } else {
                    (
                        s.rp_ids.iter().next().cloned().unwrap_or_default(),
                        passless_core::agent::CredentialRef::with_default_domain(b""),
                        0,
                        0,
                    )
                };
                passless_core::agent::GrantInfo {
                    grant_id: s.id.clone(),
                    profile_id: s.profile_id.to_string(),
                    rp_id,
                    credential_ref: cred_ref,
                    state,
                    created_at,
                    expires_at,
                }
            })
            .collect();

        let total = grants.len() as u32;
        Ok(AdminResponse::GrantList(passless_core::agent::GrantList {
            grants,
            total,
        }))
    }

    fn handle_show_grant(&self, grant_id: &GrantId) -> Result<AdminResponse, ProtocolError> {
        let details = self
            .policy_runtime
            .show_grant_details(grant_id)
            .ok_or_else(|| {
                ProtocolError::new(
                    ErrorCode::NotFound,
                    format!("grant '{}' not found", grant_id),
                    RecommendedAction::FixRequest,
                )
            })?;

        let now_mono = self.policy_runtime_clock_mono();
        let wall_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let offset = wall_now.saturating_sub(now_mono);

        let state = match details.state {
            super::grant::GrantState::Active => passless_core::agent::DelegationState::Pending,
            super::grant::GrantState::Revoked => passless_core::agent::DelegationState::Revoked,
            super::grant::GrantState::Expired => passless_core::agent::DelegationState::Expired,
        };

        Ok(AdminResponse::GrantInfo(passless_core::agent::GrantInfo {
            grant_id: details.id.clone(),
            profile_id: details.profile_id.to_string(),
            rp_id: details.first_rp_id.clone(),
            credential_ref: details
                .first_credential_ref
                .unwrap_or_else(|| passless_core::agent::CredentialRef::with_default_domain(b"")),
            state,
            created_at: details.issued_at_mono + offset,
            expires_at: details.expiry_mono + offset,
        }))
    }

    fn handle_revoke_grant(&self, grant_id: &GrantId) -> Result<AdminResponse, ProtocolError> {
        let details = self
            .policy_runtime
            .show_grant_details(grant_id)
            .ok_or_else(|| {
                ProtocolError::new(
                    ErrorCode::NotFound,
                    format!("grant '{}' not found", grant_id),
                    RecommendedAction::FixRequest,
                )
            })?;

        let revoke_event =
            super::audit_events::AdminGrantRevokeBuilder::new(grant_id.clone()).build();
        if let Err(e) = self.audit_gate.record(revoke_event) {
            return Err(ProtocolError::new(
                ErrorCode::Internal,
                format!("audit record for grant revoke failed: {}", e),
                RecommendedAction::Abort,
            ));
        }

        self.policy_runtime
            .revoke_grant_by_id(grant_id)
            .map_err(|e| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    format!("failed to revoke grant: {}", e),
                    RecommendedAction::Retry,
                )
            })?;

        for profile in self.profiles.values() {
            if profile.profile_id != details.profile_id {
                continue;
            }
            self.cleanup_all_browsers_for_profile(profile);
        }

        Ok(AdminResponse::GrantRevoked)
    }

    fn handle_list_sessions(
        &self,
        profile_filter: Option<&ProfileId>,
    ) -> Result<AdminResponse, ProtocolError> {
        let wall_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut sessions_out = Vec::new();
        for (profile_id, session_slot) in &self.managed_sessions {
            if let Some(filter) = profile_filter
                && profile_id != filter
            {
                continue;
            }
            let sessions = session_slot.lock().unwrap();
            for managed in sessions.iter() {
                let created_at = wall_now.saturating_sub(managed.created_at.elapsed().as_secs());
                let expires_at = wall_now.saturating_add(
                    managed
                        .deadline
                        .saturating_duration_since(Instant::now())
                        .as_secs(),
                );
                sessions_out.push(passless_core::agent::SessionInfo {
                    session_id: managed.session_id.clone(),
                    profile_id: profile_id.to_string(),
                    pid: managed.session.child.id(),
                    created_at,
                    expires_at,
                });
            }
        }

        let total = sessions_out.len() as u32;
        Ok(AdminResponse::SessionList(
            passless_core::agent::SessionList {
                sessions: sessions_out,
                total,
            },
        ))
    }

    fn handle_show_session(
        &self,
        session_id: &PrincipalSessionId,
    ) -> Result<AdminResponse, ProtocolError> {
        let wall_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for (profile_id, session_slot) in &self.managed_sessions {
            let sessions = session_slot.lock().unwrap();
            if let Some(managed) = sessions
                .iter()
                .find(|managed| managed.session_id == *session_id)
            {
                let created_at = wall_now.saturating_sub(managed.created_at.elapsed().as_secs());
                let expires_at = wall_now.saturating_add(
                    managed
                        .deadline
                        .saturating_duration_since(Instant::now())
                        .as_secs(),
                );
                return Ok(AdminResponse::SessionInfo(
                    passless_core::agent::SessionInfo {
                        session_id: managed.session_id.clone(),
                        profile_id: profile_id.to_string(),
                        pid: managed.session.child.id(),
                        created_at,
                        expires_at,
                    },
                ));
            }
        }

        Err(ProtocolError::new(
            ErrorCode::NotFound,
            format!("session '{}' not found", session_id),
            RecommendedAction::FixRequest,
        ))
    }

    fn handle_revoke_session(
        &self,
        session_id: &PrincipalSessionId,
    ) -> Result<AdminResponse, ProtocolError> {
        for (profile_id, session_slot) in &self.managed_sessions {
            let mut sessions = session_slot.lock().unwrap();
            if let Some(pos) = sessions
                .iter()
                .position(|managed| managed.session_id == *session_id)
            {
                let managed = sessions.remove(pos);
                drop(sessions);
                info!(
                    "Revoking session {} for profile {} (pid {})",
                    managed.session_id,
                    profile_id,
                    managed.session.child.id()
                );

                let revoke_event = super::audit_events::AdminSessionRevokeBuilder::new(
                    session_id.clone(),
                    profile_id.clone(),
                )
                .build();
                let _ = self.audit_gate.record(revoke_event);

                if let Some(profile) = self.profiles.get(profile_id) {
                    self.cleanup_browser_for_session(profile, session_id);
                }

                drop(managed.session);
                return Ok(AdminResponse::SessionRevoked);
            }
        }

        Err(ProtocolError::new(
            ErrorCode::NotFound,
            format!("session '{}' not found", session_id),
            RecommendedAction::FixRequest,
        ))
    }

    fn handle_audit_status(&self) -> Result<AdminResponse, ProtocolError> {
        let seq = self.audit_gate.current_sequence();
        let broken = self.audit_gate.is_circuit_broken();
        Ok(AdminResponse::AuditStatus(
            passless_core::agent::AuditStatusResponse {
                enabled: !broken,
                entry_count: seq,
                latest_entry_at: if seq > 0 { Some(seq) } else { None },
            },
        ))
    }

    fn handle_audit_verify(&self) -> Result<AdminResponse, ProtocolError> {
        match self.audit_gate.verify_all() {
            Ok(entries) => Ok(AdminResponse::AuditVerified(
                passless_core::agent::AuditVerifyResponse {
                    verified: true,
                    entries_checked: entries,
                    integrity_ok: true,
                },
            )),
            Err(_) => Ok(AdminResponse::AuditVerified(
                passless_core::agent::AuditVerifyResponse {
                    verified: false,
                    entries_checked: 0,
                    integrity_ok: false,
                },
            )),
        }
    }

    fn handle_audit_export(
        &self,
        format: &passless_core::agent::protocol::AuditExportFormat,
    ) -> Result<AdminResponse, ProtocolError> {
        let audit_dir = self.audit_gate.dir_path();

        let export_format = match format {
            passless_core::agent::protocol::AuditExportFormat::Json => {
                super::audit::ExportFormat::Json
            }
            passless_core::agent::protocol::AuditExportFormat::Csv => {
                super::audit::ExportFormat::Csv
            }
        };

        let result = self
            .audit_gate
            .export_verified(export_format, audit_dir)
            .map_err(|e| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    format!("audit export failed: {}", e),
                    RecommendedAction::Abort,
                )
            })?;

        Ok(AdminResponse::AuditExported(
            passless_core::agent::AuditExportedResponse {
                entry_count: result.entry_count,
                format: *format,
                path: result.path.display().to_string(),
            },
        ))
    }

    fn handle_admin_request_delegation(
        &self,
        profile_id: &ProfileId,
        rp_id: &str,
        credential_ref: &passless_core::agent::CredentialRef,
        max_session_ttl: u64,
        reason: Option<&str>,
    ) -> Result<AdminResponse, ProtocolError> {
        let profile = self.profiles.get(profile_id).ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::NotFound,
                format!("profile '{}' not found", profile_id),
                RecommendedAction::FixRequest,
            )
        })?;

        let session_slot = self.managed_sessions.get(profile_id).ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::NotFound,
                "no session slot for profile",
                RecommendedAction::Abort,
            )
        })?;

        let managed_guard = session_slot.lock().unwrap();
        let managed = match managed_guard.as_slice() {
            [managed] => managed,
            [] => {
                return Err(ProtocolError::new(
                    ErrorCode::Conflict,
                    "no active principal session for this profile; launch one first with `passless agent run`",
                    RecommendedAction::FixRequest,
                ));
            }
            _ => {
                return Err(ProtocolError::new(
                    ErrorCode::Conflict,
                    "multiple principal sessions are active; issue this request from the target principal session",
                    RecommendedAction::FixRequest,
                ));
            }
        };

        let _lifecycle = profile.lifecycle_lock.lock().unwrap();
        {
            let eid_guard = profile.endpoint_id.lock().unwrap();
            if eid_guard.is_none() {
                drop(eid_guard);
                let eid = passless_core::agent::EndpointId::new();
                info!(
                    "Profile '{}' using human-shared endpoint (no agent UHID device): {}",
                    profile_id.as_str(),
                    eid.as_str()
                );
                let mut eid_guard = profile.endpoint_id.lock().unwrap();
                *eid_guard = Some(eid);
            }
        }
        let eid = profile.endpoint_id.lock().unwrap().clone().unwrap();

        let resp = self.handle_request_delegation(RequestDelegationParams {
            profile_id,
            session_id: &managed.session_id,
            endpoint_id: &eid,
            rp_id,
            credential_ref,
            max_session_ttl,
            principal_reason: reason.map(|s| s.to_string()),
            profile,
            session_digest: &managed.process_digest,
        })?;

        match resp {
            PrincipalResponse::DelegationRequested { request_id } => {
                Ok(AdminResponse::DelegationRequested { request_id })
            }
            _ => Err(ProtocolError::new(
                ErrorCode::Internal,
                "unexpected response from delegation handler",
                RecommendedAction::Retry,
            )),
        }
    }

    fn handle_launch_browser(
        &self,
        profile_id: &ProfileId,
        start_url: Option<&str>,
    ) -> Result<AdminResponse, ProtocolError> {
        let profile = self.profiles.get(profile_id).ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::NotFound,
                format!("profile '{}' not found", profile_id),
                RecommendedAction::FixRequest,
            )
        })?;

        let endpoint_id = profile.endpoint_id.lock().unwrap().clone().ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::NotFound,
                format!("profile '{}' has no active endpoint", profile_id),
                RecommendedAction::FixRequest,
            )
        })?;

        let profile_config = &profile.profile_config;

        let browser_command = profile_config.browser_command.as_ref().ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::BadRequest,
                format!("profile '{}' has no browser_command configured", profile_id),
                RecommendedAction::FixRequest,
            )
        })?;

        let executable = PathBuf::from(&browser_command[0]);
        let extra_args = browser_command[1..].to_vec();

        let runtime_root = profile_config
            .browser_runtime_root
            .clone()
            .unwrap_or_else(|| {
                dirs::runtime_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
                    .join("passless")
                    .join("browser")
            });

        let browser_uid = profile.browser_uid.unwrap_or(profile.daemon_uid);
        let browser_gid = profile.browser_gid.unwrap_or(profile.daemon_gid);

        let rp_ids = profile_config.rule_rp_ids();

        let config = BrowserConfig {
            executable,
            start_url: start_url
                .map(|s| s.to_string())
                .or_else(|| profile_config.start_url.clone()),
            extra_args,
            runtime_root,
            ttl: std::time::Duration::from_secs(3600),
            login_timeout: std::time::Duration::from_secs(300),
            rp_ids,
            start_url_rules: profile_config.rules.clone(),
            target_uid: browser_uid,
            target_gid: browser_gid,
            daemon_uid: profile.daemon_uid,
            daemon_gid: profile.daemon_gid,
            cdp_expose: profile_config
                .browser_cdp_expose
                .unwrap_or(CdpExposeMode::Pipe),
            cdp_port: profile_config.browser_cdp_port.unwrap_or(0),
            bind_parent_death: profile_config.browser_scope != BrowserScope::Profile,
        };

        let mut browser_manager = self.browser_manager.lock().map_err(|_| {
            ProtocolError::new(
                ErrorCode::Internal,
                "browser manager lock poisoned",
                RecommendedAction::Abort,
            )
        })?;

        if let Some(existing_snapshot) = browser_manager.find_live_lease_for_profile(profile_id) {
            let cdp_endpoint = browser_manager
                .lease_cdp_endpoint(&existing_snapshot.id)
                .flatten();

            return Ok(AdminResponse::BrowserLaunched(
                passless_core::agent::protocol::BrowserLaunchedResponse {
                    lease_id: existing_snapshot.id.to_string(),
                    profile_id: profile_id.to_string(),
                    pid: existing_snapshot.pid,
                    start_url: existing_snapshot.start_url,
                    cdp_endpoint,
                },
            ));
        }

        // Generate bearer token for this browser session
        let bearer_token = super::sign::generate_bearer_token().map_err(|e| {
            ProtocolError::new(
                ErrorCode::Internal,
                format!("failed to generate bearer token: {}", e),
                RecommendedAction::Abort,
            )
        })?;

        // Registration authority is policy only (`register = "allow"` on an exact RP rule); the
        // bearer is bound to the browser lease below and revoked with it.
        let register_ctx = super::register::RegisterContext::new(
            profile_id.clone(),
            profile_config.max_operations,
        );

        let register_handler = Arc::new(super::register::RegisterHandler {
            policy_runtime: self.policy_runtime.clone(),
            credential_storage: profile.backend.credential_storage.clone(),
            audit_gate: self.audit_gate.clone(),
            key_provider: profile.backend.key_provider.clone(),
            security_config: profile.security_config.clone(),
            operation_lock: profile.backend.operation_lock.clone(),
        });

        // Register the bearer token with the sign registry for registration
        self.sign_registry
            .register_pending_registration(bearer_token.clone(), register_ctx, register_handler)
            .map_err(|e| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    format!("failed to register registration context: {}", e),
                    RecommendedAction::Abort,
                )
            })?;

        let metadata = super::browser::AgentEndpointMetadata {
            socket_path: self.sign_socket_path.to_string_lossy().into_owned(),
            bearer_token: bearer_token.clone(),
        };

        let lease_id = match browser_manager.launch_pending_with_agent_endpoint(
            &config,
            endpoint_id.clone(),
            profile_id.clone(),
            Some(&metadata),
        ) {
            Ok(id) => id,
            Err(e) => {
                self.sign_registry.revoke_registration(&bearer_token);
                return Err(ProtocolError::new(
                    ErrorCode::Internal,
                    format!("failed to launch browser: {}", e),
                    RecommendedAction::FixRequest,
                ));
            }
        };

        // The registration bearer lives and dies with the browser lease.
        if let Err(e) = self
            .sign_registry
            .bind_registration_lease(&bearer_token, lease_id.to_string())
        {
            self.sign_registry.revoke_registration(&bearer_token);
            let _ = browser_manager.revoke(&lease_id);
            let _ = browser_manager.terminate(&lease_id);
            let _ = browser_manager.cleanup(&lease_id);
            browser_manager.remove(&lease_id);
            return Err(ProtocolError::new(
                ErrorCode::Internal,
                format!("failed to bind registration context to lease: {}", e),
                RecommendedAction::Abort,
            ));
        }

        let snapshot = browser_manager.snapshot(&lease_id).ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::Internal,
                "browser lease not found after launch",
                RecommendedAction::Abort,
            )
        })?;

        let pid = snapshot.pid;

        // Register one authentication context for every credential in the selected
        // backend that is both in RP scope and in the optional configured
        // credential scope. Selection for a concrete ceremony happens in the
        // sign handler using allowCredentials/discoverable semantics.
        let mut credential_refs = Vec::new();
        if let Ok(mut storage) = profile.backend.credential_storage.lock()
            && let Ok(mut cred) = storage.read_first(crate::storage::CredentialFilter::None)
        {
            loop {
                let rp_allowed = config
                    .rp_ids
                    .iter()
                    .any(|rp| rp.eq_ignore_ascii_case(&cred.rp.id));
                let credential_ref =
                    passless_core::agent::CredentialRef::with_default_domain(&cred.id);
                let credential_allowed = profile_config
                    .credential_refs
                    .as_ref()
                    .is_none_or(|refs| refs.iter().any(|candidate| candidate == &credential_ref));
                if rp_allowed && credential_allowed {
                    credential_refs.push(credential_ref);
                }
                match storage.read_next() {
                    Ok(next) => cred = next,
                    Err(_) => break,
                }
            }
        }

        let dynamic_credential_scope = profile_config.credential_refs.is_none();
        if !config.rp_ids.is_empty() && (dynamic_credential_scope || !credential_refs.is_empty()) {
            let session_id = passless_core::agent::PrincipalSessionId::new();
            let grant_params = super::grant::GrantRequestParams {
                profile_id: profile_id.clone(),
                session_id,
                endpoint_id: endpoint_id.clone(),
                principal_digest: [0u8; 32],
                rp_ids: config.rp_ids.clone(),
                credentials: if dynamic_credential_scope {
                    Vec::new()
                } else {
                    credential_refs
                },
                requested_ttl_secs: profile_config
                    .max_session_ttl
                    .as_ref()
                    .map(|ttl| ttl.as_secs())
                    .unwrap_or(300),
            };
            let grant_request = if dynamic_credential_scope {
                self.policy_runtime
                    .admin_request_dynamic_grant(grant_params)
            } else {
                self.policy_runtime.admin_request_grant(grant_params)
            };
            match grant_request {
                Ok(request_id) => {
                    match self
                        .policy_runtime
                        .admin_approve_grant(&request_id, &super::intent::admin_authority())
                    {
                        Ok(grant_id) => {
                            let sign_ctx = super::sign::SignContext {
                                profile_id: profile_id.clone(),
                                active_grant_id: grant_id,
                                max_operations: profile_config.max_operations,
                            };
                            let sign_handler = Arc::new(super::sign::SignHandler {
                                credential_storage: profile.backend.credential_storage.clone(),
                                policy_runtime: self.policy_runtime.clone(),
                                audit_gate: self.audit_gate.clone(),
                                security_config: profile.security_config.clone(),
                                key_provider: profile.backend.key_provider.clone(),
                                operation_lock: profile.backend.operation_lock.clone(),
                            });
                            if let Err(e) = self.sign_registry.register_pending(
                                bearer_token.clone(),
                                sign_ctx,
                                sign_handler,
                            ) {
                                log::error!("failed to register sign context: {}", e);
                            } else if let Err(e) = self
                                .sign_registry
                                .bind_lease(&bearer_token, lease_id.to_string())
                            {
                                log::error!("failed to bind sign context to lease: {}", e);
                            } else {
                                info!(
                                    "sign context registered and bound to lease for profile={}",
                                    profile_id
                                );
                            }
                        }
                        Err(e) => {
                            log::error!("failed to approve grant: {}", e);
                        }
                    }
                }
                Err(e) => {
                    log::error!("failed to request grant: {}", e);
                }
            }
        } else {
            debug!(
                "no configured credentials in backend scope for profile={}; authentication remains unavailable",
                profile_id
            );
        }

        let cdp_endpoint = browser_manager.lease_cdp_endpoint(&lease_id).flatten();

        Ok(AdminResponse::BrowserLaunched(
            passless_core::agent::protocol::BrowserLaunchedResponse {
                lease_id: lease_id.to_string(),
                profile_id: profile_id.to_string(),
                pid,
                start_url: config.start_url,
                cdp_endpoint,
            },
        ))
    }

    fn handle_shutdown(&self) -> Result<AdminResponse, ProtocolError> {
        let shutdown_event =
            super::audit_events::AdminShutdownRequestBuilder::new(std::process::id()).build();
        let _ = self.audit_gate.record(shutdown_event);

        self.shutdown_requested.store(true, Ordering::Release);
        Ok(AdminResponse::ShutdownAccepted)
    }

    fn policy_runtime_clock_mono(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

impl AdminHandler for AgentRuntime {
    fn handle_admin(
        &self,
        request: &AdminRequest,
        cred: &PeerCred,
        ctx: &super::ipc::AdminRequestContext,
    ) -> Result<AdminResponse, ProtocolError> {
        if cred.uid != self.daemon_uid {
            return Err(ProtocolError::new(
                ErrorCode::Unauthorized,
                "admin peer credentials mismatch",
                RecommendedAction::Abort,
            ));
        }

        match request {
            AdminRequest::Ping => Ok(AdminResponse::Pong),
            AdminRequest::Status => {
                let credential_count = self.total_credential_count();
                Ok(AdminResponse::Status(DaemonStatus {
                    daemon_version: env!("CARGO_PKG_VERSION").into(),
                    protocol_version: passless_core::agent::protocol::CURRENT_VERSION,
                    backend: "agent".into(),
                    uptime_secs: 0,
                    credential_count,
                }))
            }
            AdminRequest::LaunchPrincipal {
                profile_id,
                command,
            } => self.handle_launch_principal(profile_id, command, cred, ctx),
            AdminRequest::TerminatePrincipal { profile_id } => {
                self.handle_terminate_principal(profile_id)
            }
            AdminRequest::WaitPrincipal {
                session_id,
                timeout_ms,
            } => self.handle_wait_principal(session_id, *timeout_ms),
            AdminRequest::ListProfiles => self.handle_listprofiles(),
            AdminRequest::ShowProfile { profile_id } => self.handle_showprofile(profile_id),
            AdminRequest::ProfileStatus { profile_id } => self.handle_showprofile(profile_id),
            AdminRequest::EnableProfile { profile_id } => self.handle_enableprofile(profile_id),
            AdminRequest::DisableProfile { profile_id } => self.handle_disableprofile(profile_id),
            AdminRequest::ShowPolicy { profile_id } => self.handle_show_policy(profile_id),
            AdminRequest::ReloadPolicy { profile_id } => self.handle_reload_policy(profile_id),
            AdminRequest::ListCredentials { rp_id } => self.handle_admin_list_credentials(rp_id),
            AdminRequest::ShowCredential { credential_ref } => {
                self.handle_admin_show_credential(credential_ref)
            }
            AdminRequest::RevokeCredential { credential_ref } => {
                self.handle_admin_revoke_credential(credential_ref)
            }
            AdminRequest::DeleteCredential { credential_ref } => {
                self.handle_admin_delete_credential(credential_ref)
            }
            AdminRequest::RenameCredential {
                credential_ref,
                user_name,
                display_name,
            } => self.handle_admin_rename_credential(credential_ref, user_name, display_name),
            AdminRequest::ListGrants { profile_id } => self.handle_list_grants(profile_id.as_ref()),
            AdminRequest::ShowGrant { grant_id } => self.handle_show_grant(grant_id),
            AdminRequest::RevokeGrant { grant_id } => self.handle_revoke_grant(grant_id),
            AdminRequest::ListDelegations { profile_id } => {
                self.handle_list_grants(profile_id.as_ref())
            }
            AdminRequest::ShowDelegation { grant_id } => self.handle_show_grant(grant_id),
            AdminRequest::RevokeDelegation { grant_id } => self.handle_revoke_grant(grant_id),
            AdminRequest::ListSessions { profile_id } => {
                self.handle_list_sessions(profile_id.as_ref())
            }
            AdminRequest::ShowSession { session_id } => self.handle_show_session(session_id),
            AdminRequest::RevokeSession { session_id } => self.handle_revoke_session(session_id),
            AdminRequest::AuditStatus => self.handle_audit_status(),
            AdminRequest::AuditVerify => self.handle_audit_verify(),
            AdminRequest::AuditExport { format } => self.handle_audit_export(format),
            AdminRequest::ProfileCheck { profile_id } => self.handle_profile_check(profile_id),
            AdminRequest::RequestDelegation {
                profile_id,
                rp_id,
                credential_ref,
                max_session_ttl,
                reason,
            } => self.handle_admin_request_delegation(
                profile_id,
                rp_id,
                credential_ref,
                *max_session_ttl,
                reason.as_deref(),
            ),
            AdminRequest::LaunchBrowser {
                profile_id,
                start_url,
            } => self.handle_launch_browser(profile_id, start_url.as_deref()),
            AdminRequest::Shutdown => self.handle_shutdown(),
        }
    }
}

impl PrincipalHandler for AgentRuntime {
    fn handle_principal(
        &self,
        profile_id: &str,
        request: &PrincipalRequest,
        cred: &PeerCred,
        identity: &super::launcher::PeerIdentity,
        capability_proof: &passless_core::agent::PrincipalCapabilityProof,
    ) -> Result<PrincipalResponse, ProtocolError> {
        let profile_id = ProfileId::new(profile_id).map_err(|e| {
            ProtocolError::new(
                ErrorCode::BadRequest,
                format!("invalid profile id: {}", e),
                RecommendedAction::FixRequest,
            )
        })?;

        let profile = self.profiles.get(&profile_id).ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::NotFound,
                format!("profile '{}' not found", profile_id),
                RecommendedAction::FixRequest,
            )
        })?;

        if !profile.enabled.load(Ordering::Acquire) {
            return Err(ProtocolError::new(
                ErrorCode::Forbidden,
                format!("profile '{}' is disabled", profile_id),
                RecommendedAction::FixRequest,
            ));
        }

        if cred.uid != profile.uid || cred.gid != profile.gid {
            return Err(ProtocolError::new(
                ErrorCode::Unauthorized,
                "principal peer credentials do not match profile",
                RecommendedAction::Abort,
            ));
        }

        let session_slot = self.managed_sessions.get(&profile_id).ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::Unauthorized,
                format!("no active launcher session for profile '{}'", profile_id),
                RecommendedAction::Abort,
            )
        })?;

        let sessions = session_slot.lock().unwrap();
        let supplied_capability = SessionCapability::from_bytes(*capability_proof.as_bytes());
        let managed = sessions
            .iter()
            .find(|managed| managed.session.capability.verify(&supplied_capability))
            .ok_or_else(|| {
                ProtocolError::new(
                    ErrorCode::Unauthorized,
                    "capability proof does not match an active principal session",
                    RecommendedAction::Abort,
                )
            })?;

        let session = &managed.session;

        let proc_root = &session.proc_root;
        let peer_pid = cred.pid;

        if identity.uid != session.identity.uid {
            return Err(ProtocolError::new(
                ErrorCode::Unauthorized,
                "peer uid mismatch with session identity",
                RecommendedAction::Abort,
            ));
        }
        if identity.gid != session.identity.gid {
            return Err(ProtocolError::new(
                ErrorCode::Unauthorized,
                "peer gid mismatch with session identity",
                RecommendedAction::Abort,
            ));
        }
        if identity.cgroup_path != session.identity.cgroup_path {
            return Err(ProtocolError::new(
                ErrorCode::Unauthorized,
                "peer cgroup mismatch with session identity",
                RecommendedAction::Abort,
            ));
        }
        if identity.ns_inodes != session.identity.ns_inodes {
            return Err(ProtocolError::new(
                ErrorCode::Unauthorized,
                "peer namespace inodes mismatch with session identity",
                RecommendedAction::Abort,
            ));
        }

        if let Err(e) = verify_process_ancestry(peer_pid, &session.identity, proc_root) {
            return Err(ProtocolError::new(
                ErrorCode::Unauthorized,
                format!("process ancestry verification failed: {}", e),
                RecommendedAction::Abort,
            ));
        }

        match request {
            PrincipalRequest::Ping => Ok(PrincipalResponse::Pong),
            PrincipalRequest::Status => {
                let credential_count = self.total_credential_count();
                Ok(PrincipalResponse::Status(DaemonStatus {
                    daemon_version: env!("CARGO_PKG_VERSION").into(),
                    protocol_version: passless_core::agent::protocol::CURRENT_VERSION,
                    backend: "agent".into(),
                    uptime_secs: 0,
                    credential_count,
                }))
            }
            PrincipalRequest::Capabilities => {
                let mode_str = format!("{:?}", profile.mode);
                Ok(PrincipalResponse::Capabilities(PrincipalCapabilities {
                    profile_id: profile_id.to_string(),
                    mode: mode_str,
                    allowed_rp_ids: profile.profile_config.allowed_rp_ids(),
                    registration_allowed: profile.profile_config.allows_registration(),
                }))
            }
            PrincipalRequest::Authority => Ok(PrincipalResponse::Authority(
                self.build_effective_authority(&profile_id, profile, managed),
            )),
            PrincipalRequest::Instructions => {
                let mode_str = format!("{:?}", profile.mode);
                Ok(PrincipalResponse::Instructions(PrincipalInstructions {
                    profile_id: profile_id.to_string(),
                    mode: mode_str,
                    instructions: "Use WebAuthn API for authentication".into(),
                }))
            }
            PrincipalRequest::Doctor => {
                let report = self.build_profile_report(&profile_id, profile);
                Ok(PrincipalResponse::Doctor(DoctorResponse {
                    healthy: report.is_healthy(),
                    checks: report.checks,
                }))
            }
            // Agent ceremonies run only through the browser extension (ADR 0014 section 5); the
            // per-ceremony intent hand-off belonged to the removed UHID route.
            PrincipalRequest::CreateIntent { .. } => Err(ProtocolError::new(
                ErrorCode::Forbidden,
                "intents are not available: agent ceremonies use the browser extension path",
                RecommendedAction::FixRequest,
            )),
            PrincipalRequest::ShowIntent { request_id } => {
                self.handle_show_intent(&profile_id, &managed.session_id, request_id, profile)
            }
            PrincipalRequest::WaitIntent { request_id } => {
                self.handle_show_intent(&profile_id, &managed.session_id, request_id, profile)
            }
            PrincipalRequest::CancelIntent { request_id } => {
                self.handle_cancel_intent(&profile_id, &managed.session_id, request_id, profile)
            }
            PrincipalRequest::RequestDelegation {
                profile_id: _req_profile_id,
                rp_id,
                credential_ref,
                max_session_ttl,
                reason,
            } => {
                let _lifecycle = profile.lifecycle_lock.lock().unwrap();
                {
                    let mut eid_guard = profile.endpoint_id.lock().unwrap();
                    if eid_guard.is_none() {
                        *eid_guard = Some(EndpointId::new());
                    }
                }
                let eid = profile.endpoint_id.lock().unwrap().clone().unwrap();
                self.handle_request_delegation(RequestDelegationParams {
                    profile_id: &profile_id,
                    session_id: &managed.session_id,
                    endpoint_id: &eid,
                    rp_id,
                    credential_ref,
                    max_session_ttl: *max_session_ttl,
                    principal_reason: reason.clone(),
                    profile,
                    session_digest: &managed.process_digest,
                })
            }
            PrincipalRequest::ShowDelegation { request_id } => {
                self.handle_show_delegation(&profile_id, &managed.session_id, request_id, profile)
            }
            PrincipalRequest::WaitDelegation { request_id } => {
                self.handle_show_delegation(&profile_id, &managed.session_id, request_id, profile)
            }
            PrincipalRequest::CancelDelegation { request_id } => {
                self.handle_cancel_delegation(&profile_id, &managed.session_id, request_id, profile)
            }
            PrincipalRequest::ListCredentials {
                profile_id: _req_profile_id,
            } => self.handle_list_credentials(&profile_id, profile),
            PrincipalRequest::BrowserStatus => {
                self.handle_browser_status(&profile_id, &managed.session_id, profile)
            }
            PrincipalRequest::EnsureBrowser { start_url } => self.handle_ensure_browser(
                &profile_id,
                &managed.session_id,
                &managed.process_digest,
                start_url.as_deref(),
                profile,
            ),
            PrincipalRequest::EndpointStatus => {
                // Agents have no device endpoint; the id is only a logical handle.
                let eid = profile.endpoint_id.lock().unwrap().clone();
                Ok(PrincipalResponse::EndpointStatus(EndpointStatusResponse {
                    endpoint_id: eid.unwrap_or_else(EndpointId::new),
                    status: "extension".into(),
                    connected: false,
                }))
            }
            PrincipalRequest::BrowserControl {
                request_json,
                timeout_ms,
            } => self.handle_browser_control(
                &profile_id,
                &managed.session_id,
                request_json,
                *timeout_ms,
                profile,
            ),
            PrincipalRequest::SignAssertion(_req) => Err(ProtocolError::new(
                ErrorCode::Forbidden,
                "sign assertions are not available; delegated mode has been removed",
                RecommendedAction::FixRequest,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_tracker_try_acquire_respects_limit() {
        let tracker = WorkerTracker::new();
        for _ in 0..MAX_WORKERS {
            assert!(tracker.try_acquire());
        }
        assert!(!tracker.try_acquire());
    }

    #[test]
    fn worker_tracker_release_allows_new_acquire() {
        let tracker = WorkerTracker::new();
        for _ in 0..MAX_WORKERS {
            assert!(tracker.try_acquire());
        }
        assert!(!tracker.try_acquire());

        tracker.release();
        assert!(tracker.try_acquire());
    }

    #[test]
    fn worker_tracker_reap_finished_removes_completed_handles() {
        let tracker = WorkerTracker::new();
        let h1 = std::thread::spawn(|| {});
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let gate_clone = gate.clone();
        let h2 = std::thread::spawn(move || {
            let (lock, cvar) = &*gate_clone;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = cvar.wait(released).unwrap();
            }
        });
        let h3 = std::thread::spawn(|| {});

        tracker.push_handle(h1);
        tracker.push_handle(h2);
        tracker.push_handle(h3);

        std::thread::sleep(Duration::from_millis(50));

        tracker.reap_finished();

        let remaining = tracker.handles.lock().unwrap().len();
        assert_eq!(remaining, 1);

        {
            let (lock, cvar) = &*gate;
            *lock.lock().unwrap() = true;
            cvar.notify_all();
        }
        tracker.join_all();
    }

    #[test]
    fn worker_tracker_join_all_waits_for_completion() {
        let tracker = WorkerTracker::new();
        let flag = Arc::new(AtomicBool::new(false));
        let flag_clone = flag.clone();

        let h = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            flag_clone.store(true, Ordering::Release);
        });
        tracker.push_handle(h);

        tracker.join_all();
        assert!(flag.load(Ordering::Acquire));
        assert!(tracker.handles.lock().unwrap().is_empty());
    }

    #[test]
    fn worker_tracker_active_count_tracks_acquire_release() {
        let tracker = WorkerTracker::new();

        assert!(tracker.try_acquire());
        assert!(tracker.try_acquire());

        tracker.release();
        tracker.release();
    }

    #[test]
    fn validate_principal_executable_rejects_relative_path() {
        let err = validate_principal_executable("relative/path", 0).unwrap_err();
        assert!(err.to_string().contains("absolute"));
    }

    #[test]
    fn validate_principal_executable_rejects_nonexistent_path() {
        let err = validate_principal_executable("/nonexistent/binary", 0).unwrap_err();
        assert!(err.to_string().contains("cannot be resolved"));
    }

    #[test]
    fn validate_principal_executable_rejects_directory() {
        let dir = tempfile::tempdir().unwrap();
        let err = validate_principal_executable(dir.path().to_str().unwrap(), 0).unwrap_err();
        assert!(err.to_string().contains("not a regular file"));
    }

    #[test]
    fn validate_principal_executable_accepts_root_owned_executable() {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata("/bin/true").unwrap();
        let result = validate_principal_executable("/bin/true", 0);
        if meta.uid() == 0 {
            assert!(
                result.is_ok(),
                "/bin/true is root-owned, should be accepted"
            );
        } else {
            assert!(
                result.is_err(),
                "/bin/true is not root-owned, should be rejected"
            );
        }
    }

    #[test]
    fn validate_principal_executable_accepts_daemon_uid_owned() {
        let my_uid = unsafe { libc::getuid() };
        let result = validate_principal_executable("/bin/true", my_uid);
        assert!(
            result.is_ok(),
            "/bin/true owned by daemon uid should be accepted"
        );
    }

    #[test]
    fn active_browser_lease_stores_session_and_deadline() {
        let lease_id = BrowserLeaseId::new();
        let session_id = PrincipalSessionId::new();
        let lease = ActiveBrowserLease {
            lease_id: lease_id.clone(),
            session_id: session_id.clone(),
        };
        assert_eq!(lease.lease_id, lease_id);
        assert_eq!(lease.session_id, session_id);
    }

    #[test]
    fn active_browser_pending_mutex_independent() {
        let lease_id = BrowserLeaseId::new();
        let session_id = PrincipalSessionId::new();
        let active = ActiveBrowserLease {
            lease_id: lease_id.clone(),
            session_id: session_id.clone(),
        };
        let mutex: Mutex<Option<ActiveBrowserLease>> = Mutex::new(None);
        assert!(mutex.lock().unwrap().is_none());
        *mutex.lock().unwrap() = Some(active);
        let taken = mutex.lock().unwrap().take();
        assert!(taken.is_some());
        let taken = taken.unwrap();
        assert_eq!(taken.lease_id, lease_id);
        assert_eq!(taken.session_id, session_id);
        assert!(mutex.lock().unwrap().is_none());
    }

    #[test]
    fn cross_session_id_mismatch_detected() {
        let session_a = PrincipalSessionId::new();
        let session_b = PrincipalSessionId::new();
        assert_ne!(session_a, session_b);

        let lease = ActiveBrowserLease {
            lease_id: BrowserLeaseId::new(),
            session_id: session_a.clone(),
        };
        assert_ne!(lease.session_id, session_b);
    }

    #[test]
    fn browser_control_outcome_has_requested_variant() {
        let outcome = super::super::audit_events::BrowserControlOutcome::Requested;
        let serialized = serde_json::to_string(&outcome).unwrap();
        assert_eq!(serialized, "\"requested\"");
    }

    #[test]
    fn active_browser_lease_deadline_is_clamped() {
        let lease_id: BrowserLeaseId =
            "0000000000000000000000000000000000000000000000000000000000000001"
                .parse()
                .unwrap();
        let session_id: PrincipalSessionId =
            "0000000000000000000000000000000000000000000000000000000000000002"
                .parse()
                .unwrap();
        let lease = ActiveBrowserLease {
            lease_id: lease_id.clone(),
            session_id: session_id.clone(),
        };
        assert_eq!(lease.lease_id, lease_id);
        assert_eq!(lease.session_id, session_id);
    }

    #[test]
    fn endpoint_id_mutex_can_store_and_retrieve() {
        let eid: Mutex<Option<EndpointId>> = Mutex::new(None);
        let new_id = EndpointId::new();
        *eid.lock().unwrap() = Some(new_id.clone());
        assert_eq!(eid.lock().unwrap().as_ref().unwrap(), &new_id);
    }

    #[test]
    fn endpoint_id_mutex_take_clears_to_none() {
        let eid: Mutex<Option<EndpointId>> = Mutex::new(Some(EndpointId::new()));
        let taken = eid.lock().unwrap().take();
        assert!(taken.is_some());
        assert!(eid.lock().unwrap().is_none());
    }

    #[test]
    fn lifecycle_lock_is_independent_of_endpoint_id() {
        let lifecycle_lock: Mutex<()> = Mutex::new(());
        let eid: Mutex<Option<EndpointId>> = Mutex::new(None);

        {
            let _lifecycle = lifecycle_lock.lock().unwrap();
            assert!(eid.lock().unwrap().is_none());
            *eid.lock().unwrap() = Some(EndpointId::new());
        }

        {
            let _lifecycle = lifecycle_lock.lock().unwrap();
            assert!(eid.lock().unwrap().is_some());
        }
    }

    #[test]
    fn no_duplicate_endpoint_under_concurrent_lifecycle_lock() {
        use std::sync::atomic::AtomicUsize;

        let lifecycle_lock: Arc<Mutex<()>> = Arc::new(Mutex::new(()));
        let eid: Arc<Mutex<Option<EndpointId>>> = Arc::new(Mutex::new(None));
        let create_count = Arc::new(AtomicUsize::new(0));

        let threads: Vec<_> = (0..4)
            .map(|_| {
                let lock = lifecycle_lock.clone();
                let eid_mutex = eid.clone();
                let count = create_count.clone();
                std::thread::spawn(move || {
                    let _lifecycle = lock.lock().unwrap();
                    let should_create = {
                        let guard = eid_mutex.lock().unwrap();
                        guard.is_none()
                    };
                    if should_create {
                        count.fetch_add(1, Ordering::SeqCst);
                        *eid_mutex.lock().unwrap() = Some(EndpointId::new());
                    }
                })
            })
            .collect();

        for t in threads {
            t.join().unwrap();
        }

        assert_eq!(
            create_count.load(Ordering::SeqCst),
            1,
            "endpoint should be created exactly once under lifecycle lock"
        );
        assert!(eid.lock().unwrap().is_some());
    }

    #[test]
    fn shared_attach_same_session_twice_keeps_refcount_one() {
        let profile_id = ProfileId::new("test-shared").unwrap();
        let session = PrincipalSessionId::new();
        let lease_id = BrowserLeaseId::new();
        let mut attached = std::collections::HashSet::new();
        attached.insert(session.clone());
        let mut lease = SharedBrowserLease {
            lease_id,
            ref_count: 1,
            attached_sessions: attached,
        };
        assert!(!lease.attach(&session));
        lease.sync_ref_count();
        assert_eq!(lease.ref_count, 1);
        assert_eq!(lease.attached_sessions.len(), 1);
        let _ = profile_id;
    }

    #[test]
    fn shared_two_unique_sessions_refcount_two() {
        let session_a = PrincipalSessionId::new();
        let session_b = PrincipalSessionId::new();
        let lease_id = BrowserLeaseId::new();
        let mut lease = SharedBrowserLease {
            lease_id,
            ref_count: 0,
            attached_sessions: std::collections::HashSet::new(),
        };
        assert!(lease.attach(&session_a));
        assert!(lease.attach(&session_b));
        lease.sync_ref_count();
        assert_eq!(lease.ref_count, 2);
    }

    #[test]
    fn shared_detach_one_keeps_other() {
        let profile_id = ProfileId::new("test-shared").unwrap();
        let session_a = PrincipalSessionId::new();
        let session_b = PrincipalSessionId::new();
        let lease_id = BrowserLeaseId::new();
        let mut attached = std::collections::HashSet::new();
        attached.insert(session_a.clone());
        attached.insert(session_b.clone());
        let lease = SharedBrowserLease {
            lease_id: lease_id.clone(),
            ref_count: 2,
            attached_sessions: attached,
        };
        let mut shared: HashMap<ProfileId, SharedBrowserLease> = HashMap::new();
        shared.insert(profile_id.clone(), lease);

        let outcome = detach_session_from_shared(&mut shared, &profile_id, &session_a);
        assert!(matches!(outcome, SharedDetachOutcome::Keep));
        assert!(shared.contains_key(&profile_id));
        assert_eq!(shared.get(&profile_id).unwrap().ref_count, 1);
        assert!(
            shared
                .get(&profile_id)
                .unwrap()
                .attached_sessions
                .contains(&session_b)
        );
    }

    #[test]
    fn shared_detach_unattached_session_unchanged() {
        let profile_id = ProfileId::new("test-shared").unwrap();
        let session_a = PrincipalSessionId::new();
        let session_unattached = PrincipalSessionId::new();
        let lease_id = BrowserLeaseId::new();
        let mut attached = std::collections::HashSet::new();
        attached.insert(session_a.clone());
        let lease = SharedBrowserLease {
            lease_id: lease_id.clone(),
            ref_count: 1,
            attached_sessions: attached,
        };
        let mut shared: HashMap<ProfileId, SharedBrowserLease> = HashMap::new();
        shared.insert(profile_id.clone(), lease);

        let outcome = detach_session_from_shared(&mut shared, &profile_id, &session_unattached);
        assert!(matches!(outcome, SharedDetachOutcome::Keep));
        assert_eq!(shared.get(&profile_id).unwrap().ref_count, 1);
    }

    #[test]
    fn shared_detach_final_triggers_termination() {
        let profile_id = ProfileId::new("test-shared").unwrap();
        let session = PrincipalSessionId::new();
        let lease_id = BrowserLeaseId::new();
        let mut attached = std::collections::HashSet::new();
        attached.insert(session.clone());
        let lease = SharedBrowserLease {
            lease_id: lease_id.clone(),
            ref_count: 1,
            attached_sessions: attached,
        };
        let mut shared: HashMap<ProfileId, SharedBrowserLease> = HashMap::new();
        shared.insert(profile_id.clone(), lease);

        let outcome = detach_session_from_shared(&mut shared, &profile_id, &session);
        assert!(matches!(outcome, SharedDetachOutcome::Terminate(_)));
        assert!(!shared.contains_key(&profile_id));
    }

    #[test]
    fn cleanup_all_deduplicates_shared_lease() {
        let profile_id = ProfileId::new("test-shared").unwrap();
        let lease_id = BrowserLeaseId::new();
        let session_a = PrincipalSessionId::new();
        let session_b = PrincipalSessionId::new();
        let mut attached = std::collections::HashSet::new();
        attached.insert(session_a.clone());
        attached.insert(session_b.clone());
        let mut shared: HashMap<ProfileId, SharedBrowserLease> = HashMap::new();
        shared.insert(
            profile_id.clone(),
            SharedBrowserLease {
                lease_id: lease_id.clone(),
                ref_count: 2,
                attached_sessions: attached,
            },
        );
        let removed = cleanup_all_shared_for_profile(&mut shared, &profile_id);
        assert_eq!(removed, Some(lease_id));
        assert!(!shared.contains_key(&profile_id));
    }

    #[test]
    fn test_shared_browser_stale_exit_cleanup_matches_lease_id() {
        let profile_id = ProfileId::new("test-stale-exit").unwrap();
        let old_lease_id = BrowserLeaseId::new();
        let new_lease_id = BrowserLeaseId::new();

        let mut shared = std::collections::HashMap::new();
        shared.insert(
            profile_id.clone(),
            SharedBrowserLease {
                lease_id: new_lease_id.clone(),
                ref_count: 1,
                attached_sessions: std::collections::HashSet::new(),
            },
        );

        let stale_exit_lease_id = old_lease_id.clone();
        let mut cleared = false;
        if let Some(lease) = shared.get(&profile_id)
            && lease.lease_id == stale_exit_lease_id
        {
            shared.remove(&profile_id);
            cleared = true;
        }

        assert!(!cleared, "stale exit should not remove replacement lease");
        assert!(
            shared.contains_key(&profile_id),
            "replacement lease should survive"
        );
        assert_eq!(shared[&profile_id].lease_id, new_lease_id);
    }

    #[test]
    fn test_shared_browser_stale_exit_cleanup_removes_matching() {
        let profile_id = ProfileId::new("test-stale-match").unwrap();
        let lease_id = BrowserLeaseId::new();

        let mut shared = std::collections::HashMap::new();
        shared.insert(
            profile_id.clone(),
            SharedBrowserLease {
                lease_id: lease_id.clone(),
                ref_count: 1,
                attached_sessions: std::collections::HashSet::new(),
            },
        );

        let exit_lease_id = lease_id.clone();
        let mut cleared = false;
        if let Some(lease) = shared.get(&profile_id)
            && lease.lease_id == exit_lease_id
        {
            shared.remove(&profile_id);
            cleared = true;
        }

        assert!(cleared, "matching lease should be removed on exit");
        assert!(!shared.contains_key(&profile_id));
    }
}
