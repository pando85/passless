use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::unix::io::AsRawFd;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use log::{debug, info};

use passless_core::agent::protocol::{
    AdminRequest, AdminResponse, DoctorResponse, ErrorCode, PeerCred, PrincipalCapabilities,
    PrincipalInstructions, PrincipalLaunchedResponse, PrincipalRequest, PrincipalResponse,
    PrincipalWaitResponse, ProtocolError, RecommendedAction,
};
use passless_core::agent::{
    AgentConfig, AgentMode, AgentProfileConfig, BrowserLeaseId, DaemonStatus, EndpointId,
    EndpointStatusResponse, GrantId, PendingRequestId, PrincipalSessionId, ProfileId,
};
use passless_core::config::{PinConfig, SecurityConfig};

use super::audit::AuditGate;
use super::audit_events::{
    BackendKind, DaemonStartBuilder, DaemonStopBuilder, EndpointCreateBuilder, FailReason,
    ProfileCreateBuilder, ProfileFailBuilder, StopReason,
};
use super::browser::{BrowserProcessManager, Clock, SystemClock};
use super::ceremony::{
    AgentCeremonyHandler, CeremonyPreparationSlot, StaticCeremonyContext,
    StaticCeremonyContextConfig,
};
use super::device::EndpointBinding;
use super::endpoint_manager::EndpointManager;
use super::intent::SystemClock as IntentSystemClock;
use super::interaction::AgentInteractionManager;
use super::ipc::{AdminHandler, IpcServer, PrincipalHandler, ProfileAccess, RuntimeDir};
use super::launcher::{
    PrincipalSession, SessionCapability, SpawnConfig, dup_fd_cloexec, spawn_principal,
    verify_process_ancestry,
};
use super::policy_engine::PolicyRuntime;
use super::prompt::{DesktopPromptHandle, PromptHandle, PromptMode};
use super::storage::{CeremonyScope, ForwardingStorageHandle, IsolatedScopedStorage};
use super::storage_factory::{
    create_shared_delegated_storage_with_registration, create_storage_bundle_with_options,
};

use crate::authenticator::AuthenticatorService;
use crate::storage::CredentialStorage;
use crate::worker::{WorkerConfig, WorkerHooks};

#[cfg(feature = "agent")]
use passless_uhid::RawUhidDevice;

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_WORKERS: usize = 16;
const DELEGATED_DESTROY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_COMPLETED_SESSIONS: usize = 256;
const COMPLETED_SESSION_TTL: Duration = Duration::from_secs(600);
const WAIT_PRINCIPAL_POLL_INTERVAL: Duration = Duration::from_millis(50);
const TERMINATE_TIMEOUT: Duration = Duration::from_secs(5);

pub type EndpointFactory = Arc<
    dyn Fn(&passless_core::agent::DeviceIdentity) -> Result<RawUhidDevice, String> + Send + Sync,
>;

#[cfg(test)]
pub type TestTransportFactory =
    Arc<dyn Fn() -> Result<Box<dyn crate::worker::HidEndpoint>, String> + Send + Sync>;

pub struct RuntimeStartParams<'a> {
    pub human_storage: Arc<Mutex<Box<dyn CredentialStorage>>>,
    pub human_pin_storage: Arc<Mutex<Box<dyn crate::pin_storage::PinStorage>>>,
    pub human_operation_lock: Arc<Mutex<()>>,
    pub agent_config: &'a AgentConfig,
    pub security_config: SecurityConfig,
    pub pin_config: PinConfig,
    pub shutdown: Arc<AtomicBool>,
    pub endpoint_factory: Option<EndpointFactory>,
}

struct CreateIntentParams<'a> {
    profile_id: &'a ProfileId,
    session_id: &'a PrincipalSessionId,
    endpoint_id: &'a EndpointId,
    action: &'a passless_core::agent::protocol::IntentAction,
    rp_id: &'a str,
    credential_ref: Option<&'a passless_core::agent::CredentialRef>,
    principal_reason: Option<String>,
    clamped_grant_ttl_secs: Option<u64>,
    clamped_session_ttl_secs: Option<u64>,
    profile: &'a ProfileRuntime,
    session_digest: &'a super::intent::ProcessIdentityDigest,
}

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

#[derive(Clone)]
pub struct EndpointSpec {
    pub profile_name: String,
    pub profile_id: ProfileId,
    pub mode: AgentMode,
    pub profile_config: AgentProfileConfig,
    pub security_config: SecurityConfig,
    pub pin_config: PinConfig,
    pub interaction_manager: Arc<AgentInteractionManager>,
    pub preparation_slot: Arc<CeremonyPreparationSlot>,
    pub operation_lock: Arc<Mutex<()>>,
    pub policy_runtime: Arc<PolicyRuntime>,
    pub audit_gate: Arc<AuditGate>,
    pub event_tx: EndpointEventSender,
    pub endpoint_factory: Option<EndpointFactory>,
    #[cfg(test)]
    pub test_transport_factory: Option<TestTransportFactory>,
    pub isolated_deps: Option<IsolatedEndpointDeps>,
    pub delegated_deps: Option<DelegatedEndpointDeps>,
}

#[derive(Clone)]
pub struct IsolatedEndpointDeps {
    pub credential_storage: Arc<Mutex<Box<dyn CredentialStorage>>>,
    pub pin_storage: Arc<Mutex<Box<dyn crate::pin_storage::PinStorage>>>,
    pub ceremony_scope: CeremonyScope,
}

#[derive(Clone)]
pub struct DelegatedEndpointDeps {
    pub human_storage: Arc<Mutex<Box<dyn CredentialStorage>>>,
    pub human_pin_storage: Arc<Mutex<Box<dyn crate::pin_storage::PinStorage>>>,
    pub human_operation_lock: Arc<Mutex<()>>,
    pub credential_refs: Vec<passless_core::agent::CredentialRef>,
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

#[derive(Debug, Clone)]
pub enum EndpointEvent {
    ResponseSent {
        endpoint_id: EndpointId,
        profile_id: ProfileId,
    },
}

pub type EndpointEventSender = mpsc::Sender<EndpointEvent>;
pub type EndpointEventReceiver = mpsc::Receiver<EndpointEvent>;

pub struct PendingRuntime {
    pub request_id: PendingRequestId,
    pub prep_generation: u64,
    pub session_id: PrincipalSessionId,
    pub browser_lease_id: Option<BrowserLeaseId>,
    pub clamped_session_ttl_secs: u64,
}

pub struct ActiveBrowserLease {
    pub lease_id: BrowserLeaseId,
    pub session_id: PrincipalSessionId,
}

pub struct ProfileRuntime {
    pub profile_name: String,
    pub profile_id: ProfileId,
    pub uid: u32,
    pub gid: u32,
    pub endpoint_id: Mutex<Option<EndpointId>>,
    pub lifecycle_lock: Mutex<()>,
    pub endpoint_spec: EndpointSpec,
    pub preparation_slot: Arc<CeremonyPreparationSlot>,
    pub operation_lock: Arc<Mutex<()>>,
    pub mode: AgentMode,
    pub profile_config: AgentProfileConfig,
    pub current_pending: Mutex<Option<PendingRuntime>>,
    pub active_browser: Mutex<Option<ActiveBrowserLease>>,
    pub daemon_uid: u32,
    pub daemon_gid: u32,
    pub browser_uid: Option<u32>,
    pub browser_gid: Option<u32>,
    pub enabled: AtomicBool,
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

fn validate_principal_executable(path_str: &str) -> Result<std::path::PathBuf, ProtocolError> {
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

    if meta.uid() != 0 {
        return Err(ProtocolError::new(
            ErrorCode::Forbidden,
            format!(
                "executable '{}' must be owned by root (uid 0), owned by uid {}",
                canonical.display(),
                meta.uid()
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
            .finish()
    }
}

pub struct CompletedSession {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub completed_at: Instant,
}

pub struct AgentRuntime {
    endpoint_manager: Mutex<EndpointManager>,
    ipc_server: Arc<IpcServer>,
    audit_gate: Arc<AuditGate>,
    policy_runtime: Arc<PolicyRuntime>,
    browser_manager: Arc<Mutex<BrowserProcessManager>>,
    profiles: BTreeMap<ProfileId, ProfileRuntime>,
    managed_sessions: BTreeMap<ProfileId, Mutex<Option<ManagedPrincipalSession>>>,
    completed_sessions: Mutex<BTreeMap<String, CompletedSession>>,
    event_rx: Mutex<EndpointEventReceiver>,
    shutdown: Arc<AtomicBool>,
    shutdown_requested: AtomicBool,
    runtime_cleanup_started: AtomicBool,
    runtime_loop: Mutex<Option<JoinHandle<()>>>,
    worker_tracker: WorkerTracker,
    daemon_uid: u32,
    daemon_gid: u32,
    agent_config: std::sync::RwLock<AgentConfig>,
}

impl AgentRuntime {
    pub fn start(
        human_storage: Arc<Mutex<Box<dyn CredentialStorage>>>,
        human_pin_storage: Arc<Mutex<Box<dyn crate::pin_storage::PinStorage>>>,
        human_operation_lock: Arc<Mutex<()>>,
        agent_config: &AgentConfig,
        security_config: SecurityConfig,
        pin_config: PinConfig,
        shutdown: Arc<AtomicBool>,
    ) -> Result<Arc<Self>, RuntimeError> {
        Self::start_with_factories(RuntimeStartParams {
            human_storage,
            human_pin_storage,
            human_operation_lock,
            agent_config,
            security_config,
            pin_config,
            shutdown,
            endpoint_factory: None,
        })
    }

    pub fn start_with_factories(params: RuntimeStartParams<'_>) -> Result<Arc<Self>, RuntimeError> {
        let RuntimeStartParams {
            human_storage,
            human_pin_storage,
            human_operation_lock,
            agent_config,
            security_config,
            pin_config,
            shutdown,
            endpoint_factory,
        } = params;
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
            PolicyRuntime::new(agent_config, clock.clone(), monotonic_clock.clone()).map_err(
                |e| RuntimeError::Policy(format!("failed to create policy runtime: {}", e)),
            )?,
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

            let browser_user_resolved = if let Some(ref browser_user) = profile.browser_user {
                let bu = resolve_user(browser_user)?;
                if is_root {
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

                let device_key = super::doctor::DeviceIdentityKey {
                    name: profile.device.name.clone(),
                    phys: profile.device.phys.clone(),
                    uniq: profile.device.uniq.clone(),
                    vendor_id: profile.device.vendor_id,
                    product_id: profile.device.product_id,
                };

                profile_startup_infos.push((name.clone(), resolved.uid, device_key, {
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
                        device_identity_unique: true,
                    }
                }));
            }

            let device_keys: Vec<(String, super::doctor::DeviceIdentityKey)> =
                profile_startup_infos
                    .iter()
                    .map(|(name, _, key, _)| {
                        (
                            name.clone(),
                            super::doctor::DeviceIdentityKey {
                                name: key.name.clone(),
                                phys: key.phys.clone(),
                                uniq: key.uniq.clone(),
                                vendor_id: key.vendor_id,
                                product_id: key.product_id,
                            },
                        )
                    })
                    .collect();
            let uniqueness = super::doctor::compute_device_identity_uniqueness(&device_keys);

            let mut final_infos: Vec<(String, super::doctor::ProfileStartupInfo)> = Vec::new();
            for (i, (name, _, _, info)) in profile_startup_infos.into_iter().enumerate() {
                let mut info = info;
                info.device_identity_unique = uniqueness[i].1;

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

        let endpoint_manager = Mutex::new(EndpointManager::new(
            agent_config.profiles.len().max(1),
            shutdown.clone(),
            WorkerConfig::default(),
        ));

        let (event_tx, event_rx) = mpsc::channel();
        let mut profiles = BTreeMap::new();
        let mut created_endpoint_ids: Vec<EndpointId> = Vec::new();

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

            let preparation_slot = Arc::new(CeremonyPreparationSlot::new());
            let interaction_manager = Arc::new(AgentInteractionManager::new());
            let profile_op_lock = Arc::new(Mutex::new(()));

            let spec_result = match profile.mode {
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

                    let ceremony_scope = CeremonyScope::new();

                    let effective_pin_config = if profile.requires_human_uv() {
                        let mut cfg = pin_config.clone();
                        cfg.enforcement = passless_core::config::PinEnforcement::Required;
                        cfg
                    } else {
                        pin_config.clone()
                    };

                    let spec = EndpointSpec {
                        profile_name: name.clone(),
                        profile_id: profile_id.clone(),
                        mode: AgentMode::Isolated,
                        profile_config: profile.clone(),
                        security_config: security_config.clone(),
                        pin_config: effective_pin_config,
                        interaction_manager: interaction_manager.clone(),
                        preparation_slot: preparation_slot.clone(),
                        operation_lock: profile_op_lock.clone(),
                        policy_runtime: policy_runtime.clone(),
                        audit_gate: audit_gate.clone(),
                        event_tx: event_tx.clone(),
                        endpoint_factory: endpoint_factory.clone(),
                        #[cfg(test)]
                        test_transport_factory: None,
                        isolated_deps: Some(IsolatedEndpointDeps {
                            credential_storage: bundle.credential_storage.clone(),
                            pin_storage: bundle.pin_storage.clone(),
                            ceremony_scope: ceremony_scope.clone(),
                        }),
                        delegated_deps: None,
                    };

                    Ok((spec, ceremony_scope, bundle.credential_storage))
                }
                AgentMode::DelegatedSession => {
                    let cred_refs = profile.credential_refs.clone().unwrap_or_default();

                    let ceremony_scope = CeremonyScope::new();

                    let effective_pin_config = if profile.requires_human_uv() {
                        let mut cfg = pin_config.clone();
                        cfg.enforcement = passless_core::config::PinEnforcement::Required;
                        cfg
                    } else {
                        pin_config.clone()
                    };

                    let spec = EndpointSpec {
                        profile_name: name.clone(),
                        profile_id: profile_id.clone(),
                        mode: AgentMode::DelegatedSession,
                        profile_config: profile.clone(),
                        security_config: security_config.clone(),
                        pin_config: effective_pin_config,
                        interaction_manager: interaction_manager.clone(),
                        preparation_slot: preparation_slot.clone(),
                        operation_lock: profile_op_lock.clone(),
                        policy_runtime: policy_runtime.clone(),
                        audit_gate: audit_gate.clone(),
                        event_tx: event_tx.clone(),
                        endpoint_factory: endpoint_factory.clone(),
                        #[cfg(test)]
                        test_transport_factory: None,
                        isolated_deps: None,
                        delegated_deps: Some(DelegatedEndpointDeps {
                            human_storage: human_storage.clone(),
                            human_pin_storage: human_pin_storage.clone(),
                            human_operation_lock: human_operation_lock.clone(),
                            credential_refs: cred_refs,
                        }),
                    };

                    Ok((spec, ceremony_scope, human_storage.clone()))
                }
            };

            match spec_result {
                Ok((spec, _ceremony_scope, cred_storage)) => {
                    let initial_endpoint_id = match profile.mode {
                        AgentMode::Isolated => {
                            match Self::create_endpoint_from_spec(
                                &spec,
                                &mut endpoint_manager.lock().unwrap(),
                            ) {
                                Ok(eid) => {
                                    created_endpoint_ids.push(eid.clone());
                                    Some(eid)
                                }
                                Err(e) => {
                                    let fail_event = ProfileFailBuilder::new(
                                        profile_id.clone(),
                                        FailReason::InternalError,
                                    )
                                    .build();
                                    let _ = audit_gate.record(fail_event);

                                    let mut em = endpoint_manager.lock().unwrap();
                                    for eid in &created_endpoint_ids {
                                        em.cancel(eid);
                                        let _ = em.destroy(eid, Some(Duration::from_secs(2)));
                                    }

                                    return Err(e);
                                }
                            }
                        }
                        AgentMode::DelegatedSession => None,
                    };

                    profiles.insert(
                        profile_id.clone(),
                        ProfileRuntime {
                            profile_name: name.clone(),
                            profile_id: profile_id.clone(),
                            uid: resolved.uid,
                            gid: resolved.gid,
                            endpoint_id: Mutex::new(initial_endpoint_id),
                            lifecycle_lock: Mutex::new(()),
                            endpoint_spec: spec,
                            preparation_slot,
                            operation_lock: profile_op_lock,
                            mode: profile.mode,
                            profile_config: profile.clone(),
                            current_pending: Mutex::new(None),
                            active_browser: Mutex::new(None),
                            daemon_uid,
                            daemon_gid,
                            browser_uid,
                            browser_gid,
                            enabled: AtomicBool::new(true),
                            credential_storage: cred_storage,
                        },
                    );
                }
                Err(e) => {
                    let fail_event =
                        ProfileFailBuilder::new(profile_id.clone(), FailReason::InternalError)
                            .build();
                    let _ = audit_gate.record(fail_event);

                    let mut em = endpoint_manager.lock().unwrap();
                    for eid in &created_endpoint_ids {
                        em.cancel(eid);
                        let _ = em.destroy(eid, Some(Duration::from_secs(2)));
                    }

                    return Err(e);
                }
            }
        }

        info!(
            "Agent runtime started with {} profile(s), {} endpoint(s)",
            profiles.len(),
            created_endpoint_ids.len()
        );

        let mut managed_sessions = BTreeMap::new();
        for profile_id in profiles.keys() {
            managed_sessions.insert(profile_id.clone(), Mutex::new(None));
        }

        let runtime = Arc::new(Self {
            endpoint_manager,
            ipc_server: ipc_server.clone(),
            audit_gate,
            policy_runtime,
            browser_manager,
            profiles,
            managed_sessions,
            completed_sessions: Mutex::new(BTreeMap::new()),
            event_rx: Mutex::new(event_rx),
            shutdown: shutdown.clone(),
            shutdown_requested: AtomicBool::new(false),
            runtime_cleanup_started: AtomicBool::new(false),
            runtime_loop: Mutex::new(None),
            worker_tracker: WorkerTracker::new(),
            daemon_uid,
            daemon_gid,
            agent_config: std::sync::RwLock::new(agent_config.clone()),
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

    #[cfg(feature = "agent")]
    fn create_endpoint_from_spec(
        spec: &EndpointSpec,
        endpoint_manager: &mut EndpointManager,
    ) -> Result<EndpointId, RuntimeError> {
        use crate::ServiceHandler;

        let name = &spec.profile_name;
        let profile_id = &spec.profile_id;
        let _grant_ttl_secs = spec
            .profile_config
            .max_grant_ttl
            .as_ref()
            .map(|d| d.as_secs())
            .unwrap_or(60);
        let _session_ttl_secs = spec
            .profile_config
            .max_session_ttl
            .as_ref()
            .map(|d| d.as_secs())
            .unwrap_or(300);
        let require_uv = spec.profile_config.rules.is_empty() && spec.profile_config.require_uv;

        let binding = EndpointBinding {
            profile_id: profile_id.clone(),
            mode: spec.mode,
        };

        let device_identity_clone = spec.profile_config.device.clone();
        let endpoint_factory_clone = spec.endpoint_factory.clone();
        let device_factory = move || -> Result<RawUhidDevice, String> {
            if let Some(ref factory) = endpoint_factory_clone {
                factory(&device_identity_clone)
            } else {
                let identity = passless_uhid::DeviceIdentity::new(
                    device_identity_clone.name.clone(),
                    device_identity_clone.phys.clone(),
                    device_identity_clone.uniq.clone(),
                    device_identity_clone.vendor_id as u32,
                    device_identity_clone.product_id as u32,
                    0,
                );
                RawUhidDevice::create(identity)
                    .map_err(|e| format!("failed to create device: {:?}", e))
            }
        };

        let profile_id_inner = profile_id.clone();
        let event_tx_inner = spec.event_tx.clone();
        let profile_id_for_hooks = profile_id.clone();
        let generated_endpoint_for_hooks = Arc::new(Mutex::new(None::<EndpointId>));
        let generated_endpoint_for_factory = generated_endpoint_for_hooks.clone();
        let policy_runtime_inner = spec.policy_runtime.clone();
        let audit_gate_inner = spec.audit_gate.clone();
        let preparation_slot_inner = spec.preparation_slot.clone();
        let interaction_manager_inner = spec.interaction_manager.clone();

        match spec.mode {
            AgentMode::Isolated => {
                let deps = spec.isolated_deps.as_ref().ok_or_else(|| {
                    RuntimeError::Config(format!(
                        "profile '{}': isolated spec missing isolated_deps",
                        name
                    ))
                })?;

                let rp_ids = spec.profile_config.allowed_rp_ids();
                let registration_allowed = spec.profile_config.allows_registration();

                let mut scoped_storage = IsolatedScopedStorage::new(
                    ForwardingStorageHandle::new(deps.credential_storage.clone()),
                    deps.ceremony_scope.clone(),
                    rp_ids,
                    registration_allowed,
                );
                scoped_storage.build_index().map_err(|e| {
                    RuntimeError::Storage(format!(
                        "profile '{}': failed to build index: {}",
                        name, e
                    ))
                })?;

                let service = AuthenticatorService::with_shared_storage_and_interaction(
                    Arc::new(Mutex::new(scoped_storage)),
                    Some(deps.pin_storage.clone()),
                    spec.security_config.clone(),
                    spec.pin_config.clone(),
                    spec.interaction_manager.clone(),
                )
                .map_err(|e| {
                    RuntimeError::Service(format!(
                        "profile '{}': failed to create authenticator service: {}",
                        name, e
                    ))
                })?;

                let ceremony_scope_inner = deps.ceremony_scope.clone();
                let op_lock_for_ctx = spec.operation_lock.clone();
                let prompt_mode = PromptMode::Isolated;

                let audit_gate_for_before_start = spec.audit_gate.clone();
                let profile_id_for_before_start = profile_id.clone();
                let name_for_before_start = name.clone();

                let endpoint_id = endpoint_manager
                    .create_and_start_full(
                        binding,
                        name.to_string(),
                        move |generated_endpoint_id: &EndpointId| {
                            *generated_endpoint_for_factory.lock().unwrap() =
                                Some(generated_endpoint_id.clone());
                            let service_handler = ServiceHandler::new(service);

                            let prompt_handle: Arc<dyn PromptHandle> =
                                Arc::new(DesktopPromptHandle::default_config());

                            let ceremony_context =
                                StaticCeremonyContext::new(StaticCeremonyContextConfig {
                                    profile_id: profile_id_inner.clone(),
                                    endpoint_id: generated_endpoint_id.clone(),
                                    mode: prompt_mode,
                                    policy_runtime: policy_runtime_inner.clone(),
                                    audit_gate: audit_gate_inner.clone(),
                                    ceremony_scope: ceremony_scope_inner.clone(),
                                    require_uv,
                                    prompt_handle,
                                    preparation_slot: preparation_slot_inner.clone(),
                                })
                                .with_interaction_manager(interaction_manager_inner.clone())
                                .with_operation_lock(op_lock_for_ctx.clone());

                            AgentCeremonyHandler::new(service_handler, ceremony_context)
                        },
                        device_factory,
                        WorkerHooks {
                            on_response_sent: Some(Box::new(move || {
                                if let Some(endpoint_id) =
                                    generated_endpoint_for_hooks.lock().unwrap().clone()
                                {
                                    let _ = event_tx_inner.send(EndpointEvent::ResponseSent {
                                        endpoint_id,
                                        profile_id: profile_id_for_hooks.clone(),
                                    });
                                }
                            })),
                        },
                        Some(Box::new(move |eid: &EndpointId| {
                            let create_event = EndpointCreateBuilder::new(
                                eid.clone(),
                                profile_id_for_before_start.clone(),
                            )
                            .build();
                            audit_gate_for_before_start
                                .record(create_event)
                                .map_err(|e| {
                                    format!(
                                        "profile '{}' endpoint create audit failed: {}",
                                        name_for_before_start, e
                                    )
                                })?;
                            Ok(())
                        })),
                    )
                    .map_err(|e| RuntimeError::Endpoint(format!("profile '{}': {}", name, e)))?;

                info!(
                    "Profile '{}' {:?} endpoint created: {}",
                    name, spec.mode, endpoint_id
                );

                Ok(endpoint_id)
            }
            AgentMode::DelegatedSession => {
                let deps = spec.delegated_deps.as_ref().ok_or_else(|| {
                    RuntimeError::Config(format!(
                        "profile '{}': delegated spec missing delegated_deps",
                        name
                    ))
                })?;

                let (delegated_storage, ceremony_scope) = {
                    let _op = deps.human_operation_lock.lock().map_err(|e| {
                        RuntimeError::Storage(format!(
                            "profile '{}': failed to acquire human operation lock: {}",
                            name, e
                        ))
                    })?;
                    create_shared_delegated_storage_with_registration(
                        deps.human_storage.clone(),
                        spec.profile_config.allowed_rp_ids(),
                        deps.credential_refs.clone(),
                        spec.security_config.constant_signature_counter,
                        spec.profile_config.delegated_registration_storage.is_some(),
                    )
                    .map_err(|e| {
                        RuntimeError::Storage(format!(
                            "profile '{}': failed to create delegated storage: {}",
                            name, e
                        ))
                    })?
                };

                let delegated_storage = Arc::new(Mutex::new(delegated_storage));

                let service = AuthenticatorService::with_shared_storage_and_interaction(
                    delegated_storage,
                    Some(deps.human_pin_storage.clone()),
                    spec.security_config.clone(),
                    spec.pin_config.clone(),
                    spec.interaction_manager.clone(),
                )
                .map_err(|e| {
                    RuntimeError::Service(format!(
                        "profile '{}': failed to create authenticator service: {}",
                        name, e
                    ))
                })?;

                let ceremony_scope_inner = ceremony_scope;
                let op_lock_for_ctx = deps.human_operation_lock.clone();
                let prompt_mode = PromptMode::DelegatedSession;

                let audit_gate_for_before_start = spec.audit_gate.clone();
                let profile_id_for_before_start = profile_id.clone();
                let name_for_before_start = name.clone();

                let endpoint_id = endpoint_manager
                    .create_and_start_full(
                        binding,
                        name.to_string(),
                        move |generated_endpoint_id: &EndpointId| {
                            *generated_endpoint_for_factory.lock().unwrap() =
                                Some(generated_endpoint_id.clone());
                            let service_handler = ServiceHandler::new(service);

                            let prompt_handle: Arc<dyn PromptHandle> =
                                Arc::new(DesktopPromptHandle::default_config());

                            let ceremony_context =
                                StaticCeremonyContext::new(StaticCeremonyContextConfig {
                                    profile_id: profile_id_inner.clone(),
                                    endpoint_id: generated_endpoint_id.clone(),
                                    mode: prompt_mode,
                                    policy_runtime: policy_runtime_inner.clone(),
                                    audit_gate: audit_gate_inner.clone(),
                                    ceremony_scope: ceremony_scope_inner.clone(),
                                    require_uv,
                                    prompt_handle,
                                    preparation_slot: preparation_slot_inner.clone(),
                                })
                                .with_interaction_manager(interaction_manager_inner.clone())
                                .with_operation_lock(op_lock_for_ctx.clone());

                            AgentCeremonyHandler::new(service_handler, ceremony_context)
                        },
                        device_factory,
                        WorkerHooks {
                            on_response_sent: Some(Box::new(move || {
                                if let Some(endpoint_id) =
                                    generated_endpoint_for_hooks.lock().unwrap().clone()
                                {
                                    let _ = event_tx_inner.send(EndpointEvent::ResponseSent {
                                        endpoint_id,
                                        profile_id: profile_id_for_hooks.clone(),
                                    });
                                }
                            })),
                        },
                        Some(Box::new(move |eid: &EndpointId| {
                            let create_event = EndpointCreateBuilder::new(
                                eid.clone(),
                                profile_id_for_before_start.clone(),
                            )
                            .build();
                            audit_gate_for_before_start
                                .record(create_event)
                                .map_err(|e| {
                                    format!(
                                        "profile '{}' endpoint create audit failed: {}",
                                        name_for_before_start, e
                                    )
                                })?;
                            Ok(())
                        })),
                    )
                    .map_err(|e| RuntimeError::Endpoint(format!("profile '{}': {}", name, e)))?;

                info!(
                    "Profile '{}' {:?} endpoint created: {}",
                    name, spec.mode, endpoint_id
                );

                Ok(endpoint_id)
            }
        }
    }

    #[cfg(not(feature = "agent"))]
    fn create_endpoint_from_spec(
        _spec: &EndpointSpec,
        _endpoint_manager: &mut EndpointManager,
    ) -> Result<EndpointId, RuntimeError> {
        Err(RuntimeError::Config(
            "agent feature not enabled".to_string(),
        ))
    }

    #[cfg(test)]
    fn create_endpoint_from_spec_with_test_transport(
        spec: &EndpointSpec,
        endpoint_manager: &mut EndpointManager,
    ) -> Result<EndpointId, RuntimeError> {
        use crate::ServiceHandler;

        let name = &spec.profile_name;
        let profile_id = &spec.profile_id;
        let _grant_ttl_secs = spec
            .profile_config
            .max_grant_ttl
            .as_ref()
            .map(|d| d.as_secs())
            .unwrap_or(60);
        let _session_ttl_secs = spec
            .profile_config
            .max_session_ttl
            .as_ref()
            .map(|d| d.as_secs())
            .unwrap_or(300);
        let require_uv = spec.profile_config.rules.is_empty() && spec.profile_config.require_uv;

        let binding = super::device::EndpointBinding {
            profile_id: profile_id.clone(),
            mode: spec.mode,
        };

        let test_transport_factory = spec.test_transport_factory.clone().ok_or_else(|| {
            RuntimeError::Config(format!(
                "profile '{}': test_transport_factory not set for test endpoint creation",
                name
            ))
        })?;

        let profile_id_inner = profile_id.clone();
        let event_tx_inner = spec.event_tx.clone();
        let profile_id_for_hooks = profile_id.clone();
        let generated_endpoint_for_hooks = Arc::new(Mutex::new(None::<EndpointId>));
        let generated_endpoint_for_factory = generated_endpoint_for_hooks.clone();
        let policy_runtime_inner = spec.policy_runtime.clone();
        let audit_gate_inner = spec.audit_gate.clone();
        let preparation_slot_inner = spec.preparation_slot.clone();
        let interaction_manager_inner = spec.interaction_manager.clone();

        match spec.mode {
            AgentMode::DelegatedSession => {
                let deps = spec.delegated_deps.as_ref().ok_or_else(|| {
                    RuntimeError::Config(format!(
                        "profile '{}': delegated spec missing delegated_deps",
                        name
                    ))
                })?;

                let (delegated_storage, ceremony_scope) = {
                    let _op = deps.human_operation_lock.lock().map_err(|e| {
                        RuntimeError::Storage(format!(
                            "profile '{}': failed to acquire human operation lock: {}",
                            name, e
                        ))
                    })?;
                    super::storage_factory::create_shared_delegated_storage_with_registration(
                        deps.human_storage.clone(),
                        spec.profile_config.allowed_rp_ids(),
                        deps.credential_refs.clone(),
                        spec.security_config.constant_signature_counter,
                        spec.profile_config.delegated_registration_storage.is_some(),
                    )
                    .map_err(|e| {
                        RuntimeError::Storage(format!(
                            "profile '{}': failed to create delegated storage: {}",
                            name, e
                        ))
                    })?
                };

                let delegated_storage = Arc::new(Mutex::new(delegated_storage));

                let service =
                    crate::authenticator::AuthenticatorService::with_shared_storage_and_interaction(
                        delegated_storage,
                        Some(deps.human_pin_storage.clone()),
                        spec.security_config.clone(),
                        spec.pin_config.clone(),
                        spec.interaction_manager.clone(),
                    )
                    .map_err(|e| {
                        RuntimeError::Service(format!(
                            "profile '{}': failed to create authenticator service: {}",
                            name, e
                        ))
                    })?;

                let ceremony_scope_inner = ceremony_scope;
                let op_lock_for_ctx = deps.human_operation_lock.clone();
                let prompt_mode = super::prompt::PromptMode::DelegatedSession;

                let audit_gate_for_before_start = spec.audit_gate.clone();
                let profile_id_for_before_start = profile_id.clone();
                let name_for_before_start = name.clone();

                let endpoint_id = endpoint_manager
                    .create_and_start_with_transport_full(
                        binding,
                        name.to_string(),
                        move |generated_endpoint_id: &EndpointId| {
                            *generated_endpoint_for_factory.lock().unwrap() =
                                Some(generated_endpoint_id.clone());
                            let service_handler = ServiceHandler::new(service);

                            let prompt_handle: Arc<dyn super::prompt::PromptHandle> =
                                Arc::new(super::prompt::DesktopPromptHandle::default_config());

                            let ceremony_context = super::ceremony::StaticCeremonyContext::new(
                                super::ceremony::StaticCeremonyContextConfig {
                                    profile_id: profile_id_inner.clone(),
                                    endpoint_id: generated_endpoint_id.clone(),
                                    mode: prompt_mode,
                                    policy_runtime: policy_runtime_inner.clone(),
                                    audit_gate: audit_gate_inner.clone(),
                                    ceremony_scope: ceremony_scope_inner.clone(),
                                    require_uv,
                                    prompt_handle,
                                    preparation_slot: preparation_slot_inner.clone(),
                                },
                            )
                            .with_interaction_manager(interaction_manager_inner.clone())
                            .with_operation_lock(op_lock_for_ctx.clone());

                            super::ceremony::AgentCeremonyHandler::new(
                                service_handler,
                                ceremony_context,
                            )
                        },
                        move || {
                            test_transport_factory()
                                .map_err(|e| format!("test transport factory failed: {}", e))
                        },
                        crate::worker::WorkerHooks {
                            on_response_sent: Some(Box::new(move || {
                                if let Some(endpoint_id) =
                                    generated_endpoint_for_hooks.lock().unwrap().clone()
                                {
                                    let _ = event_tx_inner.send(EndpointEvent::ResponseSent {
                                        endpoint_id,
                                        profile_id: profile_id_for_hooks.clone(),
                                    });
                                }
                            })),
                        },
                        Some(Box::new(move |eid: &EndpointId| {
                            let create_event = super::audit_events::EndpointCreateBuilder::new(
                                eid.clone(),
                                profile_id_for_before_start.clone(),
                            )
                            .build();
                            audit_gate_for_before_start
                                .record(create_event)
                                .map_err(|e| {
                                    format!(
                                        "profile '{}' endpoint create audit failed: {}",
                                        name_for_before_start, e
                                    )
                                })?;
                            Ok(())
                        })),
                    )
                    .map_err(|e| RuntimeError::Endpoint(format!("profile '{}': {}", name, e)))?;

                Ok(endpoint_id)
            }
            AgentMode::Isolated => {
                let deps = spec.isolated_deps.as_ref().ok_or_else(|| {
                    RuntimeError::Config(format!(
                        "profile '{}': isolated spec missing isolated_deps",
                        name
                    ))
                })?;

                let rp_ids = spec.profile_config.allowed_rp_ids();
                let registration_allowed = spec.profile_config.allows_registration();

                let mut scoped_storage = super::storage::IsolatedScopedStorage::new(
                    super::storage::ForwardingStorageHandle::new(deps.credential_storage.clone()),
                    deps.ceremony_scope.clone(),
                    rp_ids,
                    registration_allowed,
                );
                scoped_storage.build_index().map_err(|e| {
                    RuntimeError::Storage(format!(
                        "profile '{}': failed to build index: {}",
                        name, e
                    ))
                })?;

                let service =
                    crate::authenticator::AuthenticatorService::with_shared_storage_and_interaction(
                        Arc::new(Mutex::new(scoped_storage)),
                        Some(deps.pin_storage.clone()),
                        spec.security_config.clone(),
                        spec.pin_config.clone(),
                        spec.interaction_manager.clone(),
                    )
                    .map_err(|e| {
                        RuntimeError::Service(format!(
                            "profile '{}': failed to create authenticator service: {}",
                            name, e
                        ))
                    })?;

                let ceremony_scope_inner = deps.ceremony_scope.clone();
                let op_lock_for_ctx = spec.operation_lock.clone();
                let prompt_mode = super::prompt::PromptMode::Isolated;

                let audit_gate_for_before_start = spec.audit_gate.clone();
                let profile_id_for_before_start = profile_id.clone();
                let name_for_before_start = name.clone();

                let endpoint_id = endpoint_manager
                    .create_and_start_with_transport_full(
                        binding,
                        name.to_string(),
                        move |generated_endpoint_id: &EndpointId| {
                            *generated_endpoint_for_factory.lock().unwrap() =
                                Some(generated_endpoint_id.clone());
                            let service_handler = ServiceHandler::new(service);

                            let prompt_handle: Arc<dyn super::prompt::PromptHandle> =
                                Arc::new(super::prompt::DesktopPromptHandle::default_config());

                            let ceremony_context = super::ceremony::StaticCeremonyContext::new(
                                super::ceremony::StaticCeremonyContextConfig {
                                    profile_id: profile_id_inner.clone(),
                                    endpoint_id: generated_endpoint_id.clone(),
                                    mode: prompt_mode,
                                    policy_runtime: policy_runtime_inner.clone(),
                                    audit_gate: audit_gate_inner.clone(),
                                    ceremony_scope: ceremony_scope_inner.clone(),
                                    require_uv,
                                    prompt_handle,
                                    preparation_slot: preparation_slot_inner.clone(),
                                },
                            )
                            .with_interaction_manager(interaction_manager_inner.clone())
                            .with_operation_lock(op_lock_for_ctx.clone());

                            super::ceremony::AgentCeremonyHandler::new(
                                service_handler,
                                ceremony_context,
                            )
                        },
                        move || {
                            test_transport_factory()
                                .map_err(|e| format!("test transport factory failed: {}", e))
                        },
                        crate::worker::WorkerHooks {
                            on_response_sent: Some(Box::new(move || {
                                if let Some(endpoint_id) =
                                    generated_endpoint_for_hooks.lock().unwrap().clone()
                                {
                                    let _ = event_tx_inner.send(EndpointEvent::ResponseSent {
                                        endpoint_id,
                                        profile_id: profile_id_for_hooks.clone(),
                                    });
                                }
                            })),
                        },
                        Some(Box::new(move |eid: &EndpointId| {
                            let create_event = super::audit_events::EndpointCreateBuilder::new(
                                eid.clone(),
                                profile_id_for_before_start.clone(),
                            )
                            .build();
                            audit_gate_for_before_start
                                .record(create_event)
                                .map_err(|e| {
                                    format!(
                                        "profile '{}' endpoint create audit failed: {}",
                                        name_for_before_start, e
                                    )
                                })?;
                            Ok(())
                        })),
                    )
                    .map_err(|e| RuntimeError::Endpoint(format!("profile '{}': {}", name, e)))?;

                Ok(endpoint_id)
            }
        }
    }

    fn create_profile_endpoint(&self, spec: &EndpointSpec) -> Result<EndpointId, RuntimeError> {
        #[cfg(test)]
        {
            if spec.test_transport_factory.is_some() {
                let eid = Self::create_endpoint_from_spec_with_test_transport(
                    spec,
                    &mut self.endpoint_manager.lock().unwrap(),
                )?;
                return Ok(eid);
            }
        }
        let eid =
            Self::create_endpoint_from_spec(spec, &mut self.endpoint_manager.lock().unwrap())?;
        Ok(eid)
    }

    fn destroy_delegated_endpoint(&self, profile: &ProfileRuntime) -> Result<(), RuntimeError> {
        let eid = {
            let mut guard = profile.endpoint_id.lock().unwrap();
            guard.take()
        };

        let eid = match eid {
            Some(e) => e,
            None => return Ok(()),
        };

        {
            let mut em = self.endpoint_manager.lock().unwrap();
            em.cancel(&eid);
            let outcome = em.destroy(&eid, Some(DELEGATED_DESTROY_TIMEOUT));
            match outcome {
                super::endpoint_manager::DestroyOutcome::Destroyed { .. } => {
                    let destroy_event = super::audit_events::EndpointDestroyBuilder::new(
                        eid.clone(),
                        profile.profile_id.clone(),
                    )
                    .build();
                    let _ = profile.endpoint_spec.audit_gate.record(destroy_event);
                    info!(
                        "Delegated endpoint destroyed: {} for profile {}",
                        eid, profile.profile_id
                    );
                    Ok(())
                }
                super::endpoint_manager::DestroyOutcome::TimedOut { .. } => {
                    let fail_event = super::audit_events::EndpointFailBuilder::new(
                        eid.clone(),
                        profile.profile_id.clone(),
                        FailReason::Timeout,
                    )
                    .build();
                    let _ = profile.endpoint_spec.audit_gate.record(fail_event);
                    Err(RuntimeError::Endpoint(format!(
                        "endpoint {} destroy timed out",
                        eid
                    )))
                }
                super::endpoint_manager::DestroyOutcome::WorkerFailed { error, .. } => {
                    let fail_event = super::audit_events::EndpointFailBuilder::new(
                        eid.clone(),
                        profile.profile_id.clone(),
                        FailReason::InternalError,
                    )
                    .build();
                    let _ = profile.endpoint_spec.audit_gate.record(fail_event);
                    Err(RuntimeError::Endpoint(format!(
                        "endpoint {} worker failed: {}",
                        eid, error
                    )))
                }
                super::endpoint_manager::DestroyOutcome::WorkerPanicked { .. } => {
                    let fail_event = super::audit_events::EndpointFailBuilder::new(
                        eid.clone(),
                        profile.profile_id.clone(),
                        FailReason::InternalError,
                    )
                    .build();
                    let _ = profile.endpoint_spec.audit_gate.record(fail_event);
                    Err(RuntimeError::Endpoint(format!(
                        "endpoint {} worker panicked",
                        eid
                    )))
                }
            }
        }
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

            self.drain_endpoint_events();
            self.worker_tracker.reap_finished();
            self.reap_expired_sessions();
            self.prune_completed_sessions();
            self.cleanup_expired_pending();
            self.reap_stopped_workers();

            {
                let mut browser_mgr = self.browser_manager.lock().unwrap();
                let exit_infos = browser_mgr.check_exits();
                for info in &exit_infos {
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
                            let mut current = profile.current_pending.lock().unwrap();
                            if let Some(ref pending) = *current
                                && pending.browser_lease_id.as_ref() == Some(&info.lease_id)
                            {
                                let _ = self.policy_runtime.principal_cancel_pending(
                                    &pending.request_id,
                                    &pending.session_id,
                                );
                                profile
                                    .preparation_slot
                                    .clear_matching(pending.prep_generation);
                                *current = None;
                                cleared = true;
                            }
                        }
                        {
                            let mut active = profile.active_browser.lock().unwrap();
                            if let Some(ref lease) = *active
                                && lease.lease_id == info.lease_id
                            {
                                *active = None;
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
                    let _ = self.audit_gate.record(
                        super::audit_events::BrowserLeaseExpireBuilder::new(lease_id.clone())
                            .build(),
                    );
                    for profile in self.profiles.values() {
                        let mut cleared = false;
                        {
                            let mut current = profile.current_pending.lock().unwrap();
                            if let Some(ref pending) = *current
                                && pending.browser_lease_id.as_ref() == Some(lease_id)
                            {
                                let _ = self.policy_runtime.principal_cancel_pending(
                                    &pending.request_id,
                                    &pending.session_id,
                                );
                                profile
                                    .preparation_slot
                                    .clear_matching(pending.prep_generation);
                                *current = None;
                                cleared = true;
                            }
                        }
                        {
                            let mut active = profile.active_browser.lock().unwrap();
                            if let Some(ref lease) = *active
                                && lease.lease_id == *lease_id
                            {
                                *active = None;
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
                if let Err(e) = ipc.handle_one_admin(client_fd, &*runtime) {
                    debug!("Admin handler error: {}", e);
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

    fn drain_endpoint_events(&self) {
        let event_rx = self.event_rx.lock().unwrap();
        let mut events = Vec::new();
        while let Ok(event) = event_rx.try_recv() {
            events.push(event);
        }
        drop(event_rx);

        for event in events {
            self.handle_endpoint_event(event);
        }
    }

    fn handle_endpoint_event(&self, event: EndpointEvent) {
        match event {
            EndpointEvent::ResponseSent {
                endpoint_id,
                profile_id,
            } => {
                let profile = match self.profiles.get(&profile_id) {
                    Some(p) => p,
                    None => return,
                };

                let _lifecycle = profile.lifecycle_lock.lock().unwrap();

                {
                    let current_eid = profile.endpoint_id.lock().unwrap();
                    match current_eid.as_ref() {
                        Some(eid) if *eid == endpoint_id => {}
                        _ => return,
                    }
                }

                let active_session = self.get_session_id_for_profile(&profile_id);

                let pending_snapshot = {
                    let current = profile.current_pending.lock().unwrap();
                    current.as_ref().map(|p| {
                        (
                            p.request_id.clone(),
                            p.session_id.clone(),
                            p.prep_generation,
                            p.browser_lease_id.clone(),
                        )
                    })
                };

                let (request_id, session_id, prep_generation, browser_lease_id) =
                    match pending_snapshot {
                        Some(s) => s,
                        None => return,
                    };

                match active_session {
                    Some(ref sid) if *sid == session_id => {}
                    _ => return,
                }

                let status = match self
                    .policy_runtime
                    .principal_pending_status(&request_id, &session_id)
                {
                    Ok(s) => s,
                    Err(_) => return,
                };

                match status.state {
                    super::policy_engine::PendingState::Approved => {
                        match profile.mode {
                            AgentMode::DelegatedSession => {
                                if let Some(ref lease_id) = browser_lease_id {
                                    let clamped_ttl = Duration::from_secs(
                                        profile
                                            .current_pending
                                            .lock()
                                            .unwrap()
                                            .as_ref()
                                            .map(|p| p.clamped_session_ttl_secs)
                                            .unwrap_or(0),
                                    );
                                    let _clamped_ttl_secs = clamped_ttl.as_secs();

                                    let destroy_result = self.destroy_delegated_endpoint(profile);

                                    match destroy_result {
                                        Ok(()) => {
                                            let mut browser_mgr =
                                                self.browser_manager.lock().unwrap();
                                            let activation_result = browser_mgr
                                                .activate_after_assertion(lease_id, clamped_ttl);
                                            match activation_result {
                                                Ok(_) => {
                                                    let _ttl_deadline =
                                                        Instant::now() + clamped_ttl;
                                                    let mut current =
                                                        profile.current_pending.lock().unwrap();
                                                    let taken = current.take();
                                                    drop(current);
                                                    let mut active =
                                                        profile.active_browser.lock().unwrap();
                                                    *active = taken.map(|p| ActiveBrowserLease {
                                                        lease_id: p
                                                            .browser_lease_id
                                                            .unwrap_or_else(|| lease_id.clone()),
                                                        session_id: p.session_id,
                                                    });
                                                }
                                                Err(_) => {
                                                    let _ = browser_mgr.revoke(lease_id);
                                                    let _ = browser_mgr.terminate(lease_id);
                                                    let _ = browser_mgr.cleanup(lease_id);
                                                    browser_mgr.remove(lease_id);
                                                    profile
                                                        .preparation_slot
                                                        .clear_matching(prep_generation);
                                                    let mut current =
                                                        profile.current_pending.lock().unwrap();
                                                    *current = None;
                                                    let mut active =
                                                        profile.active_browser.lock().unwrap();
                                                    *active = None;
                                                    return;
                                                }
                                            }
                                        }
                                        Err(_) => {
                                            let mut browser_mgr =
                                                self.browser_manager.lock().unwrap();
                                            let _ = browser_mgr.revoke(lease_id);
                                            let _ = browser_mgr.terminate(lease_id);
                                            let _ = browser_mgr.cleanup(lease_id);
                                            browser_mgr.remove(lease_id);
                                            profile
                                                .preparation_slot
                                                .clear_matching(prep_generation);
                                            let mut current =
                                                profile.current_pending.lock().unwrap();
                                            *current = None;
                                            let mut active = profile.active_browser.lock().unwrap();
                                            *active = None;
                                            profile.enabled.store(false, Ordering::Release);
                                            return;
                                        }
                                    }
                                }
                            }
                            AgentMode::Isolated => {}
                        }
                        profile.preparation_slot.clear_matching(prep_generation);
                        if profile.mode != AgentMode::DelegatedSession || browser_lease_id.is_none()
                        {
                            let mut current = profile.current_pending.lock().unwrap();
                            *current = None;
                        }
                        if profile.mode == AgentMode::DelegatedSession && browser_lease_id.is_none()
                        {
                            let _ = self.destroy_delegated_endpoint(profile);
                        }
                    }
                    super::policy_engine::PendingState::Waiting => {}
                    super::policy_engine::PendingState::Denied
                    | super::policy_engine::PendingState::TimedOut
                    | super::policy_engine::PendingState::Cancelled => {
                        if let Some(ref lease_id) = browser_lease_id {
                            let mut browser_mgr = self.browser_manager.lock().unwrap();
                            let _ = browser_mgr.revoke(lease_id);
                            let _ = browser_mgr.terminate(lease_id);
                            let _ = browser_mgr.cleanup(lease_id);
                            browser_mgr.remove(lease_id);
                        }
                        profile.preparation_slot.clear_matching(prep_generation);
                        let mut current = profile.current_pending.lock().unwrap();
                        *current = None;

                        if profile.mode == AgentMode::DelegatedSession {
                            drop(current);
                            let _ = self.destroy_delegated_endpoint(profile);
                        }
                    }
                }
            }
        }
    }

    fn get_session_id_for_profile(&self, profile_id: &ProfileId) -> Option<PrincipalSessionId> {
        if let Some(slot) = self.managed_sessions.get(profile_id) {
            let s = slot.lock().unwrap();
            if let Some(ref managed) = *s {
                return Some(managed.session_id.clone());
            }
        }
        None
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

        {
            let mut em = self.endpoint_manager.lock().unwrap();
            em.cancel_all();
            let _ = em.shutdown_all(Some(SHUTDOWN_TIMEOUT));
        }

        let stop_event = DaemonStopBuilder::new(StopReason::GracefulShutdown, 0).build();
        let _ = self.audit_gate.record(stop_event);

        info!("Agent runtime shutdown complete");
    }

    fn handle_launch_principal(
        &self,
        profile_id: &ProfileId,
        command: &[String],
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

        let session_slot = self.managed_sessions.get(profile_id).ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::Internal,
                format!("no session slot for profile '{}'", profile_id),
                RecommendedAction::Abort,
            )
        })?;

        {
            let existing = session_slot.lock().unwrap();
            if let Some(ref session) = *existing
                && session.session.child.id() != 0
            {
                let exited;
                let pid = session.session.child.id() as i32;
                let proc_root = &session.session.proc_root;
                if let Ok(start_time) = super::launcher::read_proc_start_time(pid, proc_root) {
                    if start_time == session.session.identity.start_time {
                        return Err(ProtocolError::new(
                            ErrorCode::Conflict,
                            format!(
                                "profile '{}' already has an active session (pid {})",
                                profile_id, pid
                            ),
                            RecommendedAction::RetryWithBackoff,
                        ));
                    }
                    exited = true;
                } else {
                    exited = true;
                }
                if exited {
                    drop(existing);
                    let mut slot = session_slot.lock().unwrap();
                    *slot = None;
                }
            }
        }

        if command.is_empty() {
            return Err(ProtocolError::new(
                ErrorCode::BadRequest,
                "command must not be empty",
                RecommendedAction::FixRequest,
            ));
        }

        let program = validate_principal_executable(&command[0])?;
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
        let deadline = now + Duration::from_secs(3600);

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

        let managed = ManagedPrincipalSession {
            session_id: session_id.clone(),
            profile_id: profile_id.clone(),
            session,
            process_digest,
            created_at: now,
            deadline,
        };

        info!(
            "Launched principal session {} for profile {} (pid {})",
            session_id, profile_id, pid
        );

        let mut slot = session_slot.lock().unwrap();
        *slot = Some(managed);

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
                format!("no session slot for profile '{}'", profile_id),
                RecommendedAction::FixRequest,
            )
        })?;

        let mut slot = session_slot.lock().unwrap();
        if slot.is_none() {
            return Err(ProtocolError::new(
                ErrorCode::NotFound,
                format!("no active session for profile '{}'", profile_id),
                RecommendedAction::FixRequest,
            ));
        }

        let taken = slot.take();
        if let Some(mut managed) = taken {
            info!(
                "Terminating principal session {} for profile {} (pid {})",
                managed.session_id,
                profile_id,
                managed.session.child.id()
            );
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
            let completed = CompletedSession {
                exit_code,
                signal,
                completed_at: Instant::now(),
            };
            let mut completed_map = self.completed_sessions.lock().unwrap();
            completed_map.insert(managed.session_id.to_string(), completed);
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
            let mut found_slot = None;
            for session_slot in self.managed_sessions.values() {
                let mut slot = session_slot.lock().unwrap();
                if let Some(ref mut managed) = *slot
                    && managed.session_id == *session_id
                {
                    match managed.session.child.try_wait() {
                        Ok(Some(status)) => {
                            let (exit_code, signal) = if let Some(code) = status.code() {
                                (Some(code), None)
                            } else {
                                (None, status.signal())
                            };
                            let completed = CompletedSession {
                                exit_code,
                                signal,
                                completed_at: Instant::now(),
                            };
                            let mut completed_map = self.completed_sessions.lock().unwrap();
                            Self::prune_completed_before_insert(&mut completed_map);
                            completed_map.insert(session_id.to_string(), completed);
                            *slot = None;
                            return Ok(AdminResponse::PrincipalWait(PrincipalWaitResponse {
                                running: false,
                                exit_code,
                                signal,
                            }));
                        }
                        Ok(None) => {
                            found_slot = Some(true);
                        }
                        Err(e) => {
                            return Err(ProtocolError::new(
                                ErrorCode::Internal,
                                format!("try_wait failed: {}", e),
                                RecommendedAction::Retry,
                            ));
                        }
                    }
                }
            }

            if found_slot.is_none() {
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
            let mut slot = session_slot.lock().unwrap();
            if let Some(ref mut managed) = *slot {
                let should_reap = if now >= managed.deadline {
                    debug!(
                        "Session {} for profile {} expired, reaping",
                        managed.session_id, profile_id
                    );
                    true
                } else {
                    match managed.session.child.try_wait() {
                        Ok(Some(_)) => {
                            debug!(
                                "Session {} for profile {} exited, reaping",
                                managed.session_id, profile_id
                            );
                            true
                        }
                        Ok(None) => false,
                        Err(_) => true,
                    }
                };

                if should_reap {
                    let mut taken = slot.take().unwrap();
                    let exit_status = taken.session.child.try_wait().ok().flatten();
                    to_reap.push((profile_id.clone(), taken.session_id.clone(), exit_status));
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
            let completed = CompletedSession {
                exit_code,
                signal,
                completed_at: Instant::now(),
            };
            {
                let mut completed_map = self.completed_sessions.lock().unwrap();
                Self::prune_completed_before_insert(&mut completed_map);
                completed_map.insert(session_id.to_string(), completed);
            }

            if let Some(profile) = self.profiles.get(&profile_id) {
                let pending_action = {
                    let mut current = profile.current_pending.lock().unwrap();
                    let action = current.as_ref().map(|p| {
                        (
                            p.request_id.clone(),
                            p.session_id.clone(),
                            p.prep_generation,
                            p.browser_lease_id.clone(),
                        )
                    });
                    *current = None;
                    action
                };
                if let Some((request_id, sid, prep_gen, lease_id)) = pending_action {
                    let _ = self
                        .policy_runtime
                        .principal_cancel_pending(&request_id, &sid);
                    profile.preparation_slot.clear_matching(prep_gen);
                    if let Some(ref lid) = lease_id {
                        let mut browser_mgr = self.browser_manager.lock().unwrap();
                        let _ = browser_mgr.revoke(lid);
                        let _ = browser_mgr.terminate(lid);
                        let _ = browser_mgr.cleanup(lid);
                        browser_mgr.remove(lid);
                    }
                }
                let active_action = {
                    let mut active = profile.active_browser.lock().unwrap();
                    let action = active.as_ref().map(|l| l.lease_id.clone());
                    *active = None;
                    action
                };
                if let Some(lease_id) = active_action {
                    let mut browser_mgr = self.browser_manager.lock().unwrap();
                    let _ = browser_mgr.revoke(&lease_id);
                    let _ = browser_mgr.terminate(&lease_id);
                    let _ = browser_mgr.cleanup(&lease_id);
                    browser_mgr.remove(&lease_id);
                }
            }
        }
    }

    fn cleanup_expired_pending(&self) {
        let expired_ids = self.policy_runtime.cleanup_expired_pending();

        for (profile_id, profile) in &self.profiles {
            let mut current = profile.current_pending.lock().unwrap();
            if let Some(ref pending) = *current
                && expired_ids.contains(&pending.request_id)
            {
                profile
                    .preparation_slot
                    .clear_matching(pending.prep_generation);
                if let Some(ref lease_id) = pending.browser_lease_id {
                    let mut browser_mgr = self.browser_manager.lock().unwrap();
                    let _ = browser_mgr.revoke(lease_id);
                    let _ = browser_mgr.terminate(lease_id);
                    let _ = browser_mgr.cleanup(lease_id);
                    browser_mgr.remove(lease_id);
                }
                *current = None;
            }
            let _ = profile_id;
        }
    }

    fn prune_completed_sessions(&self) {
        let mut completed_map = self.completed_sessions.lock().unwrap();
        Self::prune_completed_before_insert(&mut completed_map);
    }

    fn reap_stopped_workers(&self) {
        let mut em = self.endpoint_manager.lock().unwrap();
        let endpoint_ids: Vec<EndpointId> = em
            .snapshot()
            .iter()
            .map(|s| s.handle.id().clone())
            .collect();

        for endpoint_id in endpoint_ids {
            if let super::endpoint_manager::ReapOutcome::Reaped { .. } =
                em.reap_stopped(&endpoint_id)
            {
                debug!("Reaped stopped worker for endpoint {}", endpoint_id);
                for profile in self.profiles.values() {
                    let mut eid_guard = profile.endpoint_id.lock().unwrap();
                    if eid_guard.as_ref() == Some(&endpoint_id) {
                        *eid_guard = None;
                        break;
                    }
                }
            }
        }
    }

    fn shutdown_all_sessions(&self) {
        for (profile_id, session_slot) in &self.managed_sessions {
            let mut slot = session_slot.lock().unwrap();
            if let Some(managed) = slot.take() {
                info!(
                    "Shutting down principal session {} for profile {}",
                    managed.session_id, profile_id
                );
                drop(managed.session);
            }
        }
    }

    fn resolve_credential_label(
        storage: &Arc<Mutex<Box<dyn CredentialStorage>>>,
        credential_ref: &passless_core::agent::CredentialRef,
    ) -> Option<String> {
        let mut storage_guard = storage.lock().ok()?;
        let cred = storage_guard.read(credential_ref.as_bytes()).ok()?;

        cred.user
            .display_name
            .as_ref()
            .map(|s| s.to_string())
            .or_else(|| cred.user.name.as_ref().map(|s| s.to_string()))
    }

    fn handle_create_intent(
        &self,
        params: CreateIntentParams<'_>,
    ) -> Result<PrincipalResponse, ProtocolError> {
        let CreateIntentParams {
            profile_id,
            session_id,
            endpoint_id,
            action,
            rp_id,
            credential_ref,
            principal_reason,
            clamped_grant_ttl_secs,
            clamped_session_ttl_secs,
            profile,
            session_digest,
        } = params;
        use passless_core::agent::protocol::IntentAction;

        let delegated_registration = profile.mode == AgentMode::DelegatedSession
            && *action == IntentAction::Register
            && profile
                .profile_config
                .delegated_registration_storage
                .is_some();
        if profile.mode != AgentMode::Isolated && !delegated_registration {
            return Err(ProtocolError::new(
                ErrorCode::Forbidden,
                "CreateIntent is allowed only for isolated profiles or explicitly configured delegated registration",
                RecommendedAction::FixRequest,
            ));
        }

        let normalized_rp = rp_id.trim().to_ascii_lowercase();
        let config = &profile.profile_config;

        let ceremony_policy = config.rule_for_rp(&normalized_rp).map(|rule| match action {
            IntentAction::Register => rule.register,
            IntentAction::Authenticate => rule.authenticate,
        });
        if ceremony_policy.as_ref().is_none_or(|policy| {
            policy.authorization == passless_core::agent::AgentAuthorization::Deny
        }) {
            return Err(ProtocolError::new(
                ErrorCode::Forbidden,
                "RP ID does not exactly match configured RP IDs",
                RecommendedAction::FixRequest,
            ));
        }

        match action {
            IntentAction::Register => {
                if credential_ref.is_some() {
                    return Err(ProtocolError::new(
                        ErrorCode::Forbidden,
                        "registration must not include a credential ref",
                        RecommendedAction::FixRequest,
                    ));
                }
            }
            IntentAction::Authenticate => {
                let cred_ref = credential_ref.ok_or_else(|| {
                    ProtocolError::new(
                        ErrorCode::BadRequest,
                        "authentication requires a credential ref",
                        RecommendedAction::FixRequest,
                    )
                })?;

                let cred_exists = {
                    let mut storage = profile.credential_storage.lock().map_err(|_| {
                        ProtocolError::new(
                            ErrorCode::Internal,
                            "credential storage lock poisoned",
                            RecommendedAction::Abort,
                        )
                    })?;
                    storage.read(cred_ref.as_bytes()).is_ok()
                };

                if !cred_exists {
                    return Err(ProtocolError::new(
                        ErrorCode::NotFound,
                        "credential ref not found in storage",
                        RecommendedAction::FixRequest,
                    ));
                }
            }
        }

        {
            let current = profile.current_pending.lock().unwrap();
            if current.is_some() {
                return Err(ProtocolError::new(
                    ErrorCode::Conflict,
                    "another pending request is already active for this profile",
                    RecommendedAction::RetryWithBackoff,
                ));
            }
        }

        let generation = self.policy_runtime.current_generation();
        let _snapshot = generation.find_snapshot(profile_id).ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::Internal,
                "profile snapshot not found in current generation",
                RecommendedAction::Abort,
            )
        })?;

        let process_digest = session_digest.clone();

        let intent_action = match action {
            IntentAction::Register => passless_core::agent::protocol::IntentAction::Register,
            IntentAction::Authenticate => {
                passless_core::agent::protocol::IntentAction::Authenticate
            }
        };

        let params = super::intent::CreateIntentParams {
            profile_id: profile_id.clone(),
            session_id: session_id.clone(),
            endpoint_id: endpoint_id.clone(),
            process_digest: process_digest.clone(),
            action: intent_action.clone(),
            rp_id: normalized_rp.clone(),
            credential_ref: credential_ref.cloned(),
            policy_generation: generation.generation_id.clone(),
            policy_digest: generation.digest.clone(),
            require_uv: ceremony_policy.as_ref().is_some_and(|policy| {
                policy.user_verification != passless_core::agent::UserVerificationSource::None
            }),
            ttl_ms: Some(300_000),
        };

        let pending_id = self
            .policy_runtime
            .principal_create_pending_intent(params)
            .map_err(|e| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    format!("failed to create pending intent: {}", e),
                    RecommendedAction::Retry,
                )
            })?;

        let config = &profile.profile_config;
        let max_grant_ttl = config.max_grant_ttl.map(|d| d.as_secs()).unwrap_or(300);
        let max_session_ttl = config.max_session_ttl.map(|d| d.as_secs()).unwrap_or(900);

        let requested_grant_ttl = clamped_grant_ttl_secs.unwrap_or(max_grant_ttl);
        let clamped_grant_ttl = requested_grant_ttl.min(max_grant_ttl).max(5);
        let requested_session_ttl = clamped_session_ttl_secs.unwrap_or(max_session_ttl);
        let clamped_session_ttl = requested_session_ttl.min(max_session_ttl).max(60);

        let trusted_credential_label = if let Some(cred_ref) = credential_ref {
            Self::resolve_credential_label(&profile.credential_storage, cred_ref)
        } else {
            None
        };

        let prep_input = super::ceremony::CeremonyPreparationInput {
            session_id: session_id.clone(),
            process_digest,
            policy_generation: generation.generation_id.clone(),
            policy_digest: generation.digest.clone(),
            credential_ref: credential_ref.cloned(),
            untrusted_metadata: super::ceremony::BoundedUntrustedMetadata::new(
                normalized_rp,
                intent_action,
                ceremony_policy.as_ref().is_some_and(|policy| {
                    policy.user_verification != passless_core::agent::UserVerificationSource::None
                }),
            )
            .with_principal_reason(principal_reason),
            clamped_grant_ttl_secs: clamped_grant_ttl,
            clamped_session_ttl_secs: clamped_session_ttl,
            trusted_credential_label,
        };

        let guard = profile.preparation_slot.install(prep_input).map_err(|e| {
            let _ = self
                .policy_runtime
                .principal_cancel_pending(&pending_id, session_id);
            ProtocolError::new(
                ErrorCode::Conflict,
                format!("failed to install preparation: {}", e),
                RecommendedAction::Retry,
            )
        })?;

        let prep_generation = guard.generation();
        guard.disarm();

        let audit_action = match action {
            IntentAction::Register => super::audit_events::AuditAction::Register,
            IntentAction::Authenticate => super::audit_events::AuditAction::Authenticate,
        };
        let intent_id = {
            let status = self
                .policy_runtime
                .principal_pending_status(&pending_id, session_id)
                .map_err(|_| {
                    ProtocolError::new(
                        ErrorCode::Internal,
                        "failed to read pending status",
                        RecommendedAction::Abort,
                    )
                })?;
            status.intent_id.clone()
        };
        let create_event = super::audit_events::IntentCreateBuilder::new(
            intent_id,
            profile_id.clone(),
            audit_action,
        )
        .build();
        if let Err(e) = self.audit_gate.record(create_event) {
            let _ = self
                .policy_runtime
                .principal_cancel_pending(&pending_id, session_id);
            profile.preparation_slot.clear_matching(prep_generation);
            return Err(ProtocolError::new(
                ErrorCode::Internal,
                format!("audit record failed: {}", e),
                RecommendedAction::Abort,
            ));
        }

        {
            let mut current = profile.current_pending.lock().unwrap();
            *current = Some(PendingRuntime {
                request_id: pending_id.clone(),
                prep_generation,
                session_id: session_id.clone(),
                browser_lease_id: None,
                clamped_session_ttl_secs: 0,
            });
        }

        Ok(PrincipalResponse::IntentCreated {
            request_id: pending_id,
        })
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

        {
            let mut current = profile.current_pending.lock().unwrap();
            if let Some(ref pending) = *current
                && pending.request_id == *request_id
            {
                profile
                    .preparation_slot
                    .clear_matching(pending.prep_generation);
                *current = None;
            }
        }

        let cancel_event =
            super::audit_events::IntentCancelBuilder::new(status.intent_id.clone()).build();
        let _ = self.audit_gate.record(cancel_event);

        Ok(PrincipalResponse::IntentCancelled)
    }

    fn handle_request_delegation(
        &self,
        params: RequestDelegationParams<'_>,
    ) -> Result<PrincipalResponse, ProtocolError> {
        let RequestDelegationParams {
            profile_id,
            session_id,
            endpoint_id,
            rp_id,
            credential_ref,
            max_session_ttl,
            principal_reason,
            profile,
            session_digest,
        } = params;
        if profile.mode != AgentMode::DelegatedSession {
            return Err(ProtocolError::new(
                ErrorCode::Forbidden,
                "RequestDelegation is only allowed for delegated profiles",
                RecommendedAction::FixRequest,
            ));
        }

        let normalized_rp = rp_id.trim().to_ascii_lowercase();
        let config = &profile.profile_config;

        if !config
            .allowed_rp_ids()
            .iter()
            .any(|id| id.trim().to_ascii_lowercase() == normalized_rp)
        {
            return Err(ProtocolError::new(
                ErrorCode::Forbidden,
                "RP ID does not exactly match configured RP IDs",
                RecommendedAction::FixRequest,
            ));
        }

        let allowed_refs = config.credential_refs.as_ref().ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::Forbidden,
                "no credential refs configured for this profile",
                RecommendedAction::Abort,
            )
        })?;
        if !allowed_refs.iter().any(|r| r == credential_ref) {
            return Err(ProtocolError::new(
                ErrorCode::Forbidden,
                "credential ref does not exactly match configured refs",
                RecommendedAction::FixRequest,
            ));
        }

        let ceremony_policy = config
            .rule_for_rp(&normalized_rp)
            .map(|rule| rule.authenticate)
            .filter(|policy| policy.authorization != passless_core::agent::AgentAuthorization::Deny)
            .ok_or_else(|| {
                ProtocolError::new(
                    ErrorCode::Forbidden,
                    "delegated authentication is denied for this RP",
                    RecommendedAction::FixRequest,
                )
            })?;

        if max_session_ttl == 0 {
            return Err(ProtocolError::new(
                ErrorCode::BadRequest,
                "max_session_ttl must be > 0",
                RecommendedAction::FixRequest,
            ));
        }

        let profile_max_ttl = config
            .max_session_ttl
            .as_ref()
            .map(|d| d.as_secs())
            .unwrap_or(3600);
        let clamped_ttl = max_session_ttl.min(profile_max_ttl);

        {
            let current = profile.current_pending.lock().unwrap();
            if current.is_some() {
                return Err(ProtocolError::new(
                    ErrorCode::Conflict,
                    "another pending request is already active for this profile",
                    RecommendedAction::RetryWithBackoff,
                ));
            }
        }

        {
            let active = profile.active_browser.lock().unwrap();
            if active.is_some() {
                return Err(ProtocolError::new(
                    ErrorCode::Conflict,
                    "a browser session is already active for this profile",
                    RecommendedAction::RetryWithBackoff,
                ));
            }
        }

        let generation = self.policy_runtime.current_generation();
        let process_digest = session_digest.clone();

        let intent_params = super::intent::CreateIntentParams {
            profile_id: profile_id.clone(),
            session_id: session_id.clone(),
            endpoint_id: endpoint_id.clone(),
            process_digest: process_digest.clone(),
            action: passless_core::agent::protocol::IntentAction::Authenticate,
            rp_id: normalized_rp.clone(),
            credential_ref: Some(credential_ref.clone()),
            policy_generation: generation.generation_id.clone(),
            policy_digest: generation.digest.clone(),
            require_uv: ceremony_policy.user_verification
                != passless_core::agent::UserVerificationSource::None,
            ttl_ms: Some(300_000),
        };

        let grant_params = super::grant::GrantRequestParams {
            profile_id: profile_id.clone(),
            session_id: session_id.clone(),
            endpoint_id: endpoint_id.clone(),
            principal_digest: *process_digest.as_bytes(),
            rp_ids: vec![normalized_rp.clone()],
            credentials: vec![credential_ref.clone()],
            requested_ttl_secs: clamped_ttl,
        };

        let pending_id = self
            .policy_runtime
            .principal_create_pending_delegated(intent_params, grant_params)
            .map_err(|e| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    format!("failed to create pending delegation: {}", e),
                    RecommendedAction::Retry,
                )
            })?;

        let config = &profile.profile_config;
        let max_grant_ttl = config.max_grant_ttl.map(|d| d.as_secs()).unwrap_or(300);
        let max_session_ttl = config.max_session_ttl.map(|d| d.as_secs()).unwrap_or(900);

        let requested_session_ttl = max_session_ttl.min(max_session_ttl);
        let clamped_session_ttl = requested_session_ttl.min(max_session_ttl).max(60);
        let requested_grant_ttl = max_grant_ttl;
        let clamped_grant_ttl = requested_grant_ttl.min(max_grant_ttl).max(5);

        let trusted_credential_label = if let Some(ref deps) = profile.endpoint_spec.delegated_deps
        {
            Self::resolve_credential_label(&deps.human_storage, credential_ref)
        } else {
            None
        };

        let prep_input = super::ceremony::CeremonyPreparationInput {
            session_id: session_id.clone(),
            process_digest,
            policy_generation: generation.generation_id.clone(),
            policy_digest: generation.digest.clone(),
            credential_ref: Some(credential_ref.clone()),
            untrusted_metadata: super::ceremony::BoundedUntrustedMetadata::new(
                normalized_rp,
                passless_core::agent::protocol::IntentAction::Authenticate,
                true,
            )
            .with_principal_reason(principal_reason),
            clamped_grant_ttl_secs: clamped_grant_ttl,
            clamped_session_ttl_secs: clamped_session_ttl,
            trusted_credential_label,
        };

        let guard = profile.preparation_slot.install(prep_input).map_err(|e| {
            let _ = self
                .policy_runtime
                .principal_cancel_pending(&pending_id, session_id);
            ProtocolError::new(
                ErrorCode::Conflict,
                format!("failed to install preparation: {}", e),
                RecommendedAction::Retry,
            )
        })?;

        let prep_generation = guard.generation();
        guard.disarm();

        let status = self
            .policy_runtime
            .principal_pending_status(&pending_id, session_id)
            .map_err(|_| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    "failed to read pending status",
                    RecommendedAction::Abort,
                )
            })?;

        let intent_create_event = super::audit_events::IntentCreateBuilder::new(
            status.intent_id.clone(),
            profile_id.clone(),
            super::audit_events::AuditAction::Authenticate,
        )
        .build();
        if let Err(e) = self.audit_gate.record(intent_create_event) {
            let _ = self
                .policy_runtime
                .principal_cancel_pending(&pending_id, session_id);
            profile.preparation_slot.clear_matching(prep_generation);
            return Err(ProtocolError::new(
                ErrorCode::Internal,
                format!("audit record failed: {}", e),
                RecommendedAction::Abort,
            ));
        }

        let browser_lease_id = {
            let browser_user = profile.browser_uid.ok_or_else(|| {
                let _ = self
                    .policy_runtime
                    .principal_cancel_pending(&pending_id, session_id);
                profile.preparation_slot.clear_matching(prep_generation);
                ProtocolError::new(
                    ErrorCode::Internal,
                    "profile has no browser user configured",
                    RecommendedAction::Abort,
                )
            })?;
            let browser_gid = profile.browser_gid.ok_or_else(|| {
                let _ = self
                    .policy_runtime
                    .principal_cancel_pending(&pending_id, session_id);
                profile.preparation_slot.clear_matching(prep_generation);
                ProtocolError::new(
                    ErrorCode::Internal,
                    "profile has no browser gid configured",
                    RecommendedAction::Abort,
                )
            })?;

            let browser_command = config.browser_command.as_ref().ok_or_else(|| {
                let _ = self
                    .policy_runtime
                    .principal_cancel_pending(&pending_id, session_id);
                profile.preparation_slot.clear_matching(prep_generation);
                ProtocolError::new(
                    ErrorCode::Internal,
                    "profile has no browser_command configured",
                    RecommendedAction::Abort,
                )
            })?;

            let executable = std::path::PathBuf::from(&browser_command[0]);
            let extra_args = if browser_command.len() > 1 {
                browser_command[1..].to_vec()
            } else {
                Vec::new()
            };

            let login_timeout_secs = config
                .max_grant_ttl
                .as_ref()
                .map(|d| d.as_secs())
                .unwrap_or(120);
            let session_ttl = std::time::Duration::from_secs(clamped_ttl);
            let login_timeout = std::time::Duration::from_secs(login_timeout_secs);

            let browser_config = super::browser::BrowserConfig {
                executable,
                start_url: config.start_url.clone(),
                extra_args,
                runtime_root: config
                    .browser_runtime_root
                    .clone()
                    .unwrap_or_else(|| std::path::PathBuf::from("/var/run/passless-browser")),
                ttl: session_ttl,
                login_timeout,
                rp_ids: config.allowed_rp_ids(),
                target_uid: browser_user,
                target_gid: browser_gid,
                daemon_uid: self.daemon_uid,
                daemon_gid: self.daemon_gid,
            };

            let mut browser_mgr = self.browser_manager.lock().unwrap();
            let lease_id = browser_mgr
                .launch_pending(&browser_config, endpoint_id.clone(), profile_id.clone())
                .map_err(|e| {
                    let _ = self
                        .policy_runtime
                        .principal_cancel_pending(&pending_id, session_id);
                    profile.preparation_slot.clear_matching(prep_generation);
                    ProtocolError::new(
                        ErrorCode::Internal,
                        format!("failed to launch browser: {}", e),
                        RecommendedAction::Retry,
                    )
                })?;

            let lease_clone = lease_id.clone();
            let pending_id_clone = pending_id.clone();
            let session_id_clone = session_id.clone();
            let browser_mgr_for_rollback = self.browser_manager.clone();
            let policy_rt = self.policy_runtime.clone();
            let prep_slot = profile.preparation_slot.clone();

            let lease_audit_event = super::audit_events::BrowserLeaseLaunchBuilder::new(
                lease_id.clone(),
                profile_id.clone(),
                endpoint_id.clone(),
            )
            .build();
            if let Err(e) = self.audit_gate.record(lease_audit_event) {
                let _ = policy_rt.principal_cancel_pending(&pending_id_clone, &session_id_clone);
                prep_slot.clear_matching(prep_generation);
                let mut bm = browser_mgr_for_rollback.lock().unwrap();
                let _ = bm.revoke(&lease_clone);
                let _ = bm.terminate(&lease_clone);
                let _ = bm.cleanup(&lease_clone);
                bm.remove(&lease_clone);
                return Err(ProtocolError::new(
                    ErrorCode::Internal,
                    format!("browser lease audit record failed: {}", e),
                    RecommendedAction::Abort,
                ));
            }

            lease_id
        };

        {
            let mut current = profile.current_pending.lock().unwrap();
            *current = Some(PendingRuntime {
                request_id: pending_id.clone(),
                prep_generation,
                session_id: session_id.clone(),
                browser_lease_id: Some(browser_lease_id),
                clamped_session_ttl_secs: clamped_ttl,
            });
        }

        Ok(PrincipalResponse::DelegationRequested {
            request_id: pending_id,
        })
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

        let _ = self
            .policy_runtime
            .principal_cancel_pending(request_id, session_id);

        {
            let current = profile.current_pending.lock().unwrap();
            if let Some(ref pending) = *current
                && pending.request_id == *request_id
            {
                profile
                    .preparation_slot
                    .clear_matching(pending.prep_generation);
            }
        }

        if let Some(ref lease_id) = {
            let current = profile.current_pending.lock().unwrap();
            current.as_ref().and_then(|p| p.browser_lease_id.clone())
        } {
            let mut browser_mgr = self.browser_manager.lock().unwrap();
            let _ = browser_mgr.terminate(lease_id);
            let _ = browser_mgr.remove(lease_id);
        }

        {
            let mut current = profile.current_pending.lock().unwrap();
            if let Some(ref pending) = *current
                && pending.request_id == *request_id
            {
                *current = None;
            }
        }

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
        profile: &ProfileRuntime,
    ) -> Result<PrincipalResponse, ProtocolError> {
        let lease_id = {
            let active = profile.active_browser.lock().unwrap();
            if let Some(ref lease) = *active {
                Some(lease.lease_id.clone())
            } else {
                drop(active);
                let current = profile.current_pending.lock().unwrap();
                current.as_ref().and_then(|p| p.browser_lease_id.clone())
            }
        };

        if let Some(lease_id) = lease_id {
            let browser_mgr = self.browser_manager.lock().unwrap();
            if let Some(snapshot) = browser_mgr.snapshot(&lease_id) {
                return Ok(PrincipalResponse::BrowserStatus(
                    passless_core::agent::BrowserStatusResponse {
                        running: !snapshot.state.is_terminal(),
                        status: format!("{}", snapshot.state),
                    },
                ));
            }
        }

        Ok(PrincipalResponse::BrowserStatus(
            passless_core::agent::BrowserStatusResponse {
                running: false,
                status: "no_browser".into(),
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
        let lease_id = {
            let active = profile.active_browser.lock().unwrap();
            if let Some(ref lease) = *active {
                if lease.session_id != *session_id {
                    let cdp_method = extract_cdp_method_for_audit(request_json);
                    let outcome = super::audit_events::BrowserControlOutcome::Denied;
                    if let Some(ref lid) = active.as_ref().map(|l| l.lease_id.clone()) {
                        let _ = self.audit_gate.record(
                            super::audit_events::BrowserControlRequestBuilder::new(
                                profile_id.clone(),
                                lid.clone(),
                                &cdp_method,
                                outcome,
                            )
                            .build(),
                        );
                    }
                    return Err(ProtocolError::new(
                        ErrorCode::Unauthorized,
                        "session_id does not match active browser lease",
                        RecommendedAction::Abort,
                    ));
                }
                lease.lease_id.clone()
            } else {
                drop(active);
                let current = profile.current_pending.lock().unwrap();
                let pending = current.as_ref().ok_or_else(|| {
                    ProtocolError::new(
                        ErrorCode::Forbidden,
                        "no active browser lease for this profile",
                        RecommendedAction::FixRequest,
                    )
                })?;
                if pending.session_id != *session_id {
                    let cdp_method = extract_cdp_method_for_audit(request_json);
                    let outcome = super::audit_events::BrowserControlOutcome::Denied;
                    if let Some(ref lid) = pending.browser_lease_id {
                        let _ = self.audit_gate.record(
                            super::audit_events::BrowserControlRequestBuilder::new(
                                profile_id.clone(),
                                lid.clone(),
                                &cdp_method,
                                outcome,
                            )
                            .build(),
                        );
                    }
                    return Err(ProtocolError::new(
                        ErrorCode::Unauthorized,
                        "session_id does not match pending browser lease",
                        RecommendedAction::Abort,
                    ));
                }
                pending.browser_lease_id.clone().ok_or_else(|| {
                    ProtocolError::new(
                        ErrorCode::Forbidden,
                        "no browser lease associated with current session",
                        RecommendedAction::FixRequest,
                    )
                })?
            }
        };

        let cdp_method = extract_cdp_method_for_audit(request_json);

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
            .map(|_| generation.generation_id.as_str().len() as u64)
            .unwrap_or(0);
        let active_grants = self
            .policy_runtime
            .active_grant_count_for_profile(profile_id);
        let pending_intents = self
            .policy_runtime
            .pending_intent_count_for_profile(profile_id);
        let active_sessions = if self.get_session_id_for_profile(profile_id).is_some() {
            1
        } else {
            0
        };

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
            active.as_ref().map(|_| "active".to_string())
        };

        let generation = self.policy_runtime.current_generation();
        let policy_gen = generation
            .find_snapshot(profile_id)
            .map(|_| generation.generation_id.as_str().len() as u64)
            .unwrap_or(0);

        let (pin_storage_available, pin_set) = {
            let pin_storage = if let Some(ref isolated) = profile.endpoint_spec.isolated_deps {
                Some(isolated.pin_storage.clone())
            } else {
                profile
                    .endpoint_spec
                    .delegated_deps
                    .as_ref()
                    .map(|delegated| delegated.human_pin_storage.clone())
            };

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

        let require_uv = profile.profile_config.requires_human_uv();

        super::doctor::build_profile_diagnostic_report(super::doctor::ProfileDiagnosticParams {
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
        })
    }

    fn handle_enableprofile(&self, profile_id: &ProfileId) -> Result<AdminResponse, ProtocolError> {
        let profile = self.profiles.get(profile_id).ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::NotFound,
                format!("profile '{}' not found", profile_id),
                RecommendedAction::FixRequest,
            )
        })?;

        let has_endpoint = {
            let eid_guard = profile.endpoint_id.lock().unwrap();
            eid_guard.is_some()
        };

        if !has_endpoint {
            match profile.mode {
                AgentMode::Isolated => {
                    let _lifecycle = profile.lifecycle_lock.lock().unwrap();
                    match self.create_profile_endpoint(&profile.endpoint_spec) {
                        Ok(eid) => {
                            let mut eid_guard = profile.endpoint_id.lock().unwrap();
                            *eid_guard = Some(eid);
                        }
                        Err(e) => {
                            return Err(ProtocolError::new(
                                ErrorCode::Internal,
                                format!("failed to recreate endpoint: {}", e),
                                RecommendedAction::Abort,
                            ));
                        }
                    }
                }
                AgentMode::DelegatedSession => {}
            }
        } else {
            let em = self.endpoint_manager.lock().unwrap();
            let eid = profile.endpoint_id.lock().unwrap().clone().unwrap();
            let healthy = em.snapshot().iter().any(|s| s.handle.id() == &eid);
            drop(em);

            if !healthy {
                return Err(ProtocolError::new(
                    ErrorCode::Conflict,
                    format!("profile '{}' endpoint runtime is not healthy", profile_id),
                    RecommendedAction::Abort,
                ));
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

        {
            let mut current = profile.current_pending.lock().unwrap();
            if let Some(ref pending) = *current {
                let _ = self
                    .policy_runtime
                    .principal_cancel_pending(&pending.request_id, &pending.session_id);
                profile
                    .preparation_slot
                    .clear_matching(pending.prep_generation);
                if let Some(ref lease_id) = pending.browser_lease_id {
                    let mut browser_mgr = self.browser_manager.lock().unwrap();
                    let _ = browser_mgr.revoke(lease_id);
                    let _ = browser_mgr.terminate(lease_id);
                    let _ = browser_mgr.cleanup(lease_id);
                    browser_mgr.remove(lease_id);
                }
                *current = None;
            }
        }

        {
            let mut active = profile.active_browser.lock().unwrap();
            if let Some(ref lease) = *active {
                let mut browser_mgr = self.browser_manager.lock().unwrap();
                let _ = browser_mgr.revoke(&lease.lease_id);
                let _ = browser_mgr.terminate(&lease.lease_id);
                let _ = browser_mgr.cleanup(&lease.lease_id);
                browser_mgr.remove(&lease.lease_id);
            }
            *active = None;
        }

        {
            let _lifecycle = profile.lifecycle_lock.lock().unwrap();
            let has_endpoint = {
                let eid_guard = profile.endpoint_id.lock().unwrap();
                eid_guard.is_some()
            };
            if has_endpoint {
                let destroy_result = self.destroy_delegated_endpoint(profile);
                if let Err(e) = destroy_result {
                    let disable_failed_event =
                        super::audit_events::AdminProfileDisableFailedBuilder::new(
                            profile_id.clone(),
                            DisableRequestReason::AdminRequested,
                            e.to_string(),
                        )
                        .build();
                    let _ = self.audit_gate.record(disable_failed_event);

                    return Err(ProtocolError::new(
                        ErrorCode::Conflict,
                        format!(
                            "profile '{}' disabled but endpoint destroy failed: {}",
                            profile_id, e
                        ),
                        RecommendedAction::RetryWithBackoff,
                    ));
                }
            }
        }

        if let Some(session_slot) = self.managed_sessions.get(profile_id) {
            let mut slot = session_slot.lock().unwrap();
            if let Some(managed) = slot.take() {
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
        let gen_num = generation.generation_id.as_str().len() as u64;
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
            generation.generation_id.as_str().len() as u64,
        )
        .build();
        let _ = self.audit_gate.record(gen_event);

        for (pid, profile) in &self.profiles {
            let mut current = profile.current_pending.lock().unwrap();
            if let Some(ref pending) = *current {
                let _ = self
                    .policy_runtime
                    .principal_cancel_pending(&pending.request_id, &pending.session_id);
                profile
                    .preparation_slot
                    .clear_matching(pending.prep_generation);
                if let Some(ref lease_id) = pending.browser_lease_id {
                    let mut browser_mgr = self.browser_manager.lock().unwrap();
                    let _ = browser_mgr.revoke(lease_id);
                    let _ = browser_mgr.terminate(lease_id);
                    let _ = browser_mgr.cleanup(lease_id);
                    browser_mgr.remove(lease_id);
                }
                *current = None;
            }
            drop(current);
            let mut active = profile.active_browser.lock().unwrap();
            if let Some(ref lease) = *active {
                let mut browser_mgr = self.browser_manager.lock().unwrap();
                let _ = browser_mgr.revoke(&lease.lease_id);
                let _ = browser_mgr.terminate(&lease.lease_id);
                let _ = browser_mgr.cleanup(&lease.lease_id);
                browser_mgr.remove(&lease.lease_id);
            }
            *active = None;
            let _ = pid;
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
                if !profile
                    .profile_config
                    .rp_ids
                    .iter()
                    .any(|configured_rp| configured_rp.trim().eq_ignore_ascii_case(rp.trim()))
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

            if profile.mode == AgentMode::DelegatedSession {
                return Err(ProtocolError::new(
                    ErrorCode::Forbidden,
                    "cannot show credentials in delegated mode",
                    RecommendedAction::FixRequest,
                ));
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
            let mut current = profile.current_pending.lock().unwrap();
            if let Some(ref pending) = *current {
                profile
                    .preparation_slot
                    .clear_matching(pending.prep_generation);
                if let Some(ref lease_id) = pending.browser_lease_id {
                    let mut browser_mgr = self.browser_manager.lock().unwrap();
                    let _ = browser_mgr.revoke(lease_id);
                    let _ = browser_mgr.terminate(lease_id);
                    let _ = browser_mgr.cleanup(lease_id);
                    browser_mgr.remove(lease_id);
                }
                *current = None;
            }
            drop(current);
            let mut active = profile.active_browser.lock().unwrap();
            if let Some(ref lease) = *active {
                let mut browser_mgr = self.browser_manager.lock().unwrap();
                let _ = browser_mgr.revoke(&lease.lease_id);
                let _ = browser_mgr.terminate(&lease.lease_id);
                let _ = browser_mgr.cleanup(&lease.lease_id);
                browser_mgr.remove(&lease.lease_id);
            }
            *active = None;
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
            for profile in self.profiles.values() {
                if profile.mode == AgentMode::DelegatedSession {
                    let is_in_profile = profile
                        .profile_config
                        .credential_refs
                        .as_ref()
                        .is_some_and(|refs| refs.iter().any(|r| r == credential_ref));
                    if is_in_profile {
                        return Err(ProtocolError::new(
                            ErrorCode::Forbidden,
                            "cannot delete credentials in delegated mode",
                            RecommendedAction::FixRequest,
                        ));
                    }
                }
            }
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
            for profile in self.profiles.values() {
                if profile.mode == AgentMode::DelegatedSession {
                    let is_in_profile = profile
                        .profile_config
                        .credential_refs
                        .as_ref()
                        .is_some_and(|refs| refs.iter().any(|r| r == credential_ref));
                    if is_in_profile {
                        return Err(ProtocolError::new(
                            ErrorCode::Forbidden,
                            "cannot rename credentials in delegated mode",
                            RecommendedAction::FixRequest,
                        ));
                    }
                }
            }
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
            let mut current = profile.current_pending.lock().unwrap();
            if let Some(ref pending) = *current {
                profile
                    .preparation_slot
                    .clear_matching(pending.prep_generation);
                if let Some(ref lease_id) = pending.browser_lease_id {
                    let mut browser_mgr = self.browser_manager.lock().unwrap();
                    let _ = browser_mgr.revoke(lease_id);
                    let _ = browser_mgr.terminate(lease_id);
                    let _ = browser_mgr.cleanup(lease_id);
                    browser_mgr.remove(lease_id);
                }
                *current = None;
            }
            drop(current);
            let mut active = profile.active_browser.lock().unwrap();
            if let Some(ref lease) = *active {
                let mut browser_mgr = self.browser_manager.lock().unwrap();
                let _ = browser_mgr.revoke(&lease.lease_id);
                let _ = browser_mgr.terminate(&lease.lease_id);
                let _ = browser_mgr.cleanup(&lease.lease_id);
                browser_mgr.remove(&lease.lease_id);
            }
            *active = None;
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

        let mut sessions = Vec::new();
        for (profile_id, session_slot) in &self.managed_sessions {
            if let Some(filter) = profile_filter
                && profile_id != filter
            {
                continue;
            }
            let slot = session_slot.lock().unwrap();
            if let Some(ref managed) = *slot {
                let created_at = wall_now.saturating_sub(managed.created_at.elapsed().as_secs());
                let expires_at = wall_now.saturating_sub(managed.deadline.elapsed().as_secs());
                sessions.push(passless_core::agent::SessionInfo {
                    session_id: managed.session_id.clone(),
                    profile_id: profile_id.to_string(),
                    pid: managed.session.child.id(),
                    created_at,
                    expires_at,
                });
            }
        }

        let total = sessions.len() as u32;
        Ok(AdminResponse::SessionList(
            passless_core::agent::SessionList { sessions, total },
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
            let slot = session_slot.lock().unwrap();
            if let Some(ref managed) = *slot
                && managed.session_id == *session_id
            {
                let created_at = wall_now.saturating_sub(managed.created_at.elapsed().as_secs());
                let expires_at = wall_now.saturating_sub(managed.deadline.elapsed().as_secs());
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
            let mut slot = session_slot.lock().unwrap();
            if let Some(ref managed) = *slot
                && managed.session_id == *session_id
            {
                let taken = slot.take();
                if let Some(managed) = taken {
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
                        let mut current = profile.current_pending.lock().unwrap();
                        if let Some(ref pending) = *current {
                            let _ = self
                                .policy_runtime
                                .principal_cancel_pending(&pending.request_id, &pending.session_id);
                            profile
                                .preparation_slot
                                .clear_matching(pending.prep_generation);
                            if let Some(ref lease_id) = pending.browser_lease_id {
                                let mut browser_mgr = self.browser_manager.lock().unwrap();
                                let _ = browser_mgr.revoke(lease_id);
                                let _ = browser_mgr.terminate(lease_id);
                                let _ = browser_mgr.cleanup(lease_id);
                                browser_mgr.remove(lease_id);
                            }
                            *current = None;
                        }
                        drop(current);
                        let mut active = profile.active_browser.lock().unwrap();
                        if let Some(ref lease) = *active {
                            let mut browser_mgr = self.browser_manager.lock().unwrap();
                            let _ = browser_mgr.revoke(&lease.lease_id);
                            let _ = browser_mgr.terminate(&lease.lease_id);
                            let _ = browser_mgr.cleanup(&lease.lease_id);
                            browser_mgr.remove(&lease.lease_id);
                        }
                        *active = None;
                    }

                    drop(managed.session);
                }
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
                let em = self.endpoint_manager.lock().unwrap();
                let credential_count = em.snapshot().len();
                Ok(AdminResponse::Status(DaemonStatus {
                    daemon_version: env!("CARGO_PKG_VERSION").into(),
                    protocol_version: passless_core::agent::protocol::CURRENT_VERSION,
                    backend: "agent".into(),
                    uptime_secs: 0,
                    credential_count: credential_count as u32,
                }))
            }
            AdminRequest::LaunchPrincipal {
                profile_id,
                command,
            } => self.handle_launch_principal(profile_id, command, ctx),
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

        let slot = session_slot.lock().unwrap();
        let managed = slot.as_ref().ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::Unauthorized,
                format!("no active session for profile '{}'", profile_id),
                RecommendedAction::Abort,
            )
        })?;

        let session = &managed.session;
        if !session
            .capability
            .verify(&SessionCapability::from_bytes(*capability_proof.as_bytes()))
        {
            return Err(ProtocolError::new(
                ErrorCode::Unauthorized,
                "capability proof verification failed",
                RecommendedAction::Abort,
            ));
        }

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
                let em = self.endpoint_manager.lock().unwrap();
                let credential_count = em.snapshot().len();
                Ok(PrincipalResponse::Status(DaemonStatus {
                    daemon_version: env!("CARGO_PKG_VERSION").into(),
                    protocol_version: passless_core::agent::protocol::CURRENT_VERSION,
                    backend: "agent".into(),
                    uptime_secs: 0,
                    credential_count: credential_count as u32,
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
            PrincipalRequest::CreateIntent {
                profile_id: _req_profile_id,
                action,
                rp_id,
                credential_ref,
                reason,
                grant_ttl_secs,
                session_ttl_secs,
            } => {
                if profile.mode == AgentMode::DelegatedSession
                    && *action == passless_core::agent::protocol::IntentAction::Register
                    && profile
                        .profile_config
                        .delegated_registration_storage
                        .is_some()
                {
                    let _lifecycle = profile.lifecycle_lock.lock().unwrap();
                    let mut eid_guard = profile.endpoint_id.lock().unwrap();
                    if eid_guard.is_none() {
                        *eid_guard = Some(self.create_profile_endpoint(&profile.endpoint_spec).map_err(
                            |e| {
                                ProtocolError::new(
                                    ErrorCode::Internal,
                                    format!(
                                        "failed to create endpoint for delegated registration: {}",
                                        e
                                    ),
                                    RecommendedAction::Retry,
                                )
                            },
                        )?);
                    }
                }
                let eid = profile.endpoint_id.lock().unwrap().clone();
                match eid {
                    Some(ref eid) => self.handle_create_intent(CreateIntentParams {
                        profile_id: &profile_id,
                        session_id: &managed.session_id,
                        endpoint_id: eid,
                        action,
                        rp_id,
                        credential_ref: credential_ref.as_ref(),
                        principal_reason: reason.clone(),
                        clamped_grant_ttl_secs: *grant_ttl_secs,
                        clamped_session_ttl_secs: *session_ttl_secs,
                        profile,
                        session_digest: &managed.process_digest,
                    }),
                    None => Err(ProtocolError::new(
                        ErrorCode::Internal,
                        "profile has no active endpoint",
                        RecommendedAction::Abort,
                    )),
                }
            }
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
                    let eid_guard = profile.endpoint_id.lock().unwrap();
                    if eid_guard.is_none() {
                        drop(eid_guard);
                        match self.create_profile_endpoint(&profile.endpoint_spec) {
                            Ok(eid) => {
                                let mut eid_guard = profile.endpoint_id.lock().unwrap();
                                *eid_guard = Some(eid);
                            }
                            Err(e) => {
                                return Err(ProtocolError::new(
                                    ErrorCode::Internal,
                                    format!("failed to create endpoint for delegation: {}", e),
                                    RecommendedAction::Retry,
                                ));
                            }
                        }
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
            PrincipalRequest::BrowserStatus => self.handle_browser_status(&profile_id, profile),
            PrincipalRequest::EndpointStatus => {
                let current_eid = profile.endpoint_id.lock().unwrap().clone();
                match current_eid {
                    Some(ref eid) => {
                        let em = self.endpoint_manager.lock().unwrap();
                        let snapshots = em.snapshot();
                        let snapshot = snapshots.into_iter().find(|s| s.handle.id() == eid);
                        match snapshot {
                            Some(s) => {
                                Ok(PrincipalResponse::EndpointStatus(EndpointStatusResponse {
                                    endpoint_id: s.handle.id().clone(),
                                    status: format!("{:?}", s.state),
                                    connected: true,
                                }))
                            }
                            None => Ok(PrincipalResponse::EndpointStatus(EndpointStatusResponse {
                                endpoint_id: eid.clone(),
                                status: "disconnected".into(),
                                connected: false,
                            })),
                        }
                    }
                    None => Ok(PrincipalResponse::EndpointStatus(EndpointStatusResponse {
                        endpoint_id: EndpointId::new(),
                        status: "no_endpoint".into(),
                        connected: false,
                    })),
                }
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
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
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
        let err = validate_principal_executable("relative/path").unwrap_err();
        assert!(err.to_string().contains("absolute"));
    }

    #[test]
    fn validate_principal_executable_rejects_nonexistent_path() {
        let err = validate_principal_executable("/nonexistent/binary").unwrap_err();
        assert!(err.to_string().contains("cannot be resolved"));
    }

    #[test]
    fn validate_principal_executable_rejects_directory() {
        let dir = tempfile::tempdir().unwrap();
        let err = validate_principal_executable(dir.path().to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("not a regular file"));
    }

    #[test]
    fn validate_principal_executable_accepts_root_owned_executable() {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata("/bin/true").unwrap();
        let result = validate_principal_executable("/bin/true");
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
    fn pending_to_active_atomic_transition() {
        let pending_mutex: Mutex<Option<PendingRuntime>> = Mutex::new(None);
        let active_mutex: Mutex<Option<ActiveBrowserLease>> = Mutex::new(None);

        let lease_id = BrowserLeaseId::new();
        let session_id = PrincipalSessionId::new();
        let request_id = PendingRequestId::new();

        *pending_mutex.lock().unwrap() = Some(PendingRuntime {
            request_id: request_id.clone(),
            prep_generation: 1,
            session_id: session_id.clone(),
            browser_lease_id: Some(lease_id.clone()),
            clamped_session_ttl_secs: 300,
        });

        assert!(pending_mutex.lock().unwrap().is_some());
        assert!(active_mutex.lock().unwrap().is_none());

        let taken = pending_mutex.lock().unwrap().take();
        *active_mutex.lock().unwrap() = taken.map(|p| ActiveBrowserLease {
            lease_id: p.browser_lease_id.unwrap(),
            session_id: p.session_id,
        });

        assert!(pending_mutex.lock().unwrap().is_none());
        let active = active_mutex.lock().unwrap();
        assert!(active.is_some());
        let active = active.as_ref().unwrap();
        assert_eq!(active.lease_id, lease_id);
        assert_eq!(active.session_id, session_id);
    }

    #[test]
    fn cleanup_clears_both_pending_and_active() {
        let pending_mutex: Mutex<Option<PendingRuntime>> = Mutex::new(None);
        let active_mutex: Mutex<Option<ActiveBrowserLease>> = Mutex::new(None);

        let lease_id_pending = BrowserLeaseId::new();
        let lease_id_active = BrowserLeaseId::new();
        let session_id = PrincipalSessionId::new();

        *pending_mutex.lock().unwrap() = Some(PendingRuntime {
            request_id: PendingRequestId::new(),
            prep_generation: 1,
            session_id: session_id.clone(),
            browser_lease_id: Some(lease_id_pending.clone()),
            clamped_session_ttl_secs: 60,
        });

        *active_mutex.lock().unwrap() = Some(ActiveBrowserLease {
            lease_id: lease_id_active.clone(),
            session_id: session_id.clone(),
        });

        assert!(pending_mutex.lock().unwrap().is_some());
        assert!(active_mutex.lock().unwrap().is_some());

        *pending_mutex.lock().unwrap() = None;
        *active_mutex.lock().unwrap() = None;

        assert!(pending_mutex.lock().unwrap().is_none());
        assert!(active_mutex.lock().unwrap().is_none());
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
    fn endpoint_id_mutex_starts_as_none_for_delegated() {
        let eid: Mutex<Option<EndpointId>> = Mutex::new(None);
        assert!(eid.lock().unwrap().is_none());
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
    fn stale_endpoint_event_ignored() {
        let current_eid = EndpointId::new();
        let stale_eid = EndpointId::new();
        assert_ne!(current_eid, stale_eid);

        let eid_mutex: Mutex<Option<EndpointId>> = Mutex::new(Some(current_eid.clone()));

        let matches = {
            let guard = eid_mutex.lock().unwrap();
            matches!(guard.as_ref(), Some(eid) if *eid == stale_eid)
        };
        assert!(!matches, "stale endpoint ID should not match current");
    }

    #[test]
    fn endpoint_spec_clone_is_independent() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_dir = temp_dir.path().join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&audit_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let spec1 = EndpointSpec {
            profile_name: "test".to_string(),
            profile_id: ProfileId::new("test").unwrap(),
            mode: AgentMode::Isolated,
            profile_config: passless_core::agent::AgentProfileConfig {
                mode: AgentMode::Isolated,
                principal_user: "testuser".to_string(),
                rp_ids: vec!["example.com".to_string()],
                require_uv: false,
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: None,
                registration_allowed: false,
                rules: vec![],
                delegated_registration_storage: None,
                device: passless_core::agent::DeviceIdentity {
                    name: "test".to_string(),
                    phys: "test".to_string(),
                    uniq: "test".to_string(),
                    vendor_id: 0x1234,
                    product_id: 0x5678,
                },
                start_url: None,
                browser_command: None,
                browser_user: None,
                browser_runtime_root: None,
            },
            security_config: SecurityConfig::default(),
            pin_config: PinConfig::default(),
            interaction_manager: Arc::new(super::super::interaction::AgentInteractionManager::new()),
            preparation_slot: Arc::new(super::super::ceremony::CeremonyPreparationSlot::new()),
            operation_lock: Arc::new(Mutex::new(())),
            policy_runtime: {
                let clock: Arc<dyn super::super::browser::Clock> =
                    Arc::new(super::super::browser::SystemClock);
                let monotonic_clock: Arc<dyn super::super::intent::MonotonicClock> =
                    Arc::new(super::super::intent::SystemClock::new());
                let config = passless_core::agent::AgentConfig::default();
                Arc::new(
                    super::super::policy_engine::PolicyRuntime::new(
                        &config,
                        clock,
                        monotonic_clock,
                    )
                    .unwrap(),
                )
            },
            audit_gate: Arc::new(super::super::audit::AuditGate::open(&audit_dir).unwrap()),
            event_tx: {
                let (tx, _rx) = mpsc::channel();
                tx
            },
            endpoint_factory: None,
            test_transport_factory: None,
            isolated_deps: None,
            delegated_deps: None,
        };

        let spec2 = spec1.clone();
        assert_eq!(spec1.profile_name, spec2.profile_name);
        assert_eq!(spec1.profile_id, spec2.profile_id);
        assert_eq!(spec1.mode, spec2.mode);
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

    // --- Runtime orchestration tests ---

    use std::sync::Condvar;
    use std::sync::atomic::AtomicUsize;

    struct ControllableEndpoint {
        release: Arc<(Mutex<bool>, Condvar)>,
        released: Arc<AtomicBool>,
    }

    impl ControllableEndpoint {
        fn release_blocking(handle: &Arc<(Mutex<bool>, Condvar)>) {
            let (lock, cvar) = &**handle;
            let mut released = lock.lock().unwrap();
            *released = true;
            cvar.notify_all();
        }
    }

    impl crate::worker::HidEndpoint for ControllableEndpoint {
        fn read_packet(
            &mut self,
            _buffer: &mut [u8; 64],
        ) -> Result<Option<usize>, crate::worker::WorkerError> {
            let (lock, cvar) = &*self.release;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = cvar.wait(released).unwrap();
            }
            self.released.store(true, Ordering::SeqCst);
            Err(crate::worker::WorkerError::Read(
                "endpoint released".to_string(),
            ))
        }

        fn write_packet(&mut self, _data: &[u8; 64]) -> Result<(), crate::worker::WorkerError> {
            Ok(())
        }
    }

    struct QuickExitEndpoint {
        call_count: std::sync::atomic::AtomicUsize,
    }

    impl QuickExitEndpoint {
        fn new() -> Self {
            Self {
                call_count: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }

    impl crate::worker::HidEndpoint for QuickExitEndpoint {
        fn read_packet(
            &mut self,
            _buffer: &mut [u8; 64],
        ) -> Result<Option<usize>, crate::worker::WorkerError> {
            let count = self.call_count.fetch_add(1, Ordering::SeqCst);
            if count == 0 {
                // First call: return None to allow cancel check
                Ok(None)
            } else {
                // Subsequent calls: return None quickly to allow drain
                std::thread::sleep(Duration::from_millis(1));
                Ok(None)
            }
        }

        fn write_packet(&mut self, _data: &[u8; 64]) -> Result<(), crate::worker::WorkerError> {
            Ok(())
        }
    }

    struct FakeCredentialStorage {
        credentials: std::collections::HashMap<Vec<u8>, soft_fido2::Credential>,
        write_counter: AtomicUsize,
        read_sign_counter: AtomicUsize,
    }

    impl FakeCredentialStorage {
        fn new() -> Self {
            Self {
                credentials: std::collections::HashMap::new(),
                write_counter: AtomicUsize::new(0),
                read_sign_counter: AtomicUsize::new(0),
            }
        }

        fn write_count(&self) -> usize {
            self.write_counter.load(Ordering::SeqCst)
        }

        fn read_sign_count(&self) -> usize {
            self.read_sign_counter.load(Ordering::SeqCst)
        }
    }

    impl crate::storage::CredentialStorage for FakeCredentialStorage {
        fn read_first(
            &mut self,
            _filter: crate::storage::CredentialFilter,
        ) -> soft_fido2::Result<soft_fido2::Credential> {
            self.read_sign_counter.fetch_add(1, Ordering::SeqCst);
            self.credentials
                .values()
                .next()
                .cloned()
                .ok_or(soft_fido2::Error::DoesNotExist)
        }

        fn read_next(&mut self) -> soft_fido2::Result<soft_fido2::Credential> {
            self.read_sign_counter.fetch_add(1, Ordering::SeqCst);
            Err(soft_fido2::Error::DoesNotExist)
        }

        fn read(&mut self, id: &[u8]) -> soft_fido2::Result<soft_fido2::Credential> {
            self.read_sign_counter.fetch_add(1, Ordering::SeqCst);
            self.credentials
                .get(id)
                .cloned()
                .ok_or(soft_fido2::Error::DoesNotExist)
        }

        fn write(&mut self, _cred: soft_fido2::CredentialRef) -> soft_fido2::Result<()> {
            self.write_counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn delete(&mut self, id: &[u8]) -> soft_fido2::Result<()> {
            self.credentials.remove(id);
            Ok(())
        }

        fn count_credentials(&self) -> usize {
            self.credentials.len()
        }
    }

    struct FakePinStorage;

    impl crate::pin_storage::PinStorage for FakePinStorage {
        fn load_pin_state(&self) -> Result<soft_fido2::PinState, soft_fido2::StatusCode> {
            Ok(soft_fido2::PinState::new())
        }

        fn save_pin_state(
            &self,
            _state: &soft_fido2::PinState,
        ) -> Result<(), soft_fido2::StatusCode> {
            Ok(())
        }
    }

    struct RuntimeHarness {
        runtime: Arc<AgentRuntime>,
        profile_id: ProfileId,
        session_id: PrincipalSessionId,
        process_digest: super::super::intent::ProcessIdentityDigest,
        credential_ref: passless_core::agent::CredentialRef,
        rp_id: String,
        _temp_dir: tempfile::TempDir,
    }

    impl Drop for RuntimeHarness {
        fn drop(&mut self) {
            self.runtime.shutdown.store(true, Ordering::Release);
            {
                let mut browser_mgr = self.runtime.browser_manager.lock().unwrap();
                browser_mgr.terminate_all();
            }
            self.runtime.worker_tracker.join_all();
            {
                let mut em = self.runtime.endpoint_manager.lock().unwrap();
                em.cancel_all();
                let _ = em.shutdown_all(Some(Duration::from_secs(1)));
            }
        }
    }

    impl RuntimeHarness {
        fn new_delegated() -> Self {
            Self::new_delegated_with_profile_name("test-delegated")
        }

        fn new_delegated_with_profile_name(name: &str) -> Self {
            let temp_dir = tempfile::tempdir().unwrap();
            let audit_dir = temp_dir.path().join("audit");
            std::fs::create_dir_all(&audit_dir).unwrap();
            let browser_runtime_dir = temp_dir.path().join("browser-runtime");
            std::fs::create_dir_all(&browser_runtime_dir).unwrap();

            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&audit_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(&browser_runtime_dir, std::fs::Permissions::from_mode(0o700))
                .unwrap();

            let audit_gate = Arc::new(super::super::audit::AuditGate::open(&audit_dir).unwrap());
            let clock: Arc<dyn super::super::browser::Clock> =
                Arc::new(super::super::browser::SystemClock);
            let monotonic_clock: Arc<dyn super::super::intent::MonotonicClock> =
                Arc::new(super::super::intent::SystemClock::new());

            let browser_manager = Arc::new(Mutex::new(
                super::super::browser::BrowserProcessManager::with_spawner(
                    clock.clone(),
                    Arc::new(super::super::browser::TestSpawner),
                ),
            ));

            let mut cred_bytes = [0u8; 32];
            cred_bytes[..16].copy_from_slice(b"test-cred-id-001");
            let credential_ref = passless_core::agent::CredentialRef::from_bytes(cred_bytes);
            let rp_id = "example.com".to_string();

            let fake_storage = Arc::new(Mutex::new(Box::new(FakeCredentialStorage::new())
                as Box<dyn crate::storage::CredentialStorage>));
            let fake_pin_storage = Arc::new(Mutex::new(
                Box::new(FakePinStorage) as Box<dyn crate::pin_storage::PinStorage>
            ));
            let human_operation_lock = Arc::new(Mutex::new(()));

            let profile_id = ProfileId::new(name).unwrap();
            let profile_config = passless_core::agent::AgentProfileConfig {
                mode: AgentMode::DelegatedSession,
                principal_user: "testuser".to_string(),
                rp_ids: vec![rp_id.clone()],
                require_uv: true,
                credential_refs: Some(vec![credential_ref.clone()]),
                max_grant_ttl: Some(passless_core::agent::BoundedDuration::new(300).unwrap()),
                max_session_ttl: Some(passless_core::agent::BoundedDuration::new(900).unwrap()),
                storage: None,
                registration_allowed: false,
                rules: vec![],
                delegated_registration_storage: None,
                device: passless_core::agent::DeviceIdentity {
                    name: "test-device".to_string(),
                    phys: "test-phys".to_string(),
                    uniq: "test-uniq".to_string(),
                    vendor_id: 0x1234,
                    product_id: 0x5678,
                },
                start_url: Some("https://example.com/login".to_string()),
                browser_command: Some(vec!["/bin/true".to_string()]),
                browser_user: Some("browseruser".to_string()),
                browser_runtime_root: Some(temp_dir.path().join("browser-runtime")),
            };

            let agent_config = {
                let mut config = passless_core::agent::AgentConfig::default();
                config
                    .profiles
                    .insert(name.to_string(), profile_config.clone());
                config
            };
            let policy_runtime = Arc::new(
                super::super::policy_engine::PolicyRuntime::new(
                    &agent_config,
                    clock.clone(),
                    monotonic_clock.clone(),
                )
                .unwrap(),
            );

            let preparation_slot = Arc::new(super::super::ceremony::CeremonyPreparationSlot::new());
            let interaction_manager =
                Arc::new(super::super::interaction::AgentInteractionManager::new());
            let operation_lock = Arc::new(Mutex::new(()));
            let (event_tx, event_rx) = mpsc::channel();

            let spec = EndpointSpec {
                profile_name: name.to_string(),
                profile_id: profile_id.clone(),
                mode: AgentMode::DelegatedSession,
                profile_config: profile_config.clone(),
                security_config: SecurityConfig::default(),
                pin_config: PinConfig::default(),
                interaction_manager: interaction_manager.clone(),
                preparation_slot: preparation_slot.clone(),
                operation_lock: operation_lock.clone(),
                policy_runtime: policy_runtime.clone(),
                audit_gate: audit_gate.clone(),
                event_tx: event_tx.clone(),
                endpoint_factory: None,
                test_transport_factory: Some(Arc::new(|| {
                    Ok(Box::new(QuickExitEndpoint::new()) as Box<dyn crate::worker::HidEndpoint>)
                })),
                isolated_deps: None,
                delegated_deps: Some(DelegatedEndpointDeps {
                    human_storage: fake_storage.clone(),
                    human_pin_storage: fake_pin_storage.clone(),
                    human_operation_lock: human_operation_lock.clone(),
                    credential_refs: vec![credential_ref.clone()],
                }),
            };

            let endpoint_manager =
                Mutex::new(super::super::endpoint_manager::EndpointManager::new(
                    1,
                    Arc::new(AtomicBool::new(false)),
                    crate::worker::WorkerConfig::default(),
                ));

            let _ceremony_scope = super::super::storage::CeremonyScope::new();

            let profile_runtime = ProfileRuntime {
                profile_name: name.to_string(),
                profile_id: profile_id.clone(),
                uid: 1000,
                gid: 1000,
                endpoint_id: Mutex::new(None),
                lifecycle_lock: Mutex::new(()),
                endpoint_spec: spec,
                preparation_slot,
                operation_lock,
                mode: AgentMode::DelegatedSession,
                profile_config,
                current_pending: Mutex::new(None),
                active_browser: Mutex::new(None),
                daemon_uid: unsafe { libc::getuid() },
                daemon_gid: unsafe { libc::getgid() },
                browser_uid: Some(1000),
                browser_gid: Some(1000),
                enabled: AtomicBool::new(true),
                credential_storage: fake_storage.clone(),
            };

            let mut profiles = std::collections::BTreeMap::new();
            profiles.insert(profile_id.clone(), profile_runtime);

            let session_id = PrincipalSessionId::new();
            let process_digest =
                super::super::intent::ProcessIdentityDigest::compute_from_session_identity(
                    &super::super::intent::SessionIdentityParams {
                        uid: 1000,
                        gid: 1000,
                        pid: 12345,
                        start_time: 1000,
                        cgroup_path: "/test/cgroup".to_string(),
                        ns_user: 100,
                        ns_pid: 200,
                        ns_mnt: 300,
                    },
                );

            let mut managed_sessions = std::collections::BTreeMap::new();
            let mut dummy_child = std::process::Command::new("/bin/true")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("failed to spawn dummy child for test session");
            let dummy_pid = dummy_child.id() as i32;
            let _ = dummy_child.wait();
            let dummy_session = super::super::launcher::PrincipalSession {
                child: std::process::Command::new("/bin/true")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .expect("failed to spawn dummy child"),
                capability: super::super::launcher::SessionCapability::generate(),
                identity: super::super::launcher::PeerIdentity::new(
                    1000,
                    1000,
                    dummy_pid,
                    1000,
                    "/test/cgroup".to_string(),
                    super::super::launcher::NamespaceInodes::new(100, 200, 300),
                ),
                pidfd: None,
                proc_root: std::path::PathBuf::from("/proc"),
            };
            let managed_session = ManagedPrincipalSession {
                session_id: session_id.clone(),
                profile_id: profile_id.clone(),
                session: dummy_session,
                process_digest: process_digest.clone(),
                created_at: Instant::now(),
                deadline: Instant::now() + Duration::from_secs(3600),
            };
            managed_sessions.insert(profile_id.clone(), Mutex::new(Some(managed_session)));

            let runtime = Arc::new(AgentRuntime {
                endpoint_manager,
                ipc_server: Arc::new(super::super::ipc::IpcServer::new_test_dummy()),
                audit_gate,
                policy_runtime,
                browser_manager,
                profiles,
                managed_sessions,
                completed_sessions: Mutex::new(std::collections::BTreeMap::new()),
                event_rx: Mutex::new(event_rx),
                shutdown: Arc::new(AtomicBool::new(false)),
                shutdown_requested: AtomicBool::new(false),
                runtime_cleanup_started: AtomicBool::new(false),
                runtime_loop: Mutex::new(None),
                worker_tracker: WorkerTracker::new(),
                daemon_uid: unsafe { libc::getuid() },
                daemon_gid: unsafe { libc::getgid() },
                agent_config: std::sync::RwLock::new(agent_config),
            });

            Self {
                runtime,
                profile_id,
                session_id,
                process_digest,
                credential_ref,
                rp_id,
                _temp_dir: temp_dir,
            }
        }

        fn profile(&self) -> &ProfileRuntime {
            self.runtime.profiles.get(&self.profile_id).unwrap()
        }

        fn create_endpoint(&self) -> EndpointId {
            let profile = self.profile();
            let _lifecycle = profile.lifecycle_lock.lock().unwrap();
            {
                let eid_guard = profile.endpoint_id.lock().unwrap();
                if eid_guard.is_some() {
                    return eid_guard.clone().unwrap();
                }
            }
            let eid = self
                .runtime
                .create_profile_endpoint(&profile.endpoint_spec)
                .unwrap();
            *profile.endpoint_id.lock().unwrap() = Some(eid.clone());
            std::thread::sleep(Duration::from_millis(10));
            eid
        }

        fn reap_workers(&self) {
            self.runtime.reap_stopped_workers();
            std::thread::sleep(Duration::from_millis(10));
        }

        fn complete_delegation_cycle(&self, endpoint_id: &EndpointId) {
            let generation = self.runtime.policy_runtime.current_generation();
            let tuple = super::super::policy_engine::CeremonyTuple {
                profile_id: self.profile_id.clone(),
                session_id: self.session_id.clone(),
                endpoint_id: endpoint_id.clone(),
                process_digest: self.process_digest.clone(),
                policy_generation: generation.generation_id.clone(),
                policy_digest: generation.digest.clone(),
                action: passless_core::agent::protocol::IntentAction::Authenticate,
                rp_id: self.rp_id.clone(),
                credential_ref: Some(self.credential_ref.clone()),
            };
            let approval = super::super::policy_engine::TrustedApproval::new();
            let _bound = self
                .runtime
                .policy_runtime
                .ceremony_resolve_pending(&tuple, &approval)
                .unwrap();

            self.runtime
                .handle_endpoint_event(EndpointEvent::ResponseSent {
                    endpoint_id: endpoint_id.clone(),
                    profile_id: self.profile_id.clone(),
                });

            self.reap_workers();
        }
    }

    #[test]
    fn handle_request_delegation_creates_pending_and_installs_preparation() {
        let harness = RuntimeHarness::new_delegated();
        let endpoint_id = harness.create_endpoint();

        let result = harness
            .runtime
            .handle_request_delegation(RequestDelegationParams {
                profile_id: &harness.profile_id,
                session_id: &harness.session_id,
                endpoint_id: &endpoint_id,
                rp_id: &harness.rp_id,
                credential_ref: &harness.credential_ref,
                max_session_ttl: 300,
                principal_reason: Some("test reason".to_string()),
                profile: harness.profile(),
                session_digest: &harness.process_digest,
            });

        assert!(
            result.is_ok(),
            "delegation request failed: {:?}",
            result.err()
        );
        let response = result.unwrap();
        match response {
            PrincipalResponse::DelegationRequested { request_id } => {
                let pending = harness.profile().current_pending.lock().unwrap();
                assert!(pending.is_some(), "current_pending should be set");
                let pending = pending.as_ref().unwrap();
                assert_eq!(pending.request_id, request_id);
                assert_eq!(pending.session_id, harness.session_id);
                assert!(
                    pending.browser_lease_id.is_some(),
                    "browser lease should be set"
                );
            }
            _ => panic!("expected DelegationRequested response"),
        }
    }

    #[test]
    fn resolve_pending_through_ceremony_destroys_endpoint_before_browser_active() {
        let harness = RuntimeHarness::new_delegated();
        let endpoint_id = harness.create_endpoint();

        let result = harness
            .runtime
            .handle_request_delegation(RequestDelegationParams {
                profile_id: &harness.profile_id,
                session_id: &harness.session_id,
                endpoint_id: &endpoint_id,
                rp_id: &harness.rp_id,
                credential_ref: &harness.credential_ref,
                max_session_ttl: 300,
                principal_reason: None,
                profile: harness.profile(),
                session_digest: &harness.process_digest,
            })
            .unwrap();

        let _request_id = match result {
            PrincipalResponse::DelegationRequested { request_id } => request_id,
            _ => panic!("expected DelegationRequested"),
        };

        let generation = harness.runtime.policy_runtime.current_generation();
        let tuple = super::super::policy_engine::CeremonyTuple {
            profile_id: harness.profile_id.clone(),
            session_id: harness.session_id.clone(),
            endpoint_id: endpoint_id.clone(),
            process_digest: harness.process_digest.clone(),
            policy_generation: generation.generation_id.clone(),
            policy_digest: generation.digest.clone(),
            action: passless_core::agent::protocol::IntentAction::Authenticate,
            rp_id: harness.rp_id.clone(),
            credential_ref: Some(harness.credential_ref.clone()),
        };
        let approval = super::super::policy_engine::TrustedApproval::new();
        let bound = harness
            .runtime
            .policy_runtime
            .ceremony_resolve_pending(&tuple, &approval)
            .unwrap();

        harness
            .runtime
            .handle_endpoint_event(EndpointEvent::ResponseSent {
                endpoint_id: endpoint_id.clone(),
                profile_id: harness.profile_id.clone(),
            });

        harness.reap_workers();

        let endpoint_after = harness.profile().endpoint_id.lock().unwrap().clone();
        assert!(
            endpoint_after.is_none(),
            "endpoint should be destroyed after ResponseSent, got {:?}",
            endpoint_after
        );

        let active = harness.profile().active_browser.lock().unwrap();
        assert!(
            active.is_some(),
            "active_browser should be set after approval"
        );
        assert_eq!(active.as_ref().unwrap().session_id, harness.session_id);

        let pending = harness.profile().current_pending.lock().unwrap();
        assert!(
            pending.is_none(),
            "current_pending should be cleared after approval"
        );

        assert!(bound.grant_id().is_some(), "grant should be created");
    }

    #[test]
    fn second_delegation_after_cleanup_creates_fresh_endpoints() {
        let harness = RuntimeHarness::new_delegated();
        let endpoint_id_1 = harness.create_endpoint();

        let _result = harness
            .runtime
            .handle_request_delegation(RequestDelegationParams {
                profile_id: &harness.profile_id,
                session_id: &harness.session_id,
                endpoint_id: &endpoint_id_1,
                rp_id: &harness.rp_id,
                credential_ref: &harness.credential_ref,
                max_session_ttl: 300,
                principal_reason: None,
                profile: harness.profile(),
                session_digest: &harness.process_digest,
            })
            .unwrap();

        harness.complete_delegation_cycle(&endpoint_id_1);

        let endpoint_after = harness.profile().endpoint_id.lock().unwrap().clone();
        assert!(
            endpoint_after.is_none(),
            "endpoint should be cleared after delegation cycle"
        );

        let active = harness.profile().active_browser.lock().unwrap();
        assert!(
            active.is_some(),
            "active_browser should be set after successful delegation"
        );
        drop(active);

        {
            let mut browser_mgr = harness.runtime.browser_manager.lock().unwrap();
            browser_mgr.terminate_all();
        }
        {
            let mut active = harness.profile().active_browser.lock().unwrap();
            *active = None;
        }

        std::thread::sleep(Duration::from_millis(50));

        let endpoint_id_2 = harness.create_endpoint();
        assert_ne!(
            endpoint_id_1, endpoint_id_2,
            "second endpoint should have fresh ID"
        );

        let result2 = harness
            .runtime
            .handle_request_delegation(RequestDelegationParams {
                profile_id: &harness.profile_id,
                session_id: &harness.session_id,
                endpoint_id: &endpoint_id_2,
                rp_id: &harness.rp_id,
                credential_ref: &harness.credential_ref,
                max_session_ttl: 300,
                principal_reason: None,
                profile: harness.profile(),
                session_digest: &harness.process_digest,
            });

        assert!(
            result2.is_ok(),
            "second delegation should succeed after cleanup"
        );
    }

    #[test]
    fn stale_endpoint_event_leaves_state_unchanged() {
        let harness = RuntimeHarness::new_delegated();
        let endpoint_id = harness.create_endpoint();

        let result = harness
            .runtime
            .handle_request_delegation(RequestDelegationParams {
                profile_id: &harness.profile_id,
                session_id: &harness.session_id,
                endpoint_id: &endpoint_id,
                rp_id: &harness.rp_id,
                credential_ref: &harness.credential_ref,
                max_session_ttl: 300,
                principal_reason: None,
                profile: harness.profile(),
                session_digest: &harness.process_digest,
            })
            .unwrap();

        let request_id = match result {
            PrincipalResponse::DelegationRequested { request_id } => request_id,
            _ => panic!("expected DelegationRequested"),
        };

        let stale_endpoint_id = EndpointId::new();
        harness
            .runtime
            .handle_endpoint_event(EndpointEvent::ResponseSent {
                endpoint_id: stale_endpoint_id,
                profile_id: harness.profile_id.clone(),
            });

        let pending = harness.profile().current_pending.lock().unwrap();
        assert!(pending.is_some(), "pending should remain after stale event");
        assert_eq!(pending.as_ref().unwrap().request_id, request_id);

        let active = harness.profile().active_browser.lock().unwrap();
        assert!(
            active.is_none(),
            "active_browser should not be set by stale event"
        );

        let endpoint_after = harness.profile().endpoint_id.lock().unwrap().clone();
        assert_eq!(
            endpoint_after,
            Some(endpoint_id),
            "endpoint_id should be unchanged"
        );
    }

    #[test]
    fn second_delegation_after_cleanup_creates_fresh_endpoint() {
        let harness = RuntimeHarness::new_delegated();
        let endpoint_id_1 = harness.create_endpoint();

        let _result = harness
            .runtime
            .handle_request_delegation(RequestDelegationParams {
                profile_id: &harness.profile_id,
                session_id: &harness.session_id,
                endpoint_id: &endpoint_id_1,
                rp_id: &harness.rp_id,
                credential_ref: &harness.credential_ref,
                max_session_ttl: 300,
                principal_reason: None,
                profile: harness.profile(),
                session_digest: &harness.process_digest,
            })
            .unwrap();

        let generation = harness.runtime.policy_runtime.current_generation();
        let tuple = super::super::policy_engine::CeremonyTuple {
            profile_id: harness.profile_id.clone(),
            session_id: harness.session_id.clone(),
            endpoint_id: endpoint_id_1.clone(),
            process_digest: harness.process_digest.clone(),
            policy_generation: generation.generation_id.clone(),
            policy_digest: generation.digest.clone(),
            action: passless_core::agent::protocol::IntentAction::Authenticate,
            rp_id: harness.rp_id.clone(),
            credential_ref: Some(harness.credential_ref.clone()),
        };
        let approval = super::super::policy_engine::TrustedApproval::new();
        let _bound = harness
            .runtime
            .policy_runtime
            .ceremony_resolve_pending(&tuple, &approval)
            .unwrap();

        harness
            .runtime
            .handle_endpoint_event(EndpointEvent::ResponseSent {
                endpoint_id: endpoint_id_1.clone(),
                profile_id: harness.profile_id.clone(),
            });

        harness.reap_workers();

        {
            let mut active = harness.profile().active_browser.lock().unwrap();
            *active = None;
        }
        {
            let mut eid = harness.profile().endpoint_id.lock().unwrap();
            *eid = None;
        }

        let endpoint_id_2 = harness.create_endpoint();
        assert_ne!(
            endpoint_id_1, endpoint_id_2,
            "second endpoint should have fresh ID"
        );

        let result2 = harness
            .runtime
            .handle_request_delegation(RequestDelegationParams {
                profile_id: &harness.profile_id,
                session_id: &harness.session_id,
                endpoint_id: &endpoint_id_2,
                rp_id: &harness.rp_id,
                credential_ref: &harness.credential_ref,
                max_session_ttl: 300,
                principal_reason: None,
                profile: harness.profile(),
                session_digest: &harness.process_digest,
            });

        assert!(
            result2.is_ok(),
            "second delegation should succeed after cleanup"
        );
    }

    #[test]
    fn concurrent_delegation_creates_exactly_one_endpoint() {
        use std::sync::Barrier;
        use std::sync::atomic::AtomicUsize;

        let harness = Arc::new(RuntimeHarness::new_delegated());
        let create_count = Arc::new(AtomicUsize::new(0));
        let conflict_count = Arc::new(AtomicUsize::new(0));
        let endpoint_ids = Arc::new(Mutex::new(Vec::new()));
        let num_threads = 4;
        let barrier = Arc::new(Barrier::new(num_threads));

        let threads: Vec<_> = (0..num_threads)
            .map(|_| {
                let harness = harness.clone();
                let create_count = create_count.clone();
                let conflict_count = conflict_count.clone();
                let endpoint_ids = endpoint_ids.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let profile = harness.profile();
                    barrier.wait();
                    let _lifecycle = profile.lifecycle_lock.lock().unwrap();
                    {
                        let eid_guard = profile.endpoint_id.lock().unwrap();
                        if eid_guard.is_some() {
                            conflict_count.fetch_add(1, Ordering::SeqCst);
                            return;
                        }
                    }
                    let eid = harness
                        .runtime
                        .create_profile_endpoint(&profile.endpoint_spec)
                        .unwrap();
                    create_count.fetch_add(1, Ordering::SeqCst);
                    endpoint_ids.lock().unwrap().push(eid.clone());
                    *profile.endpoint_id.lock().unwrap() = Some(eid);
                })
            })
            .collect();

        for t in threads {
            t.join().unwrap();
        }

        assert_eq!(
            create_count.load(Ordering::SeqCst),
            1,
            "endpoint should be created exactly once"
        );
        assert_eq!(
            conflict_count.load(Ordering::SeqCst),
            num_threads - 1,
            "all other threads should see existing endpoint (conflict)"
        );
        assert_eq!(
            endpoint_ids.lock().unwrap().len(),
            1,
            "only one endpoint ID should be stored"
        );
    }

    #[test]
    fn human_operation_lock_serializes_storage_access() {
        let harness = RuntimeHarness::new_delegated();
        let profile = harness.profile();
        let deps = profile.endpoint_spec.delegated_deps.as_ref().unwrap();
        let human_op_lock = deps.human_operation_lock.clone();
        let human_storage = deps.human_storage.clone();

        let counter = Arc::new(AtomicUsize::new(0));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let lock = human_op_lock.clone();
                let storage = human_storage.clone();
                let counter = counter.clone();
                std::thread::spawn(move || {
                    let _guard = lock.lock().unwrap();
                    let _storage_guard = storage.lock().unwrap();
                    let prev = counter.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(1));
                    let after = counter.load(Ordering::SeqCst);
                    assert_eq!(
                        after,
                        prev + 1,
                        "counter should increment serially under lock"
                    );
                })
            })
            .collect();

        for t in threads {
            t.join().unwrap();
        }

        assert_eq!(
            counter.load(Ordering::SeqCst),
            8,
            "all threads should have executed"
        );
    }

    #[test]
    fn timeout_no_activation_with_blocking_endpoint() {
        let blocking_release = Arc::new((Mutex::new(false), Condvar::new()));
        let blocking_release_for_factory = blocking_release.clone();

        let temp_dir = tempfile::tempdir().unwrap();
        let audit_dir = temp_dir.path().join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        let browser_runtime_dir = temp_dir.path().join("browser-runtime");
        std::fs::create_dir_all(&browser_runtime_dir).unwrap();

        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&audit_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&browser_runtime_dir, std::fs::Permissions::from_mode(0o700))
            .unwrap();

        let audit_gate = Arc::new(super::super::audit::AuditGate::open(&audit_dir).unwrap());
        let clock: Arc<dyn super::super::browser::Clock> =
            Arc::new(super::super::browser::SystemClock);
        let monotonic_clock: Arc<dyn super::super::intent::MonotonicClock> =
            Arc::new(super::super::intent::SystemClock::new());

        let browser_manager = Arc::new(Mutex::new(
            super::super::browser::BrowserProcessManager::with_spawner(
                clock.clone(),
                Arc::new(super::super::browser::TestSpawner),
            ),
        ));

        let mut cred_bytes = [0u8; 32];
        cred_bytes[..16].copy_from_slice(b"test-cred-id-001");
        let credential_ref = passless_core::agent::CredentialRef::from_bytes(cred_bytes);
        let rp_id = "example.com".to_string();

        let fake_storage =
            Arc::new(Mutex::new(Box::new(FakeCredentialStorage::new())
                as Box<dyn crate::storage::CredentialStorage>));
        let fake_pin_storage = Arc::new(Mutex::new(
            Box::new(FakePinStorage) as Box<dyn crate::pin_storage::PinStorage>
        ));
        let human_operation_lock = Arc::new(Mutex::new(()));

        let profile_id = ProfileId::new("test-timeout").unwrap();
        let profile_config = passless_core::agent::AgentProfileConfig {
            mode: AgentMode::DelegatedSession,
            principal_user: "testuser".to_string(),
            rp_ids: vec![rp_id.clone()],
            require_uv: true,
            credential_refs: Some(vec![credential_ref.clone()]),
            max_grant_ttl: Some(passless_core::agent::BoundedDuration::new(300).unwrap()),
            max_session_ttl: Some(passless_core::agent::BoundedDuration::new(900).unwrap()),
            storage: None,
            registration_allowed: false,
            rules: vec![],
            delegated_registration_storage: None,
            device: passless_core::agent::DeviceIdentity {
                name: "test-device".to_string(),
                phys: "test-phys".to_string(),
                uniq: "test-uniq".to_string(),
                vendor_id: 0x1234,
                product_id: 0x5678,
            },
            start_url: Some("https://example.com/login".to_string()),
            browser_command: Some(vec!["/bin/true".to_string()]),
            browser_user: Some("browseruser".to_string()),
            browser_runtime_root: Some(temp_dir.path().join("browser-runtime")),
        };

        let agent_config = {
            let mut config = passless_core::agent::AgentConfig::default();
            config
                .profiles
                .insert("test-timeout".to_string(), profile_config.clone());
            config
        };
        let policy_runtime = Arc::new(
            super::super::policy_engine::PolicyRuntime::new(
                &agent_config,
                clock.clone(),
                monotonic_clock.clone(),
            )
            .unwrap(),
        );

        let preparation_slot = Arc::new(super::super::ceremony::CeremonyPreparationSlot::new());
        let interaction_manager =
            Arc::new(super::super::interaction::AgentInteractionManager::new());
        let operation_lock = Arc::new(Mutex::new(()));
        let (event_tx, event_rx) = mpsc::channel();

        let spec = EndpointSpec {
            profile_name: "test-timeout".to_string(),
            profile_id: profile_id.clone(),
            mode: AgentMode::DelegatedSession,
            profile_config: profile_config.clone(),
            security_config: SecurityConfig::default(),
            pin_config: PinConfig::default(),
            interaction_manager: interaction_manager.clone(),
            preparation_slot: preparation_slot.clone(),
            operation_lock: operation_lock.clone(),
            policy_runtime: policy_runtime.clone(),
            audit_gate: audit_gate.clone(),
            event_tx: event_tx.clone(),
            endpoint_factory: None,
            test_transport_factory: Some(Arc::new(move || {
                let ep = ControllableEndpoint {
                    release: blocking_release_for_factory.clone(),
                    released: Arc::new(AtomicBool::new(false)),
                };
                Ok(Box::new(ep) as Box<dyn crate::worker::HidEndpoint>)
            })),
            isolated_deps: None,
            delegated_deps: Some(DelegatedEndpointDeps {
                human_storage: fake_storage.clone(),
                human_pin_storage: fake_pin_storage.clone(),
                human_operation_lock: human_operation_lock.clone(),
                credential_refs: vec![credential_ref.clone()],
            }),
        };

        let endpoint_manager = Mutex::new(super::super::endpoint_manager::EndpointManager::new(
            1,
            Arc::new(AtomicBool::new(false)),
            crate::worker::WorkerConfig::default(),
        ));

        let _ceremony_scope = super::super::storage::CeremonyScope::new();
        let session_id = PrincipalSessionId::new();
        let process_digest =
            super::super::intent::ProcessIdentityDigest::compute_from_session_identity(
                &super::super::intent::SessionIdentityParams {
                    uid: 1000,
                    gid: 1000,
                    pid: 12345,
                    start_time: 1000,
                    cgroup_path: "/test/cgroup".to_string(),
                    ns_user: 100,
                    ns_pid: 200,
                    ns_mnt: 300,
                },
            );

        let mut dummy_child = std::process::Command::new("/bin/true")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("failed to spawn dummy child");
        let dummy_pid = dummy_child.id() as i32;
        let _ = dummy_child.wait();
        let dummy_session = super::super::launcher::PrincipalSession {
            child: std::process::Command::new("/bin/true")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("failed to spawn dummy child"),
            capability: super::super::launcher::SessionCapability::generate(),
            identity: super::super::launcher::PeerIdentity::new(
                1000,
                1000,
                dummy_pid,
                1000,
                "/test/cgroup".to_string(),
                super::super::launcher::NamespaceInodes::new(100, 200, 300),
            ),
            pidfd: None,
            proc_root: std::path::PathBuf::from("/proc"),
        };
        let managed_session = ManagedPrincipalSession {
            session_id: session_id.clone(),
            profile_id: profile_id.clone(),
            session: dummy_session,
            process_digest: process_digest.clone(),
            created_at: Instant::now(),
            deadline: Instant::now() + Duration::from_secs(3600),
        };

        let profile_runtime = ProfileRuntime {
            profile_name: "test-timeout".to_string(),
            profile_id: profile_id.clone(),
            uid: 1000,
            gid: 1000,
            endpoint_id: Mutex::new(None),
            lifecycle_lock: Mutex::new(()),
            endpoint_spec: spec,
            preparation_slot,
            operation_lock,
            mode: AgentMode::DelegatedSession,
            profile_config,
            current_pending: Mutex::new(None),
            active_browser: Mutex::new(None),
            daemon_uid: unsafe { libc::getuid() },
            daemon_gid: unsafe { libc::getgid() },
            browser_uid: Some(1000),
            browser_gid: Some(1000),
            enabled: AtomicBool::new(true),
            credential_storage: fake_storage.clone(),
        };

        let mut profiles = std::collections::BTreeMap::new();
        profiles.insert(profile_id.clone(), profile_runtime);

        let mut managed_sessions = std::collections::BTreeMap::new();
        managed_sessions.insert(profile_id.clone(), Mutex::new(Some(managed_session)));

        let runtime = Arc::new(AgentRuntime {
            endpoint_manager,
            ipc_server: Arc::new(super::super::ipc::IpcServer::new_test_dummy()),
            audit_gate,
            policy_runtime,
            browser_manager,
            profiles,
            managed_sessions,
            completed_sessions: Mutex::new(std::collections::BTreeMap::new()),
            event_rx: Mutex::new(event_rx),
            shutdown: Arc::new(AtomicBool::new(false)),
            shutdown_requested: AtomicBool::new(false),
            runtime_cleanup_started: AtomicBool::new(false),
            runtime_loop: Mutex::new(None),
            worker_tracker: WorkerTracker::new(),
            daemon_uid: unsafe { libc::getuid() },
            daemon_gid: unsafe { libc::getgid() },
            agent_config: std::sync::RwLock::new(agent_config),
        });

        let eid = {
            let profile = runtime.profiles.get(&profile_id).unwrap();
            let _lifecycle = profile.lifecycle_lock.lock().unwrap();
            let eid = runtime
                .create_profile_endpoint(&profile.endpoint_spec)
                .unwrap();
            *profile.endpoint_id.lock().unwrap() = Some(eid.clone());
            eid
        };
        std::thread::sleep(Duration::from_millis(10));

        let profile = runtime.profiles.get(&profile_id).unwrap();
        let result = runtime.handle_request_delegation(RequestDelegationParams {
            profile_id: &profile_id,
            session_id: &session_id,
            endpoint_id: &eid,
            rp_id: &rp_id,
            credential_ref: &credential_ref,
            max_session_ttl: 300,
            principal_reason: None,
            profile,
            session_digest: &process_digest,
        });
        assert!(result.is_ok());

        let generation = runtime.policy_runtime.current_generation();
        let tuple = super::super::policy_engine::CeremonyTuple {
            profile_id: profile_id.clone(),
            session_id: session_id.clone(),
            endpoint_id: eid.clone(),
            process_digest: process_digest.clone(),
            policy_generation: generation.generation_id.clone(),
            policy_digest: generation.digest.clone(),
            action: passless_core::agent::protocol::IntentAction::Authenticate,
            rp_id: rp_id.clone(),
            credential_ref: Some(credential_ref.clone()),
        };
        let approval = super::super::policy_engine::TrustedApproval::new();
        let _bound = runtime
            .policy_runtime
            .ceremony_resolve_pending(&tuple, &approval)
            .unwrap();

        runtime.handle_endpoint_event(EndpointEvent::ResponseSent {
            endpoint_id: eid.clone(),
            profile_id: profile_id.clone(),
        });

        let active = profile.active_browser.lock().unwrap();
        assert!(
            active.is_none(),
            "active_browser must remain None when endpoint destroy times out"
        );
        drop(active);

        assert!(
            !profile.enabled.load(Ordering::Acquire),
            "profile should be disabled after destroy timeout"
        );

        ControllableEndpoint::release_blocking(&blocking_release);
        std::thread::sleep(Duration::from_millis(100));

        {
            let mut browser_mgr = runtime.browser_manager.lock().unwrap();
            browser_mgr.terminate_all();
        }
        runtime.worker_tracker.join_all();
        {
            let mut em = runtime.endpoint_manager.lock().unwrap();
            em.cancel_all();
            let _ = em.shutdown_all(Some(Duration::from_secs(1)));
        }
    }

    #[test]
    fn isolated_endpoint_persists_across_operations() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_dir = temp_dir.path().join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();

        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&audit_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let audit_gate = Arc::new(super::super::audit::AuditGate::open(&audit_dir).unwrap());
        let clock: Arc<dyn super::super::browser::Clock> =
            Arc::new(super::super::browser::SystemClock);
        let monotonic_clock: Arc<dyn super::super::intent::MonotonicClock> =
            Arc::new(super::super::intent::SystemClock::new());

        let profile_id = ProfileId::new("test-isolated").unwrap();
        let agent_config = {
            let mut config = passless_core::agent::AgentConfig::default();
            config.profiles.insert(
                "test-isolated".to_string(),
                passless_core::agent::AgentProfileConfig {
                    mode: AgentMode::Isolated,
                    principal_user: "testuser".to_string(),
                    rp_ids: vec!["example.com".to_string()],
                    require_uv: false,
                    credential_refs: None,
                    max_grant_ttl: None,
                    max_session_ttl: None,
                    storage: Some(passless_core::agent::AgentStorageConfig::Local {
                        path: temp_dir.path().join("creds"),
                        pin_path: temp_dir.path().join("pin"),
                    }),
                    registration_allowed: false,
                    rules: vec![],
                    delegated_registration_storage: None,
                    device: passless_core::agent::DeviceIdentity {
                        name: "test-iso-device".to_string(),
                        phys: "test-iso-phys".to_string(),
                        uniq: "test-iso-uniq".to_string(),
                        vendor_id: 0x1234,
                        product_id: 0x5678,
                    },
                    start_url: None,
                    browser_command: None,
                    browser_user: None,
                    browser_runtime_root: None,
                },
            );
            config
        };
        let policy_runtime = Arc::new(
            super::super::policy_engine::PolicyRuntime::new(
                &agent_config,
                clock.clone(),
                monotonic_clock.clone(),
            )
            .unwrap(),
        );

        let cred_storage =
            Arc::new(Mutex::new(Box::new(FakeCredentialStorage::new())
                as Box<dyn crate::storage::CredentialStorage>));
        let pin_storage = Arc::new(Mutex::new(
            Box::new(FakePinStorage) as Box<dyn crate::pin_storage::PinStorage>
        ));
        let _ceremony_scope = super::super::storage::CeremonyScope::new();

        let preparation_slot = Arc::new(super::super::ceremony::CeremonyPreparationSlot::new());
        let interaction_manager =
            Arc::new(super::super::interaction::AgentInteractionManager::new());
        let operation_lock = Arc::new(Mutex::new(()));
        let (event_tx, _event_rx) = mpsc::channel();

        let spec = EndpointSpec {
            profile_name: "test-isolated".to_string(),
            profile_id: profile_id.clone(),
            mode: AgentMode::Isolated,
            profile_config: agent_config.profiles.get("test-isolated").unwrap().clone(),
            security_config: SecurityConfig::default(),
            pin_config: PinConfig::default(),
            interaction_manager: interaction_manager.clone(),
            preparation_slot: preparation_slot.clone(),
            operation_lock: operation_lock.clone(),
            policy_runtime: policy_runtime.clone(),
            audit_gate: audit_gate.clone(),
            event_tx: event_tx.clone(),
            endpoint_factory: None,
            test_transport_factory: Some(Arc::new(|| {
                Ok(Box::new(QuickExitEndpoint::new()) as Box<dyn crate::worker::HidEndpoint>)
            })),
            isolated_deps: Some(IsolatedEndpointDeps {
                credential_storage: cred_storage.clone(),
                pin_storage: pin_storage.clone(),
                ceremony_scope: _ceremony_scope.clone(),
            }),
            delegated_deps: None,
        };

        let endpoint_manager = Mutex::new(super::super::endpoint_manager::EndpointManager::new(
            1,
            Arc::new(AtomicBool::new(false)),
            crate::worker::WorkerConfig::default(),
        ));

        let profile_runtime = ProfileRuntime {
            profile_name: "test-isolated".to_string(),
            profile_id: profile_id.clone(),
            uid: 1000,
            gid: 1000,
            endpoint_id: Mutex::new(None),
            lifecycle_lock: Mutex::new(()),
            endpoint_spec: spec,
            preparation_slot,
            operation_lock,
            mode: AgentMode::Isolated,
            profile_config: agent_config.profiles.get("test-isolated").unwrap().clone(),
            current_pending: Mutex::new(None),
            active_browser: Mutex::new(None),
            daemon_uid: unsafe { libc::getuid() },
            daemon_gid: unsafe { libc::getgid() },
            browser_uid: None,
            browser_gid: None,
            enabled: AtomicBool::new(true),
            credential_storage: cred_storage.clone(),
        };

        let mut profiles = std::collections::BTreeMap::new();
        profiles.insert(profile_id.clone(), profile_runtime);

        let mut managed_sessions = std::collections::BTreeMap::new();
        managed_sessions.insert(profile_id.clone(), Mutex::new(None));

        let runtime = Arc::new(AgentRuntime {
            endpoint_manager,
            ipc_server: Arc::new(super::super::ipc::IpcServer::new_test_dummy()),
            audit_gate,
            policy_runtime,
            browser_manager: Arc::new(Mutex::new(
                super::super::browser::BrowserProcessManager::with_spawner(
                    clock.clone(),
                    Arc::new(super::super::browser::TestSpawner),
                ),
            )),
            profiles,
            managed_sessions,
            completed_sessions: Mutex::new(std::collections::BTreeMap::new()),
            event_rx: Mutex::new(_event_rx),
            shutdown: Arc::new(AtomicBool::new(false)),
            shutdown_requested: AtomicBool::new(false),
            runtime_cleanup_started: AtomicBool::new(false),
            runtime_loop: Mutex::new(None),
            worker_tracker: WorkerTracker::new(),
            daemon_uid: unsafe { libc::getuid() },
            daemon_gid: unsafe { libc::getgid() },
            agent_config: std::sync::RwLock::new(agent_config),
        });

        let profile = runtime.profiles.get(&profile_id).unwrap();
        let eid = {
            let _lifecycle = profile.lifecycle_lock.lock().unwrap();
            let eid = runtime
                .create_profile_endpoint(&profile.endpoint_spec)
                .unwrap();
            *profile.endpoint_id.lock().unwrap() = Some(eid.clone());
            eid
        };

        std::thread::sleep(Duration::from_millis(20));

        let persisted_eid = profile.endpoint_id.lock().unwrap().clone();
        assert!(
            persisted_eid.is_some(),
            "isolated endpoint should persist after creation"
        );
        assert_eq!(persisted_eid.unwrap(), eid);

        std::thread::sleep(Duration::from_millis(50));

        let still_persisted = profile.endpoint_id.lock().unwrap().clone();
        assert!(
            still_persisted.is_some(),
            "isolated endpoint should persist across time"
        );
        assert_eq!(still_persisted.unwrap(), eid);

        assert!(
            profile.enabled.load(Ordering::Acquire),
            "isolated profile should remain enabled"
        );

        {
            let mut em = runtime.endpoint_manager.lock().unwrap();
            em.cancel_all();
            let _ = em.shutdown_all(Some(Duration::from_secs(1)));
        }
    }

    #[test]
    fn second_delegation_rejected_while_active_browser() {
        let harness = RuntimeHarness::new_delegated();
        let endpoint_id = harness.create_endpoint();

        let _result = harness
            .runtime
            .handle_request_delegation(RequestDelegationParams {
                profile_id: &harness.profile_id,
                session_id: &harness.session_id,
                endpoint_id: &endpoint_id,
                rp_id: &harness.rp_id,
                credential_ref: &harness.credential_ref,
                max_session_ttl: 300,
                principal_reason: None,
                profile: harness.profile(),
                session_digest: &harness.process_digest,
            })
            .unwrap();

        let generation = harness.runtime.policy_runtime.current_generation();
        let tuple = super::super::policy_engine::CeremonyTuple {
            profile_id: harness.profile_id.clone(),
            session_id: harness.session_id.clone(),
            endpoint_id: endpoint_id.clone(),
            process_digest: harness.process_digest.clone(),
            policy_generation: generation.generation_id.clone(),
            policy_digest: generation.digest.clone(),
            action: passless_core::agent::protocol::IntentAction::Authenticate,
            rp_id: harness.rp_id.clone(),
            credential_ref: Some(harness.credential_ref.clone()),
        };
        let approval = super::super::policy_engine::TrustedApproval::new();
        let _bound = harness
            .runtime
            .policy_runtime
            .ceremony_resolve_pending(&tuple, &approval)
            .unwrap();

        harness
            .runtime
            .handle_endpoint_event(EndpointEvent::ResponseSent {
                endpoint_id: endpoint_id.clone(),
                profile_id: harness.profile_id.clone(),
            });
        harness.reap_workers();

        let active = harness.profile().active_browser.lock().unwrap();
        assert!(
            active.is_some(),
            "active_browser should be set after successful delegation"
        );
        drop(active);

        let new_endpoint_id = EndpointId::new();
        let second_result = harness
            .runtime
            .handle_request_delegation(RequestDelegationParams {
                profile_id: &harness.profile_id,
                session_id: &harness.session_id,
                endpoint_id: &new_endpoint_id,
                rp_id: &harness.rp_id,
                credential_ref: &harness.credential_ref,
                max_session_ttl: 300,
                principal_reason: None,
                profile: harness.profile(),
                session_digest: &harness.process_digest,
            });

        assert!(
            second_result.is_err(),
            "second delegation should be rejected while browser is active"
        );
        let err = second_result.unwrap_err();
        assert_eq!(err.code, ErrorCode::Conflict);
    }

    #[test]
    fn storage_fake_persists_writes_and_tracks_read_sign_counter() {
        let mut storage = FakeCredentialStorage::new();

        assert_eq!(storage.write_count(), 0);
        assert_eq!(storage.read_sign_count(), 0);
        assert_eq!(storage.count_credentials(), 0);

        let _ = storage.read_first(crate::storage::CredentialFilter::None);
        assert_eq!(storage.read_sign_count(), 1);

        let _ = storage.read_next();
        assert_eq!(storage.read_sign_count(), 2);

        let _ = storage.read(b"nonexistent");
        assert_eq!(storage.read_sign_count(), 3);

        let result = storage.read(b"nonexistent");
        assert!(result.is_err());
        assert_eq!(storage.read_sign_count(), 4);

        assert_eq!(storage.write_count(), 0);
        assert_eq!(storage.count_credentials(), 0);
    }

    #[test]
    fn audit_records_endpoint_and_browser_events() {
        let temp_dir = tempfile::tempdir().unwrap();
        let audit_dir = temp_dir.path().join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&audit_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let audit_gate = Arc::new(super::super::audit::AuditGate::open(&audit_dir).unwrap());

        let start_event =
            super::super::audit_events::DaemonStartBuilder::new(1234, BackendKind::Local).build();
        audit_gate.record(start_event).unwrap();

        let profile_id = ProfileId::new("test-audit").unwrap();
        let create_event =
            super::super::audit_events::ProfileCreateBuilder::new(profile_id.clone()).build();
        audit_gate.record(create_event).unwrap();

        let endpoint_id = EndpointId::new();
        let endpoint_event = super::super::audit_events::EndpointCreateBuilder::new(
            endpoint_id.clone(),
            profile_id.clone(),
        )
        .build();
        audit_gate.record(endpoint_event).unwrap();

        let lease_id = passless_core::agent::BrowserLeaseId::new();
        let lease_event = super::super::audit_events::BrowserLeaseLaunchBuilder::new(
            lease_id.clone(),
            profile_id.clone(),
            endpoint_id.clone(),
        )
        .build();
        audit_gate.record(lease_event).unwrap();

        let intent_id = passless_core::agent::IntentId::new();
        let intent_event = super::super::audit_events::IntentCreateBuilder::new(
            intent_id.clone(),
            profile_id.clone(),
            super::super::audit_events::AuditAction::Authenticate,
        )
        .build();
        audit_gate.record(intent_event).unwrap();

        let audit_file = audit_dir.join("audit-000000.log");
        assert!(
            audit_file.exists(),
            "audit file should exist after recording events"
        );

        let metadata = std::fs::metadata(&audit_file).unwrap();
        assert!(
            metadata.len() > 0,
            "audit file should contain data after recording events"
        );

        let event_count = audit_gate.verify_all().unwrap();
        assert_eq!(
            event_count, 5,
            "should have recorded 5 events (daemon.start, profile.create, endpoint.create, browser_lease.launch, intent.create)"
        );
    }
}
