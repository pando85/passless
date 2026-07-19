use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[cfg(feature = "agent")]
use passless_uhid::RawUhidDevice;

use super::device::{CreateOutcome, EndpointBinding, EndpointHandle, EndpointRegistry};
use crate::worker::{self, HidEndpoint, WorkerConfig, WorkerHandle, WorkerHooks, WorkerOutcome};

#[cfg(feature = "agent")]
use crate::worker::RawUhidEndpoint;

use soft_fido2_transport::{CommandHandler, CtapHidHandler};

use passless_core::agent::EndpointId;

const DEFAULT_DESTROY_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

type BeforeStartCallback = Box<dyn FnOnce(&EndpointId) -> Result<(), String>>;

#[derive(Debug, Clone)]
pub enum ManagerError {
    CreateRejected(String),
    DeviceCreationFailed(String),
    Shutdown,
}

impl std::fmt::Display for ManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManagerError::CreateRejected(msg) => write!(f, "create rejected: {}", msg),
            ManagerError::DeviceCreationFailed(msg) => {
                write!(f, "device creation failed: {}", msg)
            }
            ManagerError::Shutdown => write!(f, "manager is shut down"),
        }
    }
}

impl std::error::Error for ManagerError {}

#[derive(Debug)]
#[allow(dead_code)]
pub enum DestroyOutcome {
    Destroyed {
        endpoint_id: EndpointId,
        elapsed: Duration,
    },
    TimedOut {
        endpoint_id: EndpointId,
        elapsed: Duration,
    },
    WorkerFailed {
        endpoint_id: EndpointId,
        error: String,
    },
    WorkerPanicked {
        endpoint_id: EndpointId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReapOutcome {
    Reaped { endpoint_id: EndpointId },
    StillRunning { endpoint_id: EndpointId },
    NotFound { endpoint_id: EndpointId },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum RuntimeState {
    Starting,
    Running,
    ShuttingDown,
}

pub struct ShutdownAllResult {
    pub destroyed: Vec<EndpointId>,
    pub timed_out: Vec<EndpointId>,
    pub failed: Vec<(EndpointId, String)>,
    pub panicked: Vec<EndpointId>,
}

struct RuntimeEntry {
    endpoint_handle: EndpointHandle,
    #[allow(dead_code)]
    profile_id: String,
    state: RuntimeState,
    cancel: Arc<AtomicBool>,
    worker: WorkerHandle,
}

pub trait EndpointTransport: HidEndpoint + 'static {}
impl<T: HidEndpoint + 'static> EndpointTransport for T {}

pub struct EndpointManager {
    endpoint_registry: Arc<EndpointRegistry>,
    runtimes: HashMap<EndpointId, RuntimeEntry>,
    daemon_cancel: Arc<AtomicBool>,
    worker_config: WorkerConfig,
}

impl EndpointManager {
    pub fn new(
        max_endpoints: usize,
        daemon_cancel: Arc<AtomicBool>,
        worker_config: WorkerConfig,
    ) -> Self {
        let endpoint_registry = Arc::new(EndpointRegistry::new(max_endpoints));

        Self {
            endpoint_registry,
            runtimes: HashMap::new(),
            daemon_cancel,
            worker_config,
        }
    }

    #[cfg(feature = "agent")]
    #[allow(dead_code)]
    pub fn create_and_start<H>(
        &mut self,
        binding: EndpointBinding,
        profile_id: String,
        handler_factory: impl FnOnce(&EndpointId) -> H + Send + 'static,
        device_factory: impl FnOnce() -> Result<RawUhidDevice, String>,
    ) -> Result<EndpointId, ManagerError>
    where
        H: CommandHandler + Send + 'static,
    {
        self.create_and_start_with_hooks(
            binding,
            profile_id,
            handler_factory,
            device_factory,
            WorkerHooks::noop(),
        )
    }

    #[cfg(feature = "agent")]
    #[allow(dead_code)]
    pub fn create_and_start_with_hooks<H>(
        &mut self,
        binding: EndpointBinding,
        profile_id: String,
        handler_factory: impl FnOnce(&EndpointId) -> H + Send + 'static,
        device_factory: impl FnOnce() -> Result<RawUhidDevice, String>,
        hooks: WorkerHooks,
    ) -> Result<EndpointId, ManagerError>
    where
        H: CommandHandler + Send + 'static,
    {
        self.create_and_start_full(
            binding,
            profile_id,
            handler_factory,
            device_factory,
            hooks,
            None,
        )
    }

    #[cfg(feature = "agent")]
    pub fn create_and_start_full<H>(
        &mut self,
        binding: EndpointBinding,
        profile_id: String,
        handler_factory: impl FnOnce(&EndpointId) -> H + Send + 'static,
        device_factory: impl FnOnce() -> Result<RawUhidDevice, String>,
        hooks: WorkerHooks,
        before_start: Option<BeforeStartCallback>,
    ) -> Result<EndpointId, ManagerError>
    where
        H: CommandHandler + Send + 'static,
    {
        if self.daemon_cancel.load(Ordering::Relaxed) {
            return Err(ManagerError::Shutdown);
        }

        let create_outcome = self.endpoint_registry.create_endpoint(binding);
        let snapshot = match create_outcome {
            CreateOutcome::Created(s) => s,
            CreateOutcome::Rejected(e) => {
                return Err(ManagerError::CreateRejected(e.to_string()));
            }
        };

        let endpoint_id = snapshot.handle.id().clone();
        let handle = snapshot.handle.clone();

        if let Some(before_start_fn) = before_start
            && let Err(e) = before_start_fn(&endpoint_id)
        {
            let _ = self
                .endpoint_registry
                .mark_failed(&handle, format!("before_start callback failed: {}", e));
            return Err(ManagerError::CreateRejected(e));
        }

        let device = match device_factory() {
            Ok(d) => d,
            Err(e) => {
                let _ = self
                    .endpoint_registry
                    .mark_failed(&handle, format!("device creation failed: {}", e));
                return Err(ManagerError::DeviceCreationFailed(e));
            }
        };

        if let Err(e) = device.set_nonblocking(true) {
            let _ = self
                .endpoint_registry
                .mark_failed(&handle, format!("set_nonblocking failed: {:?}", e));
            return Err(ManagerError::DeviceCreationFailed(format!(
                "set_nonblocking failed: {:?}",
                e
            )));
        }

        let endpoint = RawUhidEndpoint::new_nonblocking(device);
        self.start_worker(
            endpoint,
            handle,
            endpoint_id,
            profile_id,
            handler_factory,
            hooks,
        )
    }

    #[allow(dead_code)]
    pub fn create_and_start_with_transport<H, E>(
        &mut self,
        binding: EndpointBinding,
        profile_id: String,
        handler_factory: impl FnOnce(&EndpointId) -> H + Send + 'static,
        endpoint_factory: impl FnOnce() -> Result<E, String>,
    ) -> Result<EndpointId, ManagerError>
    where
        H: CommandHandler + Send + 'static,
        E: EndpointTransport,
    {
        self.create_and_start_with_transport_and_hooks(
            binding,
            profile_id,
            handler_factory,
            endpoint_factory,
            WorkerHooks::noop(),
        )
    }

    #[allow(dead_code)]
    pub fn create_and_start_with_transport_and_hooks<H, E>(
        &mut self,
        binding: EndpointBinding,
        profile_id: String,
        handler_factory: impl FnOnce(&EndpointId) -> H + Send + 'static,
        endpoint_factory: impl FnOnce() -> Result<E, String>,
        hooks: WorkerHooks,
    ) -> Result<EndpointId, ManagerError>
    where
        H: CommandHandler + Send + 'static,
        E: EndpointTransport,
    {
        self.create_and_start_with_transport_full(
            binding,
            profile_id,
            handler_factory,
            endpoint_factory,
            hooks,
            None,
        )
    }

    #[allow(dead_code)]
    pub fn create_and_start_with_transport_full<H, E>(
        &mut self,
        binding: EndpointBinding,
        profile_id: String,
        handler_factory: impl FnOnce(&EndpointId) -> H + Send + 'static,
        endpoint_factory: impl FnOnce() -> Result<E, String>,
        hooks: WorkerHooks,
        before_start: Option<BeforeStartCallback>,
    ) -> Result<EndpointId, ManagerError>
    where
        H: CommandHandler + Send + 'static,
        E: EndpointTransport,
    {
        if self.daemon_cancel.load(Ordering::Relaxed) {
            return Err(ManagerError::Shutdown);
        }

        let create_outcome = self.endpoint_registry.create_endpoint(binding);
        let snapshot = match create_outcome {
            CreateOutcome::Created(s) => s,
            CreateOutcome::Rejected(e) => {
                return Err(ManagerError::CreateRejected(e.to_string()));
            }
        };

        let endpoint_id = snapshot.handle.id().clone();
        let handle = snapshot.handle.clone();

        if let Some(before_start_fn) = before_start
            && let Err(e) = before_start_fn(&endpoint_id)
        {
            let _ = self
                .endpoint_registry
                .mark_failed(&handle, format!("before_start callback failed: {}", e));
            return Err(ManagerError::CreateRejected(e));
        }

        let endpoint = match endpoint_factory() {
            Ok(e) => e,
            Err(e) => {
                let _ = self
                    .endpoint_registry
                    .mark_failed(&handle, format!("endpoint creation failed: {}", e));
                return Err(ManagerError::DeviceCreationFailed(e));
            }
        };

        self.start_worker(
            endpoint,
            handle,
            endpoint_id,
            profile_id,
            handler_factory,
            hooks,
        )
    }

    fn start_worker<H, E>(
        &mut self,
        endpoint: E,
        handle: EndpointHandle,
        endpoint_id: EndpointId,
        profile_id: String,
        handler_factory: impl FnOnce(&EndpointId) -> H + Send + 'static,
        hooks: WorkerHooks,
    ) -> Result<EndpointId, ManagerError>
    where
        H: CommandHandler + Send + 'static,
        E: EndpointTransport,
    {
        let handler = handler_factory(&endpoint_id);
        let ctaphid = CtapHidHandler::new(handler);

        let endpoint_cancel = Arc::new(AtomicBool::new(false));

        let cache_cleanup = Box::new(|| {});

        let worker_handle = worker::spawn_with_hooks(
            endpoint,
            ctaphid,
            self.worker_config.clone(),
            endpoint_cancel.clone(),
            cache_cleanup,
            hooks,
        );

        let ready_outcome = self.endpoint_registry.mark_ready(&handle);
        if !matches!(
            ready_outcome,
            super::device::TransitionOutcome::Transitioned { .. }
        ) {
            worker_handle.cancel();
            let _ = worker_handle.join();
            let reason = format!("mark_ready transition failed: {:?}", ready_outcome);
            let _ = self.endpoint_registry.mark_failed(&handle, reason.clone());
            return Err(ManagerError::DeviceCreationFailed(reason));
        }

        let active_outcome = self.endpoint_registry.mark_active(&handle);
        if !matches!(
            active_outcome,
            super::device::TransitionOutcome::Transitioned { .. }
        ) {
            worker_handle.cancel();
            let _ = worker_handle.join();
            let reason = format!("mark_active transition failed: {:?}", active_outcome);
            let _ = self.endpoint_registry.mark_failed(&handle, reason.clone());
            return Err(ManagerError::DeviceCreationFailed(reason));
        }

        self.runtimes.insert(
            endpoint_id.clone(),
            RuntimeEntry {
                endpoint_handle: handle,
                profile_id,
                state: RuntimeState::Running,
                cancel: endpoint_cancel,
                worker: worker_handle,
            },
        );

        Ok(endpoint_id)
    }

    pub fn cancel(&mut self, endpoint_id: &EndpointId) {
        if let Some(entry) = self.runtimes.get_mut(endpoint_id) {
            entry.cancel.store(true, Ordering::Relaxed);
            entry.state = RuntimeState::ShuttingDown;
        }
    }

    pub fn cancel_all(&mut self) {
        let _snapshots = self.endpoint_registry.shutdown();
        for entry in self.runtimes.values_mut() {
            entry.cancel.store(true, Ordering::Relaxed);
            entry.state = RuntimeState::ShuttingDown;
        }
    }

    pub fn destroy(
        &mut self,
        endpoint_id: &EndpointId,
        timeout: Option<Duration>,
    ) -> DestroyOutcome {
        let timeout = timeout.unwrap_or(DEFAULT_DESTROY_TIMEOUT);
        let started = Instant::now();

        let entry = match self.runtimes.get(endpoint_id) {
            Some(e) => e,
            None => {
                return DestroyOutcome::Destroyed {
                    endpoint_id: endpoint_id.clone(),
                    elapsed: Duration::ZERO,
                };
            }
        };

        let endpoint_handle = entry.endpoint_handle.clone();
        let _ = self.endpoint_registry.mark_draining(&endpoint_handle);

        let join_outcome = {
            let entry = self.runtimes.get_mut(endpoint_id).unwrap();
            entry.cancel.store(true, Ordering::Relaxed);
            entry.state = RuntimeState::ShuttingDown;
            entry.worker.join_timeout(timeout)
        };
        let elapsed = started.elapsed();

        match join_outcome {
            worker::JoinOutcome::Finished(outcome) => {
                let handle = &self.runtimes[endpoint_id].endpoint_handle;
                let _ = self.endpoint_registry.mark_destroyed(handle);
                self.runtimes.remove(endpoint_id);

                match outcome {
                    WorkerOutcome::Clean => DestroyOutcome::Destroyed {
                        endpoint_id: endpoint_id.clone(),
                        elapsed,
                    },
                    WorkerOutcome::Error(e) => DestroyOutcome::WorkerFailed {
                        endpoint_id: endpoint_id.clone(),
                        error: e.to_string(),
                    },
                    WorkerOutcome::Panicked => DestroyOutcome::WorkerPanicked {
                        endpoint_id: endpoint_id.clone(),
                    },
                }
            }
            worker::JoinOutcome::TimedOut => {
                if let Some(entry) = self.runtimes.get_mut(endpoint_id) {
                    entry.state = RuntimeState::ShuttingDown;
                }
                DestroyOutcome::TimedOut {
                    endpoint_id: endpoint_id.clone(),
                    elapsed,
                }
            }
        }
    }

    pub fn shutdown_all(&mut self, timeout: Option<Duration>) -> ShutdownAllResult {
        let timeout = timeout.unwrap_or(DEFAULT_SHUTDOWN_TIMEOUT);
        let deadline = Instant::now() + timeout;

        self.cancel_all();

        let mut result = ShutdownAllResult {
            destroyed: Vec::new(),
            timed_out: Vec::new(),
            failed: Vec::new(),
            panicked: Vec::new(),
        };

        let endpoint_ids: Vec<EndpointId> = self.runtimes.keys().cloned().collect();

        for endpoint_id in endpoint_ids {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                if let Some(entry) = self.runtimes.get_mut(&endpoint_id) {
                    entry.state = RuntimeState::ShuttingDown;
                }
                result.timed_out.push(endpoint_id);
                continue;
            }

            let entry = match self.runtimes.get(&endpoint_id) {
                Some(e) => e,
                None => continue,
            };
            let endpoint_handle = entry.endpoint_handle.clone();
            let _ = self.endpoint_registry.mark_draining(&endpoint_handle);

            let join_outcome = {
                let entry = self.runtimes.get_mut(&endpoint_id).unwrap();
                entry.worker.join_timeout(remaining)
            };

            match join_outcome {
                worker::JoinOutcome::Finished(outcome) => {
                    let handle = self.runtimes[&endpoint_id].endpoint_handle.clone();
                    let _ = self.endpoint_registry.mark_destroyed(&handle);
                    self.runtimes.remove(&endpoint_id);

                    match outcome {
                        WorkerOutcome::Clean => result.destroyed.push(endpoint_id),
                        WorkerOutcome::Error(e) => {
                            result.failed.push((endpoint_id, e.to_string()));
                        }
                        WorkerOutcome::Panicked => result.panicked.push(endpoint_id),
                    }
                }
                worker::JoinOutcome::TimedOut => {
                    if let Some(entry) = self.runtimes.get_mut(&endpoint_id) {
                        entry.state = RuntimeState::ShuttingDown;
                    }
                    result.timed_out.push(endpoint_id);
                }
            }
        }

        result
    }

    pub fn snapshot(&self) -> Vec<super::device::EndpointSnapshot> {
        self.endpoint_registry.list()
    }

    #[cfg(test)]
    pub fn is_shutdown(&self) -> bool {
        self.endpoint_registry.is_shutdown() || self.daemon_cancel.load(Ordering::Relaxed)
    }

    #[allow(dead_code)]
    pub fn runtime_state(&self, endpoint_id: &EndpointId) -> Option<&RuntimeState> {
        self.runtimes.get(endpoint_id).map(|e| &e.state)
    }

    pub fn reap_stopped(&mut self, endpoint_id: &EndpointId) -> ReapOutcome {
        let entry = match self.runtimes.get(endpoint_id) {
            Some(e) => e,
            None => {
                return ReapOutcome::NotFound {
                    endpoint_id: endpoint_id.clone(),
                };
            }
        };

        if entry.state != RuntimeState::ShuttingDown {
            return ReapOutcome::StillRunning {
                endpoint_id: endpoint_id.clone(),
            };
        }

        let entry = match self.runtimes.get_mut(endpoint_id) {
            Some(e) => e,
            None => {
                return ReapOutcome::NotFound {
                    endpoint_id: endpoint_id.clone(),
                };
            }
        };

        let join_result = entry.worker.try_join();
        match join_result {
            Some(_) => {
                let handle = &self.runtimes[endpoint_id].endpoint_handle;
                let _ = self.endpoint_registry.mark_destroyed(handle);
                self.runtimes.remove(endpoint_id);
                ReapOutcome::Reaped {
                    endpoint_id: endpoint_id.clone(),
                }
            }
            None => ReapOutcome::StillRunning {
                endpoint_id: endpoint_id.clone(),
            },
        }
    }

    #[allow(dead_code)]
    pub fn retry_destroy(
        &mut self,
        endpoint_id: &EndpointId,
        timeout: Option<Duration>,
    ) -> Option<DestroyOutcome> {
        let entry = self.runtimes.get(endpoint_id)?;
        if entry.state != RuntimeState::ShuttingDown {
            return None;
        }

        let timeout = timeout.unwrap_or(DEFAULT_DESTROY_TIMEOUT);
        let started = Instant::now();

        let join_outcome = {
            let entry = self.runtimes.get_mut(endpoint_id).unwrap();
            entry.worker.join_timeout(timeout)
        };
        let elapsed = started.elapsed();

        match join_outcome {
            worker::JoinOutcome::Finished(outcome) => {
                let handle = &self.runtimes[endpoint_id].endpoint_handle;
                let _ = self.endpoint_registry.mark_destroyed(handle);
                self.runtimes.remove(endpoint_id);

                Some(match outcome {
                    WorkerOutcome::Clean => DestroyOutcome::Destroyed {
                        endpoint_id: endpoint_id.clone(),
                        elapsed,
                    },
                    WorkerOutcome::Error(e) => DestroyOutcome::WorkerFailed {
                        endpoint_id: endpoint_id.clone(),
                        error: e.to_string(),
                    },
                    WorkerOutcome::Panicked => DestroyOutcome::WorkerPanicked {
                        endpoint_id: endpoint_id.clone(),
                    },
                })
            }
            worker::JoinOutcome::TimedOut => Some(DestroyOutcome::TimedOut {
                endpoint_id: endpoint_id.clone(),
                elapsed,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::device::EndpointState;
    use crate::worker::WorkerError;
    use passless_core::agent::{AgentMode, ProfileId};
    use soft_fido2_transport::{Cmd, Packet};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[derive(Clone)]
    struct FakeEndpoint {
        inner: Arc<FakeEndpointInner>,
    }

    struct FakeEndpointInner {
        inbound: Mutex<VecDeque<[u8; 64]>>,
        outbound: Mutex<Vec<[u8; 64]>>,
        read_errors: Mutex<VecDeque<WorkerError>>,
        write_errors: Mutex<VecDeque<WorkerError>>,
    }

    impl FakeEndpoint {
        fn new() -> Self {
            Self {
                inner: Arc::new(FakeEndpointInner {
                    inbound: Mutex::new(VecDeque::new()),
                    outbound: Mutex::new(Vec::new()),
                    read_errors: Mutex::new(VecDeque::new()),
                    write_errors: Mutex::new(VecDeque::new()),
                }),
            }
        }

        fn push_packet(&self, packet: &Packet) {
            self.inner
                .inbound
                .lock()
                .unwrap()
                .push_back(*packet.as_bytes());
        }
    }

    impl HidEndpoint for FakeEndpoint {
        fn read_packet(&mut self, buffer: &mut [u8; 64]) -> Result<Option<usize>, WorkerError> {
            {
                let mut errors = self.inner.read_errors.lock().unwrap();
                if let Some(err) = errors.pop_front() {
                    return Err(err);
                }
            }

            let maybe = self.inner.inbound.lock().unwrap().pop_front();

            match maybe {
                Some(pkt) => {
                    buffer.copy_from_slice(&pkt);
                    Ok(Some(64))
                }
                None => Ok(None),
            }
        }

        fn write_packet(&mut self, data: &[u8; 64]) -> Result<(), WorkerError> {
            {
                let mut errors = self.inner.write_errors.lock().unwrap();
                if let Some(err) = errors.pop_front() {
                    return Err(err);
                }
            }
            self.inner.outbound.lock().unwrap().push(*data);
            Ok(())
        }
    }

    type CommandLog = Arc<Mutex<Vec<(Cmd, Vec<u8>)>>>;

    struct FakeHandler {
        commands: CommandLog,
    }

    impl FakeHandler {
        fn new() -> (Self, CommandLog) {
            let commands = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    commands: commands.clone(),
                },
                commands,
            )
        }
    }

    impl CommandHandler for FakeHandler {
        fn handle_command(
            &mut self,
            cmd: Cmd,
            data: &[u8],
        ) -> soft_fido2_transport::Result<Vec<u8>> {
            self.commands.lock().unwrap().push((cmd, data.to_vec()));
            Ok(vec![0x00])
        }
    }

    fn test_binding() -> EndpointBinding {
        EndpointBinding {
            profile_id: ProfileId::new("test-profile").unwrap(),
            mode: AgentMode::Isolated,
        }
    }

    fn failing_endpoint_factory() -> impl FnOnce() -> Result<FakeEndpoint, String> {
        || Err("endpoint creation disabled".to_string())
    }

    #[test]
    fn test_manager_creation() {
        let cancel = Arc::new(AtomicBool::new(false));
        let manager = EndpointManager::new(10, cancel, WorkerConfig::default());
        assert!(!manager.is_shutdown());
    }

    #[test]
    fn test_create_rejected_capacity_exceeded() {
        let cancel = Arc::new(AtomicBool::new(false));
        let mut manager = EndpointManager::new(1, cancel, WorkerConfig::default());

        let endpoint = FakeEndpoint::new();
        let r1 = manager.create_and_start_with_transport(
            test_binding(),
            "p1".to_string(),
            |_| {
                let (h, _) = FakeHandler::new();
                h
            },
            move || Ok(endpoint),
        );
        assert!(r1.is_ok());

        let endpoint2 = FakeEndpoint::new();
        let r2 = manager.create_and_start_with_transport(
            test_binding(),
            "p2".to_string(),
            |_| {
                let (h, _) = FakeHandler::new();
                h
            },
            move || Ok(endpoint2),
        );
        assert!(matches!(r2, Err(ManagerError::CreateRejected(_))));
    }

    #[test]
    fn test_endpoint_creation_failure_marks_endpoint_failed() {
        let cancel = Arc::new(AtomicBool::new(false));
        let mut manager = EndpointManager::new(10, cancel, WorkerConfig::default());

        let result = manager.create_and_start_with_transport(
            test_binding(),
            "test".to_string(),
            |_| {
                let (h, _) = FakeHandler::new();
                h
            },
            failing_endpoint_factory(),
        );

        assert!(matches!(result, Err(ManagerError::DeviceCreationFailed(_))));

        let snapshots = manager.snapshot();
        assert_eq!(snapshots.len(), 1);
        assert!(matches!(snapshots[0].state, EndpointState::Failed(_)));
    }

    #[test]
    fn test_cancel_all_sets_shutdown() {
        let cancel = Arc::new(AtomicBool::new(false));
        let mut manager = EndpointManager::new(10, cancel.clone(), WorkerConfig::default());

        manager.cancel_all();

        assert!(manager.is_shutdown());
    }

    #[test]
    fn test_snapshot_returns_all_endpoints() {
        let cancel = Arc::new(AtomicBool::new(false));
        let mut manager = EndpointManager::new(10, cancel, WorkerConfig::default());

        let endpoint1 = FakeEndpoint::new();
        let _ = manager.create_and_start_with_transport(
            test_binding(),
            "p1".to_string(),
            |_| {
                let (h, _) = FakeHandler::new();
                h
            },
            move || Ok(endpoint1),
        );

        let endpoint2 = FakeEndpoint::new();
        let _ = manager.create_and_start_with_transport(
            test_binding(),
            "p2".to_string(),
            |_| {
                let (h, _) = FakeHandler::new();
                h
            },
            move || Ok(endpoint2),
        );

        let snapshots = manager.snapshot();
        assert_eq!(snapshots.len(), 2);
    }

    #[test]
    fn test_happy_create_and_destroy() {
        let cancel = Arc::new(AtomicBool::new(false));
        let mut manager = EndpointManager::new(10, cancel, WorkerConfig::default());

        let endpoint = FakeEndpoint::new();
        let endpoint_id = manager
            .create_and_start_with_transport(
                test_binding(),
                "test".to_string(),
                |_| {
                    let (h, _) = FakeHandler::new();
                    h
                },
                move || Ok(endpoint),
            )
            .unwrap();

        assert_eq!(
            manager.runtime_state(&endpoint_id),
            Some(&RuntimeState::Running)
        );

        let outcome = manager.destroy(&endpoint_id, None);
        assert!(matches!(outcome, DestroyOutcome::Destroyed { .. }));
        assert!(manager.runtime_state(&endpoint_id).is_none());
    }

    #[test]
    fn test_destroy_unknown_id() {
        let cancel = Arc::new(AtomicBool::new(false));
        let mut manager = EndpointManager::new(10, cancel, WorkerConfig::default());

        let fake_id = EndpointId::new();
        let outcome = manager.destroy(&fake_id, None);
        assert!(matches!(outcome, DestroyOutcome::Destroyed { .. }));
    }

    #[test]
    fn test_cancel_sets_shutting_down_state() {
        let cancel = Arc::new(AtomicBool::new(false));
        let mut manager = EndpointManager::new(10, cancel, WorkerConfig::default());

        let endpoint = FakeEndpoint::new();
        let endpoint_id = manager
            .create_and_start_with_transport(
                test_binding(),
                "test".to_string(),
                |_| {
                    let (h, _) = FakeHandler::new();
                    h
                },
                move || Ok(endpoint),
            )
            .unwrap();

        manager.cancel(&endpoint_id);
        assert_eq!(
            manager.runtime_state(&endpoint_id),
            Some(&RuntimeState::ShuttingDown)
        );

        let _ = manager.destroy(&endpoint_id, None);
    }

    #[test]
    fn test_manager_happy_path_with_transport() {
        use soft_fido2_transport::Message;

        let cancel = Arc::new(AtomicBool::new(false));
        let mut manager = EndpointManager::new(10, cancel, WorkerConfig::default());

        let endpoint = FakeEndpoint::new();
        let (handler, commands) = FakeHandler::new();

        let payload = vec![0xA1, 0x01, 0x02];
        let msg = Message::new(0x12345678, Cmd::Cbor, payload, None);
        let packets = msg.to_packets().unwrap();
        for packet in packets {
            endpoint.push_packet(&packet);
        }

        let endpoint_id = manager
            .create_and_start_with_transport(
                test_binding(),
                "test".to_string(),
                move |_| handler,
                move || Ok(endpoint.clone()),
            )
            .unwrap();

        std::thread::sleep(Duration::from_millis(50));
        let outcome = manager.destroy(&endpoint_id, None);

        assert!(matches!(outcome, DestroyOutcome::Destroyed { .. }));
        assert_eq!(commands.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_multi_worker_isolation() {
        let cancel = Arc::new(AtomicBool::new(false));
        let mut manager = EndpointManager::new(10, cancel, WorkerConfig::default());

        let endpoint1 = FakeEndpoint::new();
        let id1 = manager
            .create_and_start_with_transport(
                test_binding(),
                "p1".to_string(),
                |_| {
                    let (h, _) = FakeHandler::new();
                    h
                },
                move || Ok(endpoint1),
            )
            .unwrap();

        let endpoint2 = FakeEndpoint::new();
        let id2 = manager
            .create_and_start_with_transport(
                test_binding(),
                "p2".to_string(),
                |_| {
                    let (h, _) = FakeHandler::new();
                    h
                },
                move || Ok(endpoint2),
            )
            .unwrap();

        let outcome1 = manager.destroy(&id1, None);
        assert!(matches!(outcome1, DestroyOutcome::Destroyed { .. }));

        assert_eq!(manager.runtime_state(&id2), Some(&RuntimeState::Running));

        let outcome2 = manager.destroy(&id2, None);
        assert!(matches!(outcome2, DestroyOutcome::Destroyed { .. }));
    }

    #[test]
    fn test_timeout_retention_and_retry() {
        use std::sync::atomic::AtomicUsize;

        let cancel = Arc::new(AtomicBool::new(false));
        let mut manager = EndpointManager::new(10, cancel, WorkerConfig::default());

        let gate = Arc::new(AtomicUsize::new(0));
        let gate_clone = gate.clone();

        #[derive(Clone)]
        struct BlockingEndpoint {
            gate: Arc<AtomicUsize>,
        }

        impl HidEndpoint for BlockingEndpoint {
            fn read_packet(
                &mut self,
                _buffer: &mut [u8; 64],
            ) -> Result<Option<usize>, WorkerError> {
                if self.gate.load(Ordering::Relaxed) == 0 {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(None)
            }

            fn write_packet(&mut self, _data: &[u8; 64]) -> Result<(), WorkerError> {
                Ok(())
            }
        }

        let blocking_ep = BlockingEndpoint {
            gate: gate_clone.clone(),
        };

        let endpoint_id = manager
            .create_and_start_with_transport(
                test_binding(),
                "blocking".to_string(),
                |_| {
                    let (h, _) = FakeHandler::new();
                    h
                },
                move || Ok(blocking_ep),
            )
            .unwrap();

        let outcome = manager.destroy(&endpoint_id, Some(Duration::from_millis(50)));
        assert!(
            matches!(
                outcome,
                DestroyOutcome::Destroyed { .. } | DestroyOutcome::TimedOut { .. }
            ),
            "expected Destroyed or TimedOut, got {:?}",
            match &outcome {
                DestroyOutcome::Destroyed { .. } => "Destroyed",
                DestroyOutcome::TimedOut { .. } => "TimedOut",
                DestroyOutcome::WorkerFailed { .. } => "WorkerFailed",
                DestroyOutcome::WorkerPanicked { .. } => "WorkerPanicked",
            }
        );

        gate_clone.store(1, Ordering::Relaxed);

        if matches!(outcome, DestroyOutcome::TimedOut { .. }) {
            let retry = manager.destroy(&endpoint_id, Some(Duration::from_secs(5)));
            assert!(
                matches!(retry, DestroyOutcome::Destroyed { .. }),
                "retry after timeout should succeed"
            );
        }
    }

    #[test]
    fn test_shared_deadline_shutdown_all() {
        let cancel = Arc::new(AtomicBool::new(false));
        let mut manager = EndpointManager::new(10, cancel, WorkerConfig::default());

        let ep1 = FakeEndpoint::new();
        let _id1 = manager
            .create_and_start_with_transport(
                test_binding(),
                "p1".to_string(),
                |_| {
                    let (h, _) = FakeHandler::new();
                    h
                },
                move || Ok(ep1),
            )
            .unwrap();

        let ep2 = FakeEndpoint::new();
        let _id2 = manager
            .create_and_start_with_transport(
                test_binding(),
                "p2".to_string(),
                |_| {
                    let (h, _) = FakeHandler::new();
                    h
                },
                move || Ok(ep2),
            )
            .unwrap();

        let result = manager.shutdown_all(Some(Duration::from_secs(5)));

        let total = result.destroyed.len()
            + result.timed_out.len()
            + result.failed.len()
            + result.panicked.len();
        assert_eq!(total, 2);

        assert!(manager.runtimes.is_empty() || !result.timed_out.is_empty());
    }

    #[test]
    fn test_transition_rollback_on_failure() {
        let cancel = Arc::new(AtomicBool::new(false));
        let manager_for_registry =
            EndpointManager::new(10, cancel.clone(), WorkerConfig::default());
        let registry = manager_for_registry.endpoint_registry.clone();

        let mut manager = EndpointManager::new(10, cancel, WorkerConfig::default());
        manager.endpoint_registry = registry.clone();

        let endpoint = FakeEndpoint::new();
        let endpoint_id = manager
            .create_and_start_with_transport(
                test_binding(),
                "test".to_string(),
                |_| {
                    let (h, _) = FakeHandler::new();
                    h
                },
                move || Ok(endpoint),
            )
            .unwrap();

        assert_eq!(
            manager.runtime_state(&endpoint_id),
            Some(&RuntimeState::Running)
        );

        let snapshots = registry.list();
        let snap = snapshots
            .iter()
            .find(|s| *s.handle.id() == endpoint_id)
            .unwrap();
        assert_eq!(snap.state, EndpointState::Active);
    }

    #[test]
    fn test_manager_error_display() {
        let e = ManagerError::CreateRejected("capacity".to_string());
        assert!(e.to_string().contains("capacity"));

        let e = ManagerError::Shutdown;
        assert!(e.to_string().contains("shut down"));
    }

    #[test]
    fn test_bounded_shutdown() {
        let cancel = Arc::new(AtomicBool::new(false));
        let mut manager = EndpointManager::new(10, cancel, WorkerConfig::default());

        let endpoint = FakeEndpoint::new();
        let endpoint_id = manager
            .create_and_start_with_transport(
                test_binding(),
                "test".to_string(),
                |_| {
                    let (h, _) = FakeHandler::new();
                    h
                },
                move || Ok(endpoint),
            )
            .unwrap();

        let start = Instant::now();
        let outcome = manager.destroy(&endpoint_id, Some(Duration::from_secs(5)));
        let elapsed = start.elapsed();

        assert!(matches!(outcome, DestroyOutcome::Destroyed { .. }));
        assert!(elapsed < Duration::from_secs(10));
    }

    #[test]
    fn test_hook_integration_via_manager() {
        use soft_fido2_transport::Message;

        let cancel = Arc::new(AtomicBool::new(false));
        let mut manager = EndpointManager::new(
            10,
            cancel,
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
        );

        let endpoint = FakeEndpoint::new();
        let (handler, _commands) = FakeHandler::new();

        let payload = vec![0xA1, 0x01, 0x02];
        let msg = Message::new(0x12345678, Cmd::Cbor, payload, None);
        let packets = msg.to_packets().unwrap();
        for packet in packets {
            endpoint.push_packet(&packet);
        }

        let hook_count = Arc::new(Mutex::new(0u32));
        let hook_count_clone = hook_count.clone();

        let endpoint_id = manager
            .create_and_start_with_transport_and_hooks(
                test_binding(),
                "test".to_string(),
                move |_| handler,
                move || Ok(endpoint.clone()),
                WorkerHooks {
                    on_response_sent: Some(Box::new(move || {
                        *hook_count_clone.lock().unwrap() += 1;
                    })),
                },
            )
            .unwrap();

        std::thread::sleep(Duration::from_millis(50));

        let count = *hook_count.lock().unwrap();
        assert_eq!(
            count, 1,
            "hook should be called once after response written"
        );

        let outcome = manager.destroy(&endpoint_id, None);
        assert!(matches!(outcome, DestroyOutcome::Destroyed { .. }));
    }

    #[test]
    fn test_noop_spawn_preserves_existing_api() {
        let cancel = Arc::new(AtomicBool::new(false));
        let mut manager = EndpointManager::new(
            10,
            cancel,
            WorkerConfig {
                poll_interval: Duration::from_millis(1),
                cache_cleanup_interval: Duration::from_secs(3600),
            },
        );

        let endpoint = FakeEndpoint::new();
        let (handler, _commands) = FakeHandler::new();

        let endpoint_id = manager
            .create_and_start_with_transport(
                test_binding(),
                "test".to_string(),
                move |_| handler,
                move || Ok(endpoint),
            )
            .unwrap();

        std::thread::sleep(Duration::from_millis(20));

        let outcome = manager.destroy(&endpoint_id, None);
        assert!(
            matches!(outcome, DestroyOutcome::Destroyed { .. }),
            "existing API without hooks should work unchanged"
        );
    }

    #[test]
    fn test_ceremony_handler_getinfo_passthrough_and_denied_without_preparation() {
        use super::super::audit::AuditGate;
        use super::super::ceremony::{
            AgentCeremonyHandler, StaticCeremonyContext, StaticCeremonyContextConfig,
        };
        use super::super::interaction::AgentInteractionManager;
        use super::super::policy_engine::PolicyRuntime;
        use super::super::prompt::{DesktopPromptHandle, PromptHandle, PromptMode};
        use super::super::storage::CeremonyScope;
        use crate::agent::ceremony::CeremonyPreparationSlot;
        use passless_core::agent::{AgentConfig, EndpointId, ProfileId};
        use soft_fido2_transport::Message;

        let tmp = std::env::temp_dir().join(format!("passless-test-audit-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        let _ = std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o700));
        let audit_gate = Arc::new(AuditGate::open(&tmp).expect("audit gate open"));

        let agent_config = AgentConfig::default();
        let clock: Arc<dyn super::super::browser::Clock> =
            Arc::new(super::super::browser::SystemClock);
        let monotonic_clock: Arc<dyn super::super::intent::MonotonicClock> =
            Arc::new(super::super::intent::SystemClock::new());
        let policy_runtime = Arc::new(
            PolicyRuntime::new(&agent_config, clock, monotonic_clock)
                .expect("policy runtime creation"),
        );

        let profile_id = ProfileId::new("test-profile").unwrap();
        let captured_context_eid = Arc::new(Mutex::new(None::<EndpointId>));

        let (fake_handler, commands_log) = FakeHandler::new();

        let cancel = Arc::new(AtomicBool::new(false));
        let mut manager = EndpointManager::new(10, cancel, WorkerConfig::default());

        let endpoint = FakeEndpoint::new();

        let getinfo_payload = vec![0x04];
        let getinfo_msg = Message::new(0xAAAABBBB, Cmd::Cbor, getinfo_payload.clone(), None);
        for pkt in getinfo_msg.to_packets().unwrap() {
            endpoint.push_packet(&pkt);
        }

        let mut mc_cbor = vec![0x01];
        mc_cbor.extend_from_slice(&[0xA0]);
        let mc_msg = Message::new(0xCCCCDDDD, Cmd::Cbor, mc_cbor.clone(), None);
        for pkt in mc_msg.to_packets().unwrap() {
            endpoint.push_packet(&pkt);
        }

        let audit_for_factory = audit_gate.clone();
        let policy_for_factory = policy_runtime.clone();
        let profile_id_for_factory = profile_id.clone();
        let captured_eid_clone = captured_context_eid.clone();

        let endpoint_id = manager
            .create_and_start_with_transport(
                test_binding(),
                "test".to_string(),
                move |generated_eid: &EndpointId| {
                    let preparation_slot = Arc::new(CeremonyPreparationSlot::new());
                    let ceremony_scope = CeremonyScope::new();
                    let interaction_manager = Arc::new(AgentInteractionManager::new());
                    let prompt_handle: Arc<dyn PromptHandle> =
                        Arc::new(DesktopPromptHandle::default_config());
                    let op_lock = Arc::new(Mutex::new(()));

                    let ctx = StaticCeremonyContext::new(StaticCeremonyContextConfig {
                        profile_id: profile_id_for_factory.clone(),
                        endpoint_id: generated_eid.clone(),
                        mode: PromptMode::Isolated,
                        policy_runtime: policy_for_factory.clone(),
                        audit_gate: audit_for_factory.clone(),
                        ceremony_scope,
                        require_uv: false,
                        prompt_handle,
                        preparation_slot,
                    })
                    .with_interaction_manager(interaction_manager)
                    .with_operation_lock(op_lock);

                    *captured_eid_clone.lock().unwrap() = Some(generated_eid.clone());

                    AgentCeremonyHandler::new(fake_handler, ctx)
                },
                move || Ok(endpoint.clone()),
            )
            .unwrap();

        let context_eid = captured_context_eid
            .lock()
            .unwrap()
            .clone()
            .expect("factory should have captured the endpoint ID");

        assert_eq!(
            endpoint_id, context_eid,
            "manager-returned endpoint ID must match context endpoint ID"
        );

        std::thread::sleep(Duration::from_millis(80));

        let outcome = manager.destroy(&endpoint_id, None);
        assert!(matches!(outcome, DestroyOutcome::Destroyed { .. }));

        let cmds = commands_log.lock().unwrap();
        assert!(
            cmds.iter()
                .any(|(cmd, data)| *cmd == Cmd::Cbor && data == &getinfo_payload),
            "GetInfo should have been passed through to inner handler"
        );
    }
}
