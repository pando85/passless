use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use passless_core::agent::{AgentMode, EndpointId, ProfileId};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EndpointHandle {
    id: EndpointId,
    generation: u64,
}

impl EndpointHandle {
    pub fn id(&self) -> &EndpointId {
        &self.id
    }

    #[cfg(test)]
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

impl fmt::Display for EndpointHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.id, self.generation)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndpointState {
    Creating,
    Ready,
    Active,
    Draining,
    Destroyed,
    Failed(String),
}

impl EndpointState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, EndpointState::Destroyed | EndpointState::Failed(_))
    }
}

impl fmt::Display for EndpointState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EndpointState::Creating => write!(f, "creating"),
            EndpointState::Ready => write!(f, "ready"),
            EndpointState::Active => write!(f, "active"),
            EndpointState::Draining => write!(f, "draining"),
            EndpointState::Destroyed => write!(f, "destroyed"),
            EndpointState::Failed(reason) => write!(f, "failed({})", reason),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointBinding {
    pub profile_id: ProfileId,
    pub mode: AgentMode,
}

#[derive(Clone, Debug)]
pub struct EndpointSnapshot {
    pub handle: EndpointHandle,
    pub state: EndpointState,
    #[allow(dead_code)]
    pub binding: EndpointBinding,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreateError {
    CapacityExceeded { max: usize, current: usize },
    Shutdown,
}

impl fmt::Display for CreateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CreateError::CapacityExceeded { max, current } => {
                write!(
                    f,
                    "endpoint capacity exceeded: {}/{} active endpoints",
                    current, max
                )
            }
            CreateError::Shutdown => write!(f, "registry is shutting down"),
        }
    }
}

impl std::error::Error for CreateError {}

#[derive(Clone, Debug)]
pub enum CreateOutcome {
    Created(EndpointSnapshot),
    Rejected(CreateError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitionError {
    InvalidTransition {
        from: EndpointState,
        to: EndpointState,
    },
    StaleHandle {
        expected: u64,
        got: u64,
    },
    NotFound,
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransitionError::InvalidTransition { from, to } => {
                write!(f, "invalid transition: {} → {}", from, to)
            }
            TransitionError::StaleHandle { expected, got } => {
                write!(
                    f,
                    "stale handle: expected generation {}, got {}",
                    expected, got
                )
            }
            TransitionError::NotFound => write!(f, "endpoint not found"),
        }
    }
}

impl std::error::Error for TransitionError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitionOutcome {
    Transitioned {
        previous: EndpointState,
        current: EndpointState,
    },
    Rejected(TransitionError),
}

struct EndpointEntry {
    handle: EndpointHandle,
    state: EndpointState,
    binding: EndpointBinding,
}

struct RegistryInner {
    endpoints: HashMap<EndpointId, EndpointEntry>,
    next_generation: u64,
    shutdown: bool,
}

pub struct EndpointRegistry {
    inner: Mutex<RegistryInner>,
    max_endpoints: usize,
}

fn is_valid_transition(from: &EndpointState, to: &EndpointState) -> bool {
    matches!(
        (from, to),
        (EndpointState::Creating, EndpointState::Ready)
            | (EndpointState::Ready, EndpointState::Active)
            | (EndpointState::Active, EndpointState::Draining)
            | (EndpointState::Draining, EndpointState::Destroyed)
            | (EndpointState::Creating, EndpointState::Failed(_))
            | (EndpointState::Ready, EndpointState::Failed(_))
            | (EndpointState::Active, EndpointState::Failed(_))
            | (EndpointState::Draining, EndpointState::Failed(_))
    )
}

impl EndpointRegistry {
    pub fn new(max_endpoints: usize) -> Self {
        Self {
            inner: Mutex::new(RegistryInner {
                endpoints: HashMap::new(),
                next_generation: 1,
                shutdown: false,
            }),
            max_endpoints,
        }
    }

    pub fn create_endpoint(&self, binding: EndpointBinding) -> CreateOutcome {
        let mut inner = self.inner.lock().unwrap();

        if inner.shutdown {
            return CreateOutcome::Rejected(CreateError::Shutdown);
        }

        let active_count = inner
            .endpoints
            .values()
            .filter(|e| !e.state.is_terminal())
            .count();

        if active_count >= self.max_endpoints {
            return CreateOutcome::Rejected(CreateError::CapacityExceeded {
                max: self.max_endpoints,
                current: active_count,
            });
        }

        let generation = inner.next_generation;
        inner.next_generation += 1;
        let id = EndpointId::new();

        let handle = EndpointHandle {
            id: id.clone(),
            generation,
        };

        let snapshot = EndpointSnapshot {
            handle: handle.clone(),
            state: EndpointState::Creating,
            binding: binding.clone(),
        };

        inner.endpoints.insert(
            id,
            EndpointEntry {
                handle,
                state: EndpointState::Creating,
                binding,
            },
        );

        CreateOutcome::Created(snapshot)
    }

    pub fn mark_ready(&self, handle: &EndpointHandle) -> TransitionOutcome {
        self.transition_inner(handle, EndpointState::Ready)
    }

    pub fn mark_active(&self, handle: &EndpointHandle) -> TransitionOutcome {
        self.transition_inner(handle, EndpointState::Active)
    }

    pub fn mark_draining(&self, handle: &EndpointHandle) -> TransitionOutcome {
        self.transition_inner(handle, EndpointState::Draining)
    }

    pub fn mark_destroyed(&self, handle: &EndpointHandle) -> TransitionOutcome {
        self.transition_inner(handle, EndpointState::Destroyed)
    }

    pub fn mark_failed(&self, handle: &EndpointHandle, reason: String) -> TransitionOutcome {
        self.transition_inner(handle, EndpointState::Failed(reason))
    }

    fn transition_inner(
        &self,
        handle: &EndpointHandle,
        target: EndpointState,
    ) -> TransitionOutcome {
        let mut inner = self.inner.lock().unwrap();

        let entry = match inner.endpoints.get_mut(&handle.id) {
            Some(e) => e,
            None => return TransitionOutcome::Rejected(TransitionError::NotFound),
        };

        if entry.handle.generation != handle.generation {
            return TransitionOutcome::Rejected(TransitionError::StaleHandle {
                expected: entry.handle.generation,
                got: handle.generation,
            });
        }

        if !is_valid_transition(&entry.state, &target) {
            return TransitionOutcome::Rejected(TransitionError::InvalidTransition {
                from: entry.state.clone(),
                to: target,
            });
        }

        let previous = entry.state.clone();
        entry.state = target.clone();

        if matches!(target, EndpointState::Destroyed) {
            entry.handle.generation += 1;
        }

        TransitionOutcome::Transitioned {
            previous,
            current: target,
        }
    }

    #[cfg(test)]
    pub fn snapshot(&self, handle: &EndpointHandle) -> Option<EndpointSnapshot> {
        let inner = self.inner.lock().unwrap();

        let entry = inner.endpoints.get(&handle.id)?;

        if entry.handle.generation != handle.generation {
            return None;
        }

        Some(EndpointSnapshot {
            handle: entry.handle.clone(),
            state: entry.state.clone(),
            binding: entry.binding.clone(),
        })
    }

    pub fn list(&self) -> Vec<EndpointSnapshot> {
        let inner = self.inner.lock().unwrap();

        inner
            .endpoints
            .values()
            .map(|e| EndpointSnapshot {
                handle: e.handle.clone(),
                state: e.state.clone(),
                binding: e.binding.clone(),
            })
            .collect()
    }

    pub fn shutdown(&self) -> Vec<EndpointSnapshot> {
        let mut inner = self.inner.lock().unwrap();
        inner.shutdown = true;

        inner
            .endpoints
            .values()
            .map(|e| EndpointSnapshot {
                handle: e.handle.clone(),
                state: e.state.clone(),
                binding: e.binding.clone(),
            })
            .collect()
    }

    #[cfg(test)]
    pub fn is_shutdown(&self) -> bool {
        self.inner.lock().unwrap().shutdown
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner
            .endpoints
            .values()
            .filter(|e| !e.state.is_terminal())
            .count()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn test_binding() -> EndpointBinding {
        EndpointBinding {
            profile_id: ProfileId::new("test-profile").unwrap(),
            mode: AgentMode::Isolated,
        }
    }

    fn test_binding_named(name: &str) -> EndpointBinding {
        EndpointBinding {
            profile_id: ProfileId::new(name).unwrap(),
            mode: AgentMode::Isolated,
        }
    }

    fn create_one(registry: &EndpointRegistry) -> EndpointHandle {
        match registry.create_endpoint(test_binding()) {
            CreateOutcome::Created(s) => s.handle,
            CreateOutcome::Rejected(e) => panic!("create rejected: {}", e),
        }
    }

    fn assert_transitioned(outcome: &TransitionOutcome) {
        assert!(
            matches!(outcome, TransitionOutcome::Transitioned { .. }),
            "expected Transitioned, got {:?}",
            outcome
        );
    }

    fn assert_rejected(outcome: &TransitionOutcome) -> &TransitionError {
        match outcome {
            TransitionOutcome::Rejected(e) => e,
            TransitionOutcome::Transitioned { .. } => {
                panic!("expected Rejected, got Transitioned")
            }
        }
    }

    #[test]
    fn test_create_endpoint_returns_creating_state() {
        let registry = EndpointRegistry::new(10);
        let snapshot = match registry.create_endpoint(test_binding()) {
            CreateOutcome::Created(s) => s,
            CreateOutcome::Rejected(e) => panic!("create rejected: {}", e),
        };
        assert_eq!(snapshot.state, EndpointState::Creating);
        assert_eq!(snapshot.handle.generation(), 1);
    }

    #[test]
    fn test_full_lifecycle_creating_to_destroyed() {
        let registry = EndpointRegistry::new(10);
        let handle = create_one(&registry);

        assert_transitioned(&registry.mark_ready(&handle));
        let snap = registry.snapshot(&handle).unwrap();
        assert_eq!(snap.state, EndpointState::Ready);

        assert_transitioned(&registry.mark_active(&handle));
        let snap = registry.snapshot(&handle).unwrap();
        assert_eq!(snap.state, EndpointState::Active);

        assert_transitioned(&registry.mark_draining(&handle));
        let snap = registry.snapshot(&handle).unwrap();
        assert_eq!(snap.state, EndpointState::Draining);

        assert_transitioned(&registry.mark_destroyed(&handle));
    }

    #[test]
    fn test_destroyed_handle_becomes_stale() {
        let registry = EndpointRegistry::new(10);
        let handle = create_one(&registry);

        assert_transitioned(&registry.mark_ready(&handle));
        assert_transitioned(&registry.mark_active(&handle));
        assert_transitioned(&registry.mark_draining(&handle));
        assert_transitioned(&registry.mark_destroyed(&handle));

        assert!(registry.snapshot(&handle).is_none());

        let outcome = registry.mark_active(&handle);
        let err = assert_rejected(&outcome);
        assert!(matches!(err, TransitionError::StaleHandle { .. }));
    }

    #[test]
    fn test_failed_from_creating() {
        let registry = EndpointRegistry::new(10);
        let handle = create_one(&registry);

        let outcome = registry.mark_failed(&handle, "init error".to_string());
        assert_transitioned(&outcome);

        let snap = registry.snapshot(&handle).unwrap();
        assert_eq!(snap.state, EndpointState::Failed("init error".to_string()));
    }

    #[test]
    fn test_failed_from_ready() {
        let registry = EndpointRegistry::new(10);
        let handle = create_one(&registry);
        assert_transitioned(&registry.mark_ready(&handle));

        let outcome = registry.mark_failed(&handle, "setup error".to_string());
        assert_transitioned(&outcome);

        let snap = registry.snapshot(&handle).unwrap();
        assert_eq!(snap.state, EndpointState::Failed("setup error".to_string()));
    }

    #[test]
    fn test_failed_from_active() {
        let registry = EndpointRegistry::new(10);
        let handle = create_one(&registry);
        assert_transitioned(&registry.mark_ready(&handle));
        assert_transitioned(&registry.mark_active(&handle));

        let outcome = registry.mark_failed(&handle, "runtime error".to_string());
        assert_transitioned(&outcome);
    }

    #[test]
    fn test_failed_from_draining() {
        let registry = EndpointRegistry::new(10);
        let handle = create_one(&registry);
        assert_transitioned(&registry.mark_ready(&handle));
        assert_transitioned(&registry.mark_active(&handle));
        assert_transitioned(&registry.mark_draining(&handle));

        let outcome = registry.mark_failed(&handle, "drain error".to_string());
        assert_transitioned(&outcome);
    }

    #[test]
    fn test_failed_is_terminal() {
        let registry = EndpointRegistry::new(10);
        let handle = create_one(&registry);
        assert_transitioned(&registry.mark_failed(&handle, "error".to_string()));

        let outcome = registry.mark_ready(&handle);
        let err = assert_rejected(&outcome);
        assert!(matches!(err, TransitionError::InvalidTransition { .. }));
    }

    #[test]
    fn test_invalid_transition_creating_to_active() {
        let registry = EndpointRegistry::new(10);
        let handle = create_one(&registry);

        let outcome = registry.mark_active(&handle);
        let err = assert_rejected(&outcome);
        assert!(matches!(
            err,
            TransitionError::InvalidTransition {
                from: EndpointState::Creating,
                to: EndpointState::Active,
            }
        ));
    }

    #[test]
    fn test_invalid_transition_creating_to_draining() {
        let registry = EndpointRegistry::new(10);
        let handle = create_one(&registry);

        let outcome = registry.mark_draining(&handle);
        let err = assert_rejected(&outcome);
        assert!(matches!(err, TransitionError::InvalidTransition { .. }));
    }

    #[test]
    fn test_invalid_transition_creating_to_destroyed() {
        let registry = EndpointRegistry::new(10);
        let handle = create_one(&registry);

        let outcome = registry.mark_destroyed(&handle);
        let err = assert_rejected(&outcome);
        assert!(matches!(err, TransitionError::InvalidTransition { .. }));
    }

    #[test]
    fn test_invalid_transition_ready_to_draining() {
        let registry = EndpointRegistry::new(10);
        let handle = create_one(&registry);
        assert_transitioned(&registry.mark_ready(&handle));

        let outcome = registry.mark_draining(&handle);
        let err = assert_rejected(&outcome);
        assert!(matches!(err, TransitionError::InvalidTransition { .. }));
    }

    #[test]
    fn test_invalid_transition_ready_to_destroyed() {
        let registry = EndpointRegistry::new(10);
        let handle = create_one(&registry);
        assert_transitioned(&registry.mark_ready(&handle));

        let outcome = registry.mark_destroyed(&handle);
        let err = assert_rejected(&outcome);
        assert!(matches!(err, TransitionError::InvalidTransition { .. }));
    }

    #[test]
    fn test_invalid_transition_active_to_ready() {
        let registry = EndpointRegistry::new(10);
        let handle = create_one(&registry);
        assert_transitioned(&registry.mark_ready(&handle));
        assert_transitioned(&registry.mark_active(&handle));

        let outcome = registry.mark_ready(&handle);
        let err = assert_rejected(&outcome);
        assert!(matches!(err, TransitionError::InvalidTransition { .. }));
    }

    #[test]
    fn test_invalid_transition_active_to_destroyed() {
        let registry = EndpointRegistry::new(10);
        let handle = create_one(&registry);
        assert_transitioned(&registry.mark_ready(&handle));
        assert_transitioned(&registry.mark_active(&handle));

        let outcome = registry.mark_destroyed(&handle);
        let err = assert_rejected(&outcome);
        assert!(matches!(err, TransitionError::InvalidTransition { .. }));
    }

    #[test]
    fn test_invalid_transition_draining_to_ready() {
        let registry = EndpointRegistry::new(10);
        let handle = create_one(&registry);
        assert_transitioned(&registry.mark_ready(&handle));
        assert_transitioned(&registry.mark_active(&handle));
        assert_transitioned(&registry.mark_draining(&handle));

        let outcome = registry.mark_ready(&handle);
        let err = assert_rejected(&outcome);
        assert!(matches!(err, TransitionError::InvalidTransition { .. }));
    }

    #[test]
    fn test_invalid_transition_draining_to_active() {
        let registry = EndpointRegistry::new(10);
        let handle = create_one(&registry);
        assert_transitioned(&registry.mark_ready(&handle));
        assert_transitioned(&registry.mark_active(&handle));
        assert_transitioned(&registry.mark_draining(&handle));

        let outcome = registry.mark_active(&handle);
        let err = assert_rejected(&outcome);
        assert!(matches!(err, TransitionError::InvalidTransition { .. }));
    }

    #[test]
    fn test_capacity_exceeded() {
        let registry = EndpointRegistry::new(2);

        let _h1 = create_one(&registry);
        let _h2 = create_one(&registry);

        match registry.create_endpoint(test_binding()) {
            CreateOutcome::Created(_) => panic!("expected capacity exceeded"),
            CreateOutcome::Rejected(e) => {
                assert!(matches!(
                    e,
                    CreateError::CapacityExceeded { max: 2, current: 2 }
                ));
            }
        }
    }

    #[test]
    fn test_capacity_freed_after_destroy() {
        let registry = EndpointRegistry::new(1);
        let handle = create_one(&registry);

        match registry.create_endpoint(test_binding()) {
            CreateOutcome::Created(_) => panic!("expected capacity exceeded"),
            CreateOutcome::Rejected(_) => {}
        }

        assert_transitioned(&registry.mark_ready(&handle));
        assert_transitioned(&registry.mark_active(&handle));
        assert_transitioned(&registry.mark_draining(&handle));
        assert_transitioned(&registry.mark_destroyed(&handle));

        let _h2 = create_one(&registry);
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_capacity_freed_after_failed() {
        let registry = EndpointRegistry::new(1);
        let handle = create_one(&registry);

        assert_transitioned(&registry.mark_failed(&handle, "err".to_string()));

        let _h2 = create_one(&registry);
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_shutdown_prevents_new_creates() {
        let registry = EndpointRegistry::new(10);
        let _handle = create_one(&registry);

        let _snapshots = registry.shutdown();
        assert!(registry.is_shutdown());

        match registry.create_endpoint(test_binding()) {
            CreateOutcome::Created(_) => panic!("expected shutdown rejection"),
            CreateOutcome::Rejected(e) => {
                assert!(matches!(e, CreateError::Shutdown));
            }
        }
    }

    #[test]
    fn test_shutdown_returns_all_snapshots() {
        let registry = EndpointRegistry::new(10);
        let _h1 = create_one(&registry);
        let h2 = create_one(&registry);
        assert_transitioned(&registry.mark_ready(&h2));

        let snapshots = registry.shutdown();
        assert_eq!(snapshots.len(), 2);

        let states: Vec<&EndpointState> = snapshots.iter().map(|s| &s.state).collect();
        assert!(states.contains(&&EndpointState::Creating));
        assert!(states.contains(&&EndpointState::Ready));
    }

    #[test]
    fn test_existing_transitions_after_shutdown() {
        let registry = EndpointRegistry::new(10);
        let handle = create_one(&registry);
        assert_transitioned(&registry.mark_ready(&handle));

        let _ = registry.shutdown();

        assert_transitioned(&registry.mark_active(&handle));
        assert_transitioned(&registry.mark_draining(&handle));
        assert_transitioned(&registry.mark_destroyed(&handle));
    }

    #[test]
    fn test_snapshot_returns_none_for_unknown_handle() {
        let registry = EndpointRegistry::new(10);
        let fake_handle = EndpointHandle {
            id: EndpointId::new(),
            generation: 1,
        };
        assert!(registry.snapshot(&fake_handle).is_none());
    }

    #[test]
    fn test_snapshot_returns_none_for_stale_generation() {
        let registry = EndpointRegistry::new(10);
        let handle = create_one(&registry);

        let stale_handle = EndpointHandle {
            id: handle.id().clone(),
            generation: 999,
        };
        assert!(registry.snapshot(&stale_handle).is_none());
    }

    #[test]
    fn test_transition_not_found_for_unknown_handle() {
        let registry = EndpointRegistry::new(10);
        let fake_handle = EndpointHandle {
            id: EndpointId::new(),
            generation: 1,
        };

        let outcome = registry.mark_ready(&fake_handle);
        let err = assert_rejected(&outcome);
        assert!(matches!(err, TransitionError::NotFound));
    }

    #[test]
    fn test_transition_stale_handle_rejected() {
        let registry = EndpointRegistry::new(10);
        let handle = create_one(&registry);

        let stale_handle = EndpointHandle {
            id: handle.id().clone(),
            generation: handle.generation() + 1,
        };

        let outcome = registry.mark_ready(&stale_handle);
        let err = assert_rejected(&outcome);
        assert!(matches!(
            err,
            TransitionError::StaleHandle {
                expected: 1,
                got: 2,
            }
        ));
    }

    #[test]
    fn test_list_returns_all_endpoints() {
        let registry = EndpointRegistry::new(10);
        let _h1 = create_one(&registry);
        let h2 = create_one(&registry);
        assert_transitioned(&registry.mark_ready(&h2));

        let list = registry.list();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_list_includes_terminal_endpoints() {
        let registry = EndpointRegistry::new(10);
        let handle = create_one(&registry);
        assert_transitioned(&registry.mark_failed(&handle, "err".to_string()));

        let list = registry.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].state, EndpointState::Failed("err".to_string()));
    }

    #[test]
    fn test_len_counts_non_terminal_only() {
        let registry = EndpointRegistry::new(10);
        let h1 = create_one(&registry);
        let _h2 = create_one(&registry);

        assert_eq!(registry.len(), 2);

        assert_transitioned(&registry.mark_failed(&h1, "err".to_string()));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_is_empty() {
        let registry = EndpointRegistry::new(10);
        assert!(registry.is_empty());

        let handle = create_one(&registry);
        assert!(!registry.is_empty());

        assert_transitioned(&registry.mark_failed(&handle, "err".to_string()));
        assert!(registry.is_empty());
    }

    #[test]
    fn test_binding_preserved_in_snapshot() {
        let registry = EndpointRegistry::new(10);
        let binding = EndpointBinding {
            profile_id: ProfileId::new("my-profile").unwrap(),
            mode: AgentMode::DelegatedSession,
        };

        let snapshot = match registry.create_endpoint(binding.clone()) {
            CreateOutcome::Created(s) => s,
            CreateOutcome::Rejected(e) => panic!("create rejected: {}", e),
        };

        assert_eq!(snapshot.binding, binding);
    }

    #[test]
    fn test_transition_outcome_contains_previous_state() {
        let registry = EndpointRegistry::new(10);
        let handle = create_one(&registry);

        let outcome = registry.mark_ready(&handle);
        match &outcome {
            TransitionOutcome::Transitioned { previous, current } => {
                assert_eq!(*previous, EndpointState::Creating);
                assert_eq!(*current, EndpointState::Ready);
            }
            _ => panic!("expected Transitioned"),
        }
    }

    #[test]
    fn test_unique_endpoint_ids() {
        let registry = EndpointRegistry::new(100);
        let mut ids = Vec::new();

        for _ in 0..50 {
            let handle = create_one(&registry);
            ids.push(handle.id().clone());
        }

        let unique: std::collections::HashSet<&EndpointId> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len());
    }

    #[test]
    fn test_monotonic_generations() {
        let registry = EndpointRegistry::new(100);
        let mut generations = Vec::new();

        for _ in 0..20 {
            let handle = create_one(&registry);
            generations.push(handle.generation());
        }

        for i in 1..generations.len() {
            assert!(generations[i] > generations[i - 1]);
        }
    }

    #[test]
    fn test_property_all_created_in_creating_state() {
        let registry = EndpointRegistry::new(100);

        for _ in 0..50 {
            let snapshot = match registry.create_endpoint(test_binding()) {
                CreateOutcome::Created(s) => s,
                CreateOutcome::Rejected(e) => panic!("create rejected: {}", e),
            };
            assert_eq!(snapshot.state, EndpointState::Creating);
        }

        assert_eq!(registry.len(), 50);
    }

    #[test]
    fn test_property_valid_transitions_always_succeed() {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        for _ in 0..100 {
            let registry = EndpointRegistry::new(10);
            let handle = create_one(&registry);

            let steps = rng.gen_range(0..=4);
            let mut current_state = EndpointState::Creating;

            let transitions: Vec<fn(&EndpointRegistry, &EndpointHandle) -> TransitionOutcome> = vec![
                |r, h| r.mark_ready(h),
                |r, h| r.mark_active(h),
                |r, h| r.mark_draining(h),
                |r, h| r.mark_destroyed(h),
            ];

            let valid_sequence = match steps {
                0 => vec![],
                1 => vec![0],
                2 => vec![0, 1],
                3 => vec![0, 1, 2],
                4 => vec![0, 1, 2, 3],
                _ => unreachable!(),
            };

            let expected_states = [
                EndpointState::Creating,
                EndpointState::Ready,
                EndpointState::Active,
                EndpointState::Draining,
                EndpointState::Destroyed,
            ];

            for (i, &step) in valid_sequence.iter().enumerate() {
                let outcome = transitions[step](&registry, &handle);
                assert_transitioned(&outcome);
                current_state = expected_states[i + 1].clone();
            }

            let snap = if current_state == EndpointState::Destroyed {
                let stale_handle = EndpointHandle {
                    id: handle.id().clone(),
                    generation: handle.generation(),
                };
                registry.snapshot(&stale_handle)
            } else {
                registry.snapshot(&handle)
            };

            if current_state != EndpointState::Destroyed {
                assert_eq!(snap.unwrap().state, current_state);
            }
        }
    }

    #[test]
    fn test_property_invalid_transitions_always_rejected() {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let invalid_pairs: Vec<(usize, usize)> = vec![
            (0, 2),
            (0, 3),
            (1, 3),
            (2, 0),
            (2, 1),
            (3, 0),
            (3, 1),
            (3, 2),
        ];

        for _ in 0..100 {
            let (from_idx, to_idx) = invalid_pairs[rng.gen_range(0..invalid_pairs.len())];

            let registry = EndpointRegistry::new(10);
            let handle = create_one(&registry);

            let forward_transitions: &[fn(
                &EndpointRegistry,
                &EndpointHandle,
            ) -> TransitionOutcome] = &[
                |r, h| r.mark_ready(h),
                |r, h| r.mark_active(h),
                |r, h| r.mark_draining(h),
                |r, h| r.mark_destroyed(h),
            ];

            for transition in forward_transitions.iter().take(from_idx) {
                assert_transitioned(&transition(&registry, &handle));
            }

            let outcome = forward_transitions[to_idx](&registry, &handle);
            let err = assert_rejected(&outcome);
            assert!(matches!(err, TransitionError::InvalidTransition { .. }));
        }
    }

    #[test]
    fn test_property_failed_from_any_non_terminal_state() {
        let registry = EndpointRegistry::new(10);

        for transition_to_try in 0..4 {
            let handle = create_one(&registry);

            let forward: &[fn(&EndpointRegistry, &EndpointHandle) -> TransitionOutcome] = &[
                |r, h| r.mark_ready(h),
                |r, h| r.mark_active(h),
                |r, h| r.mark_draining(h),
                |r, h| r.mark_destroyed(h),
            ];

            for transition in forward.iter().take(transition_to_try) {
                assert_transitioned(&transition(&registry, &handle));
            }

            let outcome = registry.mark_failed(&handle, "test error".to_string());
            if transition_to_try < 4 {
                assert_transitioned(&outcome);
                let snap = registry.snapshot(&handle).unwrap();
                assert_eq!(snap.state, EndpointState::Failed("test error".to_string()));
            } else {
                let err = assert_rejected(&outcome);
                assert!(matches!(err, TransitionError::StaleHandle { .. }));
            }
        }
    }

    #[test]
    fn test_concurrent_creates() {
        let registry = Arc::new(EndpointRegistry::new(1000));
        let mut threads = Vec::new();

        for _ in 0..20 {
            let reg = Arc::clone(&registry);
            threads.push(thread::spawn(move || {
                let mut handles = Vec::new();
                for _ in 0..10 {
                    let binding = test_binding_named("concurrent");
                    match reg.create_endpoint(binding) {
                        CreateOutcome::Created(s) => handles.push(s.handle),
                        CreateOutcome::Rejected(_) => {}
                    }
                }
                handles
            }));
        }

        let mut all_handles = Vec::new();
        for t in threads {
            all_handles.extend(t.join().unwrap());
        }

        assert_eq!(all_handles.len(), 200);
        assert_eq!(registry.len(), 200);

        let ids: Vec<&EndpointId> = all_handles.iter().map(|h| h.id()).collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len());
    }

    #[test]
    fn test_concurrent_transitions() {
        let registry = Arc::new(EndpointRegistry::new(100));
        let mut handles = Vec::new();

        for _ in 0..50 {
            handles.push(create_one(&registry));
        }

        let mut threads = Vec::new();

        for handle in handles {
            let reg = Arc::clone(&registry);
            threads.push(thread::spawn(move || {
                let outcome_ready = reg.mark_ready(&handle);
                if matches!(outcome_ready, TransitionOutcome::Transitioned { .. }) {
                    reg.mark_active(&handle);
                }
            }));
        }

        for t in threads {
            t.join().unwrap();
        }

        let active_count = registry
            .list()
            .iter()
            .filter(|s| s.state == EndpointState::Active)
            .count();
        assert_eq!(active_count, 50);
    }

    #[test]
    fn test_concurrent_create_and_drain() {
        let registry = Arc::new(EndpointRegistry::new(50));
        let mut handles = Vec::new();

        for _ in 0..20 {
            handles.push(create_one(&registry));
        }

        let handles_arc = Arc::new(handles);
        let mut threads = Vec::new();

        for i in 0..20 {
            let reg = Arc::clone(&registry);
            let handles_ref = Arc::clone(&handles_arc);

            if i < 10 {
                threads.push(thread::spawn(move || {
                    let handle = &handles_ref[i];
                    reg.mark_ready(handle);
                    reg.mark_active(handle);
                    reg.mark_draining(handle);
                    reg.mark_destroyed(handle);
                }));
            } else {
                threads.push(thread::spawn(move || {
                    let binding = test_binding_named("new-endpoint");
                    reg.create_endpoint(binding);
                }));
            }
        }

        for t in threads {
            t.join().unwrap();
        }

        let list = registry.list();
        assert!(list.len() >= 10);
    }

    #[test]
    fn test_concurrent_shutdown_and_create() {
        let registry = Arc::new(EndpointRegistry::new(100));
        let mut threads = Vec::new();

        for _ in 0..10 {
            let reg = Arc::clone(&registry);
            threads.push(thread::spawn(move || {
                let binding = test_binding_named("pre-shutdown");
                reg.create_endpoint(binding);
            }));
        }

        for t in threads {
            t.join().unwrap();
        }

        let snapshots = registry.shutdown();
        assert!(snapshots.len() >= 10);

        let mut create_threads = Vec::new();
        for _ in 0..10 {
            let reg = Arc::clone(&registry);
            create_threads.push(thread::spawn(move || {
                let binding = test_binding_named("post-shutdown");
                reg.create_endpoint(binding)
            }));
        }

        let mut post_shutdown_rejected = 0;
        for t in create_threads {
            match t.join().unwrap() {
                CreateOutcome::Created(_) => {}
                CreateOutcome::Rejected(CreateError::Shutdown) => {
                    post_shutdown_rejected += 1;
                }
                CreateOutcome::Rejected(_) => {}
            }
        }

        assert!(registry.is_shutdown());
        assert!(post_shutdown_rejected > 0);
    }

    #[test]
    fn test_concurrent_stale_handle_detection() {
        let registry = Arc::new(EndpointRegistry::new(100));
        let handle = create_one(&registry);

        assert_transitioned(&registry.mark_ready(&handle));
        assert_transitioned(&registry.mark_active(&handle));
        assert_transitioned(&registry.mark_draining(&handle));

        let mut threads = Vec::new();

        for _ in 0..10 {
            let reg = Arc::clone(&registry);
            let h = handle.clone();
            threads.push(thread::spawn(move || reg.mark_destroyed(&h)));
        }

        let mut success_count = 0;
        let mut stale_or_invalid_count = 0;

        for t in threads {
            match t.join().unwrap() {
                TransitionOutcome::Transitioned { .. } => success_count += 1,
                TransitionOutcome::Rejected(TransitionError::StaleHandle { .. }) => {
                    stale_or_invalid_count += 1
                }
                TransitionOutcome::Rejected(TransitionError::InvalidTransition { .. }) => {
                    stale_or_invalid_count += 1
                }
                TransitionOutcome::Rejected(TransitionError::NotFound) => {
                    stale_or_invalid_count += 1
                }
            }
        }

        assert_eq!(success_count, 1);
        assert_eq!(stale_or_invalid_count, 9);
    }

    #[test]
    fn test_endpoint_state_display() {
        assert_eq!(EndpointState::Creating.to_string(), "creating");
        assert_eq!(EndpointState::Ready.to_string(), "ready");
        assert_eq!(EndpointState::Active.to_string(), "active");
        assert_eq!(EndpointState::Draining.to_string(), "draining");
        assert_eq!(EndpointState::Destroyed.to_string(), "destroyed");
        assert_eq!(
            EndpointState::Failed("oops".to_string()).to_string(),
            "failed(oops)"
        );
    }

    #[test]
    fn test_endpoint_state_is_terminal() {
        assert!(!EndpointState::Creating.is_terminal());
        assert!(!EndpointState::Ready.is_terminal());
        assert!(!EndpointState::Active.is_terminal());
        assert!(!EndpointState::Draining.is_terminal());
        assert!(EndpointState::Destroyed.is_terminal());
        assert!(EndpointState::Failed("err".to_string()).is_terminal());
    }

    #[test]
    fn test_create_error_display() {
        let e = CreateError::CapacityExceeded {
            max: 10,
            current: 10,
        };
        assert!(e.to_string().contains("10/10"));

        let e = CreateError::Shutdown;
        assert!(e.to_string().contains("shutting down"));
    }

    #[test]
    fn test_transition_error_display() {
        let e = TransitionError::InvalidTransition {
            from: EndpointState::Creating,
            to: EndpointState::Active,
        };
        assert!(e.to_string().contains("creating"));
        assert!(e.to_string().contains("active"));

        let e = TransitionError::StaleHandle {
            expected: 2,
            got: 1,
        };
        assert!(e.to_string().contains("generation"));

        let e = TransitionError::NotFound;
        assert!(e.to_string().contains("not found"));
    }

    #[test]
    fn test_handle_display() {
        let handle = EndpointHandle {
            id: EndpointId::new(),
            generation: 42,
        };
        let display = handle.to_string();
        assert!(display.contains("42"));
    }

    #[test]
    fn test_zero_capacity_registry() {
        let registry = EndpointRegistry::new(0);

        match registry.create_endpoint(test_binding()) {
            CreateOutcome::Created(_) => panic!("expected capacity exceeded"),
            CreateOutcome::Rejected(e) => {
                assert!(matches!(
                    e,
                    CreateError::CapacityExceeded { max: 0, current: 0 }
                ));
            }
        }
    }

    #[test]
    fn test_double_shutdown_is_idempotent() {
        let registry = EndpointRegistry::new(10);
        let _handle = create_one(&registry);

        let s1 = registry.shutdown();
        let s2 = registry.shutdown();

        assert_eq!(s1.len(), s2.len());
        assert!(registry.is_shutdown());
    }

    #[test]
    fn test_property_random_lifecycle_paths() {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        for _ in 0..200 {
            let registry = EndpointRegistry::new(10);
            let handle = create_one(&registry);

            let fail_at = rng.gen_range(0..=5);

            let transitions: &[fn(&EndpointRegistry, &EndpointHandle) -> TransitionOutcome] = &[
                |r, h| r.mark_ready(h),
                |r, h| r.mark_active(h),
                |r, h| r.mark_draining(h),
                |r, h| r.mark_destroyed(h),
            ];

            let mut reached_destroyed = false;

            for (step, transition) in transitions.iter().enumerate().take(4) {
                if step == fail_at {
                    let outcome = registry.mark_failed(&handle, "random".to_string());
                    assert_transitioned(&outcome);
                    break;
                }

                let outcome = transition(&registry, &handle);

                if step == 3 {
                    if matches!(outcome, TransitionOutcome::Transitioned { .. }) {
                        reached_destroyed = true;
                    }
                    break;
                }

                match outcome {
                    TransitionOutcome::Transitioned { .. } => {}
                    TransitionOutcome::Rejected(_) => break,
                }
            }

            if !reached_destroyed {
                let list = registry.list();
                assert!(!list.is_empty());
            }
        }
    }

    #[test]
    fn test_concurrent_property_no_data_corruption() {
        let registry = Arc::new(EndpointRegistry::new(500));
        let mut threads = Vec::new();

        for t_id in 0..10 {
            let reg = Arc::clone(&registry);
            threads.push(thread::spawn(move || {
                let mut local_handles = Vec::new();

                for _ in 0..20 {
                    let binding = EndpointBinding {
                        profile_id: ProfileId::new(format!("profile-{}", t_id).as_str()).unwrap(),
                        mode: AgentMode::Isolated,
                    };
                    match reg.create_endpoint(binding) {
                        CreateOutcome::Created(s) => local_handles.push(s.handle),
                        CreateOutcome::Rejected(_) => break,
                    }
                }

                for handle in &local_handles {
                    let _ = reg.mark_ready(handle);
                    let _ = reg.mark_active(handle);
                }

                for handle in &local_handles {
                    let _ = reg.mark_draining(handle);
                    let _ = reg.mark_destroyed(handle);
                }

                local_handles.len()
            }));
        }

        let total_created: usize = threads.into_iter().map(|t| t.join().unwrap()).sum();
        assert!(total_created > 0);
        assert_eq!(registry.len(), 0);
    }
}
