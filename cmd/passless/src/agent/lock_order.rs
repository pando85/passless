//! Debug-build checks of the agent lock order documented in `agent/LOCKING.md`.
//!
//! Every tracked acquisition declares its [`LockLevel`]. A thread may only acquire a lock whose level
//! is strictly greater than every level it already holds, so two locks of the same level never nest
//! either. In debug builds a violation panics at the acquisition that breaks the order, before the
//! thread can block on the lock; release builds compile the checks away.

use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

#[cfg(debug_assertions)]
use std::cell::RefCell;

/// Lock levels in acquisition order (lower first). See `LOCKING.md` for what each level covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LockLevel {
    /// `AgentRuntime::managed_sessions[profile]`, held across one principal request.
    ManagedSession = 5,
    /// `ProfileRuntime::lifecycle_lock` (browser launch is single-flight per profile).
    ProfileLifecycle = 10,
    /// The backend operation lock (in same-user mode this is the human authenticator's lock).
    Operation = 20,
    /// `BrowserProcessManager`.
    BrowserManager = 30,
    /// The backend credential storage mutex.
    Storage = 40,
    /// `AgentRuntime::agent_config` (the configuration in force; written only by a reload).
    AgentConfig = 45,
    /// The `SignContextRegistry` maps.
    SignRegistry = 50,
    /// `RequestLimiter::profiles` (per-profile counters; a short section, nothing nested).
    Capacity = 55,
    /// A bearer session's replay and budget table.
    Session = 60,
    /// A profile's granted-rules write mutex (`GrantedRulesStore`): held across the store file
    /// write, its reload and the view swap; released before any epoch bump.
    GrantedRulesFile = 64,
    /// One in-flight ceremony's outcome slot (join waiters park on its condvar).
    InFlight = 65,
    /// A session's key-use gate: read from the pre-key-use re-check to the end of key use, write
    /// by `AgentSession::revoke`.
    SessionKeyUse = 66,
    /// `PolicyRuntime::reload_lock` (serializes reloads; held across the policy leaf locks).
    PolicyReload = 68,
    /// The revocation-epoch gate: read from the pre-key-use re-check to the end of key use, write
    /// by `PolicyRuntime::bump_revocation_epoch` (taken under `reload_lock` by a reload).
    EpochKeyUse = 69,
    /// Every other `PolicyRuntime` lock. A policy guard is never held across another acquisition.
    Policy = 70,
    /// The granted-rules store's loaded views, read by resolution. A leaf.
    GrantedRulesView = 71,
    /// The sign transport's readiness registry (`transport::ReadinessRegistry`). A leaf: callers may
    /// hold the profile lifecycle lock and the browser manager while they read or wait on it.
    TransportReadiness = 72,
    /// The sign transport's connection table and a connection's in-flight request table. Leaves.
    TransportConnection = 74,
    /// A transport connection's write mutex (one frame at a time). A leaf.
    TransportWrite = 76,
    /// Reserved for the P7 escalation service mutex (a leaf).
    Escalation = 80,
}

impl LockLevel {
    /// A leaf lock is never held across any other tracked acquisition.
    pub fn is_leaf(self) -> bool {
        matches!(
            self,
            Self::Policy
                | Self::GrantedRulesView
                | Self::TransportReadiness
                | Self::TransportConnection
                | Self::TransportWrite
                | Self::Escalation
        )
    }
}

#[cfg(debug_assertions)]
thread_local! {
    static HELD: RefCell<Vec<LockLevel>> = const { RefCell::new(Vec::new()) };
}

/// Marks a level as held by this thread until it is dropped.
#[must_use = "the level is released when the guard is dropped"]
pub struct LevelGuard {
    #[cfg(debug_assertions)]
    level: LockLevel,
}

/// Declare that this thread is about to acquire a lock of `level`.
///
/// Panics in debug builds when the thread already holds a lock of the same or a higher level.
pub fn enter(level: LockLevel) -> LevelGuard {
    #[cfg(debug_assertions)]
    {
        HELD.with(|held| {
            let mut held = held.borrow_mut();
            if let Some(highest) = held.iter().max()
                && (*highest >= level || highest.is_leaf())
            {
                panic!(
                    "lock order violation: acquiring {:?} while holding {:?} (held: {:?}); see agent/LOCKING.md",
                    level, highest, held
                );
            }
            held.push(level);
        });
        LevelGuard { level }
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = level;
        LevelGuard {}
    }
}

impl Drop for LevelGuard {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        HELD.with(|held| {
            let mut held = held.borrow_mut();
            if let Some(index) = held.iter().rposition(|level| *level == self.level) {
                held.remove(index);
            }
        });
    }
}

/// A lock guard that also holds its level. The lock is released before the level.
pub struct Tracked<G> {
    guard: G,
    _level: LevelGuard,
}

impl<G> Tracked<G> {
    pub fn new(level: LevelGuard, guard: G) -> Self {
        Self {
            guard,
            _level: level,
        }
    }
}

impl<G: std::ops::Deref> std::ops::Deref for Tracked<G> {
    type Target = G::Target;
    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<G: std::ops::DerefMut> std::ops::DerefMut for Tracked<G> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl<'a, T> Tracked<MutexGuard<'a, T>> {
    /// Wait on `condvar` for at most `timeout`, keeping the level declared while parked.
    pub fn wait_timeout(self, condvar: &std::sync::Condvar, timeout: std::time::Duration) -> Self {
        let Tracked { guard, _level } = self;
        let guard = match condvar.wait_timeout(guard, timeout) {
            Ok((guard, _)) => guard,
            Err(poisoned) => poisoned.into_inner().0,
        };
        Tracked { guard, _level }
    }
}

/// Lock `mutex` at `level`, checking the order first. A poisoned lock is recovered: every tracked
/// lock protects state that stays consistent across a panic (maps and counters updated in place).
pub fn lock<T>(mutex: &Mutex<T>, level: LockLevel) -> Tracked<MutexGuard<'_, T>> {
    let entered = enter(level);
    let guard = mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Tracked::new(entered, guard)
}

/// Read-lock `rwlock` at `level`, checking the order first (poison is recovered).
pub fn read<T>(rwlock: &RwLock<T>, level: LockLevel) -> Tracked<RwLockReadGuard<'_, T>> {
    let entered = enter(level);
    let guard = rwlock
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Tracked::new(entered, guard)
}

/// Write-lock `rwlock` at `level`, checking the order first (poison is recovered).
pub fn write<T>(rwlock: &RwLock<T>, level: LockLevel) -> Tracked<RwLockWriteGuard<'_, T>> {
    let entered = enter(level);
    let guard = rwlock
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Tracked::new(entered, guard)
}

/// Levels this thread holds (debug builds; empty in release builds).
#[cfg(test)]
pub fn held_levels() -> Vec<LockLevel> {
    #[cfg(debug_assertions)]
    {
        HELD.with(|held| held.borrow().clone())
    }
    #[cfg(not(debug_assertions))]
    {
        Vec::new()
    }
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::*;

    #[test]
    fn ascending_acquisition_is_allowed_and_released() {
        let a = Mutex::new(1);
        let b = Mutex::new(2);
        {
            let _op = lock(&a, LockLevel::Operation);
            let _storage = lock(&b, LockLevel::Storage);
            assert_eq!(
                held_levels(),
                vec![LockLevel::Operation, LockLevel::Storage]
            );
        }
        assert!(held_levels().is_empty());
    }

    #[test]
    #[should_panic(expected = "lock order violation")]
    fn descending_acquisition_panics() {
        let a = Mutex::new(1);
        let b = Mutex::new(2);
        let _storage = lock(&a, LockLevel::Storage);
        let _op = lock(&b, LockLevel::Operation);
    }

    #[test]
    #[should_panic(expected = "lock order violation")]
    fn policy_guard_is_never_held_across_another_policy_acquisition() {
        let a = Mutex::new(1);
        let b = Mutex::new(2);
        let _first = lock(&a, LockLevel::Policy);
        let _second = lock(&b, LockLevel::Policy);
    }

    #[test]
    #[should_panic(expected = "lock order violation")]
    fn policy_guard_is_never_held_across_a_session_acquisition() {
        let a = Mutex::new(1);
        let b = Mutex::new(2);
        let _policy = lock(&a, LockLevel::Policy);
        let _session = lock(&b, LockLevel::Session);
    }

    #[test]
    #[should_panic(expected = "lock order violation")]
    fn policy_guard_is_a_leaf_even_below_the_escalation_level() {
        let a = Mutex::new(1);
        let b = Mutex::new(2);
        let _policy = lock(&a, LockLevel::Policy);
        let _escalation = lock(&b, LockLevel::Escalation);
    }
    #[test]
    fn granted_rules_writer_may_swap_the_view() {
        let writer = Mutex::new(());
        let view = RwLock::new(());
        let _writer = lock(&writer, LockLevel::GrantedRulesFile);
        let _view = write(&view, LockLevel::GrantedRulesView);
        assert_eq!(
            held_levels(),
            vec![LockLevel::GrantedRulesFile, LockLevel::GrantedRulesView]
        );
    }

    #[test]
    #[should_panic(expected = "lock order violation")]
    fn granted_rules_view_is_a_leaf() {
        let view = RwLock::new(());
        let b = Mutex::new(());
        let _view = read(&view, LockLevel::GrantedRulesView);
        let _escalation = lock(&b, LockLevel::Escalation);
    }
}
