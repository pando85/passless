//! Concurrency caps of the agent ceremony server (plan R11).
//!
//! A request is admitted only when the global cap, its profile's cap, its connection's cap and its
//! session's cap all have room. The profile cap keeps one profile from exhausting the global cap. A request over any cap is answered with an explicit `busy` error; nothing is dropped
//! silently. Overflow is logged at most once per [`OVERFLOW_LOG_INTERVAL`] with a count of the
//! rejections in between, so a flood cannot flood the log.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use log::warn;

use passless_core::agent::{AgentRequestLimits, ProfileId};

use super::lock_order::{self, LockLevel};
use super::session::AgentSession;

/// Connections accepted beyond the global request cap. Each connection has a reader thread; a
/// connection beyond this headroom is answered `error{busy}` and closed by the accept loop.
pub const BUSY_CONNECTION_HEADROOM: usize = 16;
/// Minimum interval between two overflow log lines.
pub const OVERFLOW_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// Which cap a rejected request hit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusyScope {
    /// The global request cap.
    Global,
    /// The per-profile request cap.
    Profile,
    /// The per-connection request cap.
    Connection,
    /// The per-session request cap.
    Session,
    /// The accept loop's connection cap (the request was not read).
    Connections,
}

impl BusyScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Profile => "profile",
            Self::Connection => "connection",
            Self::Session => "session",
            Self::Connections => "connections",
        }
    }
}

/// Concurrent requests carried by one sign-transport connection (the multiplexed `connectNative`
/// connection of plan D2). Created once per accepted connection.
#[derive(Debug, Default)]
pub struct ConnectionSlots {
    active: AtomicUsize,
}

impl ConnectionSlots {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
}

/// Increment `counter` unless it already reached `max`.
pub fn try_increment(counter: &AtomicUsize, max: usize) -> bool {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        if current >= max {
            return false;
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

/// Decrement `counter`, never below zero.
pub fn decrement(counter: &AtomicUsize) {
    let mut current = counter.load(Ordering::Acquire);
    while current > 0 {
        match counter.compare_exchange_weak(
            current,
            current - 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
}

/// Admission control for ceremony requests.
pub struct RequestLimiter {
    limits: AgentRequestLimits,
    global: AtomicUsize,
    /// Per-profile counters, created on first use (a short leaf lock, never held across anything).
    profiles: Mutex<HashMap<ProfileId, Arc<AtomicUsize>>>,
    started: Instant,
    /// Milliseconds since `started` of the last overflow log line, plus one (0 = never).
    last_overflow_log_ms: AtomicU64,
    suppressed_overflows: AtomicU64,
}

impl RequestLimiter {
    pub fn new(limits: AgentRequestLimits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            global: AtomicUsize::new(0),
            profiles: Mutex::new(HashMap::new()),
            started: Instant::now(),
            last_overflow_log_ms: AtomicU64::new(0),
            suppressed_overflows: AtomicU64::new(0),
        })
    }

    pub fn limits(&self) -> &AgentRequestLimits {
        &self.limits
    }

    /// Open connections the accept loop serves with a reader thread.
    pub fn max_connections(&self) -> usize {
        usize::from(self.limits.max_concurrent_requests) + BUSY_CONNECTION_HEADROOM
    }

    /// Requests currently admitted.
    pub fn active(&self) -> usize {
        self.global.load(Ordering::Acquire)
    }

    /// Admit one request carried by `connection` for `session`, or report the cap it hit.
    pub fn try_acquire(
        self: &Arc<Self>,
        connection: &Arc<ConnectionSlots>,
        session: &Arc<AgentSession>,
    ) -> Result<RequestPermit, BusyScope> {
        let profile = self.profile_counter(session.profile_id());
        if !try_increment(
            &self.global,
            usize::from(self.limits.max_concurrent_requests),
        ) {
            return Err(BusyScope::Global);
        }
        if !try_increment(&profile, usize::from(self.limits.max_requests_per_profile)) {
            decrement(&self.global);
            return Err(BusyScope::Profile);
        }
        if !try_increment(
            &connection.active,
            usize::from(self.limits.max_requests_per_connection),
        ) {
            decrement(&profile);
            decrement(&self.global);
            return Err(BusyScope::Connection);
        }
        if !try_increment(
            session.active_requests(),
            usize::from(self.limits.max_requests_per_session),
        ) {
            decrement(&connection.active);
            decrement(&profile);
            decrement(&self.global);
            return Err(BusyScope::Session);
        }
        Ok(RequestPermit {
            limiter: self.clone(),
            profile,
            connection: connection.clone(),
            session: session.clone(),
        })
    }

    fn profile_counter(&self, profile_id: &ProfileId) -> Arc<AtomicUsize> {
        lock_order::lock(&self.profiles, LockLevel::Capacity)
            .entry(profile_id.clone())
            .or_default()
            .clone()
    }

    /// Requests currently admitted for `profile_id`.
    pub fn active_for_profile(&self, profile_id: &ProfileId) -> usize {
        self.profile_counter(profile_id).load(Ordering::Acquire)
    }

    /// Record a rejected request. Logs at most once per [`OVERFLOW_LOG_INTERVAL`].
    pub fn note_overflow(&self, scope: BusyScope) {
        let now_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let last = self.last_overflow_log_ms.load(Ordering::Acquire);
        let interval_ms = u64::try_from(OVERFLOW_LOG_INTERVAL.as_millis()).unwrap_or(u64::MAX);
        let due = last == 0 || now_ms.saturating_add(1).saturating_sub(last) >= interval_ms;
        if due
            && self
                .last_overflow_log_ms
                .compare_exchange(
                    last,
                    now_ms.saturating_add(1),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
        {
            let suppressed = self.suppressed_overflows.swap(0, Ordering::AcqRel);
            warn!(
                "agent ceremony request answered busy ({} cap reached; {} more busy replies since the last report)",
                scope.as_str(),
                suppressed
            );
        } else {
            self.suppressed_overflows.fetch_add(1, Ordering::AcqRel);
        }
    }
}

/// One admitted request. Dropping it releases its slot in every cap.
pub struct RequestPermit {
    limiter: Arc<RequestLimiter>,
    profile: Arc<AtomicUsize>,
    connection: Arc<ConnectionSlots>,
    session: Arc<AgentSession>,
}

impl Drop for RequestPermit {
    fn drop(&mut self) {
        decrement(self.session.active_requests());
        decrement(&self.connection.active);
        decrement(&self.profile);
        decrement(&self.limiter.global);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use passless_core::agent::ProfileId;

    use super::super::session::SessionBinding;

    fn session() -> Arc<AgentSession> {
        session_of("p")
    }

    fn session_of(profile: &str) -> Arc<AgentSession> {
        AgentSession::new(SessionBinding {
            profile_id: ProfileId::new(profile).unwrap(),
            principal_digest: [0u8; 32],
            revocation_epoch: 1,
            ttl: Duration::from_secs(60),
        })
    }

    fn limits(global: u16, connection: u16, session: u16) -> AgentRequestLimits {
        AgentRequestLimits {
            max_concurrent_requests: global,
            max_requests_per_profile: global,
            max_requests_per_connection: connection,
            max_requests_per_session: session,
        }
    }

    #[test]
    fn each_cap_rejects_with_its_scope_and_permits_release_every_slot() {
        let limiter = RequestLimiter::new(limits(3, 2, 2));
        let conn = ConnectionSlots::new();
        let s1 = session();
        let a = limiter.try_acquire(&conn, &s1).unwrap();
        let b = limiter.try_acquire(&conn, &s1).unwrap();
        // The connection is full before the session or the global cap.
        assert_eq!(
            limiter.try_acquire(&conn, &s1).err(),
            Some(BusyScope::Connection)
        );
        let other_conn = ConnectionSlots::new();
        assert_eq!(
            limiter.try_acquire(&other_conn, &s1).err(),
            Some(BusyScope::Session)
        );
        let s2 = session();
        let c = limiter.try_acquire(&other_conn, &s2).unwrap();
        assert_eq!(
            limiter
                .try_acquire(&ConnectionSlots::new(), &session())
                .err(),
            Some(BusyScope::Global)
        );
        // Rejections leave no slot behind.
        assert_eq!(limiter.active(), 3);
        assert_eq!(conn.active(), 2);
        drop((a, b, c));
        assert_eq!(limiter.active(), 0);
        assert_eq!(conn.active(), 0);
        assert_eq!(other_conn.active(), 0);
        assert_eq!(s1.active_requests().load(Ordering::Acquire), 0);
        assert!(limiter.try_acquire(&conn, &s1).is_ok());
    }

    #[test]
    fn concurrent_acquisition_never_exceeds_the_global_cap() {
        let limiter = RequestLimiter::new(limits(5, 64, 64));
        let s = session();
        let admitted = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..32 {
                scope.spawn(|| {
                    let conn = ConnectionSlots::new();
                    if let Ok(permit) = limiter.try_acquire(&conn, &s) {
                        admitted.fetch_add(1, Ordering::AcqRel);
                        peak.fetch_max(limiter.active(), Ordering::AcqRel);
                        std::thread::sleep(Duration::from_millis(20));
                        drop(permit);
                    }
                });
            }
        });
        assert!(peak.load(Ordering::Acquire) <= 5);
        assert!(admitted.load(Ordering::Acquire) >= 5);
        assert_eq!(limiter.active(), 0);
    }

    #[test]
    fn overflow_logging_is_rate_limited() {
        let limiter = RequestLimiter::new(limits(1, 1, 1));
        for _ in 0..100 {
            limiter.note_overflow(BusyScope::Global);
        }
        // One line was logged; the other 99 were counted as suppressed.
        assert_eq!(limiter.suppressed_overflows.load(Ordering::Acquire), 99);
    }

    #[test]
    fn one_profile_saturating_its_cap_leaves_room_for_another_profile() {
        let limiter = RequestLimiter::new(AgentRequestLimits {
            max_concurrent_requests: 32,
            max_requests_per_profile: 16,
            max_requests_per_connection: 8,
            max_requests_per_session: 8,
        });
        // Profile A: several sessions, each within its own cap, together saturate A's cap.
        let mut held = Vec::new();
        for _ in 0..4 {
            let session = session_of("a");
            for _ in 0..4 {
                held.push(
                    limiter
                        .try_acquire(&ConnectionSlots::new(), &session)
                        .unwrap(),
                );
            }
        }
        let a = ProfileId::new("a").unwrap();
        assert_eq!(limiter.active_for_profile(&a), 16);
        assert_eq!(
            limiter
                .try_acquire(&ConnectionSlots::new(), &session_of("a"))
                .err(),
            Some(BusyScope::Profile)
        );
        // Profile B still proceeds.
        let b = session_of("b");
        let permit = limiter.try_acquire(&ConnectionSlots::new(), &b).unwrap();
        drop(permit);
        drop(held);
        assert_eq!(limiter.active_for_profile(&a), 0);
        assert_eq!(limiter.active(), 0);
    }

    #[test]
    fn the_connection_cap_counts_requests_of_one_connection() {
        // One multiplexed connection (P6) carrying requests of several sessions.
        let limiter = RequestLimiter::new(AgentRequestLimits {
            max_concurrent_requests: 32,
            max_requests_per_profile: 32,
            max_requests_per_connection: 3,
            max_requests_per_session: 8,
        });
        let conn = ConnectionSlots::new();
        let permits: Vec<_> = (0..3)
            .map(|_| limiter.try_acquire(&conn, &session()).unwrap())
            .collect();
        assert_eq!(
            limiter.try_acquire(&conn, &session()).err(),
            Some(BusyScope::Connection)
        );
        assert!(
            limiter
                .try_acquire(&ConnectionSlots::new(), &session())
                .is_ok()
        );
        drop(permits);
        assert_eq!(conn.active(), 0);
    }
}
