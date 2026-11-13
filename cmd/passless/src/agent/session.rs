//! Bearer sessions: binding, replay keys and the operation budget (ADR 0014 section 9; plan R1, R4,
//! R16, V-L1).
//!
//! A session is created when a managed browser is launched for a principal. Its bearer token is
//! shared by the sign and registration paths, and so is this state: one replay table, one budget and
//! one revocation flag per bearer.
//!
//! Replay (R1): the key is `SHA-256(action ‖ rp_id ‖ origin ‖ top_origin ‖ challenge)` (see
//! [`ReplayKey::derive`] for the exact encoding). An identical key never reaches key use twice:
//! while the first request is in flight a duplicate joins it and waits until its own ceremony
//! deadline; after completion a duplicate receives the original outcome for
//! [`COMPLETED_OUTCOME_TTL`]; any later repeat, and any other request that reuses the challenge
//! with a different action, RP or origin, is rejected. A failure consumes the key like a success.
//!
//! Budget (R4): a fresh key claims one operation from the live `max_operations`. A duplicate never
//! claims budget, and a request that is rejected before its replay key is checked (origin, policy,
//! malformed request) never reaches the budget.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use rand::RngCore;
use sha2::{Digest, Sha256};

use passless_core::agent::protocol::{
    ErrorCode, PrincipalResponse, ProtocolError, RecommendedAction, RegisterCredentialResponse,
};
use passless_core::agent::{GrantId, PrincipalSessionId, ProfileId};

use super::escalation::ParkHook;
use super::lock_order::{self, LockLevel};
use super::refusal_ledger::RefusalLedger;

/// How long a completed outcome is returned to an identical duplicate (ADR 0014 section 9).
pub const COMPLETED_OUTCOME_TTL: Duration = Duration::from_secs(120);
/// Ceremony timeout assumed when the request carries none.
pub const DEFAULT_CEREMONY_TIMEOUT: Duration = Duration::from_secs(120);
/// Shortest ceremony timeout honored.
pub const MIN_CEREMONY_TIMEOUT: Duration = Duration::from_secs(1);
/// Shortest ceremony timeout of a transport-carried ceremony: Chromium's own lower clamp (3 min,
/// `kMinRequestTimeout`), so an escalation is not cut short before the page gives up.
pub const MIN_TRANSPORT_CEREMONY_TIMEOUT: Duration = Duration::from_secs(180);
/// Longest ceremony timeout honored: Chromium's own upper clamp (20 h).
pub const MAX_CEREMONY_TIMEOUT: Duration = Duration::from_secs(20 * 3600);
/// Served duplicates of one replay key that are audited; later ones are still served, not audited,
/// so a page that resubmits in a loop cannot flood the audit log.
pub const MAX_AUDITED_SERVES_PER_KEY: u32 = 16;
/// Joined duplicates of one in-flight ceremony whose request permit is suspended while they wait.
/// Suspending frees the permit's capacity slots, so it is bounded per slot: a duplicate beyond
/// this keeps its permit and the request caps bound it, as they bound any other request.
pub const MAX_SUSPENDED_DUPLICATES_PER_KEY: usize = 4;
/// How often a joined duplicate re-checks its cancellation while it waits.
const JOIN_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The ceremony deadline for a request that asked for `timeout_ms`, starting at `now`.
pub fn ceremony_deadline(timeout_ms: Option<u64>, now: Instant) -> Instant {
    let timeout = timeout_ms
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_CEREMONY_TIMEOUT)
        .clamp(MIN_CEREMONY_TIMEOUT, MAX_CEREMONY_TIMEOUT);
    now + timeout
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CeremonyAction {
    Authenticate,
    Register,
}

impl CeremonyAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authenticate => "authenticate",
            Self::Register => "register",
        }
    }
}

/// The replay key of one WebAuthn request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReplayKey([u8; 32]);

/// Digest of a request challenge, used to reject a reused challenge under a different key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChallengeDigest([u8; 32]);

fn put_field(hasher: &mut Sha256, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
}

impl ReplayKey {
    /// `SHA-256(action ‖ rp_id ‖ origin ‖ top_origin ‖ challenge)` with an unambiguous encoding:
    ///
    /// - `action`, `rp_id`, `origin` and `challenge` are each written as a 4-byte big-endian length
    ///   followed by the bytes (`action` is `authenticate` or `register`; `rp_id` is the normalized
    ///   RP ID; `origin` is the origin string as validated; `challenge` is the decoded challenge
    ///   bytes, so two base64url spellings of one challenge are one key);
    /// - `top_origin` is a presence tag: `0x00` when absent (always on the proxy path, ADR 0014
    ///   section 11), or `0x01` followed by the length-prefixed top origin.
    ///
    /// Every field is length-prefixed, so no two different tuples share an encoding.
    pub fn derive(
        action: CeremonyAction,
        rp_id: &str,
        origin: &str,
        top_origin: Option<&str>,
        challenge: &[u8],
    ) -> Self {
        let mut hasher = Sha256::new();
        put_field(&mut hasher, action.as_str().as_bytes());
        put_field(&mut hasher, rp_id.as_bytes());
        put_field(&mut hasher, origin.as_bytes());
        match top_origin {
            None => hasher.update([0x00]),
            Some(top) => {
                hasher.update([0x01]);
                put_field(&mut hasher, top.as_bytes());
            }
        }
        put_field(&mut hasher, challenge);
        Self(hasher.finalize().into())
    }
}

impl ChallengeDigest {
    pub fn of(challenge: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        put_field(&mut hasher, challenge);
        Self(hasher.finalize().into())
    }
}

/// A successful ceremony result, as returned to the extension.
#[derive(Clone, Debug)]
pub enum CeremonyResult {
    Assertion(Box<PrincipalResponse>),
    Attestation(Box<RegisterCredentialResponse>),
}

pub type CeremonyOutcome = Result<CeremonyResult, ProtocolError>;

fn internal_failure(message: &str) -> ProtocolError {
    ProtocolError::new(ErrorCode::Internal, message, RecommendedAction::Abort)
}

/// The outcome slot of one in-flight ceremony. Duplicates of the same replay key park on it.
pub struct InFlight {
    outcome: Mutex<Option<CeremonyOutcome>>,
    done: Condvar,
    /// Duplicates waiting here with their request permit suspended.
    suspended: AtomicUsize,
}

/// A duplicate waiting with its request permit suspended. Resumes the permit when dropped.
struct SuspendedDuplicate<'a> {
    in_flight: &'a InFlight,
    hook: &'a mut dyn ParkHook,
}

impl Drop for SuspendedDuplicate<'_> {
    fn drop(&mut self) {
        self.hook.resume();
        self.in_flight.suspended.fetch_sub(1, Ordering::AcqRel);
    }
}

/// What a joined duplicate gets.
#[derive(Debug)]
pub enum JoinResult {
    /// The original finished; this is its outcome.
    Completed(CeremonyOutcome),
    /// The duplicate's own ceremony deadline passed first. The original is unaffected.
    DeadlineExceeded,
    /// The duplicate was aborted (its client went away). Only the duplicate is detached.
    Detached,
}

impl InFlight {
    fn new() -> Self {
        Self {
            outcome: Mutex::new(None),
            done: Condvar::new(),
            suspended: AtomicUsize::new(0),
        }
    }

    /// Suspend the duplicate's request permit for the wait, unless the outcome is already there or
    /// [`MAX_SUSPENDED_DUPLICATES_PER_KEY`] duplicates are already suspended on this slot. The
    /// permit is resumed when the returned guard drops, also on unwinding.
    fn suspend_duplicate<'a>(
        &'a self,
        hook: &'a mut dyn ParkHook,
    ) -> Option<SuspendedDuplicate<'a>> {
        if lock_order::lock(&self.outcome, LockLevel::InFlight).is_some() {
            return None;
        }
        let mut current = self.suspended.load(Ordering::Acquire);
        loop {
            if current >= MAX_SUSPENDED_DUPLICATES_PER_KEY {
                return None;
            }
            match self.suspended.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        hook.suspend();
        Some(SuspendedDuplicate {
            in_flight: self,
            hook,
        })
    }

    fn publish(&self, outcome: CeremonyOutcome) {
        let mut slot = lock_order::lock(&self.outcome, LockLevel::InFlight);
        if slot.is_none() {
            *slot = Some(outcome);
        }
        drop(slot);
        self.done.notify_all();
    }

    /// Wait for the original's outcome until `deadline`, checking `cancelled` between waits.
    /// Waiting never holds any lock but this slot's, and a detached duplicate leaves the original
    /// running (V-L1). `park` suspends the duplicate's request permit while it waits (the
    /// original may be parked on an escalation for minutes), resuming it afterwards.
    pub fn join(
        &self,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
        park: &mut dyn ParkHook,
    ) -> JoinResult {
        #[cfg(test)]
        test_hooks::on_join();
        let _suspended = self.suspend_duplicate(park);
        loop {
            {
                let slot = lock_order::lock(&self.outcome, LockLevel::InFlight);
                if let Some(outcome) = slot.as_ref() {
                    return JoinResult::Completed(outcome.clone());
                }
                let now = Instant::now();
                if now >= deadline {
                    return JoinResult::DeadlineExceeded;
                }
                let wait = (deadline - now).min(JOIN_POLL_INTERVAL);
                let slot = slot.wait_timeout(&self.done, wait);
                if let Some(outcome) = slot.as_ref() {
                    return JoinResult::Completed(outcome.clone());
                }
            }
            if cancelled() {
                return JoinResult::Detached;
            }
        }
    }
}

enum ReplayEntry {
    InFlight(Arc<InFlight>),
    /// `outcome` is dropped once it is older than [`COMPLETED_OUTCOME_TTL`]; the key stays used.
    Completed {
        outcome: Option<CeremonyOutcome>,
        at: Instant,
        /// Whether a key was used (or may have been: an unknown outcome counts as used). Only an
        /// entry that never reached key use can be forgotten, so "never sign twice" holds
        /// however long the session lives.
        key_used: bool,
    },
}

#[derive(Default)]
struct SessionState {
    replay: HashMap<ReplayKey, ReplayEntry>,
    challenges: HashMap<ChallengeDigest, ReplayKey>,
    operations_used: u32,
    /// Duplicates served per key (joined or from the completed outcome).
    served: HashMap<ReplayKey, u32>,
}

impl SessionState {
    fn expire_outcomes(&mut self, now: Instant) {
        for entry in self.replay.values_mut() {
            if let ReplayEntry::Completed { outcome, at, .. } = entry
                && outcome.is_some()
                && now.duration_since(*at) > COMPLETED_OUTCOME_TTL
            {
                *outcome = None;
            }
        }
    }

    /// Make room for one more replay entry within `capacity` (review M2). The oldest completed
    /// entries that are past the outcome window and never reached key use are forgotten; an
    /// in-flight entry, an entry inside the window and an entry that used a key are never
    /// evicted, so a request that was signed once is never signed again. Returns whether there is
    /// room. Forgotten keys also leave `challenges` and `served`.
    fn make_room(&mut self, capacity: usize, now: Instant) -> bool {
        if self.replay.len() < capacity {
            return true;
        }
        self.replay.retain(|_, entry| match entry {
            ReplayEntry::Completed { at, key_used, .. } => {
                *key_used || now.saturating_duration_since(*at) <= COMPLETED_OUTCOME_TTL
            }
            ReplayEntry::InFlight(_) => true,
        });
        let replay = &self.replay;
        self.challenges.retain(|_, key| replay.contains_key(key));
        self.served.retain(|key, _| replay.contains_key(key));
        self.replay.len() < capacity
    }
}

/// Replay entries one session keeps (the replay table and, one for one, the challenge table).
/// Entries are kept for the session's lifetime because a key that was signed must never be signed
/// again. Each signed key claims budget, which the daemon caps at 4096 operations, so this leaves
/// room for as many more entries that ended without key use. A request that finds the table full
/// of entries it may not evict (in flight, inside the 120 s outcome window, or signed) is refused
/// as busy (review M2).
pub const MAX_REPLAY_ENTRIES: usize = 8192;

/// Why a claim was refused. None of these consumes budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimRejection {
    /// The key was used and its outcome is no longer returned.
    Replayed,
    /// The challenge was used by a request with a different key (another action, RP or origin).
    ChallengeReused,
    /// The live operation budget is used up.
    BudgetExhausted,
    /// The replay table is full of entries that may not be evicted yet (in flight, inside the
    /// outcome window, or signed): the request is refused as busy, never by evicting one.
    TableFull,
}

/// The result of checking a replay key and claiming budget, in that order (R4).
pub enum Claim {
    /// A fresh key: one operation of budget was claimed. The caller runs the ceremony and must
    /// complete the guard; dropping it records an internal failure (failures consume the key).
    Fresh(ClaimGuard),
    /// The same key is in flight: join it. The flag says whether to audit this served duplicate
    /// (at most [`MAX_AUDITED_SERVES_PER_KEY`] per key).
    Join(Arc<InFlight>, bool),
    /// The same key completed within [`COMPLETED_OUTCOME_TTL`]: this is its outcome. The flag is
    /// as for `Join`.
    Completed(CeremonyOutcome, bool),
    Rejected(ClaimRejection),
}

/// Why a session can no longer be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionInvalid {
    /// The bearer was revoked (browser exit, lease revocation, principal death).
    Revoked,
    /// The revocation epoch moved since the session was created (policy reload, revocation).
    EpochChanged,
    /// The session TTL passed.
    Expired,
}

/// What a session is bound to when it is created (ADR 0014 section 9).
#[derive(Clone, Debug)]
pub struct SessionBinding {
    pub profile_id: ProfileId,
    /// Digest of the principal process the session was issued to.
    pub principal_digest: [u8; 32],
    /// The policy revocation epoch at creation.
    pub revocation_epoch: u64,
    pub ttl: Duration,
}

/// One bearer session, shared by the sign and registration contexts of its bearer.
pub struct AgentSession {
    binding: SessionBinding,
    /// A random identifier that exists only to be hashed into audit records
    /// ([`Self::audit_id_hash`]); it is not the bearer and grants nothing.
    audit_id: [u8; 16],
    expires_at: Instant,
    /// Test seam: expire the session now, without waiting for the TTL.
    #[cfg(test)]
    expired_now: AtomicBool,
    grant_id: OnceLock<GrantId>,
    /// The UID the lease's browser (and so its `sign-proxy` relay) runs as. The sign transport
    /// admits a hello for this session only from a peer with this UID (`SO_PEERCRED`); unset means
    /// the daemon's own UID.
    browser_uid: OnceLock<u32>,
    revoked: AtomicBool,
    state: Mutex<SessionState>,
    /// The replay entries this session keeps ([`MAX_REPLAY_ENTRIES`]; tests lower it).
    replay_capacity: AtomicUsize,
    /// Coalesces this session's refusal audit records (ADR 0014 section 12).
    refusals: Arc<RefusalLedger>,
    active_requests: AtomicUsize,
    /// Key-use gate (review M1). A ceremony holds the read side from its pre-key-use re-check
    /// until key use has finished; [`Self::revoke`] takes the write side, so once it returns no
    /// operation of this session can use a key.
    key_use: RwLock<()>,
}

impl std::fmt::Debug for AgentSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentSession")
            .field("profile_id", &self.binding.profile_id)
            .field("revocation_epoch", &self.binding.revocation_epoch)
            .field("revoked", &self.is_revoked())
            .finish_non_exhaustive()
    }
}

impl AgentSession {
    pub fn new(binding: SessionBinding) -> Arc<Self> {
        let expires_at = Instant::now() + binding.ttl;
        let mut audit_id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut audit_id);
        Arc::new(Self {
            binding,
            audit_id,
            expires_at,
            #[cfg(test)]
            expired_now: AtomicBool::new(false),
            grant_id: OnceLock::new(),
            browser_uid: OnceLock::new(),
            revoked: AtomicBool::new(false),
            state: Mutex::new(SessionState::default()),
            replay_capacity: AtomicUsize::new(MAX_REPLAY_ENTRIES),
            refusals: Arc::new(RefusalLedger::default()),
            active_requests: AtomicUsize::new(0),
            key_use: RwLock::new(()),
        })
    }

    pub fn profile_id(&self) -> &ProfileId {
        &self.binding.profile_id
    }

    /// The session's identity in audit records (ADR 0014 section 12): the hex SHA-256 of its random
    /// identifier. It correlates the records of one bearer session and reveals nothing else.
    pub fn audit_id_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"passless-agent-session-audit-id");
        hasher.update(self.audit_id);
        hex::encode(hasher.finalize())
    }

    /// The principal session that owns this bearer session, through its session grant (ADR 0014
    /// amendment section 2.3): the grant must be active, belong to this session's profile and be
    /// bound to this session's principal digest. `None` for a bearer without a session grant, or
    /// whose grant is gone, revoked or bound elsewhere (fail closed: nothing session-bound, such
    /// as a pre-approval, may then be used).
    pub fn owning_principal_session(
        &self,
        policy: &super::policy_engine::PolicyRuntime,
    ) -> Option<PrincipalSessionId> {
        let grant = policy.resolve_grant_for_sign(self.profile_id(), self.grant_id()?)?;
        (grant.state == super::grant::GrantState::Active
            && !grant.is_revoked
            && grant.profile_id == *self.profile_id()
            && grant.principal_digest == *self.principal_digest())
        .then_some(grant.session_id)
    }

    pub fn principal_digest(&self) -> &[u8; 32] {
        &self.binding.principal_digest
    }

    pub fn revocation_epoch(&self) -> u64 {
        self.binding.revocation_epoch
    }

    /// Record the UID the lease's browser runs as (once; a later call changes nothing).
    pub fn bind_browser_uid(&self, uid: u32) {
        let _ = self.browser_uid.set(uid);
    }

    /// The UID the lease's browser runs as, if one was bound.
    pub fn browser_uid(&self) -> Option<u32> {
        self.browser_uid.get().copied()
    }

    /// Bind the session grant that backs authentication for this bearer. Registration checks it
    /// too, so principal death, grant revocation and grant expiry revoke both paths.
    pub fn bind_grant(&self, grant_id: GrantId) -> Result<(), GrantId> {
        self.grant_id.set(grant_id)
    }

    pub fn grant_id(&self) -> Option<&GrantId> {
        self.grant_id.get()
    }

    /// Revoke the bearer. Waits for an operation that is between its pre-key-use re-check and the
    /// end of key use; every later re-check sees the revocation.
    pub fn revoke(&self) {
        {
            let _gate = lock_order::write(&self.key_use, LockLevel::SessionKeyUse);
            self.revoked.store(true, Ordering::Release);
        }
        // The session's pending refusal counts are written now, not left for its drop (a revoked
        // bearer can stay in the tombstone ring for a long time).
        self.refusals.flush();
    }

    /// The ledger that coalesces this session's refusal records (ADR 0014 section 12).
    pub fn refusals(&self) -> &Arc<RefusalLedger> {
        &self.refusals
    }

    /// Lower the replay table's capacity (tests).
    #[cfg(test)]
    pub(crate) fn set_replay_capacity(&self, capacity: usize) {
        self.replay_capacity.store(capacity, Ordering::Release);
    }

    /// Replay entries currently held (tests).
    #[cfg(test)]
    pub(crate) fn replay_entries(&self) -> usize {
        lock_order::lock(&self.state, LockLevel::Session)
            .replay
            .len()
    }

    /// Challenge-table entries currently held (tests).
    #[cfg(test)]
    pub(crate) fn challenge_entries(&self) -> usize {
        lock_order::lock(&self.state, LockLevel::Session)
            .challenges
            .len()
    }

    /// Hold off revocation of this session until the guard is dropped (review M1). Taken right
    /// before the pre-key-use re-check and held until key use has finished; never held across a
    /// wait for anything but the key provider and the storage write.
    pub fn key_use_guard(&self) -> lock_order::Tracked<std::sync::RwLockReadGuard<'_, ()>> {
        lock_order::read(&self.key_use, LockLevel::SessionKeyUse)
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }

    /// The per-session concurrent-request counter (plan R11).
    pub fn active_requests(&self) -> &AtomicUsize {
        &self.active_requests
    }

    /// Check that the session is still usable against the live revocation epoch.
    pub fn validity(&self, current_epoch: u64, now: Instant) -> Result<(), SessionInvalid> {
        if self.is_revoked() {
            return Err(SessionInvalid::Revoked);
        }
        if current_epoch != self.binding.revocation_epoch {
            return Err(SessionInvalid::EpochChanged);
        }
        if now >= self.expires_at {
            return Err(SessionInvalid::Expired);
        }
        #[cfg(test)]
        if self.expired_now.load(Ordering::Acquire) {
            return Err(SessionInvalid::Expired);
        }
        Ok(())
    }

    /// Expire the session as if its TTL had just passed.
    #[cfg(test)]
    pub(crate) fn expire_now(&self) {
        self.expired_now.store(true, Ordering::Release);
    }

    /// Operations claimed so far.
    pub fn operations_used(&self) -> u32 {
        lock_order::lock(&self.state, LockLevel::Session).operations_used
    }

    /// When the session TTL passes.
    pub fn expires_at(&self) -> Instant {
        self.expires_at
    }

    /// Check the replay key, then claim one operation of the live budget `max_operations` (R4).
    /// A budget refusal leaves the replay key unused.
    pub fn claim(
        self: &Arc<Self>,
        key: ReplayKey,
        challenge: ChallengeDigest,
        max_operations: u32,
        now: Instant,
    ) -> Claim {
        self.claim_slot(key, challenge, Some(max_operations), now)
    }

    /// Check the replay key only (an escalated ceremony, ADR 0014 section 8.2): a fresh key takes
    /// the replay slot without budget. The budget is claimed after approval with
    /// [`ClaimGuard::claim_budget`]; a denied, expired or aborted escalation completes the slot
    /// with no budget claimed.
    pub fn claim_key(
        self: &Arc<Self>,
        key: ReplayKey,
        challenge: ChallengeDigest,
        now: Instant,
    ) -> Claim {
        self.claim_slot(key, challenge, None, now)
    }

    fn claim_slot(
        self: &Arc<Self>,
        key: ReplayKey,
        challenge: ChallengeDigest,
        max_operations: Option<u32>,
        now: Instant,
    ) -> Claim {
        let mut state = lock_order::lock(&self.state, LockLevel::Session);
        state.expire_outcomes(now);

        if let Some(entry) = state.replay.get(&key) {
            let claim = match entry {
                ReplayEntry::InFlight(in_flight) => Claim::Join(in_flight.clone(), false),
                ReplayEntry::Completed {
                    outcome: Some(outcome),
                    ..
                } => Claim::Completed(outcome.clone(), false),
                ReplayEntry::Completed { outcome: None, .. } => {
                    return Claim::Rejected(ClaimRejection::Replayed);
                }
            };
            let served = state.served.entry(key).or_insert(0);
            *served = served.saturating_add(1);
            let audit = *served <= MAX_AUDITED_SERVES_PER_KEY;
            return match claim {
                Claim::Join(in_flight, _) => Claim::Join(in_flight, audit),
                Claim::Completed(outcome, _) => Claim::Completed(outcome, audit),
                other => other,
            };
        }
        if state.challenges.get(&challenge).is_some_and(|k| *k != key) {
            return Claim::Rejected(ClaimRejection::ChallengeReused);
        }
        // A fresh key needs a slot. Forget the oldest completed entries that never reached key
        // use and are past the outcome window; if none can go, refuse rather than evict an entry
        // that protects "never sign twice" (review M2).
        let capacity = self.replay_capacity.load(Ordering::Acquire);
        if !state.make_room(capacity, now) {
            return Claim::Rejected(ClaimRejection::TableFull);
        }
        if let Some(max_operations) = max_operations {
            if state.operations_used >= max_operations {
                return Claim::Rejected(ClaimRejection::BudgetExhausted);
            }
            state.operations_used += 1;
        }

        let in_flight = Arc::new(InFlight::new());
        state
            .replay
            .insert(key, ReplayEntry::InFlight(in_flight.clone()));
        state.challenges.insert(challenge, key);
        drop(state);
        Claim::Fresh(ClaimGuard {
            session: self.clone(),
            key,
            in_flight,
            budget_claimed: max_operations.is_some(),
            done: false,
        })
    }

    /// Claim one operation of the live budget for a slot taken by [`Self::claim_key`].
    fn claim_operation(&self, max_operations: u32) -> Result<(), ClaimRejection> {
        let mut state = lock_order::lock(&self.state, LockLevel::Session);
        if state.operations_used >= max_operations {
            return Err(ClaimRejection::BudgetExhausted);
        }
        state.operations_used += 1;
        Ok(())
    }

    fn record_completion(
        &self,
        key: ReplayKey,
        outcome: CeremonyOutcome,
        refund: bool,
        key_used: bool,
    ) {
        let mut state = lock_order::lock(&self.state, LockLevel::Session);
        if refund {
            state.operations_used = state.operations_used.saturating_sub(1);
        }
        state.replay.insert(
            key,
            ReplayEntry::Completed {
                outcome: Some(outcome),
                at: Instant::now(),
                key_used,
            },
        );
    }
}

/// The right to run the ceremony of one fresh replay key. Completing it publishes the outcome to
/// joined duplicates and keeps it for [`COMPLETED_OUTCOME_TTL`].
pub struct ClaimGuard {
    session: Arc<AgentSession>,
    key: ReplayKey,
    in_flight: Arc<InFlight>,
    /// Whether this slot holds one operation of budget (always after [`AgentSession::claim`];
    /// after [`AgentSession::claim_key`] only once [`Self::claim_budget`] succeeded).
    budget_claimed: bool,
    done: bool,
}

impl ClaimGuard {
    /// Claim one operation of the live budget `max_operations` for a slot taken without budget
    /// (an approved escalation). Claiming twice is a no-op. A refusal leaves the slot unclaimed;
    /// the caller completes it with the refusal.
    pub fn claim_budget(&mut self, max_operations: u32) -> Result<(), ClaimRejection> {
        if self.budget_claimed {
            return Ok(());
        }
        self.session.claim_operation(max_operations)?;
        self.budget_claimed = true;
        Ok(())
    }

    /// Whether this slot holds one operation of budget.
    pub fn budget_claimed(&self) -> bool {
        self.budget_claimed
    }

    /// Complete after key use: the operation stays counted against the budget.
    pub fn complete(mut self, outcome: &CeremonyOutcome) {
        self.finish(outcome.clone(), false, true);
    }

    /// Complete a ceremony that ended before key use (review M2): the replay key stays consumed
    /// (a duplicate gets this outcome) but the operation, if one was claimed, is given back to the
    /// budget.
    pub fn complete_without_key_use(mut self, outcome: &CeremonyOutcome) {
        let refund = self.budget_claimed;
        self.finish(outcome.clone(), refund, false);
    }

    /// `key_used` is whether a key was (or may have been) used: only an entry that never reached
    /// key use may be forgotten when the replay table is full.
    fn finish(&mut self, outcome: CeremonyOutcome, refund: bool, key_used: bool) {
        if self.done {
            return;
        }
        self.done = true;
        // The slot first, then the table: never both at once.
        self.in_flight.publish(outcome.clone());
        self.session
            .record_completion(self.key, outcome, refund, key_used);
    }
}

impl Drop for ClaimGuard {
    fn drop(&mut self) {
        if !self.done {
            // Whether a key was used is unknown here: keep the operation counted and the entry
            // unevictable.
            self.finish(
                Err(internal_failure("ceremony ended without an outcome")),
                false,
                true,
            );
        }
    }
}

/// Test-only hooks into the ceremony flow.
#[cfg(test)]
pub(crate) mod test_hooks {
    use std::cell::RefCell;

    thread_local! {
        static BEFORE_KEY_USE: RefCell<Option<Box<dyn Fn()>>> = const { RefCell::new(None) };
        static ON_JOIN: RefCell<Option<Box<dyn Fn()>>> = const { RefCell::new(None) };
    }

    /// Run `hook` on this thread when it starts waiting for an in-flight duplicate, for as long
    /// as the returned guard lives.
    pub fn set_on_join(hook: impl Fn() + 'static) -> JoinHookGuard {
        ON_JOIN.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
        JoinHookGuard
    }

    pub struct JoinHookGuard;

    impl Drop for JoinHookGuard {
        fn drop(&mut self) {
            ON_JOIN.with(|slot| *slot.borrow_mut() = None);
        }
    }

    pub(crate) fn on_join() {
        ON_JOIN.with(|slot| {
            if let Some(hook) = slot.borrow().as_ref() {
                hook();
            }
        });
    }

    /// Run `hook` on this thread right before the pre-key-use re-check (ADR 0014 invariant 13), for
    /// as long as the returned guard lives.
    pub fn set_before_key_use(hook: impl Fn() + 'static) -> HookGuard {
        BEFORE_KEY_USE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
        HookGuard
    }

    pub struct HookGuard;

    impl Drop for HookGuard {
        fn drop(&mut self) {
            BEFORE_KEY_USE.with(|slot| *slot.borrow_mut() = None);
        }
    }

    pub(crate) fn before_key_use() {
        BEFORE_KEY_USE.with(|slot| {
            if let Some(hook) = slot.borrow().as_ref() {
                hook();
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::super::escalation::NoPark;
    use super::*;

    /// Counts the suspensions and resumptions of a duplicate's permit.
    #[derive(Default)]
    struct CountingPark {
        suspended: Arc<AtomicUsize>,
        resumed: Arc<AtomicUsize>,
    }

    impl ParkHook for CountingPark {
        fn suspend(&mut self) {
            self.suspended.fetch_add(1, Ordering::SeqCst);
        }

        fn resume(&mut self) {
            self.resumed.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn binding(epoch: u64) -> SessionBinding {
        SessionBinding {
            profile_id: ProfileId::new("p").unwrap(),
            principal_digest: [7u8; 32],
            revocation_epoch: epoch,
            ttl: Duration::from_secs(600),
        }
    }

    fn key(action: CeremonyAction, rp: &str, challenge: &[u8]) -> (ReplayKey, ChallengeDigest) {
        (
            ReplayKey::derive(action, rp, "https://rp.test", None, challenge),
            ChallengeDigest::of(challenge),
        )
    }

    fn ok_outcome() -> CeremonyOutcome {
        Ok(CeremonyResult::Assertion(Box::new(PrincipalResponse::Pong)))
    }

    #[test]
    fn replay_key_encoding_is_unambiguous() {
        let a = ReplayKey::derive(CeremonyAction::Authenticate, "ab", "c", None, b"x");
        let b = ReplayKey::derive(CeremonyAction::Authenticate, "a", "bc", None, b"x");
        assert_ne!(a, b, "field boundaries are length-prefixed");
        let absent = ReplayKey::derive(CeremonyAction::Authenticate, "rp", "o", None, b"x");
        let empty = ReplayKey::derive(CeremonyAction::Authenticate, "rp", "o", Some(""), b"x");
        assert_ne!(
            absent, empty,
            "an absent top origin differs from an empty one"
        );
        let register = ReplayKey::derive(CeremonyAction::Register, "rp", "o", None, b"x");
        assert_ne!(absent, register, "the action is part of the key");
        assert_eq!(
            absent,
            ReplayKey::derive(CeremonyAction::Authenticate, "rp", "o", None, b"x")
        );
    }

    #[test]
    fn fresh_claim_consumes_one_operation_and_duplicates_none() {
        let session = AgentSession::new(binding(1));
        let (k, c) = key(CeremonyAction::Authenticate, "rp.test", b"c1");
        let Claim::Fresh(guard) = session.claim(k, c, 4, Instant::now()) else {
            panic!("expected a fresh claim");
        };
        assert!(matches!(
            session.claim(k, c, 4, Instant::now()),
            Claim::Join(..)
        ));
        guard.complete(&ok_outcome());
        assert!(matches!(
            session.claim(k, c, 4, Instant::now()),
            Claim::Completed(Ok(_), _)
        ));
        assert_eq!(session.operations_used(), 1);
    }

    #[test]
    fn completed_outcome_expires_into_a_rejection() {
        let session = AgentSession::new(binding(1));
        let (k, c) = key(CeremonyAction::Authenticate, "rp.test", b"c1");
        let Claim::Fresh(guard) = session.claim(k, c, 4, Instant::now()) else {
            panic!("expected a fresh claim");
        };
        guard.complete(&ok_outcome());
        let later = Instant::now() + COMPLETED_OUTCOME_TTL + Duration::from_secs(1);
        assert!(matches!(
            session.claim(k, c, 4, later),
            Claim::Rejected(ClaimRejection::Replayed)
        ));
        assert_eq!(session.operations_used(), 1);
    }

    #[test]
    fn same_challenge_with_another_action_or_rp_is_rejected_not_joined() {
        let session = AgentSession::new(binding(1));
        let (k, c) = key(CeremonyAction::Authenticate, "rp.test", b"shared");
        let Claim::Fresh(_guard) = session.claim(k, c, 4, Instant::now()) else {
            panic!("expected a fresh claim");
        };
        let (k2, c2) = key(CeremonyAction::Register, "rp.test", b"shared");
        assert!(matches!(
            session.claim(k2, c2, 4, Instant::now()),
            Claim::Rejected(ClaimRejection::ChallengeReused)
        ));
        let (k3, c3) = key(CeremonyAction::Authenticate, "other.test", b"shared");
        assert!(matches!(
            session.claim(k3, c3, 4, Instant::now()),
            Claim::Rejected(ClaimRejection::ChallengeReused)
        ));
        assert_eq!(session.operations_used(), 1);
    }

    #[test]
    fn a_dropped_claim_is_a_failure_that_consumes_the_key() {
        let session = AgentSession::new(binding(1));
        let (k, c) = key(CeremonyAction::Authenticate, "rp.test", b"c1");
        let Claim::Fresh(guard) = session.claim(k, c, 4, Instant::now()) else {
            panic!("expected a fresh claim");
        };
        drop(guard);
        match session.claim(k, c, 4, Instant::now()) {
            Claim::Completed(Err(e), _) => assert_eq!(e.code, ErrorCode::Internal),
            _ => panic!("the failure must be returned to the duplicate"),
        }
    }

    #[test]
    fn a_key_only_claim_takes_budget_only_when_claimed_and_refunds_only_that() {
        let session = AgentSession::new(binding(1));
        let now = Instant::now();

        // Denied escalation: the slot completes, nothing was claimed, nothing is refunded.
        let (k1, c1) = key(CeremonyAction::Authenticate, "a.example", b"one");
        let Claim::Fresh(guard) = session.claim_key(k1, c1, now) else {
            panic!("fresh");
        };
        assert!(!guard.budget_claimed());
        assert_eq!(session.operations_used(), 0);
        guard.complete_without_key_use(&Err(internal_failure("denied")));
        assert_eq!(session.operations_used(), 0);
        // The replay key is consumed: a duplicate gets the outcome, no new slot.
        assert!(matches!(
            session.claim_key(k1, c1, now),
            Claim::Completed(..)
        ));

        // Approved: the budget is claimed once (a second claim is a no-op), then refunded only
        // if the ceremony ends before key use.
        let (k2, c2) = key(CeremonyAction::Authenticate, "a.example", b"two");
        let Claim::Fresh(mut guard) = session.claim_key(k2, c2, now) else {
            panic!("fresh");
        };
        guard.claim_budget(1).unwrap();
        guard.claim_budget(1).unwrap();
        assert_eq!(session.operations_used(), 1);
        guard.complete_without_key_use(&Err(internal_failure("before key use")));
        assert_eq!(session.operations_used(), 0);

        // The live budget is enforced at claim time, after approval.
        let (k3, c3) = key(CeremonyAction::Authenticate, "a.example", b"three");
        let Claim::Fresh(mut guard) = session.claim_key(k3, c3, now) else {
            panic!("fresh");
        };
        assert_eq!(guard.claim_budget(0), Err(ClaimRejection::BudgetExhausted));
        assert!(!guard.budget_claimed());
        guard.complete_without_key_use(&Err(internal_failure("budget")));
        assert_eq!(session.operations_used(), 0);
    }

    #[test]
    fn budget_is_claimed_only_by_fresh_keys_and_enforced_live() {
        let session = AgentSession::new(binding(1));
        for i in 0..2u8 {
            let (k, c) = key(CeremonyAction::Authenticate, "rp.test", &[i]);
            let Claim::Fresh(guard) = session.claim(k, c, 2, Instant::now()) else {
                panic!("expected a fresh claim");
            };
            guard.complete(&ok_outcome());
        }
        let (k, c) = key(CeremonyAction::Authenticate, "rp.test", &[9]);
        assert!(matches!(
            session.claim(k, c, 2, Instant::now()),
            Claim::Rejected(ClaimRejection::BudgetExhausted)
        ));
        // A live budget increase is honored without a new session.
        assert!(matches!(
            session.claim(k, c, 3, Instant::now()),
            Claim::Fresh(_)
        ));
    }

    #[test]
    fn join_returns_the_original_outcome_and_a_detached_duplicate_leaves_it_running() {
        let session = AgentSession::new(binding(1));
        let (k, c) = key(CeremonyAction::Authenticate, "rp.test", b"c1");
        let Claim::Fresh(guard) = session.claim(k, c, 4, Instant::now()) else {
            panic!("expected a fresh claim");
        };
        let Claim::Join(slot, _) = session.claim(k, c, 4, Instant::now()) else {
            panic!("expected a join");
        };
        // A duplicate that is cancelled detaches; the original is not affected.
        let detached = slot.join(
            Instant::now() + Duration::from_secs(5),
            &|| true,
            &mut NoPark,
        );
        assert!(matches!(detached, JoinResult::Detached));
        let expired = slot.join(Instant::now(), &|| false, &mut NoPark);
        assert!(matches!(expired, JoinResult::DeadlineExceeded));

        let waiter = {
            let slot = slot.clone();
            std::thread::spawn(move || {
                slot.join(
                    Instant::now() + Duration::from_secs(10),
                    &|| false,
                    &mut NoPark,
                )
            })
        };
        std::thread::sleep(Duration::from_millis(50));
        guard.complete(&ok_outcome());
        assert!(matches!(
            waiter.join().unwrap(),
            JoinResult::Completed(Ok(_))
        ));
    }

    #[test]
    fn validity_tracks_revocation_epoch_and_ttl() {
        let session = AgentSession::new(binding(3));
        let now = Instant::now();
        assert_eq!(session.validity(3, now), Ok(()));
        assert_eq!(session.validity(4, now), Err(SessionInvalid::EpochChanged));
        assert_eq!(
            session.validity(3, now + Duration::from_secs(601)),
            Err(SessionInvalid::Expired)
        );
        session.revoke();
        assert_eq!(session.validity(3, now), Err(SessionInvalid::Revoked));
    }

    #[test]
    fn ceremony_deadline_is_clamped() {
        let now = Instant::now();
        assert_eq!(ceremony_deadline(Some(0), now), now + MIN_CEREMONY_TIMEOUT);
        assert_eq!(ceremony_deadline(None, now), now + DEFAULT_CEREMONY_TIMEOUT);
        assert_eq!(
            ceremony_deadline(Some(u64::MAX), now),
            now + MAX_CEREMONY_TIMEOUT
        );
    }

    #[test]
    fn a_joined_duplicate_suspends_its_permit_while_it_waits_and_resumes_it() {
        let session = AgentSession::new(binding(1));
        let (k, c) = key(CeremonyAction::Authenticate, "rp.test", b"c-park");
        let Claim::Fresh(guard) = session.claim(k, c, 4, Instant::now()) else {
            panic!("expected a fresh claim");
        };
        let Claim::Join(slot, _) = session.claim(k, c, 4, Instant::now()) else {
            panic!("expected a join");
        };
        let park = CountingPark::default();
        let (suspended, resumed) = (park.suspended.clone(), park.resumed.clone());
        let waiter = {
            let slot = slot.clone();
            std::thread::spawn(move || {
                let mut park = park;
                slot.join(
                    Instant::now() + Duration::from_secs(10),
                    &|| false,
                    &mut park,
                )
            })
        };
        let started = Instant::now();
        while suspended.load(Ordering::SeqCst) == 0 {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "never suspended"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        // Parked: the permit is suspended and not yet resumed.
        assert_eq!(resumed.load(Ordering::SeqCst), 0);
        guard.complete(&ok_outcome());
        assert!(matches!(
            waiter.join().unwrap(),
            JoinResult::Completed(Ok(_))
        ));
        assert_eq!(suspended.load(Ordering::SeqCst), 1);
        assert_eq!(resumed.load(Ordering::SeqCst), 1);
        assert_eq!(slot.suspended.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn suspended_duplicates_are_bounded_per_key_and_a_finished_slot_suspends_none() {
        let slot = InFlight::new();
        let mut parks: Vec<CountingPark> = (0..MAX_SUSPENDED_DUPLICATES_PER_KEY + 1)
            .map(|_| CountingPark::default())
            .collect();
        let mut guards = Vec::new();
        let mut iter = parks.iter_mut();
        for _ in 0..MAX_SUSPENDED_DUPLICATES_PER_KEY {
            guards.push(slot.suspend_duplicate(iter.next().unwrap()).unwrap());
        }
        let over = iter.next().unwrap();
        assert!(slot.suspend_duplicate(over).is_none());
        drop(guards);
        assert_eq!(slot.suspended.load(Ordering::SeqCst), 0);
        for park in &parks[..MAX_SUSPENDED_DUPLICATES_PER_KEY] {
            assert_eq!(park.resumed.load(Ordering::SeqCst), 1);
        }
        assert_eq!(
            parks[MAX_SUSPENDED_DUPLICATES_PER_KEY]
                .suspended
                .load(Ordering::SeqCst),
            0
        );

        slot.publish(ok_outcome());
        let mut park = CountingPark::default();
        assert!(slot.suspend_duplicate(&mut park).is_none());
    }

    fn numbered(n: usize) -> (ReplayKey, ChallengeDigest) {
        key(
            CeremonyAction::Authenticate,
            "rp.test",
            format!("c{n}").as_bytes(),
        )
    }

    /// Fill `session` with `count` entries that ended without key use.
    fn fill_without_key_use(session: &Arc<AgentSession>, count: usize, now: Instant) {
        for n in 0..count {
            let (k, c) = numbered(n);
            let Claim::Fresh(guard) = session.claim(k, c, 1_000_000, now) else {
                panic!("entry {n} should be fresh");
            };
            guard.complete_without_key_use(&Ok(CeremonyResult::Assertion(Box::new(
                PrincipalResponse::Pong,
            ))));
        }
    }

    #[test]
    fn a_full_replay_table_refuses_while_every_entry_is_inside_the_window() {
        let session = AgentSession::new(binding(1));
        session.set_replay_capacity(4);
        let now = Instant::now();
        fill_without_key_use(&session, 4, now);
        assert_eq!(session.replay_entries(), 4);

        let (k, c) = numbered(99);
        assert!(matches!(
            session.claim(k, c, 1_000_000, now + Duration::from_secs(10)),
            Claim::Rejected(ClaimRejection::TableFull)
        ));
        // Nothing was evicted, nothing was claimed, and the refused key is not consumed.
        assert_eq!(session.replay_entries(), 4);
        assert_eq!(session.challenge_entries(), 4);
        assert_eq!(session.operations_used(), 0);
        // A duplicate of a completed entry inside the window still gets its outcome.
        let (k0, c0) = numbered(0);
        assert!(matches!(
            session.claim(k0, c0, 1_000_000, now + Duration::from_secs(10)),
            Claim::Completed(..)
        ));
    }

    #[test]
    fn a_full_replay_table_refuses_while_an_entry_is_in_flight() {
        let session = AgentSession::new(binding(1));
        session.set_replay_capacity(3);
        let now = Instant::now();
        fill_without_key_use(&session, 2, now);
        let (k, c) = numbered(50);
        let Claim::Fresh(in_flight) = session.claim_key(k, c, now) else {
            panic!("a fresh key");
        };
        // Long past the window: the two completed entries may go, the in-flight one may not.
        let later = now + COMPLETED_OUTCOME_TTL * 2;
        let (k2, c2) = numbered(51);
        assert!(matches!(session.claim_key(k2, c2, later), Claim::Fresh(_)));
        assert!(session.replay_entries() <= 3);
        assert!(
            matches!(session.claim_key(k, c, later), Claim::Join(..)),
            "the in-flight entry survived the eviction"
        );
        drop(in_flight);
    }

    #[test]
    fn old_completed_entries_without_key_use_are_evicted_to_make_room() {
        let session = AgentSession::new(binding(1));
        session.set_replay_capacity(4);
        let now = Instant::now();
        fill_without_key_use(&session, 4, now);

        let later = now + COMPLETED_OUTCOME_TTL + Duration::from_secs(1);
        let (k, c) = numbered(99);
        let Claim::Fresh(guard) = session.claim(k, c, 1_000_000, later) else {
            panic!("entries past the outcome window make room");
        };
        // The four old entries went, with their challenges; the new one is in flight.
        assert_eq!(session.replay_entries(), 1);
        assert_eq!(session.challenge_entries(), 1);
        drop(guard);
        // The table stays bounded however many requests follow.
        let mut at = later;
        for n in 100..140 {
            at += COMPLETED_OUTCOME_TTL + Duration::from_secs(1);
            let (k, c) = numbered(n);
            let Claim::Fresh(guard) = session.claim(k, c, 1_000_000, at) else {
                panic!("entry {n} should be fresh");
            };
            guard.complete_without_key_use(&ok_outcome());
            assert!(session.replay_entries() <= 4);
            assert!(session.challenge_entries() <= 4);
        }
    }

    /// "Never sign twice": an entry that reached key use is never forgotten, however old, so the
    /// table refuses instead.
    #[test]
    fn an_entry_that_used_a_key_is_never_evicted() {
        let session = AgentSession::new(binding(1));
        session.set_replay_capacity(3);
        let now = Instant::now();
        let mut used = Vec::new();
        for n in 0..3 {
            let (k, c) = numbered(n);
            let Claim::Fresh(guard) = session.claim(k, c, 1_000_000, now) else {
                panic!("fresh");
            };
            guard.complete(&ok_outcome());
            used.push((k, c));
        }
        let much_later = now + COMPLETED_OUTCOME_TTL * 100;
        let (k, c) = numbered(99);
        assert!(matches!(
            session.claim(k, c, 1_000_000, much_later),
            Claim::Rejected(ClaimRejection::TableFull)
        ));
        // Each signed key is still refused as a replay, long after its outcome expired.
        for (k, c) in used {
            assert!(matches!(
                session.claim(k, c, 1_000_000, much_later),
                Claim::Rejected(ClaimRejection::Replayed)
            ));
        }
        assert_eq!(session.operations_used(), 3);
    }

    #[test]
    fn a_dropped_claim_is_unevictable_because_key_use_is_unknown() {
        let session = AgentSession::new(binding(1));
        session.set_replay_capacity(1);
        let now = Instant::now();
        let (k, c) = numbered(0);
        let Claim::Fresh(guard) = session.claim(k, c, 1_000_000, now) else {
            panic!("fresh");
        };
        drop(guard);
        let (k2, c2) = numbered(1);
        assert!(matches!(
            session.claim(k2, c2, 1_000_000, now + COMPLETED_OUTCOME_TTL * 2),
            Claim::Rejected(ClaimRejection::TableFull)
        ));
    }
}
