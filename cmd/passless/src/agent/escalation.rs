//! The escalation coordinator (ADR 0014 section 8; plan P7 section 1).
//!
//! A ceremony that resolves to `request` creates or joins a pending escalation keyed by
//! `(profile, rp_id, action)` and parks on it until the human decides, its own deadline passes, it
//! is aborted or its session becomes invalid.
//!
//! - `authenticate` escalations are joinable: concurrent ceremonies of one key wait on one prompt.
//!   Registration escalations are not: a concurrent one for the same key is refused with
//!   `escalation_busy`, and its approval is a one-use [`RegistrationApproval`] handed only to the
//!   creating ceremony.
//! - Each profile shows at most one prompt at a time; other keys wait in a FIFO bounded at
//!   [`MAX_QUEUED_PER_PROFILE`]. Overflow is refused with `escalation_queue_full`.
//! - Waiters are capped per session ([`MAX_WAITERS_PER_SESSION`]), per profile
//!   ([`MAX_WAITERS_PER_PROFILE`]) and globally ([`MAX_WAITERS_GLOBAL`]).
//! - A deny or a timeout starts the key's cooldown. Withdrawals (the last waiter left, or the
//!   notification server went away) are rate-limited (V-M2): the third within
//!   [`WITHDRAWAL_WINDOW`] starts the cooldown too.
//! - When the last waiter leaves, a queued entry is dequeued and an active prompt is withdrawn at
//!   once; `escalation.expired` is recorded with `reason = aborted` (or `timeout`).
//!
//! Locking: one mutex at [`LockLevel::Escalation`], a leaf. No audit, store, prompt or D-Bus call
//! happens under it: state changes are made under the mutex and their effects (audit records,
//! prompt show and withdraw) are run after it is released. Waiters park on its condvar holding
//! nothing else, and call their `cancelled`/`still_valid` checks with the mutex released.
//!
//! Approval protocol: under the mutex the decision must match the active ticket of an entry that
//! is still `Prompting`; it becomes `Deciding`. With the mutex released the approval is audited
//! (`escalation.approved`) and, for `authenticate`, the grant is persisted (which bumps the grant
//! epoch). Then the entry becomes `Approved` under the mutex and the waiters are woken. A failed
//! audit or store write turns the approval into a deny. A registration approval persists nothing
//! here: the creating ceremony persists the grant after the credential is written
//! ([`EscalationService::record_registration_grant`]).

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use log::{debug, info, warn};
use rand::RngCore;

use passless_core::agent::{AgentMode, CredentialRef, ProfileId};

use super::audit::AuditGate;
use super::audit_events::{
    AuditAction, AuditEvent, EscalationAuditContext, EscalationDenyCause, EscalationExpireReason,
    EscalationRevokeReason, GrantedRuleAddBuilder, PolicyDenyReason,
};
use super::escalation_prompt::{PromptFields, PromptVerb};
use super::granted_rules::{
    GrantKind, GrantStoreError, GrantedRule, GrantedRulesStore, PermittingRule, ProfileGrants,
};
use super::identity::{MonotonicClock, MonotonicTime};
use super::lock_order::{self, LockLevel, Tracked};
use super::policy_engine::PolicyRuntime;
use super::session::{AgentSession, CeremonyAction};

/// Keys that may wait behind a profile's active prompt.
pub const MAX_QUEUED_PER_PROFILE: usize = 8;
/// Escalation waiters per bearer session.
pub const MAX_WAITERS_PER_SESSION: usize = 4;
/// Escalation waiters per profile.
pub const MAX_WAITERS_PER_PROFILE: usize = 16;
/// Escalation waiters in the whole daemon (bounds the parked ceremony threads).
pub const MAX_WAITERS_GLOBAL: usize = 64;
/// The V-M2 window: the third withdrawal of a key within it starts the key's cooldown.
pub const WITHDRAWAL_WINDOW: Duration = Duration::from_secs(600);
/// Withdrawals within [`WITHDRAWAL_WINDOW`] that start the cooldown.
pub const WITHDRAWALS_BEFORE_COOLDOWN: usize = 3;
/// Longest a waiter parks before it re-checks its cancellation, deadline and session.
pub const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(250);
/// An abort this close to the deadline counts as a timeout (Chromium's cancel and the daemon's
/// deadline race; plan P7 gap 8).
pub const DEADLINE_ABORT_GRACE: Duration = Duration::from_secs(2);

/// The ID of one escalation (`request_id` of the granted rule it produces).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct EscalationId(String);

impl EscalationId {
    fn generate() -> Self {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(format!("esc-{}", hex::encode(bytes)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[cfg(test)]
    pub fn for_tests(id: &str) -> Self {
        Self(id.to_string())
    }
}

impl fmt::Display for EscalationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What an escalation is keyed by.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct EscalationKey {
    pub profile: ProfileId,
    /// The normalized RP ID.
    pub rp_id: String,
    pub action: CeremonyAction,
}

/// The bearer session a waiter belongs to (for the per-session waiter cap).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct WaiterSession(usize);

impl WaiterSession {
    /// The session behind a bearer.
    pub fn of(session: &Arc<AgentSession>) -> Self {
        Self(Arc::as_ptr(session) as usize)
    }

    /// A session tag from a raw value (tests and callers without an `AgentSession`).
    pub fn from_raw(raw: usize) -> Self {
        Self(raw)
    }
}

/// One ceremony's escalation request. Every field is daemon-derived.
#[derive(Clone, Debug)]
pub struct EscalationRequest {
    pub profile: ProfileId,
    /// The normalized RP ID.
    pub rp_id: String,
    pub action: CeremonyAction,
    /// The validated origin of the ceremony.
    pub origin: String,
    /// The configured rule that resolved to `request`.
    pub rule: PermittingRule,
    pub session: WaiterSession,
    pub mode: AgentMode,
    pub principal_user: String,
    /// The profile's live `max_granted_rules`.
    pub max_granted_rules: usize,
}

impl EscalationRequest {
    pub fn key(&self) -> EscalationKey {
        EscalationKey {
            profile: self.profile.clone(),
            rp_id: self.rp_id.clone(),
            action: self.action,
        }
    }

    fn audit_action(&self) -> AuditAction {
        match self.action {
            CeremonyAction::Authenticate => AuditAction::Authenticate,
            CeremonyAction::Register => AuditAction::Register,
        }
    }

    /// The prompt's daemon-derived fields.
    pub fn prompt_fields(&self) -> PromptFields {
        PromptFields {
            profile: self.profile.as_str().to_string(),
            mode: self.mode.to_string(),
            principal_user: self.principal_user.clone(),
            verb: match self.action {
                CeremonyAction::Authenticate => PromptVerb::Authenticate,
                CeremonyAction::Register => PromptVerb::Register,
            },
            rp_id: self.rp_id.clone(),
            origin: self.origin.clone(),
        }
    }
}

/// Why an escalation was not started or joined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EscalationRefusal {
    /// No prompt can be shown (no bus, or the server is rejected).
    Unavailable,
    /// The key is in its cooldown.
    Cooldown,
    /// The profile's queue is full.
    QueueFull,
    /// A per-session, per-profile or global waiter cap is reached.
    WaiterCap,
    /// A registration escalation for the key is already pending.
    Busy,
    /// The profile holds `max_granted_rules` grants.
    GrantCapReached,
    /// The profile's granted-rules store is disabled.
    GrantsUnavailable,
    /// The `escalation.requested` record could not be written.
    AuditFailure,
}

impl EscalationRefusal {
    pub fn deny_reason(self) -> PolicyDenyReason {
        match self {
            Self::Unavailable => PolicyDenyReason::EscalationUnavailable,
            Self::Cooldown => PolicyDenyReason::EscalationCooldown,
            Self::QueueFull => PolicyDenyReason::EscalationQueueFull,
            Self::WaiterCap => PolicyDenyReason::EscalationWaiterCap,
            Self::Busy => PolicyDenyReason::EscalationBusy,
            Self::GrantCapReached => PolicyDenyReason::GrantCapReached,
            Self::GrantsUnavailable => PolicyDenyReason::GrantsUnavailable,
            Self::AuditFailure => PolicyDenyReason::AuditFailure,
        }
    }
}

/// The one-use approval of a registration escalation, handed only to the creating ceremony. It
/// permits exactly one registration for exactly this RP within that ceremony (ADR 0014 section
/// 8.3). It is deliberately not `Clone`.
#[derive(Debug)]
pub struct RegistrationApproval {
    escalation_id: EscalationId,
    profile: ProfileId,
    rp_id: String,
    origin: String,
    rule: PermittingRule,
    session: WaiterSession,
}

impl RegistrationApproval {
    pub fn escalation_id(&self) -> &EscalationId {
        &self.escalation_id
    }

    pub fn profile(&self) -> &ProfileId {
        &self.profile
    }

    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub fn rule(&self) -> PermittingRule {
        self.rule
    }

    pub fn session(&self) -> WaiterSession {
        self.session
    }
}

/// How a wait ended.
#[derive(Debug)]
pub enum EscalationOutcome {
    /// An `authenticate` escalation was approved and its grant persisted: re-resolve.
    Approved { escalation_id: EscalationId },
    /// A registration escalation was approved; the token permits this ceremony's registration.
    RegistrationApproved(RegistrationApproval),
    /// Denied. `reason` is set when the deny was not the human's (a failed prompt, audit or grant
    /// write); a human deny, dismissal or early approval carries `None`.
    Denied {
        escalation_id: EscalationId,
        cause: EscalationDenyCause,
        reason: Option<PolicyDenyReason>,
    },
    /// The notification server went away; no cooldown was started.
    ServerLost { escalation_id: EscalationId },
    /// A policy reload cancelled the escalation.
    Revoked { escalation_id: EscalationId },
    /// This waiter's deadline passed (or it was aborted within [`DEADLINE_ABORT_GRACE`] of it).
    TimedOut,
    /// This waiter's ceremony was cancelled.
    Aborted,
    /// This waiter's session became invalid.
    SessionInvalid,
}

/// Lifecycle of an escalation entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EscalationState {
    Queued,
    Prompting,
    Deciding,
    Approved,
    Denied,
    Expired,
    Withdrawn,
    Revoked,
}

impl EscalationState {
    fn is_terminal(self) -> bool {
        !matches!(self, Self::Queued | Self::Prompting | Self::Deciding)
    }
}

/// Identifies one shown prompt. A decision is accepted only for the active ticket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromptTicket {
    pub profile: ProfileId,
    pub escalation_id: EscalationId,
    pub seq: u64,
}

/// What the prompt driver reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PromptEvent {
    /// The notification is on screen.
    Shown,
    /// "Allow always", after the minimum review delay.
    Approved,
    /// "Deny", a dismissal, or an early approval.
    Denied(EscalationDenyCause),
    /// The notification server went away.
    ServerLost,
    /// The prompt could not be shown.
    Failed(String),
}

/// Receives the prompt driver's reports.
pub trait PromptSink: Send + Sync {
    fn prompt_event(&self, ticket: &PromptTicket, event: PromptEvent);
}

/// Shows and withdraws escalation prompts (the notification driver in `prompt.rs`, or a fake).
/// Never called with the escalation mutex held.
pub trait Prompter: Send + Sync {
    /// Whether a prompt can be shown for `profile` at all (a session bus can be resolved).
    fn available(&self, profile: &ProfileId) -> Result<(), String>;
    /// Show the prompt; report through `sink`.
    fn show(&self, ticket: PromptTicket, fields: PromptFields, sink: Weak<dyn PromptSink>);
    /// Withdraw the prompt of `ticket` (close the notification, end the prompt child).
    fn withdraw(&self, ticket: &PromptTicket);
}

/// The audit records of the coordinator. A failure is returned, never panicked on.
pub trait EscalationAudit: Send + Sync {
    fn record(&self, event: AuditEvent) -> Result<(), String>;
}

impl EscalationAudit for AuditGate {
    fn record(&self, event: AuditEvent) -> Result<(), String> {
        AuditGate::record(self, event)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// The state of a profile's granted-rules store, for the pre-prompt checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantCapacity {
    Available { used: usize },
    Unavailable,
}

/// Persists granted rules. Called without the escalation mutex.
pub trait GrantWriter: Send + Sync {
    fn capacity(&self, profile: &ProfileId) -> GrantCapacity;
    /// Persist `rule` and bump the grant epoch.
    fn add(
        &self,
        profile: &ProfileId,
        rule: GrantedRule,
        max_rules: usize,
    ) -> Result<(), GrantStoreError>;
}

/// The production [`GrantWriter`]: the granted-rules store, bumping the policy's grant epoch.
pub struct StoreGrantWriter {
    pub store: Arc<GrantedRulesStore>,
    pub policy: Arc<PolicyRuntime>,
}

impl GrantWriter for StoreGrantWriter {
    fn capacity(&self, profile: &ProfileId) -> GrantCapacity {
        match self.store.profile(profile).as_deref() {
            Some(ProfileGrants::Enabled(rules)) => GrantCapacity::Available { used: rules.len() },
            Some(ProfileGrants::Disabled(_)) | None => GrantCapacity::Unavailable,
        }
    }

    fn add(
        &self,
        profile: &ProfileId,
        rule: GrantedRule,
        max_rules: usize,
    ) -> Result<(), GrantStoreError> {
        self.store
            .add(&self.policy, profile, rule, max_rules)
            .map(|_| ())
    }
}

/// The [`Prompter`] of a daemon that cannot show escalation prompts at all (a root daemon without
/// `agents.notify_user`): every `request` resolution is refused with `escalation_unavailable`
/// before anything is prompted.
pub struct UnavailablePrompter {
    reason: String,
}

impl UnavailablePrompter {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl Prompter for UnavailablePrompter {
    fn available(&self, _profile: &ProfileId) -> Result<(), String> {
        Err(self.reason.clone())
    }

    fn show(&self, ticket: PromptTicket, _fields: PromptFields, sink: Weak<dyn PromptSink>) {
        if let Some(sink) = sink.upgrade() {
            sink.prompt_event(&ticket, PromptEvent::Failed(self.reason.clone()));
        }
    }

    fn withdraw(&self, _ticket: &PromptTicket) {}
}

/// Suspends and resumes the ceremony's capacity permit around the wait (`capacity.rs`
/// `RequestPermit`). `resume` is called exactly once after every `suspend`, also on unwinding.
pub trait ParkHook {
    fn suspend(&mut self) {}
    fn resume(&mut self) {}
}

/// A [`ParkHook`] that does nothing.
pub struct NoPark;

impl ParkHook for NoPark {}

/// What the coordinator needs.
pub struct EscalationDeps {
    pub audit: Arc<dyn EscalationAudit>,
    pub grants: Arc<dyn GrantWriter>,
    pub prompter: Arc<dyn Prompter>,
    pub clock: Arc<dyn MonotonicClock>,
    /// `agents.escalation_cooldown`; later changes go through [`EscalationService::set_cooldown`].
    pub cooldown: Duration,
}

/// The terminal outcome stored on an entry.
#[derive(Debug)]
enum EntryOutcome {
    Approved,
    Registration(Option<RegistrationApproval>),
    Denied {
        cause: EscalationDenyCause,
        reason: Option<PolicyDenyReason>,
    },
    ServerLost,
    Revoked,
    Expired,
}

#[derive(Debug)]
struct WaiterRecord {
    id: u64,
    session: WaiterSession,
}

#[derive(Debug)]
struct Entry {
    id: EscalationId,
    request: EscalationRequest,
    state: EscalationState,
    waiters: Vec<WaiterRecord>,
    joinable: bool,
    /// `escalation.requested` was written; only announced entries are prompted or audited.
    announced: bool,
    /// The active prompt's ticket sequence number.
    ticket: Option<u64>,
    prompted_at: Option<MonotonicTime>,
    outcome: Option<EntryOutcome>,
}

impl Entry {
    fn audit_context(&self) -> EscalationAuditContext {
        EscalationAuditContext {
            escalation_id: self.id.as_str().to_string(),
            profile_id: self.request.profile.clone(),
            action: self.request.audit_action(),
            rp_id: self.request.rp_id.clone(),
        }
    }

    fn ticket(&self) -> Option<PromptTicket> {
        self.ticket.map(|seq| PromptTicket {
            profile: self.request.profile.clone(),
            escalation_id: self.id.clone(),
            seq,
        })
    }
}

#[derive(Debug, Default)]
struct ProfileSlot {
    active: Option<u64>,
    queue: VecDeque<u64>,
    waiters: usize,
}

#[derive(Debug, Default)]
struct Inner {
    entries: HashMap<u64, Entry>,
    /// The live (non-terminal) entry of each key.
    by_key: HashMap<EscalationKey, u64>,
    profiles: HashMap<ProfileId, ProfileSlot>,
    session_waiters: HashMap<WaiterSession, usize>,
    global_waiters: usize,
    /// Cooldown end per key.
    cooldown: HashMap<EscalationKey, MonotonicTime>,
    /// Recent withdrawals per key (V-M2).
    withdrawals: HashMap<EscalationKey, VecDeque<MonotonicTime>>,
    next_serial: u64,
    next_waiter: u64,
    next_ticket: u64,
}

/// Deferred side effects, run after the mutex is released.
enum Effect {
    Audit(AuditEvent),
    Show(PromptTicket, PromptFields),
    Withdraw(PromptTicket),
}

fn later(time: MonotonicTime, duration: Duration) -> MonotonicTime {
    let ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
    time.checked_add(ms)
        .unwrap_or(MonotonicTime::from_millis(u64::MAX))
}

impl Inner {
    fn in_cooldown(&mut self, key: &EscalationKey, now: MonotonicTime) -> bool {
        match self.cooldown.get(key) {
            Some(until) if now < *until => true,
            Some(_) => {
                self.cooldown.remove(key);
                false
            }
            None => false,
        }
    }

    fn start_cooldown(&mut self, key: &EscalationKey, now: MonotonicTime, cooldown: Duration) {
        self.cooldown.insert(key.clone(), later(now, cooldown));
        self.withdrawals.remove(key);
    }

    /// Count a withdrawal of `key` (V-M2); the third within the window starts the cooldown.
    fn record_withdrawal(&mut self, key: &EscalationKey, now: MonotonicTime, cooldown: Duration) {
        let window = u64::try_from(WITHDRAWAL_WINDOW.as_millis()).unwrap_or(u64::MAX);
        let recent = self.withdrawals.entry(key.clone()).or_default();
        recent.retain(|at| now.saturating_duration_since(*at) < window);
        recent.push_back(now);
        if recent.len() >= WITHDRAWALS_BEFORE_COOLDOWN {
            info!(
                "escalation: {} withdrawals of {}/{} within {:?}; cooldown started",
                recent.len(),
                key.profile,
                key.rp_id,
                WITHDRAWAL_WINDOW
            );
            self.start_cooldown(key, now, cooldown);
        }
    }

    fn check_waiter_caps(
        &self,
        profile: &ProfileId,
        session: WaiterSession,
    ) -> Result<(), EscalationRefusal> {
        let per_session = self.session_waiters.get(&session).copied().unwrap_or(0);
        let per_profile = self.profiles.get(profile).map_or(0, |slot| slot.waiters);
        if per_session >= MAX_WAITERS_PER_SESSION
            || per_profile >= MAX_WAITERS_PER_PROFILE
            || self.global_waiters >= MAX_WAITERS_GLOBAL
        {
            return Err(EscalationRefusal::WaiterCap);
        }
        Ok(())
    }

    /// Admission of `request` under the mutex: `Some(serial)` to join, `None` to create.
    fn admit(
        &mut self,
        request: &EscalationRequest,
        key: &EscalationKey,
        now: MonotonicTime,
    ) -> Result<Option<u64>, EscalationRefusal> {
        if self.in_cooldown(key, now) {
            return Err(EscalationRefusal::Cooldown);
        }
        if let Some(&serial) = self.by_key.get(key) {
            let joinable = self
                .entries
                .get(&serial)
                .is_some_and(|entry| entry.joinable);
            if !joinable {
                return Err(EscalationRefusal::Busy);
            }
            self.check_waiter_caps(&request.profile, request.session)?;
            return Ok(Some(serial));
        }
        if let Some(slot) = self.profiles.get(&request.profile) {
            let pending = slot.queue.len() + usize::from(slot.active.is_some());
            if pending > MAX_QUEUED_PER_PROFILE {
                return Err(EscalationRefusal::QueueFull);
            }
        }
        self.check_waiter_caps(&request.profile, request.session)?;
        Ok(None)
    }

    fn add_waiter(&mut self, serial: u64, session: WaiterSession) -> u64 {
        self.next_waiter += 1;
        let id = self.next_waiter;
        let Some(entry) = self.entries.get_mut(&serial) else {
            return id;
        };
        entry.waiters.push(WaiterRecord { id, session });
        let profile = entry.request.profile.clone();
        self.profiles.entry(profile).or_default().waiters += 1;
        *self.session_waiters.entry(session).or_default() += 1;
        self.global_waiters += 1;
        id
    }

    /// Remove a waiter. `Some(remaining)` when it was attached.
    fn remove_waiter(&mut self, serial: u64, waiter: u64) -> Option<usize> {
        let entry = self.entries.get_mut(&serial)?;
        let index = entry
            .waiters
            .iter()
            .position(|record| record.id == waiter)?;
        let record = entry.waiters.swap_remove(index);
        let remaining = entry.waiters.len();
        let profile = entry.request.profile.clone();
        if let Some(slot) = self.profiles.get_mut(&profile) {
            slot.waiters = slot.waiters.saturating_sub(1);
        }
        if let Some(count) = self.session_waiters.get_mut(&record.session) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.session_waiters.remove(&record.session);
            }
        }
        self.global_waiters = self.global_waiters.saturating_sub(1);
        Some(remaining)
    }

    /// Take `serial` out of its key, its profile's queue and the active slot.
    fn unlink(&mut self, serial: u64) {
        let Some(entry) = self.entries.get(&serial) else {
            return;
        };
        let key = entry.request.key();
        if self.by_key.get(&key) == Some(&serial) {
            self.by_key.remove(&key);
        }
        if let Some(slot) = self.profiles.get_mut(&entry.request.profile) {
            slot.queue.retain(|queued| *queued != serial);
            if slot.active == Some(serial) {
                slot.active = None;
            }
        }
    }

    /// Drop a terminal entry nobody waits on (a `Deciding` entry is finished by its approver).
    fn collect(&mut self, serial: u64) {
        let finished = self.entries.get(&serial).is_some_and(|entry| {
            entry.waiters.is_empty() && entry.state.is_terminal() && entry.outcome.is_some()
        });
        if finished {
            self.entries.remove(&serial);
        }
    }

    /// Prompt the profile's next announced entry if its slot is free.
    fn pump(&mut self, profile: &ProfileId, now: MonotonicTime, effects: &mut Vec<Effect>) {
        let Some(slot) = self.profiles.get_mut(profile) else {
            return;
        };
        while slot.active.is_none() {
            let Some(&serial) = slot.queue.front() else {
                return;
            };
            let Some(entry) = self.entries.get_mut(&serial) else {
                slot.queue.pop_front();
                continue;
            };
            if entry.state != EscalationState::Queued {
                slot.queue.pop_front();
                continue;
            }
            if !entry.announced {
                // FIFO: the head is still being announced; it is pumped when that finishes.
                return;
            }
            slot.queue.pop_front();
            slot.active = Some(serial);
            self.next_ticket += 1;
            entry.state = EscalationState::Prompting;
            entry.ticket = Some(self.next_ticket);
            entry.prompted_at = Some(now);
            if let Some(ticket) = entry.ticket() {
                effects.push(Effect::Show(ticket, entry.request.prompt_fields()));
            }
        }
    }

    /// The live entry `ticket` names, if it is still prompting with that ticket.
    fn prompting(&self, ticket: &PromptTicket) -> Option<u64> {
        let serial = *self.profiles.get(&ticket.profile)?.active.as_ref()?;
        let entry = self.entries.get(&serial)?;
        (entry.state == EscalationState::Prompting
            && entry.id == ticket.escalation_id
            && entry.ticket == Some(ticket.seq))
        .then_some(serial)
    }
}

/// Why a waiter leaves before its entry ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Departure {
    Timeout,
    Aborted,
}

/// The escalation coordinator.
pub struct EscalationService {
    inner: Mutex<Inner>,
    changed: Condvar,
    audit: Arc<dyn EscalationAudit>,
    grants: Arc<dyn GrantWriter>,
    prompter: Arc<dyn Prompter>,
    clock: Arc<dyn MonotonicClock>,
    cooldown_ms: AtomicU64,
    self_ref: Weak<EscalationService>,
}

impl fmt::Debug for EscalationService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EscalationService").finish_non_exhaustive()
    }
}

impl EscalationService {
    pub fn new(deps: EscalationDeps) -> Arc<Self> {
        let cooldown_ms = u64::try_from(deps.cooldown.as_millis()).unwrap_or(u64::MAX);
        Arc::new_cyclic(|self_ref| Self {
            inner: Mutex::new(Inner::default()),
            changed: Condvar::new(),
            audit: deps.audit,
            grants: deps.grants,
            prompter: deps.prompter,
            clock: deps.clock,
            cooldown_ms: AtomicU64::new(cooldown_ms),
            self_ref: self_ref.clone(),
        })
    }

    /// Apply a reloaded `agents.escalation_cooldown` (read live by every later deny).
    pub fn set_cooldown(&self, cooldown: Duration) {
        let ms = u64::try_from(cooldown.as_millis()).unwrap_or(u64::MAX);
        self.cooldown_ms.store(ms, Ordering::Release);
    }

    fn cooldown(&self) -> Duration {
        Duration::from_millis(self.cooldown_ms.load(Ordering::Acquire))
    }

    fn lock(&self) -> Tracked<MutexGuard<'_, Inner>> {
        lock_order::lock(&self.inner, LockLevel::Escalation)
    }

    fn sink(&self) -> Weak<dyn PromptSink> {
        self.self_ref.clone()
    }

    /// Run deferred effects; the mutex must not be held.
    fn run(&self, effects: Vec<Effect>) {
        for effect in effects {
            match effect {
                Effect::Audit(event) => {
                    let kind = event.kind_name();
                    if let Err(e) = self.audit.record(event) {
                        warn!("escalation: failed to audit {}: {}", kind, e);
                    }
                }
                Effect::Show(ticket, fields) => self.prompter.show(ticket, fields, self.sink()),
                Effect::Withdraw(ticket) => self.prompter.withdraw(&ticket),
            }
        }
    }

    /// The checks made without the mutex: prompt availability and the grant store.
    fn check_resources(&self, request: &EscalationRequest) -> Result<(), EscalationRefusal> {
        match self.grants.capacity(&request.profile) {
            GrantCapacity::Unavailable => return Err(EscalationRefusal::GrantsUnavailable),
            GrantCapacity::Available { used } if used >= request.max_granted_rules => {
                return Err(EscalationRefusal::GrantCapReached);
            }
            GrantCapacity::Available { .. } => {}
        }
        if let Err(reason) = self.prompter.available(&request.profile) {
            debug!(
                "escalation: no prompt for profile '{}': {}",
                request.profile, reason
            );
            return Err(EscalationRefusal::Unavailable);
        }
        Ok(())
    }

    /// Whether `request` would be admitted now: cooldown, grant cap and store, bus, queue, waiter
    /// caps and a pending registration duplicate. Changes nothing; [`Self::join_or_create`]
    /// repeats every check atomically.
    pub fn precheck(&self, request: &EscalationRequest) -> Result<(), EscalationRefusal> {
        let key = request.key();
        if self.lock().in_cooldown(&key, self.clock.now()) {
            return Err(EscalationRefusal::Cooldown);
        }
        self.check_resources(request)?;
        self.lock()
            .admit(request, &key, self.clock.now())
            .map(|_| ())
    }

    /// Create the escalation of `request`'s key, or join it when it is a pending `authenticate`
    /// escalation. The creator writes `escalation.requested` before the entry can be prompted; a
    /// failed write refuses the escalation (and fails every waiter that joined meanwhile).
    pub fn join_or_create(
        self: &Arc<Self>,
        request: EscalationRequest,
    ) -> Result<Waiter, EscalationRefusal> {
        let key = request.key();
        if self.lock().in_cooldown(&key, self.clock.now()) {
            return Err(EscalationRefusal::Cooldown);
        }
        self.check_resources(&request)?;

        let now = self.clock.now();
        let (waiter, announcement) = {
            let mut inner = self.lock();
            match inner.admit(&request, &key, now)? {
                Some(serial) => {
                    let id = inner.add_waiter(serial, request.session);
                    let escalation_id = inner.entries[&serial].id.clone();
                    (
                        self.waiter(serial, id, escalation_id, request.session, true),
                        None,
                    )
                }
                None => {
                    inner.next_serial += 1;
                    let serial = inner.next_serial;
                    let escalation_id = EscalationId::generate();
                    let entry = Entry {
                        id: escalation_id.clone(),
                        joinable: request.action == CeremonyAction::Authenticate,
                        request: request.clone(),
                        state: EscalationState::Queued,
                        waiters: Vec::new(),
                        announced: false,
                        ticket: None,
                        prompted_at: None,
                        outcome: None,
                    };
                    let announcement = entry
                        .audit_context()
                        .requested(&request.origin, request.rule);
                    inner.entries.insert(serial, entry);
                    inner.by_key.insert(key.clone(), serial);
                    inner
                        .profiles
                        .entry(request.profile.clone())
                        .or_default()
                        .queue
                        .push_back(serial);
                    let id = inner.add_waiter(serial, request.session);
                    (
                        self.waiter(serial, id, escalation_id, request.session, false),
                        Some(announcement),
                    )
                }
            }
        };

        let Some(announcement) = announcement else {
            debug!(
                "escalation {}: joined ({}/{})",
                waiter.escalation_id, key.profile, key.rp_id
            );
            return Ok(waiter);
        };

        let recorded = self.audit.record(announcement);
        let mut effects = Vec::new();
        {
            let mut inner = self.lock();
            let serial = waiter.serial;
            match &recorded {
                Ok(()) => {
                    if let Some(entry) = inner.entries.get_mut(&serial) {
                        entry.announced = true;
                    }
                    inner.pump(&key.profile, self.clock.now(), &mut effects);
                }
                Err(e) => {
                    warn!(
                        "escalation {}: escalation.requested could not be audited: {}",
                        waiter.escalation_id, e
                    );
                    if let Some(entry) = inner.entries.get_mut(&serial)
                        && entry.state == EscalationState::Queued
                    {
                        entry.state = EscalationState::Denied;
                        entry.outcome = Some(EntryOutcome::Denied {
                            cause: EscalationDenyCause::AuditFailure,
                            reason: Some(PolicyDenyReason::AuditFailure),
                        });
                    }
                    inner.unlink(serial);
                    inner.pump(&key.profile, self.clock.now(), &mut effects);
                    self.changed.notify_all();
                }
            }
        }
        self.run(effects);
        match recorded {
            Ok(()) => {
                info!(
                    "escalation {}: requested ({}/{} {})",
                    waiter.escalation_id,
                    key.profile,
                    key.rp_id,
                    key.action.as_str()
                );
                Ok(waiter)
            }
            Err(_) => {
                drop(waiter);
                Err(EscalationRefusal::AuditFailure)
            }
        }
    }

    fn waiter(
        self: &Arc<Self>,
        serial: u64,
        id: u64,
        escalation_id: EscalationId,
        session: WaiterSession,
        joined: bool,
    ) -> Waiter {
        Waiter {
            service: Arc::clone(self),
            serial,
            id,
            escalation_id,
            session,
            joined,
            attached: true,
        }
    }

    /// A waiter leaves. When it was the last one of a pending entry, the entry ends: dequeued or
    /// withdrawn, audited as expired, and counted for V-M2 (an abort) or put in cooldown (a
    /// timeout).
    fn depart(&self, serial: u64, waiter: u64, departure: Departure) {
        let cooldown = self.cooldown();
        let now = self.clock.now();
        let mut effects = Vec::new();
        {
            let mut inner = self.lock();
            let Some(remaining) = inner.remove_waiter(serial, waiter) else {
                return;
            };
            if remaining == 0
                && let Some(entry) = inner.entries.get_mut(&serial)
                && matches!(
                    entry.state,
                    EscalationState::Queued | EscalationState::Prompting
                )
            {
                let was_prompting = entry.state == EscalationState::Prompting;
                let reason = match departure {
                    Departure::Timeout => EscalationExpireReason::Timeout,
                    Departure::Aborted => EscalationExpireReason::Aborted,
                };
                entry.state = match departure {
                    Departure::Timeout => EscalationState::Expired,
                    Departure::Aborted => EscalationState::Withdrawn,
                };
                entry.outcome = Some(EntryOutcome::Expired);
                if was_prompting && let Some(ticket) = entry.ticket() {
                    effects.push(Effect::Withdraw(ticket));
                }
                if entry.announced {
                    effects.push(Effect::Audit(entry.audit_context().expired(reason)));
                }
                let key = entry.request.key();
                let profile = key.profile.clone();
                info!(
                    "escalation {}: last waiter left ({:?}); {}",
                    entry.id,
                    departure,
                    if was_prompting {
                        "withdrawn"
                    } else {
                        "dequeued"
                    }
                );
                inner.unlink(serial);
                match departure {
                    Departure::Timeout => inner.start_cooldown(&key, now, cooldown),
                    Departure::Aborted => inner.record_withdrawal(&key, now, cooldown),
                }
                inner.pump(&profile, now, &mut effects);
            }
            inner.collect(serial);
        }
        self.run(effects);
    }

    /// End the active prompt of `ticket` without approval.
    fn finish_prompt(&self, ticket: &PromptTicket, event: PromptEvent) {
        let cooldown = self.cooldown();
        let now = self.clock.now();
        let mut effects = Vec::new();
        {
            let mut inner = self.lock();
            let Some(serial) = inner.prompting(ticket) else {
                debug!(
                    "escalation {}: ignoring a stale prompt report ({:?})",
                    ticket.escalation_id, event
                );
                return;
            };
            let Some(entry) = inner.entries.get_mut(&serial) else {
                return;
            };
            let key = entry.request.key();
            let context = entry.audit_context();
            let mut start_cooldown = false;
            let mut withdrawn = false;
            match &event {
                PromptEvent::Denied(cause) => {
                    entry.state = EscalationState::Denied;
                    entry.outcome = Some(EntryOutcome::Denied {
                        cause: *cause,
                        reason: None,
                    });
                    effects.push(Effect::Audit(context.denied(*cause)));
                    start_cooldown = true;
                    info!("escalation {}: denied ({:?})", entry.id, cause);
                }
                PromptEvent::ServerLost => {
                    entry.state = EscalationState::Expired;
                    entry.outcome = Some(EntryOutcome::ServerLost);
                    effects.push(Effect::Audit(
                        context.expired(EscalationExpireReason::ServerLost),
                    ));
                    withdrawn = true;
                    info!("escalation {}: notification server lost", entry.id);
                }
                PromptEvent::Failed(detail) => {
                    entry.state = EscalationState::Denied;
                    entry.outcome = Some(EntryOutcome::Denied {
                        cause: EscalationDenyCause::PromptUnavailable,
                        reason: Some(PolicyDenyReason::EscalationUnavailable),
                    });
                    effects.push(Effect::Audit(
                        context.denied(EscalationDenyCause::PromptUnavailable),
                    ));
                    warn!("escalation {}: prompt failed: {}", entry.id, detail);
                }
                PromptEvent::Shown | PromptEvent::Approved => return,
            }
            inner.unlink(serial);
            if start_cooldown {
                inner.start_cooldown(&key, now, cooldown);
            }
            if withdrawn {
                inner.record_withdrawal(&key, now, cooldown);
            }
            inner.pump(&key.profile, now, &mut effects);
            inner.collect(serial);
            self.changed.notify_all();
        }
        self.run(effects);
    }

    /// The approval protocol (module documentation).
    fn approve(&self, ticket: &PromptTicket) {
        let now = self.clock.now();
        let (serial, request, escalation_id, context, latency_ms) = {
            let mut inner = self.lock();
            let Some(serial) = inner.prompting(ticket) else {
                debug!(
                    "escalation {}: ignoring a stale or late approval",
                    ticket.escalation_id
                );
                return;
            };
            let Some(entry) = inner.entries.get_mut(&serial) else {
                return;
            };
            entry.state = EscalationState::Deciding;
            let latency_ms = entry
                .prompted_at
                .map_or(0, |at| now.saturating_duration_since(at));
            (
                serial,
                entry.request.clone(),
                entry.id.clone(),
                entry.audit_context(),
                latency_ms,
            )
        };

        if let Err(e) = self.audit.record(context.approved(latency_ms)) {
            warn!(
                "escalation {}: escalation.approved could not be audited, denying: {}",
                escalation_id, e
            );
            self.finish_deciding(
                serial,
                EntryOutcome::Denied {
                    cause: EscalationDenyCause::AuditFailure,
                    reason: Some(PolicyDenyReason::AuditFailure),
                },
                Some(context.denied(EscalationDenyCause::AuditFailure)),
            );
            return;
        }

        let outcome = match request.action {
            CeremonyAction::Authenticate => {
                let rule = GrantedRule::new(
                    &request.rp_id,
                    GrantKind::Escalation,
                    escalation_id.as_str(),
                    &request.origin,
                    request.rule,
                    None,
                );
                match self
                    .grants
                    .add(&request.profile, rule, request.max_granted_rules)
                {
                    Ok(()) => {
                        let added = GrantedRuleAddBuilder::new(
                            request.profile.clone(),
                            &request.rp_id,
                            GrantKind::Escalation,
                            escalation_id.as_str(),
                            request.rule,
                        )
                        .build();
                        if let Err(e) = self.audit.record(added) {
                            warn!(
                                "escalation {}: granted_rule.add could not be audited: {}",
                                escalation_id, e
                            );
                        }
                        info!(
                            "escalation {}: approved; {}/{} granted",
                            escalation_id, request.profile, request.rp_id
                        );
                        EntryOutcome::Approved
                    }
                    Err(e) => {
                        warn!(
                            "escalation {}: the grant could not be persisted, denying: {}",
                            escalation_id, e
                        );
                        let reason = match e {
                            GrantStoreError::CapReached(_) => PolicyDenyReason::GrantCapReached,
                            _ => PolicyDenyReason::GrantsUnavailable,
                        };
                        self.finish_deciding(
                            serial,
                            EntryOutcome::Denied {
                                cause: EscalationDenyCause::GrantWriteFailed,
                                reason: Some(reason),
                            },
                            Some(context.denied(EscalationDenyCause::GrantWriteFailed)),
                        );
                        return;
                    }
                }
            }
            CeremonyAction::Register => {
                info!(
                    "escalation {}: registration approved for {}/{}",
                    escalation_id, request.profile, request.rp_id
                );
                EntryOutcome::Registration(Some(RegistrationApproval {
                    escalation_id: escalation_id.clone(),
                    profile: request.profile.clone(),
                    rp_id: request.rp_id.clone(),
                    origin: request.origin.clone(),
                    rule: request.rule,
                    session: request.session,
                }))
            }
        };
        self.finish_deciding(serial, outcome, None);
    }

    /// Step 4 of the approval protocol (or its deny).
    fn finish_deciding(&self, serial: u64, outcome: EntryOutcome, audit: Option<AuditEvent>) {
        let now = self.clock.now();
        let mut effects = Vec::new();
        if let Some(event) = audit {
            effects.push(Effect::Audit(event));
        }
        {
            let mut inner = self.lock();
            let Some(entry) = inner.entries.get_mut(&serial) else {
                drop(inner);
                self.run(effects);
                return;
            };
            if entry.state != EscalationState::Deciding {
                // Revoked by a reload while the approval was written; the revocation stands.
                inner.collect(serial);
                drop(inner);
                self.run(effects);
                return;
            }
            entry.state = match outcome {
                EntryOutcome::Approved | EntryOutcome::Registration(_) => EscalationState::Approved,
                _ => EscalationState::Denied,
            };
            entry.outcome = Some(outcome);
            let profile = entry.request.profile.clone();
            inner.unlink(serial);
            inner.pump(&profile, now, &mut effects);
            inner.collect(serial);
            self.changed.notify_all();
        }
        self.run(effects);
    }

    /// Cancel every pending escalation of `profile` after a reload changed the policy. Each is
    /// recorded as `escalation.revoked` with `reason = policy_reload`; their waiters see
    /// [`EscalationOutcome::Revoked`].
    pub fn cancel_profile(&self, profile: &ProfileId) {
        let mut effects = Vec::new();
        {
            let mut inner = self.lock();
            let serials: Vec<u64> = inner
                .entries
                .iter()
                .filter(|(_, entry)| {
                    entry.request.profile == *profile && !entry.state.is_terminal()
                })
                .map(|(serial, _)| *serial)
                .collect();
            for serial in serials {
                let Some(entry) = inner.entries.get_mut(&serial) else {
                    continue;
                };
                if entry.state == EscalationState::Prompting
                    && let Some(ticket) = entry.ticket()
                {
                    effects.push(Effect::Withdraw(ticket));
                }
                entry.state = EscalationState::Revoked;
                entry.outcome = Some(EntryOutcome::Revoked);
                if entry.announced {
                    effects.push(Effect::Audit(
                        entry
                            .audit_context()
                            .revoked(EscalationRevokeReason::PolicyReload),
                    ));
                }
                info!("escalation {}: revoked by a policy reload", entry.id);
                inner.unlink(serial);
                inner.collect(serial);
            }
            self.changed.notify_all();
        }
        self.run(effects);
    }

    /// Persist the grant of an approved registration after its credential was written (ADR 0014
    /// section 8.3), bump the grant epoch and audit `granted_rule.add`. A failure persists
    /// nothing and is audited as `escalation.denied` with `cause = grant_write_failed`; the
    /// credential stays and its next authentication escalates again (plan P7 gap 10).
    pub fn record_registration_grant(
        &self,
        approval: &RegistrationApproval,
        credential_ref: CredentialRef,
        max_granted_rules: usize,
    ) -> Result<(), GrantStoreError> {
        let rule = GrantedRule::new(
            &approval.rp_id,
            GrantKind::Registration,
            approval.escalation_id.as_str(),
            &approval.origin,
            approval.rule,
            Some(credential_ref.clone()),
        );
        if let Err(e) = self.grants.add(&approval.profile, rule, max_granted_rules) {
            warn!(
                "escalation {}: the registration grant could not be persisted: {}",
                approval.escalation_id, e
            );
            let context = EscalationAuditContext {
                escalation_id: approval.escalation_id.as_str().to_string(),
                profile_id: approval.profile.clone(),
                action: AuditAction::Register,
                rp_id: approval.rp_id.clone(),
            };
            if let Err(audit_error) = self
                .audit
                .record(context.denied(EscalationDenyCause::GrantWriteFailed))
            {
                warn!(
                    "escalation {}: the failed grant write could not be audited: {}",
                    approval.escalation_id, audit_error
                );
            }
            return Err(e);
        }
        let added = GrantedRuleAddBuilder::new(
            approval.profile.clone(),
            &approval.rp_id,
            GrantKind::Registration,
            approval.escalation_id.as_str(),
            approval.rule,
        )
        .credential_ref(Some(credential_ref))
        .build();
        if let Err(e) = self.audit.record(added) {
            warn!(
                "escalation {}: granted_rule.add could not be audited: {}",
                approval.escalation_id, e
            );
        }
        Ok(())
    }

    /// The state of `key`'s live entry, if any.
    pub fn state_of(&self, key: &EscalationKey) -> Option<EscalationState> {
        let inner = self.lock();
        let serial = inner.by_key.get(key)?;
        inner.entries.get(serial).map(|entry| entry.state)
    }

    /// Escalations of `profile` waiting behind its active prompt.
    pub fn queued(&self, profile: &ProfileId) -> usize {
        self.lock()
            .profiles
            .get(profile)
            .map_or(0, |slot| slot.queue.len())
    }

    /// Whether `key` is in its cooldown now.
    pub fn in_cooldown(&self, key: &EscalationKey) -> bool {
        let now = self.clock.now();
        self.lock().in_cooldown(key, now)
    }
}

impl PromptSink for EscalationService {
    fn prompt_event(&self, ticket: &PromptTicket, event: PromptEvent) {
        match event {
            PromptEvent::Shown => debug!("escalation {}: prompt shown", ticket.escalation_id),
            PromptEvent::Approved => self.approve(ticket),
            other => self.finish_prompt(ticket, other),
        }
    }
}

/// Calls [`ParkHook::resume`] when dropped.
struct Resume<'a> {
    hook: &'a mut dyn ParkHook,
}

impl Drop for Resume<'_> {
    fn drop(&mut self) {
        self.hook.resume();
    }
}

/// One ceremony waiting on an escalation. Dropping it detaches it (as an abort).
pub struct Waiter {
    service: Arc<EscalationService>,
    serial: u64,
    id: u64,
    escalation_id: EscalationId,
    session: WaiterSession,
    joined: bool,
    attached: bool,
}

impl fmt::Debug for Waiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Waiter")
            .field("escalation_id", &self.escalation_id)
            .field("joined", &self.joined)
            .finish_non_exhaustive()
    }
}

impl Waiter {
    pub fn escalation_id(&self) -> &EscalationId {
        &self.escalation_id
    }

    /// Whether this waiter joined an escalation another ceremony created.
    pub fn joined(&self) -> bool {
        self.joined
    }

    pub fn session(&self) -> WaiterSession {
        self.session
    }

    /// The entry's outcome for this waiter, taken under the mutex; detaches the waiter.
    fn take_outcome(&mut self, inner: &mut Inner) -> Option<EscalationOutcome> {
        let entry = inner.entries.get_mut(&self.serial)?;
        let escalation_id = entry.id.clone();
        let outcome = match entry.outcome.as_mut()? {
            EntryOutcome::Approved => EscalationOutcome::Approved { escalation_id },
            EntryOutcome::Registration(token) => match token.take() {
                Some(approval) => EscalationOutcome::RegistrationApproved(approval),
                // Registration escalations are not joinable; the token was the creator's.
                None => EscalationOutcome::Denied {
                    escalation_id,
                    cause: EscalationDenyCause::User,
                    reason: Some(PolicyDenyReason::EscalationBusy),
                },
            },
            EntryOutcome::Denied { cause, reason } => EscalationOutcome::Denied {
                escalation_id,
                cause: *cause,
                reason: *reason,
            },
            EntryOutcome::ServerLost => EscalationOutcome::ServerLost { escalation_id },
            EntryOutcome::Revoked => EscalationOutcome::Revoked { escalation_id },
            EntryOutcome::Expired => EscalationOutcome::Aborted,
        };
        inner.remove_waiter(self.serial, self.id);
        inner.collect(self.serial);
        self.attached = false;
        Some(outcome)
    }

    /// Park until the escalation ends, `deadline` passes, `cancelled()` returns true or
    /// `still_valid()` returns false. The waiter wakes at least every [`WAIT_POLL_INTERVAL`] and
    /// calls both checks with no lock held. `park` suspends the ceremony's capacity permit for the
    /// wait and resumes it afterwards, unconditionally.
    pub fn wait(
        mut self,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
        still_valid: &dyn Fn() -> bool,
        park: &mut dyn ParkHook,
    ) -> EscalationOutcome {
        park.suspend();
        let _resume = Resume { hook: park };
        let service = Arc::clone(&self.service);
        loop {
            {
                let mut inner = service.lock();
                if let Some(outcome) = self.take_outcome(&mut inner) {
                    return outcome;
                }
                let now = Instant::now();
                if now < deadline {
                    let pause = WAIT_POLL_INTERVAL.min(deadline - now);
                    inner = inner.wait_timeout(&service.changed, pause);
                    if let Some(outcome) = self.take_outcome(&mut inner) {
                        return outcome;
                    }
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return self.leave(Departure::Timeout, EscalationOutcome::TimedOut);
            }
            if cancelled() {
                if deadline.saturating_duration_since(now) <= DEADLINE_ABORT_GRACE {
                    return self.leave(Departure::Timeout, EscalationOutcome::TimedOut);
                }
                return self.leave(Departure::Aborted, EscalationOutcome::Aborted);
            }
            if !still_valid() {
                return self.leave(Departure::Aborted, EscalationOutcome::SessionInvalid);
            }
        }
    }

    fn leave(&mut self, departure: Departure, outcome: EscalationOutcome) -> EscalationOutcome {
        if self.attached {
            self.attached = false;
            self.service.depart(self.serial, self.id, departure);
        }
        outcome
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        if self.attached {
            self.attached = false;
            self.service
                .depart(self.serial, self.id, Departure::Aborted);
        }
    }
}

/// A scripted prompter and service constructors for the ceremony tests (`sign.rs`, `register.rs`).
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    use std::sync::atomic::AtomicBool;

    use super::super::identity::SystemClock;

    /// One shown prompt and where its decision goes.
    type Shown = (PromptTicket, PromptFields, Weak<dyn PromptSink>);

    /// Records shown and withdrawn prompts; a test decides the last shown prompt by hand.
    #[derive(Default)]
    pub struct ScriptedPrompter {
        shown: Mutex<Vec<Shown>>,
        withdrawn: Mutex<Vec<PromptTicket>>,
        changed: Condvar,
        unavailable: AtomicBool,
    }

    impl ScriptedPrompter {
        pub fn set_unavailable(&self, unavailable: bool) {
            self.unavailable.store(unavailable, Ordering::SeqCst);
        }

        pub fn shown(&self) -> usize {
            self.shown.lock().unwrap().len()
        }

        pub fn withdrawn(&self) -> usize {
            self.withdrawn.lock().unwrap().len()
        }

        pub fn last_fields(&self) -> PromptFields {
            self.shown.lock().unwrap().last().unwrap().1.clone()
        }

        /// Wait until `count` prompts were shown.
        pub fn wait_shown(&self, count: usize) {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut shown = self.shown.lock().unwrap();
            while shown.len() < count {
                let now = Instant::now();
                assert!(now < deadline, "only {} prompt(s) shown", shown.len());
                shown = self.changed.wait_timeout(shown, deadline - now).unwrap().0;
            }
        }

        /// Report `event` for the last shown prompt.
        pub fn decide(&self, event: PromptEvent) {
            let (ticket, sink) = {
                let shown = self.shown.lock().unwrap();
                let (ticket, _, sink) = shown.last().expect("no prompt shown");
                (ticket.clone(), sink.clone())
            };
            sink.upgrade()
                .expect("escalation service dropped")
                .prompt_event(&ticket, event);
        }

        /// Wait for prompt `count`, then approve it.
        pub fn approve(&self, count: usize) {
            self.wait_shown(count);
            self.decide(PromptEvent::Approved);
        }
    }

    impl Prompter for ScriptedPrompter {
        fn available(&self, _profile: &ProfileId) -> Result<(), String> {
            if self.unavailable.load(Ordering::SeqCst) {
                Err("no session bus".to_string())
            } else {
                Ok(())
            }
        }

        fn show(&self, ticket: PromptTicket, fields: PromptFields, sink: Weak<dyn PromptSink>) {
            assert!(lock_order::held_levels().is_empty());
            self.shown.lock().unwrap().push((ticket, fields, sink));
            self.changed.notify_all();
        }

        fn withdraw(&self, ticket: &PromptTicket) {
            assert!(lock_order::held_levels().is_empty());
            self.withdrawn.lock().unwrap().push(ticket.clone());
        }
    }

    /// Accepts no grant (the ceremony tests that never approve).
    struct NoGrants;

    impl GrantWriter for NoGrants {
        fn capacity(&self, _profile: &ProfileId) -> GrantCapacity {
            GrantCapacity::Available { used: 0 }
        }

        fn add(
            &self,
            profile: &ProfileId,
            _rule: GrantedRule,
            _max_rules: usize,
        ) -> Result<(), GrantStoreError> {
            Err(GrantStoreError::Unavailable(profile.to_string()))
        }
    }

    /// A coordinator that can show no prompt: every escalation is refused with
    /// `escalation_unavailable` (a daemon without a session bus).
    pub fn idle_service(audit: Arc<AuditGate>) -> Arc<EscalationService> {
        EscalationService::new(EscalationDeps {
            audit,
            grants: Arc::new(NoGrants),
            prompter: Arc::new(UnavailablePrompter::new("no session bus in this test")),
            clock: Arc::new(SystemClock::new()),
            cooldown: Duration::from_secs(600),
        })
    }

    /// The production coordinator over the real audit gate and granted-rules store, with a
    /// scripted prompter.
    pub fn service(
        audit: Arc<AuditGate>,
        store: Arc<GrantedRulesStore>,
        policy: Arc<PolicyRuntime>,
        prompter: Arc<ScriptedPrompter>,
        cooldown: Duration,
    ) -> Arc<EscalationService> {
        EscalationService::new(EscalationDeps {
            audit,
            grants: Arc::new(StoreGrantWriter { store, policy }),
            prompter,
            clock: Arc::new(SystemClock::new()),
            cooldown,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;
    use std::sync::atomic::AtomicBool;
    use std::thread;

    /// A clock the test moves by hand.
    struct ManualClock(AtomicU64);

    impl ManualClock {
        fn advance(&self, by: Duration) {
            self.0.fetch_add(by.as_millis() as u64, Ordering::SeqCst);
        }
    }

    impl MonotonicClock for ManualClock {
        fn now(&self) -> MonotonicTime {
            MonotonicTime::from_millis(self.0.load(Ordering::SeqCst))
        }
    }

    #[derive(Default)]
    struct FakeAudit {
        kinds: Mutex<Vec<String>>,
        events: Mutex<Vec<serde_json::Value>>,
        failing: Mutex<HashSet<&'static str>>,
    }

    impl FakeAudit {
        fn fail(&self, kind: &'static str) {
            self.failing.lock().unwrap().insert(kind);
        }

        fn kinds(&self) -> Vec<String> {
            self.kinds.lock().unwrap().clone()
        }

        fn count(&self, kind: &str) -> usize {
            self.kinds().iter().filter(|k| *k == kind).count()
        }

        fn last(&self, kind: &str) -> serde_json::Value {
            self.events
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|event| event["kind"] == kind)
                .cloned()
                .unwrap_or_else(|| panic!("no {kind} event in {:?}", self.kinds()))
        }
    }

    impl EscalationAudit for FakeAudit {
        fn record(&self, event: AuditEvent) -> Result<(), String> {
            assert!(
                lock_order::held_levels().is_empty(),
                "audit under a lock: {:?}",
                lock_order::held_levels()
            );
            let kind = event.kind_name();
            if self.failing.lock().unwrap().contains(kind) {
                return Err("injected audit failure".to_string());
            }
            self.kinds.lock().unwrap().push(kind.to_string());
            self.events
                .lock()
                .unwrap()
                .push(serde_json::to_value(&event).unwrap());
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeGrants {
        rules: Mutex<Vec<GrantedRule>>,
        unavailable: AtomicBool,
        fail_writes: AtomicBool,
    }

    impl GrantWriter for FakeGrants {
        fn capacity(&self, _profile: &ProfileId) -> GrantCapacity {
            if self.unavailable.load(Ordering::SeqCst) {
                return GrantCapacity::Unavailable;
            }
            GrantCapacity::Available {
                used: self.rules.lock().unwrap().len(),
            }
        }

        fn add(
            &self,
            _profile: &ProfileId,
            rule: GrantedRule,
            max_rules: usize,
        ) -> Result<(), GrantStoreError> {
            assert!(lock_order::held_levels().is_empty());
            if self.fail_writes.load(Ordering::SeqCst) {
                return Err(GrantStoreError::Io("injected".to_string()));
            }
            let mut rules = self.rules.lock().unwrap();
            if rules.len() >= max_rules {
                return Err(GrantStoreError::CapReached(max_rules));
            }
            rules.push(rule);
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakePrompter {
        shown: Mutex<Vec<(PromptTicket, PromptFields)>>,
        withdrawn: Mutex<Vec<PromptTicket>>,
        unavailable: AtomicBool,
    }

    impl FakePrompter {
        fn shown(&self) -> Vec<PromptTicket> {
            self.shown
                .lock()
                .unwrap()
                .iter()
                .map(|(ticket, _)| ticket.clone())
                .collect()
        }

        fn last_shown(&self) -> PromptTicket {
            self.shown().last().cloned().expect("no prompt shown")
        }

        fn withdrawn(&self) -> Vec<PromptTicket> {
            self.withdrawn.lock().unwrap().clone()
        }
    }

    impl Prompter for FakePrompter {
        fn available(&self, _profile: &ProfileId) -> Result<(), String> {
            if self.unavailable.load(Ordering::SeqCst) {
                Err("no bus".to_string())
            } else {
                Ok(())
            }
        }

        fn show(&self, ticket: PromptTicket, fields: PromptFields, _sink: Weak<dyn PromptSink>) {
            assert!(lock_order::held_levels().is_empty());
            self.shown.lock().unwrap().push((ticket, fields));
        }

        fn withdraw(&self, ticket: &PromptTicket) {
            assert!(lock_order::held_levels().is_empty());
            self.withdrawn.lock().unwrap().push(ticket.clone());
        }
    }

    struct Harness {
        service: Arc<EscalationService>,
        audit: Arc<FakeAudit>,
        grants: Arc<FakeGrants>,
        prompter: Arc<FakePrompter>,
        clock: Arc<ManualClock>,
    }

    const COOLDOWN: Duration = Duration::from_secs(600);

    fn harness() -> Harness {
        let audit = Arc::new(FakeAudit::default());
        let grants = Arc::new(FakeGrants::default());
        let prompter = Arc::new(FakePrompter::default());
        let clock = Arc::new(ManualClock(AtomicU64::new(1_000)));
        let service = EscalationService::new(EscalationDeps {
            audit: audit.clone(),
            grants: grants.clone(),
            prompter: prompter.clone(),
            clock: clock.clone(),
            cooldown: COOLDOWN,
        });
        Harness {
            service,
            audit,
            grants,
            prompter,
            clock,
        }
    }

    fn profile(name: &str) -> ProfileId {
        ProfileId::new(name).unwrap()
    }

    fn request(profile_name: &str, rp_id: &str, session: usize) -> EscalationRequest {
        EscalationRequest {
            profile: profile(profile_name),
            rp_id: rp_id.to_string(),
            action: CeremonyAction::Authenticate,
            origin: format!("https://{rp_id}"),
            rule: PermittingRule::Exact,
            session: WaiterSession::from_raw(session),
            mode: AgentMode::Isolated,
            principal_user: "agent".to_string(),
            max_granted_rules: 64,
        }
    }

    fn register(profile_name: &str, rp_id: &str, session: usize) -> EscalationRequest {
        EscalationRequest {
            action: CeremonyAction::Register,
            ..request(profile_name, rp_id, session)
        }
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    /// Park `waiter` on a thread; join it for the outcome.
    fn park(waiter: Waiter) -> thread::JoinHandle<EscalationOutcome> {
        park_until(waiter, far(), Arc::new(AtomicBool::new(false)))
    }

    fn park_until(
        waiter: Waiter,
        deadline: Instant,
        cancel: Arc<AtomicBool>,
    ) -> thread::JoinHandle<EscalationOutcome> {
        thread::spawn(move || {
            waiter.wait(
                deadline,
                &|| cancel.load(Ordering::SeqCst),
                &|| true,
                &mut NoPark,
            )
        })
    }

    #[test]
    fn authenticate_escalations_join_and_coalesce_into_one_prompt() {
        let h = harness();
        let first = h
            .service
            .join_or_create(request("p", "a.example", 1))
            .unwrap();
        let second = h
            .service
            .join_or_create(request("p", "a.example", 2))
            .unwrap();
        assert!(!first.joined());
        assert!(second.joined());
        assert_eq!(first.escalation_id(), second.escalation_id());
        assert_eq!(h.prompter.shown().len(), 1);
        assert_eq!(h.audit.count("escalation.requested"), 1);

        let (a, b) = (park(first), park(second));
        h.clock.advance(Duration::from_secs(2));
        h.service
            .prompt_event(&h.prompter.last_shown(), PromptEvent::Approved);
        assert!(matches!(
            a.join().unwrap(),
            EscalationOutcome::Approved { .. }
        ));
        assert!(matches!(
            b.join().unwrap(),
            EscalationOutcome::Approved { .. }
        ));
        assert_eq!(h.grants.rules.lock().unwrap().len(), 1);
        let rule = h.grants.rules.lock().unwrap()[0].clone();
        assert_eq!(rule.rp_id, "a.example");
        assert_eq!(rule.kind, GrantKind::Escalation);
        assert_eq!(rule.origin, "https://a.example");
        assert_eq!(
            h.audit.kinds(),
            [
                "escalation.requested",
                "escalation.approved",
                "granted_rule.add"
            ]
        );
        assert_eq!(h.audit.last("escalation.approved")["latency_ms"], 2000);
        assert_eq!(
            h.service.state_of(&request("p", "a.example", 1).key()),
            None
        );
    }

    #[test]
    fn registration_is_not_joinable_and_its_approval_is_a_token() {
        let h = harness();
        let waiter = h
            .service
            .join_or_create(register("p", "r.example", 1))
            .unwrap();
        assert_eq!(
            h.service
                .join_or_create(register("p", "r.example", 2))
                .unwrap_err(),
            EscalationRefusal::Busy
        );
        assert_eq!(
            h.service.precheck(&register("p", "r.example", 2)),
            Err(EscalationRefusal::Busy)
        );
        let parked = park(waiter);
        h.service
            .prompt_event(&h.prompter.last_shown(), PromptEvent::Approved);
        match parked.join().unwrap() {
            EscalationOutcome::RegistrationApproved(approval) => {
                assert_eq!(approval.rp_id(), "r.example");
                assert_eq!(approval.session(), WaiterSession::from_raw(1));
                assert!(h.grants.rules.lock().unwrap().is_empty());
                h.service
                    .record_registration_grant(
                        &approval,
                        CredentialRef::with_default_domain(b"cred"),
                        64,
                    )
                    .unwrap();
            }
            other => panic!("unexpected {other:?}"),
        }
        let rules = h.grants.rules.lock().unwrap().clone();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].kind, GrantKind::Registration);
        assert!(rules[0].credential_ref.is_some());
        let added = h.audit.last("granted_rule.add");
        assert_eq!(added["grant_kind"], "registration");
        assert_eq!(added["escalation_id"], rules[0].request_id.as_str());
        assert!(added["credential_ref"].is_string());
        // A new registration for the key prompts again.
        let _again = h
            .service
            .join_or_create(register("p", "r.example", 1))
            .unwrap();
        assert_eq!(h.prompter.shown().len(), 2);
    }

    #[test]
    fn deny_starts_the_cooldown_until_the_clock_passes_it() {
        let h = harness();
        let parked = park(
            h.service
                .join_or_create(request("p", "a.example", 1))
                .unwrap(),
        );
        h.service.prompt_event(
            &h.prompter.last_shown(),
            PromptEvent::Denied(EscalationDenyCause::User),
        );
        match parked.join().unwrap() {
            EscalationOutcome::Denied { cause, reason, .. } => {
                assert_eq!(cause, EscalationDenyCause::User);
                assert_eq!(reason, None);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(h.audit.last("escalation.denied")["cause"], "user");
        let key = request("p", "a.example", 1).key();
        assert!(h.service.in_cooldown(&key));
        assert_eq!(
            h.service
                .join_or_create(request("p", "a.example", 1))
                .unwrap_err(),
            EscalationRefusal::Cooldown
        );
        assert_eq!(h.prompter.shown().len(), 1);
        // Another key and another profile are unaffected.
        assert!(h.service.precheck(&request("p", "b.example", 1)).is_ok());
        assert!(h.service.precheck(&request("q", "a.example", 1)).is_ok());

        h.clock.advance(COOLDOWN - Duration::from_millis(1));
        assert!(h.service.in_cooldown(&key));
        h.clock.advance(Duration::from_millis(1));
        assert!(!h.service.in_cooldown(&key));
        let _again = h
            .service
            .join_or_create(request("p", "a.example", 1))
            .unwrap();
        assert_eq!(h.prompter.shown().len(), 2);
    }

    #[test]
    fn cooldown_follows_the_live_setting_and_dismissals_and_early_approvals_deny() {
        let h = harness();
        h.service.set_cooldown(Duration::from_secs(1));
        for cause in [
            EscalationDenyCause::Dismissed,
            EscalationDenyCause::EarlyApproval,
        ] {
            let parked = park(
                h.service
                    .join_or_create(request("p", "a.example", 1))
                    .unwrap(),
            );
            h.service
                .prompt_event(&h.prompter.last_shown(), PromptEvent::Denied(cause));
            assert!(matches!(
                parked.join().unwrap(),
                EscalationOutcome::Denied { cause: got, .. } if got == cause
            ));
            assert!(h.service.in_cooldown(&request("p", "a.example", 1).key()));
            h.clock.advance(Duration::from_secs(1));
        }
        assert!(h.grants.rules.lock().unwrap().is_empty());
    }

    #[test]
    fn last_waiter_timing_out_expires_with_cooldown_and_withdraws_the_prompt() {
        let h = harness();
        let waiter = h
            .service
            .join_or_create(request("p", "a.example", 1))
            .unwrap();
        let deadline = Instant::now() + Duration::from_millis(300);
        let outcome = park_until(waiter, deadline, Arc::new(AtomicBool::new(false)))
            .join()
            .unwrap();
        assert!(matches!(outcome, EscalationOutcome::TimedOut));
        assert_eq!(h.prompter.withdrawn(), h.prompter.shown());
        assert_eq!(h.audit.last("escalation.expired")["reason"], "timeout");
        assert!(h.service.in_cooldown(&request("p", "a.example", 1).key()));
    }

    #[test]
    fn third_withdrawal_within_ten_minutes_starts_the_cooldown() {
        let h = harness();
        let key = request("p", "a.example", 1).key();
        for n in 1..=3 {
            let waiter = h
                .service
                .join_or_create(request("p", "a.example", 1))
                .unwrap();
            assert_eq!(h.prompter.shown().len(), n);
            drop(waiter);
            assert_eq!(h.prompter.withdrawn().len(), n);
            assert_eq!(h.service.in_cooldown(&key), n == 3, "after withdrawal {n}");
            h.clock.advance(Duration::from_secs(60));
        }
        assert_eq!(h.audit.count("escalation.expired"), 3);
        assert_eq!(h.audit.last("escalation.expired")["reason"], "aborted");
        assert_eq!(
            h.service
                .join_or_create(request("p", "a.example", 1))
                .unwrap_err(),
            EscalationRefusal::Cooldown
        );
    }

    #[test]
    fn withdrawals_outside_the_window_do_not_add_up() {
        let h = harness();
        let key = request("p", "a.example", 1).key();
        for _ in 0..3 {
            drop(
                h.service
                    .join_or_create(request("p", "a.example", 1))
                    .unwrap(),
            );
            h.clock.advance(Duration::from_secs(301));
        }
        assert!(!h.service.in_cooldown(&key));
    }

    #[test]
    fn an_abort_close_to_the_deadline_counts_as_a_timeout() {
        let h = harness();
        let waiter = h
            .service
            .join_or_create(request("p", "a.example", 1))
            .unwrap();
        let cancel = Arc::new(AtomicBool::new(true));
        let deadline = Instant::now() + Duration::from_secs(1);
        let outcome = park_until(waiter, deadline, cancel).join().unwrap();
        assert!(matches!(outcome, EscalationOutcome::TimedOut));
        assert_eq!(h.audit.last("escalation.expired")["reason"], "timeout");

        let waiter = h
            .service
            .join_or_create(request("p", "b.example", 1))
            .unwrap();
        let outcome = park_until(waiter, far(), Arc::new(AtomicBool::new(true)))
            .join()
            .unwrap();
        assert!(matches!(outcome, EscalationOutcome::Aborted));
        assert_eq!(h.audit.last("escalation.expired")["reason"], "aborted");
    }

    #[test]
    fn an_invalid_session_leaves_the_wait() {
        let h = harness();
        let waiter = h
            .service
            .join_or_create(request("p", "a.example", 1))
            .unwrap();
        let outcome = waiter.wait(far(), &|| false, &|| false, &mut NoPark);
        assert!(matches!(outcome, EscalationOutcome::SessionInvalid));
        assert_eq!(h.prompter.withdrawn().len(), 1);
    }

    #[test]
    fn queue_is_fifo_bounded_and_dequeues_on_last_waiter() {
        let h = harness();
        let mut waiters = Vec::new();
        // One active prompt plus MAX_QUEUED_PER_PROFILE queued keys, one session each.
        for n in 0..=MAX_QUEUED_PER_PROFILE {
            waiters.push(
                h.service
                    .join_or_create(request("p", &format!("rp{n}.example"), n))
                    .unwrap(),
            );
        }
        assert_eq!(h.prompter.shown().len(), 1);
        assert_eq!(h.service.queued(&profile("p")), MAX_QUEUED_PER_PROFILE);
        assert_eq!(
            h.service
                .join_or_create(request("p", "overflow.example", 100))
                .unwrap_err(),
            EscalationRefusal::QueueFull
        );
        // Another profile has its own slot.
        let _other = h
            .service
            .join_or_create(request("q", "rp0.example", 200))
            .unwrap();
        assert_eq!(h.prompter.shown().len(), 2);

        // The last waiter of a queued key leaves: dequeued, no prompt, audited as aborted.
        let dequeued = waiters.remove(2);
        drop(dequeued);
        assert_eq!(h.service.queued(&profile("p")), MAX_QUEUED_PER_PROFILE - 1);
        assert_eq!(h.prompter.withdrawn().len(), 0);
        assert_eq!(h.audit.count("escalation.expired"), 1);

        // Deny the active prompt: the next key in FIFO order is prompted.
        h.service.prompt_event(
            &h.prompter.shown()[0],
            PromptEvent::Denied(EscalationDenyCause::User),
        );
        let shown = h.prompter.shown.lock().unwrap().clone();
        assert_eq!(shown.len(), 3);
        assert_eq!(shown[2].1.rp_id, "rp1.example");
        h.service
            .prompt_event(&shown[2].0, PromptEvent::Denied(EscalationDenyCause::User));
        let shown = h.prompter.shown.lock().unwrap().clone();
        assert_eq!(shown[3].1.rp_id, "rp3.example", "rp2 was dequeued");
    }

    #[test]
    fn active_prompt_with_zero_waiters_is_withdrawn_and_the_next_shown() {
        let h = harness();
        let first = h
            .service
            .join_or_create(request("p", "a.example", 1))
            .unwrap();
        let _second = h
            .service
            .join_or_create(request("p", "b.example", 2))
            .unwrap();
        assert_eq!(h.prompter.shown().len(), 1);
        drop(first);
        assert_eq!(h.prompter.withdrawn(), vec![h.prompter.shown()[0].clone()]);
        assert_eq!(h.prompter.shown().len(), 2);
        assert_eq!(h.audit.last("escalation.expired")["reason"], "aborted");
        // A click on the withdrawn prompt has no effect.
        h.service
            .prompt_event(&h.prompter.shown()[0], PromptEvent::Approved);
        assert!(h.grants.rules.lock().unwrap().is_empty());
        assert_eq!(h.audit.count("escalation.approved"), 0);
    }

    #[test]
    fn waiter_caps_per_session_profile_and_global() {
        let h = harness();
        let mut held = Vec::new();
        for n in 0..MAX_WAITERS_PER_SESSION {
            held.push(
                h.service
                    .join_or_create(request("p", "a.example", 1))
                    .unwrap_or_else(|e| panic!("waiter {n}: {e:?}")),
            );
        }
        assert_eq!(
            h.service
                .join_or_create(request("p", "a.example", 1))
                .unwrap_err(),
            EscalationRefusal::WaiterCap
        );
        assert_eq!(
            h.service.precheck(&request("p", "b.example", 1)),
            Err(EscalationRefusal::WaiterCap)
        );
        // Other sessions of the profile fill it up to the profile cap.
        for session in 2..=4 {
            for _ in 0..MAX_WAITERS_PER_SESSION {
                held.push(
                    h.service
                        .join_or_create(request("p", "a.example", session))
                        .unwrap(),
                );
            }
        }
        assert_eq!(
            h.service
                .join_or_create(request("p", "a.example", 5))
                .unwrap_err(),
            EscalationRefusal::WaiterCap
        );
        // Another profile is unaffected.
        let other = h
            .service
            .join_or_create(request("q", "a.example", 6))
            .unwrap();
        drop(other);
        // Fill the global cap with profiles of 16 waiters each.
        for p in 0..3 {
            for session in 0..4 {
                for _ in 0..MAX_WAITERS_PER_SESSION {
                    held.push(
                        h.service
                            .join_or_create(request(
                                &format!("g{p}"),
                                "a.example",
                                1000 + p * 10 + session,
                            ))
                            .unwrap(),
                    );
                }
            }
        }
        assert_eq!(held.len(), MAX_WAITERS_GLOBAL);
        assert_eq!(
            h.service
                .join_or_create(request("fresh", "a.example", 9999))
                .unwrap_err(),
            EscalationRefusal::WaiterCap
        );
        held.pop();
        assert!(
            h.service
                .join_or_create(request("fresh", "a.example", 9999))
                .is_ok()
        );
    }

    #[test]
    fn grant_cap_and_disabled_store_deny_before_any_prompt() {
        let h = harness();
        let mut capped = request("p", "a.example", 1);
        capped.max_granted_rules = 0;
        assert_eq!(
            h.service.join_or_create(capped).unwrap_err(),
            EscalationRefusal::GrantCapReached
        );
        h.grants.unavailable.store(true, Ordering::SeqCst);
        assert_eq!(
            h.service
                .join_or_create(request("p", "a.example", 1))
                .unwrap_err(),
            EscalationRefusal::GrantsUnavailable
        );
        h.grants.unavailable.store(false, Ordering::SeqCst);
        h.prompter.unavailable.store(true, Ordering::SeqCst);
        assert_eq!(
            h.service
                .join_or_create(request("p", "a.example", 1))
                .unwrap_err(),
            EscalationRefusal::Unavailable
        );
        assert!(h.prompter.shown().is_empty());
        assert!(h.audit.kinds().is_empty());
        assert_eq!(
            EscalationRefusal::GrantCapReached.deny_reason(),
            PolicyDenyReason::GrantCapReached
        );
    }

    #[test]
    fn stale_or_late_tickets_are_ignored() {
        let h = harness();
        let parked = park(
            h.service
                .join_or_create(request("p", "a.example", 1))
                .unwrap(),
        );
        let ticket = h.prompter.last_shown();
        let stale = PromptTicket {
            seq: ticket.seq + 100,
            ..ticket.clone()
        };
        h.service.prompt_event(&stale, PromptEvent::Approved);
        let other = PromptTicket {
            escalation_id: EscalationId("esc-forged".to_string()),
            ..ticket.clone()
        };
        h.service.prompt_event(&other, PromptEvent::Approved);
        assert_eq!(
            h.service.state_of(&request("p", "a.example", 1).key()),
            Some(EscalationState::Prompting)
        );
        h.service
            .prompt_event(&ticket, PromptEvent::Denied(EscalationDenyCause::User));
        assert!(matches!(
            parked.join().unwrap(),
            EscalationOutcome::Denied { .. }
        ));
        // A late approval after the deny does nothing.
        h.service.prompt_event(&ticket, PromptEvent::Approved);
        assert!(h.grants.rules.lock().unwrap().is_empty());
        assert_eq!(h.audit.count("escalation.approved"), 0);
    }

    #[test]
    fn audit_failures_fail_the_escalation() {
        let h = harness();
        h.audit.fail("escalation.requested");
        assert_eq!(
            h.service
                .join_or_create(request("p", "a.example", 1))
                .unwrap_err(),
            EscalationRefusal::AuditFailure
        );
        assert!(h.prompter.shown().is_empty());
        assert_eq!(
            h.service.state_of(&request("p", "a.example", 1).key()),
            None
        );

        let h = harness();
        h.audit.fail("escalation.approved");
        let parked = park(
            h.service
                .join_or_create(request("p", "a.example", 1))
                .unwrap(),
        );
        h.service
            .prompt_event(&h.prompter.last_shown(), PromptEvent::Approved);
        match parked.join().unwrap() {
            EscalationOutcome::Denied { cause, reason, .. } => {
                assert_eq!(cause, EscalationDenyCause::AuditFailure);
                assert_eq!(reason, Some(PolicyDenyReason::AuditFailure));
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(h.grants.rules.lock().unwrap().is_empty());
    }

    #[test]
    fn store_failures_turn_the_approval_into_a_deny() {
        let h = harness();
        h.grants.fail_writes.store(true, Ordering::SeqCst);
        let parked = park(
            h.service
                .join_or_create(request("p", "a.example", 1))
                .unwrap(),
        );
        h.service
            .prompt_event(&h.prompter.last_shown(), PromptEvent::Approved);
        match parked.join().unwrap() {
            EscalationOutcome::Denied { cause, reason, .. } => {
                assert_eq!(cause, EscalationDenyCause::GrantWriteFailed);
                assert_eq!(reason, Some(PolicyDenyReason::GrantsUnavailable));
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            h.audit.last("escalation.denied")["cause"],
            "grant_write_failed"
        );
        assert_eq!(h.audit.count("granted_rule.add"), 0);
        // The prompt slot is free again.
        let _next = h
            .service
            .join_or_create(request("p", "b.example", 1))
            .unwrap();
        assert_eq!(h.prompter.shown().len(), 2);
    }

    #[test]
    fn server_lost_expires_without_cooldown_but_counts_for_v_m2() {
        let h = harness();
        let key = request("p", "a.example", 1).key();
        for n in 1..=3 {
            let parked = park(
                h.service
                    .join_or_create(request("p", "a.example", 1))
                    .unwrap(),
            );
            h.service
                .prompt_event(&h.prompter.last_shown(), PromptEvent::ServerLost);
            assert!(matches!(
                parked.join().unwrap(),
                EscalationOutcome::ServerLost { .. }
            ));
            assert_eq!(h.service.in_cooldown(&key), n == 3);
        }
        assert_eq!(h.audit.last("escalation.expired")["reason"], "server_lost");
    }

    #[test]
    fn prompt_failure_denies_as_unavailable_without_cooldown() {
        let h = harness();
        let parked = park(
            h.service
                .join_or_create(request("p", "a.example", 1))
                .unwrap(),
        );
        h.service.prompt_event(
            &h.prompter.last_shown(),
            PromptEvent::Failed("capability_rejected".to_string()),
        );
        match parked.join().unwrap() {
            EscalationOutcome::Denied { reason, .. } => {
                assert_eq!(reason, Some(PolicyDenyReason::EscalationUnavailable));
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(!h.service.in_cooldown(&request("p", "a.example", 1).key()));
    }

    #[test]
    fn cancel_profile_revokes_pending_escalations() {
        let h = harness();
        let active = park(
            h.service
                .join_or_create(request("p", "a.example", 1))
                .unwrap(),
        );
        let queued = park(
            h.service
                .join_or_create(request("p", "b.example", 2))
                .unwrap(),
        );
        let other = h
            .service
            .join_or_create(request("q", "a.example", 3))
            .unwrap();
        thread::sleep(Duration::from_millis(50));
        h.service.cancel_profile(&profile("p"));
        assert!(matches!(
            active.join().unwrap(),
            EscalationOutcome::Revoked { .. }
        ));
        assert!(matches!(
            queued.join().unwrap(),
            EscalationOutcome::Revoked { .. }
        ));
        assert_eq!(h.audit.count("escalation.revoked"), 2);
        assert_eq!(
            h.audit.last("escalation.revoked")["reason"],
            "policy_reload"
        );
        assert_eq!(h.prompter.withdrawn().len(), 1);
        assert_eq!(h.service.queued(&profile("p")), 0);
        assert_eq!(
            h.service.state_of(&request("q", "a.example", 3).key()),
            Some(EscalationState::Prompting)
        );
        drop(other);
        // The profile prompts again after the reload.
        let _again = h
            .service
            .join_or_create(request("p", "a.example", 1))
            .unwrap();
        assert_eq!(h.prompter.shown().len(), 3);
    }

    #[test]
    fn wait_suspends_and_resumes_the_park_hook() {
        struct Counting<'a>(&'a mut Vec<&'static str>);
        impl ParkHook for Counting<'_> {
            fn suspend(&mut self) {
                self.0.push("suspend");
            }
            fn resume(&mut self) {
                self.0.push("resume");
            }
        }
        let h = harness();
        let waiter = h
            .service
            .join_or_create(request("p", "a.example", 1))
            .unwrap();
        let mut calls = Vec::new();
        let outcome = waiter.wait(
            Instant::now() + Duration::from_millis(50),
            &|| false,
            &|| true,
            &mut Counting(&mut calls),
        );
        assert!(matches!(outcome, EscalationOutcome::TimedOut));
        assert_eq!(calls, ["suspend", "resume"]);
    }

    #[test]
    fn waiters_wake_on_the_decision_well_within_the_poll_interval() {
        let h = harness();
        let parked = park(
            h.service
                .join_or_create(request("p", "a.example", 1))
                .unwrap(),
        );
        thread::sleep(Duration::from_millis(20));
        let start = Instant::now();
        h.service
            .prompt_event(&h.prompter.last_shown(), PromptEvent::Approved);
        assert!(matches!(
            parked.join().unwrap(),
            EscalationOutcome::Approved { .. }
        ));
        assert!(start.elapsed() < WAIT_POLL_INTERVAL);
    }

    #[test]
    fn escalation_requested_names_the_rule_and_origin() {
        let h = harness();
        let mut wildcard = request("p", "a.example", 1);
        wildcard.rule = PermittingRule::Wildcard;
        let _waiter = h.service.join_or_create(wildcard).unwrap();
        let event = h.audit.last("escalation.requested");
        assert_eq!(event["rule"], "*");
        assert_eq!(event["origin"], "https://a.example");
        assert_eq!(event["action"], "authenticate");
        assert!(event["escalation_id"].as_str().unwrap().starts_with("esc-"));
        let parsed: AuditEvent = serde_json::from_value(event).unwrap();
        assert_eq!(parsed.kind_name(), "escalation.requested");
    }
}
