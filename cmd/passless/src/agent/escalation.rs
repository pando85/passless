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
//! - Waiters are capped per session ([`MAX_WAITERS_PER_SESSION`]) and per profile
//!   ([`MAX_WAITERS_PER_PROFILE`]); a profile at its cap never affects another. The global bound
//!   ([`MAX_WAITERS_GLOBAL`]) is a safety limit on parked threads, sized so that no realistic
//!   number of profiles reaches it.
//! - A deny or a timeout starts the key's cooldown. Withdrawals (the last waiter left, or the
//!   notification server went away) are rate-limited (V-M2): the third within
//!   [`WITHDRAWAL_WINDOW`] starts the cooldown too. The cooldown map never evicts a live cooldown
//!   (review L1): when it is full, new escalations are refused
//!   ([`EscalationRefusal::TrackingFull`]) instead.
//! - When the last waiter leaves, a queued entry is dequeued and an active prompt is withdrawn at
//!   once; `escalation.expired` is recorded with `reason = aborted` (or `timeout`).
//! - Registration through the `*` rule (ADR 0014 amendment section 2.2) has three more
//!   pre-checks, each refusing without a prompt: the profile's wildcard registration grants plus
//!   its live wildcard registration escalations reach `max_wildcard_registrations`
//!   ([`EscalationRefusal::WildcardRegistrationCap`]); the profile's wildcard registration prompts
//!   shown in the last [`WILDCARD_PROMPT_WINDOW`] plus those queued reach
//!   `wildcard_registration_prompts_per_day` ([`EscalationRefusal::WildcardRegistrationRate`]); a
//!   profile-wide cooldown, started with the per-key cooldown of any wildcard registration
//!   escalation (deny, timeout, or the third withdrawal) and as long
//!   ([`EscalationRefusal::WildcardRegistrationCooldown`]). Exact-rule registrations are not
//!   affected by any of them. The window and the cooldown are in memory: a restart resets them.
//!
//! Locking: one mutex at [`LockLevel::Escalation`], a leaf. No audit, store, prompt or D-Bus call
//! happens under it: state changes are made under the mutex and their effects (audit records,
//! prompt show and withdraw) are run after it is released. Waiters park on its condvar holding
//! nothing else, and call their `cancelled`/`still_valid` checks with the mutex released.
//!
//! Approval protocol: under the mutex the decision must match the active ticket of an entry that
//! is still `Prompting`; it becomes `Deciding`. With the mutex released, and under an unwind guard
//! that finishes the entry as denied if anything panics:
//!
//! 1. `escalation.approved` is audited;
//! 2. for `authenticate`, `granted_rule.add` is audited, before the store write;
//! 3. the entry is re-checked under the mutex: a reload or a grant clear that cancelled it while it
//!    was `Deciding` stands, and nothing is written;
//! 4. the grant is persisted (which bumps the grant epoch);
//! 5. the entry becomes `Approved` under the mutex and the waiters are woken. If a cancellation
//!    got in between 3 and 5, the grant just written is revoked again (compensation) and the
//!    revocation is audited as `granted_rule.revoke`.
//!
//! A failed audit or store write turns the approval into a deny. A registration approval persists
//! nothing here: the creating ceremony persists the grant after the credential is written
//! ([`EscalationService::record_registration_grant`], which also audits before it writes).

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use log::{debug, info, warn};
use rand::RngCore;

use passless_core::agent::{AgentMode, CredentialRef, ProfileId};

use super::audit::AuditGate;
use super::audit_events::{
    AuditAction, AuditEvent, EscalationAuditContext, EscalationDenyCause, EscalationExpireReason,
    EscalationRevokeReason, GrantedRuleAddBuilder, GrantedRuleRevokeBuilder, PolicyDenyReason,
};
use super::escalation_prompt::{PromptFields, PromptRule, PromptVerb};
use super::granted_rules::{
    GrantKind, GrantStoreError, GrantedRule, GrantedRulesStore, PermittingRule, ProfileGrants,
    RevokeToken, wildcard_registration_count,
};
use super::identity::{MonotonicClock, MonotonicTime};
use super::lock_order::{self, LockLevel, Tracked};
use super::policy_engine::PolicyRuntime;
use super::session::{AgentSession, CeremonyAction};

/// Keys that may wait behind a profile's active prompt.
pub const MAX_QUEUED_PER_PROFILE: usize = 8;
/// Escalation waiters per bearer session.
pub const MAX_WAITERS_PER_SESSION: usize = 4;
/// Escalation waiters per profile. This is the cap that isolates profiles from each other
/// (ADR 0014 section 8.2: a profile at its cap leaves other profiles unaffected).
pub const MAX_WAITERS_PER_PROFILE: usize = 16;
/// Escalation waiters in the whole daemon: a safety bound on the parked ceremony threads, not a
/// fairness limit. It is 64 times [`MAX_WAITERS_PER_PROFILE`], so one profile (or a few) can never
/// starve another of waiters; it is reached only if 64 profiles are each saturated at once.
pub const MAX_WAITERS_GLOBAL: usize = 1024;
/// The V-M2 window: the third withdrawal of a key within it starts the key's cooldown.
pub const WITHDRAWAL_WINDOW: Duration = Duration::from_secs(600);
/// Withdrawals within [`WITHDRAWAL_WINDOW`] that start the cooldown.
pub const WITHDRAWALS_BEFORE_COOLDOWN: usize = 3;
/// Keys each of the cooldown and withdrawal maps tracks. The withdrawal map evicts its oldest
/// entry beyond it. The cooldown map never evicts a live cooldown (a human's deny must hold):
/// when live cooldowns plus live escalations reach it, new escalations are refused. No profile
/// may hold more than [`MAX_TRACKED_KEYS_PER_PROFILE`] of them, so the global bound is a backstop.
pub const MAX_TRACKED_KEYS: usize = 4096;
/// Live cooldowns plus live escalations one profile may hold. A profile at its quota is refused
/// alone (`escalation_tracking_full`), so a hostile page behind a broad `request` rule cannot
/// fill the shared table and starve other profiles (review M-e). The global [`MAX_TRACKED_KEYS`]
/// stays as a backstop; it is 16 times this quota.
pub const MAX_TRACKED_KEYS_PER_PROFILE: usize = 256;
/// Longest a waiter parks before it re-checks its cancellation, deadline and session.
pub const WAIT_POLL_INTERVAL: Duration = Duration::from_millis(250);
/// An abort this close to the deadline counts as a timeout (Chromium's cancel and the daemon's
/// deadline race; plan P7 gap 8).
pub const DEADLINE_ABORT_GRACE: Duration = Duration::from_secs(2);
/// The rolling window of `wildcard_registration_prompts_per_day` (ADR 0014 amendment 2.2 item 5).
pub const WILDCARD_PROMPT_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

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
    /// The profile's live `max_wildcard_registrations` (read for a wildcard registration only).
    pub max_wildcard_registrations: usize,
    /// The profile's live `wildcard_registration_prompts_per_day` (likewise).
    pub wildcard_registration_prompts_per_day: usize,
    /// Registration only: the target store's passkey count for the RP, read from the backend's
    /// index before the escalation was raised. Shown to the human only, never to the agent.
    pub store_count: Option<usize>,
}

impl EscalationRequest {
    /// A registration that resolved through the `*` rule (ADR 0014 amendment section 2.2).
    pub fn is_wildcard_registration(&self) -> bool {
        self.action == CeremonyAction::Register && self.rule == PermittingRule::Wildcard
    }

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
            rule: match self.rule {
                PermittingRule::Exact => PromptRule::Exact,
                PermittingRule::Wildcard => PromptRule::Wildcard,
            },
            store_count: match self.action {
                CeremonyAction::Register => self.store_count,
                CeremonyAction::Authenticate => None,
            },
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
    /// The cooldown table is full of live cooldowns (review L1): no new escalation is admitted
    /// until one expires, so that no live cooldown is ever evicted.
    TrackingFull,
    /// A registration escalation for the key is already pending.
    Busy,
    /// The profile holds `max_granted_rules` grants.
    GrantCapReached,
    /// The profile's granted-rules store is disabled.
    GrantsUnavailable,
    /// The `escalation.requested` record could not be written.
    AuditFailure,
    /// A wildcard registration: the profile is at `max_wildcard_registrations`.
    WildcardRegistrationCap,
    /// A wildcard registration: the profile used its `wildcard_registration_prompts_per_day`.
    WildcardRegistrationRate,
    /// A wildcard registration: the profile-wide wildcard registration cooldown is running.
    WildcardRegistrationCooldown,
}

impl EscalationRefusal {
    pub fn deny_reason(self) -> PolicyDenyReason {
        match self {
            Self::Unavailable => PolicyDenyReason::EscalationUnavailable,
            Self::Cooldown => PolicyDenyReason::EscalationCooldown,
            Self::QueueFull => PolicyDenyReason::EscalationQueueFull,
            Self::WaiterCap => PolicyDenyReason::EscalationWaiterCap,
            Self::TrackingFull => PolicyDenyReason::EscalationTrackingFull,
            Self::Busy => PolicyDenyReason::EscalationBusy,
            Self::GrantCapReached => PolicyDenyReason::GrantCapReached,
            Self::GrantsUnavailable => PolicyDenyReason::GrantsUnavailable,
            Self::AuditFailure => PolicyDenyReason::AuditFailure,
            Self::WildcardRegistrationCap => PolicyDenyReason::WildcardRegistrationCap,
            Self::WildcardRegistrationRate => PolicyDenyReason::WildcardRegistrationRate,
            Self::WildcardRegistrationCooldown => PolicyDenyReason::WildcardRegistrationCooldown,
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
    /// The RP's revocation generation when the escalation was raised: the grant is persisted
    /// only if no `grants revoke` or `grants clear` happened since (review M-c).
    revoke_token: Option<RevokeToken>,
    /// For a registration through `*`: the cap slot held from the approval until the grant write
    /// returns (review L2). Released when the approval is dropped, whatever the ceremony does.
    reservation: Option<WildcardReservation>,
}

/// A wildcard registration cap slot held between an approval and the write of its grant (review
/// L2). The approval turns its escalation terminal at once, but the grant is written only after
/// the credential exists (with `pass`: after GPG, a commit and a push); without this slot the
/// registration would count as neither live nor stored in between, and a second wildcard
/// registration would be admitted and prompted at the cap. Dropping it releases the slot, so a
/// failed, aborted or panicking ceremony cannot leak one.
///
/// The release bumps `epoch` before it lowers the count. A check that read the stored grants
/// before the release and the count after it sees the epoch moved and adds the releases to the
/// stored count (an over-estimate: safe), so no interleaving lets a grant that was just written
/// go uncounted.
#[derive(Debug)]
struct WildcardReservation {
    held: Arc<AtomicUsize>,
    epoch: Arc<AtomicU64>,
    released: AtomicBool,
}

impl WildcardReservation {
    fn release(&self) {
        if !self.released.swap(true, Ordering::SeqCst) {
            self.epoch.fetch_add(1, Ordering::SeqCst);
            self.held.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl Drop for WildcardReservation {
    fn drop(&mut self) {
        self.release();
    }
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
    Available {
        used: usize,
        /// Of those, the wildcard registration grants (`kind = "registration"`, `rule = "*"`).
        wildcard_registrations: usize,
    },
    Unavailable,
}

/// Persists granted rules. Called without the escalation mutex.
pub trait GrantWriter: Send + Sync {
    fn capacity(&self, profile: &ProfileId) -> GrantCapacity;
    /// The RP's revocation generation now ([`GrantedRulesStore::revoke_token`]); `None` when the
    /// store cannot say (it is disabled, and every write fails anyway).
    fn revoke_token(&self, _profile: &ProfileId, _rp_id: &str) -> Option<RevokeToken> {
        None
    }
    /// Persist `rule` and bump the grant epoch; refused with [`GrantStoreError::Revoked`] when
    /// `token` is stale ([`GrantedRulesStore::add_unless_revoked`]), and with
    /// [`GrantStoreError::WildcardCapReached`] when `wildcard_cap` is given and the profile
    /// already holds that many wildcard registration grants.
    fn add(
        &self,
        profile: &ProfileId,
        rule: GrantedRule,
        max_rules: usize,
        token: Option<RevokeToken>,
        wildcard_cap: Option<usize>,
    ) -> Result<(), GrantStoreError>;
    /// Remove what the escalation `request_id` persisted and bump the revocation epoch (the
    /// compensation of an approval a reload or a clear overtook). Returns the rules removed;
    /// `Ok(0)` or `NotFound` when it persisted nothing.
    fn revoke_request(
        &self,
        profile: &ProfileId,
        request_id: &str,
    ) -> Result<usize, GrantStoreError>;
}

/// The production [`GrantWriter`]: the granted-rules store, bumping the policy's grant epoch.
pub struct StoreGrantWriter {
    pub store: Arc<GrantedRulesStore>,
    pub policy: Arc<PolicyRuntime>,
}

impl GrantWriter for StoreGrantWriter {
    fn capacity(&self, profile: &ProfileId) -> GrantCapacity {
        match self.store.profile(profile).as_deref() {
            Some(ProfileGrants::Enabled(rules)) => GrantCapacity::Available {
                used: rules.len(),
                wildcard_registrations: wildcard_registration_count(rules),
            },
            Some(ProfileGrants::Disabled(_)) | None => GrantCapacity::Unavailable,
        }
    }

    fn revoke_token(&self, profile: &ProfileId, rp_id: &str) -> Option<RevokeToken> {
        self.store.revoke_token(profile, rp_id).ok()
    }

    fn add(
        &self,
        profile: &ProfileId,
        rule: GrantedRule,
        max_rules: usize,
        token: Option<RevokeToken>,
        wildcard_cap: Option<usize>,
    ) -> Result<(), GrantStoreError> {
        self.store
            .add_with_wildcard_cap(&self.policy, profile, rule, max_rules, token, wildcard_cap)
            .map(|_| ())
    }

    fn revoke_request(
        &self,
        profile: &ProfileId,
        request_id: &str,
    ) -> Result<usize, GrantStoreError> {
        match self.store.revoke_request(&self.policy, profile, request_id) {
            Ok(outcome) => Ok(outcome.revoked),
            Err(GrantStoreError::NotFound) => Ok(0),
            Err(e) => Err(e),
        }
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
    /// The RP's revocation generation captured before the entry was created (review M-c, M-d).
    revoke_token: Option<RevokeToken>,
}

impl Entry {
    fn audit_context(&self) -> EscalationAuditContext {
        EscalationAuditContext {
            escalation_id: self.id.as_str().to_string(),
            profile_id: self.request.profile.clone(),
            action: self.request.audit_action(),
            rp_id: self.request.rp_id.clone(),
            origin: self.request.origin.clone(),
            rule: self.request.rule,
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
    /// End of the profile-wide wildcard registration cooldown, per profile (amendment 2.2
    /// item 6). One entry per configured profile at most.
    wildcard_cooldown: HashMap<ProfileId, MonotonicTime>,
    /// When each wildcard registration prompt of the last [`WILDCARD_PROMPT_WINDOW`] was shown,
    /// per profile (item 5). Bounded by the profile's `wildcard_registration_prompts_per_day`
    /// (at most 24): a prompt is only shown after the admission check against it.
    wildcard_prompts: HashMap<ProfileId, VecDeque<MonotonicTime>>,
    /// Cap slots held by approved wildcard registrations whose grant is not written yet, per
    /// profile (review L2). One entry per configured profile at most.
    wildcard_reserved: HashMap<ProfileId, Arc<AtomicUsize>>,
    /// Counts reservation releases (see [`WildcardReservation`]).
    reservation_epoch: Arc<AtomicU64>,
    next_serial: u64,
    next_waiter: u64,
    next_ticket: u64,
}

/// The profile's stored wildcard registration grants as read by a check, with the reservation
/// epoch read before them (see [`WildcardReservation`]).
#[derive(Clone, Copy, Debug)]
struct StoredWildcards {
    count: usize,
    epoch: u64,
}

#[cfg(test)]
impl StoredWildcards {
    /// Nothing stored, read before any reservation was released.
    const NONE: Self = Self { count: 0, epoch: 0 };
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

    /// Start the cooldown of `request`'s key and, for a wildcard registration, the profile-wide
    /// wildcard registration cooldown of the same length (amendment 2.2 item 6).
    fn start_cooldowns(
        &mut self,
        request: &EscalationRequest,
        now: MonotonicTime,
        cooldown: Duration,
    ) {
        self.start_cooldown(&request.key(), now, cooldown);
        if request.is_wildcard_registration() {
            self.start_wildcard_cooldown(&request.profile, now, cooldown);
        }
    }

    fn start_wildcard_cooldown(
        &mut self,
        profile: &ProfileId,
        now: MonotonicTime,
        cooldown: Duration,
    ) {
        info!(
            "escalation: wildcard registrations of profile '{}' are in cooldown for {:?}",
            profile, cooldown
        );
        let until = later(now, cooldown);
        let entry = self
            .wildcard_cooldown
            .entry(profile.clone())
            .or_insert(until);
        if *entry < until {
            *entry = until;
        }
    }

    fn in_wildcard_cooldown(&mut self, profile: &ProfileId, now: MonotonicTime) -> bool {
        match self.wildcard_cooldown.get(profile) {
            Some(until) if now < *until => true,
            Some(_) => {
                self.wildcard_cooldown.remove(profile);
                false
            }
            None => false,
        }
    }

    /// Wildcard registration prompts of `profile` shown within the window (expired ones pruned).
    fn wildcard_prompts_shown(&mut self, profile: &ProfileId, now: MonotonicTime) -> usize {
        let window = u64::try_from(WILDCARD_PROMPT_WINDOW.as_millis()).unwrap_or(u64::MAX);
        let Some(shown) = self.wildcard_prompts.get_mut(profile) else {
            return 0;
        };
        while shown
            .front()
            .is_some_and(|at| now.saturating_duration_since(*at) >= window)
        {
            shown.pop_front();
        }
        let count = shown.len();
        if count == 0 {
            self.wildcard_prompts.remove(profile);
        }
        count
    }

    /// Take a cap slot for an approved wildcard registration of `profile` (review L2).
    fn reserve_wildcard(&mut self, profile: &ProfileId) -> WildcardReservation {
        let held = self.wildcard_reserved.entry(profile.clone()).or_default();
        held.fetch_add(1, Ordering::SeqCst);
        WildcardReservation {
            held: Arc::clone(held),
            epoch: Arc::clone(&self.reservation_epoch),
            released: AtomicBool::new(false),
        }
    }

    fn reserved_wildcards(&self, profile: &ProfileId) -> usize {
        self.wildcard_reserved
            .get(profile)
            .map_or(0, |held| held.load(Ordering::SeqCst))
    }

    /// The profile's wildcard registrations that hold a cap slot but are not stored: the live
    /// escalations plus the approved ones whose grant is pending. Returns `(all, not yet shown)`.
    fn live_wildcard_registrations(&self, profile: &ProfileId) -> (usize, usize) {
        let (live, unshown) = self.live_wildcard_escalations(profile);
        (
            live.saturating_add(self.reserved_wildcards(profile)),
            unshown,
        )
    }

    /// The profile's live wildcard registration escalations: `(all, not yet shown)`.
    fn live_wildcard_escalations(&self, profile: &ProfileId) -> (usize, usize) {
        self.entries
            .values()
            .filter(|entry| {
                entry.request.profile == *profile
                    && entry.request.is_wildcard_registration()
                    && !entry.state.is_terminal()
            })
            .fold((0, 0), |(all, unshown), entry| {
                (
                    all + 1,
                    unshown + usize::from(entry.state == EscalationState::Queued),
                )
            })
    }

    /// The wildcard registration pre-checks of `request` (amendment 2.2 items 4 to 6), in the
    /// amendment's order: cap, daily limit, profile-wide cooldown. `persisted` is the profile's
    /// stored wildcard registration grants. Anything but a wildcard registration passes.
    fn check_wildcard_registration(
        &mut self,
        request: &EscalationRequest,
        stored: StoredWildcards,
        now: MonotonicTime,
    ) -> Result<(), EscalationRefusal> {
        if !request.is_wildcard_registration() {
            return Ok(());
        }
        let (live, unshown) = self.live_wildcard_registrations(&request.profile);
        // Read after the count above: a reservation released since `stored` was read may have
        // written its grant after that read, so each such release counts as one more stored
        // grant (over-counting is safe; review L2).
        let released = self
            .reservation_epoch
            .load(Ordering::SeqCst)
            .saturating_sub(stored.epoch);
        let persisted = stored
            .count
            .saturating_add(usize::try_from(released).unwrap_or(usize::MAX));
        // A pending escalation, or an approved registration whose grant is not written yet, may
        // still end in a grant, so each holds a slot of the cap.
        if persisted.saturating_add(live) >= request.max_wildcard_registrations {
            return Err(EscalationRefusal::WildcardRegistrationCap);
        }
        // A queued escalation will show a prompt when it reaches the front: count it now, so the
        // limit can never be exceeded by prompts admitted together.
        let shown = self.wildcard_prompts_shown(&request.profile, now);
        if shown.saturating_add(unshown) >= request.wildcard_registration_prompts_per_day {
            return Err(EscalationRefusal::WildcardRegistrationRate);
        }
        if self.in_wildcard_cooldown(&request.profile, now) {
            return Err(EscalationRefusal::WildcardRegistrationCooldown);
        }
        Ok(())
    }

    fn start_cooldown(&mut self, key: &EscalationKey, now: MonotonicTime, cooldown: Duration) {
        self.withdrawals.remove(key);
        // Prune on every insert, so the map holds live cooldowns only. A live cooldown is never
        // evicted (review L1): an agent with a broad `request` rule could otherwise push out the
        // cooldown a human's deny just set. The size is bounded at admission instead (`admit`
        // refuses a new escalation while live cooldowns plus live escalations fill the table),
        // and a cooldown only ever starts for a key that has a live escalation, so this insert
        // always has room.
        self.cooldown.retain(|_, until| now < *until);
        self.cooldown.insert(key.clone(), later(now, cooldown));
    }

    /// Whether `profile` has no room for another escalation: its own live cooldowns plus a slot
    /// for each of its live escalations (which may end in a cooldown) reach
    /// [`MAX_TRACKED_KEYS_PER_PROFILE`], or the same count over all profiles reaches the
    /// [`MAX_TRACKED_KEYS`] backstop. Expired cooldowns are pruned first, so an entry that ran
    /// out frees its slot; a live one is never evicted. Only the profile at its quota is refused.
    fn tracking_full(&mut self, profile: &ProfileId, now: MonotonicTime) -> bool {
        if !self.tracking_reached(profile) {
            return false;
        }
        self.cooldown.retain(|_, until| now < *until);
        self.tracking_reached(profile)
    }

    fn tracking_reached(&self, profile: &ProfileId) -> bool {
        let total = self.cooldown.len() + self.by_key.len();
        let own = self
            .cooldown
            .keys()
            .filter(|k| &k.profile == profile)
            .count()
            + self.by_key.keys().filter(|k| &k.profile == profile).count();
        own >= MAX_TRACKED_KEYS_PER_PROFILE || total >= MAX_TRACKED_KEYS
    }

    /// Count a withdrawal of `request`'s key (V-M2); the third within the window starts the
    /// cooldowns ([`Self::start_cooldowns`]), the profile-wide one included.
    fn record_withdrawal_of(
        &mut self,
        request: &EscalationRequest,
        now: MonotonicTime,
        cooldown: Duration,
    ) {
        if self.record_withdrawal(&request.key(), now, cooldown)
            && request.is_wildcard_registration()
        {
            self.start_wildcard_cooldown(&request.profile, now, cooldown);
        }
    }

    /// Count a withdrawal of `key` (V-M2); the third within the window starts the cooldown.
    /// Returns whether it did.
    fn record_withdrawal(
        &mut self,
        key: &EscalationKey,
        now: MonotonicTime,
        cooldown: Duration,
    ) -> bool {
        let window = u64::try_from(WITHDRAWAL_WINDOW.as_millis()).unwrap_or(u64::MAX);
        // Prune on every insert, so the map holds keys with a withdrawal inside the window only,
        // then cap it.
        self.withdrawals.retain(|_, recent| {
            recent.retain(|at| now.saturating_duration_since(*at) < window);
            !recent.is_empty()
        });
        if !self.withdrawals.contains_key(key) && self.withdrawals.len() >= MAX_TRACKED_KEYS {
            // Nothing is expired after the prune: the key whose latest withdrawal is oldest goes.
            let oldest = self
                .withdrawals
                .iter()
                .min_by_key(|(_, recent)| recent.back().copied())
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                self.withdrawals.remove(&oldest);
            }
        }
        let recent = self.withdrawals.entry(key.clone()).or_default();
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
            return true;
        }
        false
    }

    /// The per-session and per-profile caps (ADR 0014 section 8.2: a profile at its cap does not
    /// affect another) and the global safety bound, which is far above what the per-profile caps
    /// of a realistic number of profiles add up to.
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
    /// `stored` is the profile's stored wildcard registration grants.
    fn admit(
        &mut self,
        request: &EscalationRequest,
        key: &EscalationKey,
        now: MonotonicTime,
        stored: StoredWildcards,
    ) -> Result<Option<u64>, EscalationRefusal> {
        if self.in_cooldown(key, now) {
            return Err(EscalationRefusal::Cooldown);
        }
        self.check_wildcard_registration(request, stored, now)?;
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
        // A new escalation may end in a cooldown: refuse it while its profile's share of the table
        // (or the table) is full of live ones rather than evict one (reviews L1, M-e).
        if self.tracking_full(&request.profile, now) {
            return Err(EscalationRefusal::TrackingFull);
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
            if entry.request.is_wildcard_registration() {
                // Counted when shown (amendment 2.2 item 5).
                self.wildcard_prompts
                    .entry(profile.clone())
                    .or_default()
                    .push_back(now);
            }
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

    /// The checks made without the mutex (the wildcard ones take it briefly): the wildcard
    /// registration limits first (amendment section 2.3 order), then the grant store and prompt
    /// availability. Returns the profile's stored wildcard registration grants, which admission
    /// checks again under the mutex.
    fn check_resources(
        &self,
        request: &EscalationRequest,
    ) -> Result<StoredWildcards, EscalationRefusal> {
        // Before the store is read (see `WildcardReservation`).
        let epoch = self.lock().reservation_epoch.load(Ordering::SeqCst);
        let capacity = self.grants.capacity(&request.profile);
        let wildcard_persisted = match capacity {
            GrantCapacity::Available {
                wildcard_registrations,
                ..
            } => wildcard_registrations,
            GrantCapacity::Unavailable => 0,
        };
        let stored = StoredWildcards {
            count: wildcard_persisted,
            epoch,
        };
        if request.is_wildcard_registration() {
            // An unreadable store cannot be counted: refuse rather than assume zero.
            if capacity == GrantCapacity::Unavailable {
                return Err(EscalationRefusal::GrantsUnavailable);
            }
            let now = self.clock.now();
            self.lock()
                .check_wildcard_registration(request, stored, now)?;
        }
        match capacity {
            GrantCapacity::Unavailable => return Err(EscalationRefusal::GrantsUnavailable),
            GrantCapacity::Available { used, .. } if used >= request.max_granted_rules => {
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
        Ok(stored)
    }

    /// Whether `request` would be admitted now: cooldown, the wildcard registration limits,
    /// grant cap and store, bus, queue, waiter caps and a pending registration duplicate. Changes
    /// nothing; [`Self::join_or_create`] repeats every check atomically.
    pub fn precheck(&self, request: &EscalationRequest) -> Result<(), EscalationRefusal> {
        let key = request.key();
        if self.lock().in_cooldown(&key, self.clock.now()) {
            return Err(EscalationRefusal::Cooldown);
        }
        let stored = self.check_resources(request)?;
        self.lock()
            .admit(request, &key, self.clock.now(), stored)
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
        let stored = self.check_resources(&request)?;
        // Before the entry exists, with no lock held (the grant writer, LOCKING.md rank 64): a
        // revocation from here on makes this escalation's approval persist nothing.
        let revoke_token = self.grants.revoke_token(&request.profile, &request.rp_id);

        let now = self.clock.now();
        let (waiter, announcement) = {
            let mut inner = self.lock();
            match inner.admit(&request, &key, now, stored)? {
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
                        revoke_token,
                    };
                    let announcement = entry.audit_context().requested();
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
                let request = entry.request.clone();
                let profile = request.profile.clone();
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
                    Departure::Timeout => inner.start_cooldowns(&request, now, cooldown),
                    Departure::Aborted => inner.record_withdrawal_of(&request, now, cooldown),
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
            let request = entry.request.clone();
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
                inner.start_cooldowns(&request, now, cooldown);
            }
            if withdrawn {
                inner.record_withdrawal_of(&request, now, cooldown);
            }
            inner.pump(&request.profile, now, &mut effects);
            inner.collect(serial);
            self.changed.notify_all();
        }
        self.run(effects);
    }

    /// The approval protocol (module documentation).
    fn approve(&self, ticket: &PromptTicket) {
        let now = self.clock.now();
        let (serial, request, escalation_id, context, latency_ms, revoke_token) = {
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
                entry.revoke_token,
            )
        };

        // From here until the entry is finished, a panic must not leave it `Deciding`.
        let mut guard = DecidingGuard {
            service: self,
            serial,
            context: context.clone(),
            cause: EscalationDenyCause::AuditFailure,
            reason: PolicyDenyReason::AuditFailure,
            armed: true,
        };
        let settled = self.settle_approval(
            &mut guard,
            &request,
            &escalation_id,
            latency_ms,
            revoke_token,
        );
        guard.armed = false;
        let committed = self.finish_deciding(serial, settled.outcome, settled.audit);
        if !committed && settled.grant_written {
            self.compensate_grant(&request, &escalation_id);
        }
    }

    /// Steps 1 to 4 of the approval protocol: the audit records and the grant write. The returned
    /// outcome is published by [`Self::finish_deciding`].
    fn settle_approval(
        &self,
        guard: &mut DecidingGuard<'_>,
        request: &EscalationRequest,
        escalation_id: &EscalationId,
        latency_ms: u64,
        revoke_token: Option<RevokeToken>,
    ) -> Settled {
        let context = guard.context.clone();
        let denied = |cause: EscalationDenyCause, reason: PolicyDenyReason| Settled {
            outcome: EntryOutcome::Denied {
                cause,
                reason: Some(reason),
            },
            audit: Some(context.denied(cause)),
            grant_written: false,
        };

        if let Err(e) = self.audit.record(context.approved(latency_ms)) {
            warn!(
                "escalation {}: escalation.approved could not be audited, denying: {}",
                escalation_id, e
            );
            return denied(
                EscalationDenyCause::AuditFailure,
                PolicyDenyReason::AuditFailure,
            );
        }

        if request.action == CeremonyAction::Register {
            info!(
                "escalation {}: registration approved for {}/{}",
                escalation_id, request.profile, request.rp_id
            );
            // The entry turns terminal when this outcome is published, but its grant is written
            // only after the credential exists: hold the cap slot meanwhile (review L2). Taken
            // while the entry is still `Deciding`, so the slot is never uncounted.
            let reservation = request
                .is_wildcard_registration()
                .then(|| self.lock().reserve_wildcard(&request.profile));
            return Settled {
                outcome: EntryOutcome::Registration(Some(RegistrationApproval {
                    escalation_id: escalation_id.clone(),
                    profile: request.profile.clone(),
                    rp_id: request.rp_id.clone(),
                    origin: request.origin.clone(),
                    rule: request.rule,
                    session: request.session,
                    revoke_token,
                    reservation,
                })),
                audit: None,
                grant_written: false,
            };
        }

        // The audit record comes before the store write: a grant is never persisted without its
        // record. If this write fails the approval is denied; if the store write then fails, the
        // `escalation.denied` record follows this one.
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
                "escalation {}: granted_rule.add could not be audited, denying: {}",
                escalation_id, e
            );
            return denied(
                EscalationDenyCause::AuditFailure,
                PolicyDenyReason::AuditFailure,
            );
        }

        // A reload or a grant clear may have cancelled the entry while it was `Deciding`: the
        // revocation stands, so nothing is written. (A cancellation after this check is caught by
        // the compensation in `approve`.)
        if !self.is_deciding(guard.serial) {
            info!(
                "escalation {}: cancelled while deciding; no grant is written",
                escalation_id
            );
            return Settled {
                outcome: EntryOutcome::Revoked,
                audit: None,
                grant_written: false,
            };
        }

        guard.cause = EscalationDenyCause::GrantWriteFailed;
        guard.reason = PolicyDenyReason::GrantsUnavailable;
        let rule = GrantedRule::new(
            &request.rp_id,
            GrantKind::Escalation,
            escalation_id.as_str(),
            &request.origin,
            request.rule,
            None,
        );
        match self.grants.add(
            &request.profile,
            rule,
            request.max_granted_rules,
            revoke_token,
            None,
        ) {
            Err(GrantStoreError::Revoked) => {
                // `grants revoke` or `grants clear` ran after the escalation was raised and before
                // its cancel reached this entry (review M-d): the revocation stands.
                info!(
                    "escalation {}: the RP was revoked meanwhile; no grant is written",
                    escalation_id
                );
                Settled {
                    outcome: EntryOutcome::Revoked,
                    audit: Some(context.revoked(EscalationRevokeReason::PolicyReload)),
                    grant_written: false,
                }
            }
            Ok(()) => {
                info!(
                    "escalation {}: approved; {}/{} granted",
                    escalation_id, request.profile, request.rp_id
                );
                Settled {
                    outcome: EntryOutcome::Approved,
                    audit: None,
                    grant_written: true,
                }
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
                denied(EscalationDenyCause::GrantWriteFailed, reason)
            }
        }
    }

    /// Whether `serial` is still `Deciding` (not cancelled by a reload or a clear).
    fn is_deciding(&self, serial: u64) -> bool {
        self.lock()
            .entries
            .get(&serial)
            .is_some_and(|entry| entry.state == EscalationState::Deciding)
    }

    /// Revoke the grant of `escalation_id` that was written while a reload or a grant clear
    /// cancelled its entry, and audit the revocation. The entry itself stays `Revoked`.
    fn compensate_grant(&self, request: &EscalationRequest, escalation_id: &EscalationId) {
        match self
            .grants
            .revoke_request(&request.profile, escalation_id.as_str())
        {
            Ok(revoked) => {
                info!(
                    "escalation {}: cancelled while its grant was written; {} grant(s) revoked",
                    escalation_id, revoked
                );
                let event = GrantedRuleRevokeBuilder::new(
                    request.profile.clone(),
                    Some(request.rp_id.clone()),
                    revoked,
                )
                .build();
                if let Err(e) = self.audit.record(event) {
                    warn!(
                        "escalation {}: granted_rule.revoke could not be audited: {}",
                        escalation_id, e
                    );
                }
            }
            Err(e) => warn!(
                "escalation {}: cancelled while its grant was written, and the grant could not \
                 be revoked again; revoke it with the granted-rules CLI: {}",
                escalation_id, e
            ),
        }
    }

    /// Step 5 of the approval protocol (or its deny). Returns whether the entry was still
    /// `Deciding` and took `outcome`; `false` when a reload or a clear cancelled it meanwhile (the
    /// cancellation stands).
    fn finish_deciding(
        &self,
        serial: u64,
        outcome: EntryOutcome,
        audit: Option<AuditEvent>,
    ) -> bool {
        let now = self.clock.now();
        let mut effects = Vec::new();
        if let Some(event) = audit {
            effects.push(Effect::Audit(event));
        }
        let committed = {
            let mut inner = self.lock();
            let Some(entry) = inner.entries.get_mut(&serial) else {
                drop(inner);
                self.run(effects);
                return false;
            };
            if entry.state != EscalationState::Deciding {
                // Revoked by a reload while the approval was written; the revocation stands.
                inner.collect(serial);
                drop(inner);
                self.run(effects);
                return false;
            }
            entry.state = match outcome {
                EntryOutcome::Approved | EntryOutcome::Registration(_) => EscalationState::Approved,
                EntryOutcome::Revoked => EscalationState::Revoked,
                _ => EscalationState::Denied,
            };
            entry.outcome = Some(outcome);
            let profile = entry.request.profile.clone();
            inner.unlink(serial);
            inner.pump(&profile, now, &mut effects);
            inner.collect(serial);
            self.changed.notify_all();
            true
        };
        self.run(effects);
        committed
    }

    /// Cancel every pending escalation of `profile` after a reload changed the policy. Each is
    /// recorded as `escalation.revoked` with `reason = policy_reload`; their waiters see
    /// [`EscalationOutcome::Revoked`].
    pub fn cancel_profile(&self, profile: &ProfileId) {
        self.cancel_where(profile, |_| true);
    }

    /// Cancel every pending escalation of `profile` for `rp_id` (any action) after `grants revoke`
    /// removed its granted rule, so a late approval cannot persist the grant again (review L2).
    /// Recorded and observed like [`Self::cancel_profile`]; the profile's other escalations stay,
    /// and a queued one is prompted if the cancelled one held the prompt.
    pub fn cancel_rp(&self, profile: &ProfileId, rp_id: &str) {
        self.cancel_where(profile, |request| request.rp_id == rp_id);
    }

    fn cancel_where(&self, profile: &ProfileId, matches: impl Fn(&EscalationRequest) -> bool) {
        let mut effects = Vec::new();
        {
            let mut inner = self.lock();
            let serials: Vec<u64> = inner
                .entries
                .iter()
                .filter(|(_, entry)| {
                    entry.request.profile == *profile
                        && matches(&entry.request)
                        && !entry.state.is_terminal()
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
                info!("escalation {}: revoked by a policy change", entry.id);
                inner.unlink(serial);
                inner.collect(serial);
            }
            // The profile's remaining queued escalations (a `cancel_rp` leaves them) get the
            // prompt slot; after a whole-profile cancel the queue is empty and this does nothing.
            inner.pump(profile, self.clock.now(), &mut effects);
            self.changed.notify_all();
        }
        self.run(effects);
    }

    /// Persist the grant of an approved registration after its credential was written (ADR 0014
    /// section 8.3), bump the grant epoch and audit `granted_rule.add`. The audit record is
    /// written first: if it fails nothing is persisted. A failure of either step is audited as
    /// `escalation.denied` with `cause = audit_failure` or `grant_write_failed`; the credential
    /// stays and its next authentication escalates again (plan P7 gap 10).
    ///
    /// A registration through the `*` rule is persisted only while the profile holds fewer than
    /// `max_wildcard_registrations` wildcard registration grants (checked atomically with the
    /// write); at the cap the credential stays without a grant, so the agent cannot sign in with
    /// it unattended. The approval's cap slot (review L2) is held until this returns, whatever the
    /// outcome, and the cap is also checked before `granted_rule.add` is audited, so that record
    /// never describes a grant the cap refuses.
    pub fn record_registration_grant(
        &self,
        approval: &RegistrationApproval,
        credential_ref: CredentialRef,
        max_granted_rules: usize,
        max_wildcard_registrations: usize,
    ) -> Result<(), GrantStoreError> {
        // The slot is released when this function returns, on every path (the store holds the
        // grant by then, or never will).
        struct ReleaseSlot<'a>(&'a RegistrationApproval);
        impl Drop for ReleaseSlot<'_> {
            fn drop(&mut self) {
                if let Some(reservation) = &self.0.reservation {
                    reservation.release();
                }
            }
        }
        let _slot = ReleaseSlot(approval);

        let context = EscalationAuditContext {
            escalation_id: approval.escalation_id.as_str().to_string(),
            profile_id: approval.profile.clone(),
            action: AuditAction::Register,
            rp_id: approval.rp_id.clone(),
            origin: approval.origin.clone(),
            rule: approval.rule,
        };
        let audit_denial = |cause: EscalationDenyCause| {
            if let Err(audit_error) = self.audit.record(context.denied(cause)) {
                warn!(
                    "escalation {}: the failed grant write could not be audited: {}",
                    approval.escalation_id, audit_error
                );
            }
        };
        // A cap that no longer admits this grant (a reload lowered it, or grants were stored
        // meanwhile) is refused before `granted_rule.add` is audited: that record exists only for
        // grants the store is about to take. The store re-checks atomically with the write.
        let refused = match self.grants.capacity(&approval.profile) {
            GrantCapacity::Available { used, .. } if used >= max_granted_rules => {
                Some(GrantStoreError::CapReached(max_granted_rules))
            }
            GrantCapacity::Available {
                wildcard_registrations,
                ..
            } if approval.rule == PermittingRule::Wildcard
                && wildcard_registrations >= max_wildcard_registrations =>
            {
                Some(GrantStoreError::WildcardCapReached(
                    max_wildcard_registrations,
                ))
            }
            _ => None,
        };
        if let Some(error) = refused {
            warn!(
                "escalation {}: the registration grant is refused before it is audited: {}",
                approval.escalation_id, error
            );
            audit_denial(EscalationDenyCause::GrantWriteFailed);
            return Err(error);
        }
        let added = GrantedRuleAddBuilder::new(
            approval.profile.clone(),
            &approval.rp_id,
            GrantKind::Registration,
            approval.escalation_id.as_str(),
            approval.rule,
        )
        .credential_ref(Some(credential_ref.clone()))
        .build();
        if let Err(e) = self.audit.record(added) {
            warn!(
                "escalation {}: granted_rule.add could not be audited, no grant persisted: {}",
                approval.escalation_id, e
            );
            audit_denial(EscalationDenyCause::AuditFailure);
            return Err(GrantStoreError::Io(format!(
                "granted_rule.add could not be audited: {e}"
            )));
        }
        let rule = GrantedRule::new(
            &approval.rp_id,
            GrantKind::Registration,
            approval.escalation_id.as_str(),
            &approval.origin,
            approval.rule,
            Some(credential_ref),
        );
        let wildcard_cap =
            (approval.rule == PermittingRule::Wildcard).then_some(max_wildcard_registrations);
        match self.grants.add(
            &approval.profile,
            rule,
            max_granted_rules,
            approval.revoke_token,
            wildcard_cap,
        ) {
            Ok(()) => {}
            Err(GrantStoreError::Revoked) => {
                // The RP was revoked (or the profile cleared) after the escalation was raised:
                // the credential stays, no grant is persisted (ADR 0014 section 8.3, review M-c).
                info!(
                    "escalation {}: the RP was revoked meanwhile; the credential is kept without \
                     a registration grant",
                    approval.escalation_id
                );
                if let Err(audit_error) = self
                    .audit
                    .record(context.revoked(EscalationRevokeReason::PolicyReload))
                {
                    warn!(
                        "escalation {}: the revocation could not be audited: {}",
                        approval.escalation_id, audit_error
                    );
                }
                return Err(GrantStoreError::Revoked);
            }
            Err(e) => {
                warn!(
                    "escalation {}: the registration grant could not be persisted: {}",
                    approval.escalation_id, e
                );
                audit_denial(EscalationDenyCause::GrantWriteFailed);
                return Err(e);
            }
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

/// What the approval decided, to be published by `finish_deciding`.
struct Settled {
    outcome: EntryOutcome,
    audit: Option<AuditEvent>,
    /// The grant was persisted (it is revoked again if the entry was cancelled meanwhile).
    grant_written: bool,
}

/// Finishes a `Deciding` entry as `Denied`, and wakes its waiters, if the approval unwinds: a panic
/// in an audit or store call must not leave the profile's prompt slot jammed. The state change
/// comes first; the denial's audit record is then attempted without letting a second panic (the
/// one that is unwinding may come from the audit itself) escape the destructor.
struct DecidingGuard<'a> {
    service: &'a EscalationService,
    serial: u64,
    context: EscalationAuditContext,
    cause: EscalationDenyCause,
    reason: PolicyDenyReason,
    armed: bool,
}

impl Drop for DecidingGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        warn!(
            "escalation {}: the approval panicked; denying",
            self.context.escalation_id
        );
        let outcome = EntryOutcome::Denied {
            cause: self.cause,
            reason: Some(self.reason),
        };
        let _ = panic::catch_unwind(AssertUnwindSafe(|| {
            self.service.finish_deciding(self.serial, outcome, None);
        }));
        let _ = panic::catch_unwind(AssertUnwindSafe(|| {
            if let Err(e) = self.service.audit.record(self.context.denied(self.cause)) {
                warn!(
                    "escalation {}: the denial could not be audited: {}",
                    self.context.escalation_id, e
                );
            }
        }));
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
        self,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
        still_valid: &dyn Fn() -> bool,
        park: &mut dyn ParkHook,
    ) -> EscalationOutcome {
        self.wait_polling(WAIT_POLL_INTERVAL, deadline, cancelled, still_valid, park)
    }

    /// [`Waiter::wait`] with an explicit poll interval (a test passes a very long one to show that
    /// a decision wakes the waiter without waiting for a poll).
    fn wait_polling(
        mut self,
        poll_interval: Duration,
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
                    let pause = poll_interval.min(deadline - now);
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
            GrantCapacity::Available {
                used: 0,
                wildcard_registrations: 0,
            }
        }

        fn add(
            &self,
            profile: &ProfileId,
            _rule: GrantedRule,
            _max_rules: usize,
            _token: Option<RevokeToken>,
            _wildcard_cap: Option<usize>,
        ) -> Result<(), GrantStoreError> {
            Err(GrantStoreError::Unavailable(profile.to_string()))
        }

        fn revoke_request(
            &self,
            _profile: &ProfileId,
            _request_id: &str,
        ) -> Result<usize, GrantStoreError> {
            Ok(0)
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

    type Hook = Arc<dyn Fn() + Send + Sync>;

    #[derive(Default)]
    struct FakeAudit {
        kinds: Mutex<Vec<String>>,
        events: Mutex<Vec<serde_json::Value>>,
        failing: Mutex<HashSet<&'static str>>,
        panicking: Mutex<HashSet<&'static str>>,
        /// Runs (with no lock held) after the record of that kind is written.
        hooks: Mutex<HashMap<&'static str, Hook>>,
    }

    impl FakeAudit {
        fn panic_on(&self, kind: &'static str) {
            self.panicking.lock().unwrap().insert(kind);
        }

        fn hook(&self, kind: &'static str, hook: impl Fn() + Send + Sync + 'static) {
            self.hooks.lock().unwrap().insert(kind, Arc::new(hook));
        }

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
            if self.panicking.lock().unwrap().contains(kind) {
                panic!("injected audit panic");
            }
            if self.failing.lock().unwrap().contains(kind) {
                return Err("injected audit failure".to_string());
            }
            self.kinds.lock().unwrap().push(kind.to_string());
            self.events
                .lock()
                .unwrap()
                .push(serde_json::to_value(&event).unwrap());
            let hook = self.hooks.lock().unwrap().get(kind).cloned();
            if let Some(hook) = hook {
                hook();
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeGrants {
        rules: Mutex<Vec<GrantedRule>>,
        unavailable: AtomicBool,
        fail_writes: AtomicBool,
        panic_writes: AtomicBool,
        adds: AtomicU64,
        /// Runs (with no lock held) after the rule is stored.
        after_add: Mutex<Option<Hook>>,
        /// The real store's revocation generations, by RP (`GrantedRulesStore::revoke_token`).
        generations: Mutex<HashMap<String, u64>>,
    }

    impl FakeGrants {
        /// What `GrantedRulesStore::revoke` does: bump the RP's generation and drop its rules.
        fn revoke_rp(&self, rp_id: &str) {
            *self
                .generations
                .lock()
                .unwrap()
                .entry(rp_id.to_string())
                .or_default() += 1;
            self.rules
                .lock()
                .unwrap()
                .retain(|rule| rule.rp_id != rp_id);
        }

        fn token(&self, rp_id: &str) -> u64 {
            self.generations
                .lock()
                .unwrap()
                .get(rp_id)
                .copied()
                .unwrap_or(0)
        }
    }

    impl GrantWriter for FakeGrants {
        fn capacity(&self, _profile: &ProfileId) -> GrantCapacity {
            if self.unavailable.load(Ordering::SeqCst) {
                return GrantCapacity::Unavailable;
            }
            let rules = self.rules.lock().unwrap();
            GrantCapacity::Available {
                used: rules.len(),
                wildcard_registrations: wildcard_registration_count(&rules),
            }
        }

        fn revoke_token(&self, _profile: &ProfileId, rp_id: &str) -> Option<RevokeToken> {
            Some(RevokeToken::for_test(0, self.token(rp_id)))
        }

        fn add(
            &self,
            _profile: &ProfileId,
            rule: GrantedRule,
            max_rules: usize,
            token: Option<RevokeToken>,
            wildcard_cap: Option<usize>,
        ) -> Result<(), GrantStoreError> {
            assert!(lock_order::held_levels().is_empty());
            self.adds.fetch_add(1, Ordering::SeqCst);
            if token.is_some_and(|token| token != RevokeToken::for_test(0, self.token(&rule.rp_id)))
            {
                return Err(GrantStoreError::Revoked);
            }
            if self.panic_writes.load(Ordering::SeqCst) {
                panic!("injected store panic");
            }
            if self.fail_writes.load(Ordering::SeqCst) {
                return Err(GrantStoreError::Io("injected".to_string()));
            }
            {
                let mut rules = self.rules.lock().unwrap();
                if rules.len() >= max_rules {
                    return Err(GrantStoreError::CapReached(max_rules));
                }
                if let Some(cap) = wildcard_cap
                    && wildcard_registration_count(&rules) >= cap
                {
                    return Err(GrantStoreError::WildcardCapReached(cap));
                }
                rules.push(rule);
            }
            let hook = self.after_add.lock().unwrap().clone();
            if let Some(hook) = hook {
                hook();
            }
            Ok(())
        }

        fn revoke_request(
            &self,
            _profile: &ProfileId,
            request_id: &str,
        ) -> Result<usize, GrantStoreError> {
            assert!(lock_order::held_levels().is_empty());
            let mut rules = self.rules.lock().unwrap();
            let before = rules.len();
            rules.retain(|rule| rule.request_id != request_id);
            Ok(before - rules.len())
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
            max_wildcard_registrations: 4,
            wildcard_registration_prompts_per_day: 3,
            store_count: None,
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
                        4,
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
        // Review L3: saturated profiles never starve another one. Many profiles at their own cap
        // (far more than the old shared cap of 64 allowed) leave a fresh profile able to wait.
        for p in 0..8 {
            for session in 0..4 {
                for _ in 0..MAX_WAITERS_PER_SESSION {
                    held.push(
                        h.service
                            .join_or_create(request(
                                &format!("s{p}"),
                                "a.example",
                                5000 + p * 10 + session,
                            ))
                            .unwrap(),
                    );
                }
            }
        }
        assert!(held.len() > 64);
        let fresh = h
            .service
            .join_or_create(request("newcomer", "a.example", 6000))
            .expect("a saturated profile does not affect another");
        drop(fresh);
        for _ in 0..8 * 4 * MAX_WAITERS_PER_SESSION {
            held.pop();
        }
        // Fill the global safety bound with profiles of 16 waiters each.
        for p in 0..63 {
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
        // The record precedes the failed write, and the deny follows it.
        let kinds = h.audit.kinds();
        let position = |kind: &str| kinds.iter().position(|k| k == kind).unwrap();
        assert!(position("granted_rule.add") < position("escalation.denied"));
        // The prompt slot is free again.
        let _next = h
            .service
            .join_or_create(request("p", "b.example", 1))
            .unwrap();
        assert_eq!(h.prompter.shown().len(), 2);
    }

    /// Approve the last shown prompt of `h`, run the approval on this thread and return the
    /// parked waiter's outcome.
    fn approve_and_join(h: &Harness, rp_id: &str) -> EscalationOutcome {
        let parked = park(h.service.join_or_create(request("p", rp_id, 1)).unwrap());
        h.service
            .prompt_event(&h.prompter.last_shown(), PromptEvent::Approved);
        parked.join().unwrap()
    }

    fn assert_denied(outcome: EscalationOutcome, expected_cause: EscalationDenyCause) {
        match outcome {
            EscalationOutcome::Denied { cause, .. } => assert_eq!(cause, expected_cause),
            other => panic!("unexpected {other:?}"),
        }
    }

    fn cancel_on(h: &Harness) -> impl Fn() + Send + Sync + 'static {
        let service = Arc::clone(&h.service);
        move || service.cancel_profile(&profile("p"))
    }

    #[test]
    fn the_grant_is_audited_before_the_store_write_and_an_audit_failure_denies() {
        let h = harness();
        h.audit.fail("granted_rule.add");
        let outcome = approve_and_join(&h, "a.example");
        match outcome {
            EscalationOutcome::Denied { cause, reason, .. } => {
                assert_eq!(cause, EscalationDenyCause::AuditFailure);
                assert_eq!(reason, Some(PolicyDenyReason::AuditFailure));
            }
            other => panic!("unexpected {other:?}"),
        }
        // Nothing was written: the record failed first.
        assert_eq!(h.grants.adds.load(Ordering::SeqCst), 0);
        assert!(h.grants.rules.lock().unwrap().is_empty());
        assert_eq!(h.audit.last("escalation.denied")["cause"], "audit_failure");
        // The prompt slot is free again.
        let _next = h
            .service
            .join_or_create(request("p", "b.example", 1))
            .unwrap();
        assert_eq!(h.prompter.shown().len(), 2);

        // A successful approval records the grant, then writes it.
        let h = harness();
        let seen = Arc::new(AtomicU64::new(u64::MAX));
        let (audit_grants, observed) = (Arc::clone(&h.grants), Arc::clone(&seen));
        h.audit.hook("granted_rule.add", move || {
            observed.store(audit_grants.adds.load(Ordering::SeqCst), Ordering::SeqCst);
        });
        assert!(matches!(
            approve_and_join(&h, "a.example"),
            EscalationOutcome::Approved { .. }
        ));
        assert_eq!(seen.load(Ordering::SeqCst), 0, "store written before audit");
        assert_eq!(h.grants.adds.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn registration_grant_is_audited_before_the_store_write() {
        fn approval(h: &Harness) -> RegistrationApproval {
            match approve_and_join_register(h) {
                EscalationOutcome::RegistrationApproved(approval) => approval,
                other => panic!("unexpected {other:?}"),
            }
        }
        fn approve_and_join_register(h: &Harness) -> EscalationOutcome {
            let parked = park(
                h.service
                    .join_or_create(register("p", "r.example", 1))
                    .unwrap(),
            );
            h.service
                .prompt_event(&h.prompter.last_shown(), PromptEvent::Approved);
            parked.join().unwrap()
        }
        let cred = || CredentialRef::with_default_domain(b"cred");

        // The record fails: nothing is persisted.
        let h = harness();
        let approval_token = approval(&h);
        h.audit.fail("granted_rule.add");
        assert!(
            h.service
                .record_registration_grant(&approval_token, cred(), 64, 4)
                .is_err()
        );
        assert_eq!(h.grants.adds.load(Ordering::SeqCst), 0);
        assert_eq!(h.audit.last("escalation.denied")["cause"], "audit_failure");

        // The write fails: the record precedes the deny.
        let h = harness();
        let approval_token = approval(&h);
        h.grants.fail_writes.store(true, Ordering::SeqCst);
        assert!(
            h.service
                .record_registration_grant(&approval_token, cred(), 64, 4)
                .is_err()
        );
        let kinds = h.audit.kinds();
        let position = |kind: &str| kinds.iter().position(|k| k == kind).unwrap();
        assert!(position("granted_rule.add") < position("escalation.denied"));
        assert_eq!(
            h.audit.last("escalation.denied")["cause"],
            "grant_write_failed"
        );
        assert!(h.grants.rules.lock().unwrap().is_empty());
    }

    #[test]
    fn a_reload_between_the_grant_audit_and_the_store_write_stands() {
        let h = harness();
        h.audit.hook("granted_rule.add", cancel_on(&h));
        let outcome = approve_and_join(&h, "a.example");
        assert!(matches!(outcome, EscalationOutcome::Revoked { .. }));
        // The re-check under the mutex saw the revocation: no write, nothing to compensate.
        assert_eq!(h.grants.adds.load(Ordering::SeqCst), 0);
        assert!(h.grants.rules.lock().unwrap().is_empty());
        assert_eq!(h.audit.count("escalation.revoked"), 1);
        assert_eq!(h.audit.count("granted_rule.revoke"), 0);
        assert_eq!(
            h.service.state_of(&request("p", "a.example", 1).key()),
            None
        );
        // The profile prompts again.
        let _again = h
            .service
            .join_or_create(request("p", "a.example", 1))
            .unwrap();
        assert_eq!(h.prompter.shown().len(), 2);
    }

    #[test]
    fn a_reload_after_the_store_write_revokes_the_grant_again() {
        let h = harness();
        *h.grants.after_add.lock().unwrap() = Some(Arc::new(cancel_on(&h)));
        let outcome = approve_and_join(&h, "a.example");
        assert!(matches!(outcome, EscalationOutcome::Revoked { .. }));
        assert_eq!(h.grants.adds.load(Ordering::SeqCst), 1);
        // The compensation removed the grant and audited it.
        assert!(h.grants.rules.lock().unwrap().is_empty());
        let revoked = h.audit.last("granted_rule.revoke");
        assert_eq!(revoked["rp_id"], "a.example");
        assert_eq!(revoked["revoked"], 1);
        assert_eq!(h.audit.count("escalation.revoked"), 1);
        assert_eq!(
            h.service.state_of(&request("p", "a.example", 1).key()),
            None
        );
    }

    #[test]
    fn a_registration_approval_cancelled_while_deciding_stands_cancelled() {
        let h = harness();
        h.audit.hook("escalation.approved", cancel_on(&h));
        let parked = park(
            h.service
                .join_or_create(register("p", "r.example", 1))
                .unwrap(),
        );
        h.service
            .prompt_event(&h.prompter.last_shown(), PromptEvent::Approved);
        assert!(matches!(
            parked.join().unwrap(),
            EscalationOutcome::Revoked { .. }
        ));
        assert_eq!(h.grants.adds.load(Ordering::SeqCst), 0);
    }

    /// Run an approval that panics; it must leave the entry denied and the slot free.
    fn assert_panicking_approval_denies(h: &Harness, cause: EscalationDenyCause) {
        let parked = park(
            h.service
                .join_or_create(request("p", "a.example", 1))
                .unwrap(),
        );
        let ticket = h.prompter.last_shown();
        let panicked = std::panic::catch_unwind(AssertUnwindSafe(|| {
            h.service.prompt_event(&ticket, PromptEvent::Approved);
        }));
        assert!(panicked.is_err(), "the injected panic must propagate");
        assert_denied(parked.join().unwrap(), cause);
        assert!(h.grants.rules.lock().unwrap().is_empty());
        assert_eq!(
            h.service.state_of(&request("p", "a.example", 1).key()),
            None
        );
        // The profile's prompt slot is not jammed.
        let _next = h
            .service
            .join_or_create(request("p", "b.example", 1))
            .unwrap();
        assert_eq!(h.prompter.shown().len(), 2);
    }

    #[test]
    fn a_panicking_audit_does_not_jam_the_profile() {
        let h = harness();
        h.audit.panic_on("escalation.approved");
        assert_panicking_approval_denies(&h, EscalationDenyCause::AuditFailure);
        assert_eq!(h.audit.last("escalation.denied")["cause"], "audit_failure");

        let h = harness();
        h.audit.panic_on("granted_rule.add");
        assert_panicking_approval_denies(&h, EscalationDenyCause::AuditFailure);
        assert_eq!(h.grants.adds.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_panicking_store_does_not_jam_the_profile() {
        let h = harness();
        h.grants.panic_writes.store(true, Ordering::SeqCst);
        assert_panicking_approval_denies(&h, EscalationDenyCause::GrantWriteFailed);
        assert_eq!(
            h.audit.last("escalation.denied")["cause"],
            "grant_write_failed"
        );
    }

    #[test]
    fn a_second_panic_in_the_guard_is_contained() {
        // The audit panics on the approval and again on the denial: the entry is still finished.
        let h = harness();
        h.audit.panic_on("escalation.approved");
        h.audit.panic_on("escalation.denied");
        assert_panicking_approval_denies(&h, EscalationDenyCause::AuditFailure);
        assert_eq!(h.audit.count("escalation.denied"), 0);
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
    fn cancel_rp_revokes_only_that_rps_escalations_and_prompts_the_next() {
        // Review L2: `grants revoke` cancels the revoked RP's escalations, of any action.
        let h = harness();
        let active = park(
            h.service
                .join_or_create(request("p", "a.example", 1))
                .unwrap(),
        );
        let queued = h
            .service
            .join_or_create(request("p", "b.example", 2))
            .unwrap();
        let other_profile = h
            .service
            .join_or_create(request("q", "a.example", 3))
            .unwrap();
        thread::sleep(Duration::from_millis(50));
        assert_eq!(h.prompter.shown().len(), 2);
        h.service.cancel_rp(&profile("p"), "a.example");
        assert!(matches!(
            active.join().unwrap(),
            EscalationOutcome::Revoked { .. }
        ));
        assert_eq!(h.audit.count("escalation.revoked"), 1);
        assert_eq!(h.prompter.withdrawn().len(), 1);
        // The profile's queued escalation for another RP takes the prompt slot.
        assert_eq!(
            h.service.state_of(&request("p", "b.example", 2).key()),
            Some(EscalationState::Prompting)
        );
        assert_eq!(h.prompter.shown().len(), 3);
        // Another profile's escalation for the same RP is untouched.
        assert_eq!(
            h.service.state_of(&request("q", "a.example", 3).key()),
            Some(EscalationState::Prompting)
        );
        drop((queued, other_profile));
    }

    #[test]
    fn a_grant_revoke_after_the_store_write_revokes_the_grant_again() {
        // Review L2: the approval wrote its grant, then the operator revoked that RP before the
        // approval published. The late approval must not leave the grant behind.
        let h = harness();
        let service = Arc::clone(&h.service);
        *h.grants.after_add.lock().unwrap() = Some(Arc::new(move || {
            service.cancel_rp(&profile("p"), "a.example")
        }));
        let outcome = approve_and_join(&h, "a.example");
        assert!(matches!(outcome, EscalationOutcome::Revoked { .. }));
        assert_eq!(h.grants.adds.load(Ordering::SeqCst), 1);
        assert!(h.grants.rules.lock().unwrap().is_empty());
        assert_eq!(h.audit.last("granted_rule.revoke")["rp_id"], "a.example");
    }

    #[test]
    fn a_store_revoke_before_the_grant_write_denies_the_late_approval() {
        // Review M-d: `grants revoke` has revoked the store (bumping the RP's generation) but its
        // `cancel_rp` has not reached the entry yet when the approval writes its grant. The write
        // is refused under the store's writer, so nothing persists and nothing needs undoing,
        // whatever the order of the cancel that follows.
        let h = harness();
        let grants = Arc::clone(&h.grants);
        h.audit
            .hook("granted_rule.add", move || grants.revoke_rp("a.example"));
        let outcome = approve_and_join(&h, "a.example");
        assert!(
            matches!(outcome, EscalationOutcome::Revoked { .. }),
            "{outcome:?}"
        );
        assert_eq!(
            h.grants.adds.load(Ordering::SeqCst),
            1,
            "the write was tried"
        );
        assert!(h.grants.rules.lock().unwrap().is_empty(), "and refused");
        assert_eq!(h.audit.count("escalation.revoked"), 1);
        assert_eq!(
            h.audit.count("granted_rule.revoke"),
            0,
            "nothing to compensate"
        );
        // The cancel arrives late: the entry is gone already, nothing changes.
        h.service.cancel_rp(&profile("p"), "a.example");
        assert!(h.grants.rules.lock().unwrap().is_empty());

        // A revoke while the prompt is shown (before the click) has the same effect.
        let h = harness();
        let parked = park(
            h.service
                .join_or_create(request("p", "a.example", 1))
                .unwrap(),
        );
        h.grants.revoke_rp("a.example");
        h.service
            .prompt_event(&h.prompter.last_shown(), PromptEvent::Approved);
        assert!(matches!(
            parked.join().unwrap(),
            EscalationOutcome::Revoked { .. }
        ));
        assert!(h.grants.rules.lock().unwrap().is_empty());

        // An escalation raised after the revocation is a new question and is granted normally.
        let outcome = approve_and_join(&h, "a.example");
        assert!(matches!(outcome, EscalationOutcome::Approved { .. }));
        assert_eq!(h.grants.rules.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_registration_grant_after_a_grants_revoke_is_not_persisted() {
        // Review M-c: the registration was approved and its credential written; `grants revoke`
        // runs before `record_registration_grant` (its cancel skips the approved entry). The
        // credential stays, the grant is not persisted (ADR 0014 section 8.3).
        let h = harness();
        let parked = park(
            h.service
                .join_or_create(register("p", "r.example", 1))
                .unwrap(),
        );
        h.service
            .prompt_event(&h.prompter.last_shown(), PromptEvent::Approved);
        let EscalationOutcome::RegistrationApproved(approval) = parked.join().unwrap() else {
            panic!("the registration was not approved");
        };
        h.grants.revoke_rp("r.example");
        h.service.cancel_rp(&profile("p"), "r.example");
        let recorded = h.service.record_registration_grant(
            &approval,
            CredentialRef::with_default_domain(b"cred"),
            64,
            4,
        );
        assert_eq!(recorded, Err(GrantStoreError::Revoked));
        assert!(h.grants.rules.lock().unwrap().is_empty());
        assert_eq!(h.audit.count("escalation.revoked"), 1);
        assert_eq!(h.audit.count("escalation.denied"), 0);
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
    fn waiters_are_woken_by_the_decision_not_by_the_poll_interval() {
        // A poll interval and a deadline far beyond the bound: only the decision's notification
        // can wake the waiter in time. No scheduler delay can fail this, since the bound is
        // generous and a polling-only waiter would sleep for the whole minute.
        const POLL: Duration = Duration::from_secs(60);
        const BOUND: Duration = Duration::from_secs(10);
        let h = harness();
        let waiter = h
            .service
            .join_or_create(request("p", "a.example", 1))
            .unwrap();
        let parked = thread::spawn(move || {
            waiter.wait_polling(
                POLL,
                Instant::now() + 2 * POLL,
                &|| false,
                &|| true,
                &mut NoPark,
            )
        });
        // Let the waiter reach its condvar wait; deciding earlier is harmless but proves less.
        thread::sleep(Duration::from_millis(50));
        let start = Instant::now();
        h.service
            .prompt_event(&h.prompter.last_shown(), PromptEvent::Approved);
        assert!(matches!(
            parked.join().unwrap(),
            EscalationOutcome::Approved { .. }
        ));
        assert!(
            start.elapsed() < BOUND,
            "the waiter slept through the decision for {:?}",
            start.elapsed()
        );
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
    fn key(index: usize) -> EscalationKey {
        EscalationKey {
            profile: profile("p"),
            rp_id: format!("{index}.example"),
            action: CeremonyAction::Authenticate,
        }
    }

    fn at(ms: u64) -> MonotonicTime {
        MonotonicTime::from_millis(ms)
    }

    #[test]
    fn cooldown_map_prunes_expired_entries_on_every_insert_and_is_capped() {
        let mut inner = Inner::default();
        let cooldown = Duration::from_secs(10);
        inner.start_cooldown(&key(0), at(1_000), cooldown);
        inner.start_cooldown(&key(1), at(2_000), cooldown);
        assert_eq!(inner.cooldown.len(), 2);
        // The first two expired and are never looked up again; the next insert drops them.
        inner.start_cooldown(&key(2), at(60_000), cooldown);
        assert_eq!(inner.cooldown.len(), 1);
        assert!(inner.cooldown.contains_key(&key(2)));

        // An expired entry is dropped on the next insert.
        let long = Duration::from_secs(3_600);
        let mut inner = Inner::default();
        for index in 0..MAX_TRACKED_KEYS {
            inner.start_cooldown(&key(index), at(1_000 + index as u64), long);
        }
        assert_eq!(inner.cooldown.len(), MAX_TRACKED_KEYS);
        inner.start_cooldown(&key(99_999), at(10_000_000 + 3_600_000), long);
        assert_eq!(inner.cooldown.len(), 1);
    }

    /// Review L1: a live cooldown is never evicted. The table refuses new escalations when it is
    /// full, so an agent with a broad `request` rule cannot push out a cooldown the human just
    /// set by denying.
    #[test]
    fn a_full_cooldown_table_refuses_new_escalations_and_evicts_nothing() {
        let long = Duration::from_secs(3_600);
        let mut inner = Inner::default();
        for index in 0..MAX_TRACKED_KEYS {
            inner.start_cooldown(&key(index), at(1_000 + index as u64), long);
        }
        assert_eq!(inner.cooldown.len(), MAX_TRACKED_KEYS);
        let now = at(60_000);

        // A new key is refused, not admitted at the expense of an old cooldown.
        let fresh = request("p", "fresh.example", 1);
        assert_eq!(
            inner.admit(&fresh, &fresh.key(), now, StoredWildcards::NONE),
            Err(EscalationRefusal::TrackingFull)
        );
        assert_eq!(inner.cooldown.len(), MAX_TRACKED_KEYS);
        // The oldest cooldown (the human's deny, say) is untouched and still refuses its key.
        assert!(inner.in_cooldown(&key(0), now));
        let oldest = request("p", "0.example", 1);
        assert_eq!(
            inner.admit(&oldest, &oldest.key(), now, StoredWildcards::NONE),
            Err(EscalationRefusal::Cooldown)
        );
        // A refresh of a present key evicts nothing either.
        inner.start_cooldown(&key(MAX_TRACKED_KEYS - 1), at(70_000), long);
        assert_eq!(inner.cooldown.len(), MAX_TRACKED_KEYS);
        assert!(inner.cooldown.contains_key(&key(0)));

        // Once cooldowns expire the table has room again.
        let after = at(1_000 + 3_600_000 + MAX_TRACKED_KEYS as u64 + 1);
        assert!(matches!(
            inner.admit(&fresh, &fresh.key(), after, StoredWildcards::NONE),
            Ok(None)
        ));
    }

    /// Live escalations count against the table too: each may end in a cooldown, and that insert
    /// must never need an eviction.
    #[test]
    fn live_escalations_count_against_the_cooldown_table() {
        let mut inner = Inner::default();
        let long = Duration::from_secs(3_600);
        for index in 0..MAX_TRACKED_KEYS - 1 {
            inner.start_cooldown(&key(index), at(1_000), long);
        }
        // One slot left: the next key takes it as a live escalation.
        inner.by_key.insert(key(MAX_TRACKED_KEYS), 1);
        let next = request("p", "next.example", 1);
        assert_eq!(
            inner.admit(&next, &next.key(), at(2_000), StoredWildcards::NONE),
            Err(EscalationRefusal::TrackingFull)
        );
    }

    fn profile_key(profile_name: &str, index: usize) -> EscalationKey {
        EscalationKey {
            profile: profile(profile_name),
            rp_id: format!("{index}.example"),
            action: CeremonyAction::Authenticate,
        }
    }

    /// Review M-e: one profile filling its quota is refused alone. Another profile still
    /// escalates, and the saturated profile's live cooldowns are all kept.
    #[test]
    fn a_profile_at_its_tracking_quota_does_not_starve_another_profile() {
        let mut inner = Inner::default();
        let long = Duration::from_secs(3_600);
        for index in 0..MAX_TRACKED_KEYS_PER_PROFILE {
            inner.start_cooldown(&profile_key("hostile", index), at(1_000), long);
        }
        let now = at(2_000);
        let more = request("hostile", "more.example", 1);
        assert_eq!(
            inner.admit(&more, &more.key(), now, StoredWildcards::NONE),
            Err(EscalationRefusal::TrackingFull)
        );
        // Live escalations count toward the quota as well.
        let other = request("other", "a.example", 2);
        assert!(matches!(
            inner.admit(&other, &other.key(), now, StoredWildcards::NONE),
            Ok(None)
        ));
        assert_eq!(inner.cooldown.len(), MAX_TRACKED_KEYS_PER_PROFILE);
        assert!(inner.in_cooldown(&profile_key("hostile", 0), now));
        // The quota frees up when the cooldowns run out.
        let later = at(1_000 + 3_600_000 + 1);
        assert!(matches!(
            inner.admit(&more, &more.key(), later, StoredWildcards::NONE),
            Ok(None)
        ));
    }

    #[test]
    fn live_escalations_count_against_the_profile_quota_only() {
        let mut inner = Inner::default();
        for index in 0..MAX_TRACKED_KEYS_PER_PROFILE {
            inner
                .by_key
                .insert(profile_key("hostile", index), index as u64);
        }
        let hostile = request("hostile", "new.example", 1);
        assert_eq!(
            inner.admit(&hostile, &hostile.key(), at(1), StoredWildcards::NONE),
            Err(EscalationRefusal::TrackingFull)
        );
        let other = request("other", "new.example", 2);
        assert!(matches!(
            inner.admit(&other, &other.key(), at(1), StoredWildcards::NONE),
            Ok(None)
        ));
    }

    /// The global bound stays a backstop: profiles that each stay under their quota can still
    /// fill it, and then every profile is refused.
    #[test]
    fn the_global_tracking_bound_is_a_backstop_behind_the_profile_quota() {
        let mut inner = Inner::default();
        let long = Duration::from_secs(3_600);
        let profiles = MAX_TRACKED_KEYS / MAX_TRACKED_KEYS_PER_PROFILE;
        for p in 0..profiles {
            for index in 0..MAX_TRACKED_KEYS_PER_PROFILE {
                inner.start_cooldown(&profile_key(&format!("p{p}"), index), at(1_000), long);
            }
        }
        assert_eq!(inner.cooldown.len(), MAX_TRACKED_KEYS);
        let fresh = request("fresh", "a.example", 1);
        assert_eq!(
            inner.admit(&fresh, &fresh.key(), at(2_000), StoredWildcards::NONE),
            Err(EscalationRefusal::TrackingFull)
        );
    }

    #[test]
    fn withdrawal_map_prunes_expired_entries_on_every_insert_and_is_capped() {
        let cooldown = Duration::from_secs(600);
        let window = WITHDRAWAL_WINDOW.as_millis() as u64;
        let mut inner = Inner::default();
        inner.record_withdrawal(&key(0), at(1_000), cooldown);
        inner.record_withdrawal(&key(1), at(2_000), cooldown);
        assert_eq!(inner.withdrawals.len(), 2);
        // Both left the window without being touched again; another key's insert drops them.
        inner.record_withdrawal(&key(2), at(2_000 + window), cooldown);
        assert_eq!(inner.withdrawals.len(), 1);
        assert!(inner.withdrawals.contains_key(&key(2)));

        let mut inner = Inner::default();
        for index in 0..MAX_TRACKED_KEYS + 10 {
            inner.record_withdrawal(&key(index), at(1_000 + index as u64), cooldown);
            assert!(inner.withdrawals.len() <= MAX_TRACKED_KEYS);
        }
        assert_eq!(inner.withdrawals.len(), MAX_TRACKED_KEYS);
        assert!(!inner.withdrawals.contains_key(&key(0)));
        assert!(inner.withdrawals.contains_key(&key(10)));
        assert!(inner.withdrawals.contains_key(&key(MAX_TRACKED_KEYS + 9)));
        // The V-M2 count of a tracked key still reaches its cooldown.
        let tracked = key(MAX_TRACKED_KEYS + 9);
        inner.record_withdrawal(&tracked, at(100_000), cooldown);
        inner.record_withdrawal(&tracked, at(100_001), cooldown);
        assert!(inner.in_cooldown(&tracked, at(100_002)));
    }

    #[test]
    fn session_expiry_is_reported_by_still_valid_without_a_cooldown() {
        let h = harness();
        let waiter = h
            .service
            .join_or_create(request("p", "a.example", 1))
            .unwrap();
        let started = Instant::now();
        // A deadline far away: the session going invalid after a moment ends the wait.
        let outcome = waiter.wait(
            far(),
            &|| false,
            &|| started.elapsed() < Duration::from_millis(300),
            &mut NoPark,
        );
        assert!(matches!(outcome, EscalationOutcome::SessionInvalid));
        assert_eq!(h.audit.last("escalation.expired")["reason"], "aborted");
        assert_eq!(h.audit.count("escalation.denied"), 0);
        assert!(!h.service.in_cooldown(&request("p", "a.example", 1).key()));
        // The key can be escalated at once again.
        let _again = h
            .service
            .join_or_create(request("p", "a.example", 1))
            .unwrap();
        assert_eq!(h.prompter.shown().len(), 2);
    }

    // --- Registration through `*` (ADR 0014 amendment section 2.2 items 4 to 6) ---

    fn wildcard_register(profile_name: &str, rp_id: &str, session: usize) -> EscalationRequest {
        EscalationRequest {
            rule: PermittingRule::Wildcard,
            mode: AgentMode::SameUser,
            store_count: Some(2),
            ..register(profile_name, rp_id, session)
        }
    }

    fn wildcard_grant(rp_id: &str) -> GrantedRule {
        GrantedRule::new(
            rp_id,
            GrantKind::Registration,
            &format!("esc-{rp_id}"),
            &format!("https://{rp_id}"),
            PermittingRule::Wildcard,
            Some(CredentialRef::with_default_domain(rp_id.as_bytes())),
        )
    }

    #[test]
    fn wildcard_registration_prompt_carries_the_rule_and_the_store_count() {
        let h = harness();
        let _waiter = h
            .service
            .join_or_create(wildcard_register("p", "a.example", 1))
            .unwrap();
        let fields = h.prompter.shown.lock().unwrap()[0].1.clone();
        assert_eq!(fields.verb, PromptVerb::Register);
        assert_eq!(fields.rule, PromptRule::Wildcard);
        assert_eq!(fields.store_count, Some(2));
        // A sign-in prompt never carries a count, even if one was set.
        let mut sign_in = request("p", "b.example", 1);
        sign_in.store_count = Some(5);
        assert_eq!(sign_in.prompt_fields().store_count, None);
        assert_eq!(sign_in.prompt_fields().rule, PromptRule::Exact);
    }

    #[test]
    fn wildcard_registration_cap_counts_stored_grants_and_live_escalations() {
        let h = harness();
        let capped = |rp: &str| EscalationRequest {
            max_wildcard_registrations: 2,
            ..wildcard_register("p", rp, 1)
        };
        // One stored wildcard registration grant; exact-rule and escalation grants do not count.
        h.grants.rules.lock().unwrap().extend([
            wildcard_grant("stored.example"),
            GrantedRule::new(
                "exact.example",
                GrantKind::Registration,
                "esc-exact",
                "https://exact.example",
                PermittingRule::Exact,
                Some(CredentialRef::with_default_domain(b"exact")),
            ),
            GrantedRule::new(
                "signin.example",
                GrantKind::Escalation,
                "esc-signin",
                "https://signin.example",
                PermittingRule::Wildcard,
                None,
            ),
        ]);
        // One live wildcard registration escalation holds the second slot.
        let pending = h.service.join_or_create(capped("a.example")).unwrap();
        assert_eq!(
            h.service.precheck(&capped("b.example")).unwrap_err(),
            EscalationRefusal::WildcardRegistrationCap
        );
        assert_eq!(
            h.service.join_or_create(capped("b.example")).unwrap_err(),
            EscalationRefusal::WildcardRegistrationCap
        );
        assert_eq!(h.prompter.shown().len(), 1, "refused without a prompt");
        assert_eq!(
            EscalationRefusal::WildcardRegistrationCap.deny_reason(),
            PolicyDenyReason::WildcardRegistrationCap
        );
        // Exact-rule registrations and wildcard sign-ins are not capped by it.
        assert!(h.service.precheck(&register("p", "c.example", 1)).is_ok());
        let wildcard_sign_in = EscalationRequest {
            rule: PermittingRule::Wildcard,
            max_wildcard_registrations: 0,
            ..request("p", "d.example", 1)
        };
        assert!(h.service.precheck(&wildcard_sign_in).is_ok());

        // The pending escalation ends without a grant: its slot is free again.
        drop(pending);
        assert!(h.service.precheck(&capped("b.example")).is_ok());
        // Revoking the stored grant frees another.
        h.grants
            .rules
            .lock()
            .unwrap()
            .retain(|rule| rule.rp_id != "stored.example");
        let one = EscalationRequest {
            max_wildcard_registrations: 1,
            ..wildcard_register("p", "e.example", 1)
        };
        assert!(h.service.precheck(&one).is_ok());
    }

    #[test]
    fn wildcard_registration_grant_write_enforces_the_cap_atomically() {
        let h = harness();
        h.grants
            .rules
            .lock()
            .unwrap()
            .push(wildcard_grant("stored.example"));
        let waiter = h
            .service
            .join_or_create(wildcard_register("p", "a.example", 1))
            .unwrap();
        let parked = park(waiter);
        h.clock.advance(Duration::from_secs(5));
        h.service
            .prompt_event(&h.prompter.last_shown(), PromptEvent::Approved);
        let EscalationOutcome::RegistrationApproved(approval) = parked.join().unwrap() else {
            panic!("expected a registration approval");
        };
        assert_eq!(approval.rule(), PermittingRule::Wildcard);
        // Another wildcard grant was stored meanwhile: at a cap of 2 the write is refused.
        h.grants
            .rules
            .lock()
            .unwrap()
            .push(wildcard_grant("raced.example"));
        assert_eq!(
            h.service
                .record_registration_grant(
                    &approval,
                    CredentialRef::with_default_domain(b"c"),
                    64,
                    2
                )
                .unwrap_err(),
            GrantStoreError::WildcardCapReached(2)
        );
        assert_eq!(
            h.audit.last("escalation.denied")["cause"],
            "grant_write_failed"
        );
        h.service
            .record_registration_grant(&approval, CredentialRef::with_default_domain(b"c"), 64, 3)
            .unwrap();
        let rules = h.grants.rules.lock().unwrap();
        let stored = rules.iter().find(|rule| rule.rp_id == "a.example").unwrap();
        assert_eq!(stored.kind, GrantKind::Registration);
        assert_eq!(stored.rule, PermittingRule::Wildcard);
        assert_eq!(wildcard_registration_count(&rules), 3);
    }

    /// Approve a wildcard registration of `rp_id` (cap 2, one grant already stored), leaving the
    /// credential unwritten: the approval is returned with no grant recorded yet.
    fn approved_wildcard_registration(h: &Harness, rp_id: &str) -> RegistrationApproval {
        let waiter = h
            .service
            .join_or_create(capped_wildcard_register(rp_id, 1))
            .unwrap();
        let parked = park(waiter);
        h.clock.advance(Duration::from_secs(5));
        h.service
            .prompt_event(&h.prompter.last_shown(), PromptEvent::Approved);
        let EscalationOutcome::RegistrationApproved(approval) = parked.join().unwrap() else {
            panic!("expected a registration approval");
        };
        approval
    }

    fn capped_wildcard_register(rp_id: &str, session: usize) -> EscalationRequest {
        EscalationRequest {
            max_wildcard_registrations: 2,
            wildcard_registration_prompts_per_day: 24,
            ..wildcard_register("p", rp_id, session)
        }
    }

    /// Review L2: between the approval and the grant write the registration counts as neither
    /// live nor stored. A second wildcard registration used to be admitted and prompted at the
    /// cap; the approval now holds a slot until its grant write returns.
    #[test]
    fn an_approved_wildcard_registration_holds_its_cap_slot_until_the_grant_is_written() {
        let h = harness();
        h.grants
            .rules
            .lock()
            .unwrap()
            .push(wildcard_grant("stored.example"));
        let approval = approved_wildcard_registration(&h, "a.example");
        // The credential is being written; no grant exists yet. The cap (2) is full.
        let shown = h.prompter.shown().len();
        let second = capped_wildcard_register("b.example", 2);
        assert_eq!(
            h.service.precheck(&second).unwrap_err(),
            EscalationRefusal::WildcardRegistrationCap
        );
        assert_eq!(
            h.service.join_or_create(second.clone()).unwrap_err(),
            EscalationRefusal::WildcardRegistrationCap
        );
        assert_eq!(h.prompter.shown().len(), shown, "refused without a prompt");
        assert_eq!(
            h.service
                .join_or_create(second.clone())
                .unwrap_err()
                .deny_reason(),
            PolicyDenyReason::WildcardRegistrationCap
        );

        // The grant is written: the slot is now a stored grant, the cap stays full.
        h.service
            .record_registration_grant(&approval, CredentialRef::with_default_domain(b"c"), 64, 2)
            .unwrap();
        assert_eq!(h.audit.count("granted_rule.add"), 1);
        assert_eq!(
            h.service.precheck(&second).unwrap_err(),
            EscalationRefusal::WildcardRegistrationCap
        );
        assert_eq!(
            wildcard_registration_count(&h.grants.rules.lock().unwrap()),
            2
        );
    }

    /// A ceremony that fails or aborts after the approval releases the slot, whichever way it
    /// ends: dropped without a write, a refused write, or a failed store.
    #[test]
    fn a_failed_or_aborted_wildcard_registration_releases_its_cap_slot() {
        let h = harness();
        h.grants
            .rules
            .lock()
            .unwrap()
            .push(wildcard_grant("stored.example"));
        let second = capped_wildcard_register("b.example", 2);

        // Aborted: the ceremony returns without recording a grant.
        let approval = approved_wildcard_registration(&h, "a.example");
        assert!(h.service.precheck(&second).is_err());
        drop(approval);
        assert!(
            h.service.precheck(&second).is_ok(),
            "the slot is free again"
        );

        // The store fails: the slot is released and nothing is stored.
        let approval = approved_wildcard_registration(&h, "c.example");
        assert!(h.service.precheck(&second).is_err());
        h.grants.fail_writes.store(true, Ordering::SeqCst);
        assert!(
            h.service
                .record_registration_grant(
                    &approval,
                    CredentialRef::with_default_domain(b"c"),
                    64,
                    2
                )
                .is_err()
        );
        h.grants.fail_writes.store(false, Ordering::SeqCst);
        assert!(h.service.precheck(&second).is_ok());
        assert_eq!(
            wildcard_registration_count(&h.grants.rules.lock().unwrap()),
            1
        );

        // A panic in the ceremony after the approval unwinds the approval and frees the slot.
        let approval = approved_wildcard_registration(&h, "d.example");
        assert!(h.service.precheck(&second).is_err());
        let unwound = panic::catch_unwind(AssertUnwindSafe(move || {
            let _held = approval;
            panic!("ceremony failed after the approval");
        }));
        assert!(unwound.is_err());
        assert!(h.service.precheck(&second).is_ok());
    }

    /// `granted_rule.add` is audited only for a grant the store takes: a cap that refuses the
    /// grant is caught before the record is written (review L2).
    #[test]
    fn a_grant_the_cap_refuses_is_never_audited_as_added() {
        let h = harness();
        h.grants
            .rules
            .lock()
            .unwrap()
            .push(wildcard_grant("stored.example"));
        let approval = approved_wildcard_registration(&h, "a.example");
        // The operator lowered the cap while the ceremony was in flight.
        assert_eq!(
            h.service
                .record_registration_grant(
                    &approval,
                    CredentialRef::with_default_domain(b"c"),
                    64,
                    1
                )
                .unwrap_err(),
            GrantStoreError::WildcardCapReached(1)
        );
        assert_eq!(h.audit.count("granted_rule.add"), 0);
        assert_eq!(
            h.audit.last("escalation.denied")["cause"],
            "grant_write_failed"
        );
        assert_eq!(
            wildcard_registration_count(&h.grants.rules.lock().unwrap()),
            1,
            "no grant was stored"
        );
        assert!(
            h.service
                .precheck(&capped_wildcard_register("b.example", 2))
                .is_ok()
        );
    }

    /// A check that read the stored grants before a reservation was released and the reservation
    /// count after it must not undercount the grant written in between.
    #[test]
    fn a_stale_stored_count_is_corrected_by_the_release_epoch() {
        let h = harness();
        h.grants
            .rules
            .lock()
            .unwrap()
            .push(wildcard_grant("stored.example"));
        let approval = approved_wildcard_registration(&h, "a.example");
        // A checker reads the epoch and the stored count (1) ...
        let epoch = h.service.lock().reservation_epoch.load(Ordering::SeqCst);
        // ... then the grant is written and the slot released ...
        h.service
            .record_registration_grant(&approval, CredentialRef::with_default_domain(b"c"), 64, 2)
            .unwrap();
        // ... before the checker reads the live count: the stale 1 would admit a third grant.
        let mut inner = h.service.lock();
        assert_eq!(
            inner.check_wildcard_registration(
                &capped_wildcard_register("b.example", 2),
                StoredWildcards { count: 1, epoch },
                at(1_000)
            ),
            Err(EscalationRefusal::WildcardRegistrationCap)
        );
    }

    #[test]
    fn wildcard_registration_prompts_are_limited_per_rolling_day() {
        let h = harness();
        let limited = |rp: &str, session: usize| EscalationRequest {
            wildcard_registration_prompts_per_day: 2,
            ..wildcard_register("p", rp, session)
        };
        // Two prompts shown (and approved, so no cooldown starts).
        for rp in ["a.example", "b.example"] {
            let parked = park(h.service.join_or_create(limited(rp, 1)).unwrap());
            h.clock.advance(Duration::from_secs(5));
            h.service
                .prompt_event(&h.prompter.last_shown(), PromptEvent::Approved);
            assert!(matches!(
                parked.join().unwrap(),
                EscalationOutcome::RegistrationApproved(_)
            ));
        }
        assert_eq!(
            h.service
                .join_or_create(limited("c.example", 1))
                .unwrap_err(),
            EscalationRefusal::WildcardRegistrationRate
        );
        assert_eq!(h.prompter.shown().len(), 2, "refused without a prompt");
        // Exact-rule registration prompts do not count and are not limited.
        assert!(h.service.precheck(&register("p", "c.example", 1)).is_ok());
        // Another profile has its own window.
        assert!(
            h.service
                .precheck(&limited("c.example", 1).clone_for("q"))
                .is_ok()
        );

        // The window rolls: 24 hours after the first prompt (shown 10 s ago) one slot is free.
        h.clock
            .advance(WILDCARD_PROMPT_WINDOW - Duration::from_secs(11));
        assert_eq!(
            h.service.precheck(&limited("c.example", 1)).unwrap_err(),
            EscalationRefusal::WildcardRegistrationRate
        );
        h.clock.advance(Duration::from_secs(1));
        assert!(h.service.precheck(&limited("c.example", 1)).is_ok());
    }

    #[test]
    fn queued_wildcard_registrations_count_against_the_daily_limit() {
        let h = harness();
        // An exact sign-in prompt holds the profile's prompt slot, so the next ones queue.
        let _active = h
            .service
            .join_or_create(request("p", "active.example", 1))
            .unwrap();
        let limited = |rp: &str, session: usize| EscalationRequest {
            wildcard_registration_prompts_per_day: 2,
            ..wildcard_register("p", rp, session)
        };
        let _first = h.service.join_or_create(limited("a.example", 2)).unwrap();
        let _second = h.service.join_or_create(limited("b.example", 3)).unwrap();
        assert_eq!(h.service.queued(&profile("p")), 2);
        assert_eq!(
            h.service.precheck(&limited("c.example", 4)).unwrap_err(),
            EscalationRefusal::WildcardRegistrationRate
        );
    }

    #[test]
    fn a_denied_wildcard_registration_starts_a_profile_wide_cooldown() {
        let h = harness();
        let parked = park(
            h.service
                .join_or_create(wildcard_register("p", "a.example", 1))
                .unwrap(),
        );
        h.service.prompt_event(
            &h.prompter.last_shown(),
            PromptEvent::Denied(EscalationDenyCause::User),
        );
        assert!(matches!(
            parked.join().unwrap(),
            EscalationOutcome::Denied { .. }
        ));
        // The key's own cooldown, and every other wildcard registration of the profile.
        assert_eq!(
            h.service
                .join_or_create(wildcard_register("p", "a.example", 1))
                .unwrap_err(),
            EscalationRefusal::Cooldown
        );
        assert_eq!(
            h.service
                .join_or_create(wildcard_register("p", "rotated.example", 1))
                .unwrap_err(),
            EscalationRefusal::WildcardRegistrationCooldown
        );
        assert_eq!(h.prompter.shown().len(), 1, "refused without a prompt");
        // Exact-rule registrations, wildcard sign-ins and other profiles are unaffected.
        assert!(
            h.service
                .precheck(&register("p", "exact.example", 1))
                .is_ok()
        );
        let wildcard_sign_in = EscalationRequest {
            rule: PermittingRule::Wildcard,
            ..request("p", "rotated.example", 1)
        };
        assert!(h.service.precheck(&wildcard_sign_in).is_ok());
        assert!(
            h.service
                .precheck(&wildcard_register("q", "rotated.example", 1))
                .is_ok()
        );

        // It lasts `agents.escalation_cooldown`.
        h.clock.advance(COOLDOWN - Duration::from_millis(1));
        assert_eq!(
            h.service
                .precheck(&wildcard_register("p", "rotated.example", 1))
                .unwrap_err(),
            EscalationRefusal::WildcardRegistrationCooldown
        );
        h.clock.advance(Duration::from_millis(1));
        assert!(
            h.service
                .precheck(&wildcard_register("p", "rotated.example", 1))
                .is_ok()
        );
    }

    #[test]
    fn an_exact_registration_deny_starts_no_profile_wide_cooldown() {
        let h = harness();
        let parked = park(
            h.service
                .join_or_create(register("p", "exact.example", 1))
                .unwrap(),
        );
        h.service.prompt_event(
            &h.prompter.last_shown(),
            PromptEvent::Denied(EscalationDenyCause::User),
        );
        parked.join().unwrap();
        assert!(
            h.service
                .precheck(&wildcard_register("p", "a.example", 1))
                .is_ok()
        );
    }

    #[test]
    fn a_timed_out_wildcard_registration_starts_the_profile_wide_cooldown() {
        let h = harness();
        let waiter = h
            .service
            .join_or_create(wildcard_register("p", "a.example", 1))
            .unwrap();
        let deadline = Instant::now() + Duration::from_millis(300);
        let outcome = park_until(waiter, deadline, Arc::new(AtomicBool::new(false)))
            .join()
            .unwrap();
        assert!(matches!(outcome, EscalationOutcome::TimedOut));
        assert_eq!(
            h.service
                .precheck(&wildcard_register("p", "b.example", 1))
                .unwrap_err(),
            EscalationRefusal::WildcardRegistrationCooldown
        );
    }

    #[test]
    fn the_third_wildcard_registration_withdrawal_starts_the_profile_wide_cooldown() {
        let h = harness();
        let roomy = |rp: &str| EscalationRequest {
            wildcard_registration_prompts_per_day: 24,
            ..wildcard_register("p", rp, 1)
        };
        for n in 1..=3 {
            drop(h.service.join_or_create(roomy("a.example")).unwrap());
            let cooled = h.service.precheck(&roomy("b.example"));
            if n < 3 {
                assert!(cooled.is_ok(), "after withdrawal {n}: {cooled:?}");
            } else {
                assert_eq!(
                    cooled.unwrap_err(),
                    EscalationRefusal::WildcardRegistrationCooldown
                );
            }
            h.clock.advance(Duration::from_secs(60));
        }
    }

    #[test]
    fn wildcard_registration_refusals_follow_the_amendment_order() {
        // Cap, then daily limit, then the profile-wide cooldown (amendment section 2.3).
        let mut inner = Inner::default();
        let now = at(1_000);
        let req = EscalationRequest {
            max_wildcard_registrations: 1,
            wildcard_registration_prompts_per_day: 1,
            ..wildcard_register("p", "a.example", 1)
        };
        inner.start_wildcard_cooldown(&profile("p"), now, COOLDOWN);
        inner
            .wildcard_prompts
            .entry(profile("p"))
            .or_default()
            .push_back(now);
        assert_eq!(
            inner.check_wildcard_registration(&req, StoredWildcards { count: 1, epoch: 0 }, now),
            Err(EscalationRefusal::WildcardRegistrationCap)
        );
        assert_eq!(
            inner.check_wildcard_registration(&req, StoredWildcards { count: 0, epoch: 0 }, now),
            Err(EscalationRefusal::WildcardRegistrationRate)
        );
        let roomy = EscalationRequest {
            wildcard_registration_prompts_per_day: 2,
            ..req.clone()
        };
        assert_eq!(
            inner.check_wildcard_registration(&roomy, StoredWildcards { count: 0, epoch: 0 }, now),
            Err(EscalationRefusal::WildcardRegistrationCooldown)
        );
        // Not a wildcard registration: never refused by these checks.
        assert_eq!(
            inner.check_wildcard_registration(
                &register("p", "a.example", 1),
                StoredWildcards {
                    count: 99,
                    epoch: 0
                },
                now
            ),
            Ok(())
        );
    }

    #[test]
    fn an_unavailable_grant_store_refuses_a_wildcard_registration() {
        let h = harness();
        h.grants.unavailable.store(true, Ordering::SeqCst);
        assert_eq!(
            h.service
                .precheck(&wildcard_register("p", "a.example", 1))
                .unwrap_err(),
            EscalationRefusal::GrantsUnavailable
        );
    }

    impl EscalationRequest {
        fn clone_for(&self, profile_name: &str) -> Self {
            Self {
                profile: profile(profile_name),
                ..self.clone()
            }
        }
    }
}
