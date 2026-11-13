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
//! - Pre-requests (ADR 0014 amendment section 2.3): a principal may ask before it navigates
//!   ([`EscalationService::pre_request`]). The request passes exactly the admission of a
//!   ceremony for the same key and then waits as a *detached* waiter: it holds a waiter slot of
//!   its principal session but no thread, and its own deadline
//!   ([`PRE_REQUEST_PENDING_LIMIT`], or `agents.escalation_timeout` if shorter) is enforced by
//!   [`EscalationService::sweep_pre_requests`], by the requester's own wait and by every later
//!   call. Its expiry is a timeout of the key (cooldown). Repeating the request from the same
//!   principal session reports its state instead of raising another. Per principal session at
//!   most [`MAX_PENDING_PRE_REQUESTS`] is pending and at most [`MAX_PRE_REQUESTS_PER_WINDOW`] are
//!   raised per [`PRE_REQUEST_WINDOW`]; per profile, across all its principal sessions (the
//!   out-of-session CLI starts a new one for every call), at most
//!   [`MAX_PENDING_PRE_REQUESTS_PER_PROFILE`] are pending and at most
//!   [`MAX_PRE_REQUESTS_PER_PROFILE_WINDOW`] are raised per window.
//!   - `authenticate`: ceremonies of the key join the pre-request's escalation as usual, and a
//!     pre-request joins a ceremony's. The approval persists the same grant a ceremony-time
//!     approval would, with `source = "pre_request"` and no origin.
//!   - `register`: the escalation is not joinable and is bound to the requesting principal
//!     session. The first registration ceremony at the RP from a bearer session owned by that
//!     principal session (through its session grant) *adopts* it while it is queued or shown and
//!     waits on it as its creator; any other registration of the key gets `escalation_busy`. An
//!     approval nobody adopted becomes a [`PreApprovalToken`]: one use, in memory, bound to the
//!     profile, the RP, the principal session, the revocation epoch and the RP's revoke token,
//!     for [`PRE_APPROVAL_TTL`] at most (and never beyond the principal session). The first
//!     registration ceremony of that principal session at that RP consumes it
//!     ([`EscalationService::take_pre_approval`]) and continues as if its own escalation had been
//!     approved. A token is dropped on its TTL, the end of its principal session, the revocation
//!     of a browser lease of that session, a revocation-epoch bump, `grants revoke` for its RP
//!     and `grants clear`; each drop is audited as `pre_approval.expired`. A token holds its
//!     wildcard cap slot (review L2) until it is consumed and the grant is written, or dropped.
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

use passless_core::agent::{AgentMode, CredentialRef, PrincipalSessionId, ProfileId};

use super::audit::AuditGate;
use super::audit_events::{
    AuditAction, AuditEvent, EscalationAuditContext, EscalationDenyCause, EscalationExpireReason,
    EscalationRevokeReason, GrantedRuleAddBuilder, GrantedRuleRevokeBuilder, PolicyDenyReason,
    PreApprovalExpireReason, PreApprovalMeta,
};
use super::escalation_prompt::{PromptFields, PromptRule, PromptVerb};
use super::granted_rules::{
    GrantKind, GrantStoreError, GrantedRule, GrantedRulesStore, PermittingRule, ProfileGrants,
    RequestSource, RevokeToken, wildcard_registration_count,
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
/// Longest a pre-request stays pending (ADR 0014 amendment section 2.3; `agents.escalation_timeout`
/// shortens it).
pub const PRE_REQUEST_PENDING_LIMIT: Duration = Duration::from_secs(600);
/// Longest a pre-approval waits for its registration ceremony (amendment section 2.3; the
/// principal session's own end shortens it).
pub const PRE_APPROVAL_TTL: Duration = Duration::from_secs(600);
/// Pending pre-requests per principal session.
pub const MAX_PENDING_PRE_REQUESTS: usize = 1;
/// Pre-requests a principal session may raise per [`PRE_REQUEST_WINDOW`].
pub const MAX_PRE_REQUESTS_PER_WINDOW: usize = 6;
/// Pending pre-requests per profile, across all its principal sessions. The per-session limits
/// do not bound the out-of-session CLI, which starts a fresh principal session for every call.
pub const MAX_PENDING_PRE_REQUESTS_PER_PROFILE: usize = 3;
/// Pre-requests a profile may raise per [`PRE_REQUEST_WINDOW`], across all its principal
/// sessions.
pub const MAX_PRE_REQUESTS_PER_PROFILE_WINDOW: usize = 12;
/// The window of [`MAX_PRE_REQUESTS_PER_WINDOW`] and [`MAX_PRE_REQUESTS_PER_PROFILE_WINDOW`]; also
/// how long an unreported pre-request outcome is kept for its requester.
pub const PRE_REQUEST_WINDOW: Duration = Duration::from_secs(600);

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

/// The session a waiter belongs to (for the per-session waiter cap): a ceremony's bearer
/// session, or the principal session of a pre-request.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum WaiterSession {
    Bearer(usize),
    Principal(u64),
}

impl WaiterSession {
    /// The session behind a bearer.
    pub fn of(session: &Arc<AgentSession>) -> Self {
        Self::Bearer(Arc::as_ptr(session) as usize)
    }

    /// A principal session's tag (a pre-request's waiter slot).
    pub fn of_principal(session: &PrincipalSessionId) -> Self {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        session.as_str().hash(&mut hasher);
        Self::Principal(hasher.finish())
    }

    /// A session tag from a raw value (tests and callers without an `AgentSession`).
    pub fn from_raw(raw: usize) -> Self {
        Self::Bearer(raw)
    }
}

/// One ceremony's escalation request. Every field is daemon-derived.
#[derive(Clone, Debug)]
pub struct EscalationRequest {
    pub profile: ProfileId,
    /// The normalized RP ID.
    pub rp_id: String,
    pub action: CeremonyAction,
    /// The validated origin of the ceremony; `None` for a pre-request (no page yet).
    pub origin: Option<String>,
    /// The configured rule that resolved to `request`.
    pub rule: PermittingRule,
    pub session: WaiterSession,
    /// Who asks: a ceremony, or the agent in advance (ADR 0014 amendment section 2.3).
    pub source: RequestSource,
    /// The principal session behind the request: the requester of a pre-request, or the owner
    /// of a ceremony's bearer session through its session grant (`None` when it has none). A
    /// pre-register escalation is adoptable, and a pre-approval consumable, only by ceremonies
    /// of this principal session.
    pub principal: Option<PrincipalSessionId>,
    /// A pre-request's agent note, already sanitized and bounded: written to
    /// `escalation.requested` only, never shown in a prompt.
    pub agent_note: Option<String>,
    pub mode: AgentMode,
    pub principal_user: String,
    /// The profile's live `max_granted_rules`.
    pub max_granted_rules: usize,
    /// The profile's live `max_wildcard_registrations` (read for a wildcard registration only).
    pub max_wildcard_registrations: usize,
    /// The profile's live `wildcard_registration_prompts_per_day` (likewise).
    pub wildcard_registration_prompts_per_day: usize,
    /// Registration only: how to count the target store's passkeys for the RP when the prompt is
    /// shown (review L4), so a queued prompt shows the count of its own moment, not of the
    /// moment it was raised. The count goes to the human only, never to the agent.
    pub store_counter: Option<Arc<dyn StoreCounter>>,
}

/// Counts the passkeys a store holds for an RP, from metadata alone (never decrypting). Asked
/// when a registration prompt is shown, with no escalation lock held, so an implementation may
/// take the store's own lock for the count and nothing longer.
pub trait StoreCounter: fmt::Debug + Send + Sync {
    /// `None` when the count cannot be made: the prompt then omits the count clause.
    fn count_for_rp(&self, rp_id: &str) -> Option<usize>;
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

    /// The `escalation.*` context of `escalation_id` raised by this request.
    fn audit_context(&self, escalation_id: &EscalationId) -> EscalationAuditContext {
        EscalationAuditContext {
            escalation_id: escalation_id.as_str().to_string(),
            profile_id: self.profile.clone(),
            action: self.audit_action(),
            rp_id: self.rp_id.clone(),
            origin: self.origin.clone(),
            rule: self.rule,
            source: self.source,
            principal: self.principal.clone(),
            agent_note: self.agent_note.clone(),
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
            // A ceremony that adopted the pre-request has a page: the prompt names its origin
            // and no longer says that nothing is waiting.
            requested_in_advance: self.source == RequestSource::PreRequest && self.origin.is_none(),
            rule: match self.rule {
                PermittingRule::Exact => PromptRule::Exact,
                PermittingRule::Wildcard => PromptRule::Wildcard,
            },
            // Filled in when the prompt is shown, see `EscalationService::run`.
            store_count: None,
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
    /// A pre-request beyond its principal session's limits (found under the admission mutex,
    /// when a concurrent pre-request of the same session got there first).
    PreRequestRateLimited,
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
            Self::PreRequestRateLimited => PolicyDenyReason::PreRequestRateLimited,
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
    /// The origin of the ceremony that registers. `None` only while the approval waits in a
    /// [`PreApprovalToken`]: consumption sets the consuming ceremony's.
    origin: Option<String>,
    rule: PermittingRule,
    session: WaiterSession,
    /// Who raised the approved escalation.
    source: RequestSource,
    /// The principal session the approval is bound to, when known (always for a pre-request).
    principal: Option<PrincipalSessionId>,
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

    pub fn origin(&self) -> Option<&str> {
        self.origin.as_deref()
    }

    pub fn rule(&self) -> PermittingRule {
        self.rule
    }

    pub fn session(&self) -> WaiterSession {
        self.session
    }

    pub fn source(&self) -> RequestSource {
        self.source
    }

    /// The principal session the approval is bound to, when known.
    pub fn principal(&self) -> Option<&PrincipalSessionId> {
        self.principal.as_ref()
    }

    /// The `escalation.*` context of this approval's escalation.
    pub fn audit_context(&self) -> EscalationAuditContext {
        EscalationAuditContext {
            escalation_id: self.escalation_id.as_str().to_string(),
            profile_id: self.profile.clone(),
            action: AuditAction::Register,
            rp_id: self.rp_id.clone(),
            origin: self.origin.clone(),
            rule: self.rule,
            source: self.source,
            principal: self.principal.clone(),
            agent_note: None,
        }
    }
}

/// A registration pre-approval (ADR 0014 amendment section 2.3): the approval of a `register`
/// pre-request that no ceremony adopted while it was pending. In memory only, never persisted,
/// deliberately not `Clone`. It is bound to the profile, the normalized RP ID, the principal
/// session, the revocation epoch at issue and (through the approval) the RP's revoke token, and
/// it holds the approval's wildcard cap slot until it is consumed or dropped. Only
/// [`EscalationService::take_pre_approval`] turns it into a ceremony's [`RegistrationApproval`].
#[derive(Debug)]
pub struct PreApprovalToken {
    approval: RegistrationApproval,
    principal: PrincipalSessionId,
    /// The revocation epoch when the token was issued: a bump drops it.
    revocation_epoch: u64,
    expires_at: MonotonicTime,
}

impl PreApprovalToken {
    fn meta(&self) -> PreApprovalMeta {
        PreApprovalMeta::new(
            self.approval.escalation_id.as_str(),
            self.approval.profile.clone(),
            &self.approval.rp_id,
            self.approval.rule,
            &self.principal,
        )
    }

    /// Why the token can no longer be used at `now` under `epoch`, if it cannot.
    fn invalid(&self, now: MonotonicTime, epoch: u64) -> Option<PreApprovalExpireReason> {
        if epoch != self.revocation_epoch {
            Some(PreApprovalExpireReason::PolicyReload)
        } else if now >= self.expires_at {
            Some(PreApprovalExpireReason::Ttl)
        } else {
            None
        }
    }
}

/// The state of a pre-request as its requester sees it (ADR 0014 amendment section 2.3). It never
/// says whether the user holds a credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreRequestState {
    /// The human has not decided yet.
    Pending,
    /// A registration ceremony of the same principal session took the request over and waits on
    /// it; the outcome goes to that ceremony.
    Adopted,
    /// `authenticate`: approved; the grant is persisted.
    Approved,
    /// `register`: approved; a one-use pre-approval waits this long for the principal session's
    /// next registration at the RP.
    PreApproved { expires_in: Duration },
    /// Denied. `reason` is set when the deny was not the human's (a failed prompt, audit or grant
    /// write).
    Denied { reason: Option<PolicyDenyReason> },
    /// Ended without a decision (its deadline, or the notification server went away).
    Expired,
    /// Cancelled by a policy reload or a granted-rule revocation.
    Revoked,
    /// Not admitted; nothing was prompted.
    Refused(EscalationRefusal),
    /// Over the principal session's pre-request limits; nothing was prompted. `retry_after` is
    /// when the window frees a slot, when that is what limits it.
    RateLimited { retry_after: Option<Duration> },
}

/// Who consumes a pre-approval: a registration ceremony at the point where it would raise its
/// own escalation.
#[derive(Clone, Copy, Debug)]
pub struct PreApprovalConsumer<'a> {
    pub profile: &'a ProfileId,
    /// The normalized RP ID of the registration.
    pub rp_id: &'a str,
    /// The principal session that owns the ceremony's bearer session (through its session
    /// grant).
    pub principal: &'a PrincipalSessionId,
    /// The rule the registration resolved through now (`request`).
    pub rule: PermittingRule,
    /// The ceremony's bearer session: the approval is bound to it from here on.
    pub session: WaiterSession,
    /// The ceremony's validated origin (the grant records it).
    pub origin: &'a str,
    /// The ceremony's `request_id` (`pre_approval.consumed` names it).
    pub request_id: &'a str,
}

/// What a pre-request needs besides its [`EscalationRequest`].
#[derive(Clone, Debug)]
pub struct PreRequestParams {
    /// `source = PreRequest`, `origin = None`, `principal = Some(..)`, and the principal
    /// session's [`WaiterSession::of_principal`].
    pub request: EscalationRequest,
    /// How long it may stay pending: [`PRE_REQUEST_PENDING_LIMIT`], or `agents.escalation_timeout`
    /// if shorter.
    pub pending_for: Duration,
    /// What is left of the principal session's lifetime: a pre-approval never outlives it.
    pub session_remaining: Duration,
}

/// Where a pre-request is.
#[derive(Debug)]
enum PreStatus {
    /// Its detached waiter is attached to the escalation.
    Pending,
    /// A registration ceremony adopted the escalation.
    Adopted,
    /// A `register` approval nobody adopted, whose `pre_approval.issued` record is not written
    /// yet: not usable. `dropped` is set when something that drops a token (session end, lease
    /// revocation, a policy change) happened meanwhile; the issuing step then records the drop
    /// right after `issued`.
    Issuing {
        token: Box<PreApprovalToken>,
        dropped: Option<PreApprovalExpireReason>,
    },
    /// A `register` approval nobody adopted, issued (audited) and usable.
    Token(Box<PreApprovalToken>),
    /// Ended; reported once to the requester, then forgotten.
    Settled(PreRequestState),
}

/// One principal session's pre-request for one key.
#[derive(Debug)]
struct PreRequestRecord {
    serial: u64,
    /// The detached waiter while it is attached.
    waiter: Option<u64>,
    /// When it stops waiting (and its key's cooldown starts).
    deadline: MonotonicTime,
    /// When its principal session ends: a pre-approval never outlives it.
    session_ends: MonotonicTime,
    /// When it settled (unreported outcomes are dropped after [`PRE_REQUEST_WINDOW`]).
    settled_at: Option<MonotonicTime>,
    status: PreStatus,
}

/// A pre-request's key: its principal session and its escalation key.
type PreRequestKey = (PrincipalSessionId, EscalationKey);

/// The live revocation epoch (ADR 0014 section 6.4), read when a pre-approval is issued and
/// whenever one is checked.
pub trait RevocationEpoch: Send + Sync {
    fn current(&self) -> u64;
}

impl RevocationEpoch for PolicyRuntime {
    fn current(&self) -> u64 {
        self.revocation_epoch()
    }
}

/// How a wait ended.
#[derive(Debug)]
pub enum EscalationOutcome {
    /// An `authenticate` escalation was approved and its grant persisted: re-resolve. `source`
    /// says who raised it (a ceremony, or a pre-request the ceremony joined).
    Approved {
        escalation_id: EscalationId,
        source: RequestSource,
    },
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
    /// The live revocation epoch, which binds a pre-approval.
    pub epoch: Arc<dyn RevocationEpoch>,
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
    /// A `register` pre-request's escalation: the principal session whose registration ceremony
    /// may adopt it. Cleared on adoption.
    adoptable_by: Option<PrincipalSessionId>,
}

impl Entry {
    fn audit_context(&self) -> EscalationAuditContext {
        self.request.audit_context(&self.id)
    }

    /// Whether a ceremony of `request` may adopt this `register` pre-request: the same principal
    /// session, a registration ceremony, and the escalation still queued or shown (not being
    /// decided).
    fn adoptable(&self, request: &EscalationRequest) -> bool {
        request.source == RequestSource::Ceremony
            && request.action == CeremonyAction::Register
            && self.adoptable_by.is_some()
            && self.adoptable_by == request.principal
            && matches!(
                self.state,
                EscalationState::Queued | EscalationState::Prompting
            )
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
    /// Pre-requests by principal session and key (ADR 0014 amendment section 2.3). Bounded: a
    /// principal session has at most [`MAX_PENDING_PRE_REQUESTS`] pending and raises at most
    /// [`MAX_PRE_REQUESTS_PER_WINDOW`] per window, and a profile has at most
    /// [`MAX_PENDING_PRE_REQUESTS_PER_PROFILE`] pending and raises at most
    /// [`MAX_PRE_REQUESTS_PER_PROFILE_WINDOW`] per window across its sessions; settled ones are dropped once reported or after
    /// the window, and all of a session's go when it ends.
    pre_requests: HashMap<PreRequestKey, PreRequestRecord>,
    /// When each principal session raised its recent pre-requests (the rate window).
    pre_request_history: HashMap<PrincipalSessionId, VecDeque<MonotonicTime>>,
    /// When each profile raised its recent pre-requests, across all its principal sessions (the
    /// profile's rate window). At most [`MAX_PRE_REQUESTS_PER_PROFILE_WINDOW`] per profile;
    /// unlike a session's, it survives the end of the session that raised them.
    pre_request_profile_history: HashMap<ProfileId, VecDeque<MonotonicTime>>,
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

/// What admission decided for a request whose key may have a live entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Admission {
    /// Create a new escalation.
    Create,
    /// Join the live `authenticate` escalation.
    Join(u64),
    /// Adopt the live `register` pre-request of the ceremony's own principal session.
    Adopt(u64),
}

/// Deferred side effects, run after the mutex is released.
enum Effect {
    Audit(AuditEvent),
    /// Record `pre_approval.issued` of the pre-approval in `Issuing` state at this key and only
    /// then make it usable ([`EscalationService::issue_token`]).
    Issue(PreRequestKey, AuditEvent),
    /// Show a prompt; a registration's count is taken just before it is rendered (review L4).
    Show(PromptTicket, PromptFields, Option<Arc<dyn StoreCounter>>),
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

    /// The live `register` pre-request of `request`'s key that `request` may adopt, if any.
    fn adoptable(&self, request: &EscalationRequest) -> Option<u64> {
        let serial = *self.by_key.get(&request.key())?;
        self.entries
            .get(&serial)
            .is_some_and(|entry| entry.adoptable(request))
            .then_some(serial)
    }

    /// Admission of `request` under the mutex. `stored` is the profile's stored wildcard
    /// registration grants. An adoption takes over an escalation that was admitted (and counted
    /// against the wildcard limits) already, so those limits are not counted again for it.
    fn admit(
        &mut self,
        request: &EscalationRequest,
        key: &EscalationKey,
        now: MonotonicTime,
        stored: StoredWildcards,
    ) -> Result<Admission, EscalationRefusal> {
        if self.in_cooldown(key, now) {
            return Err(EscalationRefusal::Cooldown);
        }
        if let Some(serial) = self.adoptable(request) {
            self.check_waiter_caps(&request.profile, request.session)?;
            return Ok(Admission::Adopt(serial));
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
            return Ok(Admission::Join(serial));
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
        Ok(Admission::Create)
    }

    /// A registration ceremony of `request` adopts the `register` pre-request `serial` (admission
    /// checked [`Entry::adoptable`]): it becomes the escalation's creator, with its own session
    /// and origin, so the approval is bound to it; the pre-request's detached waiter leaves
    /// without ending the entry (the ceremony's waiter is attached right after).
    fn adopt(&mut self, serial: u64, request: &EscalationRequest) {
        let Some(entry) = self.entries.get_mut(&serial) else {
            return;
        };
        entry.adoptable_by = None;
        entry.request.session = request.session;
        entry.request.origin = request.origin.clone();
        info!(
            "escalation {}: adopted by a registration ceremony of its principal session",
            entry.id
        );
        let detached: Vec<(PreRequestKey, Option<u64>)> = self
            .pre_requests
            .iter_mut()
            .filter(|(_, record)| {
                record.serial == serial && matches!(record.status, PreStatus::Pending)
            })
            .map(|(key, record)| {
                record.status = PreStatus::Adopted;
                (key.clone(), record.waiter.take())
            })
            .collect();
        for (_, waiter) in detached {
            if let Some(waiter) = waiter {
                self.remove_waiter(serial, waiter);
            }
        }
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
                let counter = match entry.request.action {
                    CeremonyAction::Register => entry.request.store_counter.clone(),
                    CeremonyAction::Authenticate => None,
                };
                effects.push(Effect::Show(ticket, entry.request.prompt_fields(), counter));
            }
        }
    }

    /// A waiter leaves. When it was the last one of a pending entry, the entry ends: dequeued or
    /// withdrawn, audited as expired, and counted for V-M2 (an abort) or put in cooldown (a
    /// timeout).
    #[allow(clippy::too_many_arguments)]
    fn depart(
        &mut self,
        serial: u64,
        waiter: u64,
        departure: Departure,
        now: MonotonicTime,
        cooldown: Duration,
        epoch: u64,
        effects: &mut Vec<Effect>,
    ) {
        let Some(remaining) = self.remove_waiter(serial, waiter) else {
            return;
        };
        if remaining == 0
            && let Some(entry) = self.entries.get_mut(&serial)
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
            self.unlink(serial);
            match departure {
                Departure::Timeout => self.start_cooldowns(&request, now, cooldown),
                Departure::Aborted => self.record_withdrawal_of(&request, now, cooldown),
            }
            self.settle_pre_requests(serial, now, epoch, effects);
            self.pump(&profile, now, effects);
        }
        self.collect(serial);
    }

    /// The pre-requests waiting on `serial` learn its outcome once it is terminal: a detached
    /// waiter is detached, an adopted pre-request is forgotten (its ceremony has the outcome),
    /// and a `register` approval nobody adopted becomes a [`PreApprovalToken`] bound to `epoch`.
    fn settle_pre_requests(
        &mut self,
        serial: u64,
        now: MonotonicTime,
        epoch: u64,
        effects: &mut Vec<Effect>,
    ) {
        if !self
            .entries
            .get(&serial)
            .is_some_and(|entry| entry.state.is_terminal())
        {
            return;
        }
        let keys: Vec<PreRequestKey> = self
            .pre_requests
            .iter()
            .filter(|(_, record)| {
                record.serial == serial
                    && matches!(record.status, PreStatus::Pending | PreStatus::Adopted)
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in keys {
            let Some(mut record) = self.pre_requests.remove(&key) else {
                continue;
            };
            if matches!(record.status, PreStatus::Adopted) {
                continue;
            }
            if let Some(waiter) = record.waiter.take() {
                self.remove_waiter(serial, waiter);
            }
            let Some(entry) = self.entries.get_mut(&serial) else {
                continue;
            };
            let state = match entry.outcome.as_mut() {
                Some(EntryOutcome::Approved) => PreRequestState::Approved,
                Some(EntryOutcome::Registration(slot)) => match slot.take() {
                    Some(approval) => {
                        let expires_at = later(now, PRE_APPROVAL_TTL).min(record.session_ends);
                        let token = PreApprovalToken {
                            approval,
                            principal: key.0.clone(),
                            revocation_epoch: epoch,
                            expires_at,
                        };
                        let ttl_secs = expires_at.saturating_duration_since(now) / 1000;
                        // Usable only once `pre_approval.issued` is written (review N1): the
                        // record waits in `Issuing`, which the requester sees as pending.
                        effects.push(Effect::Issue(key.clone(), token.meta().issued(ttl_secs)));
                        info!(
                            "escalation {}: registration pre-approved for {}/{} ({} s)",
                            token.approval.escalation_id, key.1.profile, key.1.rp_id, ttl_secs
                        );
                        record.status = PreStatus::Issuing {
                            token: Box::new(token),
                            dropped: None,
                        };
                        record.settled_at = Some(now);
                        self.pre_requests.insert(key, record);
                        continue;
                    }
                    // Not reachable (a pre-register escalation has no other waiter); fail closed.
                    None => PreRequestState::Denied {
                        reason: Some(PolicyDenyReason::EscalationBusy),
                    },
                },
                Some(EntryOutcome::Denied { reason, .. }) => {
                    PreRequestState::Denied { reason: *reason }
                }
                Some(EntryOutcome::Revoked) => PreRequestState::Revoked,
                Some(EntryOutcome::ServerLost) | Some(EntryOutcome::Expired) | None => {
                    PreRequestState::Expired
                }
            };
            record.status = PreStatus::Settled(state);
            record.settled_at = Some(now);
            self.pre_requests.insert(key, record);
        }
    }

    /// Settle the pre-approval at `key` that is in `Issuing` state as if its `issued` record
    /// could not be written: no token (its wildcard cap slot is released), and the requester is
    /// told `unavailable`. A pre-approval that was already marked dropped is forgotten instead.
    fn refuse_issuing(&mut self, key: &PreRequestKey, now: MonotonicTime) {
        let Some(record) = self.pre_requests.get_mut(key) else {
            return;
        };
        if !matches!(record.status, PreStatus::Issuing { .. }) {
            return;
        }
        let PreStatus::Issuing { token, dropped } = std::mem::replace(
            &mut record.status,
            PreStatus::Settled(PreRequestState::Refused(EscalationRefusal::AuditFailure)),
        ) else {
            return;
        };
        record.settled_at = Some(now);
        if dropped.is_some() {
            self.pre_requests.remove(key);
        }
        // The token (and with it the wildcard cap slot) is dropped here.
        drop(token);
    }

    /// Drop the pre-approvals `matches` selects, auditing each as `pre_approval.expired` with
    /// `reason`.
    fn drop_tokens(
        &mut self,
        matches: impl Fn(&PreRequestKey) -> bool,
        reason: PreApprovalExpireReason,
        effects: &mut Vec<Effect>,
    ) {
        // A pre-approval whose `issued` record is still being written is marked: the issuing
        // step records the drop right after `issued`, so the audit shows both.
        for (key, record) in &mut self.pre_requests {
            if let PreStatus::Issuing { dropped, .. } = &mut record.status
                && dropped.is_none()
                && matches(key)
            {
                *dropped = Some(reason);
            }
        }
        let keys: Vec<PreRequestKey> = self
            .pre_requests
            .iter()
            .filter(|(key, record)| matches!(record.status, PreStatus::Token(_)) && matches(key))
            .map(|(key, _)| key.clone())
            .collect();
        for key in keys {
            if let Some(PreRequestRecord {
                status: PreStatus::Token(token),
                ..
            }) = self.pre_requests.remove(&key)
            {
                info!(
                    "escalation {}: pre-approval for {}/{} dropped ({:?})",
                    token.approval.escalation_id, key.1.profile, key.1.rp_id, reason
                );
                effects.push(Effect::Audit(token.meta().expired(reason)));
            }
        }
    }

    /// Whether `principal` may raise another pre-request in `profile` now. Per principal session:
    /// at most [`MAX_PENDING_PRE_REQUESTS`] pending and [`MAX_PRE_REQUESTS_PER_WINDOW`] per
    /// [`PRE_REQUEST_WINDOW`]. Per profile, across all its principal sessions: at most
    /// [`MAX_PENDING_PRE_REQUESTS_PER_PROFILE`] pending and
    /// [`MAX_PRE_REQUESTS_PER_PROFILE_WINDOW`] per window (the out-of-session CLI starts a fresh
    /// principal session for every call, so the session limits alone never bind it).
    fn pre_request_limit(
        &mut self,
        principal: &PrincipalSessionId,
        profile: &ProfileId,
        now: MonotonicTime,
    ) -> Option<PreRequestState> {
        let (session_pending, profile_pending) = self
            .pre_requests
            .iter()
            .filter(|(_, record)| matches!(record.status, PreStatus::Pending))
            .fold((0, 0), |(session, in_profile), ((owner, key), _)| {
                (
                    session + usize::from(owner == principal),
                    in_profile + usize::from(key.profile == *profile),
                )
            });
        if session_pending >= MAX_PENDING_PRE_REQUESTS
            || profile_pending >= MAX_PENDING_PRE_REQUESTS_PER_PROFILE
        {
            return Some(PreRequestState::RateLimited { retry_after: None });
        }
        let window = u64::try_from(PRE_REQUEST_WINDOW.as_millis()).unwrap_or(u64::MAX);
        let mut limited = None;
        if let Some(recent) = self.pre_request_history.get_mut(principal) {
            limited = window_limit(recent, MAX_PRE_REQUESTS_PER_WINDOW, window, now);
            if recent.is_empty() {
                self.pre_request_history.remove(principal);
            }
        }
        if let Some(recent) = self.pre_request_profile_history.get_mut(profile) {
            let profile_limited =
                window_limit(recent, MAX_PRE_REQUESTS_PER_PROFILE_WINDOW, window, now);
            if recent.is_empty() {
                self.pre_request_profile_history.remove(profile);
            }
            limited = limited.or(profile_limited);
        }
        limited
    }

    /// The state of `principal`'s pre-request for `key`, if it has one. A settled outcome is
    /// reported once and then forgotten; a pre-approval stays until it is used or dropped.
    fn report(
        &mut self,
        principal: &PrincipalSessionId,
        key: &EscalationKey,
        now: MonotonicTime,
    ) -> Option<PreRequestState> {
        let record_key = (principal.clone(), key.clone());
        let record = self.pre_requests.get(&record_key)?;
        match &record.status {
            // Not usable until its `issued` record is written.
            PreStatus::Pending | PreStatus::Issuing { .. } => Some(PreRequestState::Pending),
            PreStatus::Adopted => Some(PreRequestState::Adopted),
            PreStatus::Token(token) => Some(PreRequestState::PreApproved {
                expires_in: Duration::from_millis(token.expires_at.saturating_duration_since(now)),
            }),
            PreStatus::Settled(_) => match self.pre_requests.remove(&record_key) {
                Some(PreRequestRecord {
                    status: PreStatus::Settled(state),
                    ..
                }) => Some(state),
                _ => None,
            },
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

/// Drop the entries of `recent` older than `window` (milliseconds) and say whether it still
/// holds `limit` of them: the answer is then `RateLimited` with the time until the oldest ages
/// out.
fn window_limit(
    recent: &mut VecDeque<MonotonicTime>,
    limit: usize,
    window: u64,
    now: MonotonicTime,
) -> Option<PreRequestState> {
    while recent
        .front()
        .is_some_and(|at| now.saturating_duration_since(*at) >= window)
    {
        recent.pop_front();
    }
    if recent.len() < limit {
        return None;
    }
    let retry_after = recent.front().map(|oldest| {
        Duration::from_millis(window.saturating_sub(now.saturating_duration_since(*oldest)))
    });
    Some(PreRequestState::RateLimited { retry_after })
}

/// The escalation coordinator.
pub struct EscalationService {
    inner: Mutex<Inner>,
    changed: Condvar,
    audit: Arc<dyn EscalationAudit>,
    grants: Arc<dyn GrantWriter>,
    prompter: Arc<dyn Prompter>,
    clock: Arc<dyn MonotonicClock>,
    epoch: Arc<dyn RevocationEpoch>,
    cooldown_ms: AtomicU64,
    self_ref: Weak<EscalationService>,
}

impl fmt::Debug for EscalationService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EscalationService").finish_non_exhaustive()
    }
}

/// How a request enters an escalation.
enum Attach {
    /// A ceremony: it gets a [`Waiter`] and parks on it.
    Ceremony,
    /// A pre-request: a detached waiter and its record.
    PreRequest {
        deadline: MonotonicTime,
        session_ends: MonotonicTime,
    },
}

/// What [`EscalationService::enter`] did.
struct Entered {
    serial: u64,
    waiter: u64,
    escalation_id: EscalationId,
    joined: bool,
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
            epoch: deps.epoch,
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
                Effect::Issue(key, event) => self.issue_token(&key, event),
                Effect::Show(ticket, mut fields, counter) => {
                    // The count of this moment, under the store's lock for the count alone and
                    // with no escalation lock held; an unavailable count omits the clause.
                    if let Some(counter) = counter {
                        fields.store_count = counter.count_for_rp(&fields.rp_id);
                    }
                    self.prompter.show(ticket, fields, self.sink());
                }
                Effect::Withdraw(ticket) => self.prompter.withdraw(&ticket),
            }
        }
    }

    /// The checks made without the mutex (the wildcard ones take it briefly): the wildcard
    /// registration limits first (amendment section 2.3 order), then the grant store and prompt
    /// availability. Returns the profile's stored wildcard registration grants, which admission
    /// checks again under the mutex. The adoption of a `register` pre-request is not a new
    /// escalation, so the wildcard limits are not counted for it.
    fn check_resources(
        &self,
        request: &EscalationRequest,
    ) -> Result<StoredWildcards, EscalationRefusal> {
        // Before the store is read (see `WildcardReservation`).
        let (epoch, adopts) = {
            let inner = self.lock();
            (
                inner.reservation_epoch.load(Ordering::SeqCst),
                inner.adoptable(request).is_some(),
            )
        };
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
        if request.is_wildcard_registration() && !adopts {
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
    /// escalation, or adopt it when it is a pending `register` pre-request of the ceremony's own
    /// principal session. The creator writes `escalation.requested` before the entry can be
    /// prompted; a failed write refuses the escalation (and fails every waiter that joined
    /// meanwhile).
    pub fn join_or_create(
        self: &Arc<Self>,
        request: EscalationRequest,
    ) -> Result<Waiter, EscalationRefusal> {
        let session = request.session;
        let entered = self.enter(request, Attach::Ceremony)?;
        Ok(self.waiter(
            entered.serial,
            entered.waiter,
            entered.escalation_id,
            session,
            entered.joined,
        ))
    }

    /// Admit `request` and attach it: the shared path of a ceremony and a pre-request. For a
    /// pre-request the per-session limits are checked again under the same mutex hold that
    /// inserts its record, so they cannot be exceeded by concurrent calls. A pre-request that
    /// joins a live escalation writes its own `escalation.requested` before it is attached; a
    /// failed write refuses it alone.
    fn enter(
        &self,
        request: EscalationRequest,
        attach: Attach,
    ) -> Result<Entered, EscalationRefusal> {
        let key = request.key();
        if self.lock().in_cooldown(&key, self.clock.now()) {
            return Err(EscalationRefusal::Cooldown);
        }
        let stored = self.check_resources(&request)?;
        // Before the entry exists, with no lock held (the grant writer, LOCKING.md rank 64): a
        // revocation from here on makes this escalation's approval persist nothing.
        let revoke_token = self.grants.revoke_token(&request.profile, &request.rp_id);

        let now = self.clock.now();
        // The escalation a pre-request joined and announced before attaching (see below).
        let mut announced: Option<EscalationId> = None;
        let (entered, announcement) = loop {
            let mut inner = self.lock();
            let admission = inner.admit(&request, &key, now, stored)?;
            if let (Attach::PreRequest { .. }, Some(principal)) = (&attach, &request.principal)
                && (inner
                    .pre_requests
                    .contains_key(&(principal.clone(), key.clone()))
                    || inner
                        .pre_request_limit(principal, &request.profile, now)
                        .is_some())
            {
                // Raced with another pre-request of the same session; the caller reports it.
                return Err(EscalationRefusal::PreRequestRateLimited);
            }
            let (serial, joined, announcement) = match admission {
                Admission::Join(serial) => {
                    let id = inner.entries.get(&serial).map(|entry| entry.id.clone());
                    if request.source == RequestSource::PreRequest
                        && let Some(id) = id
                        && announced.as_ref() != Some(&id)
                    {
                        // A pre-request that joins a live escalation is announced under that
                        // escalation's ID with its own principal session hash and note. The
                        // record is written before the joiner's waiter is attached, so it can
                        // never follow `approved`, and a failed write refuses the joiner (ADR
                        // 0014) without touching the escalation or its other waiters. The
                        // state is admitted again afterwards, as it may have moved on.
                        drop(inner);
                        if let Err(e) = self.audit.record(request.audit_context(&id).requested()) {
                            warn!(
                                "escalation {}: the joining pre-request could not be audited: {}",
                                id, e
                            );
                            return Err(EscalationRefusal::AuditFailure);
                        }
                        announced = Some(id);
                        continue;
                    }
                    (serial, true, None)
                }
                Admission::Adopt(serial) => {
                    inner.adopt(serial, &request);
                    (serial, true, None)
                }
                Admission::Create => {
                    inner.next_serial += 1;
                    let serial = inner.next_serial;
                    let escalation_id = EscalationId::generate();
                    let entry = Entry {
                        id: escalation_id,
                        joinable: request.action == CeremonyAction::Authenticate,
                        adoptable_by: match request.action {
                            CeremonyAction::Register
                                if request.source == RequestSource::PreRequest =>
                            {
                                request.principal.clone()
                            }
                            _ => None,
                        },
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
                    (serial, false, Some(announcement))
                }
            };
            let waiter = inner.add_waiter(serial, request.session);
            let escalation_id = inner.entries[&serial].id.clone();
            if let (
                Attach::PreRequest {
                    deadline,
                    session_ends,
                },
                Some(principal),
            ) = (&attach, &request.principal)
            {
                inner.pre_requests.insert(
                    (principal.clone(), key.clone()),
                    PreRequestRecord {
                        serial,
                        waiter: Some(waiter),
                        deadline: *deadline,
                        session_ends: *session_ends,
                        settled_at: None,
                        status: PreStatus::Pending,
                    },
                );
                inner
                    .pre_request_history
                    .entry(principal.clone())
                    .or_default()
                    .push_back(now);
                inner
                    .pre_request_profile_history
                    .entry(request.profile.clone())
                    .or_default()
                    .push_back(now);
            }
            break (
                Entered {
                    serial,
                    waiter,
                    escalation_id,
                    joined,
                },
                announcement,
            );
        };

        let Some(announcement) = announcement else {
            debug!(
                "escalation {}: {} ({}/{})",
                entered.escalation_id,
                if request.source == RequestSource::PreRequest {
                    "joined by a pre-request"
                } else {
                    "joined"
                },
                key.profile,
                key.rp_id
            );
            return Ok(entered);
        };

        let recorded = self.audit.record(announcement);
        let mut effects = Vec::new();
        {
            let mut inner = self.lock();
            let serial = entered.serial;
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
                        entered.escalation_id, e
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
                    let now = self.clock.now();
                    inner.settle_pre_requests(serial, now, self.epoch.current(), &mut effects);
                    if let Some(principal) = &request.principal {
                        // The refusal is the answer; nothing is left to report.
                        inner.pre_requests.remove(&(principal.clone(), key.clone()));
                    }
                    inner.pump(&key.profile, now, &mut effects);
                    self.changed.notify_all();
                }
            }
        }
        self.run(effects);
        match recorded {
            Ok(()) => {
                info!(
                    "escalation {}: requested ({}/{} {}{})",
                    entered.escalation_id,
                    key.profile,
                    key.rp_id,
                    key.action.as_str(),
                    if request.source == RequestSource::PreRequest {
                        ", in advance"
                    } else {
                        ""
                    }
                );
                Ok(entered)
            }
            Err(_) => {
                if matches!(attach, Attach::Ceremony) {
                    // Detach the creator (the entry is already terminal).
                    drop(self.waiter_of(&entered, request.session));
                }
                Err(EscalationRefusal::AuditFailure)
            }
        }
    }

    /// A [`Waiter`] handle for an attached ceremony waiter (only to detach it).
    fn waiter_of(&self, entered: &Entered, session: WaiterSession) -> Option<Waiter> {
        let service = self.self_ref.upgrade()?;
        Some(service.waiter(
            entered.serial,
            entered.waiter,
            entered.escalation_id.clone(),
            session,
            entered.joined,
        ))
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

    /// A waiter leaves (see [`Inner::depart`]).
    fn depart(&self, serial: u64, waiter: u64, departure: Departure) {
        let cooldown = self.cooldown();
        let now = self.clock.now();
        let epoch = self.epoch.current();
        let mut effects = Vec::new();
        {
            let mut inner = self.lock();
            inner.depart(
                serial,
                waiter,
                departure,
                now,
                cooldown,
                epoch,
                &mut effects,
            );
            self.changed.notify_all();
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
            inner.settle_pre_requests(serial, now, self.epoch.current(), &mut effects);
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
                    source: request.source,
                    principal: request.principal.clone(),
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
        // A pre-request's grant has no origin when no ceremony joined before the prompt
        // (amendment section 7); every other grant names the ceremony's.
        let rule = GrantedRule::from_escalation(
            &request.rp_id,
            GrantKind::Escalation,
            escalation_id.as_str(),
            request.origin.as_deref(),
            request.rule,
            None,
            request.source,
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
            inner.settle_pre_requests(serial, now, self.epoch.current(), &mut effects);
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
    /// The profile's pre-approvals are dropped too (`pre_approval.expired`, `policy_reload`).
    pub fn cancel_profile(&self, profile: &ProfileId) {
        self.cancel_where(profile, |_| true, PreApprovalExpireReason::PolicyReload);
    }

    /// [`Self::cancel_profile`] after `grants clear`: the pre-approvals are dropped with
    /// `reason = grant_revoked` (ADR 0014 amendment section 2.3).
    pub fn cancel_profile_grants_cleared(&self, profile: &ProfileId) {
        self.cancel_where(profile, |_| true, PreApprovalExpireReason::GrantRevoked);
    }

    /// Cancel every pending escalation of `profile` for `rp_id` (any action) after `grants revoke`
    /// removed its granted rule, so a late approval cannot persist the grant again (review L2).
    /// Recorded and observed like [`Self::cancel_profile`]; the profile's other escalations stay,
    /// and a queued one is prompted if the cancelled one held the prompt. The RP's pre-approvals
    /// are dropped (`grant_revoked`).
    pub fn cancel_rp(&self, profile: &ProfileId, rp_id: &str) {
        self.cancel_where(
            profile,
            |candidate| candidate == rp_id,
            PreApprovalExpireReason::GrantRevoked,
        );
    }

    fn cancel_where(
        &self,
        profile: &ProfileId,
        matches: impl Fn(&str) -> bool,
        token_reason: PreApprovalExpireReason,
    ) {
        let now = self.clock.now();
        let epoch = self.epoch.current();
        let mut effects = Vec::new();
        {
            let mut inner = self.lock();
            inner.drop_tokens(
                |(_, key)| key.profile == *profile && matches(&key.rp_id),
                token_reason,
                &mut effects,
            );
            // An unreported outcome from before the change (an approval whose grant was just
            // revoked) must not be reported as the state of a new request.
            inner.pre_requests.retain(|(_, key), record| {
                !(key.profile == *profile
                    && matches(&key.rp_id)
                    && matches!(record.status, PreStatus::Settled(_)))
            });
            let serials: Vec<u64> = inner
                .entries
                .iter()
                .filter(|(_, entry)| {
                    entry.request.profile == *profile
                        && matches(&entry.request.rp_id)
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
                inner.settle_pre_requests(serial, now, epoch, &mut effects);
                inner.collect(serial);
            }
            // The profile's remaining queued escalations (a `cancel_rp` leaves them) get the
            // prompt slot; after a whole-profile cancel the queue is empty and this does nothing.
            inner.pump(profile, now, &mut effects);
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

        let context = approval.audit_context();
        let audit_denial = |cause: EscalationDenyCause| {
            if let Err(audit_error) = self.audit.record(context.denied(cause)) {
                warn!(
                    "escalation {}: the failed grant write could not be audited: {}",
                    approval.escalation_id, audit_error
                );
            }
        };
        // A registration grant always names the origin it was created at; an approval without
        // one was never consumed by a ceremony (fail closed).
        let Some(origin) = approval.origin.as_deref() else {
            warn!(
                "escalation {}: the registration approval has no origin; no grant is persisted",
                approval.escalation_id
            );
            audit_denial(EscalationDenyCause::GrantWriteFailed);
            return Err(GrantStoreError::Io(
                "the registration approval has no origin".to_string(),
            ));
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
        let rule = GrantedRule::from_escalation(
            &approval.rp_id,
            GrantKind::Registration,
            approval.escalation_id.as_str(),
            Some(origin),
            approval.rule,
            Some(credential_ref),
            approval.source,
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

    /// Raise a pre-request (ADR 0014 amendment section 2.3), or report the state of the one
    /// `params.request`'s principal session already has for the key. The caller has resolved the
    /// key to `request` against the live policy, checked `pre_request_actions` and, for
    /// `register`, that the principal session can run the ceremony. Then, in the ceremony's
    /// order: the principal session's limits, cooldown, the wildcard registration limits, grant
    /// cap and store, bus, queue and waiter caps. Nothing here waits for the human; see
    /// [`Self::wait_pre_request`].
    pub fn pre_request(&self, params: PreRequestParams) -> PreRequestState {
        self.pre_request_while(params, &|| true)
    }

    /// [`Self::pre_request`] for a requester whose principal session can end while the request is
    /// admitted (review L1): the caller copied the session out of its list and released the list
    /// before calling, so [`Self::principal_session_ended`] may already have run and found
    /// nothing to withdraw. After the request is admitted, if `still_valid()` (called with no lock
    /// held) says the session is gone, the request is withdrawn like any other of that session
    /// and the answer is `Expired`. A session leaves its list before its cleanup runs, so a
    /// session that is still listed here is cleaned up by its own, later, call.
    pub fn pre_request_while(
        &self,
        params: PreRequestParams,
        still_valid: &dyn Fn() -> bool,
    ) -> PreRequestState {
        let principal = params.request.principal.clone();
        let state = self.pre_request_inner(params);
        match principal {
            Some(principal) if !still_valid() => {
                self.principal_session_ended(&principal);
                PreRequestState::Expired
            }
            _ => state,
        }
    }

    fn pre_request_inner(&self, params: PreRequestParams) -> PreRequestState {
        let PreRequestParams {
            request,
            pending_for,
            session_remaining,
        } = params;
        let Some(principal) = request.principal.clone() else {
            // A pre-request always names its principal session; fail closed.
            return PreRequestState::Refused(EscalationRefusal::Unavailable);
        };
        if request.source != RequestSource::PreRequest || request.origin.is_some() {
            return PreRequestState::Refused(EscalationRefusal::Unavailable);
        }
        self.sweep_pre_requests();
        let key = request.key();
        let profile = request.profile.clone();
        let now = self.clock.now();
        {
            let mut inner = self.lock();
            if let Some(state) = inner.report(&principal, &key, now) {
                return state;
            }
            if let Some(limited) = inner.pre_request_limit(&principal, &request.profile, now) {
                return limited;
            }
        }
        let attach = Attach::PreRequest {
            deadline: later(now, pending_for.min(PRE_REQUEST_PENDING_LIMIT)),
            session_ends: later(now, session_remaining),
        };
        match self.enter(request, attach) {
            Ok(entered) => {
                debug!(
                    "escalation {}: pre-request by a principal session is pending",
                    entered.escalation_id
                );
                let now = self.clock.now();
                self.lock()
                    .report(&principal, &key, now)
                    .unwrap_or(PreRequestState::Pending)
            }
            Err(EscalationRefusal::PreRequestRateLimited) => {
                let now = self.clock.now();
                let mut inner = self.lock();
                inner
                    .report(&principal, &key, now)
                    .or_else(|| inner.pre_request_limit(&principal, &profile, now))
                    .unwrap_or(PreRequestState::RateLimited { retry_after: None })
            }
            Err(refusal) => PreRequestState::Refused(refusal),
        }
    }

    /// Wait until `principal`'s pre-request for `key` leaves `Pending`, `until` passes or
    /// `still_valid()` turns false (its principal session is gone), and return its state. The
    /// waiter holds no lock: it parks on the escalation condvar, wakes at least every
    /// [`WAIT_POLL_INTERVAL`] and calls `still_valid` with the mutex released. Leaving early
    /// changes nothing: the pre-request stays pending until its own deadline.
    pub fn wait_pre_request(
        &self,
        principal: &PrincipalSessionId,
        key: &EscalationKey,
        until: Instant,
        still_valid: &dyn Fn() -> bool,
    ) -> PreRequestState {
        loop {
            self.sweep_pre_requests();
            {
                let now = self.clock.now();
                let mut inner = self.lock();
                let state = match inner.report(principal, key, now) {
                    Some(PreRequestState::Pending) => PreRequestState::Pending,
                    Some(state) => return state,
                    // Forgotten: its principal session ended.
                    None => return PreRequestState::Expired,
                };
                let now = Instant::now();
                if now >= until {
                    return state;
                }
                let pause = WAIT_POLL_INTERVAL.min(until - now);
                drop(inner.wait_timeout(&self.changed, pause));
            }
            if !still_valid() {
                return PreRequestState::Expired;
            }
        }
    }

    /// Whether [`Self::take_pre_approval`] would hand out a pre-approval for `consumer` now:
    /// a usable token of its principal session exists, is within its TTL and revocation epoch and
    /// was approved through the rule that matches now. Consumes and audits nothing (review L3): a
    /// registration ceremony asks before it takes the replay key, and takes the token only once
    /// the key is fresh. A token that is no longer valid is left for the sweep or the take to
    /// drop and audit.
    pub fn has_pre_approval(&self, consumer: &PreApprovalConsumer<'_>) -> bool {
        let now = self.clock.now();
        let epoch = self.epoch.current();
        let key = (
            consumer.principal.clone(),
            EscalationKey {
                profile: consumer.profile.clone(),
                rp_id: consumer.rp_id.to_string(),
                action: CeremonyAction::Register,
            },
        );
        let inner = self.lock();
        matches!(
            inner.pre_requests.get(&key).map(|record| &record.status),
            Some(PreStatus::Token(token))
                if token.invalid(now, epoch).is_none() && token.approval.rule == consumer.rule
        )
    }

    /// Consume the pre-approval of `consumer.principal` for a registration at `consumer.rp_id`
    /// (ADR 0014 amendment section 2.3), at the point where the ceremony would raise its own
    /// escalation. One use: the first caller takes it; a racing second one gets `None` and
    /// escalates as usual. A token that is past its TTL, issued under another revocation epoch,
    /// or approved through another rule than the one that matches now, is dropped instead
    /// (`pre_approval.expired`). The consumption is audited (`pre_approval.consumed`) before the
    /// approval is handed out; if that record cannot be written the token is spent and nothing is
    /// handed out (fail closed).
    pub fn take_pre_approval(
        &self,
        consumer: PreApprovalConsumer<'_>,
    ) -> Option<RegistrationApproval> {
        let now = self.clock.now();
        let epoch = self.epoch.current();
        let key = (
            consumer.principal.clone(),
            EscalationKey {
                profile: consumer.profile.clone(),
                rp_id: consumer.rp_id.to_string(),
                action: CeremonyAction::Register,
            },
        );
        let token = {
            let mut inner = self.lock();
            if !matches!(
                inner.pre_requests.get(&key).map(|record| &record.status),
                Some(PreStatus::Token(_))
            ) {
                return None;
            }
            match inner.pre_requests.remove(&key) {
                Some(PreRequestRecord {
                    status: PreStatus::Token(token),
                    ..
                }) => *token,
                _ => return None,
            }
        };
        let meta = token.meta();
        let invalid = token.invalid(now, epoch).or_else(|| {
            (token.approval.rule != consumer.rule).then_some(PreApprovalExpireReason::PolicyReload)
        });
        if let Some(reason) = invalid {
            info!(
                "escalation {}: pre-approval for {}/{} dropped at use ({:?})",
                token.approval.escalation_id, consumer.profile, consumer.rp_id, reason
            );
            if let Err(e) = self.audit.record(meta.expired(reason)) {
                warn!("escalation: failed to audit pre_approval.expired: {}", e);
            }
            return None;
        }
        if let Err(e) = self.audit.record(meta.consumed(consumer.request_id)) {
            warn!(
                "escalation {}: pre_approval.consumed could not be audited; the pre-approval is \
                 not used: {}",
                token.approval.escalation_id, e
            );
            return None;
        }
        let PreApprovalToken {
            mut approval,
            principal,
            ..
        } = token;
        approval.session = consumer.session;
        approval.origin = Some(consumer.origin.to_string());
        approval.principal = Some(principal);
        info!(
            "escalation {}: pre-approval consumed by a registration at {}",
            approval.escalation_id, consumer.rp_id
        );
        Some(approval)
    }

    /// Record `pre_approval.issued` and only then make the pre-approval at `key` usable (review
    /// N1): a token must never be consumable before its issue is on the audit trail. If the
    /// record cannot be written the token is dropped (its wildcard cap slot is released) and the
    /// requester is told `unavailable`: fail closed. A drop that happened while the record was
    /// being written (the session ended, a lease was revoked, the policy changed) is recorded as
    /// `pre_approval.expired` right after `issued`. Runs with no lock held.
    fn issue_token(&self, key: &PreRequestKey, issued: AuditEvent) {
        let waiting = matches!(
            self.lock()
                .pre_requests
                .get(key)
                .map(|record| &record.status),
            Some(PreStatus::Issuing { .. })
        );
        if !waiting {
            return;
        }
        // If the record's write unwinds, the guard settles the record like a failed write.
        let mut guard = IssuingGuard {
            service: self,
            key,
            armed: true,
        };
        let recorded = self.audit.record(issued);
        guard.armed = false;
        let mut effects = Vec::new();
        {
            let mut inner = self.lock();
            let now = self.clock.now();
            if let Err(e) = &recorded {
                warn!(
                    "escalation {}/{}: pre_approval.issued could not be audited; no \
                     pre-approval is issued: {}",
                    key.1.profile, key.1.rp_id, e
                );
                inner.refuse_issuing(key, now);
            } else if let Some(record) = inner.pre_requests.get_mut(key)
                && matches!(record.status, PreStatus::Issuing { .. })
                && let PreStatus::Issuing { token, dropped } = std::mem::replace(
                    &mut record.status,
                    PreStatus::Settled(PreRequestState::Expired),
                )
            {
                if let Some(reason) = dropped {
                    effects.push(Effect::Audit(token.meta().expired(reason)));
                    inner.pre_requests.remove(key);
                } else {
                    record.status = PreStatus::Token(token);
                }
            }
            self.changed.notify_all();
        }
        self.run(effects);
    }

    /// Enforce the pre-requests' deadlines and the pre-approvals' TTL and epoch binding, and
    /// forget unreported outcomes older than [`PRE_REQUEST_WINDOW`]. The runtime loop calls it
    /// about once a second; every pre-request call runs it first as well.
    pub fn sweep_pre_requests(&self) {
        let now = self.clock.now();
        let epoch = self.epoch.current();
        let cooldown = self.cooldown();
        let mut effects = Vec::new();
        {
            let mut inner = self.lock();
            if inner.pre_requests.is_empty() {
                return;
            }
            // A pre-request whose escalation the human has decided (`Deciding`: the approval is
            // being written) is not expired: `finish_deciding` settles it with the decision.
            let due_keys: Vec<PreRequestKey> = inner
                .pre_requests
                .iter()
                .filter(|(_, record)| {
                    matches!(record.status, PreStatus::Pending)
                        && record.deadline <= now
                        && inner.entries.get(&record.serial).map(|entry| entry.state)
                            != Some(EscalationState::Deciding)
                })
                .map(|(key, _)| key.clone())
                .collect();
            let due: Vec<(PreRequestKey, u64, Option<u64>)> = due_keys
                .into_iter()
                .filter_map(|key| {
                    let record = inner.pre_requests.get_mut(&key)?;
                    Some((key, record.serial, record.waiter.take()))
                })
                .collect();
            for (key, serial, waiter) in due {
                info!(
                    "escalation: a pre-request for {}/{} reached its deadline",
                    key.1.profile, key.1.rp_id
                );
                if let Some(waiter) = waiter {
                    // The last waiter's timeout ends the escalation and starts the key's
                    // cooldown; with ceremonies still waiting it continues for them.
                    inner.depart(
                        serial,
                        waiter,
                        Departure::Timeout,
                        now,
                        cooldown,
                        epoch,
                        &mut effects,
                    );
                }
                if let Some(record) = inner.pre_requests.get_mut(&key)
                    && matches!(record.status, PreStatus::Pending)
                {
                    record.status = PreStatus::Settled(PreRequestState::Expired);
                    record.settled_at = Some(now);
                }
            }
            let stale: Vec<(PreRequestKey, PreApprovalExpireReason)> = inner
                .pre_requests
                .iter()
                .filter_map(|(key, record)| match &record.status {
                    PreStatus::Token(token) => token
                        .invalid(now, epoch)
                        .map(|reason| (key.clone(), reason)),
                    _ => None,
                })
                .collect();
            for (key, reason) in stale {
                inner.drop_tokens(|candidate| *candidate == key, reason, &mut effects);
            }
            let window = u64::try_from(PRE_REQUEST_WINDOW.as_millis()).unwrap_or(u64::MAX);
            inner.pre_requests.retain(|_, record| {
                !(matches!(record.status, PreStatus::Settled(_))
                    && record
                        .settled_at
                        .is_some_and(|at| now.saturating_duration_since(at) >= window))
            });
            self.changed.notify_all();
        }
        self.run(effects);
    }

    /// A principal session ended: its pending pre-requests are withdrawn (their detached waiters
    /// leave as an abort), its pre-approvals are dropped (`session_end`) and everything it asked
    /// is forgotten.
    pub fn principal_session_ended(&self, principal: &PrincipalSessionId) {
        let now = self.clock.now();
        let epoch = self.epoch.current();
        let cooldown = self.cooldown();
        let mut effects = Vec::new();
        {
            let mut inner = self.lock();
            inner.drop_tokens(
                |(owner, _)| owner == principal,
                PreApprovalExpireReason::SessionEnd,
                &mut effects,
            );
            let pending: Vec<(u64, u64)> = inner
                .pre_requests
                .iter_mut()
                .filter(|((owner, _), _)| owner == principal)
                .filter_map(|(_, record)| record.waiter.take().map(|w| (record.serial, w)))
                .collect();
            for (serial, waiter) in pending {
                inner.depart(
                    serial,
                    waiter,
                    Departure::Aborted,
                    now,
                    cooldown,
                    epoch,
                    &mut effects,
                );
            }
            // A pre-approval still being issued is marked dropped above and removed by its
            // issuing step, which records the drop after `issued`.
            inner.pre_requests.retain(|(owner, _), record| {
                owner != principal || matches!(record.status, PreStatus::Issuing { .. })
            });
            inner.pre_request_history.remove(principal);
            // A `register` pre-request a ceremony has not adopted is no longer adoptable by
            // anyone (it was withdrawn above unless ceremonies of other keys hold it).
            for entry in inner.entries.values_mut() {
                if entry.adoptable_by.as_ref() == Some(principal) {
                    entry.adoptable_by = None;
                }
            }
            self.changed.notify_all();
        }
        self.run(effects);
    }

    /// A browser lease of `principal` was revoked: its pre-approvals are dropped
    /// (`lease_revoked`). A pending pre-request stays; its approval binds to the session's next
    /// lease.
    pub fn lease_revoked(&self, principal: &PrincipalSessionId) {
        let mut effects = Vec::new();
        {
            let mut inner = self.lock();
            inner.drop_tokens(
                |(owner, _)| owner == principal,
                PreApprovalExpireReason::LeaseRevoked,
                &mut effects,
            );
        }
        self.run(effects);
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

/// Settles a pre-approval left in `Issuing` state if the write of its `pre_approval.issued`
/// record unwinds: without it the record would stay `Issuing` (a session's end keeps those, the TTL
/// sweep only looks at usable tokens and the outcome sweep only at settled ones) and hold its
/// wildcard cap slot until restart. The settlement is that of a failed write; the lock is taken
/// without letting a panic escape the destructor.
struct IssuingGuard<'a> {
    service: &'a EscalationService,
    key: &'a PreRequestKey,
    armed: bool,
}

impl Drop for IssuingGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        warn!(
            "escalation {}/{}: recording pre_approval.issued panicked; no pre-approval is issued",
            self.key.1.profile, self.key.1.rp_id
        );
        let _ = panic::catch_unwind(AssertUnwindSafe(|| {
            let now = self.service.clock.now();
            self.service.lock().refuse_issuing(self.key, now);
            self.service.changed.notify_all();
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
        let source = entry.request.source;
        let outcome = match entry.outcome.as_mut()? {
            EntryOutcome::Approved => EscalationOutcome::Approved {
                escalation_id,
                source,
            },
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

    /// A revocation epoch the test moves by hand.
    #[derive(Default)]
    pub struct FixedEpoch(pub AtomicU64);

    impl FixedEpoch {
        pub fn bump(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl RevocationEpoch for FixedEpoch {
        fn current(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
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
            epoch: Arc::new(FixedEpoch::default()),
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
            grants: Arc::new(StoreGrantWriter {
                store,
                policy: policy.clone(),
            }),
            prompter,
            clock: Arc::new(SystemClock::new()),
            cooldown,
            epoch: policy,
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
        epoch: Arc<test_support::FixedEpoch>,
    }

    const COOLDOWN: Duration = Duration::from_secs(600);

    fn harness() -> Harness {
        let audit = Arc::new(FakeAudit::default());
        let grants = Arc::new(FakeGrants::default());
        let prompter = Arc::new(FakePrompter::default());
        let clock = Arc::new(ManualClock(AtomicU64::new(1_000)));
        let epoch = Arc::new(test_support::FixedEpoch::default());
        let service = EscalationService::new(EscalationDeps {
            audit: audit.clone(),
            grants: grants.clone(),
            prompter: prompter.clone(),
            clock: clock.clone(),
            cooldown: COOLDOWN,
            epoch: epoch.clone(),
        });
        Harness {
            service,
            audit,
            grants,
            prompter,
            clock,
            epoch,
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
            origin: Some(format!("https://{rp_id}")),
            rule: PermittingRule::Exact,
            session: WaiterSession::from_raw(session),
            source: RequestSource::Ceremony,
            principal: None,
            agent_note: None,
            mode: AgentMode::Isolated,
            principal_user: "agent".to_string(),
            max_granted_rules: 64,
            max_wildcard_registrations: 4,
            wildcard_registration_prompts_per_day: 3,
            store_counter: None,
        }
    }

    /// A store whose count the test changes: what `StoreCounter` reads when the prompt is shown.
    #[derive(Debug)]
    struct FakeStoreCounter {
        count: Mutex<Option<usize>>,
        asked: Mutex<Vec<String>>,
    }

    impl FakeStoreCounter {
        fn new(count: Option<usize>) -> Arc<Self> {
            Arc::new(Self {
                count: Mutex::new(count),
                asked: Mutex::new(Vec::new()),
            })
        }

        fn set(&self, count: Option<usize>) {
            *self.count.lock().unwrap() = count;
        }
    }

    impl StoreCounter for FakeStoreCounter {
        fn count_for_rp(&self, rp_id: &str) -> Option<usize> {
            assert!(
                lock_order::held_levels().is_empty(),
                "counted with a lock held"
            );
            self.asked.lock().unwrap().push(rp_id.to_string());
            *self.count.lock().unwrap()
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
        assert_eq!(rule.origin.as_deref(), Some("https://a.example"));
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
            Ok(Admission::Create)
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
            Ok(Admission::Create)
        ));
        assert_eq!(inner.cooldown.len(), MAX_TRACKED_KEYS_PER_PROFILE);
        assert!(inner.in_cooldown(&profile_key("hostile", 0), now));
        // The quota frees up when the cooldowns run out.
        let later = at(1_000 + 3_600_000 + 1);
        assert!(matches!(
            inner.admit(&more, &more.key(), later, StoredWildcards::NONE),
            Ok(Admission::Create)
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
            Ok(Admission::Create)
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
            store_counter: Some(FakeStoreCounter::new(Some(2))),
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
        // A sign-in prompt never carries a count, even if a counter was set.
        let counter = FakeStoreCounter::new(Some(5));
        let mut sign_in = request("p", "b.example", 1);
        sign_in.store_counter = Some(counter.clone());
        assert_eq!(sign_in.prompt_fields().store_count, None);
        assert_eq!(sign_in.prompt_fields().rule, PromptRule::Exact);
        let _sign_in = h.service.join_or_create(sign_in).unwrap();
        assert!(counter.asked.lock().unwrap().is_empty());
    }

    /// Review L4: the count is taken when the prompt is shown. A registration queued behind
    /// another shows the count of the moment it reaches the screen, not the one it was raised
    /// with.
    #[test]
    fn a_queued_registration_prompt_counts_when_it_is_shown() {
        let h = harness();
        let first = FakeStoreCounter::new(Some(0));
        let second = FakeStoreCounter::new(Some(0));
        let with = |rp: &str, counter: &Arc<FakeStoreCounter>| EscalationRequest {
            store_counter: Some(counter.clone()),
            ..wildcard_register("p", rp, 1)
        };
        let parked = park(h.service.join_or_create(with("a.example", &first)).unwrap());
        let _queued = h
            .service
            .join_or_create(with("b.example", &second))
            .unwrap();
        assert_eq!(h.prompter.shown().len(), 1, "the second prompt is queued");
        assert!(
            second.asked.lock().unwrap().is_empty(),
            "a queued prompt is not counted yet"
        );

        // The store changes while it waits (another registration, an external sync).
        second.set(Some(3));
        h.clock.advance(Duration::from_secs(5));
        h.service
            .prompt_event(&h.prompter.last_shown(), PromptEvent::Approved);
        assert!(matches!(
            parked.join().unwrap(),
            EscalationOutcome::RegistrationApproved(_)
        ));
        let shown = h.prompter.shown.lock().unwrap();
        assert_eq!(shown.len(), 2);
        assert_eq!(shown[0].1.store_count, Some(0));
        assert_eq!(
            shown[1].1.store_count,
            Some(3),
            "the count of display time, not of admission"
        );
        assert_eq!(*second.asked.lock().unwrap(), vec!["b.example".to_string()]);
    }

    /// A count that cannot be made is omitted, never shown as "no passkey yet".
    #[test]
    fn an_unavailable_store_count_leaves_the_prompt_without_a_count() {
        let h = harness();
        let counter = FakeStoreCounter::new(None);
        let _waiter = h
            .service
            .join_or_create(EscalationRequest {
                store_counter: Some(counter.clone()),
                ..wildcard_register("p", "a.example", 1)
            })
            .unwrap();
        let fields = h.prompter.shown.lock().unwrap()[0].1.clone();
        assert_eq!(fields.store_count, None);
        assert_eq!(counter.asked.lock().unwrap().len(), 1);
        let (_, body) = crate::agent::escalation_prompt::render_prompt(&fields)
            .expect("the registration prompt renders");
        assert!(!body.contains("holds no passkey"), "{body}");
        assert!(!body.contains("already holds"), "{body}");
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

    /// ADR 0014 amendment section 2.3: pre-requests, adoption and pre-approval tokens.
    mod pre_requests {
        use super::*;

        use std::sync::Barrier;

        use crate::agent::escalation_prompt::{render_prompt, sanitize_agent_note};

        fn principal(n: u8) -> PrincipalSessionId {
            format!("{n:02x}").repeat(32).parse().unwrap()
        }

        fn pre(action: CeremonyAction, rp_id: &str, who: &PrincipalSessionId) -> EscalationRequest {
            EscalationRequest {
                action,
                origin: None,
                session: WaiterSession::of_principal(who),
                source: RequestSource::PreRequest,
                principal: Some(who.clone()),
                agent_note: Some("agent says hi".to_string()),
                ..request("p", rp_id, 0)
            }
        }

        fn params(request: EscalationRequest) -> PreRequestParams {
            PreRequestParams {
                request,
                pending_for: PRE_REQUEST_PENDING_LIMIT,
                session_remaining: Duration::from_secs(3600),
            }
        }

        fn pre_auth(h: &Harness, rp_id: &str, who: &PrincipalSessionId) -> PreRequestState {
            h.service
                .pre_request(params(pre(CeremonyAction::Authenticate, rp_id, who)))
        }

        fn pre_reg(h: &Harness, rp_id: &str, who: &PrincipalSessionId) -> PreRequestState {
            h.service
                .pre_request(params(pre(CeremonyAction::Register, rp_id, who)))
        }

        /// A registration ceremony whose bearer is owned by `who`.
        fn ceremony_register(
            rp_id: &str,
            session: usize,
            who: &PrincipalSessionId,
        ) -> EscalationRequest {
            EscalationRequest {
                principal: Some(who.clone()),
                ..register("p", rp_id, session)
            }
        }

        fn key(action: CeremonyAction, rp_id: &str) -> EscalationKey {
            EscalationKey {
                profile: profile("p"),
                rp_id: rp_id.to_string(),
                action,
            }
        }

        fn consumer<'a>(rp_id: &'a str, who: &'a PrincipalSessionId) -> PreApprovalConsumer<'a> {
            PreApprovalConsumer {
                profile: PROFILE_P.get_or_init(|| profile("p")),
                rp_id,
                principal: who,
                rule: PermittingRule::Exact,
                session: WaiterSession::from_raw(77),
                origin: "https://www.r.example",
                request_id: "req-consumer",
            }
        }

        static PROFILE_P: std::sync::OnceLock<ProfileId> = std::sync::OnceLock::new();

        fn approve_last(h: &Harness) {
            h.clock.advance(Duration::from_secs(2));
            h.service
                .prompt_event(&h.prompter.last_shown(), PromptEvent::Approved);
        }

        /// Raise a `register` pre-request and approve it: a token waits.
        fn issue_token(h: &Harness, rp_id: &str, who: &PrincipalSessionId) {
            assert_eq!(pre_reg(h, rp_id, who), PreRequestState::Pending);
            approve_last(h);
            assert!(matches!(
                h.service
                    .pre_request(params(pre(CeremonyAction::Register, rp_id, who))),
                PreRequestState::PreApproved { .. }
            ));
        }

        #[test]
        fn an_authenticate_pre_request_prompts_once_and_persists_a_pre_request_grant() {
            let h = harness();
            let a = principal(1);
            assert_eq!(pre_auth(&h, "a.example", &a), PreRequestState::Pending);
            // Idempotent: the repeat reports the same pending request; no second prompt.
            assert_eq!(pre_auth(&h, "a.example", &a), PreRequestState::Pending);
            assert_eq!(h.prompter.shown().len(), 1);
            assert_eq!(h.audit.count("escalation.requested"), 1);
            let fields = h.prompter.shown.lock().unwrap()[0].1.clone();
            assert_eq!(fields.origin, None);
            assert!(fields.requested_in_advance);
            let requested = h.audit.last("escalation.requested");
            assert_eq!(requested["source"], "pre_request");
            assert!(requested["origin"].is_null());
            assert_eq!(requested["agent_note"], "agent says hi");
            assert_eq!(
                requested["principal_session_id_hash"],
                crate::agent::audit_events::principal_session_id_hash(&a)
            );

            approve_last(&h);
            let rules = h.grants.rules.lock().unwrap().clone();
            assert_eq!(rules.len(), 1);
            assert_eq!(rules[0].source, RequestSource::PreRequest);
            assert_eq!(rules[0].origin, None);
            assert_eq!(rules[0].kind, GrantKind::Escalation);
            // The note is on `requested` only.
            assert!(h.audit.last("escalation.approved")["agent_note"].is_null());
            assert_eq!(h.audit.last("escalation.approved")["source"], "pre_request");
            // Reported once, then forgotten.
            assert_eq!(
                h.service.wait_pre_request(
                    &a,
                    &key(CeremonyAction::Authenticate, "a.example"),
                    far(),
                    &|| true
                ),
                PreRequestState::Approved
            );
            assert!(h.service.lock().pre_requests.is_empty());
            assert!(
                h.service.lock().entries.is_empty(),
                "the entry is collected"
            );
        }

        #[test]
        fn ceremonies_join_an_authenticate_pre_request_and_a_pre_request_joins_a_ceremony() {
            let h = harness();
            let a = principal(1);
            assert_eq!(pre_auth(&h, "a.example", &a), PreRequestState::Pending);
            let ceremony = h
                .service
                .join_or_create(request("p", "a.example", 1))
                .unwrap();
            assert!(ceremony.joined());
            let parked = park(ceremony);
            approve_last(&h);
            match parked.join().unwrap() {
                EscalationOutcome::Approved { source, .. } => {
                    assert_eq!(source, RequestSource::PreRequest)
                }
                other => panic!("unexpected {other:?}"),
            }
            assert_eq!(h.prompter.shown().len(), 1);

            // The other way round: a ceremony's escalation, joined by a pre-request.
            let ceremony = h
                .service
                .join_or_create(request("p", "b.example", 1))
                .unwrap();
            let b = principal(2);
            assert_eq!(pre_auth(&h, "b.example", &b), PreRequestState::Pending);
            // The joiner is announced too (review N3): same escalation, its own hash and note.
            assert_eq!(h.audit.count("escalation.requested"), 3);
            let joined = h.audit.last("escalation.requested");
            let creator = h
                .audit
                .events
                .lock()
                .unwrap()
                .iter()
                .rev()
                .filter(|event| event["kind"] == "escalation.requested")
                .nth(1)
                .cloned()
                .unwrap();
            assert_eq!(creator["rp_id"], "b.example");
            assert_eq!(creator["source"], "ceremony");
            assert!(creator["agent_note"].is_null());
            assert_eq!(joined["escalation_id"], creator["escalation_id"]);
            assert_eq!(joined["source"], "pre_request");
            assert_eq!(joined["agent_note"], "agent says hi");
            assert_eq!(
                joined["principal_session_id_hash"],
                crate::agent::audit_events::principal_session_id_hash(&b)
            );
            let parked = park(ceremony);
            approve_last(&h);
            assert!(matches!(
                parked.join().unwrap(),
                EscalationOutcome::Approved {
                    source: RequestSource::Ceremony,
                    ..
                }
            ));
            assert_eq!(
                h.service
                    .pre_request(params(pre(CeremonyAction::Authenticate, "b.example", &b))),
                PreRequestState::Approved
            );
            let rules = h.grants.rules.lock().unwrap().clone();
            let b_rule = rules.iter().find(|r| r.rp_id == "b.example").unwrap();
            assert_eq!(b_rule.source, RequestSource::Ceremony);
            assert_eq!(b_rule.origin.as_deref(), Some("https://b.example"));
        }

        #[test]
        fn a_denied_pre_request_puts_the_key_in_the_shared_cooldown() {
            let h = harness();
            let a = principal(1);
            pre_auth(&h, "a.example", &a);
            h.service.prompt_event(
                &h.prompter.last_shown(),
                PromptEvent::Denied(EscalationDenyCause::User),
            );
            assert_eq!(
                pre_auth(&h, "a.example", &a),
                PreRequestState::Denied { reason: None }
            );
            // The ceremony sees the cooldown the pre-request's deny started ...
            assert_eq!(
                h.service.precheck(&request("p", "a.example", 1)),
                Err(EscalationRefusal::Cooldown)
            );
            // ... and so does a new pre-request.
            assert_eq!(
                pre_auth(&h, "a.example", &a),
                PreRequestState::Refused(EscalationRefusal::Cooldown)
            );
            // The other direction: a ceremony's deny cools down pre-requests.
            let ceremony = h
                .service
                .join_or_create(request("p", "b.example", 1))
                .unwrap();
            let parked = park(ceremony);
            h.service.prompt_event(
                &h.prompter.last_shown(),
                PromptEvent::Denied(EscalationDenyCause::User),
            );
            parked.join().unwrap();
            assert_eq!(
                pre_auth(&h, "b.example", &a),
                PreRequestState::Refused(EscalationRefusal::Cooldown)
            );
            assert_eq!(h.prompter.shown().len(), 2);
        }

        #[test]
        fn a_pending_pre_request_expires_at_its_deadline_into_the_cooldown() {
            let h = harness();
            let a = principal(1);
            let mut short = params(pre(CeremonyAction::Authenticate, "a.example", &a));
            short.pending_for = Duration::from_secs(30);
            assert_eq!(h.service.pre_request(short), PreRequestState::Pending);
            h.clock.advance(Duration::from_secs(29));
            h.service.sweep_pre_requests();
            assert_eq!(pre_auth(&h, "a.example", &a), PreRequestState::Pending);
            h.clock.advance(Duration::from_secs(1));
            h.service.sweep_pre_requests();
            assert_eq!(h.prompter.withdrawn().len(), 1);
            assert_eq!(h.audit.last("escalation.expired")["reason"], "timeout");
            assert_eq!(pre_auth(&h, "a.example", &a), PreRequestState::Expired);
            assert_eq!(
                pre_auth(&h, "a.example", &a),
                PreRequestState::Refused(EscalationRefusal::Cooldown)
            );
            assert!(
                h.service
                    .in_cooldown(&key(CeremonyAction::Authenticate, "a.example"))
            );
        }

        #[test]
        fn the_pending_lifetime_is_capped_at_ten_minutes() {
            let h = harness();
            let a = principal(1);
            let mut long = params(pre(CeremonyAction::Authenticate, "a.example", &a));
            long.pending_for = Duration::from_secs(3600);
            h.service.pre_request(long);
            h.clock.advance(PRE_REQUEST_PENDING_LIMIT);
            h.service.sweep_pre_requests();
            assert_eq!(pre_auth(&h, "a.example", &a), PreRequestState::Expired);
        }

        #[test]
        fn a_pre_request_that_expires_leaves_waiting_ceremonies_their_escalation() {
            let h = harness();
            let a = principal(1);
            let mut short = params(pre(CeremonyAction::Authenticate, "a.example", &a));
            short.pending_for = Duration::from_secs(5);
            h.service.pre_request(short);
            let ceremony = h
                .service
                .join_or_create(request("p", "a.example", 1))
                .unwrap();
            h.clock.advance(Duration::from_secs(6));
            h.service.sweep_pre_requests();
            assert_eq!(pre_auth(&h, "a.example", &a), PreRequestState::Expired);
            assert!(h.prompter.withdrawn().is_empty());
            let parked = park(ceremony);
            approve_last(&h);
            assert!(matches!(
                parked.join().unwrap(),
                EscalationOutcome::Approved { .. }
            ));
        }

        #[test]
        fn the_requesters_wait_ends_at_the_decision_or_its_own_bound() {
            let h = harness();
            let a = principal(1);
            pre_auth(&h, "a.example", &a);
            let k = key(CeremonyAction::Authenticate, "a.example");
            // Its own bound: still pending, and the request stays.
            let start = Instant::now();
            assert_eq!(
                h.service.wait_pre_request(
                    &a,
                    &k,
                    Instant::now() + Duration::from_millis(300),
                    &|| true
                ),
                PreRequestState::Pending
            );
            assert!(start.elapsed() >= Duration::from_millis(300));
            assert_eq!(h.prompter.withdrawn().len(), 0);
            // A decision wakes it.
            let service = Arc::clone(&h.service);
            let waiting = {
                let a = a.clone();
                let k = k.clone();
                thread::spawn(move || service.wait_pre_request(&a, &k, far(), &|| true))
            };
            thread::sleep(Duration::from_millis(50));
            approve_last(&h);
            assert_eq!(waiting.join().unwrap(), PreRequestState::Approved);
            // A requester whose session went away stops waiting.
            pre_auth(&h, "b.example", &a);
            assert_eq!(
                h.service.wait_pre_request(
                    &a,
                    &key(CeremonyAction::Authenticate, "b.example"),
                    far(),
                    &|| false
                ),
                PreRequestState::Expired
            );
        }

        #[test]
        fn the_limits_bound_each_session_and_the_profile_across_sessions() {
            let h = harness();
            let a = principal(1);
            assert_eq!(pre_auth(&h, "a1.example", &a), PreRequestState::Pending);
            // Per session: one pending.
            assert_eq!(
                pre_auth(&h, "a2.example", &a),
                PreRequestState::RateLimited { retry_after: None }
            );
            // Another session is not affected by it, up to the profile's three pending ...
            assert_eq!(
                pre_auth(&h, "a2.example", &principal(2)),
                PreRequestState::Pending
            );
            assert_eq!(
                pre_auth(&h, "a3.example", &principal(3)),
                PreRequestState::Pending
            );
            // ... and a fourth session, with nothing pending of its own, is refused: the profile
            // already has three, whichever sessions raised them (the out-of-session CLI starts a
            // fresh session per call). Nothing is prompted for it.
            let shown = h.prompter.shown().len();
            assert_eq!(
                pre_auth(&h, "a4.example", &principal(4)),
                PreRequestState::RateLimited { retry_after: None }
            );
            assert_eq!(h.prompter.shown().len(), shown);
            for _ in 0..3 {
                approve_last(&h);
            }
            // A decided request no longer counts as pending: the fourth session is admitted.
            assert_eq!(
                pre_auth(&h, "a4.example", &principal(4)),
                PreRequestState::Pending
            );
            approve_last(&h);
            // Per session: six per window. `a` raised one; five more.
            for n in 2..=6 {
                let rp = format!("a{n}x.example");
                assert_eq!(pre_auth(&h, &rp, &a), PreRequestState::Pending, "{n}");
                approve_last(&h);
            }
            // The seventh of `a` within ten minutes is refused without a prompt.
            let shown = h.prompter.shown().len();
            match pre_auth(&h, "a7.example", &a) {
                PreRequestState::RateLimited {
                    retry_after: Some(after),
                } => assert!(after <= PRE_REQUEST_WINDOW),
                other => panic!("unexpected {other:?}"),
            }
            assert_eq!(h.prompter.shown().len(), shown);
            // Per profile: twelve per window across sessions. `a`'s six and three other sessions'
            // made nine; three more sessions make twelve.
            for n in 10..13u8 {
                let rp = format!("s{n}.example");
                assert_eq!(pre_auth(&h, &rp, &principal(n)), PreRequestState::Pending);
                approve_last(&h);
            }
            // The thirteenth, from a session that never asked, is refused without a prompt.
            let shown = h.prompter.shown().len();
            match pre_auth(&h, "s13.example", &principal(14)) {
                PreRequestState::RateLimited {
                    retry_after: Some(after),
                } => assert!(after <= PRE_REQUEST_WINDOW),
                other => panic!("unexpected {other:?}"),
            }
            assert_eq!(h.prompter.shown().len(), shown);
            h.clock.advance(PRE_REQUEST_WINDOW);
            assert_eq!(pre_auth(&h, "a7.example", &a), PreRequestState::Pending);
            assert_eq!(
                pre_auth(&h, "s13.example", &principal(14)),
                PreRequestState::Pending
            );
        }

        #[test]
        fn ending_sessions_neither_resets_nor_keeps_the_profile_limits() {
            let h = harness();
            // Twelve sessions of one profile, each ended after its request: the out-of-session
            // CLI's pattern. The profile window outlives the sessions.
            for n in 1..=12u8 {
                let who = principal(n);
                let rp = format!("c{n}.example");
                assert_eq!(pre_auth(&h, &rp, &who), PreRequestState::Pending, "{n}");
                approve_last(&h);
                h.service.principal_session_ended(&who);
            }
            let shown = h.prompter.shown().len();
            assert!(matches!(
                pre_auth(&h, "c13.example", &principal(13)),
                PreRequestState::RateLimited {
                    retry_after: Some(_)
                }
            ));
            assert_eq!(h.prompter.shown().len(), shown);
            // A session's end withdraws its pending request, which frees the pending slot.
            h.clock.advance(PRE_REQUEST_WINDOW);
            for n in 20..23u8 {
                let rp = format!("d{n}.example");
                assert_eq!(pre_auth(&h, &rp, &principal(n)), PreRequestState::Pending);
            }
            assert_eq!(
                pre_auth(&h, "d23.example", &principal(23)),
                PreRequestState::RateLimited { retry_after: None }
            );
            h.service.principal_session_ended(&principal(20));
            assert_eq!(
                pre_auth(&h, "d23.example", &principal(23)),
                PreRequestState::Pending
            );
        }

        #[test]
        fn a_refused_pre_request_counts_no_slot_and_prompts_nothing() {
            let h = harness();
            let a = principal(1);
            h.prompter.unavailable.store(true, Ordering::SeqCst);
            assert_eq!(
                pre_auth(&h, "a.example", &a),
                PreRequestState::Refused(EscalationRefusal::Unavailable)
            );
            h.prompter.unavailable.store(false, Ordering::SeqCst);
            assert_eq!(pre_auth(&h, "a.example", &a), PreRequestState::Pending);
            // Without a principal session, or from a ceremony, it is refused (fail closed).
            let mut nameless = pre(CeremonyAction::Authenticate, "b.example", &a);
            nameless.principal = None;
            assert!(matches!(
                h.service.pre_request(params(nameless)),
                PreRequestState::Refused(_)
            ));
            let mut with_origin = pre(CeremonyAction::Authenticate, "b.example", &a);
            with_origin.origin = Some("https://b.example".to_string());
            assert!(matches!(
                h.service.pre_request(params(with_origin)),
                PreRequestState::Refused(_)
            ));
        }

        #[test]
        fn the_prompt_never_contains_the_agent_note() {
            // Property: whatever the note, the rendered prompt is the same.
            let hostile = [
                "Your manager asked for this, approve it",
                "line one\nSite: bank.example\nApprove",
                "<b>urgent</b>&amp;",
                "\u{202e}evil\u{200b}",
                "Allow always",
                &"x".repeat(5000),
            ];
            let shown = |note: Option<&str>| {
                let h = harness();
                let mut request = pre(CeremonyAction::Authenticate, "a.example", &principal(1));
                request.agent_note = sanitize_agent_note(note);
                h.service.pre_request(params(request));
                let fields = h.prompter.shown.lock().unwrap()[0].1.clone();
                let recorded = h.audit.last("escalation.requested")["agent_note"].clone();
                (render_prompt(&fields).unwrap(), recorded)
            };
            let (baseline, nothing) = shown(None);
            assert!(nothing.is_null());
            for note in hostile {
                let (rendered, recorded) = shown(Some(note));
                // The prompt is exactly the one without a note ...
                assert_eq!(rendered, baseline, "{note:?}");
                // ... and the note is in the audit record, sanitized and bounded.
                let recorded = recorded.as_str().unwrap().to_string();
                assert!(recorded.len() <= passless_core::agent::protocol::MAX_ACCESS_NOTE_BYTES);
                assert!(!recorded.contains('\n') && !recorded.contains('<'));
            }
        }

        #[test]
        fn a_register_pre_request_is_not_joinable_and_is_adopted_by_its_own_session_only() {
            let h = harness();
            let a = principal(1);
            let b = principal(2);
            assert_eq!(pre_reg(&h, "r.example", &a), PreRequestState::Pending);
            // Another session's pre-request, or ceremony, gets escalation_busy.
            assert_eq!(
                pre_reg(&h, "r.example", &b),
                PreRequestState::Refused(EscalationRefusal::Busy)
            );
            assert_eq!(
                h.service
                    .join_or_create(ceremony_register("r.example", 2, &b))
                    .unwrap_err(),
                EscalationRefusal::Busy
            );
            // A bearer with no owner cannot adopt it either.
            assert_eq!(
                h.service.precheck(&register("p", "r.example", 3)),
                Err(EscalationRefusal::Busy)
            );
            // The first registration ceremony of the same principal session adopts it.
            let ceremony = h
                .service
                .join_or_create(ceremony_register("r.example", 1, &a))
                .unwrap();
            assert!(ceremony.joined());
            assert_eq!(h.prompter.shown().len(), 1, "adoption raises no prompt");
            assert_eq!(pre_reg(&h, "r.example", &a), PreRequestState::Adopted);
            // A second one of the same session is busy: it was adopted.
            assert_eq!(
                h.service
                    .join_or_create(ceremony_register("r.example", 4, &a))
                    .unwrap_err(),
                EscalationRefusal::Busy
            );
            let parked = park(ceremony);
            approve_last(&h);
            match parked.join().unwrap() {
                EscalationOutcome::RegistrationApproved(approval) => {
                    assert_eq!(approval.session(), WaiterSession::from_raw(1));
                    assert_eq!(approval.origin(), Some("https://r.example"));
                    assert_eq!(approval.source(), RequestSource::PreRequest);
                    assert_eq!(approval.principal(), Some(&a));
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
            // The adopting ceremony had the outcome: no token is issued.
            assert_eq!(h.audit.count("pre_approval.issued"), 0);
            assert!(h.service.lock().pre_requests.is_empty());
            let rule = h.grants.rules.lock().unwrap()[0].clone();
            assert_eq!(rule.source, RequestSource::PreRequest);
            assert_eq!(rule.origin.as_deref(), Some("https://r.example"));
        }

        #[test]
        fn an_unadopted_register_approval_becomes_a_one_use_token() {
            let h = harness();
            let a = principal(1);
            issue_token(&h, "r.example", &a);
            let issued = h.audit.last("pre_approval.issued");
            assert_eq!(issued["ttl_secs"], 600);
            assert_eq!(issued["rp_id"], "r.example");
            // Idempotent: the repeat reports the token, no new prompt.
            match pre_reg(&h, "r.example", &a) {
                PreRequestState::PreApproved { expires_in } => {
                    assert!(expires_in <= PRE_APPROVAL_TTL)
                }
                other => panic!("unexpected {other:?}"),
            }
            assert_eq!(h.prompter.shown().len(), 1);
            // Another principal session cannot consume it.
            let b = principal(2);
            assert!(
                h.service
                    .take_pre_approval(consumer("r.example", &b))
                    .is_none()
            );
            // Nor at another RP.
            assert!(
                h.service
                    .take_pre_approval(consumer("s.example", &a))
                    .is_none()
            );
            // Its own session consumes it once.
            let approval = h
                .service
                .take_pre_approval(consumer("r.example", &a))
                .expect("the token");
            assert_eq!(approval.session(), WaiterSession::from_raw(77));
            assert_eq!(approval.origin(), Some("https://www.r.example"));
            assert_eq!(approval.source(), RequestSource::PreRequest);
            assert_eq!(approval.principal(), Some(&a));
            assert_eq!(
                h.audit.last("pre_approval.consumed")["request_id"],
                "req-consumer"
            );
            // Replay: nothing left.
            assert!(
                h.service
                    .take_pre_approval(consumer("r.example", &a))
                    .is_none()
            );
            assert_eq!(h.audit.count("pre_approval.consumed"), 1);
            h.service
                .record_registration_grant(
                    &approval,
                    CredentialRef::with_default_domain(b"c"),
                    64,
                    4,
                )
                .unwrap();
            let rule = h.grants.rules.lock().unwrap()[0].clone();
            assert_eq!(rule.kind, GrantKind::Registration);
            assert_eq!(rule.source, RequestSource::PreRequest);
            assert_eq!(rule.origin.as_deref(), Some("https://www.r.example"));
        }

        #[test]
        fn two_ceremonies_racing_for_one_token_get_it_once() {
            for _ in 0..20 {
                let h = harness();
                let a = principal(1);
                issue_token(&h, "r.example", &a);
                let barrier = Arc::new(Barrier::new(2));
                let racers: Vec<_> = (0..2)
                    .map(|_| {
                        let service = Arc::clone(&h.service);
                        let barrier = Arc::clone(&barrier);
                        let a = a.clone();
                        thread::spawn(move || {
                            barrier.wait();
                            service
                                .take_pre_approval(consumer("r.example", &a))
                                .is_some()
                        })
                    })
                    .collect();
                let won: usize = racers
                    .into_iter()
                    .map(|racer| usize::from(racer.join().unwrap()))
                    .sum();
                assert_eq!(won, 1);
                assert_eq!(h.audit.count("pre_approval.consumed"), 1);
            }
        }

        #[test]
        fn a_token_lapses_after_its_ttl() {
            let h = harness();
            let a = principal(1);
            issue_token(&h, "r.example", &a);
            h.clock.advance(PRE_APPROVAL_TTL);
            h.service.sweep_pre_requests();
            assert_eq!(h.audit.last("pre_approval.expired")["reason"], "ttl");
            assert!(
                h.service
                    .take_pre_approval(consumer("r.example", &a))
                    .is_none()
            );
            // Asking again prompts again.
            assert_eq!(pre_reg(&h, "r.example", &a), PreRequestState::Pending);
        }

        #[test]
        fn a_token_lapsing_at_use_is_dropped_not_handed_out() {
            let h = harness();
            let a = principal(1);
            issue_token(&h, "r.example", &a);
            // No sweep ran: the check at use drops it.
            h.clock.advance(PRE_APPROVAL_TTL);
            assert!(
                h.service
                    .take_pre_approval(consumer("r.example", &a))
                    .is_none()
            );
            assert_eq!(h.audit.last("pre_approval.expired")["reason"], "ttl");
            assert_eq!(h.audit.count("pre_approval.consumed"), 0);
        }

        #[test]
        fn a_token_never_outlives_its_principal_session() {
            let h = harness();
            let a = principal(1);
            let mut short = params(pre(CeremonyAction::Register, "r.example", &a));
            short.session_remaining = Duration::from_secs(90);
            h.service.pre_request(short);
            approve_last(&h);
            match pre_reg(&h, "r.example", &a) {
                PreRequestState::PreApproved { expires_in } => {
                    assert!(expires_in <= Duration::from_secs(90))
                }
                other => panic!("unexpected {other:?}"),
            }
            assert!(
                h.audit.last("pre_approval.issued")["ttl_secs"]
                    .as_u64()
                    .unwrap()
                    <= 90
            );
        }

        #[test]
        fn every_revocation_path_drops_the_token() {
            type Revoke = fn(&Harness, &PrincipalSessionId);
            let paths: [(&str, Revoke); 6] = [
                ("session_end", |h, a| h.service.principal_session_ended(a)),
                ("lease_revoked", |h, a| h.service.lease_revoked(a)),
                ("policy_reload", |h, _| {
                    h.service.cancel_profile(&profile("p"))
                }),
                ("grant_revoked", |h, _| {
                    h.service.cancel_rp(&profile("p"), "r.example")
                }),
                ("grant_revoked", |h, _| {
                    h.service.cancel_profile_grants_cleared(&profile("p"))
                }),
                ("policy_reload", |h, _| {
                    h.epoch.bump();
                    h.service.sweep_pre_requests();
                }),
            ];
            for (reason, revoke) in paths {
                let h = harness();
                let a = principal(1);
                issue_token(&h, "r.example", &a);
                revoke(&h, &a);
                assert_eq!(
                    h.audit.last("pre_approval.expired")["reason"],
                    reason,
                    "{reason}"
                );
                assert!(
                    h.service
                        .take_pre_approval(consumer("r.example", &a))
                        .is_none(),
                    "{reason}"
                );
            }
            // A revocation of another RP, or another session's end or lease, leaves it.
            let h = harness();
            let a = principal(1);
            issue_token(&h, "r.example", &a);
            h.service.cancel_rp(&profile("p"), "other.example");
            h.service.principal_session_ended(&principal(2));
            h.service.lease_revoked(&principal(2));
            assert_eq!(h.audit.count("pre_approval.expired"), 0);
            assert!(
                h.service
                    .take_pre_approval(consumer("r.example", &a))
                    .is_some()
            );
        }

        #[test]
        fn an_epoch_bump_at_use_and_a_rule_change_drop_the_token() {
            let h = harness();
            let a = principal(1);
            issue_token(&h, "r.example", &a);
            h.epoch.bump();
            assert!(
                h.service
                    .take_pre_approval(consumer("r.example", &a))
                    .is_none()
            );
            assert_eq!(
                h.audit.last("pre_approval.expired")["reason"],
                "policy_reload"
            );

            let h = harness();
            issue_token(&h, "r.example", &a);
            let mut through_wildcard = consumer("r.example", &a);
            through_wildcard.rule = PermittingRule::Wildcard;
            assert!(h.service.take_pre_approval(through_wildcard).is_none());
            assert!(
                h.service
                    .take_pre_approval(consumer("r.example", &a))
                    .is_none()
            );
        }

        #[test]
        fn a_session_end_withdraws_its_pending_pre_request() {
            let h = harness();
            let a = principal(1);
            pre_reg(&h, "r.example", &a);
            h.service.principal_session_ended(&a);
            assert_eq!(h.prompter.withdrawn().len(), 1);
            assert_eq!(h.audit.last("escalation.expired")["reason"], "aborted");
            assert!(h.service.lock().pre_requests.is_empty());
            assert!(h.service.lock().entries.is_empty());
            // Nothing is left to adopt.
            assert!(
                h.service
                    .precheck(&ceremony_register("r.example", 1, &a))
                    .is_ok()
            );
        }

        #[test]
        fn a_grant_revocation_forgets_an_unreported_approval() {
            let h = harness();
            let a = principal(1);
            pre_auth(&h, "a.example", &a);
            approve_last(&h);
            // The operator revokes the grant before the agent polled: the next request is new.
            h.service.cancel_rp(&profile("p"), "a.example");
            assert_eq!(pre_auth(&h, "a.example", &a), PreRequestState::Pending);
            assert_eq!(h.prompter.shown().len(), 2);
        }

        #[test]
        fn a_reload_revokes_a_pending_pre_request() {
            let h = harness();
            let a = principal(1);
            pre_auth(&h, "a.example", &a);
            h.service.cancel_profile(&profile("p"));
            assert_eq!(pre_auth(&h, "a.example", &a), PreRequestState::Revoked);
        }

        #[test]
        fn a_panic_while_recording_issued_settles_the_pre_approval_and_frees_its_cap_slot() {
            let h = harness();
            let a = principal(1);
            let wildcard = |rp_id: &str, who: &PrincipalSessionId| EscalationRequest {
                rule: PermittingRule::Wildcard,
                mode: AgentMode::SameUser,
                max_wildcard_registrations: 1,
                wildcard_registration_prompts_per_day: 24,
                ..pre(CeremonyAction::Register, rp_id, who)
            };
            assert_eq!(
                h.service.pre_request(params(wildcard("w.example", &a))),
                PreRequestState::Pending
            );
            let ticket = h.prompter.last_shown();
            h.audit.panic_on("pre_approval.issued");
            h.clock.advance(Duration::from_secs(2));
            let svc = h.service.clone();
            let unwound = panic::catch_unwind(AssertUnwindSafe(|| {
                svc.prompt_event(&ticket, PromptEvent::Approved)
            }));
            assert!(unwound.is_err(), "the injected panic reaches the caller");
            h.audit.panicking.lock().unwrap().clear();

            // The record is neither waiting nor holding a token.
            {
                let inner = h.service.lock();
                for record in inner.pre_requests.values() {
                    assert!(
                        !matches!(
                            record.status,
                            PreStatus::Pending | PreStatus::Issuing { .. } | PreStatus::Token(_)
                        ),
                        "left behind: {:?}",
                        record.settled_at
                    );
                }
            }
            // The requester is told `unavailable` (`Refused(AuditFailure)`), once.
            assert_eq!(
                h.service.pre_request(params(wildcard("w.example", &a))),
                PreRequestState::Refused(EscalationRefusal::AuditFailure)
            );
            // Another session's wildcard registration is not refused for the dead slot, even
            // after the first session ends and the pre-approval TTL has passed.
            h.service.principal_session_ended(&a);
            h.clock.advance(PRE_APPROVAL_TTL + PRE_REQUEST_WINDOW);
            h.service.sweep_pre_requests();
            assert_eq!(
                h.service
                    .pre_request(params(wildcard("v.example", &principal(2)))),
                PreRequestState::Pending
            );
            assert_eq!(h.audit.count("pre_approval.issued"), 0);
        }

        #[test]
        fn a_failed_requested_record_refuses_the_joining_pre_request_only() {
            let h = harness();
            let ceremony = h
                .service
                .join_or_create(request("p", "b.example", 1))
                .unwrap();
            let b = principal(2);
            h.audit.fail("escalation.requested");
            assert_eq!(
                pre_auth(&h, "b.example", &b),
                PreRequestState::Refused(EscalationRefusal::AuditFailure)
            );
            h.audit.failing.lock().unwrap().clear();
            // Nothing of the joiner is left: no record, no waiter, no rate-limit charge.
            {
                let inner = h.service.lock();
                assert!(inner.pre_requests.is_empty());
                assert!(!inner.pre_request_history.contains_key(&b));
                let entry = inner.entries.values().next().unwrap();
                assert_eq!(entry.waiters.len(), 1, "only the ceremony waits");
            }
            assert_eq!(h.audit.count("escalation.requested"), 1);
            // The escalation and its waiter are unaffected.
            let parked = park(ceremony);
            approve_last(&h);
            assert!(matches!(
                parked.join().unwrap(),
                EscalationOutcome::Approved { .. }
            ));
            assert_eq!(h.audit.count("escalation.approved"), 1);
        }

        #[test]
        fn the_joiners_requested_record_precedes_approved() {
            let h = harness();
            let ceremony = h
                .service
                .join_or_create(request("p", "b.example", 1))
                .unwrap();
            let b = principal(2);
            // The human approves while the joiner's record is being written: the joiner is not
            // attached yet, so it can never be announced after `approved`.
            let svc = h.service.clone();
            let prompter = h.prompter.clone();
            let clock = h.clock.clone();
            let fired = Arc::new(AtomicBool::new(false));
            h.audit.hook("escalation.requested", move || {
                if !fired.swap(true, Ordering::SeqCst) {
                    clock.advance(Duration::from_secs(2));
                    svc.prompt_event(&prompter.last_shown(), PromptEvent::Approved);
                }
            });
            let parked = park(ceremony);
            let _ = pre_auth(&h, "b.example", &b);
            assert!(matches!(
                parked.join().unwrap(),
                EscalationOutcome::Approved { .. }
            ));
            let kinds = h.audit.kinds();
            let approved = kinds
                .iter()
                .position(|kind| kind == "escalation.approved")
                .unwrap();
            let joiner_requested = h
                .audit
                .events
                .lock()
                .unwrap()
                .iter()
                .position(|event| {
                    event["kind"] == "escalation.requested" && event["source"] == "pre_request"
                })
                .unwrap();
            assert!(joiner_requested < approved, "{kinds:?}");
        }

        #[test]
        fn a_wildcard_token_holds_its_cap_slot_until_used_or_dropped() {
            let h = harness();
            let a = principal(1);
            let wildcard = |rp_id: &str, who: &PrincipalSessionId| EscalationRequest {
                rule: PermittingRule::Wildcard,
                mode: AgentMode::SameUser,
                max_wildcard_registrations: 1,
                wildcard_registration_prompts_per_day: 24,
                ..pre(CeremonyAction::Register, rp_id, who)
            };
            assert_eq!(
                h.service.pre_request(params(wildcard("w.example", &a))),
                PreRequestState::Pending
            );
            approve_last(&h);
            // The token holds the only slot: another wildcard registration is refused.
            let other = EscalationRequest {
                max_wildcard_registrations: 1,
                wildcard_registration_prompts_per_day: 24,
                ..wildcard_register("p", "v.example", 1)
            };
            assert_eq!(
                h.service.precheck(&other),
                Err(EscalationRefusal::WildcardRegistrationCap)
            );
            assert_eq!(
                h.service
                    .pre_request(params(wildcard("v.example", &principal(2)))),
                PreRequestState::Refused(EscalationRefusal::WildcardRegistrationCap)
            );
            // Dropping it frees the slot.
            h.service.principal_session_ended(&a);
            assert_eq!(h.service.precheck(&other), Ok(()));
        }

        #[test]
        fn adoption_does_not_count_the_wildcard_limits_twice() {
            let h = harness();
            let a = principal(1);
            let request = EscalationRequest {
                rule: PermittingRule::Wildcard,
                mode: AgentMode::SameUser,
                max_wildcard_registrations: 1,
                wildcard_registration_prompts_per_day: 1,
                ..pre(CeremonyAction::Register, "w.example", &a)
            };
            assert_eq!(
                h.service.pre_request(params(request)),
                PreRequestState::Pending
            );
            // At the cap and the daily limit, counting the pre-request itself: its own
            // ceremony still adopts it.
            let ceremony = EscalationRequest {
                principal: Some(a.clone()),
                max_wildcard_registrations: 1,
                wildcard_registration_prompts_per_day: 1,
                ..wildcard_register("p", "w.example", 1)
            };
            assert_eq!(h.service.precheck(&ceremony), Ok(()));
            let waiter = h.service.join_or_create(ceremony).unwrap();
            assert!(waiter.joined());
        }

        #[test]
        fn a_pre_request_admitted_after_its_session_ended_is_withdrawn() {
            // Review L1: the runtime copies the requester out of its session list and releases
            // the list; the session can end (and its cleanup run) before the request is
            // admitted, and the cleanup then finds nothing to withdraw.
            let h = harness();
            let a = principal(1);
            h.service.principal_session_ended(&a);
            let state = h.service.pre_request_while(
                params(pre(CeremonyAction::Authenticate, "a.example", &a)),
                &|| false,
            );
            assert_eq!(state, PreRequestState::Expired);
            // The prompt that was raised is withdrawn, and nothing of the session is left.
            assert_eq!(h.prompter.shown().len(), 1);
            assert_eq!(h.prompter.withdrawn().len(), 1);
            {
                let inner = h.service.lock();
                assert!(inner.pre_requests.is_empty());
                assert!(!inner.pre_request_history.contains_key(&a));
                assert!(inner.entries.is_empty(), "the entry is collected");
            }
            // Nothing keeps it alive until its own deadline.
            h.clock.advance(Duration::from_secs(599));
            h.service.sweep_pre_requests();
            assert_eq!(h.prompter.withdrawn().len(), 1);
            // A late approval of the withdrawn prompt persists no grant.
            assert!(h.grants.rules.lock().unwrap().is_empty());
            // A session that is still there is not touched.
            assert_eq!(
                h.service.pre_request_while(
                    params(pre(
                        CeremonyAction::Authenticate,
                        "b.example",
                        &principal(2)
                    )),
                    &|| true
                ),
                PreRequestState::Pending
            );
            assert_eq!(h.service.lock().pre_requests.len(), 1);
        }

        #[test]
        fn a_sweep_during_the_decision_does_not_discard_the_approval() {
            // Review L4: the deadline passes while the human's approval is being written.
            for action in [CeremonyAction::Register, CeremonyAction::Authenticate] {
                let h = harness();
                let a = principal(1);
                let request = |h: &Harness| {
                    h.service
                        .pre_request(params(pre(action, "r.example", &principal(1))))
                };
                assert_eq!(request(&h), PreRequestState::Pending);
                let service = h.service.clone();
                let clock = h.clock.clone();
                h.audit.hook("escalation.approved", move || {
                    clock.advance(PRE_REQUEST_PENDING_LIMIT);
                    service.sweep_pre_requests();
                });
                approve_last(&h);
                match action {
                    CeremonyAction::Register => {
                        assert!(
                            matches!(request(&h), PreRequestState::PreApproved { .. }),
                            "a register approval issues a pre-approval"
                        );
                        assert_eq!(h.audit.count("pre_approval.issued"), 1);
                        assert!(h.service.has_pre_approval(&consumer("r.example", &a)));
                    }
                    CeremonyAction::Authenticate => {
                        assert_eq!(request(&h), PreRequestState::Approved);
                        assert_eq!(h.grants.rules.lock().unwrap().len(), 1);
                    }
                }
                assert_eq!(h.audit.count("escalation.approved"), 1);
                assert_eq!(h.audit.count("escalation.expired"), 0);
                // An undecided pre-request still expires at its deadline.
                let h = harness();
                assert_eq!(request(&h), PreRequestState::Pending);
                h.clock.advance(PRE_REQUEST_PENDING_LIMIT);
                h.service.sweep_pre_requests();
                assert_eq!(request(&h), PreRequestState::Expired);
            }
        }

        #[test]
        fn a_pre_approval_is_usable_only_after_its_issue_is_recorded() {
            // Review N1: `issued` is on the audit trail before the token can be consumed.
            let h = harness();
            let a = principal(1);
            let early = Arc::new(Mutex::new(Vec::new()));
            {
                let service = h.service.clone();
                let a = a.clone();
                let early = early.clone();
                h.audit.hook("pre_approval.issued", move || {
                    // While `issued` is being recorded the token is neither visible nor usable.
                    let c = consumer("r.example", &a);
                    early.lock().unwrap().push((
                        service.has_pre_approval(&c),
                        service.take_pre_approval(c).is_some(),
                    ));
                });
            }
            assert_eq!(pre_reg(&h, "r.example", &a), PreRequestState::Pending);
            approve_last(&h);
            assert_eq!(*early.lock().unwrap(), [(false, false)]);
            // Once recorded it is usable, and `consumed` follows `issued`.
            assert!(matches!(
                pre_reg(&h, "r.example", &a),
                PreRequestState::PreApproved { .. }
            ));
            assert!(
                h.service
                    .take_pre_approval(consumer("r.example", &a))
                    .is_some()
            );
            let kinds = h.audit.kinds();
            let position = |kind: &str| kinds.iter().position(|k| k == kind).unwrap();
            assert!(position("pre_approval.issued") < position("pre_approval.consumed"));
            assert_eq!(h.audit.count("pre_approval.issued"), 1);
            assert_eq!(h.audit.count("pre_approval.consumed"), 1);
        }

        #[test]
        fn a_pre_approval_whose_issue_cannot_be_recorded_is_not_issued() {
            let h = harness();
            let a = principal(1);
            let wildcard = |who: &PrincipalSessionId| EscalationRequest {
                rule: PermittingRule::Wildcard,
                mode: AgentMode::SameUser,
                max_wildcard_registrations: 1,
                wildcard_registration_prompts_per_day: 24,
                ..pre(CeremonyAction::Register, "w.example", who)
            };
            h.audit.fail("pre_approval.issued");
            assert_eq!(
                h.service.pre_request(params(wildcard(&a))),
                PreRequestState::Pending
            );
            approve_last(&h);
            // Fail closed: no token, and the agent is told it is unavailable.
            assert_eq!(h.audit.count("pre_approval.issued"), 0);
            let mut c = consumer("w.example", &a);
            c.rule = PermittingRule::Wildcard;
            assert!(!h.service.has_pre_approval(&c));
            assert!(h.service.take_pre_approval(c).is_none());
            assert_eq!(h.audit.count("pre_approval.consumed"), 0);
            assert_eq!(
                h.service.pre_request(params(wildcard(&a))),
                PreRequestState::Refused(EscalationRefusal::AuditFailure)
            );
            // The wildcard cap slot is free again.
            assert_eq!(h.service.lock().reserved_wildcards(&profile("p")), 0);
            let other = EscalationRequest {
                max_wildcard_registrations: 1,
                wildcard_registration_prompts_per_day: 24,
                ..wildcard_register("p", "v.example", 1)
            };
            assert_eq!(h.service.precheck(&other), Ok(()));
        }

        #[test]
        fn a_pre_approval_dropped_while_its_issue_is_recorded_is_dropped_after_it() {
            let h = harness();
            let a = principal(1);
            {
                let service = h.service.clone();
                let a = a.clone();
                h.audit.hook("pre_approval.issued", move || {
                    service.principal_session_ended(&a);
                });
            }
            assert_eq!(pre_reg(&h, "r.example", &a), PreRequestState::Pending);
            approve_last(&h);
            let kinds = h.audit.kinds();
            let issued = kinds
                .iter()
                .position(|k| k == "pre_approval.issued")
                .unwrap();
            let expired = kinds
                .iter()
                .position(|k| k == "pre_approval.expired")
                .unwrap();
            assert!(issued < expired);
            assert_eq!(
                h.audit.last("pre_approval.expired")["reason"],
                "session_end"
            );
            assert!(
                h.service
                    .take_pre_approval(consumer("r.example", &a))
                    .is_none()
            );
            assert!(h.service.lock().pre_requests.is_empty());
        }

        #[test]
        fn the_prompt_of_an_adopted_pre_request_names_its_page_not_the_advance_request() {
            // Review N2: a ceremony that adopts the pre-request before it is shown gives it an
            // origin; the prompt must not also say that no page is waiting.
            let h = harness();
            let a = principal(1);
            // Another escalation holds the prompt, so the pre-request waits in the queue.
            let first = h
                .service
                .join_or_create(request("p", "first.example", 1))
                .unwrap();
            let first = park(first);
            assert_eq!(pre_reg(&h, "r.example", &a), PreRequestState::Pending);
            assert_eq!(h.prompter.shown().len(), 1);
            let ceremony = h
                .service
                .join_or_create(EscalationRequest {
                    origin: Some("https://www.r.example".to_string()),
                    ..ceremony_register("r.example", 5, &a)
                })
                .unwrap();
            let adopted = park(ceremony);
            approve_last(&h);
            assert!(matches!(
                first.join().unwrap(),
                EscalationOutcome::Approved { .. }
            ));
            assert_eq!(h.prompter.shown().len(), 2);
            let fields = h.prompter.shown.lock().unwrap()[1].1.clone();
            assert_eq!(fields.origin.as_deref(), Some("https://www.r.example"));
            assert!(!fields.requested_in_advance);
            let (_, body) = render_prompt(&fields).unwrap();
            assert!(body.contains("Origin: https://www.r.example"), "{body}");
            assert!(!body.contains("in advance"), "{body}");
            approve_last(&h);
            assert!(matches!(
                adopted.join().unwrap(),
                EscalationOutcome::RegistrationApproved(_)
            ));
            // A pre-request nobody adopted still says so.
            let h = harness();
            assert_eq!(pre_reg(&h, "r.example", &a), PreRequestState::Pending);
            let fields = h.prompter.shown.lock().unwrap()[0].1.clone();
            assert!(fields.requested_in_advance && fields.origin.is_none());
        }
    }
}
