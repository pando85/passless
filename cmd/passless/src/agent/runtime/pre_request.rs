//! `PrincipalRequest::RequestAccess`: the agent asks before it navigates (ADR 0014 amendment
//! section 2.3).
//!
//! The principal checks of `handle_principal` (capability, peer credentials, process identity,
//! namespaces, cgroup, ancestry) have passed and identified the requester's principal session.
//! The handler releases the `managed_sessions` slot before anything else: a pre-request may wait
//! for the human (LOCKING.md rule 3). Then, in the amendment's order:
//!
//! 1. the action is listed in the profile's live `pre_request_actions` (`not_enabled`);
//! 2. the RP ID validates (`validate_rp_id`: normalized, no IP, no public suffix);
//! 3. resolution against the live policy and grants: `allow` is `already_allowed` and `deny` (or
//!    no rule) `not_requestable`, both without a prompt; only `request` continues. A registration
//!    through `*` also needs a same-user profile listed in `acknowledge_global_registration`
//!    (checked again here, fail closed, as the ceremony does);
//! 4. for `register`, the principal session must own the browser its ceremonies will run in:
//!    any session under `browser_scope = "session"`, the owner under `"profile"`, or any session
//!    while the profile has no shared browser (it would own the next one);
//! 5. the escalation service: the session's limits, then the ceremony-time pre-checks, then a
//!    detached waiter ([`EscalationService::pre_request`]);
//! 6. an optional wait for the decision, bounded by `wait_ms`.
//!
//! Every refusal is audited as `policy.deny` and coalesced per principal session, like a
//! ceremony's. The answer never says whether the user holds a credential, and never contains
//! anything the agent sent except the validated RP ID. The note goes to `escalation.requested`
//! only, sanitized with the prompt's rules and cut to [`passless_core::agent::protocol::MAX_ACCESS_NOTE_BYTES`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use log::info;

use passless_core::agent::config::validate_rp_id;
use passless_core::agent::protocol::{
    AccessRequestState, AccessRequestStatus, ErrorCode, GrantAction, MAX_ACCESS_WAIT_MS,
    PrincipalResponse, ProtocolError, RecommendedAction,
};
use passless_core::agent::{
    AgentMode, BrowserScope, PreRequestAction, PrincipalSessionId, ProfileId, RuleAction,
    RuleIdentity,
};

use super::{AgentRuntime, ProfileRuntime};
use crate::agent::audit_events::{
    AuditAction, OperationRecord, PolicyDenyBuilder, PolicyDenyReason,
};
use crate::agent::escalation::{
    EscalationRefusal, EscalationRequest, PRE_REQUEST_PENDING_LIMIT, PreRequestParams,
    PreRequestState, StoreCounter, WaiterSession,
};
use crate::agent::escalation_prompt::sanitize_agent_note;
use crate::agent::granted_rules::{PermittingRule, RequestSource};
use crate::agent::refusal_ledger::{Admission, RefusalKey, RefusalLedger, SummaryTemplate};
use crate::agent::register::StorageCounter;
use crate::agent::session::CeremonyAction;

/// Per principal session bookkeeping of pre-requests: the refusal ledgers (ADR 0014 sections 9
/// and 12, review M2: refusals are coalesced per session) and the parked calls. Plain
/// bookkeeping mutexes: only the map or set is touched under each, never held across another
/// lock, and a removed ledger is dropped (which writes its pending counts) after it is released.
#[derive(Default)]
pub(crate) struct PreRequestRefusals {
    ledgers: Mutex<HashMap<PrincipalSessionId, Arc<RefusalLedger>>>,
    /// Principal sessions with a `RequestAccess` call parked in [`EscalationService::wait_pre_request`].
    /// A parked call holds a principal worker thread (the runtime has [`super::MAX_WORKERS`],
    /// shared with the admin socket), so each session parks at most one call and the daemon at
    /// most [`MAX_PARKED_PRE_REQUEST_CALLS`]; any other call answers the state at once.
    parked: Mutex<std::collections::HashSet<PrincipalSessionId>>,
}

/// `RequestAccess` calls that may wait for the human at once, daemon-wide: a quarter of the
/// worker threads, so waiting agents never starve the admin socket.
pub(crate) const MAX_PARKED_PRE_REQUEST_CALLS: usize = super::MAX_WORKERS / 4;

/// A parked call's slot; released on drop.
pub(crate) struct ParkedCall<'a> {
    refusals: &'a PreRequestRefusals,
    session: PrincipalSessionId,
}

impl Drop for ParkedCall<'_> {
    fn drop(&mut self) {
        self.refusals
            .parked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.session);
    }
}

impl PreRequestRefusals {
    /// A slot for one parked call of `session`, if neither it nor the daemon is at its limit.
    pub(crate) fn park(&self, session: &PrincipalSessionId) -> Option<ParkedCall<'_>> {
        let mut parked = self
            .parked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if parked.len() >= MAX_PARKED_PRE_REQUEST_CALLS || !parked.insert(session.clone()) {
            return None;
        }
        Some(ParkedCall {
            refusals: self,
            session: session.clone(),
        })
    }

    fn ledger(&self, session: &PrincipalSessionId) -> Arc<RefusalLedger> {
        self.ledgers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(session.clone())
            .or_default()
            .clone()
    }

    /// Account for one refusal of `session` in its ledger. The ledger is created on demand, so a
    /// refusal that races the session's end would recreate one that nothing removes: when
    /// `alive()` (called with no lock held) says the session is gone afterwards, the ledger is
    /// forgotten again, as [`Self::session_ended`] does.
    fn admit(
        &self,
        session: &PrincipalSessionId,
        key: RefusalKey,
        now: Instant,
        template: impl FnOnce() -> SummaryTemplate,
        alive: impl FnOnce() -> bool,
    ) -> Admission {
        let admission = self.ledger(session).admit(key, now, template);
        if !alive() {
            self.session_ended(session);
        }
        admission
    }

    /// Forget a principal session that ended; its pending counts are written as the ledger
    /// drops.
    pub(crate) fn session_ended(&self, session: &PrincipalSessionId) {
        let removed = self
            .ledgers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(session);
        drop(removed);
    }
}

/// What the requester is: copied out of the `managed_sessions` slot before it is released.
pub(super) struct Requester {
    pub session_id: PrincipalSessionId,
    /// The principal session's own deadline: a pre-approval never outlives it.
    pub deadline: Instant,
}

/// The arguments of one `RequestAccess`.
pub(super) struct AccessRequest<'a> {
    pub rp_id: &'a str,
    pub action: &'a GrantAction,
    pub note: Option<&'a str>,
    pub wait_ms: Option<u64>,
}

fn status(
    state: AccessRequestState,
    rp_id: &str,
    action: &GrantAction,
    message: impl Into<String>,
) -> AccessRequestStatus {
    AccessRequestStatus {
        state,
        rp_id: rp_id.to_string(),
        action: action.clone(),
        expires_in_secs: None,
        retry_after_secs: None,
        message: message.into(),
    }
}

fn ceremony_action(action: &GrantAction) -> CeremonyAction {
    match action {
        GrantAction::Authenticate => CeremonyAction::Authenticate,
        GrantAction::Register => CeremonyAction::Register,
    }
}

fn audit_action(action: &GrantAction) -> AuditAction {
    match action {
        GrantAction::Authenticate => AuditAction::Authenticate,
        GrantAction::Register => AuditAction::Register,
    }
}

fn pre_request_action(action: &GrantAction) -> PreRequestAction {
    match action {
        GrantAction::Authenticate => PreRequestAction::Authenticate,
        GrantAction::Register => PreRequestAction::Register,
    }
}

/// The answer to a pre-request's state. The messages are the daemon's own words; the only input
/// they name is the validated RP ID.
pub(crate) fn access_status(
    state: &PreRequestState,
    rp_id: &str,
    action: &GrantAction,
) -> AccessRequestStatus {
    let register = *action == GrantAction::Register;
    match state {
        PreRequestState::Pending => status(
            AccessRequestState::Pending,
            rp_id,
            action,
            "Waiting for the human's decision. Call again later with the same arguments; the \
             request stays pending for up to 10 minutes.",
        ),
        PreRequestState::Adopted => status(
            AccessRequestState::Pending,
            rp_id,
            action,
            "A registration in this browser took the request over and waits for the human's \
             decision; finish it in the page.",
        ),
        PreRequestState::Approved => status(
            AccessRequestState::Approved,
            rp_id,
            action,
            format!(
                "Sign-in approved for {rp_id}. Navigate there and use the site's normal WebAuthn \
                 sign-in; it will not ask the human again."
            ),
        ),
        PreRequestState::PreApproved { expires_in } => {
            let secs = expires_in.as_secs();
            AccessRequestStatus {
                expires_in_secs: Some(secs),
                ..status(
                    AccessRequestState::Approved,
                    rp_id,
                    action,
                    format!(
                        "Registration approved once for {rp_id} in this browser for {} minutes, or \
                         until this session or MCP server exits, whichever comes first. Navigate \
                         there and use the site's normal WebAuthn registration.",
                        secs.div_ceil(60)
                    ),
                )
            }
        }
        PreRequestState::Denied {
            reason: Some(PolicyDenyReason::EscalationUnavailable),
        } => status(
            AccessRequestState::Unavailable,
            rp_id,
            action,
            "No prompt could be shown: there is no usable notification server.",
        ),
        PreRequestState::Denied { reason: None } => status(
            AccessRequestState::Denied,
            rp_id,
            action,
            format!(
                "The human denied it. Asking again for {rp_id} is refused while its cooldown \
                 runs."
            ),
        ),
        PreRequestState::Denied { reason: Some(_) } => status(
            AccessRequestState::Denied,
            rp_id,
            action,
            "The approval could not be recorded, so it counts as denied.",
        ),
        PreRequestState::Expired => status(
            AccessRequestState::Expired,
            rp_id,
            action,
            "The request ended without a decision.",
        ),
        PreRequestState::Revoked => status(
            AccessRequestState::Expired,
            rp_id,
            action,
            "A policy change cancelled the request.",
        ),
        PreRequestState::RateLimited { retry_after } => AccessRequestStatus {
            retry_after_secs: retry_after.map(|after| after.as_secs().max(1)),
            ..status(
                AccessRequestState::RateLimited,
                rp_id,
                action,
                "This session has a pending request already, or asked too often; wait for it, \
                 then call again.",
            )
        },
        PreRequestState::Refused(refusal) => refused_status(*refusal, rp_id, action, register),
    }
}

fn refused_status(
    refusal: EscalationRefusal,
    rp_id: &str,
    action: &GrantAction,
    register: bool,
) -> AccessRequestStatus {
    let (state, message): (AccessRequestState, String) = match refusal {
        EscalationRefusal::Cooldown => (
            AccessRequestState::Cooldown,
            format!("{rp_id} is in its cooldown after a recent deny or timeout."),
        ),
        EscalationRefusal::WildcardRegistrationCooldown => (
            AccessRequestState::Cooldown,
            "Registrations at unlisted sites are in their cooldown after a recent deny or \
             timeout."
                .to_string(),
        ),
        EscalationRefusal::Unavailable | EscalationRefusal::AuditFailure => (
            AccessRequestState::Unavailable,
            "No prompt can be shown right now.".to_string(),
        ),
        EscalationRefusal::Busy => (
            AccessRequestState::Busy,
            if register {
                format!("Another registration request for {rp_id} is in progress.")
            } else {
                format!("Another request for {rp_id} is in progress.")
            },
        ),
        EscalationRefusal::QueueFull
        | EscalationRefusal::WaiterCap
        | EscalationRefusal::TrackingFull => (
            AccessRequestState::Busy,
            "Too many requests are waiting for the human; try again later.".to_string(),
        ),
        EscalationRefusal::PreRequestRateLimited | EscalationRefusal::WildcardRegistrationRate => (
            AccessRequestState::RateLimited,
            "Too many requests recently; try again later.".to_string(),
        ),
        EscalationRefusal::GrantCapReached
        | EscalationRefusal::GrantsUnavailable
        | EscalationRefusal::WildcardRegistrationCap => (
            AccessRequestState::NotRequestable,
            "The profile cannot record another approval; the operator must free one first."
                .to_string(),
        ),
    };
    status(state, rp_id, action, message)
}

/// Whether `session` may hold a registration pre-approval (ADR 0014 amendment section 2.3): it
/// owns the browser its registrations run in, or will own the next one. Under
/// `browser_scope = "session"` every session gets its own browser; under `"profile"` only the
/// session that launched the shared browser (`shared_owner`) owns it, and while none runs any
/// session may launch it.
pub(crate) fn owns_or_will_own_browser(
    scope: BrowserScope,
    shared_owner: Option<&PrincipalSessionId>,
    session: &PrincipalSessionId,
) -> bool {
    match scope {
        BrowserScope::Session => true,
        BrowserScope::Profile => shared_owner.is_none_or(|owner| owner == session),
    }
}

impl AgentRuntime {
    /// `PrincipalRequest::RequestAccess` (see the module documentation). Called with no lock held.
    pub(super) fn handle_request_access(
        &self,
        profile_id: &ProfileId,
        profile: &ProfileRuntime,
        requester: Requester,
        request: AccessRequest<'_>,
    ) -> Result<PrincipalResponse, ProtocolError> {
        let AccessRequest {
            rp_id,
            action,
            note,
            wait_ms,
        } = request;
        let respond = |status: AccessRequestStatus| Ok(PrincipalResponse::AccessRequest(status));
        let live_config = self.live_profile_config(profile);

        // 1. Opt-in per profile and action.
        if !live_config.pre_request_allows(pre_request_action(action)) {
            self.audit_pre_request_refusal(
                profile_id,
                profile,
                &requester.session_id,
                action,
                "unknown",
                None,
                PolicyDenyReason::PreRequestNotEnabled,
            );
            return respond(status(
                AccessRequestState::NotEnabled,
                rp_id,
                action,
                format!(
                    "The profile does not allow asking in advance for {}; the operator can list \
                     it in pre_request_actions.",
                    pre_request_action(action).as_str()
                ),
            ));
        }

        // 2. The RP ID, as every rule and grant names it. A malformed one is a malformed call.
        let normalized = validate_rp_id(rp_id).map_err(|e| {
            ProtocolError::new(
                ErrorCode::BadRequest,
                format!("request_access: invalid RP ID: {e}"),
                RecommendedAction::FixRequest,
            )
        })?;
        let rp_id = normalized.as_str();

        // 3. Resolution first, against the live policy and grants.
        let matched = self.policy_runtime.resolve(profile_id, action, rp_id);
        let not_requestable = |message: String| {
            self.audit_pre_request_refusal(
                profile_id,
                profile,
                &requester.session_id,
                action,
                rp_id,
                Some(&matched.rule),
                PolicyDenyReason::NotRequestable,
            );
            respond(status(
                AccessRequestState::NotRequestable,
                rp_id,
                action,
                message,
            ))
        };
        let rule = match (matched.action, &matched.rule) {
            (RuleAction::Allow, _) => {
                return respond(status(
                    AccessRequestState::AlreadyAllowed,
                    rp_id,
                    action,
                    format!(
                        "Already allowed at {rp_id}; navigate there and use the site's normal \
                         WebAuthn flow."
                    ),
                ));
            }
            (RuleAction::Request, RuleIdentity::Exact(_)) => PermittingRule::Exact,
            (RuleAction::Request, RuleIdentity::Wildcard) => PermittingRule::Wildcard,
            _ => {
                return not_requestable(format!(
                    "The policy does not let the human approve this at {rp_id}."
                ));
            }
        };
        let Some(escalation_profile) = self.policy_runtime.escalation_profile(profile_id) else {
            return not_requestable("The profile no longer exists.".to_string());
        };
        if *action == GrantAction::Register
            && rule == PermittingRule::Wildcard
            && (escalation_profile.mode != AgentMode::SameUser
                || !escalation_profile.wildcard_registration_acknowledged)
        {
            return not_requestable(format!(
                "The policy does not let the human approve this at {rp_id}."
            ));
        }

        // 4. A registration pre-approval binds to this principal session: only a session whose
        //    browser runs the ceremony may ask for one.
        if *action == GrantAction::Register
            && !self.may_own_browser(profile, &live_config.browser_scope, &requester.session_id)
        {
            return not_requestable(
                "Another session owns this profile's browser; ask from the session that \
                 launched it."
                    .to_string(),
            );
        }

        // 5. The escalation service: the session's limits and the ceremony-time pre-checks.
        let pending_for = escalation_profile
            .escalation_timeout
            .map_or(PRE_REQUEST_PENDING_LIMIT, |timeout| {
                timeout.min(PRE_REQUEST_PENDING_LIMIT)
            });
        let now = Instant::now();
        let session_remaining = requester.deadline.saturating_duration_since(now);
        let store_counter: Option<Arc<dyn StoreCounter>> =
            (*action == GrantAction::Register).then(|| {
                Arc::new(StorageCounter(profile.backend.credential_storage.clone()))
                    as Arc<dyn StoreCounter>
            });
        let escalation_request = EscalationRequest {
            profile: profile_id.clone(),
            rp_id: rp_id.to_string(),
            action: ceremony_action(action),
            origin: None,
            rule,
            session: WaiterSession::of_principal(&requester.session_id),
            source: RequestSource::PreRequest,
            principal: Some(requester.session_id.clone()),
            agent_note: sanitize_agent_note(note),
            mode: escalation_profile.mode,
            principal_user: escalation_profile.principal_user.clone(),
            max_granted_rules: escalation_profile.max_granted_rules,
            max_wildcard_registrations: escalation_profile.max_wildcard_registrations,
            wildcard_registration_prompts_per_day: escalation_profile
                .wildcard_registration_prompts_per_day,
            store_counter,
        };
        let key = escalation_request.key();
        // `handle_principal` released the session's slot before this call, so the session may
        // have ended since (review L1): the request is then withdrawn at once, and the session's
        // refusal ledger is dropped too, as `cleanup_browser_for_session` would have done had it
        // run after this call. The slot is taken alone, with no lock held.
        let session_alive = || self.principal_session_alive(profile_id, &requester.session_id);
        let mut state = self.escalation.pre_request_while(
            PreRequestParams {
                request: escalation_request,
                pending_for,
                session_remaining,
            },
            &session_alive,
        );
        if state == PreRequestState::Expired && !session_alive() {
            self.pre_request_refusals
                .session_ended(&requester.session_id);
            info!(
                "agent pre-request: profile={} rp={} action={:?} -> its session ended",
                profile_id, rp_id, action
            );
            return respond(access_status(&state, rp_id, action));
        }

        // 6. Wait for the decision, if asked to, holding no lock.
        let wait = Duration::from_millis(wait_ms.unwrap_or(0).min(MAX_ACCESS_WAIT_MS));
        if state == PreRequestState::Pending
            && !wait.is_zero()
            && let Some(_parked) = self.pre_request_refusals.park(&requester.session_id)
        {
            state = self.escalation.wait_pre_request(
                &requester.session_id,
                &key,
                Instant::now() + wait,
                &session_alive,
            );
        }

        let reason = match &state {
            PreRequestState::Refused(refusal) => Some(refusal.deny_reason()),
            PreRequestState::RateLimited { .. } => Some(PolicyDenyReason::PreRequestRateLimited),
            _ => None,
        };
        if let Some(reason) = reason {
            self.audit_pre_request_refusal(
                profile_id,
                profile,
                &requester.session_id,
                action,
                rp_id,
                Some(&matched.rule),
                reason,
            );
        }
        info!(
            "agent pre-request: profile={} rp={} action={:?} -> {:?}",
            profile_id, rp_id, action, state
        );
        respond(access_status(&state, rp_id, action))
    }

    /// Whether `session` owns, or would own, the browser its registrations run in (see
    /// [`owns_or_will_own_browser`]). A poisoned bookkeeping lock fails closed.
    fn may_own_browser(
        &self,
        profile: &ProfileRuntime,
        scope: &BrowserScope,
        session: &PrincipalSessionId,
    ) -> bool {
        let Ok(shared) = profile.shared_browsers.lock() else {
            return false;
        };
        let owner = shared
            .get(&profile.profile_id)
            .map(|lease| &lease.owner_session);
        owns_or_will_own_browser(*scope, owner, session)
    }

    /// Whether `session` is still a live principal session of `profile_id`. Takes the
    /// `managed_sessions` slot (rank 5) alone; called with no lock held.
    fn principal_session_alive(
        &self,
        profile_id: &ProfileId,
        session: &PrincipalSessionId,
    ) -> bool {
        self.managed_sessions.get(profile_id).is_some_and(|slot| {
            crate::agent::lock_order::lock(
                slot,
                crate::agent::lock_order::LockLevel::ManagedSession,
            )
            .iter()
            .any(|managed| managed.session_id == *session)
        })
    }

    /// A refused pre-request's `policy.deny` record, coalesced per principal session like a
    /// ceremony's refusals.
    #[allow(clippy::too_many_arguments)]
    fn audit_pre_request_refusal(
        &self,
        profile_id: &ProfileId,
        profile: &ProfileRuntime,
        session: &PrincipalSessionId,
        action: &GrantAction,
        rp_id: &str,
        rule: Option<&RuleIdentity>,
        reason: PolicyDenyReason,
    ) {
        let deployment = profile.audit_deployment();
        let rule = match rule {
            Some(RuleIdentity::Exact(_)) => Some("exact".to_string()),
            Some(RuleIdentity::Wildcard) => {
                Some(passless_core::agent::config::ANY_RP_ID.to_string())
            }
            _ => None,
        };
        let op = OperationRecord::new(profile_id.clone(), audit_action(action), rp_id)
            .deployment(
                deployment.mode.clone(),
                deployment.principal_relationship.clone(),
                deployment.backend.clone(),
                deployment.key_provider.clone(),
            )
            .epochs(
                self.policy_runtime.revocation_epoch(),
                self.policy_runtime.grant_epoch(),
            )
            .matched(rule, None);
        let key = RefusalKey::new(audit_action(action), rp_id, reason);
        // Refusals before the escalation service's liveness check (steps 1 to 4) can race the
        // session's end; its ledger is then dropped again.
        let admission = self.pre_request_refusals.admit(
            session,
            key,
            Instant::now(),
            || SummaryTemplate {
                gate: self.audit_gate.clone(),
                profile_id: profile_id.clone(),
                op: op.clone(),
            },
            || self.principal_session_alive(profile_id, session),
        );
        for summary in admission.summaries {
            summary.write();
        }
        if admission.write_in_full {
            let event =
                PolicyDenyBuilder::new(profile_id.clone(), audit_action(action), rp_id, reason)
                    .operation(op)
                    .build();
            let _ = self.audit_gate.record(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use passless_core::agent::protocol::MAX_ACCESS_NOTE_BYTES;

    const RP: &str = "example.org";

    #[test]
    fn a_session_parks_one_call_and_the_daemon_a_quarter_of_its_workers() {
        let refusals = PreRequestRefusals::default();
        let me = PrincipalSessionId::new();
        let first = refusals.park(&me).expect("a slot");
        assert!(refusals.park(&me).is_none(), "one parked call per session");
        drop(first);
        assert!(refusals.park(&me).is_some());
        let sessions: Vec<_> = (0..MAX_PARKED_PRE_REQUEST_CALLS)
            .map(|_| PrincipalSessionId::new())
            .collect();
        let slots: Vec<_> = sessions.iter().map(|s| refusals.park(s).unwrap()).collect();
        assert!(refusals.park(&PrincipalSessionId::new()).is_none());
        drop(slots);
        assert!(refusals.park(&PrincipalSessionId::new()).is_some());
        const { assert!(MAX_PARKED_PRE_REQUEST_CALLS < super::super::MAX_WORKERS) };
    }

    #[test]
    fn a_refusal_that_races_the_end_of_its_session_leaves_no_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let gate =
            Arc::new(crate::agent::audit::AuditGate::open(dir.path().join("audit")).unwrap());
        let profile = ProfileId::new("test-profile").unwrap();
        let op = OperationRecord::new(profile.clone(), AuditAction::Authenticate, RP);
        let refusals = PreRequestRefusals::default();
        let refuse = |session: &PrincipalSessionId, alive: bool| {
            let key = RefusalKey::new(
                AuditAction::Authenticate,
                RP,
                PolicyDenyReason::PreRequestNotEnabled,
            );
            refusals.admit(
                session,
                key,
                Instant::now(),
                || SummaryTemplate {
                    gate: gate.clone(),
                    profile_id: profile.clone(),
                    op: op.clone(),
                },
                || alive,
            )
        };

        // A live session keeps its ledger, so its refusals are coalesced.
        let live = PrincipalSessionId::new();
        assert!(refuse(&live, true).write_in_full);
        assert_eq!(refusals.ledgers.lock().unwrap().len(), 1);

        // A session that ended meanwhile does not get one that nothing would remove.
        let gone = PrincipalSessionId::new();
        assert!(refuse(&gone, false).write_in_full);
        let ledgers = refusals.ledgers.lock().unwrap();
        assert_eq!(ledgers.len(), 1);
        assert!(ledgers.contains_key(&live));
        assert!(!ledgers.contains_key(&gone));
    }

    #[test]
    fn only_the_browser_owner_may_hold_a_registration_pre_approval() {
        let me = PrincipalSessionId::new();
        let other = PrincipalSessionId::new();
        // Session scope: every session owns its own browser.
        assert!(owns_or_will_own_browser(BrowserScope::Session, None, &me));
        assert!(owns_or_will_own_browser(
            BrowserScope::Session,
            Some(&other),
            &me
        ));
        // Profile scope: the owner of the shared browser, or anyone while none runs.
        assert!(owns_or_will_own_browser(BrowserScope::Profile, None, &me));
        assert!(owns_or_will_own_browser(
            BrowserScope::Profile,
            Some(&me),
            &me
        ));
        assert!(!owns_or_will_own_browser(
            BrowserScope::Profile,
            Some(&other),
            &me
        ));
    }

    #[test]
    fn the_agent_note_is_sanitized_and_bounded() {
        assert_eq!(sanitize_agent_note(None), None);
        assert_eq!(sanitize_agent_note(Some("  \n\t ")), None);
        let hostile = format!(
            "Approve this\n<b>now</b>\u{202e}{}",
            "x".repeat(4 * MAX_ACCESS_NOTE_BYTES)
        );
        let note = sanitize_agent_note(Some(&hostile)).unwrap();
        assert!(note.len() <= MAX_ACCESS_NOTE_BYTES);
        assert!(!note.contains('\n') && !note.contains('<') && !note.contains('\u{202e}'));
        assert!(note.starts_with("Approve this bnow/b"));
        // A multi-byte character is never cut in half.
        let wide = "é".repeat(MAX_ACCESS_NOTE_BYTES);
        let note = sanitize_agent_note(Some(&wide)).unwrap();
        assert!(note.len() <= MAX_ACCESS_NOTE_BYTES);
        assert!(note.chars().all(|c| c == 'é'));
    }

    #[test]
    fn every_state_maps_to_its_wire_state_without_agent_text() {
        let auth = GrantAction::Authenticate;
        let reg = GrantAction::Register;
        let cases: Vec<(PreRequestState, &GrantAction, AccessRequestState)> = vec![
            (PreRequestState::Pending, &auth, AccessRequestState::Pending),
            (PreRequestState::Adopted, &reg, AccessRequestState::Pending),
            (
                PreRequestState::Approved,
                &auth,
                AccessRequestState::Approved,
            ),
            (
                PreRequestState::PreApproved {
                    expires_in: Duration::from_secs(597),
                },
                &reg,
                AccessRequestState::Approved,
            ),
            (
                PreRequestState::Denied { reason: None },
                &auth,
                AccessRequestState::Denied,
            ),
            (
                PreRequestState::Denied {
                    reason: Some(PolicyDenyReason::EscalationUnavailable),
                },
                &auth,
                AccessRequestState::Unavailable,
            ),
            (PreRequestState::Expired, &auth, AccessRequestState::Expired),
            (PreRequestState::Revoked, &auth, AccessRequestState::Expired),
            (
                PreRequestState::RateLimited {
                    retry_after: Some(Duration::from_secs(30)),
                },
                &auth,
                AccessRequestState::RateLimited,
            ),
            (
                PreRequestState::Refused(EscalationRefusal::Cooldown),
                &auth,
                AccessRequestState::Cooldown,
            ),
            (
                PreRequestState::Refused(EscalationRefusal::WildcardRegistrationCooldown),
                &reg,
                AccessRequestState::Cooldown,
            ),
            (
                PreRequestState::Refused(EscalationRefusal::Unavailable),
                &auth,
                AccessRequestState::Unavailable,
            ),
            (
                PreRequestState::Refused(EscalationRefusal::Busy),
                &reg,
                AccessRequestState::Busy,
            ),
            (
                PreRequestState::Refused(EscalationRefusal::WildcardRegistrationCap),
                &reg,
                AccessRequestState::NotRequestable,
            ),
            (
                PreRequestState::Refused(EscalationRefusal::PreRequestRateLimited),
                &auth,
                AccessRequestState::RateLimited,
            ),
        ];
        for (state, action, expected) in cases {
            let answer = access_status(&state, RP, action);
            assert_eq!(answer.state, expected, "{state:?}");
            assert_eq!(answer.rp_id, RP);
            assert_eq!(&answer.action, action);
            assert!(!answer.message.is_empty());
        }
        let approved = access_status(
            &PreRequestState::PreApproved {
                expires_in: Duration::from_secs(597),
            },
            RP,
            &reg,
        );
        assert_eq!(approved.expires_in_secs, Some(597));
        assert_eq!(
            approved.message,
            "Registration approved once for example.org in this browser for 10 minutes, or until \
             this session or MCP server exits, whichever comes first. Navigate there and use the \
             site's normal WebAuthn registration."
        );
        let limited = access_status(
            &PreRequestState::RateLimited {
                retry_after: Some(Duration::from_millis(1500)),
            },
            RP,
            &auth,
        );
        assert_eq!(limited.retry_after_secs, Some(1));
    }
}
