//! Per-ceremony audit (ADR 0014 section 12).
//!
//! Every authentication and registration builds one [`CeremonyAudit`]. It carries what the
//! operation records of that ceremony share (the session identity hash, the daemon-assigned request
//! ID, the deployment axes, the matched rule, the credential and the counters) and is the only
//! thing that writes them:
//!
//! - a refusal before the reservation is one `policy.deny` record ([`CeremonyAudit::deny`]);
//! - the durable reservation is one `policy.allow` record ([`CeremonyAudit::reserve`]), written
//!   before any key use (invariant 16); a failed write blocks key use;
//! - every reservation is closed by exactly one `operation.terminal` record, written by
//!   [`CeremonyAudit::conclude`] at the single exit point of the ceremony, or by the drop guard if
//!   the ceremony unwinds before it gets there. After the reservation a failure no longer writes a
//!   `policy.deny`: it is noted and becomes the terminal record's failure class, so a new early
//!   return after the reservation cannot skip the terminal record.
//!
//! Locking (`LOCKING.md`, rule 5): the audit gate is a terminal leaf and may be called with any
//! lock held. This module takes no lock of its own: its state is a `RefCell` that only the
//! ceremony's own thread touches, and the live epochs it reads are atomics.

use std::cell::RefCell;
use std::sync::Arc;

use log::warn;
use rand::RngCore;

use passless_core::agent::config::{ANY_RP_ID, CredentialSelection};
use passless_core::agent::protocol::ProtocolError;
use passless_core::agent::{AgentMode, CredentialRef, MatchedRule, ProfileId, RuleIdentity};

use super::audit::AuditGate;
use super::audit_events::{
    AuditAction, OperationRecord, OperationTerminalBuilder, PolicyAllowBuilder, PolicyDenyBuilder,
    PolicyDenyReason, RuleGrantSource,
};
use super::policy_engine::PolicyRuntime;
use super::session::AgentSession;

/// What an audit record says about where an operation ran (ADR 0014 sections 5 and 13): the two
/// deployment axes and the backend. Every field is null when unknown.
#[derive(Clone, Debug, Default)]
pub struct AuditDeployment {
    /// `same-user` or `isolated`.
    pub mode: Option<String>,
    /// `shared-uid` or `distinct-uid`, from the principal UID against the daemon UID.
    pub principal_relationship: Option<String>,
    /// `human` (the human backend a same-user profile shares), `local`, `pass` or `tpm`.
    pub backend: Option<String>,
    /// `software` or the portable key provider's name (`tpm`).
    pub key_provider: Option<String>,
}

impl AuditDeployment {
    pub fn new(
        mode: AgentMode,
        shared_uid: bool,
        backend: &str,
        key_provider: &dyn soft_fido2::CredentialKeyProvider,
    ) -> Self {
        let provider_id = key_provider.provider_id();
        let key_provider = if provider_id.is_software() {
            "software".to_string()
        } else {
            // A provider ID is a short ASCII name; anything else is reported as `other`.
            let id = provider_id.as_bytes();
            if !id.is_empty()
                && id.len() <= 32
                && id
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            {
                String::from_utf8_lossy(id).into_owned()
            } else {
                "other".to_string()
            }
        };
        Self {
            mode: Some(mode.to_string()),
            principal_relationship: Some(
                if shared_uid {
                    "shared-uid"
                } else {
                    "distinct-uid"
                }
                .to_string(),
            ),
            backend: Some(backend.to_string()),
            key_provider: Some(key_provider),
        }
    }
}

/// What a ceremony's records say about its request: the RP ID and the origin context. On the proxy
/// path the browser never supplies a top origin, so it is recorded as null.
#[derive(Clone, Copy)]
pub(crate) struct AuditTarget<'a> {
    pub rp_id: &'a str,
    pub origin: Option<&'a str>,
    pub top_origin: Option<&'a str>,
    pub cross_origin: Option<bool>,
    pub audit: &'a CeremonyAudit,
}

impl<'a> AuditTarget<'a> {
    pub fn of_request(
        audit: &'a CeremonyAudit,
        rp_id: &'a str,
        origin: &'a str,
        top_origin: Option<&'a str>,
        cross_origin: bool,
    ) -> Self {
        Self {
            rp_id,
            origin: Some(origin),
            top_origin,
            cross_origin: Some(cross_origin),
            audit,
        }
    }

    /// A record about an RP only (a refused request whose origin is not known).
    pub fn rp_only(audit: &'a CeremonyAudit, rp_id: &'a str) -> Self {
        Self {
            rp_id,
            origin: None,
            top_origin: None,
            cross_origin: None,
            audit,
        }
    }
}

/// The request an open reservation was made for, kept so the terminal record can be written from
/// anywhere (including a drop guard).
struct Reservation {
    rp_id: String,
    origin: Option<String>,
    top_origin: Option<String>,
    cross_origin: Option<bool>,
}

#[derive(Default)]
struct State {
    rule: Option<String>,
    grant_source: Option<RuleGrantSource>,
    escalation_id: Option<String>,
    credential_ref: Option<CredentialRef>,
    selection_rule: Option<String>,
    counter_before: Option<u32>,
    counter_after: Option<u32>,
    /// The first failure noted after the reservation.
    failure: Option<PolicyDenyReason>,
    /// Set while a reservation is open: its terminal record is still owed.
    reservation: Option<Reservation>,
}

/// The audit of one ceremony. See the module documentation.
pub(crate) struct CeremonyAudit {
    gate: Arc<AuditGate>,
    policy_runtime: Arc<PolicyRuntime>,
    deployment: AuditDeployment,
    session_id_hash: String,
    request_id: String,
    profile_id: ProfileId,
    action: AuditAction,
    state: RefCell<State>,
}

impl CeremonyAudit {
    pub fn new(
        gate: &Arc<AuditGate>,
        policy_runtime: &Arc<PolicyRuntime>,
        deployment: &AuditDeployment,
        session: &AgentSession,
        profile_id: &ProfileId,
        action: AuditAction,
    ) -> Self {
        let mut id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut id);
        Self {
            gate: gate.clone(),
            policy_runtime: policy_runtime.clone(),
            deployment: deployment.clone(),
            session_id_hash: session.audit_id_hash(),
            request_id: format!("req-{}", hex::encode(id)),
            profile_id: profile_id.clone(),
            action,
            state: RefCell::new(State::default()),
        }
    }

    /// Record the rule that decided (`exact` or `*`, as in the granted-rules store; the record's
    /// `rp_id` names an exact rule's RP) and its grant source.
    pub fn matched(&self, matched: &MatchedRule) {
        let mut state = self.state.borrow_mut();
        state.rule = match matched.rule {
            RuleIdentity::Exact(_) => Some("exact".to_string()),
            RuleIdentity::Wildcard => Some(ANY_RP_ID.to_string()),
            RuleIdentity::None => None,
        };
        state.grant_source = state.rule.as_ref().map(|_| {
            if matched.granted {
                RuleGrantSource::Granted
            } else {
                RuleGrantSource::Config
            }
        });
    }

    /// Record the escalation the ceremony waited on.
    pub fn escalation(&self, escalation_id: &str) {
        self.state.borrow_mut().escalation_id = Some(escalation_id.to_string());
    }

    /// Record the credential the operation selected, how it was selected and the counter before.
    pub fn selected(
        &self,
        credential_ref: Option<CredentialRef>,
        selection: Option<&CredentialSelection>,
        counter_before: Option<u32>,
    ) {
        let mut state = self.state.borrow_mut();
        state.credential_ref = credential_ref;
        state.selection_rule = selection.map(ToString::to_string);
        state.counter_before = counter_before;
    }

    /// Record the credential a registration created.
    pub fn created(&self, credential_ref: CredentialRef) {
        self.state.borrow_mut().credential_ref = Some(credential_ref);
    }

    /// Record the signature counter after key use.
    pub fn counter_after(&self, counter: u32) {
        self.state.borrow_mut().counter_after = Some(counter);
    }

    /// Note a failure after the reservation (the first one wins). It becomes the terminal record's
    /// failure class; nothing is written until [`Self::conclude`].
    pub fn fail(&self, failure: PolicyDenyReason) {
        let mut state = self.state.borrow_mut();
        state.failure.get_or_insert(failure);
    }

    fn base(&self, state: &State, target: &Reservation) -> OperationRecord {
        OperationRecord::new(self.profile_id.clone(), self.action, &target.rp_id)
            .origin_context(
                target.origin.as_deref(),
                target.top_origin.as_deref(),
                target.cross_origin,
            )
            .session(
                Some(self.session_id_hash.clone()),
                Some(self.request_id.clone()),
            )
            .escalation(state.escalation_id.clone())
            .deployment(
                self.deployment.mode.clone(),
                self.deployment.principal_relationship.clone(),
                self.deployment.backend.clone(),
                self.deployment.key_provider.clone(),
            )
            .epochs(
                self.policy_runtime.revocation_epoch(),
                self.policy_runtime.grant_epoch(),
            )
            .matched(state.rule.clone(), state.grant_source)
            .credential(state.credential_ref.clone(), state.selection_rule.clone())
            .counters(state.counter_before, state.counter_after)
    }

    fn snapshot(target: &AuditTarget) -> Reservation {
        Reservation {
            rp_id: target.rp_id.to_string(),
            origin: target.origin.map(str::to_string),
            top_origin: target.top_origin.map(str::to_string),
            cross_origin: target.cross_origin,
        }
    }

    /// A refusal. Before the reservation it is a `policy.deny` record (or `policy.replay_served`
    /// for a duplicate that was served); after it, the failure is only noted and the terminal
    /// record carries it.
    pub fn deny(&self, target: &AuditTarget, reason: PolicyDenyReason) {
        let event = {
            let mut state = self.state.borrow_mut();
            if state.reservation.is_some() {
                state.failure.get_or_insert(reason);
                return;
            }
            let op = self.base(&state, &Self::snapshot(target));
            PolicyDenyBuilder::new(self.profile_id.clone(), self.action, target.rp_id, reason)
                .operation(op)
                .build()
        };
        let _ = self.gate.record(event);
    }

    /// Write the durable reservation (`policy.allow`) before key use. On success the ceremony owes
    /// exactly one terminal record. A failed write means no reservation: the caller must not use
    /// a key.
    pub fn reserve(&self, target: &AuditTarget) -> Result<(), ProtocolError> {
        let event = {
            let state = self.state.borrow();
            let op = self.base(&state, &Self::snapshot(target));
            PolicyAllowBuilder::new(self.profile_id.clone(), self.action, target.rp_id)
                .evidence_sources("allow", "agent", "agent")
                .operation(op)
                .build()
        };
        self.gate.record(event).map_err(|_| {
            ProtocolError::new(
                passless_core::agent::protocol::ErrorCode::Internal,
                "audit record failed",
                passless_core::agent::protocol::RecommendedAction::Retry,
            )
        })?;
        self.state.borrow_mut().reservation = Some(Self::snapshot(target));
        Ok(())
    }

    /// The single exit point: close the open reservation, if any, with its terminal record. The
    /// result comes from the ceremony's outcome and the failure noted on the way.
    pub fn conclude<T>(&self, outcome: &Result<T, ProtocolError>) {
        let failure = match outcome {
            Ok(_) => None,
            Err(_) => Some(
                self.state
                    .borrow()
                    .failure
                    .unwrap_or(PolicyDenyReason::InternalFailure),
            ),
        };
        self.terminal(failure);
    }

    fn terminal(&self, failure: Option<PolicyDenyReason>) {
        let event = {
            let mut state = self.state.borrow_mut();
            let Some(reservation) = state.reservation.take() else {
                return;
            };
            let op = self.base(&state, &reservation);
            OperationTerminalBuilder::new(op, failure).build()
        };
        if let Err(e) = self.gate.record(event) {
            // The audit gate has failed: agent support is degraded until an administrator repairs
            // it (ADR 0014 section 12); the human path is not affected.
            warn!(
                "agent audit: the terminal record of {} could not be written: {}",
                self.request_id, e
            );
        }
    }
}

impl Drop for CeremonyAudit {
    /// A ceremony that unwinds with its reservation open still owes the terminal record.
    fn drop(&mut self) {
        self.terminal(Some(PolicyDenyReason::Abandoned));
    }
}
