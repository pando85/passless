use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use log::{debug, warn};
use sha2::{Digest, Sha256};

use passless_core::agent::protocol::{
    ErrorCode, GrantAction, ProtocolError, RecommendedAction, RegisterCredentialRequest,
    RegisterCredentialResponse,
};
use passless_core::agent::{CredentialRef, ProfileId, RuleAction, RuleIdentity};
use passless_core::config::SecurityConfig;

use super::audit::AuditGate;
use super::audit_events::{
    AuditAction, EscalationAuditContext, EscalationDenyCause, PolicyDenyReason,
};
use super::escalation::{
    EscalationOutcome, EscalationService, NoPark, ParkHook, RegistrationApproval, WaiterSession,
};
use super::lock_order::{self, LockLevel};
use super::operation_audit::{AuditDeployment, AuditTarget, CeremonyAudit};
use super::policy_engine::PolicyRuntime;
use super::session::{
    AgentSession, CeremonyAction, CeremonyOutcome, CeremonyResult, ChallengeDigest, Claim,
    ClaimGuard, JoinResult, ReplayKey, ceremony_deadline,
};
use super::sign::{
    Escalation, PreparedEscalation, aborted_error, b64u_decode, b64u_encode, claim_rejection_error,
    decode_challenge, extensions_supported, join_timeout_error, session_invalid_error,
    verify_origin_context,
};

use crate::storage::CredentialStorage;

use soft_fido2::CredentialKeyProvider;

const PASSLESS_AAGUID: [u8; 16] = [
    0x66, 0x69, 0x64, 0x6F, 0x2E, 0x70, 0x61, 0x73, 0x73, 0x6C, 0x65, 0x73, 0x73, 0x2E, 0x72, 0x73,
];

/// Client extensions a registration request may name. `credProps` is a client-side report (the
/// credential is always discoverable). `remoteDesktopClientOverride` is browser metadata that the
/// transport strips while it parses the request (ADR 0014 section 11).
const SUPPORTED_CREATE_EXTENSIONS: &[&str] = &["credProps"];

#[derive(Clone)]
pub struct RegisterContext {
    pub profile_id: ProfileId,
    /// The bearer session, shared with the sign context of the same bearer: revocation (browser
    /// exit, lease revocation, policy change, TTL), the replay table and the budget usage. The budget
    /// limit is read from the live policy on every request (plan R16).
    pub session: Arc<AgentSession>,
}

impl RegisterContext {
    pub fn new(profile_id: ProfileId, session: Arc<AgentSession>) -> Self {
        Self {
            profile_id,
            session,
        }
    }

    /// Mark the bearer this context belongs to as revoked.
    pub fn revoke(&self) {
        self.session.revoke();
    }
}

pub struct RegisterHandler {
    pub policy_runtime: Arc<PolicyRuntime>,
    pub credential_storage: Arc<Mutex<Box<dyn CredentialStorage>>>,
    pub audit_gate: Arc<AuditGate>,
    pub key_provider: Arc<dyn CredentialKeyProvider + Send + Sync>,
    pub security_config: SecurityConfig,
    pub operation_lock: Arc<Mutex<()>>,
    /// The escalation coordinator a `register = "request"` resolution waits on (ADR 0014
    /// section 8.3).
    pub escalation: Arc<EscalationService>,
    /// The deployment axes and backend that every operation record of this handler reports
    /// (ADR 0014 section 12).
    pub audit_deployment: AuditDeployment,
}

/// A registration approval is bound to the creating ceremony: its profile, RP and session.
fn approval_matches(approval: &RegistrationApproval, ctx: &RegisterContext, rp_id: &str) -> bool {
    approval.profile() == &ctx.profile_id
        && approval.rp_id() == rp_id
        && approval.session() == WaiterSession::of(&ctx.session)
}

/// What the escalated path carries into [`RegisterHandler::register_fresh`].
struct Fresh<'a> {
    algorithm: i32,
    user_id: Vec<u8>,
    guard: &'a mut ClaimGuard,
}

/// The attestation inside a replayed or joined outcome.
fn attestation_outcome(
    outcome: CeremonyOutcome,
) -> Result<RegisterCredentialResponse, ProtocolError> {
    match outcome {
        Ok(CeremonyResult::Attestation(response)) => Ok(*response),
        Ok(CeremonyResult::Assertion(_)) => Err(ProtocolError::new(
            ErrorCode::Internal,
            "replay outcome has the wrong ceremony type",
            RecommendedAction::Abort,
        )),
        Err(e) => Err(e),
    }
}

/// The credential reference a registration grant binds to; an undecodable or empty credential id
/// is an error, never an empty reference.
fn registration_credential_ref(credential_id_b64u: &str) -> Result<CredentialRef, String> {
    let credential_id = b64u_decode(credential_id_b64u)
        .map_err(|e| format!("the credential id does not decode: {e}"))?;
    if credential_id.is_empty() {
        return Err("the credential id is empty".to_string());
    }
    Ok(CredentialRef::with_default_domain(&credential_id))
}

impl RegisterHandler {
    /// A new audit for one ceremony of `ctx` (ADR 0014 section 12).
    fn ceremony_audit(&self, ctx: &RegisterContext) -> CeremonyAudit {
        CeremonyAudit::new(
            &self.audit_gate,
            &self.policy_runtime,
            &self.audit_deployment,
            &ctx.session,
            &ctx.profile_id,
            AuditAction::Register,
        )
    }

    /// A refusal: a `policy.deny` record before the reservation, a noted failure after it.
    fn record_policy_deny(&self, target: &AuditTarget, reason: PolicyDenyReason) {
        target.audit.deny(target, reason);
    }

    fn deny(
        &self,
        target: &AuditTarget,
        (reason, error): (PolicyDenyReason, ProtocolError),
    ) -> ProtocolError {
        self.record_policy_deny(target, reason);
        error
    }

    /// Refuse and audit a registration made with a bearer that was revoked (browser exit or lease
    /// revocation). The request never reaches policy or key generation. `rp_id` is the RP ID the
    /// refused request named, if any.
    pub fn refuse_revoked_bearer(&self, ctx: &RegisterContext, rp_id: Option<&str>) {
        // The request is untrusted: only a syntactically valid RP ID is recorded.
        let rp_id = rp_id
            .map(normalize_rp_id)
            .filter(|rp| passless_core::agent::config::validate_rp_id(rp).is_ok())
            .unwrap_or_else(|| "unknown".to_string());
        let audit = self.ceremony_audit(ctx);
        self.record_policy_deny(
            &AuditTarget::rp_only(&audit, &rp_id),
            PolicyDenyReason::BearerRevoked,
        );
    }

    /// The bearer session is usable, bound to this profile and, when the bearer also carries a
    /// session grant, to that grant's principal (ADR 0014 sections 7 and 9). Grant revocation,
    /// expiry and principal death therefore revoke registration as well as authentication.
    fn check_session(
        &self,
        ctx: &RegisterContext,
        target: &AuditTarget,
    ) -> Result<(), ProtocolError> {
        if ctx.session.profile_id() != &ctx.profile_id {
            return Err(self.deny(
                target,
                (
                    PolicyDenyReason::SessionMismatch,
                    ProtocolError::new(
                        ErrorCode::Forbidden,
                        "bearer session belongs to another profile",
                        RecommendedAction::Abort,
                    ),
                ),
            ));
        }
        ctx.session
            .validity(self.policy_runtime.revocation_epoch(), Instant::now())
            .map_err(|invalid| self.deny(target, session_invalid_error(invalid)))?;
        let Some(grant_id) = ctx.session.grant_id() else {
            return Ok(());
        };
        let Some(grant) = self
            .policy_runtime
            .resolve_grant_for_sign(&ctx.profile_id, grant_id)
        else {
            return Err(self.deny(target, revoked_grant_error()));
        };
        if grant.state != super::grant::GrantState::Active {
            return Err(self.deny(target, revoked_grant_error()));
        }
        if grant.profile_id != ctx.profile_id
            || grant.principal_digest != *ctx.session.principal_digest()
        {
            return Err(self.deny(
                target,
                (
                    PolicyDenyReason::PrincipalMismatch,
                    ProtocolError::new(
                        ErrorCode::Forbidden,
                        "bearer session is not bound to the grant's principal",
                        RecommendedAction::Abort,
                    ),
                ),
            ));
        }
        Ok(())
    }

    /// Register with the default ceremony deadline and no cancellation (tests and direct use).
    pub fn register(
        &self,
        ctx: &RegisterContext,
        req: &RegisterCredentialRequest,
    ) -> Result<RegisterCredentialResponse, ProtocolError> {
        let deadline = ceremony_deadline(req.timeout_ms, Instant::now());
        self.register_with(ctx, req, deadline, &|| false)
    }

    /// Register. The checks follow ADR 0014 section 9 and plan R4 in the same order as
    /// [`super::sign::SignHandler::sign_with`]:
    ///
    /// 1. bearer session (revocation, epoch, TTL, profile, grant principal);
    /// 2. origin and RP validation;
    /// 3. resolve `register` against the live policy (an exact rule, or the `*` rule's `request`);
    /// 4. options the authenticator cannot honor (`NotSupportedError`): extensions, enterprise
    ///    attestation, no supported algorithm; and malformed fields;
    /// 5. replay key, then budget; for `request`, the replay key only, then this ceremony's own
    ///    escalation (not joinable), and after approval the budget and the one-use approval that
    ///    the pre-key-use re-check requires ([`Self::register_escalated`]);
    /// 6. backend operation lock, `excludeCredentials` (`InvalidStateError`);
    /// 7. durable audit reservation;
    /// 8. immediately before key use: revocation epoch, live re-resolve, session validity;
    /// 9. key generation, then a final session check before the credential is written.
    pub fn register_with(
        &self,
        ctx: &RegisterContext,
        req: &RegisterCredentialRequest,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<RegisterCredentialResponse, ProtocolError> {
        self.register_parked(ctx, req, deadline, cancelled, &mut NoPark)
    }

    /// [`Self::register_with`] for a transport-carried ceremony: `park` suspends the request's
    /// capacity permit while the ceremony waits on an escalation.
    pub fn register_parked(
        &self,
        ctx: &RegisterContext,
        req: &RegisterCredentialRequest,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
        park: &mut dyn ParkHook,
    ) -> Result<RegisterCredentialResponse, ProtocolError> {
        // The audit is the ceremony's single exit point: whatever way `register_audited` ends,
        // the reservation it may have made is closed by exactly one terminal record (a panic is
        // covered by the audit's drop guard).
        let audit = self.ceremony_audit(ctx);
        let outcome = self.register_audited(ctx, req, deadline, cancelled, park, &audit);
        audit.conclude(&outcome);
        outcome
    }

    fn register_audited(
        &self,
        ctx: &RegisterContext,
        req: &RegisterCredentialRequest,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
        park: &mut dyn ParkHook,
        audit: &CeremonyAudit,
    ) -> Result<RegisterCredentialResponse, ProtocolError> {
        let normalized_rp = normalize_rp_id(&req.rp_id);
        let target = AuditTarget::of_request(
            audit,
            &normalized_rp,
            &req.origin,
            req.top_origin.as_deref(),
            req.cross_origin,
        );
        let target = &target;

        // 1. Bearer session.
        self.check_session(ctx, target)?;

        // 2. Origin and RP validation.
        if !verify_origin_context(
            &req.origin,
            req.top_origin.as_deref(),
            req.cross_origin,
            &normalized_rp,
        ) {
            let (reason, code, message) = if req.cross_origin {
                (
                    PolicyDenyReason::CrossOriginDenied,
                    ErrorCode::Forbidden,
                    "cross-origin frames are not permitted",
                )
            } else {
                (
                    PolicyDenyReason::OriginInvalid,
                    ErrorCode::OriginInvalid,
                    "origin not valid for RP",
                )
            };
            return Err(self.deny(
                target,
                (
                    reason,
                    ProtocolError::new(code, message, RecommendedAction::FixRequest),
                ),
            ));
        }

        // 3. Registration authority is policy only (ADR 0014 section 10.3): an exact RP rule with
        //    `register = "allow"` or `"request"`, or the `*` rule with `register = "request"`
        //    (amendment section 2.2), resolved against the live policy on every request (plan
        //    R16). There is no operator-minted enrollment grant. The wildcard never permits a
        //    registration without a human: a wildcard `allow` resolves to `deny`, and `*` never
        //    matches `localhost`.
        let matched =
            self.policy_runtime
                .resolve(&ctx.profile_id, &GrantAction::Register, &normalized_rp);
        audit.matched(&matched);
        match matched.action {
            RuleAction::Deny => {
                return Err(self.deny(
                    target,
                    (
                        PolicyDenyReason::ActionNotAllowed,
                        ProtocolError::new(
                            ErrorCode::Forbidden,
                            if matched.rule == RuleIdentity::None {
                                "RP policy does not allow registration"
                            } else {
                                "RP policy denies registration"
                            },
                            RecommendedAction::FixRequest,
                        ),
                    ),
                ));
            }
            // `register = "request"` (ADR 0014 section 8.3): steps 4 and 5 run unchanged; the
            // replay key is taken without budget, then the ceremony escalates
            // (`Self::register_escalated`). A registration escalation is not joinable (V-M3).
            RuleAction::Request => {}
            RuleAction::Allow => {}
        }

        // 4. Unsupported requirements fail with `NotSupportedError` before any budget is claimed or
        //    storage is touched (ADR 0014 section 10.3).
        let unsupported = |message: &str| {
            self.deny(
                target,
                (
                    PolicyDenyReason::UnsupportedOption,
                    ProtocolError::new(
                        ErrorCode::NotSupported,
                        message,
                        RecommendedAction::FixRequest,
                    ),
                ),
            )
        };
        if !extensions_supported(&req.extensions, SUPPORTED_CREATE_EXTENSIONS)? {
            return Err(unsupported("a requested extension is not supported"));
        }
        // Only `none` attestation is produced. `indirect` and `direct` are preferences that a
        // `none` statement satisfies; unknown values are ignored as WebAuthn requires.
        if req.attestation.as_deref() == Some("enterprise") {
            return Err(unsupported("enterprise attestation is not supported"));
        }
        // Passless is a roaming authenticator; a platform attachment requirement cannot be met
        // (invariant 22). `cross-platform` and unknown values are accepted.
        if req.authenticator_attachment.as_deref() == Some("platform") {
            return Err(unsupported("a platform authenticator is not supported"));
        }
        let Some(algorithm) = req
            .pub_key_cred_params
            .iter()
            .copied()
            .find(|algorithm| self.key_provider.supports_algorithm(*algorithm))
        else {
            return Err(self.deny(
                target,
                (
                    PolicyDenyReason::AlgorithmUnsupported,
                    ProtocolError::new(
                        ErrorCode::NotSupported,
                        "no requested public-key algorithm is supported by this backend",
                        RecommendedAction::FixRequest,
                    ),
                ),
            ));
        };
        let user_id = b64u_decode(&req.user_id_b64u).map_err(|_| {
            ProtocolError::new(
                ErrorCode::BadRequest,
                "invalid user_id_b64u encoding",
                RecommendedAction::FixRequest,
            )
        })?;
        let challenge = decode_challenge(&req.challenge_b64u)?;

        // The browser already cancelled the request: stop before the replay key is consumed.
        if cancelled() {
            return Err(self.deny(target, aborted_error()));
        }

        // 5. Replay key, then budget (R1, R4): an identical registration never creates a second
        //    credential. The budget limit is the live `max_operations`. A `request` resolution
        //    takes the replay key only; its budget is claimed after approval (V-H2).
        let key = ReplayKey::derive(
            CeremonyAction::Register,
            &normalized_rp,
            &req.origin,
            req.top_origin.as_deref(),
            &challenge,
        );
        // The prompt shows how many passkeys the target store already holds for the site
        // (amendment section 5.2): counted from the backend's path index, never by decrypting,
        // holding only the storage lock and only for the count, before the escalation is raised
        // and never across its wait (LOCKING.md). It goes to the human only.
        let store_count = if matched.action == RuleAction::Request {
            lock_order::lock(&self.credential_storage, LockLevel::Storage)
                .count_for_rp(target.rp_id)
        } else {
            None
        };
        let escalation = Escalation {
            service: &self.escalation,
            policy_runtime: &self.policy_runtime,
            session: &ctx.session,
            profile_id: &ctx.profile_id,
            action: CeremonyAction::Register,
            rp_id: target.rp_id,
            origin: &req.origin,
            rule: &matched.rule,
            audit,
            store_count,
        };
        let prepared = if matched.action == RuleAction::Request {
            Some(
                escalation
                    .prepare()
                    .map_err(|refused| self.deny(target, refused))?,
            )
        } else {
            None
        };
        let claim = if prepared.is_some() {
            ctx.session
                .claim_key(key, ChallengeDigest::of(&challenge), Instant::now())
        } else {
            let max_operations = self
                .policy_runtime
                .max_operations(&ctx.profile_id)
                .unwrap_or(0);
            ctx.session.claim(
                key,
                ChallengeDigest::of(&challenge),
                u32::from(max_operations),
                Instant::now(),
            )
        };
        match claim {
            Claim::Fresh(mut guard) => {
                let mut key_used = false;
                let outcome = if let Some(prepared) = prepared {
                    self.register_escalated(
                        ctx,
                        req,
                        target,
                        (&escalation, prepared),
                        Fresh {
                            algorithm,
                            user_id,
                            guard: &mut guard,
                        },
                        deadline,
                        cancelled,
                        park,
                        &mut key_used,
                    )
                } else {
                    self.register_fresh(
                        ctx,
                        req,
                        target,
                        algorithm,
                        user_id,
                        None,
                        cancelled,
                        &mut key_used,
                    )
                };
                let ceremony = outcome
                    .clone()
                    .map(|response| CeremonyResult::Attestation(Box::new(response)));
                if key_used {
                    guard.complete(&ceremony);
                } else {
                    // Ended before key generation: the key stays consumed, a claimed budget is
                    // given back (review M2).
                    guard.complete_without_key_use(&ceremony);
                }
                outcome
            }
            Claim::Join(in_flight, audit) => match in_flight.join(deadline, cancelled, park) {
                JoinResult::Completed(outcome) => {
                    self.serve_duplicate(ctx, target, audit)?;
                    attestation_outcome(outcome)
                }
                // The browser cancelled the duplicate while it waited: audited like any abort.
                JoinResult::Detached => Err(self.deny(target, aborted_error())),
                JoinResult::DeadlineExceeded => Err(self.deny(target, join_timeout_error())),
            },
            Claim::Completed(outcome, audit) => {
                self.serve_duplicate(ctx, target, audit)?;
                attestation_outcome(outcome)
            }
            Claim::Rejected(rejection) => Err(self.deny(target, claim_rejection_error(rejection))),
        }
    }

    /// The escalated path of a fresh replay key (ADR 0014 section 8.3): raise this ceremony's own
    /// escalation (never joined) and wait holding no lock. On approval claim the budget and
    /// register with the one-use approval, which the pre-key-use re-check requires. After the
    /// credential is written, persist `authenticate = allow` with `kind = registration` and the
    /// new credential reference; if that fails the credential is still returned, the failure is
    /// audited and no grant persists (plan P7 gap 10). A deny, expiry or abort claims no budget.
    #[allow(clippy::too_many_arguments)]
    fn register_escalated(
        &self,
        ctx: &RegisterContext,
        req: &RegisterCredentialRequest,
        target: &AuditTarget,
        (escalation, prepared): (&Escalation<'_>, PreparedEscalation),
        fresh: Fresh<'_>,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
        park: &mut dyn ParkHook,
        key_used: &mut bool,
    ) -> Result<RegisterCredentialResponse, ProtocolError> {
        let approval = match escalation.wait(prepared, deadline, cancelled, park) {
            Ok(EscalationOutcome::RegistrationApproved(approval)) => approval,
            Ok(_) => {
                return Err(ProtocolError::new(
                    ErrorCode::Internal,
                    "a registration escalation ended without a registration approval",
                    RecommendedAction::Abort,
                ));
            }
            Err(denied) => return Err(self.deny(target, denied)),
        };
        if !approval_matches(&approval, ctx, target.rp_id) {
            return Err(self.deny(
                target,
                (
                    PolicyDenyReason::PolicyRevoked,
                    ProtocolError::new(
                        ErrorCode::Forbidden,
                        "the registration approval is bound to another ceremony",
                        RecommendedAction::Abort,
                    ),
                ),
            ));
        }
        let max_operations = self
            .policy_runtime
            .max_operations(&ctx.profile_id)
            .unwrap_or(0);
        fresh
            .guard
            .claim_budget(u32::from(max_operations))
            .map_err(|rejection| self.deny(target, claim_rejection_error(rejection)))?;
        let response = self.register_fresh(
            ctx,
            req,
            target,
            fresh.algorithm,
            fresh.user_id,
            Some(&approval),
            cancelled,
            key_used,
        )?;

        // The operation and storage locks are released: persist the registration grant. For a
        // registration through `*` it carries `rule = "*"` and counts against
        // `max_wildcard_registrations`; the next sign-in at the RP uses this credential only
        // (amendment section 2.2 items 2 and 3).
        let (max_granted_rules, max_wildcard_registrations) = self
            .policy_runtime
            .escalation_profile(&ctx.profile_id)
            .map_or((0, 0), |profile| {
                (
                    profile.max_granted_rules,
                    profile.max_wildcard_registrations,
                )
            });
        match registration_credential_ref(&response.credential_id_b64u) {
            Ok(credential_ref) => {
                if let Err(e) = self.escalation.record_registration_grant(
                    &approval,
                    credential_ref,
                    max_granted_rules,
                    max_wildcard_registrations,
                ) {
                    warn!(
                        "agent register: credential for rp={} kept without a registration grant: {}",
                        target.rp_id, e
                    );
                }
            }
            Err(e) => {
                // Never persist a grant bound to an empty credential reference.
                warn!(
                    "agent register: credential for rp={} kept without a registration grant: {}",
                    target.rp_id, e
                );
                let context = EscalationAuditContext {
                    escalation_id: approval.escalation_id().as_str().to_string(),
                    profile_id: approval.profile().clone(),
                    action: AuditAction::Register,
                    rp_id: approval.rp_id().to_string(),
                    origin: approval.origin().to_string(),
                    rule: approval.rule(),
                };
                if let Err(audit_error) = self
                    .audit_gate
                    .record(context.denied(EscalationDenyCause::GrantWriteFailed))
                {
                    warn!(
                        "agent register: the failed grant write could not be audited: {}",
                        audit_error
                    );
                }
            }
        }
        Ok(response)
    }

    /// Before a duplicate gets the stored outcome its session must still be valid (review L3);
    /// served duplicates are audited (bounded per key).
    fn serve_duplicate(
        &self,
        ctx: &RegisterContext,
        target: &AuditTarget,
        audit: bool,
    ) -> Result<(), ProtocolError> {
        ctx.session
            .validity(self.policy_runtime.revocation_epoch(), Instant::now())
            .map_err(|invalid| self.deny(target, session_invalid_error(invalid)))?;
        if audit {
            self.record_policy_deny(target, PolicyDenyReason::ReplayServed);
        }
        Ok(())
    }

    /// Re-check the session, the revocation epoch and the live rule (invariant 13). A request the
    /// browser cancelled meanwhile stops here too (the terminal record of its reservation).
    fn recheck_before_key_use(
        &self,
        ctx: &RegisterContext,
        target: &AuditTarget,
        approval: Option<&RegistrationApproval>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), ProtocolError> {
        let rp_id = target.rp_id;
        if cancelled() {
            return Err(self.deny(target, aborted_error()));
        }
        self.check_session(ctx, target)?;
        let matched = self
            .policy_runtime
            .resolve(&ctx.profile_id, &GrantAction::Register, rp_id);
        // A configured `request` permits key use only with this ceremony's own approval (ADR 0014
        // section 8.3).
        let approved = matched.configured == RuleAction::Request
            && approval.is_some_and(|approval| approval_matches(approval, ctx, rp_id));
        if matched.action != RuleAction::Allow && !approved {
            return Err(self.deny(
                target,
                (
                    PolicyDenyReason::PolicyRevoked,
                    ProtocolError::new(
                        ErrorCode::Forbidden,
                        "policy no longer allows this operation",
                        RecommendedAction::Abort,
                    ),
                ),
            ));
        }
        Ok(())
    }

    /// Steps 6-9 for a fresh replay key.
    #[allow(clippy::too_many_arguments)]
    fn register_fresh(
        &self,
        ctx: &RegisterContext,
        req: &RegisterCredentialRequest,
        target: &AuditTarget,
        algorithm: i32,
        user_id: Vec<u8>,
        approval: Option<&RegistrationApproval>,
        cancelled: &dyn Fn() -> bool,
        key_used: &mut bool,
    ) -> Result<RegisterCredentialResponse, ProtocolError> {
        let normalized_rp = target.rp_id;
        // 6. Backend operation lock, then storage (LOCKING.md).
        let _op_lock = lock_order::lock(&self.operation_lock, LockLevel::Operation);
        let mut storage = lock_order::lock(&self.credential_storage, LockLevel::Storage);

        // The exclude list is matched within this RP only (WebAuthn section 5.4.4 scopes it to the
        // RP): a credential ID that exists for another RP must not be revealed (review L8).
        for excluded_b64u in &req.exclude_credentials {
            if let Ok(excluded_id) = b64u_decode(excluded_b64u)
                && storage
                    .read(&excluded_id)
                    .is_ok_and(|existing| existing.rp.id.eq_ignore_ascii_case(normalized_rp))
            {
                return Err(self.deny(
                    target,
                    (
                        PolicyDenyReason::CredentialExcluded,
                        ProtocolError::new(
                            ErrorCode::InvalidState,
                            "credential matches exclude list",
                            RecommendedAction::FixRequest,
                        ),
                    ),
                ));
            }
        }

        // 7. Durable audit reservation before key use (invariant 16). From here every exit path
        //    ends in the ceremony's terminal record (`CeremonyAudit::conclude`).
        target.audit.reserve(target)?;

        // 8. Immediately before key use. The key-use gates are held until the credential is
        //    written, so a revocation either precedes this check or waits (review M1).
        #[cfg(test)]
        super::session::test_hooks::before_key_use();
        let _session_gate = ctx.session.key_use_guard();
        let _epoch_gate = self.policy_runtime.key_use_guard();
        self.recheck_before_key_use(ctx, target, approval, cancelled)?;

        // 9. Key generation.
        *key_used = true;
        let generated = self.key_provider.generate(algorithm).map_err(|_| {
            target.audit.fail(PolicyDenyReason::KeyGenerationFailed);
            ProtocolError::new(
                ErrorCode::Internal,
                "key generation failed",
                RecommendedAction::Retry,
            )
        })?;

        // Fallible, never panicking: storage and the human operation lock are held here, and a
        // panic would abort the daemon, human path included (ADR 0014 invariant 23).
        let credential_id = generate_credential_id().map_err(|_| {
            target.audit.fail(PolicyDenyReason::KeyGenerationFailed);
            ProtocolError::new(
                ErrorCode::Internal,
                "credential ID generation failed",
                RecommendedAction::Retry,
            )
        })?;

        // `GeneratedCredentialKey::cose_public_key` is the provider's raw public key (SEC1 point or
        // Ed25519 bytes), not a COSE_Key; encode it before it goes into the attested credential data.
        let cose_key = cose_key_from_raw_public_key(algorithm, &generated.cose_public_key)
            .map_err(|_| {
                target.audit.fail(PolicyDenyReason::KeyGenerationFailed);
                ProtocolError::new(
                    ErrorCode::Internal,
                    "key provider returned an unusable public key",
                    RecommendedAction::Abort,
                )
            })?;

        let authenticator_data = build_authenticator_data_for_registration(
            normalized_rp,
            &credential_id,
            &cose_key,
            // `allow` is the only agent evidence: UP and UV come from the validated agent session
            // (ADR 0014 section 7).
            true,
            true,
        );

        let client_data_json = build_client_data_json_for_registration(
            &req.origin,
            &req.challenge_b64u,
            req.cross_origin,
            req.top_origin.as_deref(),
        );

        let attestation_object = build_attestation_object(&authenticator_data).map_err(|_| {
            target.audit.fail(PolicyDenyReason::KeyGenerationFailed);
            ProtocolError::new(
                ErrorCode::Internal,
                "attestation object encoding failed",
                RecommendedAction::Retry,
            )
        })?;

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let credential = soft_fido2::Credential {
            id: credential_id.clone(),
            rp: soft_fido2_ctap::types::RelyingParty {
                id: normalized_rp.to_string(),
                name: req.rp_name.clone(),
            },
            user: soft_fido2_ctap::types::User {
                id: user_id,
                name: Some(req.user_name.clone()),
                display_name: req.user_display_name.clone(),
            },
            sign_count: 0,
            alg: algorithm,
            key: generated.key,
            created: now_ms,
            discoverable: true,
            backup_state: if self.security_config.enable_credential_backup {
                soft_fido2::CredentialBackupState::Eligible
            } else {
                soft_fido2::CredentialBackupState::NotEligible
            },
            extensions: soft_fido2::Extensions::default(),
        };

        let cred_ref = soft_fido2::CredentialRef {
            id: &credential.id,
            rp_id: &credential.rp.id,
            rp_name: credential.rp.name.as_deref(),
            user_id: &credential.user.id,
            user_name: credential.user.name.as_deref(),
            user_display_name: credential.user.display_name.as_deref(),
            sign_count: &credential.sign_count,
            alg: &credential.alg,
            key: &credential.key,
            created: &credential.created,
            discoverable: &credential.discoverable,
            cred_protect: credential.extensions.cred_protect.as_ref(),
            cred_random: None,
            backup_state: &credential.backup_state,
        };

        // A revocation that raced key generation still prevents the credential from being written.
        if let Err(invalid) = ctx
            .session
            .validity(self.policy_runtime.revocation_epoch(), Instant::now())
        {
            return Err(self.deny(target, session_invalid_error(invalid)));
        }

        storage.write(cred_ref).map_err(|_| {
            target.audit.fail(PolicyDenyReason::CredentialWriteFailed);
            ProtocolError::new(
                ErrorCode::Internal,
                "failed to write credential to storage",
                RecommendedAction::Retry,
            )
        })?;
        target
            .audit
            .created(CredentialRef::with_default_domain(&credential_id));
        target.audit.counter_after(0);

        debug!(
            "registered credential for rp={} profile={}",
            normalized_rp, ctx.profile_id
        );

        Ok(RegisterCredentialResponse {
            credential_id_b64u: b64u_encode(&credential_id),
            public_key_algorithm: algorithm,
            authenticator_data_b64u: b64u_encode(&authenticator_data),
            attestation_object_b64u: b64u_encode(&attestation_object),
            client_data_json_b64u: b64u_encode(&client_data_json),
        })
    }
}

fn revoked_grant_error() -> (PolicyDenyReason, ProtocolError) {
    (
        PolicyDenyReason::GrantRevoked,
        ProtocolError::new(
            ErrorCode::Unauthorized,
            "the bearer's session grant is no longer active",
            RecommendedAction::Abort,
        ),
    )
}

fn normalize_rp_id(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

/// 32 random bytes from the OS (`getrandom(2)`, no file descriptor). A failure is an error, not a
/// panic: the caller holds storage and, in same-user mode, the human operation lock.
fn generate_credential_id() -> Result<Vec<u8>, rand::Error> {
    let mut id = vec![0u8; 32];
    rand::RngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut id)?;
    Ok(id)
}

/// Encode a provider public key as a COSE_Key (RFC 9052 section 7) in CTAP2 canonical form.
///
/// - ES256 (-7): `{1: 2, 3: -7, -1: 1, -2: x, -3: y}` from an uncompressed SEC1 point.
/// - EdDSA (-8) and Ed25519 (-19): `{1: 1, 3: alg, -1: 6, -2: x}` from the 32-byte public key.
///
/// Map keys are sorted by their encoded bytes (1, 3, -1, -2, -3), which is the CTAP2 canonical order.
fn cose_key_from_raw_public_key(algorithm: i32, raw: &[u8]) -> Result<Vec<u8>, &'static str> {
    use ciborium::Value;

    let int = |n: i64| Value::Integer(n.into());
    let entries = match algorithm {
        -7 => {
            if raw.len() != 65 || raw[0] != 0x04 {
                return Err("expected an uncompressed P-256 point");
            }
            vec![
                (int(1), int(2)),
                (int(3), int(-7)),
                (int(-1), int(1)),
                (int(-2), Value::Bytes(raw[1..33].to_vec())),
                (int(-3), Value::Bytes(raw[33..65].to_vec())),
            ]
        }
        -8 | -19 => {
            if raw.len() != 32 {
                return Err("expected a 32-byte Ed25519 public key");
            }
            vec![
                (int(1), int(1)),
                (int(3), int(i64::from(algorithm))),
                (int(-1), int(6)),
                (int(-2), Value::Bytes(raw.to_vec())),
            ]
        }
        _ => return Err("unsupported COSE algorithm"),
    };

    let mut out = Vec::with_capacity(80);
    ciborium::into_writer(&Value::Map(entries), &mut out).map_err(|_| "CBOR encoding failed")?;
    Ok(out)
}

fn build_authenticator_data_for_registration(
    rp_id: &str,
    credential_id: &[u8],
    cose_public_key: &[u8],
    up: bool,
    uv: bool,
) -> Vec<u8> {
    let mut auth_data = Vec::with_capacity(37 + credential_id.len() + cose_public_key.len());

    let rp_id_hash = Sha256::digest(rp_id.as_bytes());
    auth_data.extend_from_slice(&rp_id_hash);

    let mut flags = 0x40;
    if up {
        flags |= 0x01;
    }
    if uv {
        flags |= 0x04;
    }
    auth_data.push(flags);

    auth_data.extend_from_slice(&0u32.to_be_bytes());

    auth_data.extend_from_slice(&PASSLESS_AAGUID);

    auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(credential_id);

    auth_data.extend_from_slice(cose_public_key);

    auth_data
}

fn build_client_data_json_for_registration(
    origin: &str,
    challenge_b64u: &str,
    cross_origin: bool,
    top_origin: Option<&str>,
) -> Vec<u8> {
    let mut cdj = String::with_capacity(128);
    cdj.push_str("{\"type\":\"webauthn.create\",\"challenge\":\"");
    cdj.push_str(challenge_b64u);
    cdj.push_str("\",\"origin\":\"");
    cdj.push_str(&json_escape_string(origin));
    cdj.push('"');
    if cross_origin {
        cdj.push_str(",\"crossOrigin\":true");
        if let Some(top_origin) = top_origin {
            cdj.push_str(",\"topOrigin\":\"");
            cdj.push_str(&json_escape_string(top_origin));
            cdj.push('"');
        }
    }
    cdj.push('}');
    cdj.into_bytes()
}

fn json_escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < '\x20' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

fn build_attestation_object(auth_data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let attestation_map = ciborium::Value::Map(vec![
        (
            ciborium::Value::Text("fmt".to_string()),
            ciborium::Value::Text("none".to_string()),
        ),
        (
            ciborium::Value::Text("attStmt".to_string()),
            ciborium::Value::Map(vec![]),
        ),
        (
            ciborium::Value::Text("authData".to_string()),
            ciborium::Value::Bytes(auth_data.to_vec()),
        ),
    ]);

    let mut buf = Vec::new();
    ciborium::into_writer(&attestation_map, &mut buf).map_err(|_| "CBOR encoding failed")?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::agent::audit::{AuditGate, test_support::read_audit_events};
    use crate::agent::browser::SystemClock;
    use crate::agent::escalation::test_support::{self, ScriptedPrompter};
    use crate::agent::escalation::{EscalationService, PromptEvent};
    use crate::agent::granted_rules::{GrantKind, GrantedRulesStore};
    use crate::storage::CredentialStorage;
    use passless_core::agent::config::ANY_RP_ID as WILDCARD_RP_ID;
    use passless_core::agent::{
        AgentConfig, AgentMode, AgentProfileConfig, AgentRpRule, BrowserScope, CredentialSelection,
    };
    use passless_core::config::SecurityConfig;
    use soft_fido2::{CredentialBackupState, RelyingParty, SoftwareCredentialKeyProvider, User};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    pub struct WriteCountingStorage {
        creds: Mutex<Vec<soft_fido2::Credential>>,
        write_count: AtomicU64,
    }
    impl WriteCountingStorage {
        pub fn new() -> Self {
            Self {
                creds: Mutex::new(Vec::new()),
                write_count: AtomicU64::new(0),
            }
        }
        #[allow(dead_code)]
        fn writes(&self) -> u64 {
            self.write_count.load(Ordering::Acquire)
        }
        #[allow(dead_code)]
        pub fn add_cred(&self, cred: soft_fido2::Credential) {
            self.creds.lock().unwrap().push(cred);
        }
    }
    impl CredentialStorage for WriteCountingStorage {
        fn read_first(
            &mut self,
            filter: crate::storage::CredentialFilter,
        ) -> soft_fido2::Result<soft_fido2::Credential> {
            let creds = self.creds.lock().unwrap();
            match filter {
                crate::storage::CredentialFilter::ByRp(rp_id) => creds
                    .iter()
                    .find(|c| c.rp.id == rp_id)
                    .cloned()
                    .ok_or(soft_fido2::Error::Other),
                crate::storage::CredentialFilter::None => {
                    creds.first().cloned().ok_or(soft_fido2::Error::Other)
                }
                crate::storage::CredentialFilter::ById(id) => creds
                    .iter()
                    .find(|c| c.id == id)
                    .cloned()
                    .ok_or(soft_fido2::Error::Other),
                crate::storage::CredentialFilter::ByHash(_) => Err(soft_fido2::Error::Other),
            }
        }
        fn read_next(&mut self) -> soft_fido2::Result<soft_fido2::Credential> {
            Err(soft_fido2::Error::Other)
        }
        fn read(&mut self, id: &[u8]) -> soft_fido2::Result<soft_fido2::Credential> {
            self.creds
                .lock()
                .unwrap()
                .iter()
                .find(|c| c.id == id)
                .cloned()
                .ok_or(soft_fido2::Error::Other)
        }
        fn write(&mut self, cred: soft_fido2::CredentialRef) -> soft_fido2::Result<()> {
            self.write_count.fetch_add(1, Ordering::AcqRel);
            let owned = cred.to_owned();
            let mut creds = self.creds.lock().unwrap();
            if let Some(existing) = creds.iter_mut().find(|c| c.id == owned.id) {
                *existing = owned;
            } else {
                creds.push(owned);
            }
            Ok(())
        }
        fn delete(&mut self, id: &[u8]) -> soft_fido2::Result<()> {
            self.creds.lock().unwrap().retain(|c| c.id != id);
            Ok(())
        }
        fn count_credentials(&self) -> usize {
            self.creds.lock().unwrap().len()
        }

        /// Like the path index of the real backends: counts without reading a credential.
        fn count_for_rp(&self, rp_id: &str) -> Option<usize> {
            Some(
                self.creds
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|c| c.rp.id == rp_id)
                    .count(),
            )
        }
    }

    fn make_test_security_config() -> SecurityConfig {
        SecurityConfig {
            check_mlock: false,
            disable_core_dumps: false,
            constant_signature_counter: false,
            enable_credential_backup: false,
            always_uv: false,
            user_verification_registration: false,
            user_verification_authentication: false,
            notification_timeout: 0,
        }
    }

    fn register_rule(rp_id: &str, register: RuleAction) -> AgentRpRule {
        AgentRpRule {
            rp_id: rp_id.to_string(),
            register,
            authenticate: RuleAction::Deny,
            credential_selection: None,
        }
    }

    fn profile_with_rules(rules: Vec<AgentRpRule>) -> AgentProfileConfig {
        AgentProfileConfig {
            max_wildcard_registrations: None,
            wildcard_registration_prompts_per_day: None,
            max_granted_rules: 64,
            max_operations: 64,
            max_concurrent_sessions: 1,
            browser_scope: BrowserScope::Session,
            credential_selection: CredentialSelection::Single,
            mode: AgentMode::Isolated,
            principal_user: String::new(),
            credential_refs: Some(vec![]),
            max_grant_ttl: None,
            max_session_ttl: None,
            storage: None,
            rules,
            legacy: Default::default(),
            device: None,
            start_url: None,
            browser_command: None,
            browser_user: None,
            browser_runtime_root: None,
            browser_cdp_expose: None,
            browser_cdp_port: None,
        }
    }

    fn make_registration_profile_config() -> AgentProfileConfig {
        profile_with_rules(vec![register_rule("example.com", RuleAction::Allow)])
    }

    struct RegisterTestFixture {
        profile_id: ProfileId,
        storage: Arc<Mutex<Box<dyn CredentialStorage>>>,
        key_provider: Arc<SoftwareCredentialKeyProvider>,
        audit_gate: Arc<AuditGate>,
        audit_dir: std::path::PathBuf,
        operation_lock: Arc<Mutex<()>>,
        security_config: SecurityConfig,
        policy_runtime: Arc<PolicyRuntime>,
        store: Arc<GrantedRulesStore>,
        prompter: Arc<ScriptedPrompter>,
        escalation: Arc<EscalationService>,
        _tmp: tempfile::TempDir,
    }

    impl RegisterTestFixture {
        fn new() -> Self {
            make_fixture_with_config(make_registration_profile_config())
        }

        fn make_handler(&self) -> RegisterHandler {
            RegisterHandler {
                policy_runtime: self.policy_runtime.clone(),
                credential_storage: self.storage.clone(),
                audit_gate: self.audit_gate.clone(),
                key_provider: self.key_provider.clone(),
                security_config: self.security_config.clone(),
                operation_lock: self.operation_lock.clone(),
                escalation: self.escalation.clone(),
                audit_deployment: Default::default(),
            }
        }

        /// A fresh bearer session bound at the live revocation epoch.
        fn make_ctx(&self) -> RegisterContext {
            RegisterContext::new(
                self.profile_id.clone(),
                crate::agent::session::AgentSession::new(crate::agent::session::SessionBinding {
                    profile_id: self.profile_id.clone(),
                    principal_digest: [0u8; 32],
                    revocation_epoch: self.policy_runtime.revocation_epoch(),
                    ttl: std::time::Duration::from_secs(600),
                }),
            )
        }

        /// Replace the live policy (the session context is NOT rebuilt).
        fn reload_profile(&self, profile_config: AgentProfileConfig) {
            self.policy_runtime
                .reload(&agent_config_for(&self.profile_id, profile_config))
                .unwrap();
        }

        fn make_req(&self) -> RegisterCredentialRequest {
            RegisterCredentialRequest {
                extensions: Vec::new(),
                attestation: None,
                timeout_ms: None,
                authenticator_attachment: None,
                origin: "https://example.com".to_string(),
                top_origin: None,
                rp_id: "example.com".to_string(),
                challenge_b64u: "dGVzdA".to_string(),
                user_id_b64u: "dXNlcg".to_string(),
                user_name: "testuser".to_string(),
                user_display_name: Some("Test User".to_string()),
                rp_name: Some("Example".to_string()),
                exclude_credentials: vec![],
                pub_key_cred_params: vec![-7],
                user_verification: false,
                cross_origin: false,
            }
        }

        fn policy_events(&self) -> Vec<serde_json::Value> {
            read_audit_events(&self.audit_dir)
                .into_iter()
                .filter(|e| {
                    e.get("kind").and_then(|k| k.as_str()).is_some_and(|k| {
                        k == "policy.allow"
                            || k == "policy.deny"
                            || (k == "operation.terminal" && e["failure_class"].is_string())
                    })
                })
                .collect()
        }
    }

    fn make_deny_profile_config() -> AgentProfileConfig {
        profile_with_rules(vec![AgentRpRule {
            rp_id: "example.com".to_string(),
            register: RuleAction::Deny,
            authenticate: RuleAction::Allow,
            credential_selection: None,
        }])
    }

    fn agent_config_for(profile_id: &ProfileId, profile_config: AgentProfileConfig) -> AgentConfig {
        let mut profiles = BTreeMap::new();
        profiles.insert(profile_id.as_str().to_string(), profile_config);
        AgentConfig {
            notify_user: None,
            state_dir: None,
            escalation_timeout: None,
            escalation_cooldown: 600,
            allow_automatic_human_path: false,
            browser_path: None,
            limits: Default::default(),
            enabled: true,
            profiles,
            audit_path: Some(std::path::PathBuf::from("/tmp/test-audit")),
            acknowledge_global_same_user: vec![profile_id.as_str().to_string()],
            acknowledge_same_user_registration: vec![profile_id.as_str().to_string()],
            acknowledge_global_registration: vec![profile_id.as_str().to_string()],
        }
    }

    fn make_fixture_with_config(profile_config: AgentProfileConfig) -> RegisterTestFixture {
        let tmp = tempfile::tempdir().unwrap();
        let audit_dir = tmp.path().join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::set_permissions(
            &audit_dir,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let audit_gate = Arc::new(AuditGate::open(&audit_dir).unwrap());
        let profile_id = ProfileId::new("test-register-profile").unwrap();
        let store = Arc::new(GrantedRulesStore::open(
            &tmp.path().join("state"),
            [profile_id.clone()],
        ));
        let policy_runtime = Arc::new(
            PolicyRuntime::new(
                &agent_config_for(&profile_id, profile_config),
                Arc::new(SystemClock),
                None,
            )
            .unwrap()
            .with_grant_source(store.clone()),
        );
        let prompter = Arc::new(ScriptedPrompter::default());
        let escalation = test_support::service(
            audit_gate.clone(),
            store.clone(),
            policy_runtime.clone(),
            prompter.clone(),
            std::time::Duration::from_secs(600),
        );

        RegisterTestFixture {
            profile_id,
            storage: Arc::new(Mutex::new(
                Box::new(WriteCountingStorage::new()) as Box<dyn CredentialStorage>
            )),
            key_provider: Arc::new(SoftwareCredentialKeyProvider),
            audit_gate,
            audit_dir,
            operation_lock: Arc::new(Mutex::new(())),
            security_config: make_test_security_config(),
            policy_runtime,
            store,
            prompter,
            escalation,
            _tmp: tmp,
        }
    }

    #[test]
    fn test_build_authenticator_data_for_registration_structure() {
        let rp_id = "example.com";
        let cred_id = vec![0xAA; 32];
        let cose_key = vec![0xBB; 20];

        let auth_data =
            build_authenticator_data_for_registration(rp_id, &cred_id, &cose_key, true, false);

        assert_eq!(auth_data[32], 0x41);
        assert_eq!(&auth_data[33..37], &0u32.to_be_bytes());
        assert_eq!(&auth_data[37..53], &PASSLESS_AAGUID);
        let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]);
        assert_eq!(cred_id_len, 32);
        assert_eq!(&auth_data[55..87], &cred_id[..]);
        assert_eq!(&auth_data[87..], &cose_key[..]);
    }

    #[test]
    fn test_build_authenticator_data_rp_id_hash() {
        let rp_id = "example.com";
        let auth_data =
            build_authenticator_data_for_registration(rp_id, &[0; 10], &[0; 10], true, false);

        let mut hasher = Sha256::new();
        hasher.update(rp_id.as_bytes());
        let expected_hash = hasher.finalize();
        assert_eq!(&auth_data[0..32], expected_hash.as_slice());
    }

    #[test]
    fn test_build_client_data_json_for_registration_no_cross_origin() {
        let cdj =
            build_client_data_json_for_registration("https://example.com", "dGVzdA", false, None);
        let expected =
            br#"{"type":"webauthn.create","challenge":"dGVzdA","origin":"https://example.com"}"#;
        assert_eq!(cdj, expected);
    }

    #[test]
    fn test_build_client_data_json_for_registration_with_cross_origin() {
        let cdj = build_client_data_json_for_registration(
            "https://example.com",
            "dGVzdA",
            true,
            Some("https://top.example"),
        );
        let expected = br#"{"type":"webauthn.create","challenge":"dGVzdA","origin":"https://example.com","crossOrigin":true,"topOrigin":"https://top.example"}"#;
        assert_eq!(cdj, expected);
    }

    #[test]
    fn test_build_attestation_object_is_valid_cbor() {
        let auth_data = vec![0x01, 0x02, 0x03];
        let att_obj = build_attestation_object(&auth_data).expect("encodes");

        let value: ciborium::Value = ciborium::from_reader(att_obj.as_slice()).expect("valid CBOR");

        if let ciborium::Value::Map(map) = value {
            let fmt = map
                .iter()
                .find(|(k, _)| k == &ciborium::Value::Text("fmt".to_string()))
                .map(|(_, v)| v);
            assert_eq!(fmt, Some(&ciborium::Value::Text("none".to_string())));

            let auth_data_val = map
                .iter()
                .find(|(k, _)| k == &ciborium::Value::Text("authData".to_string()))
                .map(|(_, v)| v);
            assert_eq!(auth_data_val, Some(&ciborium::Value::Bytes(auth_data)));
        } else {
            panic!("attestation object should be a CBOR map");
        }
    }

    #[test]
    fn test_generate_credential_id_length() {
        let id = generate_credential_id().expect("the OS RNG works");
        assert_eq!(id.len(), 32);
    }

    #[test]
    fn test_generate_credential_id_unique() {
        let id1 = generate_credential_id().expect("the OS RNG works");
        let id2 = generate_credential_id().expect("the OS RNG works");
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_json_escape_string_quotes() {
        let escaped = json_escape_string(r#"hello "world""#);
        assert_eq!(escaped, r#"hello \"world\""#);
    }

    #[test]
    fn test_json_escape_string_backslash() {
        let escaped = json_escape_string(r#"path\to\file"#);
        assert_eq!(escaped, r#"path\\to\\file"#);
    }

    #[test]
    fn test_json_escape_string_control_chars() {
        let escaped = json_escape_string("line1\nline2");
        assert_eq!(escaped, "line1\\nline2");
    }

    #[test]
    fn test_normalize_rp_id() {
        assert_eq!(normalize_rp_id("Example.COM"), "example.com");
        assert_eq!(normalize_rp_id("  test.com  "), "test.com");
    }

    #[test]
    fn test_register_origin_verification() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let mut req = f.make_req();
        req.origin = "https://evil.com".to_string();

        let result = handler.register(&ctx, &req);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::OriginInvalid);
    }

    #[test]
    fn test_register_invalid_user_id_b64u() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let mut req = f.make_req();
        req.user_id_b64u = "!!!invalid!!!".to_string();

        let result = handler.register(&ctx, &req);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::BadRequest);
    }

    #[test]
    fn test_register_exclude_list_match() {
        let f = RegisterTestFixture::new();

        let existing_cred = soft_fido2::Credential {
            id: vec![0xCC; 32],
            rp: RelyingParty::new("example.com".into()),
            user: User::new(vec![1, 2, 3]),
            sign_count: 0,
            alg: -7,
            key: f.key_provider.generate(-7).unwrap().key,
            created: 0,
            discoverable: true,
            backup_state: CredentialBackupState::NotEligible,
            extensions: soft_fido2::Extensions::default(),
        };
        {
            let mut storage = f.storage.lock().unwrap();
            let cred_ref = soft_fido2::CredentialRef {
                id: &existing_cred.id,
                rp_id: &existing_cred.rp.id,
                rp_name: existing_cred.rp.name.as_deref(),
                user_id: &existing_cred.user.id,
                user_name: existing_cred.user.name.as_deref(),
                user_display_name: existing_cred.user.display_name.as_deref(),
                sign_count: &existing_cred.sign_count,
                alg: &existing_cred.alg,
                key: &existing_cred.key,
                created: &existing_cred.created,
                discoverable: &existing_cred.discoverable,
                cred_protect: existing_cred.extensions.cred_protect.as_ref(),
                cred_random: None,
                backup_state: &existing_cred.backup_state,
            };
            storage.write(cred_ref).unwrap();
        }

        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let mut req = f.make_req();
        req.exclude_credentials = vec![b64u_encode(&existing_cred.id)];

        let result = handler.register(&ctx, &req);
        assert!(result.is_err());
        let err = result.unwrap_err();
        // WebAuthn `InvalidStateError` (ADR 0014 section 10.3).
        assert_eq!(err.code, ErrorCode::InvalidState);
    }

    /// Review L8: the exclude list is matched within the request's RP. A credential ID that
    /// exists for another RP must not be revealed (the outcome is the same as for an unknown ID)
    /// and must not block the registration.
    #[test]
    fn test_register_exclude_list_does_not_reveal_a_credential_of_another_rp() {
        let f = RegisterTestFixture::new();
        let other = soft_fido2::Credential {
            id: vec![0xCD; 32],
            rp: RelyingParty::new("other.example".into()),
            user: User::new(vec![1, 2, 3]),
            sign_count: 0,
            alg: -7,
            key: f.key_provider.generate(-7).unwrap().key,
            created: 0,
            discoverable: true,
            backup_state: CredentialBackupState::NotEligible,
            extensions: soft_fido2::Extensions::default(),
        };
        {
            let mut storage = f.storage.lock().unwrap();
            let cred_ref = soft_fido2::CredentialRef {
                id: &other.id,
                rp_id: &other.rp.id,
                rp_name: other.rp.name.as_deref(),
                user_id: &other.user.id,
                user_name: other.user.name.as_deref(),
                user_display_name: other.user.display_name.as_deref(),
                sign_count: &other.sign_count,
                alg: &other.alg,
                key: &other.key,
                created: &other.created,
                discoverable: &other.discoverable,
                cred_protect: other.extensions.cred_protect.as_ref(),
                cred_random: None,
                backup_state: &other.backup_state,
            };
            storage.write(cred_ref).unwrap();
        }

        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let mut req = f.make_req();
        assert_eq!(req.rp_id, "example.com");
        req.exclude_credentials = vec![b64u_encode(&other.id)];

        let result = handler.register(&ctx, &req);
        assert!(
            result.is_ok(),
            "a credential of another RP in excludeCredentials must be ignored: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_register_rejects_denied_policy() {
        let deny_config = make_deny_profile_config();
        let f = make_fixture_with_config(deny_config);
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let req = f.make_req();

        let result = handler.register(&ctx, &req);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, ErrorCode::Forbidden);
    }

    #[test]
    fn test_register_request_rule_without_a_prompt_denies_with_escalation_unavailable() {
        let f = make_fixture_with_config(profile_with_rules(vec![register_rule(
            "example.com",
            RuleAction::Request,
        )]));
        // No session bus: nothing is prompted, the ceremony is denied and audited.
        f.prompter.set_unavailable(true);

        let err = f
            .make_handler()
            .register(&f.make_ctx(), &f.make_req())
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Forbidden);
        assert!(err.message.contains("escalation is unavailable"));
        assert_eq!(f.prompter.shown(), 0);
        assert_eq!(
            deny_reasons(&f),
            vec![(
                "example.com".to_string(),
                "escalation_unavailable".to_string()
            )]
        );
        assert_eq!(f.storage.lock().unwrap().count_credentials(), 0);
        assert!(
            f.policy_events()
                .iter()
                .all(|e| e["kind"] != "policy.allow"),
            "no allow event for a request rule"
        );
    }

    #[test]
    fn test_register_cross_origin_is_denied() {
        let f = RegisterTestFixture::new();
        let mut req = f.make_req();
        req.top_origin = Some("https://top.example".to_string());
        req.cross_origin = true;

        let err = f.make_handler().register(&f.make_ctx(), &req).unwrap_err();
        assert_eq!(err.code, ErrorCode::Forbidden);
    }

    #[test]
    fn test_register_generates_keypair() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let req = f.make_req();

        let result = handler.register(&ctx, &req);
        assert!(result.is_ok());
        let resp = result.unwrap();

        let auth_data = b64u_decode(&resp.authenticator_data_b64u).unwrap();
        assert!(auth_data.len() > 55);
        let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
        assert!(auth_data.len() >= 55 + cred_id_len);
    }

    #[test]
    fn test_register_writes_credential() {
        let f = RegisterTestFixture::new();
        let storage = f.storage.clone();
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let req = f.make_req();

        {
            let boxed = storage.lock().unwrap();
            let counting = unsafe {
                &*(boxed.as_ref() as *const dyn CredentialStorage as *const WriteCountingStorage)
            };
            assert_eq!(counting.writes(), 0);
        }

        let result = handler.register(&ctx, &req);
        assert!(result.is_ok());

        {
            let boxed = storage.lock().unwrap();
            let counting = unsafe {
                &*(boxed.as_ref() as *const dyn CredentialStorage as *const WriteCountingStorage)
            };
            assert_eq!(counting.writes(), 1);
            assert_eq!(counting.count_credentials(), 1);
        }
    }

    #[test]
    fn test_register_success_response_fields() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let req = f.make_req();

        let result = handler.register(&ctx, &req);
        assert!(result.is_ok());
        let resp = result.unwrap();

        assert!(!resp.credential_id_b64u.is_empty());
        assert!(!resp.authenticator_data_b64u.is_empty());
        assert!(!resp.attestation_object_b64u.is_empty());
        assert!(!resp.client_data_json_b64u.is_empty());

        let cdj = b64u_decode(&resp.client_data_json_b64u).unwrap();
        let cdj_str = std::str::from_utf8(&cdj).unwrap();
        assert!(cdj_str.contains("\"type\":\"webauthn.create\""));
        assert!(cdj_str.contains("\"challenge\":\"dGVzdA\""));
        assert!(cdj_str.contains("\"origin\":\"https://example.com\""));

        let auth_data = b64u_decode(&resp.authenticator_data_b64u).unwrap();
        assert_eq!(auth_data[32], 0x45);
        assert_eq!(&auth_data[37..53], &PASSLESS_AAGUID);

        let att_obj_bytes = b64u_decode(&resp.attestation_object_b64u).unwrap();
        let att_value: ciborium::Value =
            ciborium::from_reader(att_obj_bytes.as_slice()).expect("valid CBOR");
        if let ciborium::Value::Map(map) = att_value {
            let fmt = map
                .iter()
                .find(|(k, _)| k == &ciborium::Value::Text("fmt".to_string()))
                .map(|(_, v)| v);
            assert_eq!(fmt, Some(&ciborium::Value::Text("none".to_string())));
        } else {
            panic!("attestation object should be a CBOR map");
        }
    }

    #[test]
    fn test_register_allow_sets_up_and_uv_and_audits_agent_evidence() {
        let f = RegisterTestFixture::new();
        let mut req = f.make_req();
        // The RP's `userVerification` request does not matter: allow means UP and UV from the
        // agent session (ADR 0014 section 7).
        req.user_verification = false;
        let resp = f.make_handler().register(&f.make_ctx(), &req).unwrap();

        let auth_data = b64u_decode(&resp.authenticator_data_b64u).unwrap();
        assert_eq!(auth_data[32] & 0x05, 0x05, "UP and UV flags");
        assert_eq!(auth_data[32] & 0x40, 0x40, "AT flag");

        let events = f.policy_events();
        let allow = events.last().unwrap();
        assert_eq!(allow["kind"], "policy.allow");
        assert_eq!(allow["action"], "register");
        assert_eq!(allow["rp_id"], "example.com");
    }

    #[test]
    fn test_register_origin_spoofing_prevented() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();
        let ctx = f.make_ctx();

        let spoofed_origins = [
            "http://example.com",
            "https://example.com/path",
            "https://example.com?foo=bar",
            "https://example.com#frag",
            "https://user:pass@example.com",
            "https://notexample.com",
            "https://example.com.evil.com",
        ];

        for origin in &spoofed_origins {
            let mut req = f.make_req();
            req.origin = origin.to_string();
            let result = handler.register(&ctx, &req);
            assert!(result.is_err(), "should reject spoofed origin: {}", origin);
            assert_eq!(result.unwrap_err().code, ErrorCode::OriginInvalid);
        }
    }

    #[test]
    fn test_register_explicit_https_port_allowed() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let mut req = f.make_req();
        req.origin = "https://example.com:8443".to_string();

        let result = handler.register(&ctx, &req);
        assert!(result.is_ok());
    }

    #[test]
    fn test_register_concurrent_requests_serialized() {
        let f = Arc::new(RegisterTestFixture::new());
        let handler = Arc::new(f.make_handler());
        let mut handles = Vec::new();

        for _ in 0..4 {
            let h = handler.clone();
            let ctx = f.make_ctx();
            let req = f.make_req();
            handles.push(std::thread::spawn(move || h.register(&ctx, &req)));
        }

        let mut success_count = 0;
        for h in handles {
            if h.join().unwrap().is_ok() {
                success_count += 1;
            }
        }
        assert_eq!(success_count, 4);

        let boxed = f.storage.lock().unwrap();
        let counting = unsafe {
            &*(boxed.as_ref() as *const dyn CredentialStorage as *const WriteCountingStorage)
        };
        assert_eq!(counting.writes(), 4);
    }

    #[test]
    fn test_register_exclude_list_nonexistent_credential_passes() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let mut req = f.make_req();
        req.exclude_credentials = vec![b64u_encode(&[0xFF; 32])];

        let result = handler.register(&ctx, &req);
        assert!(result.is_ok());
    }

    // --- B3: the attested credential data carries a real COSE_Key ---

    /// Split registration `authenticatorData` into (credential id, COSE_Key bytes), checking that
    /// nothing is left over after the COSE_Key (the "Leftover bytes" failure a real RP reports).
    fn parse_attested_credential_data(auth_data: &[u8]) -> (Vec<u8>, ciborium::Value) {
        assert!(
            auth_data.len() > 55,
            "too short for attested credential data"
        );
        assert_eq!(auth_data[32] & 0x40, 0x40, "AT flag must be set");
        assert_eq!(&auth_data[37..53], &PASSLESS_AAGUID);
        let id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
        let id = auth_data[55..55 + id_len].to_vec();
        let mut cose = &auth_data[55 + id_len..];
        let key: ciborium::Value =
            ciborium::from_reader(&mut cose).expect("COSE_Key is valid CBOR");
        assert!(
            cose.is_empty(),
            "leftover bytes after the COSE_Key: {}",
            cose.len()
        );
        (id, key)
    }

    fn cose_int(key: &ciborium::Value, label: i64) -> Option<i128> {
        let ciborium::Value::Map(map) = key else {
            panic!("COSE_Key must be a CBOR map");
        };
        map.iter().find_map(|(k, v)| match (k, v) {
            (ciborium::Value::Integer(k), ciborium::Value::Integer(v))
                if i128::from(*k) == i128::from(label) =>
            {
                Some(i128::from(*v))
            }
            _ => None,
        })
    }

    fn cose_bytes(key: &ciborium::Value, label: i64) -> Option<Vec<u8>> {
        let ciborium::Value::Map(map) = key else {
            panic!("COSE_Key must be a CBOR map");
        };
        map.iter().find_map(|(k, v)| match (k, v) {
            (ciborium::Value::Integer(k), ciborium::Value::Bytes(v))
                if i128::from(*k) == i128::from(label) =>
            {
                Some(v.clone())
            }
            _ => None,
        })
    }

    #[test]
    fn test_cose_key_es256_exact_encoding() {
        let mut raw = vec![0x04];
        raw.extend_from_slice(&[0x11; 32]);
        raw.extend_from_slice(&[0x22; 32]);

        let cose = cose_key_from_raw_public_key(-7, &raw).unwrap();

        // {1: 2, 3: -7, -1: 1, -2: h'11..', -3: h'22..'} in CTAP2 canonical key order.
        assert_eq!(cose.len(), 77);
        assert_eq!(
            &cose[..10],
            &[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]
        );
        assert_eq!(&cose[10..42], &[0x11; 32]);
        assert_eq!(&cose[42..45], &[0x22, 0x58, 0x20]);
        assert_eq!(&cose[45..], &[0x22; 32]);
    }

    #[test]
    fn test_cose_key_eddsa_encoding() {
        let cose = cose_key_from_raw_public_key(-19, &[0x33; 32]).unwrap();
        let key: ciborium::Value = ciborium::from_reader(cose.as_slice()).unwrap();
        assert_eq!(cose_int(&key, 1), Some(1));
        assert_eq!(cose_int(&key, 3), Some(-19));
        assert_eq!(cose_int(&key, -1), Some(6));
        assert_eq!(cose_bytes(&key, -2), Some(vec![0x33; 32]));
    }

    #[test]
    fn test_cose_key_rejects_malformed_public_keys() {
        assert!(cose_key_from_raw_public_key(-7, &[0x04; 10]).is_err());
        let mut compressed = vec![0x02];
        compressed.extend_from_slice(&[0u8; 64]);
        assert!(cose_key_from_raw_public_key(-7, &compressed).is_err());
        assert!(cose_key_from_raw_public_key(-19, &[0u8; 31]).is_err());
        assert!(cose_key_from_raw_public_key(-257, &[0u8; 65]).is_err());
    }

    #[test]
    fn test_register_attested_credential_data_round_trips_and_verifies() {
        let f = RegisterTestFixture::new();
        let resp = f
            .make_handler()
            .register(&f.make_ctx(), &f.make_req())
            .unwrap();

        let auth_data = b64u_decode(&resp.authenticator_data_b64u).unwrap();
        let (credential_id, key) = parse_attested_credential_data(&auth_data);
        assert_eq!(b64u_encode(&credential_id), resp.credential_id_b64u);

        // EC2 / ES256 / P-256 with 32-byte coordinates.
        assert_eq!(cose_int(&key, 1), Some(2), "kty");
        assert_eq!(cose_int(&key, 3), Some(-7), "alg");
        assert_eq!(cose_int(&key, -1), Some(1), "crv");
        let x = cose_bytes(&key, -2).expect("x");
        let y = cose_bytes(&key, -3).expect("y");
        assert_eq!((x.len(), y.len()), (32, 32));

        // The decoded COSE key verifies a signature made with the stored credential key.
        let stored = f.storage.lock().unwrap().read(&credential_id).unwrap();
        let message = b"authenticatorData || clientDataHash";
        let signature = f.key_provider.sign(&stored.key, -7, message).unwrap();
        let mut sec1 = vec![0x04];
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        soft_fido2_crypto::ecdsa::verify(&sec1, message, &signature)
            .expect("signature verifies with the public key decoded from authenticatorData");
        assert!(soft_fido2_crypto::ecdsa::verify(&sec1, b"other message", &signature).is_err());
    }

    // --- registration authority is policy only (ADR 0014 section 10.3) ---

    fn deny_reasons(f: &RegisterTestFixture) -> Vec<(String, String)> {
        f.policy_events()
            .iter()
            .filter(|e| e["kind"] == "policy.deny" || e["kind"] == "operation.terminal")
            .map(|e| {
                (
                    e["rp_id"].as_str().unwrap_or_default().to_string(),
                    e["reason"]
                        .as_str()
                        .or_else(|| e["failure_class"].as_str())
                        .unwrap_or_default()
                        .to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn test_register_allow_needs_no_enrollment_grant() {
        let f = RegisterTestFixture::new();
        f.make_handler()
            .register(&f.make_ctx(), &f.make_req())
            .expect("register = allow is sufficient");
        let events = f.policy_events();
        assert_eq!(events.last().unwrap()["kind"], "policy.allow");
        assert_eq!(events.last().unwrap()["action"], "register");
    }

    #[test]
    fn test_register_unlisted_rp_is_denied_and_audited() {
        let f = RegisterTestFixture::new();
        let mut req = f.make_req();
        req.rp_id = "other.com".to_string();
        req.origin = "https://other.com".to_string();

        let err = f.make_handler().register(&f.make_ctx(), &req).unwrap_err();
        assert_eq!(err.code, ErrorCode::Forbidden);
        assert_eq!(
            deny_reasons(&f),
            vec![("other.com".to_string(), "action_not_allowed".to_string())]
        );
    }

    #[test]
    fn test_register_deny_rule_is_audited() {
        let f = make_fixture_with_config(make_deny_profile_config());
        let err = f
            .make_handler()
            .register(&f.make_ctx(), &f.make_req())
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Forbidden);
        assert_eq!(
            deny_reasons(&f),
            vec![("example.com".to_string(), "action_not_allowed".to_string())]
        );
    }

    fn wildcard_register_config(register: RuleAction) -> AgentProfileConfig {
        let mut config = profile_with_rules(vec![register_rule(WILDCARD_RP_ID, register)]);
        config.mode = AgentMode::SameUser;
        config
    }

    /// A same-user profile whose `*` rule requests both actions, with no pins (ADR 0014
    /// amendment section 3), plus an exact rule for `exact.example` that requests registration.
    fn wildcard_request_config() -> AgentProfileConfig {
        let mut config = profile_with_rules(vec![
            AgentRpRule {
                rp_id: WILDCARD_RP_ID.to_string(),
                register: RuleAction::Request,
                authenticate: RuleAction::Request,
                credential_selection: None,
            },
            AgentRpRule {
                rp_id: "exact.example".to_string(),
                register: RuleAction::Request,
                authenticate: RuleAction::Allow,
                credential_selection: None,
            },
        ]);
        config.mode = AgentMode::SameUser;
        config.principal_user = "alice".to_string();
        config.credential_refs = None;
        config
    }

    #[test]
    fn test_wildcard_register_allow_resolves_to_deny() {
        // `register = "allow"` on `*` is invalid configuration (see the config tests), and
        // resolution maps it to `deny` as defence in depth (amendment section 4): no prompt, no
        // credential. A wildcard `deny` is the default deny.
        for register in [RuleAction::Deny, RuleAction::Allow] {
            let f = make_fixture_with_config(wildcard_register_config(register));
            let err = f
                .make_handler()
                .register(&f.make_ctx(), &f.make_req())
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::Forbidden, "{register}");
            assert_eq!(
                deny_reasons(&f),
                vec![("example.com".to_string(), "action_not_allowed".to_string())],
                "{register}"
            );
            assert_eq!(f.prompter.shown(), 0);
            let boxed = f.storage.lock().unwrap();
            assert_eq!(boxed.count_credentials(), 0, "no credential may be written");
        }
    }

    #[test]
    fn test_wildcard_registration_without_its_acknowledgement_is_refused() {
        // Validation refuses this configuration at startup (amendment section 3); a policy
        // compiled without the acknowledgement is refused again at the escalation, without a
        // prompt (fail closed).
        let config = wildcard_request_config();
        let mut unacknowledged = agent_config_for(&ProfileId::new("p").unwrap(), config.clone());
        unacknowledged.acknowledge_global_registration.clear();
        let err = unacknowledged.validate(None).unwrap_err().to_string();
        assert!(err.contains("acknowledge_global_registration"), "{err}");

        let f = make_fixture_with_config(config);
        f.policy_runtime
            .reload(&{
                let mut c = agent_config_for(&f.profile_id, wildcard_request_config());
                c.acknowledge_global_registration.clear();
                c
            })
            .unwrap();
        let err = f
            .make_handler()
            .register(&f.make_ctx(), &f.make_req())
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Forbidden);
        assert_eq!(deny_reasons(&f).last().unwrap().1, "action_not_allowed");
        assert_eq!(f.prompter.shown(), 0);
        assert_eq!(f.storage.lock().unwrap().count_credentials(), 0);
    }

    #[test]
    fn test_exact_rule_wins_over_wildcard_for_registration() {
        let mut config = wildcard_register_config(RuleAction::Deny);
        config
            .rules
            .insert(0, register_rule("example.com", RuleAction::Allow));
        let f = make_fixture_with_config(config);
        f.make_handler()
            .register(&f.make_ctx(), &f.make_req())
            .expect("exact allow rule is used");
    }

    #[test]
    fn test_register_resolution_is_live_reload_to_deny() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();
        let ctx = f.make_ctx();

        handler
            .register(&ctx, &f.make_req())
            .expect("allowed before reload");
        assert_eq!(f.storage.lock().unwrap().count_credentials(), 1);

        // A reload that changes the policy revokes the existing session (ADR 0014 section 9) ...
        f.reload_profile(make_deny_profile_config());
        let err = handler.register(&ctx, &f.make_req()).unwrap_err();
        assert_eq!(err.code, ErrorCode::Unauthorized);
        // ... and a new session resolves against the new policy with the same handler.
        let err = handler.register(&f.make_ctx(), &f.make_req()).unwrap_err();
        assert_eq!(err.code, ErrorCode::Forbidden);
        assert_eq!(
            deny_reasons(&f),
            vec![
                ("example.com".to_string(), "policy_revoked".to_string()),
                ("example.com".to_string(), "action_not_allowed".to_string())
            ]
        );
        assert_eq!(
            f.storage.lock().unwrap().count_credentials(),
            1,
            "nothing written after the reload"
        );
    }

    #[test]
    fn test_register_resolution_is_live_reload_to_request_and_back() {
        let f = make_fixture_with_config(make_deny_profile_config());
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        assert!(handler.register(&ctx, &f.make_req()).is_err());

        // The reverse direction: a deny profile becomes allow for a session created after the
        // reload, with the same handler.
        f.reload_profile(make_registration_profile_config());
        handler
            .register(&f.make_ctx(), &f.make_req())
            .expect("allowed after reload");

        f.reload_profile(profile_with_rules(vec![register_rule(
            "example.com",
            RuleAction::Request,
        )]));
        f.prompter.set_unavailable(true);
        let err = handler.register(&f.make_ctx(), &f.make_req()).unwrap_err();
        assert!(err.message.contains("escalation is unavailable"));
        let reasons = deny_reasons(&f);
        assert_eq!(
            reasons.last().unwrap(),
            &(
                "example.com".to_string(),
                "escalation_unavailable".to_string()
            )
        );
    }

    #[test]
    fn test_refuse_revoked_bearer_records_bearer_revoked() {
        let f = RegisterTestFixture::new();
        f.make_handler()
            .refuse_revoked_bearer(&f.make_ctx(), Some("Example.com"));
        f.make_handler().refuse_revoked_bearer(&f.make_ctx(), None);
        f.make_handler()
            .refuse_revoked_bearer(&f.make_ctx(), Some("not an rp id!"));

        assert_eq!(
            deny_reasons(&f),
            vec![
                ("example.com".to_string(), "bearer_revoked".to_string()),
                ("unknown".to_string(), "bearer_revoked".to_string()),
                ("unknown".to_string(), "bearer_revoked".to_string()),
            ]
        );
        assert_eq!(f.storage.lock().unwrap().count_credentials(), 0);
    }

    // --- revocation while a request is in flight (ADR 0014 section 9) ---

    /// Counts `generate` calls and can revoke the bearer while the key is being generated, which is
    /// the window between the registry lookup and the credential write.
    struct InterferingKeyProvider {
        inner: SoftwareCredentialKeyProvider,
        generated: std::sync::atomic::AtomicUsize,
        /// Revoke this context from another thread while the key is being generated.
        revoke_during_generate: Option<RegisterContext>,
        /// Whether that revocation returned before key generation finished.
        revoke_returned_during_key_use: std::sync::atomic::AtomicBool,
        revoker: Mutex<Option<std::thread::JoinHandle<()>>>,
    }

    impl soft_fido2::CredentialKeyProvider for InterferingKeyProvider {
        fn provider_id(&self) -> soft_fido2::CredentialKeyProviderId {
            self.inner.provider_id()
        }
        fn supports_algorithm(&self, algorithm: i32) -> bool {
            self.inner.supports_algorithm(algorithm)
        }
        fn generate(
            &self,
            algorithm: i32,
        ) -> Result<soft_fido2::GeneratedCredentialKey, soft_fido2::CredentialKeyError> {
            self.generated.fetch_add(1, Ordering::AcqRel);
            if let Some(ctx) = &self.revoke_during_generate {
                let ctx = ctx.clone();
                let handle = std::thread::spawn(move || ctx.revoke());
                std::thread::sleep(std::time::Duration::from_millis(200));
                self.revoke_returned_during_key_use
                    .store(handle.is_finished(), Ordering::Release);
                *self.revoker.lock().unwrap() = Some(handle);
            }
            self.inner.generate(algorithm)
        }
        fn sign(
            &self,
            key: &soft_fido2::CredentialKey,
            algorithm: i32,
            data: &[u8],
        ) -> Result<Vec<u8>, soft_fido2::CredentialKeyError> {
            self.inner.sign(key, algorithm, data)
        }
    }

    fn handler_with_provider(
        f: &RegisterTestFixture,
        provider: Arc<InterferingKeyProvider>,
    ) -> RegisterHandler {
        RegisterHandler {
            key_provider: provider,
            ..f.make_handler()
        }
    }

    #[test]
    fn test_revoked_before_key_use_generates_nothing() {
        let f = RegisterTestFixture::new();
        let ctx = f.make_ctx();
        ctx.revoke();
        let provider = Arc::new(InterferingKeyProvider {
            inner: SoftwareCredentialKeyProvider,
            generated: std::sync::atomic::AtomicUsize::new(0),
            revoke_during_generate: None,
            revoke_returned_during_key_use: std::sync::atomic::AtomicBool::new(false),
            revoker: Mutex::new(None),
        });

        let err = handler_with_provider(&f, provider.clone())
            .register(&ctx, &f.make_req())
            .unwrap_err();

        assert_eq!(err.code, ErrorCode::Unauthorized);
        assert_eq!(provider.generated.load(Ordering::Acquire), 0, "no key use");
        assert_eq!(f.storage.lock().unwrap().count_credentials(), 0);
        assert_eq!(
            deny_reasons(&f),
            vec![("example.com".to_string(), "bearer_revoked".to_string())]
        );
    }

    #[test]
    fn test_revocation_during_key_use_waits_and_then_holds() {
        // Review M1: a revocation that starts after the pre-key-use re-check waits until the
        // credential is written; once it has returned, the bearer cannot be used again.
        let f = RegisterTestFixture::new();
        let ctx = f.make_ctx();
        let provider = Arc::new(InterferingKeyProvider {
            inner: SoftwareCredentialKeyProvider,
            generated: std::sync::atomic::AtomicUsize::new(0),
            revoke_during_generate: Some(ctx.clone()),
            revoke_returned_during_key_use: std::sync::atomic::AtomicBool::new(false),
            revoker: Mutex::new(None),
        });
        let handler = handler_with_provider(&f, provider.clone());

        handler
            .register(&ctx, &f.make_req())
            .expect("the registration past its re-check completes");
        assert!(
            !provider
                .revoke_returned_during_key_use
                .load(Ordering::Acquire),
            "the revocation waited for key use to finish"
        );
        provider
            .revoker
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(f.storage.lock().unwrap().count_credentials(), 1);

        let mut later = f.make_req();
        later.challenge_b64u = b64u_encode(b"later");
        assert_eq!(
            handler.register(&ctx, &later).unwrap_err().code,
            ErrorCode::Unauthorized
        );
        assert_eq!(provider.generated.load(Ordering::Acquire), 1);
    }

    #[test]
    fn test_unsupported_algorithm_is_a_deny_not_an_allow() {
        let f = RegisterTestFixture::new();
        let mut req = f.make_req();
        req.pub_key_cred_params = vec![-257];

        let err = f.make_handler().register(&f.make_ctx(), &req).unwrap_err();

        assert_eq!(err.code, ErrorCode::NotSupported);
        assert_eq!(
            deny_reasons(&f),
            vec![(
                "example.com".to_string(),
                "algorithm_unsupported".to_string()
            )]
        );
        assert!(
            f.policy_events()
                .iter()
                .all(|e| e["kind"] != "policy.allow"),
            "no allow without a credential"
        );
    }

    #[test]
    fn test_register_user_verification_request_is_irrelevant_under_allow() {
        // The RP's `userVerification` request and `always_uv` no longer matter: `allow` carries UV
        // from the agent session.
        let f = RegisterTestFixture::new();
        for rp_wants_uv in [false, true] {
            let mut req = f.make_req();
            req.user_verification = rp_wants_uv;
            let resp = f.make_handler().register(&f.make_ctx(), &req).unwrap();
            let auth_data = b64u_decode(&resp.authenticator_data_b64u).unwrap();
            assert_eq!(auth_data[32] & 0x05, 0x05);
        }
    }

    #[test]
    fn test_cose_key_eddsa_byte_order_and_signature_verify() {
        let provider = SoftwareCredentialKeyProvider;
        let generated = provider.generate(-19).unwrap();
        assert_eq!(generated.cose_public_key.len(), 32);

        let cose = cose_key_from_raw_public_key(-19, &generated.cose_public_key).unwrap();

        // {1: 1, 3: -19, -1: 6, -2: h'..'} in CTAP2 canonical key order.
        assert_eq!(cose.len(), 1 + 2 + 2 + 2 + 35);
        assert_eq!(
            &cose[..9],
            &[0xa4, 0x01, 0x01, 0x03, 0x32, 0x20, 0x06, 0x21, 0x58]
        );
        assert_eq!(cose[9], 0x20);

        let mut rest = cose.as_slice();
        let key: ciborium::Value = ciborium::from_reader(&mut rest).unwrap();
        assert!(rest.is_empty(), "leftover bytes after the COSE_Key");
        assert_eq!(cose_int(&key, 1), Some(1));
        assert_eq!(cose_int(&key, 3), Some(-19));
        assert_eq!(cose_int(&key, -1), Some(6));
        let x = cose_bytes(&key, -2).expect("x");

        let message = b"authenticatorData || clientDataHash";
        let signature = provider.sign(&generated.key, -19, message).unwrap();
        soft_fido2_crypto::eddsa::verify(&x, message, &signature)
            .expect("signature verifies with the public key decoded from the COSE_Key");
        assert!(soft_fido2_crypto::eddsa::verify(&x, b"other message", &signature).is_err());
    }

    // --- P5: replay, budget, binding and revocation for registration (ADR 0014 section 9) ---

    #[test]
    fn identical_registration_creates_one_credential_and_returns_the_same_result() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let first = handler.register(&ctx, &f.make_req()).unwrap();
        let second = handler.register(&ctx, &f.make_req()).unwrap();
        assert_eq!(first, second);
        assert_eq!(f.storage.lock().unwrap().count_credentials(), 1);
        assert_eq!(ctx.session.operations_used(), 1);
    }

    #[test]
    fn rejected_registrations_claim_no_budget() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let mut bad_origin = f.make_req();
        bad_origin.origin = "https://evil.test".to_string();
        assert!(handler.register(&ctx, &bad_origin).is_err());
        let mut unsupported = f.make_req();
        unsupported.extensions = vec!["largeBlob".to_string()];
        assert_eq!(
            handler.register(&ctx, &unsupported).unwrap_err().code,
            ErrorCode::NotSupported
        );
        let mut enterprise = f.make_req();
        enterprise.attestation = Some("enterprise".to_string());
        assert_eq!(
            handler.register(&ctx, &enterprise).unwrap_err().code,
            ErrorCode::NotSupported
        );
        let mut algorithms = f.make_req();
        algorithms.pub_key_cred_params = vec![-257];
        assert_eq!(
            handler.register(&ctx, &algorithms).unwrap_err().code,
            ErrorCode::NotSupported
        );
        assert_eq!(ctx.session.operations_used(), 0);
        assert_eq!(f.storage.lock().unwrap().count_credentials(), 0);

        // Supported extensions and attestation preferences pass.
        let mut ok = f.make_req();
        ok.extensions = vec!["credProps".to_string()];
        ok.attestation = Some("direct".to_string());
        handler
            .register(&ctx, &ok)
            .expect("credProps and direct are honored");
    }

    #[test]
    fn registration_bound_to_a_grant_of_another_principal_is_denied() {
        let f = RegisterTestFixture::new();
        let ctx = f.make_ctx();
        let request = f
            .policy_runtime
            .admin_request_session_grant(
                crate::agent::grant::GrantRequestParams {
                    profile_id: f.profile_id.clone(),
                    session_id: passless_core::agent::PrincipalSessionId::new(),
                    principal_digest: [5u8; 32],
                    rp_ids: vec!["example.com".to_string()],
                    credentials: vec![],
                    requested_ttl_secs: 60,
                },
                true,
            )
            .unwrap();
        let grant_id = f
            .policy_runtime
            .admin_approve_grant(&request, &crate::agent::identity::admin_authority())
            .unwrap();
        ctx.session.bind_grant(grant_id).unwrap();
        let err = f.make_handler().register(&ctx, &f.make_req()).unwrap_err();
        assert_eq!(err.code, ErrorCode::Forbidden);
        assert_eq!(
            deny_reasons(&f),
            vec![("example.com".to_string(), "principal_mismatch".to_string())]
        );
        assert_eq!(f.storage.lock().unwrap().count_credentials(), 0);
    }

    #[test]
    fn changed_reload_during_registration_writes_no_credential() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let runtime = f.policy_runtime.clone();
        let profile_id = f.profile_id.clone();
        let _hook = crate::agent::session::test_hooks::set_before_key_use(move || {
            let mut changed = make_registration_profile_config();
            changed.max_operations = 3;
            assert!(
                runtime
                    .reload(&agent_config_for(&profile_id, changed))
                    .unwrap()
                    .changed
            );
        });
        let err = handler.register(&ctx, &f.make_req()).unwrap_err();
        assert_eq!(err.code, ErrorCode::Unauthorized);
        assert_eq!(f.storage.lock().unwrap().count_credentials(), 0);
        assert_eq!(
            deny_reasons(&f),
            vec![("example.com".to_string(), "policy_revoked".to_string())]
        );
    }
    fn records_of_kind(f: &RegisterTestFixture, kind: &str) -> Vec<serde_json::Value> {
        read_audit_events(&f.audit_dir)
            .into_iter()
            .filter(|e| e["kind"] == kind)
            .collect()
    }

    #[test]
    fn a_successful_registration_is_one_reservation_and_one_terminal_record() {
        let f = RegisterTestFixture::new();
        let mut handler = f.make_handler();
        handler.audit_deployment = AuditDeployment {
            mode: Some("isolated".to_string()),
            principal_relationship: Some("distinct-uid".to_string()),
            backend: Some("local".to_string()),
            key_provider: Some("software".to_string()),
        };
        let response = handler.register(&f.make_ctx(), &f.make_req()).unwrap();
        let allows = records_of_kind(&f, "policy.allow");
        let terminals = records_of_kind(&f, "operation.terminal");
        assert_eq!((allows.len(), terminals.len()), (1, 1));
        let (allow, terminal) = (&allows[0], &terminals[0]);
        assert_eq!(allow["request_id"], terminal["request_id"]);
        for record in [allow, terminal] {
            assert_eq!(record["action"], "register");
            assert_eq!(record["rp_id"], "example.com");
            assert_eq!(record["mode"], "isolated");
            assert_eq!(record["principal_relationship"], "distinct-uid");
            assert_eq!(record["backend"], "local");
            assert_eq!(record["key_provider"], "software");
            assert_eq!(record["rule"], "exact");
            assert_eq!(record["grant_source"], "config");
            assert_eq!(record["decision"], "allow");
            assert_eq!(record["evidence_source"], "agent");
            assert!(record["selection_rule"].is_null());
            assert!(record["counter_before"].is_null());
        }
        assert!(
            allow["credential_ref"].is_null(),
            "the credential does not exist at reservation"
        );
        assert_eq!(terminal["result"], "success");
        assert!(terminal["failure_class"].is_null());
        assert_eq!(terminal["counter_after"], 0);
        let id = b64u_decode(&response.credential_id_b64u).unwrap();
        assert_eq!(
            terminal["credential_ref"],
            serde_json::to_value(CredentialRef::with_default_domain(&id)).unwrap()
        );
    }

    #[test]
    fn a_revoked_bearer_is_refused_before_any_reservation() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        ctx.revoke();
        // A revoked bearer is refused before any reservation: one refusal, no terminal record.
        handler.register(&ctx, &f.make_req()).unwrap_err();
        assert_eq!(records_of_kind(&f, "policy.deny").len(), 1);
        assert!(records_of_kind(&f, "operation.terminal").is_empty());
    }

    #[test]
    fn a_reload_between_the_reservation_and_key_generation_ends_in_one_terminal_record() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let runtime = f.policy_runtime.clone();
        let profile_id = f.profile_id.clone();
        let _hook = crate::agent::session::test_hooks::set_before_key_use(move || {
            let mut changed = make_registration_profile_config();
            changed.max_operations = 3;
            runtime
                .reload(&agent_config_for(&profile_id, changed))
                .unwrap();
        });
        handler.register(&ctx, &f.make_req()).unwrap_err();
        assert_eq!(records_of_kind(&f, "policy.allow").len(), 1);
        let terminals = records_of_kind(&f, "operation.terminal");
        assert_eq!(terminals.len(), 1);
        assert_eq!(terminals[0]["result"], "revoked");
        assert_eq!(terminals[0]["failure_class"], "policy_revoked");
        assert!(terminals[0]["credential_ref"].is_null());
        assert!(
            records_of_kind(&f, "policy.deny").is_empty(),
            "after the reservation a failure is the terminal record, not a second refusal"
        );
    }

    /// A key provider whose `generate` panics.
    struct PanickingKeyProvider;

    impl soft_fido2::CredentialKeyProvider for PanickingKeyProvider {
        fn provider_id(&self) -> soft_fido2::CredentialKeyProviderId {
            SoftwareCredentialKeyProvider.provider_id()
        }
        fn supports_algorithm(&self, algorithm: i32) -> bool {
            SoftwareCredentialKeyProvider.supports_algorithm(algorithm)
        }
        fn generate(
            &self,
            _algorithm: i32,
        ) -> Result<soft_fido2::GeneratedCredentialKey, soft_fido2::CredentialKeyError> {
            panic!("the key provider panicked");
        }
        fn sign(
            &self,
            _key: &soft_fido2::CredentialKey,
            _algorithm: i32,
            _data: &[u8],
        ) -> Result<Vec<u8>, soft_fido2::CredentialKeyError> {
            unreachable!("registration never signs")
        }
    }

    #[test]
    fn a_panic_in_key_generation_still_gets_exactly_one_abandoned_terminal_record() {
        let f = RegisterTestFixture::new();
        let handler = RegisterHandler {
            key_provider: Arc::new(PanickingKeyProvider),
            ..f.make_handler()
        };
        let ctx = f.make_ctx();
        let req = f.make_req();
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = handler.register(&ctx, &req);
        }));
        assert!(unwound.is_err());
        assert_eq!(records_of_kind(&f, "policy.allow").len(), 1);
        let terminals = records_of_kind(&f, "operation.terminal");
        assert_eq!(terminals.len(), 1, "exactly one terminal record");
        assert_eq!(terminals[0]["result"], "error");
        assert_eq!(terminals[0]["failure_class"], "abandoned");
        assert_eq!(
            terminals[0]["request_id"],
            records_of_kind(&f, "policy.allow")[0]["request_id"]
        );
        assert!(records_of_kind(&f, "policy.deny").is_empty());
    }

    #[test]
    fn an_abort_between_the_reservation_and_key_generation_ends_in_an_aborted_terminal_record() {
        let f = RegisterTestFixture::new();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        // The first check (before the replay key) passes; the re-check before key use sees it.
        let cancelled = || calls.fetch_add(1, Ordering::AcqRel) >= 1;
        let deadline = ceremony_deadline(None, Instant::now());
        f.make_handler()
            .register_with(&f.make_ctx(), &f.make_req(), deadline, &cancelled)
            .unwrap_err();
        assert_eq!(records_of_kind(&f, "policy.allow").len(), 1);
        let terminals = records_of_kind(&f, "operation.terminal");
        assert_eq!(terminals.len(), 1);
        assert_eq!(terminals[0]["result"], "aborted");
        assert_eq!(terminals[0]["failure_class"], "aborted");
        assert!(terminals[0]["credential_ref"].is_null());
        assert!(records_of_kind(&f, "policy.deny").is_empty());
        assert_eq!(f.storage.lock().unwrap().count_credentials(), 0);
    }

    #[test]
    fn a_bearer_revoked_between_the_reservation_and_key_generation_ends_in_a_revoked_terminal() {
        let f = RegisterTestFixture::new();
        let ctx = f.make_ctx();
        let session = ctx.session.clone();
        let _hook = crate::agent::session::test_hooks::set_before_key_use(move || {
            session.revoke();
        });
        f.make_handler().register(&ctx, &f.make_req()).unwrap_err();
        assert_eq!(records_of_kind(&f, "policy.allow").len(), 1);
        let terminals = records_of_kind(&f, "operation.terminal");
        assert_eq!(terminals.len(), 1);
        assert_eq!(terminals[0]["result"], "revoked");
        assert!(terminals[0]["failure_class"].is_string());
        assert!(records_of_kind(&f, "policy.deny").is_empty());
        assert_eq!(f.storage.lock().unwrap().count_credentials(), 0);
    }

    #[test]
    fn an_excluded_credential_failure_gives_the_budget_back() {
        let f = RegisterTestFixture::new();
        let handler = f.make_handler();
        let ctx = f.make_ctx();
        let created = handler.register(&ctx, &f.make_req()).unwrap();
        assert_eq!(ctx.session.operations_used(), 1);
        for i in 0..5u8 {
            let mut req = f.make_req();
            req.challenge_b64u = b64u_encode(&[b'x', i]);
            req.exclude_credentials = vec![created.credential_id_b64u.clone()];
            assert_eq!(
                handler.register(&ctx, &req).unwrap_err().code,
                ErrorCode::InvalidState
            );
        }
        assert_eq!(
            ctx.session.operations_used(),
            1,
            "InvalidState ends before key use"
        );
        assert_eq!(f.storage.lock().unwrap().count_credentials(), 1);
    }

    // --- P7: registration escalation (ADR 0014 section 8.3) ---

    fn register_request_config() -> AgentProfileConfig {
        profile_with_rules(vec![AgentRpRule {
            rp_id: "example.com".to_string(),
            register: RuleAction::Request,
            authenticate: RuleAction::Request,
            credential_selection: None,
        }])
    }

    type RegisterResult = Result<RegisterCredentialResponse, ProtocolError>;

    fn register_on_thread(
        f: &RegisterTestFixture,
        ctx: &RegisterContext,
        req: RegisterCredentialRequest,
    ) -> std::thread::JoinHandle<RegisterResult> {
        let handler = f.make_handler();
        let ctx = ctx.clone();
        std::thread::spawn(move || handler.register(&ctx, &req))
    }

    fn req_with_challenge(f: &RegisterTestFixture, challenge: &[u8]) -> RegisterCredentialRequest {
        RegisterCredentialRequest {
            challenge_b64u: b64u_encode(challenge),
            ..f.make_req()
        }
    }

    fn escalation_kinds(f: &RegisterTestFixture) -> Vec<String> {
        read_audit_events(&f.audit_dir)
            .iter()
            .filter_map(|e| e["kind"].as_str().map(str::to_string))
            .filter(|k| k.starts_with("escalation.") || k.starts_with("granted_rule."))
            .collect()
    }

    fn deny() -> PromptEvent {
        PromptEvent::Denied(crate::agent::audit_events::EscalationDenyCause::User)
    }

    #[test]
    fn test_registration_escalation_registers_once_and_persists_a_registration_grant() {
        let f = make_fixture_with_config(register_request_config());
        let ctx = f.make_ctx();
        let ceremony = register_on_thread(&f, &ctx, f.make_req());
        f.prompter.approve(1);
        let response = ceremony.join().unwrap().expect("approved registration");
        assert_eq!(f.storage.lock().unwrap().count_credentials(), 1);
        assert_eq!(ctx.session.operations_used(), 1);

        let credential_id = b64u_decode(&response.credential_id_b64u).unwrap();
        let grants = f.store.profile(&f.profile_id).unwrap();
        let rules = grants.rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].kind, GrantKind::Registration);
        assert_eq!(rules[0].rp_id, "example.com");
        assert_eq!(
            rules[0].credential_ref,
            Some(CredentialRef::with_default_domain(&credential_id))
        );
        assert_eq!(
            escalation_kinds(&f),
            vec![
                "escalation.requested",
                "escalation.approved",
                "granted_rule.add"
            ]
        );
        // `authenticate` for the RP is now a granted allow; registration still escalates.
        let auth =
            f.policy_runtime
                .resolve(&f.profile_id, &GrantAction::Authenticate, "example.com");
        assert!(auth.granted && auth.action == RuleAction::Allow);

        let second = register_on_thread(&f, &ctx, req_with_challenge(&f, b"second"));
        f.prompter.wait_shown(2);
        f.prompter.decide(deny());
        assert_eq!(
            second.join().unwrap().unwrap_err().code,
            ErrorCode::Forbidden
        );
        assert_eq!(f.storage.lock().unwrap().count_credentials(), 1);
        assert_eq!(
            ctx.session.operations_used(),
            1,
            "a denied escalation claims nothing"
        );
    }

    #[test]
    fn test_concurrent_registration_escalation_is_busy_not_joined() {
        let f = make_fixture_with_config(register_request_config());
        let ctx = f.make_ctx();
        let first = register_on_thread(&f, &ctx, f.make_req());
        f.prompter.wait_shown(1);

        let err = f
            .make_handler()
            .register(&ctx, &req_with_challenge(&f, b"concurrent"))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Forbidden);
        assert_eq!(deny_reasons(&f).last().unwrap().1, "escalation_busy");
        assert_eq!(f.prompter.shown(), 1);

        f.prompter.decide(deny());
        assert_eq!(
            first.join().unwrap().unwrap_err().code,
            ErrorCode::Forbidden
        );
        assert_eq!(deny_reasons(&f).last().unwrap().1, "escalation_denied");
        assert_eq!(f.storage.lock().unwrap().count_credentials(), 0);
        assert_eq!(ctx.session.operations_used(), 0);
        assert!(f.store.profile(&f.profile_id).unwrap().rules().is_empty());
    }

    #[test]
    fn test_registration_request_needs_its_own_approval_before_key_use() {
        // Without an approval the pre-key-use re-check refuses a configured `request`.
        let f = make_fixture_with_config(register_request_config());
        let ctx = f.make_ctx();
        let req = f.make_req();
        let handler = f.make_handler();
        let audit = handler.ceremony_audit(&ctx);
        let target = AuditTarget::of_request(&audit, "example.com", &req.origin, None, false);
        let err = handler
            .recheck_before_key_use(&ctx, &target, None, &|| false)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Forbidden);
        assert_eq!(deny_reasons(&f).last().unwrap().1, "policy_revoked");
    }

    #[test]
    fn test_registration_credential_ref_rejects_undecodable_and_empty_ids() {
        assert!(registration_credential_ref("!!not base64!!").is_err());
        assert!(registration_credential_ref("").is_err());
        let id = b"\x01\x02\x03";
        assert_eq!(
            registration_credential_ref(&b64u_encode(id)).unwrap(),
            CredentialRef::with_default_domain(id)
        );
    }

    #[test]
    fn a_registration_that_fails_after_approval_persists_nothing() {
        // The approval is given, then a reload revokes the operation between the reservation and
        // key generation: no credential is created and no grant (registration or authenticate)
        // reaches the store (ADR 0014 section 8.3, plan RG-05).
        let f = make_fixture_with_config(register_request_config());
        let ctx = f.make_ctx();
        let handler = f.make_handler();
        let req = f.make_req();
        let runtime = f.policy_runtime.clone();
        let profile_id = f.profile_id.clone();
        let ceremony = {
            let ctx = ctx.clone();
            std::thread::spawn(move || {
                let _hook = crate::agent::session::test_hooks::set_before_key_use(move || {
                    let mut changed = register_request_config();
                    changed.max_operations = 3;
                    runtime
                        .reload(&agent_config_for(&profile_id, changed))
                        .unwrap();
                });
                handler.register(&ctx, &req)
            })
        };
        f.prompter.approve(1);
        let err = ceremony.join().unwrap().unwrap_err();
        assert!(
            matches!(err.code, ErrorCode::Unauthorized | ErrorCode::Forbidden),
            "{err:?}"
        );

        assert_eq!(f.storage.lock().unwrap().count_credentials(), 0);
        assert!(
            f.store
                .profile(&f.profile_id)
                .is_none_or(|grants| grants.rules().is_empty()),
            "no grant persisted after a failed registration"
        );
        assert!(
            !escalation_kinds(&f).contains(&"granted_rule.add".to_string()),
            "{:?}",
            escalation_kinds(&f)
        );
        // `authenticate` is not upgraded either: it still escalates.
        let auth =
            f.policy_runtime
                .resolve(&f.profile_id, &GrantAction::Authenticate, "example.com");
        assert!(!auth.granted);
        assert_eq!(auth.action, RuleAction::Request);
    }

    #[test]
    fn test_failed_registration_grant_write_keeps_the_credential() {
        use std::os::unix::fs::PermissionsExt;

        let f = make_fixture_with_config(register_request_config());
        let dir = f.store.dir().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let ctx = f.make_ctx();
        let ceremony = register_on_thread(&f, &ctx, f.make_req());
        f.prompter.wait_shown(1);
        // The store becomes unwritable between the prompt and the credential write.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        f.prompter.decide(PromptEvent::Approved);
        let result = ceremony.join().unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        result.expect("the credential is returned (plan P7 gap 10)");
        assert_eq!(f.storage.lock().unwrap().count_credentials(), 1);
        assert!(
            f.store
                .profile(&f.profile_id)
                .is_none_or(|grants| grants.rules().is_empty()),
            "no grant persisted"
        );
        let denied = read_audit_events(&f.audit_dir)
            .into_iter()
            .find(|e| e["kind"] == "escalation.denied")
            .expect("the failed grant write is audited");
        assert_eq!(denied["cause"], "grant_write_failed");
        // The next authentication escalates again.
        let auth =
            f.policy_runtime
                .resolve(&f.profile_id, &GrantAction::Authenticate, "example.com");
        assert_eq!(auth.action, RuleAction::Request);
    }

    // --- Registration at unlisted sites (ADR 0014 amendment section 2.2) ---

    fn req_for(
        f: &RegisterTestFixture,
        rp_id: &str,
        challenge: &[u8],
    ) -> RegisterCredentialRequest {
        RegisterCredentialRequest {
            rp_id: rp_id.to_string(),
            origin: format!("https://www.{rp_id}"),
            challenge_b64u: b64u_encode(challenge),
            ..f.make_req()
        }
    }

    /// A credential the human already holds at `rp_id`.
    fn human_credential(f: &RegisterTestFixture, rp_id: &str, id: u8) {
        let mut boxed = f.storage.lock().unwrap();
        let generated = SoftwareCredentialKeyProvider.generate(-7).unwrap();
        let credential = soft_fido2::Credential {
            id: vec![id; 32],
            rp: RelyingParty::new(rp_id.into()),
            user: User::new(vec![id]),
            sign_count: 0,
            alg: -7,
            key: generated.key,
            created: 0,
            discoverable: true,
            backup_state: CredentialBackupState::NotEligible,
            extensions: soft_fido2::Extensions::default(),
        };
        boxed
            .write(soft_fido2::CredentialRef {
                id: &credential.id,
                rp_id: &credential.rp.id,
                rp_name: None,
                user_id: &credential.user.id,
                user_name: None,
                user_display_name: None,
                sign_count: &credential.sign_count,
                alg: &credential.alg,
                key: &credential.key,
                created: &credential.created,
                discoverable: &credential.discoverable,
                cred_protect: None,
                cred_random: None,
                backup_state: &credential.backup_state,
            })
            .unwrap();
    }

    fn wildcard_fixture(tune: impl FnOnce(&mut AgentProfileConfig)) -> RegisterTestFixture {
        let mut config = wildcard_request_config();
        tune(&mut config);
        make_fixture_with_config(config)
    }

    /// Run one registration through `*` at `rp_id` and approve it.
    fn approved_wildcard_registration(
        f: &RegisterTestFixture,
        rp_id: &str,
        prompts_before: usize,
    ) -> RegisterCredentialResponse {
        let ceremony = register_on_thread(f, &f.make_ctx(), req_for(f, rp_id, rp_id.as_bytes()));
        f.prompter.approve(prompts_before + 1);
        ceremony
            .join()
            .unwrap()
            .expect("approved wildcard registration")
    }

    #[test]
    fn wildcard_registration_is_prompted_once_and_persists_a_wildcard_grant() {
        let f = wildcard_fixture(|_| {});
        human_credential(&f, "example.org", 7);
        let ctx = f.make_ctx();
        let ceremony = register_on_thread(&f, &ctx, req_for(&f, "example.org", b"one"));
        f.prompter.wait_shown(1);

        // The prompt is a registration prompt through `*`, with the store count (amendment 5).
        let fields = f.prompter.last_fields();
        assert_eq!(
            fields.verb,
            crate::agent::escalation_prompt::PromptVerb::Register
        );
        assert_eq!(
            fields.rule,
            crate::agent::escalation_prompt::PromptRule::Wildcard
        );
        assert_eq!(
            fields.store_count,
            Some(1),
            "the human's passkey is counted"
        );
        assert_eq!(fields.mode, "same-user");
        let (summary, body) = crate::agent::escalation_prompt::render_prompt(&fields).unwrap();
        assert_eq!(summary, "Passless: CREATE A NEW PASSKEY? (not a sign-in)");
        assert!(body.contains("Site: example.org (NOT on your list; matched by the * rule)"));
        assert!(body.contains("which already holds 1 passkey for this site"));

        f.prompter.decide(PromptEvent::Approved);
        let response = ceremony.join().unwrap().expect("approved");
        assert_eq!(f.storage.lock().unwrap().count_credentials(), 2);

        // The grant: authenticate = allow for exactly that RP, kind registration, rule `*`, the
        // new credential (item 2).
        let credential_id = b64u_decode(&response.credential_id_b64u).unwrap();
        let grants = f.store.profile(&f.profile_id).unwrap();
        let rules = grants.rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].rp_id, "example.org");
        assert_eq!(rules[0].kind, GrantKind::Registration);
        assert_eq!(
            rules[0].rule,
            crate::agent::granted_rules::PermittingRule::Wildcard
        );
        assert_eq!(
            rules[0].credential_ref,
            Some(CredentialRef::with_default_domain(&credential_id))
        );
        assert_eq!(
            f.policy_runtime
                .granted_credential_refs(&f.profile_id, "example.org"),
            vec![CredentialRef::with_default_domain(&credential_id)]
        );
        // The `*` sign-in at that RP is now a granted allow; other unlisted RPs still escalate.
        let auth =
            f.policy_runtime
                .resolve(&f.profile_id, &GrantAction::Authenticate, "example.org");
        assert!(auth.granted && auth.action == RuleAction::Allow);
        assert_eq!(auth.rule, RuleIdentity::Wildcard);
        let other =
            f.policy_runtime
                .resolve(&f.profile_id, &GrantAction::Authenticate, "example.net");
        assert_eq!(other.action, RuleAction::Request);
        // Registration is never upgraded: the next one at the same RP escalates again.
        let again = f
            .policy_runtime
            .resolve(&f.profile_id, &GrantAction::Register, "example.org");
        assert_eq!(again.action, RuleAction::Request);

        // Audit: the escalation and the operation name rule `*`; a registration has no
        // candidate scope.
        let events = read_audit_events(&f.audit_dir);
        let requested = events
            .iter()
            .find(|e| e["kind"] == "escalation.requested")
            .unwrap();
        assert_eq!(requested["rule"], "*");
        assert_eq!(requested["action"], "register");
        let reservation = events.iter().find(|e| e["kind"] == "policy.allow").unwrap();
        assert_eq!(reservation["rule"], "*");
        assert_eq!(reservation["v"], 4);
        assert!(reservation["credential_scope"].is_null());
        let added = events
            .iter()
            .find(|e| e["kind"] == "granted_rule.add")
            .unwrap();
        assert_eq!(added["grant_kind"], "registration");
        assert_eq!(added["rule"], "*");
    }

    #[test]
    fn wildcard_registration_store_count_is_read_without_the_operation_lock() {
        let f = wildcard_fixture(|_| {});
        // The human path holds the operation lock for as long as the prompt is up: the count is
        // read under the storage lock alone, so the prompt still appears.
        let op = f.operation_lock.lock().unwrap();
        let ceremony = register_on_thread(&f, &f.make_ctx(), req_for(&f, "example.org", b"x"));
        f.prompter.wait_shown(1);
        assert_eq!(f.prompter.last_fields().store_count, Some(0));
        f.prompter.decide(deny());
        assert!(ceremony.join().unwrap().is_err());
        drop(op);
    }

    #[test]
    fn wildcard_registration_at_the_cap_is_refused_without_a_prompt() {
        let f = wildcard_fixture(|config| config.max_wildcard_registrations = Some(1));
        approved_wildcard_registration(&f, "example.org", 0);

        let err = f
            .make_handler()
            .register(&f.make_ctx(), &req_for(&f, "example.net", b"two"))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Forbidden);
        assert!(err.message.contains("wildcard_registration_cap"), "{err:?}");
        assert_eq!(
            deny_reasons(&f).last().unwrap(),
            &(
                "example.net".to_string(),
                "wildcard_registration_cap".to_string()
            )
        );
        assert_eq!(f.prompter.shown(), 1, "no prompt at the cap");

        // An exact-rule registration is not capped.
        let exact = register_on_thread(&f, &f.make_ctx(), req_for(&f, "exact.example", b"e"));
        f.prompter.wait_shown(2);
        assert_eq!(
            f.prompter.last_fields().rule,
            crate::agent::escalation_prompt::PromptRule::Exact
        );
        f.prompter.decide(deny());
        assert!(exact.join().unwrap().is_err());

        // Revoking the wildcard grant frees the slot (the credential stays).
        f.store
            .revoke(
                &f.policy_runtime,
                &f.profile_id,
                "example.org",
                crate::agent::granted_rules::GrantedAction::Authenticate,
            )
            .unwrap();
        assert_eq!(f.storage.lock().unwrap().count_credentials(), 1);
        approved_wildcard_registration(&f, "example.net", 2);
    }

    #[test]
    fn wildcard_registration_prompts_are_limited_per_day() {
        let f = wildcard_fixture(|config| config.wildcard_registration_prompts_per_day = Some(2));
        approved_wildcard_registration(&f, "a.example", 0);
        approved_wildcard_registration(&f, "b.example", 1);
        let err = f
            .make_handler()
            .register(&f.make_ctx(), &req_for(&f, "c.example", b"c"))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Forbidden);
        assert_eq!(
            deny_reasons(&f).last().unwrap(),
            &(
                "c.example".to_string(),
                "wildcard_registration_rate".to_string()
            )
        );
        assert_eq!(f.prompter.shown(), 2);
        // Exact-rule registration prompts neither count nor are limited.
        let exact = register_on_thread(&f, &f.make_ctx(), req_for(&f, "exact.example", b"e"));
        f.prompter.approve(3);
        exact
            .join()
            .unwrap()
            .expect("exact registration still prompts");
    }

    #[test]
    fn a_denied_wildcard_registration_cools_down_every_unlisted_site() {
        let f = wildcard_fixture(|_| {});
        let first = register_on_thread(&f, &f.make_ctx(), req_for(&f, "a.example", b"a"));
        f.prompter.wait_shown(1);
        f.prompter.decide(deny());
        assert_eq!(
            first.join().unwrap().unwrap_err().code,
            ErrorCode::Forbidden
        );

        // A page or agent that rotates RP IDs gets no fresh prompt.
        for rp in ["b.example", "c.example"] {
            let err = f
                .make_handler()
                .register(&f.make_ctx(), &req_for(&f, rp, rp.as_bytes()))
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::Forbidden);
            assert_eq!(
                deny_reasons(&f).last().unwrap(),
                &(rp.to_string(), "wildcard_registration_cooldown".to_string())
            );
        }
        assert_eq!(f.prompter.shown(), 1);
        assert_eq!(f.storage.lock().unwrap().count_credentials(), 0);
        // Exact-rule registrations are unaffected.
        let exact = register_on_thread(&f, &f.make_ctx(), req_for(&f, "exact.example", b"e"));
        f.prompter.approve(2);
        exact
            .join()
            .unwrap()
            .expect("exact registration still prompts");
    }

    #[test]
    fn localhost_never_registers_through_the_wildcard() {
        let f = wildcard_fixture(|_| {});
        let req = RegisterCredentialRequest {
            rp_id: "localhost".to_string(),
            origin: "http://localhost:8080".to_string(),
            ..f.make_req()
        };
        let err = f.make_handler().register(&f.make_ctx(), &req).unwrap_err();
        assert_eq!(err.code, ErrorCode::Forbidden);
        assert_eq!(
            deny_reasons(&f),
            vec![("localhost".to_string(), "action_not_allowed".to_string())]
        );
        assert_eq!(f.prompter.shown(), 0);
        assert_eq!(f.storage.lock().unwrap().count_credentials(), 0);
    }

    #[test]
    fn every_registration_prompt_says_register_once_with_the_count_exact_rules_too() {
        let f = wildcard_fixture(|_| {});
        human_credential(&f, "exact.example", 3);
        human_credential(&f, "exact.example", 4);
        let ceremony = register_on_thread(&f, &f.make_ctx(), req_for(&f, "exact.example", b"e"));
        f.prompter.wait_shown(1);
        let fields = f.prompter.last_fields();
        assert_eq!(
            fields.rule,
            crate::agent::escalation_prompt::PromptRule::Exact
        );
        assert_eq!(fields.store_count, Some(2));
        let (_, body) = crate::agent::escalation_prompt::render_prompt(&fields).unwrap();
        assert!(body.contains("Site: exact.example (your rule for this site)"));
        assert!(body.contains("which already holds 2 passkeys for this site"));
        f.prompter.decide(PromptEvent::Approved);
        ceremony.join().unwrap().expect("approved");
        let grants = f.store.profile(&f.profile_id).unwrap();
        assert_eq!(
            grants.rules()[0].rule,
            crate::agent::granted_rules::PermittingRule::Exact
        );
    }
}
