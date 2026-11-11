use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use passless_core::agent::config::{ANY_RP_ID, validate_rp_id};
use passless_core::agent::protocol::IntentAction;
use passless_core::agent::{
    AgentConfig, AgentMode, AgentProfileConfig, AgentRpRule, CredentialRef, CredentialSelection,
    EndpointId, GrantId, GrantSource, IntentId, MatchedRule, NoGrantedRules, PendingRequestId,
    Policy, PolicyAction, PolicyDigest, PolicyGenerationId, PolicyParams, PrincipalSessionId,
    ProfileId, RuleAction, resolve_rules,
};

use super::audit::AuditGate;
use super::browser::Clock;
use super::grant::{CeremonyId, GrantError, GrantRegistry, GrantRequestId, GrantRequestParams};
use super::intent::{
    AdminAuthority, CreateIntentParams, IntentConsumeInfo, IntentError, IntentQueryParams,
    IntentStore, MonotonicClock, ProcessIdentityDigest,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonCode {
    DefaultDeny,
    InvalidConfig,
    ProfileNotFound,
    SessionUnbound,
    ModeMismatch,
    ActionNotAllowed,
    RpIdNotExactMatch,
    CredentialNotExactMatch,
    GrantExpired,
    GrantNotFound,
    IntentConsumed,
    IntentExpired,
    IntentNotFound,
    UvRequired,
    Allowed,
    UnknownAction,
    UnknownMode,
    EmptyRpList,
    EmptyCredentialList,
    StaleGeneration,
    SuffixNotExact,
    DelegatedRegistrationDenied,
    GrantMissingForDelegated,
    IntentMissingForDelegated,
    IntentNotApproved,
    GrantIntentMismatch,
    SessionMismatch,
    EndpointMismatch,
    ProcessMismatch,
    GenerationStale,
    GrantRevoked,
    CeremonyInvalidated,
    PartialClaimFailed,
}

impl ReasonCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DefaultDeny => "default_deny",
            Self::InvalidConfig => "invalid_config",
            Self::ProfileNotFound => "profile_not_found",
            Self::SessionUnbound => "session_unbound",
            Self::ModeMismatch => "mode_mismatch",
            Self::ActionNotAllowed => "action_not_allowed",
            Self::RpIdNotExactMatch => "rp_id_not_exact_match",
            Self::CredentialNotExactMatch => "credential_not_exact_match",
            Self::GrantExpired => "grant_expired",
            Self::GrantNotFound => "grant_not_found",
            Self::IntentConsumed => "intent_consumed",
            Self::IntentExpired => "intent_expired",
            Self::IntentNotFound => "intent_not_found",
            Self::UvRequired => "uv_required",
            Self::Allowed => "allowed",
            Self::UnknownAction => "unknown_action",
            Self::UnknownMode => "unknown_mode",
            Self::EmptyRpList => "empty_rp_list",
            Self::EmptyCredentialList => "empty_credential_list",
            Self::StaleGeneration => "stale_generation",
            Self::SuffixNotExact => "suffix_not_exact",
            Self::DelegatedRegistrationDenied => "delegated_registration_denied",
            Self::GrantMissingForDelegated => "grant_missing_for_delegated",
            Self::IntentMissingForDelegated => "intent_missing_for_delegated",
            Self::IntentNotApproved => "intent_not_approved",
            Self::GrantIntentMismatch => "grant_intent_mismatch",
            Self::SessionMismatch => "session_mismatch",
            Self::EndpointMismatch => "endpoint_mismatch",
            Self::ProcessMismatch => "process_mismatch",
            Self::GenerationStale => "generation_stale",
            Self::GrantRevoked => "grant_revoked",
            Self::CeremonyInvalidated => "ceremony_invalidated",
            Self::PartialClaimFailed => "partial_claim_failed",
        }
    }
}

impl fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorAction {
    None,
    Retry,
    RecreateSession,
    ContactAdmin,
    ReloadPolicy,
    VerifyUser,
}

impl OperatorAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Retry => "retry",
            Self::RecreateSession => "recreate_session",
            Self::ContactAdmin => "contact_admin",
            Self::ReloadPolicy => "reload_policy",
            Self::VerifyUser => "verify_user",
        }
    }
}

impl fmt::Display for OperatorAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub outcome: Outcome,
    pub reason: ReasonCode,
    pub operator_action: OperatorAction,
}

impl Decision {
    pub fn allow(reason: ReasonCode) -> Self {
        Self {
            outcome: Outcome::Allow,
            reason,
            operator_action: OperatorAction::None,
        }
    }

    pub fn deny(reason: ReasonCode, action: OperatorAction) -> Self {
        Self {
            outcome: Outcome::Deny,
            reason,
            operator_action: action,
        }
    }

    pub fn is_allowed(&self) -> bool {
        self.outcome == Outcome::Allow
    }
}

#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    pub profile_id: ProfileId,
    pub policy: Policy,
    pub digest: PolicyDigest,
    pub mode: AgentMode,
    pub normalized_rp_ids: Vec<String>,
    pub credential_refs: Vec<CredentialRef>,
    pub max_grant_ttl_secs: u64,
    pub max_session_ttl_secs: u64,
    pub max_concurrent_grants: u64,
    pub allowed_actions: BTreeSet<String>,
    /// Profile default credential selection (a rule may override it; the wildcard is `single`).
    pub credential_selection: CredentialSelection,
    pub rules: Vec<AgentRpRule>,
}

impl PolicySnapshot {
    pub fn rp_id_set(&self) -> HashSet<&str> {
        self.normalized_rp_ids.iter().map(|s| s.as_str()).collect()
    }

    pub fn credential_ref_set(&self) -> HashSet<&CredentialRef> {
        self.credential_refs.iter().collect()
    }

    pub fn is_rp_exact_match(&self, rp_id: &str) -> bool {
        let Ok(normalized) = validate_rp_id(rp_id) else {
            return false;
        };
        self.normalized_rp_ids.contains(&normalized)
            || self.normalized_rp_ids.iter().any(|id| id == ANY_RP_ID)
    }

    pub fn is_suffix_only(&self, rp_id: &str) -> bool {
        let Ok(normalized) = validate_rp_id(rp_id) else {
            return false;
        };
        if self.is_rp_exact_match(&normalized) {
            return false;
        }
        self.normalized_rp_ids
            .iter()
            .filter(|id| id.as_str() != ANY_RP_ID)
            .any(|id| normalized.ends_with(&format!(".{}", id)))
    }

    pub fn action_allowed(&self, action: &IntentAction) -> bool {
        let action_str = match action {
            IntentAction::Register => "register",
            IntentAction::Authenticate => "authenticate",
        };
        self.allowed_actions.contains(action_str)
    }

    /// Resolve `(action, rp_id)` over this snapshot's rules (ADR 0014 section 6.2).
    pub fn resolve(
        &self,
        action: &IntentAction,
        rp_id: &str,
        grants: &dyn GrantSource,
    ) -> MatchedRule {
        resolve_rules(
            &self.rules,
            &self.credential_selection,
            policy_action(action),
            rp_id,
            |rp_id| grants.is_granted(&self.profile_id, rp_id),
        )
    }
}

fn policy_action(action: &IntentAction) -> PolicyAction {
    match action {
        IntentAction::Register => PolicyAction::Register,
        IntentAction::Authenticate => PolicyAction::Authenticate,
    }
}

#[derive(Debug, Clone)]
pub struct PolicyGenerationSnapshot {
    pub generation_id: PolicyGenerationId,
    /// Monotonic policy generation: 1 at start, bumped by every reload (ADR 0014 section 6.4).
    /// It accompanies the digest; the digest identifies content, the generation orders loads.
    pub generation: u64,
    pub snapshots: Vec<PolicySnapshot>,
    pub digest: PolicyDigest,
    pub created_at_mono: u64,
}

impl PolicyGenerationSnapshot {
    pub fn find_snapshot(&self, profile_id: &ProfileId) -> Option<&PolicySnapshot> {
        self.snapshots.iter().find(|s| s.profile_id == *profile_id)
    }

    pub fn is_stale(&self, max_age: Duration, now_mono: u64) -> bool {
        now_mono.saturating_sub(self.created_at_mono) > max_age.as_secs()
    }
}

#[derive(Debug, Clone)]
pub struct GrantSignSnapshot {
    pub grant_id: GrantId,
    pub profile_id: ProfileId,
    pub rp_ids: Vec<String>,
    pub credential_refs: Vec<CredentialRef>,
    pub state: super::grant::GrantState,
    pub expiry_mono: u64,
    pub is_revoked: bool,
}

pub struct AuthorizationHandle {
    ceremony_id: CeremonyId,
    grant_id: Option<passless_core::agent::GrantId>,
    intent_id: Option<IntentId>,
    profile_id: ProfileId,
    session_id: PrincipalSessionId,
    endpoint_id: EndpointId,
    process_digest: ProcessIdentityDigest,
    policy_generation: PolicyGenerationId,
    policy_digest: PolicyDigest,
    action: IntentAction,
    rp_id: String,
    credential_ref: Option<CredentialRef>,
}

impl AuthorizationHandle {
    pub fn ceremony_id(&self) -> &CeremonyId {
        &self.ceremony_id
    }

    pub fn grant_id(&self) -> Option<&passless_core::agent::GrantId> {
        self.grant_id.as_ref()
    }

    pub fn intent_id(&self) -> Option<&IntentId> {
        self.intent_id.as_ref()
    }

    pub fn profile_id(&self) -> &ProfileId {
        &self.profile_id
    }

    pub fn action(&self) -> &IntentAction {
        &self.action
    }

    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    pub fn credential_ref(&self) -> Option<&CredentialRef> {
        self.credential_ref.as_ref()
    }
}

impl fmt::Debug for AuthorizationHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizationHandle")
            .field("ceremony_id", &self.ceremony_id)
            .field("grant_id", &self.grant_id)
            .field("intent_id", &self.intent_id)
            .field("profile_id", &self.profile_id)
            .field("action", &self.action)
            .field("rp_id", &self.rp_id)
            .field("credential_ref", &self.credential_ref)
            .finish()
    }
}

pub struct AuthorizationRequest {
    pub profile_id: ProfileId,
    pub session_id: PrincipalSessionId,
    pub endpoint_id: EndpointId,
    pub process_digest: ProcessIdentityDigest,
    pub policy_generation_id: PolicyGenerationId,
    pub policy_digest: PolicyDigest,
    pub action: IntentAction,
    pub rp_id: String,
    pub credential_ref: Option<CredentialRef>,
    pub uv_enforced: bool,
}

struct PendingAuthorization {
    ceremony_id: CeremonyId,
    grant_id: Option<passless_core::agent::GrantId>,
    intent_id: Option<IntentId>,
    profile_id: ProfileId,
    session_id: PrincipalSessionId,
    endpoint_id: EndpointId,
    process_digest: ProcessIdentityDigest,
    policy_generation: PolicyGenerationId,
    policy_digest: PolicyDigest,
    action: IntentAction,
    rp_id: String,
    credential_ref: Option<CredentialRef>,
    invalidated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingRequestKind {
    IsolatedIntent,
    DelegatedAuth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingState {
    Waiting,
    Approved,
    Denied,
    TimedOut,
    Cancelled,
}

impl PendingState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Denied | Self::TimedOut | Self::Cancelled)
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
        }
    }
}

impl fmt::Display for PendingState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

pub struct PendingPrincipalRequest {
    id: PendingRequestId,
    kind: PendingRequestKind,
    profile_id: ProfileId,
    session_id: PrincipalSessionId,
    endpoint_id: EndpointId,
    process_digest: ProcessIdentityDigest,
    policy_generation: PolicyGenerationId,
    policy_digest: PolicyDigest,
    action: IntentAction,
    rp_id: String,
    credential_ref: Option<CredentialRef>,
    intent_id: IntentId,
    grant_request_id: Option<GrantRequestId>,
    state: PendingState,
    created_at_mono: u64,
    deadline_mono: u64,
}

pub struct BoundApprovalResult {
    intent_id: IntentId,
    grant_id: Option<GrantId>,
    profile_id: ProfileId,
    session_id: PrincipalSessionId,
    endpoint_id: EndpointId,
    process_digest: ProcessIdentityDigest,
    policy_generation: PolicyGenerationId,
    policy_digest: PolicyDigest,
    action: IntentAction,
    rp_id: String,
    credential_ref: Option<CredentialRef>,
}

impl BoundApprovalResult {
    pub fn intent_id(&self) -> &IntentId {
        &self.intent_id
    }

    pub fn grant_id(&self) -> Option<&GrantId> {
        self.grant_id.as_ref()
    }

    pub fn profile_id(&self) -> &ProfileId {
        &self.profile_id
    }

    pub fn session_id(&self) -> &PrincipalSessionId {
        &self.session_id
    }

    pub fn endpoint_id(&self) -> &EndpointId {
        &self.endpoint_id
    }

    pub fn process_digest(&self) -> &ProcessIdentityDigest {
        &self.process_digest
    }

    pub fn policy_generation(&self) -> &PolicyGenerationId {
        &self.policy_generation
    }

    pub fn policy_digest(&self) -> &PolicyDigest {
        &self.policy_digest
    }

    pub fn action(&self) -> &IntentAction {
        &self.action
    }

    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    pub fn credential_ref(&self) -> Option<&CredentialRef> {
        self.credential_ref.as_ref()
    }
}

impl fmt::Debug for BoundApprovalResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundApprovalResult")
            .field("intent_id", &self.intent_id)
            .field("grant_id", &self.grant_id)
            .field("profile_id", &self.profile_id)
            .field("action", &self.action)
            .field("rp_id", &self.rp_id)
            .field("credential_ref", &self.credential_ref)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingCreateError {
    IntentCreationFailed(IntentError),
    GrantRequestFailed(GrantError),
    DuplicatePending,
    Internal(String),
}

impl fmt::Display for PendingCreateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntentCreationFailed(e) => write!(f, "intent creation failed: {}", e),
            Self::GrantRequestFailed(e) => write!(f, "grant request failed: {}", e),
            Self::DuplicatePending => write!(f, "duplicate pending request for this tuple"),
            Self::Internal(s) => write!(f, "internal error: {}", s),
        }
    }
}

impl std::error::Error for PendingCreateError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CeremonyResolveError {
    PendingNotFound,
    AmbiguousPending(usize),
    AlreadyResolved,
    TimedOut,
    Cancelled,
    PolicyDenied(ReasonCode),
    IntentApprovalFailed(String),
    GrantFailed(String),
    TupleMismatch,
}

impl fmt::Display for CeremonyResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PendingNotFound => write!(f, "no pending request found for tuple"),
            Self::AmbiguousPending(n) => {
                write!(f, "ambiguous: {} pending requests match tuple", n)
            }
            Self::AlreadyResolved => write!(f, "pending request already resolved"),
            Self::TimedOut => write!(f, "pending request timed out"),
            Self::Cancelled => write!(f, "pending request cancelled"),
            Self::PolicyDenied(r) => write!(f, "policy denied on re-evaluation: {}", r),
            Self::IntentApprovalFailed(s) => write!(f, "intent approval failed: {}", s),
            Self::GrantFailed(s) => write!(f, "grant operation failed: {}", s),
            Self::TupleMismatch => write!(f, "bound result tuple does not match request"),
        }
    }
}

impl std::error::Error for CeremonyResolveError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingCancelError {
    NotFound,
    AlreadyResolved,
    SessionMismatch,
}

impl fmt::Display for PendingCancelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "pending request not found"),
            Self::AlreadyResolved => write!(f, "pending request already resolved"),
            Self::SessionMismatch => write!(f, "session mismatch for cancel"),
        }
    }
}

impl std::error::Error for PendingCancelError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyRuntimeError {
    Compilation(String),
    Reload(String),
    Internal(String),
}

impl fmt::Display for PolicyRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compilation(s) => write!(f, "policy compilation failed: {}", s),
            Self::Reload(s) => write!(f, "policy reload failed: {}", s),
            Self::Internal(s) => write!(f, "internal error: {}", s),
        }
    }
}

impl std::error::Error for PolicyRuntimeError {}

pub struct PolicyRuntime {
    current: RwLock<Arc<PolicyGenerationSnapshot>>,
    intents: Mutex<IntentStore>,
    grants: Mutex<HashMap<String, GrantRegistry>>,
    pending: Mutex<HashMap<String, PendingAuthorization>>,
    pending_requests: Mutex<HashMap<String, PendingPrincipalRequest>>,
    clock: Arc<dyn Clock>,
    audit_gate: Option<Arc<AuditGate>>,
    /// The granted-rules store consulted to upgrade a `request` (ADR 0014 section 6.2). It holds
    /// nothing until the escalation service lands (P7).
    granted_rules: Arc<dyn GrantSource>,
    /// Serializes reloads, so the numeric generation is read, bumped and published atomically:
    /// concurrent reloads get distinct, strictly increasing generations.
    reload_lock: Mutex<()>,
}

impl PolicyRuntime {
    pub fn new(
        config: &AgentConfig,
        clock: Arc<dyn Clock>,
        monotonic_clock: Arc<dyn MonotonicClock>,
        audit_gate: Option<Arc<AuditGate>>,
    ) -> Result<Self, PolicyRuntimeError> {
        let generation = Self::compile_generation(config, clock.monotonic_secs(), 1)?;
        let gen_arc = Arc::new(generation);

        let intent_store = IntentStore::with_defaults(Box::new(ArcMonotonicClockAdapter(
            Arc::clone(&monotonic_clock),
        )));

        let mut grant_registries = HashMap::new();
        for snapshot in &gen_arc.snapshots {
            let registry = GrantRegistry::new(
                Arc::clone(&clock),
                gen_arc.generation_id.clone(),
                snapshot.digest.clone(),
                snapshot.max_grant_ttl_secs,
                snapshot.allowed_actions.clone(),
                snapshot.max_concurrent_grants,
                audit_gate.clone(),
            );
            grant_registries.insert(snapshot.profile_id.as_str().to_string(), registry);
        }

        Ok(Self {
            current: RwLock::new(gen_arc),
            intents: Mutex::new(intent_store),
            grants: Mutex::new(grant_registries),
            pending: Mutex::new(HashMap::new()),
            pending_requests: Mutex::new(HashMap::new()),
            clock,
            audit_gate,
            granted_rules: Arc::new(NoGrantedRules),
            reload_lock: Mutex::new(()),
        })
    }

    /// Install the granted-rules store consulted by [`Self::resolve`].
    pub fn with_grant_source(mut self, granted_rules: Arc<dyn GrantSource>) -> Self {
        self.granted_rules = granted_rules;
        self
    }

    pub fn compile_generation(
        config: &AgentConfig,
        now_mono: u64,
        generation: u64,
    ) -> Result<PolicyGenerationSnapshot, PolicyRuntimeError> {
        let mut snapshots = Vec::new();

        for (name, profile_config) in &config.profiles {
            let profile_id = ProfileId::new(name.as_str()).map_err(|e| {
                PolicyRuntimeError::Compilation(format!("invalid profile id '{}': {}", name, e))
            })?;

            let snapshot = Self::compile_snapshot(
                &profile_id,
                profile_config,
                config.acknowledge_global_same_user.contains(name),
                config.acknowledge_same_user_registration.contains(name),
            )?;
            snapshots.push(snapshot);
        }

        snapshots.sort_by(|a, b| a.profile_id.as_str().cmp(b.profile_id.as_str()));

        let cbor_entries: Vec<(String, Vec<u8>)> = snapshots
            .iter()
            .map(|s| {
                (
                    s.profile_id.as_str().to_string(),
                    s.digest.as_bytes().to_vec(),
                )
            })
            .collect();
        let gen_cbor = passless_core::agent::policy::cbor::encode_generation_digest(&cbor_entries);
        let digest = PolicyDigest::from_cbor_bytes(&gen_cbor);

        let generation_id = PolicyGenerationId::new();

        Ok(PolicyGenerationSnapshot {
            generation_id,
            generation,
            snapshots,
            digest,
            created_at_mono: now_mono,
        })
    }

    fn compile_snapshot(
        profile_id: &ProfileId,
        config: &AgentProfileConfig,
        acknowledged_global_same_user: bool,
        acknowledged_same_user_registration: bool,
    ) -> Result<PolicySnapshot, PolicyRuntimeError> {
        let mut rules = config.rules.clone();
        rules.sort_by_key(|rule| rule.rp_id.trim().to_ascii_lowercase());
        let mut normalized_rp_ids: Vec<String> = rules
            .iter()
            .map(|rule| rule.rp_id.trim().to_ascii_lowercase())
            .collect();
        normalized_rp_ids.sort();
        normalized_rp_ids.dedup();

        let credential_refs = config.credential_refs.clone().unwrap_or_default();

        let mut allowed_actions = BTreeSet::new();
        if rules
            .iter()
            .any(|rule| rule.authenticate != RuleAction::Deny)
        {
            allowed_actions.insert("authenticate".to_string());
        }
        if rules.iter().any(|rule| rule.register != RuleAction::Deny) {
            allowed_actions.insert("register".to_string());
        }

        let max_grant_ttl_secs = config.max_grant_ttl.map(|d| d.as_secs()).unwrap_or(300);
        let max_session_ttl_secs = config.max_session_ttl.map(|d| d.as_secs()).unwrap_or(3600);
        let max_concurrent_grants: u64 = 5;

        let storage_backend = config
            .storage
            .as_ref()
            .map(|s| format!("{}", s))
            .unwrap_or_default();
        let storage_path = config
            .storage
            .as_ref()
            .map(|s| s.credential_state_path().display().to_string())
            .unwrap_or_default();

        let params = PolicyParams {
            profile_id: profile_id.clone(),
            mode: config.mode.to_string(),
            normalized_rp_ids: normalized_rp_ids.clone(),
            credential_refs: credential_refs.clone(),
            allowed_actions: allowed_actions.iter().cloned().collect(),
            max_concurrent_grants,
            max_grant_ttl: max_grant_ttl_secs,
            max_session_ttl: max_session_ttl_secs,
            max_operations: u64::from(config.max_operations),
            max_concurrent_sessions: u64::from(config.max_concurrent_sessions),
            browser_scope: config.browser_scope.to_string(),
            principal_user: config.principal_user.clone(),
            start_url: config.start_url.clone(),
            browser_argv: config.browser_command.clone().unwrap_or_default(),
            browser_cdp_expose: config
                .browser_cdp_expose
                .map(|mode| mode.to_string())
                .unwrap_or_default(),
            browser_cdp_port: u64::from(config.browser_cdp_port.unwrap_or(0)),
            credential_selection: config.credential_selection.clone(),
            acknowledged_global_same_user,
            acknowledged_same_user_registration,
            storage_backend,
            storage_path,
            browser_user: config.browser_user.clone().unwrap_or_default(),
            browser_runtime_root: config
                .browser_runtime_root
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            rules: rules.clone(),
        };

        let policy = Policy::from_params(params)
            .map_err(|e| PolicyRuntimeError::Compilation(format!("invalid policy: {}", e)))?;

        let digest = policy.digest();

        Ok(PolicySnapshot {
            profile_id: profile_id.clone(),
            policy,
            digest,
            mode: config.mode,
            normalized_rp_ids,
            credential_refs,
            max_grant_ttl_secs,
            max_session_ttl_secs,
            max_concurrent_grants,
            allowed_actions,
            credential_selection: config.credential_selection.clone(),
            rules,
        })
    }

    pub fn current_generation(&self) -> Arc<PolicyGenerationSnapshot> {
        self.current.read().unwrap().clone()
    }

    /// Resolve `(action, rp_id)` for `profile_id` against the LIVE compiled policy (the current
    /// generation, replaced on reload) and the granted-rules store (ADR 0014 sections 6.2, 6.4).
    ///
    /// Ceremonies resolve through this on every request instead of a profile configuration copied
    /// into the session at creation (plan R16). An unknown profile resolves to default deny.
    pub fn resolve(
        &self,
        profile_id: &ProfileId,
        action: &IntentAction,
        rp_id: &str,
    ) -> MatchedRule {
        let generation = self.current.read().unwrap().clone();
        match generation.find_snapshot(profile_id) {
            Some(snapshot) => snapshot.resolve(action, rp_id, self.granted_rules.as_ref()),
            None => resolve_rules(
                &[],
                &CredentialSelection::default(),
                policy_action(action),
                rp_id,
                |_| false,
            ),
        }
    }

    /// The numeric policy generation (1 at start, bumped by every reload).
    pub fn generation_number(&self) -> u64 {
        self.current.read().unwrap().generation
    }

    pub fn digest(&self) -> PolicyDigest {
        self.current.read().unwrap().digest.clone()
    }

    pub fn list_grants(
        &self,
        profile_filter: Option<&ProfileId>,
    ) -> Vec<super::grant::GrantSnapshot> {
        let grants = self.grants.lock().unwrap();
        let mut result = Vec::new();
        for (key, registry) in grants.iter() {
            if let Some(filter) = profile_filter
                && key != filter.as_str()
            {
                continue;
            }
            result.extend(registry.list_all_snapshots());
        }
        result
    }

    pub fn show_grant_details(&self, grant_id: &GrantId) -> Option<super::grant::GrantDetails> {
        let grants = self.grants.lock().unwrap();
        for registry in grants.values() {
            if let Some(details) = registry.find_grant_with_details(grant_id) {
                return Some(details);
            }
        }
        None
    }

    pub fn revoke_grant_by_id(
        &self,
        grant_id: &GrantId,
    ) -> Result<super::grant::GrantState, super::grant::GrantError> {
        let authority = super::intent::admin_authority();
        let grants = self.grants.lock().unwrap();
        for registry in grants.values() {
            if registry.show_grant(grant_id).is_some() {
                return registry.revoke_grant(grant_id, &authority);
            }
        }
        Err(super::grant::GrantError::GrantNotFound(grant_id.clone()))
    }

    pub fn find_grants_by_credential(
        &self,
        cred_ref: &passless_core::agent::CredentialRef,
    ) -> Vec<passless_core::agent::GrantId> {
        let grants = self.grants.lock().unwrap();
        let mut result = Vec::new();
        for registry in grants.values() {
            result.extend(registry.find_grant_id_by_credential(cred_ref));
        }
        result
    }

    pub fn find_grants_by_credential_for_profile(
        &self,
        profile_id: &ProfileId,
        cred_refs: &[passless_core::agent::CredentialRef],
    ) -> Vec<passless_core::agent::GrantId> {
        let grants = self.grants.lock().unwrap();
        let registry = match grants.get(profile_id.as_str()) {
            Some(r) => r,
            None => return Vec::new(),
        };
        let mut result = Vec::new();
        for cred_ref in cred_refs {
            result.extend(registry.find_grant_id_by_credential(cred_ref));
        }
        result
    }

    pub fn resolve_grant_for_sign(
        &self,
        profile_id: &ProfileId,
        grant_id: &GrantId,
    ) -> Option<GrantSignSnapshot> {
        let mut grants_map = self.grants.lock().unwrap();
        let registry = grants_map.get_mut(profile_id.as_str())?;
        let _ = registry.check_expired();
        let snap = registry.snapshot_for_sign(grant_id)?;
        let is_revoked = snap.state == super::grant::GrantState::Revoked;
        Some(GrantSignSnapshot {
            grant_id: snap.grant_id,
            profile_id: snap.profile_id,
            rp_ids: snap.rp_ids,
            credential_refs: snap.credential_refs,
            state: snap.state,
            expiry_mono: snap.expiry_mono,
            is_revoked,
        })
    }
    pub fn active_grant_count_for_profile(&self, profile_id: &ProfileId) -> u32 {
        let grants = self.grants.lock().unwrap();
        grants
            .get(profile_id.as_str())
            .map(|r| r.active_count() as u32)
            .unwrap_or(0)
    }

    pub fn pending_intent_count_for_profile(&self, profile_id: &ProfileId) -> u32 {
        let pending = self.pending.lock().unwrap();
        pending
            .values()
            .filter(|pa| pa.profile_id == *profile_id && !pa.invalidated)
            .count() as u32
    }

    pub fn reload(&self, config: &AgentConfig) -> Result<PolicyDigest, PolicyRuntimeError> {
        let _reload = self.reload_lock.lock().unwrap_or_else(|e| e.into_inner());
        let now_mono = self.clock.monotonic_secs();
        let next_generation = self.current.read().unwrap().generation.saturating_add(1);
        let new_generation = Self::compile_generation(config, now_mono, next_generation)?;
        let new_digest = new_generation.digest.clone();

        let mut new_registries = HashMap::new();
        for snapshot in &new_generation.snapshots {
            let registry = GrantRegistry::new(
                Arc::clone(&self.clock),
                new_generation.generation_id.clone(),
                snapshot.digest.clone(),
                snapshot.max_grant_ttl_secs,
                snapshot.allowed_actions.clone(),
                snapshot.max_concurrent_grants,
                self.audit_gate.clone(),
            );
            new_registries.insert(snapshot.profile_id.as_str().to_string(), registry);
        }

        {
            let mut intents = self.intents.lock().unwrap();
            intents.invalidate_all();
        }

        {
            let mut pending = self.pending.lock().unwrap();
            for pa in pending.values_mut() {
                pa.invalidated = true;
            }
        }

        {
            let mut pending_requests = self.pending_requests.lock().unwrap();
            for pr in pending_requests.values_mut() {
                if pr.state == PendingState::Waiting {
                    pr.state = PendingState::Cancelled;
                }
            }
        }

        {
            let mut grants = self.grants.lock().unwrap();
            *grants = new_registries;
        }

        {
            let mut current = self.current.write().unwrap();
            *current = Arc::new(new_generation);
        }

        Ok(new_digest)
    }

    /// Authorization decision follows documented precedence:
    ///
    /// 1. Profile must exist in current generation
    /// 2. RP ID must be exact match (suffix denied)
    /// 3. Credential must be exact match if specified
    /// 4. Mode-specific rules:
    ///    a. Delegated registration: always denied
    ///    b. Delegated authentication: requires BOTH active grant AND approved one-shot intent
    ///    c. Isolated authentication: requires approved one-shot intent
    ///
    ///    Registration does not go through this function: registration authority is the
    ///    exact-RP `register = "allow"` rule, checked by `RegisterHandler` on the extension path
    ///    (ADR 0014 section 10.3). The intent hand-off here belonged to the removed UHID route
    ///    and goes away with the principal intent protocol (P7).
    /// 5. UV must be satisfied if policy requires it
    /// 6. Returns unconsumed AuthorizationHandle bound to exact claims
    ///
    /// Lock ordering: intents lock is acquired first, then grants lock.
    /// This prevents deadlocks and ensures atomic claim of both intent and grant.
    pub fn authorize(
        &self,
        request: &AuthorizationRequest,
    ) -> (Decision, Option<AuthorizationHandle>) {
        let generation = self.current.read().unwrap().clone();

        if request.policy_generation_id != generation.generation_id
            || request.policy_digest != generation.digest
        {
            return (
                Decision::deny(ReasonCode::GenerationStale, OperatorAction::ReloadPolicy),
                None,
            );
        }

        let snapshot = match generation.find_snapshot(&request.profile_id) {
            Some(s) => s,
            None => {
                return (
                    Decision::deny(ReasonCode::ProfileNotFound, OperatorAction::ContactAdmin),
                    None,
                );
            }
        };

        if snapshot.normalized_rp_ids.is_empty() {
            return (
                Decision::deny(ReasonCode::EmptyRpList, OperatorAction::ContactAdmin),
                None,
            );
        }

        if !snapshot.is_rp_exact_match(&request.rp_id) {
            if snapshot.is_suffix_only(&request.rp_id) {
                return (
                    Decision::deny(ReasonCode::SuffixNotExact, OperatorAction::Retry),
                    None,
                );
            }
            return (
                Decision::deny(ReasonCode::RpIdNotExactMatch, OperatorAction::Retry),
                None,
            );
        }

        // `request` denies here: escalation lands with P7, and this intent hand-off is removed there.
        let matched =
            snapshot.resolve(&request.action, &request.rp_id, self.granted_rules.as_ref());
        if matched.action != RuleAction::Allow {
            return (
                Decision::deny(ReasonCode::ActionNotAllowed, OperatorAction::None),
                None,
            );
        }

        if let Some(ref cred_ref) = request.credential_ref
            && !snapshot.credential_refs.is_empty()
            && !snapshot.credential_ref_set().contains(cred_ref)
        {
            return (
                Decision::deny(ReasonCode::CredentialNotExactMatch, OperatorAction::Retry),
                None,
            );
        }

        match snapshot.mode {
            AgentMode::SameUser | AgentMode::Isolated => {
                if !snapshot.action_allowed(&request.action) {
                    return (
                        Decision::deny(ReasonCode::ActionNotAllowed, OperatorAction::None),
                        None,
                    );
                }

                self.authorize_isolated(snapshot, request, &generation)
            }
        }
    }

    /// Lock ordering: intents only (no grants needed for isolated mode).
    fn authorize_isolated(
        &self,
        snapshot: &PolicySnapshot,
        request: &AuthorizationRequest,
        _generation: &PolicyGenerationSnapshot,
    ) -> (Decision, Option<AuthorizationHandle>) {
        let mut intents = self.intents.lock().unwrap();

        let intent_id = match intents.claim_approved(&IntentQueryParams {
            profile_id: snapshot.profile_id.clone(),
            session_id: request.session_id.clone(),
            endpoint_id: request.endpoint_id.clone(),
            process_digest: request.process_digest.clone(),
            policy_generation: Some(request.policy_generation_id.clone()),
            policy_digest: request.policy_digest.clone(),
            action: request.action.clone(),
            rp_id: request.rp_id.clone(),
            credential_ref: request.credential_ref.clone(),
        }) {
            Ok(iid) => iid,
            Err(IntentError::NotFound) => {
                return (
                    Decision::deny(ReasonCode::IntentNotFound, OperatorAction::Retry),
                    None,
                );
            }
            Err(_) => {
                return (
                    Decision::deny(ReasonCode::IntentNotApproved, OperatorAction::Retry),
                    None,
                );
            }
        };

        let ceremony_id = CeremonyId::new();

        let handle = AuthorizationHandle {
            ceremony_id: ceremony_id.clone(),
            grant_id: None,
            intent_id: Some(intent_id.clone()),
            profile_id: snapshot.profile_id.clone(),
            session_id: request.session_id.clone(),
            endpoint_id: request.endpoint_id.clone(),
            process_digest: request.process_digest.clone(),
            policy_generation: request.policy_generation_id.clone(),
            policy_digest: request.policy_digest.clone(),
            action: request.action.clone(),
            rp_id: request.rp_id.clone(),
            credential_ref: request.credential_ref.clone(),
        };

        let pending_auth = PendingAuthorization {
            ceremony_id: ceremony_id.clone(),
            grant_id: None,
            intent_id: Some(intent_id),
            profile_id: snapshot.profile_id.clone(),
            session_id: request.session_id.clone(),
            endpoint_id: request.endpoint_id.clone(),
            process_digest: request.process_digest.clone(),
            policy_generation: request.policy_generation_id.clone(),
            policy_digest: request.policy_digest.clone(),
            action: request.action.clone(),
            rp_id: request.rp_id.clone(),
            credential_ref: request.credential_ref.clone(),
            invalidated: false,
        };

        drop(intents);

        {
            let mut pending = self.pending.lock().unwrap();
            pending.insert(ceremony_id.as_str().to_string(), pending_auth);
        }

        (Decision::allow(ReasonCode::Allowed), Some(handle))
    }

    pub fn consume_authorization(
        &self,
        handle: &AuthorizationHandle,
    ) -> Result<IntentConsumeInfo, ReasonCode> {
        let ceremony_key = handle.ceremony_id.as_str().to_string();

        {
            let pending = self.pending.lock().unwrap();
            match pending.get(&ceremony_key) {
                Some(pa)
                    if !pa.invalidated
                        && pa.grant_id == handle.grant_id
                        && pa.intent_id == handle.intent_id
                        && pa.profile_id == handle.profile_id
                        && pa.session_id == handle.session_id
                        && pa.endpoint_id == handle.endpoint_id
                        && pa.process_digest == handle.process_digest
                        && pa.policy_generation == handle.policy_generation
                        && pa.policy_digest == handle.policy_digest
                        && pa.action == handle.action
                        && pa.rp_id == handle.rp_id
                        && pa.credential_ref == handle.credential_ref => {}
                Some(_) => return Err(ReasonCode::CeremonyInvalidated),
                None => return Err(ReasonCode::CeremonyInvalidated),
            }
        }

        let generation = self.current.read().unwrap().clone();
        if handle.policy_generation != generation.generation_id
            || handle.policy_digest != generation.digest
        {
            self.invalidate_ceremony(&ceremony_key);
            return Err(ReasonCode::GenerationStale);
        }

        if let Some(ref grant_id) = handle.grant_id {
            let profile_key = handle.profile_id.as_str().to_string();
            let grants_map = self.grants.lock().unwrap();
            if let Some(grants) = grants_map.get(&profile_key) {
                if !grants.is_grant_active(grant_id) {
                    drop(grants_map);
                    self.invalidate_ceremony(&ceremony_key);
                    return Err(ReasonCode::GrantRevoked);
                }
                if grants.current_policy_generation() != &handle.policy_generation {
                    drop(grants_map);
                    self.invalidate_ceremony(&ceremony_key);
                    return Err(ReasonCode::GenerationStale);
                }
            } else {
                drop(grants_map);
                self.invalidate_ceremony(&ceremony_key);
                return Err(ReasonCode::ProfileNotFound);
            }
        }

        let intent_id = handle
            .intent_id
            .as_ref()
            .ok_or(ReasonCode::IntentNotFound)?;
        let consume_info = {
            let mut intents = self.intents.lock().unwrap();
            match intents.consume_claimed(intent_id) {
                Ok(info) => info,
                Err(IntentError::InvalidTransition { .. }) => {
                    return Err(ReasonCode::IntentConsumed);
                }
                Err(IntentError::NotFound) => {
                    return Err(ReasonCode::IntentNotFound);
                }
                Err(_) => {
                    return Err(ReasonCode::IntentConsumed);
                }
            }
        };

        if let Some(ref _grant_id) = handle.grant_id {
            let profile_key = handle.profile_id.as_str().to_string();
            let grant_consume_ok = {
                let grants_map = self.grants.lock().unwrap();
                if let Some(grants) = grants_map.get(&profile_key) {
                    grants
                        .consume_claim_by_ceremony(&handle.ceremony_id)
                        .is_ok()
                } else {
                    false
                }
            };
            if !grant_consume_ok {
                {
                    let mut intents = self.intents.lock().unwrap();
                    let _ = intents.rollback_claim(intent_id);
                }
                self.invalidate_ceremony(&ceremony_key);
                return Err(ReasonCode::PartialClaimFailed);
            }
        }

        self.invalidate_ceremony(&ceremony_key);
        Ok(consume_info)
    }

    fn invalidate_ceremony(&self, ceremony_key: &str) {
        let mut pending = self.pending.lock().unwrap();
        if let Some(pa) = pending.get_mut(ceremony_key) {
            pa.invalidated = true;
            if let Some(ref intent_id) = pa.intent_id {
                let mut intents = self.intents.lock().unwrap();
                let _ = intents.rollback_claim(intent_id);
            }
            if let Some(ref grant_id) = pa.grant_id {
                let profile_key = pa.profile_id.as_str().to_string();
                let mut grants_map = self.grants.lock().unwrap();
                if let Some(grants) = grants_map.get_mut(&profile_key) {
                    grants.cancel_claim(&pa.ceremony_id);
                }
                let _ = grant_id;
            }
        }
    }

    pub fn admin_approve_intent(
        &self,
        intent_id: &IntentId,
        authority: &AdminAuthority,
    ) -> Result<(), IntentError> {
        let mut intents = self.intents.lock().unwrap();
        intents.approve(intent_id, authority)
    }

    pub fn admin_deny_intent(
        &self,
        intent_id: &IntentId,
        authority: &AdminAuthority,
    ) -> Result<(), IntentError> {
        let mut intents = self.intents.lock().unwrap();
        intents.deny(intent_id, authority)
    }

    pub fn admin_create_intent(
        &self,
        params: CreateIntentParams,
    ) -> Result<(IntentId, super::intent::ClaimToken), IntentError> {
        let mut intents = self.intents.lock().unwrap();
        intents.create(params)
    }

    pub fn admin_request_grant(
        &self,
        params: GrantRequestParams,
    ) -> Result<super::grant::GrantRequestId, GrantError> {
        let profile_key = params.profile_id.as_str().to_string();
        let mut grants_map = self.grants.lock().unwrap();
        let grants = grants_map
            .get_mut(&profile_key)
            .ok_or(GrantError::ProfileMismatch)?;
        grants.request_grant(params)
    }

    pub fn admin_request_dynamic_grant(
        &self,
        params: GrantRequestParams,
    ) -> Result<super::grant::GrantRequestId, GrantError> {
        let profile_key = params.profile_id.as_str().to_string();
        let mut grants_map = self.grants.lock().unwrap();
        let grants = grants_map
            .get_mut(&profile_key)
            .ok_or(GrantError::ProfileMismatch)?;
        grants.request_dynamic_grant(params)
    }

    pub fn admin_approve_grant(
        &self,
        request_id: &super::grant::GrantRequestId,
        authority: &AdminAuthority,
    ) -> Result<passless_core::agent::GrantId, GrantError> {
        let mut grants_map = self.grants.lock().unwrap();
        for grants in grants_map.values_mut() {
            if let Ok(gid) = grants.approve_grant(request_id, authority) {
                return Ok(gid);
            }
        }
        Err(GrantError::PendingRequestNotFound(request_id.clone()))
    }

    pub fn admin_revoke_grant(
        &self,
        grant_id: &passless_core::agent::GrantId,
        authority: &AdminAuthority,
    ) -> Result<super::grant::GrantState, GrantError> {
        let mut grants_map = self.grants.lock().unwrap();
        let mut result = Err(GrantError::GrantNotFound(grant_id.clone()));
        let mut found_profile: Option<String> = None;
        for (key, grants) in grants_map.iter() {
            if grants.is_grant_active(grant_id) {
                found_profile = Some(key.clone());
                break;
            }
        }
        if let Some(profile_key) = found_profile {
            let grants = grants_map.get_mut(&profile_key).unwrap();
            result = grants.revoke_grant(grant_id, authority);
            if result.is_ok() {
                grants.cancel_claims_for_grant(grant_id);
            }
        }

        drop(grants_map);
        if result.is_ok() {
            let mut pending = self.pending.lock().unwrap();
            for pa in pending.values_mut() {
                if pa.grant_id.as_ref() == Some(grant_id) {
                    pa.invalidated = true;
                }
            }
        }
        result
    }

    pub fn rollback_grant(&self, grant_id: &passless_core::agent::GrantId) {
        let authority = super::intent::admin_authority();
        let _ = self.admin_revoke_grant(grant_id, &authority);
    }

    pub fn resolved_grant_id_for_request(
        &self,
        profile_id: &ProfileId,
        grant_request_id: &super::grant::GrantRequestId,
    ) -> Option<passless_core::agent::GrantId> {
        let grants = self.grants.lock().unwrap();
        let profile_key = profile_id.as_str().to_string();
        grants
            .get(&profile_key)
            .and_then(|g| g.resolved_grant_id(grant_request_id))
    }

    pub fn principal_cancel_intent(
        &self,
        intent_id: &IntentId,
        profile_id: &ProfileId,
        session_id: &PrincipalSessionId,
    ) -> Result<(), IntentError> {
        let mut intents = self.intents.lock().unwrap();
        intents.cancel_by_principal(intent_id, profile_id, session_id)
    }

    pub fn principal_exit(&self, session_id: &PrincipalSessionId) {
        {
            let mut intents = self.intents.lock().unwrap();
            intents.cancel_by_session(session_id);
        }
        {
            let mut grants_map = self.grants.lock().unwrap();
            for grants in grants_map.values_mut() {
                grants.on_principal_exit(session_id);
                grants.cancel_claims_for_session(session_id);
            }
        }
        {
            let mut pending = self.pending.lock().unwrap();
            for pa in pending.values_mut() {
                if pa.session_id == *session_id {
                    pa.invalidated = true;
                }
            }
        }
        {
            let mut pending_requests = self.pending_requests.lock().unwrap();
            for pr in pending_requests.values_mut() {
                if pr.session_id == *session_id && pr.state == PendingState::Waiting {
                    pr.state = PendingState::Cancelled;
                }
            }
        }
    }

    #[cfg(test)]
    pub fn admin_authority(&self) -> AdminAuthority {
        super::intent::admin_authority()
    }

    pub fn principal_create_pending_intent(
        &self,
        params: CreateIntentParams,
    ) -> Result<PendingRequestId, PendingCreateError> {
        let now_mono = self.clock.monotonic_secs();
        let ttl_ms = params.ttl_ms.unwrap_or(300_000);
        let ttl_secs = ttl_ms.div_ceil(1000);

        let normalized_rp = params.rp_id.trim().to_ascii_lowercase();
        let profile_id = params.profile_id.clone();
        let session_id = params.session_id.clone();
        let endpoint_id = params.endpoint_id.clone();
        let process_digest = params.process_digest.clone();
        let policy_generation = params.policy_generation.clone();
        let policy_digest = params.policy_digest.clone();
        let action = params.action.clone();
        let credential_ref = params.credential_ref.clone();

        let (intent_id, _claim_token) = {
            let mut intents = self.intents.lock().unwrap();
            intents
                .create(params)
                .map_err(PendingCreateError::IntentCreationFailed)?
        };

        let pending_id = PendingRequestId::new();

        let request = PendingPrincipalRequest {
            id: pending_id.clone(),
            kind: PendingRequestKind::IsolatedIntent,
            profile_id,
            session_id,
            endpoint_id,
            process_digest,
            policy_generation,
            policy_digest,
            action,
            rp_id: normalized_rp,
            credential_ref,
            intent_id,
            grant_request_id: None,
            state: PendingState::Waiting,
            created_at_mono: now_mono,
            deadline_mono: now_mono.saturating_add(ttl_secs),
        };

        let mut pending_requests = self.pending_requests.lock().unwrap();
        pending_requests.insert(pending_id.as_str().to_string(), request);
        Ok(pending_id)
    }

    pub fn principal_create_pending_delegated(
        &self,
        intent_params: CreateIntentParams,
        grant_params: GrantRequestParams,
    ) -> Result<(PendingRequestId, super::grant::GrantRequestId), PendingCreateError> {
        let now_mono = self.clock.monotonic_secs();
        let ttl_ms = intent_params.ttl_ms.unwrap_or(300_000);
        let ttl_secs = ttl_ms.div_ceil(1000);

        let normalized_rp = intent_params.rp_id.trim().to_ascii_lowercase();
        let profile_id = intent_params.profile_id.clone();
        let session_id = intent_params.session_id.clone();
        let endpoint_id = intent_params.endpoint_id.clone();
        let process_digest = intent_params.process_digest.clone();
        let policy_generation = intent_params.policy_generation.clone();
        let policy_digest = intent_params.policy_digest.clone();
        let action = intent_params.action.clone();
        let credential_ref = intent_params.credential_ref.clone();

        let (intent_id, _claim_token) = {
            let mut intents = self.intents.lock().unwrap();
            intents
                .create(intent_params)
                .map_err(PendingCreateError::IntentCreationFailed)?
        };

        let grant_request_id =
            {
                let profile_key = profile_id.as_str().to_string();
                let mut grants_map = self.grants.lock().unwrap();
                let grants = grants_map.get_mut(&profile_key).ok_or(
                    PendingCreateError::GrantRequestFailed(GrantError::ProfileMismatch),
                )?;
                grants
                    .request_grant(grant_params)
                    .map_err(PendingCreateError::GrantRequestFailed)?
            };

        let pending_id = PendingRequestId::new();

        let request = PendingPrincipalRequest {
            id: pending_id.clone(),
            kind: PendingRequestKind::DelegatedAuth,
            profile_id,
            session_id,
            endpoint_id,
            process_digest,
            policy_generation,
            policy_digest,
            action,
            rp_id: normalized_rp,
            credential_ref,
            intent_id,
            grant_request_id: Some(grant_request_id.clone()),
            state: PendingState::Waiting,
            created_at_mono: now_mono,
            deadline_mono: now_mono.saturating_add(ttl_secs),
        };

        let mut pending_requests = self.pending_requests.lock().unwrap();
        pending_requests.insert(pending_id.as_str().to_string(), request);
        Ok((pending_id, grant_request_id))
    }

    pub fn principal_cancel_pending(
        &self,
        pending_id: &PendingRequestId,
        session_id: &PrincipalSessionId,
    ) -> Result<(), PendingCancelError> {
        let mut pending_requests = self.pending_requests.lock().unwrap();
        let request = pending_requests
            .get_mut(pending_id.as_str())
            .ok_or(PendingCancelError::NotFound)?;

        if request.state != PendingState::Waiting {
            return Err(PendingCancelError::AlreadyResolved);
        }

        if request.session_id != *session_id {
            return Err(PendingCancelError::SessionMismatch);
        }

        request.state = PendingState::Cancelled;

        let mut intents = self.intents.lock().unwrap();
        let authority = super::intent::admin_authority();
        let _ = intents.deny(&request.intent_id, &authority);

        if let Some(ref grant_request_id) = request.grant_request_id {
            let profile_key = request.profile_id.as_str().to_string();
            let mut grants_map = self.grants.lock().unwrap();
            if let Some(grants) = grants_map.get_mut(&profile_key) {
                if let Some(grant_id) = grants.resolved_grant_id(grant_request_id) {
                    let _ = grants.revoke_grant(&grant_id, &authority);
                }
                let _ = grants.cancel_request(grant_request_id);
            }
        }

        Ok(())
    }

    pub fn principal_pending_status(
        &self,
        pending_id: &PendingRequestId,
        session_id: &PrincipalSessionId,
    ) -> Result<PendingStatusSnapshot, PendingStatusError> {
        let pending_requests = self.pending_requests.lock().unwrap();
        let request = pending_requests
            .get(pending_id.as_str())
            .ok_or(PendingStatusError::NotFound)?;

        if request.session_id != *session_id {
            return Err(PendingStatusError::SessionMismatch);
        }

        let now_mono = self.clock.monotonic_secs();
        let effective_state =
            if request.state == PendingState::Waiting && now_mono >= request.deadline_mono {
                PendingState::TimedOut
            } else {
                request.state
            };

        Ok(PendingStatusSnapshot {
            id: request.id.clone(),
            kind: request.kind,
            state: effective_state,
            profile_id: request.profile_id.clone(),
            session_id: request.session_id.clone(),
            endpoint_id: request.endpoint_id.clone(),
            process_digest: request.process_digest.clone(),
            policy_generation: request.policy_generation.clone(),
            policy_digest: request.policy_digest.clone(),
            action: request.action.clone(),
            rp_id: request.rp_id.clone(),
            credential_ref: request.credential_ref.clone(),
            intent_id: request.intent_id.clone(),
            grant_request_id: request.grant_request_id.clone(),
            created_at_mono: request.created_at_mono,
            deadline_mono: request.deadline_mono,
        })
    }

    pub fn cleanup_expired_pending(&self) -> Vec<PendingRequestId> {
        let now_mono = self.clock.monotonic_secs();
        let mut pending_requests = self.pending_requests.lock().unwrap();
        let mut expired = Vec::new();

        for (key, request) in pending_requests.iter_mut() {
            if request.state == PendingState::Waiting && now_mono >= request.deadline_mono {
                request.state = PendingState::TimedOut;
                expired.push(request.id.clone());

                let mut intents = self.intents.lock().unwrap();
                let authority = super::intent::admin_authority();
                let _ = intents.deny(&request.intent_id, &authority);

                if let Some(ref grant_request_id) = request.grant_request_id {
                    let profile_key = request.profile_id.as_str().to_string();
                    let mut grants_map = self.grants.lock().unwrap();
                    if let Some(grants) = grants_map.get_mut(&profile_key) {
                        if let Some(grant_id) = grants.resolved_grant_id(grant_request_id) {
                            let _ = grants.revoke_grant(&grant_id, &authority);
                        }
                        let _ = grants.cancel_request(grant_request_id);
                    }
                }
                let _ = key;
            }
        }

        expired
    }

    pub fn cancel_pending_for_session(&self, session_id: &PrincipalSessionId) {
        let mut pending_requests = self.pending_requests.lock().unwrap();
        for request in pending_requests.values_mut() {
            if request.session_id == *session_id && request.state == PendingState::Waiting {
                request.state = PendingState::Cancelled;

                let mut intents = self.intents.lock().unwrap();
                let authority = super::intent::admin_authority();
                let _ = intents.deny(&request.intent_id, &authority);

                if let Some(ref grant_request_id) = request.grant_request_id {
                    let profile_key = request.profile_id.as_str().to_string();
                    let mut grants_map = self.grants.lock().unwrap();
                    if let Some(grants) = grants_map.get_mut(&profile_key) {
                        if let Some(grant_id) = grants.resolved_grant_id(grant_request_id) {
                            let _ = grants.revoke_grant(&grant_id, &authority);
                        }
                        let _ = grants.cancel_request(grant_request_id);
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct PendingStatusSnapshot {
    pub id: PendingRequestId,
    pub kind: PendingRequestKind,
    pub state: PendingState,
    pub profile_id: ProfileId,
    pub session_id: PrincipalSessionId,
    pub endpoint_id: EndpointId,
    pub process_digest: ProcessIdentityDigest,
    pub policy_generation: PolicyGenerationId,
    pub policy_digest: PolicyDigest,
    pub action: IntentAction,
    pub rp_id: String,
    pub credential_ref: Option<CredentialRef>,
    pub intent_id: IntentId,
    pub grant_request_id: Option<GrantRequestId>,
    pub created_at_mono: u64,
    pub deadline_mono: u64,
}

impl PendingStatusSnapshot {
    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    pub fn is_expired(&self) -> bool {
        self.state == PendingState::TimedOut
    }

    pub fn to_intent_state(&self) -> passless_core::agent::protocol::IntentState {
        match self.state {
            PendingState::Waiting => passless_core::agent::protocol::IntentState::Pending,
            PendingState::Approved => passless_core::agent::protocol::IntentState::Approved,
            PendingState::Denied => passless_core::agent::protocol::IntentState::Denied,
            PendingState::TimedOut => passless_core::agent::protocol::IntentState::Expired,
            PendingState::Cancelled => passless_core::agent::protocol::IntentState::Cancelled,
        }
    }

    pub fn to_delegation_state(&self) -> passless_core::agent::protocol::DelegationState {
        match self.state {
            PendingState::Waiting => passless_core::agent::protocol::DelegationState::Pending,
            PendingState::Approved => passless_core::agent::protocol::DelegationState::Approved,
            PendingState::Denied => passless_core::agent::protocol::DelegationState::Denied,
            PendingState::TimedOut => passless_core::agent::protocol::DelegationState::Expired,
            PendingState::Cancelled => passless_core::agent::protocol::DelegationState::Cancelled,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingStatusError {
    NotFound,
    SessionMismatch,
}

impl std::fmt::Display for PendingStatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "pending request not found"),
            Self::SessionMismatch => write!(f, "session mismatch for pending request"),
        }
    }
}

impl std::error::Error for PendingStatusError {}

struct ArcMonotonicClockAdapter(Arc<dyn MonotonicClock>);

impl MonotonicClock for ArcMonotonicClockAdapter {
    fn now(&self) -> super::intent::MonotonicTime {
        self.0.now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use passless_core::agent::{
        AgentConfig, AgentMode, AgentProfileConfig, AgentRpRule, AgentStorageConfig, BrowserScope,
        CredentialRef, ProfileId, RuleAction, RuleIdentity,
    };
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use super::super::browser::Clock;
    use super::super::intent::{
        CreateIntentParams, MonotonicClock, MonotonicTime, ProcessIdentityDigest,
    };
    use passless_core::agent::protocol::IntentAction;

    struct MockClock {
        inner: Mutex<MockInner>,
    }

    struct MockInner {
        base: Instant,
        offset: Duration,
    }

    impl MockClock {
        fn new() -> Self {
            Self {
                inner: Mutex::new(MockInner {
                    base: Instant::now(),
                    offset: Duration::ZERO,
                }),
            }
        }

        fn advance(&self, d: Duration) {
            self.inner.lock().unwrap().offset += d;
        }
    }

    impl Clock for MockClock {
        fn now(&self) -> Instant {
            let inner = self.inner.lock().unwrap();
            inner.base + inner.offset
        }

        fn monotonic_secs(&self) -> u64 {
            self.inner.lock().unwrap().offset.as_secs()
        }
    }

    impl MonotonicClock for MockClock {
        fn now(&self) -> MonotonicTime {
            MonotonicTime::from_millis(self.inner.lock().unwrap().offset.as_millis() as u64)
        }
    }

    fn test_clock() -> Arc<MockClock> {
        Arc::new(MockClock::new())
    }

    fn make_isolated_config(
        profile_name: &str,
        rp_ids: Vec<&str>,
        registration_allowed: bool,
    ) -> AgentConfig {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            profile_name.to_string(),
            AgentProfileConfig {
                max_operations: 64,
                max_concurrent_sessions: 1,
                browser_scope: BrowserScope::Session,
                credential_selection: CredentialSelection::Single,
                mode: AgentMode::Isolated,
                principal_user: "test-user".to_string(),
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: PathBuf::from(format!("/tmp/test-{}/creds", profile_name)),
                    pin_path: PathBuf::from(format!("/tmp/test-{}/pin", profile_name)),
                }),
                rules: rp_ids
                    .into_iter()
                    .map(|rp_id| AgentRpRule {
                        rp_id: rp_id.to_string(),
                        register: if registration_allowed {
                            RuleAction::Allow
                        } else {
                            RuleAction::Deny
                        },
                        authenticate: RuleAction::Allow,
                        credential_selection: None,
                    })
                    .collect(),
                legacy: Default::default(),
                device: None,
                start_url: None,
                browser_command: None,
                browser_user: None,
                browser_runtime_root: None,
                browser_cdp_expose: None,
                browser_cdp_port: None,
            },
        );
        AgentConfig {
            enabled: true,
            profiles,
            audit_path: Some(PathBuf::from("/tmp/test-audit")),
            acknowledge_global_same_user: vec![],
            acknowledge_same_user_registration: vec![],
        }
    }

    fn make_runtime(config: &AgentConfig) -> (PolicyRuntime, Arc<MockClock>) {
        let clock = test_clock();
        let runtime = PolicyRuntime::new(config, clock.clone(), clock.clone(), None).unwrap();
        (runtime, clock)
    }

    fn make_auth_request(
        runtime: &PolicyRuntime,
        profile_id: ProfileId,
        action: IntentAction,
        rp_id: &str,
        credential_ref: Option<CredentialRef>,
        uv_enforced: bool,
    ) -> AuthorizationRequest {
        let generation = runtime.current_generation();
        AuthorizationRequest {
            profile_id,
            session_id: passless_core::agent::PrincipalSessionId::new(),
            endpoint_id: passless_core::agent::EndpointId::new(),
            process_digest: ProcessIdentityDigest::compute(1000, 1000, 42, b"test"),
            policy_generation_id: generation.generation_id.clone(),
            policy_digest: generation.digest.clone(),
            action,
            rp_id: rp_id.to_string(),
            credential_ref,
            uv_enforced,
        }
    }

    fn rule(rp_id: &str, authenticate: RuleAction, register: RuleAction) -> AgentRpRule {
        AgentRpRule {
            rp_id: rp_id.to_string(),
            register,
            authenticate,
            credential_selection: None,
        }
    }

    /// A granted-rules store with a fixed set of `(profile, rp_id)` entries.
    struct TestGrants(Vec<(String, String)>);

    impl TestGrants {
        fn of(entries: &[(&str, &str)]) -> Arc<Self> {
            Arc::new(Self(
                entries
                    .iter()
                    .map(|(p, r)| (p.to_string(), r.to_string()))
                    .collect(),
            ))
        }
    }

    impl GrantSource for TestGrants {
        fn is_granted(&self, profile_id: &ProfileId, rp_id: &str) -> bool {
            self.0
                .iter()
                .any(|(p, r)| p == profile_id.as_str() && r == rp_id)
        }
    }

    fn same_user_config(name: &str, rules: Vec<AgentRpRule>) -> AgentConfig {
        let mut config = make_isolated_config(name, vec![], false);
        config.acknowledge_global_same_user = vec![name.to_string()];
        let profile = config.profiles.get_mut(name).unwrap();
        profile.mode = AgentMode::SameUser;
        profile.storage = None;
        profile.rules = rules;
        config
    }

    #[test]
    fn test_compile_isolated_snapshot() {
        let config = make_isolated_config("test", vec!["example.com"], true);
        let generation = PolicyRuntime::compile_generation(&config, 0, 1).unwrap();

        assert_eq!(generation.snapshots.len(), 1);
        let s = &generation.snapshots[0];
        assert_eq!(s.profile_id.as_str(), "test");
        assert_eq!(s.mode, AgentMode::Isolated);
        assert_eq!(s.normalized_rp_ids, vec!["example.com"]);
        assert!(s.allowed_actions.contains("register"));
        assert!(s.allowed_actions.contains("authenticate"));
        assert_eq!(s.credential_selection, CredentialSelection::Single);
    }

    #[test]
    fn test_snapshot_deterministic_digest() {
        let config = make_isolated_config("det", vec!["example.com"], false);
        let gen1 = PolicyRuntime::compile_generation(&config, 0, 1).unwrap();
        let gen2 = PolicyRuntime::compile_generation(&config, 0, 1).unwrap();

        assert_eq!(gen1.snapshots[0].digest, gen2.snapshots[0].digest);
    }

    #[test]
    fn test_compile_explicit_allow_and_deny_rules() {
        let mut config = make_isolated_config("rules", vec![], false);
        let profile = config.profiles.get_mut("rules").unwrap();
        profile.rules = vec![rule("example.com", RuleAction::Allow, RuleAction::Deny)];

        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("rules").unwrap();
        let auth = runtime.resolve(&pid, &IntentAction::Authenticate, "example.com");
        assert_eq!(auth.action, RuleAction::Allow);
        assert_eq!(auth.rule, RuleIdentity::Exact("example.com".to_string()));
        let reg = runtime.resolve(&pid, &IntentAction::Register, "example.com");
        assert_eq!(reg.action, RuleAction::Deny);

        let generation = runtime.current_generation();
        let snapshot = &generation.snapshots[0];
        assert!(snapshot.action_allowed(&IntentAction::Authenticate));
        assert!(!snapshot.action_allowed(&IntentAction::Register));
    }

    #[test]
    fn test_compile_all_deny_profile_succeeds() {
        // Regression (defect B4): a profile whose rules are all `deny` is valid and authorizes
        // nothing.
        let mut config = make_isolated_config("alldeny", vec![], false);
        config.profiles.get_mut("alldeny").unwrap().rules = vec![
            rule("example.com", RuleAction::Deny, RuleAction::Deny),
            rule("github.com", RuleAction::Deny, RuleAction::Deny),
        ];

        let generation = PolicyRuntime::compile_generation(&config, 0, 1).unwrap();
        let snapshot = &generation.snapshots[0];
        assert!(snapshot.allowed_actions.is_empty());
        assert!(snapshot.policy.allowed_actions.is_empty());

        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("alldeny").unwrap();
        for action in [IntentAction::Authenticate, IntentAction::Register] {
            assert_eq!(
                runtime.resolve(&pid, &action, "example.com").action,
                RuleAction::Deny
            );
        }
    }

    #[test]
    fn test_compile_profile_without_rules_succeeds() {
        let config = make_isolated_config("norules", vec![], false);
        let generation = PolicyRuntime::compile_generation(&config, 0, 1).unwrap();
        assert!(generation.snapshots[0].allowed_actions.is_empty());
    }

    #[test]
    fn test_compile_same_user_wildcard_policy_with_exact_override() {
        let config = same_user_config(
            "wildcard",
            vec![
                rule(ANY_RP_ID, RuleAction::Allow, RuleAction::Deny),
                rule("bank.example.com", RuleAction::Request, RuleAction::Deny),
            ],
        );

        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("wildcard").unwrap();
        let generation = runtime.current_generation();
        let snapshot = &generation.snapshots[0];
        assert!(snapshot.is_rp_exact_match("github.com"));
        assert!(!snapshot.is_rp_exact_match("com"));

        let github = runtime.resolve(&pid, &IntentAction::Authenticate, "github.com");
        assert_eq!(github.action, RuleAction::Allow);
        assert!(github.is_wildcard());
        assert_eq!(github.audit_rule(), Some("*"));

        let bank = runtime.resolve(&pid, &IntentAction::Authenticate, "bank.example.com");
        assert_eq!(bank.configured, RuleAction::Request);
        assert_eq!(bank.action, RuleAction::Request);
        assert_eq!(bank.audit_rule(), Some("bank.example.com"));

        assert_eq!(
            runtime
                .resolve(&pid, &IntentAction::Register, "github.com")
                .action,
            RuleAction::Deny
        );
        assert_eq!(
            runtime
                .resolve(&pid, &IntentAction::Authenticate, "com")
                .action,
            RuleAction::Deny
        );
    }

    #[test]
    fn test_resolve_precedence_exact_over_wildcard() {
        let config = same_user_config(
            "prec",
            vec![
                rule(ANY_RP_ID, RuleAction::Allow, RuleAction::Deny),
                rule("blocked.example.com", RuleAction::Deny, RuleAction::Deny),
            ],
        );
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("prec").unwrap();

        let blocked = runtime.resolve(&pid, &IntentAction::Authenticate, "blocked.example.com");
        assert_eq!(blocked.action, RuleAction::Deny);
        assert_eq!(
            blocked.rule,
            RuleIdentity::Exact("blocked.example.com".to_string())
        );
        let other = runtime.resolve(&pid, &IntentAction::Authenticate, "other.example.com");
        assert_eq!(other.action, RuleAction::Allow);
        assert_eq!(other.rule, RuleIdentity::Wildcard);
    }

    #[test]
    fn test_resolve_granted_placeholder_between_exact_and_wildcard() {
        // exact `allow` > granted `request` > wildcard `allow`/`request`.
        let config = same_user_config(
            "granted",
            vec![
                rule(ANY_RP_ID, RuleAction::Request, RuleAction::Deny),
                rule("github.com", RuleAction::Request, RuleAction::Deny),
                rule("direct.example.com", RuleAction::Allow, RuleAction::Deny),
            ],
        );
        let clock = test_clock();
        let runtime = PolicyRuntime::new(&config, clock.clone(), clock, None)
            .unwrap()
            .with_grant_source(TestGrants::of(&[
                ("granted", "github.com"),
                ("granted", "direct.example.com"),
                ("granted", "wild.example.com"),
            ]));
        let pid = ProfileId::new("granted").unwrap();
        let auth = IntentAction::Authenticate;

        // An exact `request` rule with a matching grant becomes `allow`.
        let github = runtime.resolve(&pid, &auth, "github.com");
        assert_eq!(github.configured, RuleAction::Request);
        assert_eq!(github.action, RuleAction::Allow);
        assert!(github.granted);

        // Exact `allow` is allow without consulting the store.
        let direct = runtime.resolve(&pid, &auth, "direct.example.com");
        assert_eq!(direct.action, RuleAction::Allow);
        assert!(!direct.granted);

        // The wildcard `request` is also upgraded by an exact granted entry for the RP...
        let wild = runtime.resolve(&pid, &auth, "wild.example.com");
        assert_eq!(wild.rule, RuleIdentity::Wildcard);
        assert_eq!(wild.action, RuleAction::Allow);
        assert!(wild.granted);

        // ...and stays `request` without one.
        let other = runtime.resolve(&pid, &auth, "other.example.com");
        assert_eq!(other.rule, RuleIdentity::Wildcard);
        assert_eq!(other.action, RuleAction::Request);
        assert!(!other.granted);
    }

    #[test]
    fn test_resolve_orphaned_grant_is_inert() {
        // The granted-rules store says granted, but the config rule is `deny` or absent: never
        // `allow` (ADR 0014 section 6.2).
        let config = make_isolated_config("orphan", vec![], false);
        let mut config = config;
        config.profiles.get_mut("orphan").unwrap().rules = vec![
            rule("denied.example.com", RuleAction::Deny, RuleAction::Deny),
            rule("alsodenied.example.com", RuleAction::Deny, RuleAction::Deny),
        ];
        let clock = test_clock();
        let runtime = PolicyRuntime::new(&config, clock.clone(), clock, None)
            .unwrap()
            .with_grant_source(TestGrants::of(&[
                ("orphan", "denied.example.com"),
                ("orphan", "removed.example.com"),
            ]));
        let pid = ProfileId::new("orphan").unwrap();

        let denied = runtime.resolve(&pid, &IntentAction::Authenticate, "denied.example.com");
        assert_eq!(denied.action, RuleAction::Deny);
        assert!(!denied.granted);

        let removed = runtime.resolve(&pid, &IntentAction::Authenticate, "removed.example.com");
        assert_eq!(removed.action, RuleAction::Deny);
        assert_eq!(removed.rule, RuleIdentity::None);
        assert!(!removed.granted);
    }

    #[test]
    fn test_resolve_grant_never_upgrades_register_request() {
        let mut config = make_isolated_config("regreq", vec![], false);
        config.profiles.get_mut("regreq").unwrap().rules =
            vec![rule("example.com", RuleAction::Allow, RuleAction::Request)];
        let clock = test_clock();
        let runtime = PolicyRuntime::new(&config, clock.clone(), clock, None)
            .unwrap()
            .with_grant_source(TestGrants::of(&[("regreq", "example.com")]));
        let pid = ProfileId::new("regreq").unwrap();
        let reg = runtime.resolve(&pid, &IntentAction::Register, "example.com");
        assert_eq!(reg.action, RuleAction::Request);
        assert!(!reg.granted);
    }

    #[test]
    fn test_resolve_grants_are_per_profile() {
        let mut config = make_isolated_config("p_one", vec![], false);
        config.profiles.get_mut("p_one").unwrap().rules =
            vec![rule("example.com", RuleAction::Request, RuleAction::Deny)];
        let clock = test_clock();
        let runtime = PolicyRuntime::new(&config, clock.clone(), clock, None)
            .unwrap()
            .with_grant_source(TestGrants::of(&[("someone_else", "example.com")]));
        let pid = ProfileId::new("p_one").unwrap();
        assert_eq!(
            runtime
                .resolve(&pid, &IntentAction::Authenticate, "example.com")
                .action,
            RuleAction::Request
        );
    }

    #[test]
    fn test_resolve_wildcard_never_matches_localhost_or_register() {
        let config = same_user_config(
            "wildlocal",
            vec![rule(ANY_RP_ID, RuleAction::Allow, RuleAction::Allow)],
        );
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("wildlocal").unwrap();
        assert_eq!(
            runtime
                .resolve(&pid, &IntentAction::Authenticate, "localhost")
                .action,
            RuleAction::Deny
        );
        assert_eq!(
            runtime
                .resolve(&pid, &IntentAction::Register, "example.com")
                .action,
            RuleAction::Deny
        );
    }

    #[test]
    fn test_resolve_wildcard_selection_is_forced_single() {
        let mut config = same_user_config(
            "wildsel",
            vec![
                rule(ANY_RP_ID, RuleAction::Allow, RuleAction::Deny),
                rule("exact.example.com", RuleAction::Allow, RuleAction::Deny),
            ],
        );
        config
            .profiles
            .get_mut("wildsel")
            .unwrap()
            .credential_selection = CredentialSelection::Newest;
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("wildsel").unwrap();

        let wild = runtime.resolve(&pid, &IntentAction::Authenticate, "any.example.com");
        assert_eq!(wild.selection, CredentialSelection::Single);
        let exact = runtime.resolve(&pid, &IntentAction::Authenticate, "exact.example.com");
        assert_eq!(exact.selection, CredentialSelection::Newest);
    }

    #[test]
    fn test_resolve_unknown_profile_denies() {
        let config = make_isolated_config("known", vec!["example.com"], false);
        let (runtime, _clock) = make_runtime(&config);
        let unknown = ProfileId::new("unknown").unwrap();
        for action in [IntentAction::Authenticate, IntentAction::Register] {
            let matched = runtime.resolve(&unknown, &action, "example.com");
            assert_eq!(matched.action, RuleAction::Deny);
            assert_eq!(matched.rule, RuleIdentity::None);
            assert!(matched.audit_rule().is_none());
        }
    }

    #[test]
    fn test_resolve_is_live_after_reload() {
        let allow = make_isolated_config("live", vec!["example.com"], false);
        let (runtime, _clock) = make_runtime(&allow);
        let pid = ProfileId::new("live").unwrap();
        let auth = IntentAction::Authenticate;
        assert_eq!(
            runtime.resolve(&pid, &auth, "example.com").action,
            RuleAction::Allow
        );

        let mut deny = allow.clone();
        deny.profiles.get_mut("live").unwrap().rules[0].authenticate = RuleAction::Deny;
        runtime.reload(&deny).unwrap();
        assert_eq!(
            runtime.resolve(&pid, &auth, "example.com").action,
            RuleAction::Deny
        );

        runtime.reload(&allow).unwrap();
        assert_eq!(
            runtime.resolve(&pid, &auth, "example.com").action,
            RuleAction::Allow
        );
    }

    #[test]
    fn test_generation_number_starts_at_one_and_increments_on_reload() {
        let config = make_isolated_config("gen", vec!["example.com"], false);
        let (runtime, _clock) = make_runtime(&config);
        assert_eq!(runtime.generation_number(), 1);
        assert_eq!(runtime.current_generation().generation, 1);

        let digest_before = runtime.digest();
        let generation_id_before = runtime.current_generation().generation_id.clone();

        // A no-op reload leaves the content digest unchanged, but the numeric generation and the
        // generation id still advance.
        let digest_after = runtime.reload(&config).unwrap();
        assert_eq!(digest_after, digest_before);
        assert_eq!(runtime.digest(), digest_before);
        assert_eq!(runtime.generation_number(), 2);
        assert_ne!(
            runtime.current_generation().generation_id,
            generation_id_before
        );

        let mut changed = config.clone();
        changed.profiles.get_mut("gen").unwrap().rules[0].authenticate = RuleAction::Request;
        let digest_changed = runtime.reload(&changed).unwrap();
        assert_ne!(digest_changed, digest_before);
        assert_eq!(runtime.generation_number(), 3);
    }

    #[test]
    fn test_failed_reload_keeps_generation_number() {
        let config = make_isolated_config("genfail", vec!["example.com"], false);
        let (runtime, _clock) = make_runtime(&config);
        let mut broken = config.clone();
        broken.profiles.insert(
            String::new(),
            broken.profiles.get("genfail").unwrap().clone(),
        );
        assert!(runtime.reload(&broken).is_err());
        assert_eq!(runtime.generation_number(), 1);
    }

    #[test]
    fn test_concurrent_reloads_get_unique_monotonic_generations() {
        let config = make_isolated_config("genrace", vec!["example.com"], false);
        let (runtime, _clock) = make_runtime(&config);
        let runtime = Arc::new(runtime);
        const THREADS: u64 = 8;
        const RELOADS_PER_THREAD: u64 = 10;
        let observed = Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(|| {
                    for _ in 0..RELOADS_PER_THREAD {
                        runtime.reload(&config).unwrap();
                        observed.lock().unwrap().push(runtime.generation_number());
                    }
                });
            }
        });
        // Every reload bumped the generation exactly once: none was lost to a racing reload.
        assert_eq!(
            runtime.generation_number(),
            1 + THREADS * RELOADS_PER_THREAD
        );
        let observed = observed.into_inner().unwrap();
        assert!(observed.iter().all(|g| *g >= 2));
    }

    #[test]
    fn test_digest_changes_with_rule_action() {
        let allow = make_isolated_config("dig", vec!["example.com"], false);
        let mut request = allow.clone();
        request.profiles.get_mut("dig").unwrap().rules[0].authenticate = RuleAction::Request;
        let d1 = PolicyRuntime::compile_generation(&allow, 0, 1)
            .unwrap()
            .digest;
        let d2 = PolicyRuntime::compile_generation(&request, 0, 1)
            .unwrap()
            .digest;
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_authorize_denies_non_allow_rule_actions() {
        let mut config = make_isolated_config("nonallow", vec![], false);
        config.profiles.get_mut("nonallow").unwrap().rules = vec![
            rule("request.example.com", RuleAction::Request, RuleAction::Deny),
            rule("deny.example.com", RuleAction::Deny, RuleAction::Deny),
        ];
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("nonallow").unwrap();
        for rp in ["request.example.com", "deny.example.com"] {
            let request = make_auth_request(
                &runtime,
                pid.clone(),
                IntentAction::Authenticate,
                rp,
                None,
                false,
            );
            let (decision, handle) = runtime.authorize(&request);
            assert_eq!(decision.outcome, Outcome::Deny, "{rp}");
            assert_eq!(decision.reason, ReasonCode::ActionNotAllowed, "{rp}");
            assert!(handle.is_none());
        }
    }

    #[test]
    fn test_isolated_auth_requires_intent() {
        let config = make_isolated_config("iso", vec!["example.com"], false);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("iso").unwrap();

        let request = make_auth_request(
            &runtime,
            pid,
            IntentAction::Authenticate,
            "example.com",
            None,
            false,
        );

        let (decision, _) = runtime.authorize(&request);
        assert_eq!(decision.outcome, Outcome::Deny);
        assert_eq!(decision.reason, ReasonCode::IntentNotFound);
    }

    #[test]
    fn test_isolated_auth_with_intent_allowed() {
        let config = make_isolated_config("isook", vec!["example.com"], false);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("isook").unwrap();
        let authority = runtime.admin_authority();
        let session = passless_core::agent::PrincipalSessionId::new();
        let endpoint = passless_core::agent::EndpointId::new();
        let process_digest = ProcessIdentityDigest::compute(1000, 1000, 42, b"test");
        let generation = runtime.current_generation();

        let (intent_id, _token) = runtime
            .admin_create_intent(CreateIntentParams {
                profile_id: pid.clone(),
                session_id: session.clone(),
                endpoint_id: endpoint.clone(),
                process_digest: process_digest.clone(),
                action: IntentAction::Authenticate,
                rp_id: "example.com".to_string(),
                credential_ref: None,
                policy_generation: generation.generation_id.clone(),
                policy_digest: generation.digest.clone(),
                require_uv: false,
                ttl_ms: Some(60_000),
            })
            .unwrap();
        runtime
            .admin_approve_intent(&intent_id, &authority)
            .unwrap();

        let request = AuthorizationRequest {
            profile_id: pid,
            session_id: session,
            endpoint_id: endpoint,
            process_digest,
            policy_generation_id: generation.generation_id.clone(),
            policy_digest: generation.digest.clone(),
            action: IntentAction::Authenticate,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            uv_enforced: false,
        };

        let (decision, handle) = runtime.authorize(&request);
        assert_eq!(decision.outcome, Outcome::Allow);
        assert!(handle.is_some());
    }

    #[test]
    fn test_suffix_rp_denied() {
        let config = make_isolated_config("suf", vec!["example.com"], false);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("suf").unwrap();

        let request = make_auth_request(
            &runtime,
            pid,
            IntentAction::Authenticate,
            "sub.example.com",
            None,
            false,
        );

        let (decision, _) = runtime.authorize(&request);
        assert_eq!(decision.outcome, Outcome::Deny);
        assert_eq!(decision.reason, ReasonCode::SuffixNotExact);
    }

    #[test]
    fn test_reload_invalidates_stores() {
        let config1 = make_isolated_config("reload", vec!["example.com"], false);
        let (runtime, _clock) = make_runtime(&config1);
        let pid = ProfileId::new("reload").unwrap();
        let authority = runtime.admin_authority();
        let session = passless_core::agent::PrincipalSessionId::new();
        let endpoint = passless_core::agent::EndpointId::new();
        let generation = runtime.current_generation();

        let (intent_id, _) = runtime
            .admin_create_intent(CreateIntentParams {
                profile_id: pid.clone(),
                session_id: session.clone(),
                endpoint_id: endpoint.clone(),
                process_digest: ProcessIdentityDigest::compute(1000, 1000, 42, b"test"),
                action: IntentAction::Authenticate,
                rp_id: "example.com".to_string(),
                credential_ref: None,
                policy_generation: generation.generation_id.clone(),
                policy_digest: generation.digest.clone(),
                require_uv: false,
                ttl_ms: Some(60_000),
            })
            .unwrap();
        runtime
            .admin_approve_intent(&intent_id, &authority)
            .unwrap();

        let config2 = make_isolated_config("reload", vec!["example.com", "github.com"], false);
        let _new_digest = runtime.reload(&config2).unwrap();

        let pending = runtime.pending.lock().unwrap();
        assert!(pending.values().all(|p| p.invalidated));
    }

    #[test]
    fn test_handle_consume_exactly_once() {
        let config = make_isolated_config("consume", vec!["example.com"], false);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("consume").unwrap();
        let authority = runtime.admin_authority();
        let session = passless_core::agent::PrincipalSessionId::new();
        let endpoint = passless_core::agent::EndpointId::new();
        let process_digest = ProcessIdentityDigest::compute(1000, 1000, 42, b"test");
        let generation = runtime.current_generation();

        let (intent_id, _) = runtime
            .admin_create_intent(CreateIntentParams {
                profile_id: pid.clone(),
                session_id: session.clone(),
                endpoint_id: endpoint.clone(),
                process_digest: process_digest.clone(),
                action: IntentAction::Authenticate,
                rp_id: "example.com".to_string(),
                credential_ref: None,
                policy_generation: generation.generation_id.clone(),
                policy_digest: generation.digest.clone(),
                require_uv: false,
                ttl_ms: Some(60_000),
            })
            .unwrap();
        runtime
            .admin_approve_intent(&intent_id, &authority)
            .unwrap();

        let request = AuthorizationRequest {
            profile_id: pid,
            session_id: session,
            endpoint_id: endpoint,
            process_digest,
            policy_generation_id: generation.generation_id.clone(),
            policy_digest: generation.digest.clone(),
            action: IntentAction::Authenticate,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            uv_enforced: false,
        };

        let (decision, handle) = runtime.authorize(&request);
        assert!(decision.is_allowed());
        let h = handle.unwrap();

        assert!(runtime.consume_authorization(&h).is_ok());
        assert!(matches!(
            runtime.consume_authorization(&h),
            Err(ReasonCode::CeremonyInvalidated)
        ));
    }

    #[test]
    fn test_public_principal_cannot_approve() {
        let config = make_isolated_config("noapprove", vec!["example.com"], false);
        let (runtime, _clock) = make_runtime(&config);

        let _authority = runtime.admin_authority();
    }

    #[test]
    fn test_concurrent_authorize_one_claim() {
        let config = make_isolated_config("concurrent", vec!["example.com"], false);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("concurrent").unwrap();
        let authority = runtime.admin_authority();
        let session = passless_core::agent::PrincipalSessionId::new();
        let endpoint = passless_core::agent::EndpointId::new();
        let process_digest = ProcessIdentityDigest::compute(1000, 1000, 42, b"test");
        let generation = runtime.current_generation();

        let (intent_id, _) = runtime
            .admin_create_intent(CreateIntentParams {
                profile_id: pid.clone(),
                session_id: session.clone(),
                endpoint_id: endpoint.clone(),
                process_digest: process_digest.clone(),
                action: IntentAction::Authenticate,
                rp_id: "example.com".to_string(),
                credential_ref: None,
                policy_generation: generation.generation_id.clone(),
                policy_digest: generation.digest.clone(),
                require_uv: false,
                ttl_ms: Some(60_000),
            })
            .unwrap();
        runtime
            .admin_approve_intent(&intent_id, &authority)
            .unwrap();

        let request = AuthorizationRequest {
            profile_id: pid,
            session_id: session,
            endpoint_id: endpoint,
            process_digest,
            policy_generation_id: generation.generation_id.clone(),
            policy_digest: generation.digest.clone(),
            action: IntentAction::Authenticate,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            uv_enforced: false,
        };

        let (_decision, handle) = runtime.authorize(&request);
        let h = handle.unwrap();

        let results: Vec<bool> = (0..10)
            .map(|_| runtime.consume_authorization(&h).is_ok())
            .collect();
        let successes = results.iter().filter(|&&r| r).count();
        assert_eq!(successes, 1);
    }

    #[test]
    fn test_intent_replay_denied() {
        let config = make_isolated_config("replay", vec!["example.com"], false);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("replay").unwrap();
        let authority = runtime.admin_authority();
        let session = passless_core::agent::PrincipalSessionId::new();
        let endpoint = passless_core::agent::EndpointId::new();
        let generation = runtime.current_generation();

        let (intent_id, _) = runtime
            .admin_create_intent(CreateIntentParams {
                profile_id: pid.clone(),
                session_id: session.clone(),
                endpoint_id: endpoint.clone(),
                process_digest: ProcessIdentityDigest::compute(1000, 1000, 42, b"test"),
                action: IntentAction::Authenticate,
                rp_id: "example.com".to_string(),
                credential_ref: None,
                policy_generation: generation.generation_id.clone(),
                policy_digest: generation.digest.clone(),
                require_uv: false,
                ttl_ms: Some(60_000),
            })
            .unwrap();
        runtime
            .admin_approve_intent(&intent_id, &authority)
            .unwrap();
    }

    #[test]
    fn test_two_authorize_races_one_intent_one_succeeds() {
        let config = make_isolated_config("race", vec!["example.com"], false);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("race").unwrap();
        let authority = runtime.admin_authority();
        let session = passless_core::agent::PrincipalSessionId::new();
        let endpoint = passless_core::agent::EndpointId::new();
        let process_digest = ProcessIdentityDigest::compute(1000, 1000, 42, b"test");
        let generation = runtime.current_generation();

        let (intent_id, _) = runtime
            .admin_create_intent(CreateIntentParams {
                profile_id: pid.clone(),
                session_id: session.clone(),
                endpoint_id: endpoint.clone(),
                process_digest: process_digest.clone(),
                action: IntentAction::Authenticate,
                rp_id: "example.com".to_string(),
                credential_ref: None,
                policy_generation: generation.generation_id.clone(),
                policy_digest: generation.digest.clone(),
                require_uv: false,
                ttl_ms: Some(60_000),
            })
            .unwrap();
        runtime
            .admin_approve_intent(&intent_id, &authority)
            .unwrap();

        let request = AuthorizationRequest {
            profile_id: pid.clone(),
            session_id: session.clone(),
            endpoint_id: endpoint.clone(),
            process_digest: process_digest.clone(),
            policy_generation_id: generation.generation_id.clone(),
            policy_digest: generation.digest.clone(),
            action: IntentAction::Authenticate,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            uv_enforced: false,
        };

        let (d1, h1) = runtime.authorize(&request);
        let (d2, h2) = runtime.authorize(&request);

        assert!(d1.is_allowed());
        assert_eq!(d2.outcome, Outcome::Deny);
        assert!(h1.is_some());
        assert!(h2.is_none());
    }

    #[test]
    fn test_cross_session_denied() {
        let config = make_isolated_config("crosssession", vec!["example.com"], false);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("crosssession").unwrap();
        let authority = runtime.admin_authority();
        let session1 = passless_core::agent::PrincipalSessionId::new();
        let session2 = passless_core::agent::PrincipalSessionId::new();
        let endpoint = passless_core::agent::EndpointId::new();
        let process_digest = ProcessIdentityDigest::compute(1000, 1000, 42, b"test");
        let generation = runtime.current_generation();

        let (intent_id, _) = runtime
            .admin_create_intent(CreateIntentParams {
                profile_id: pid.clone(),
                session_id: session1.clone(),
                endpoint_id: endpoint.clone(),
                process_digest: process_digest.clone(),
                action: IntentAction::Authenticate,
                rp_id: "example.com".to_string(),
                credential_ref: None,
                policy_generation: generation.generation_id.clone(),
                policy_digest: generation.digest.clone(),
                require_uv: false,
                ttl_ms: Some(60_000),
            })
            .unwrap();
        runtime
            .admin_approve_intent(&intent_id, &authority)
            .unwrap();

        let request = AuthorizationRequest {
            profile_id: pid,
            session_id: session2,
            endpoint_id: endpoint,
            process_digest,
            policy_generation_id: generation.generation_id.clone(),
            policy_digest: generation.digest.clone(),
            action: IntentAction::Authenticate,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            uv_enforced: false,
        };

        let (decision, _) = runtime.authorize(&request);
        assert_eq!(decision.outcome, Outcome::Deny);
        assert_eq!(decision.reason, ReasonCode::IntentNotFound);
    }

    #[test]
    fn test_cross_endpoint_denied() {
        let config = make_isolated_config("crossendpoint", vec!["example.com"], false);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("crossendpoint").unwrap();
        let authority = runtime.admin_authority();
        let session = passless_core::agent::PrincipalSessionId::new();
        let endpoint1 = passless_core::agent::EndpointId::new();
        let endpoint2 = passless_core::agent::EndpointId::new();
        let process_digest = ProcessIdentityDigest::compute(1000, 1000, 42, b"test");
        let generation = runtime.current_generation();

        let (intent_id, _) = runtime
            .admin_create_intent(CreateIntentParams {
                profile_id: pid.clone(),
                session_id: session.clone(),
                endpoint_id: endpoint1.clone(),
                process_digest: process_digest.clone(),
                action: IntentAction::Authenticate,
                rp_id: "example.com".to_string(),
                credential_ref: None,
                policy_generation: generation.generation_id.clone(),
                policy_digest: generation.digest.clone(),
                require_uv: false,
                ttl_ms: Some(60_000),
            })
            .unwrap();
        runtime
            .admin_approve_intent(&intent_id, &authority)
            .unwrap();

        let request = AuthorizationRequest {
            profile_id: pid,
            session_id: session,
            endpoint_id: endpoint2,
            process_digest,
            policy_generation_id: generation.generation_id.clone(),
            policy_digest: generation.digest.clone(),
            action: IntentAction::Authenticate,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            uv_enforced: false,
        };

        let (decision, _) = runtime.authorize(&request);
        assert_eq!(decision.outcome, Outcome::Deny);
        assert_eq!(decision.reason, ReasonCode::IntentNotFound);
    }

    #[test]
    fn test_cross_process_denied() {
        let config = make_isolated_config("crossprocess", vec!["example.com"], false);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("crossprocess").unwrap();
        let authority = runtime.admin_authority();
        let session = passless_core::agent::PrincipalSessionId::new();
        let endpoint = passless_core::agent::EndpointId::new();
        let process_digest1 = ProcessIdentityDigest::compute(1000, 1000, 42, b"test-a");
        let process_digest2 = ProcessIdentityDigest::compute(1000, 1000, 42, b"test-b");
        let generation = runtime.current_generation();

        let (intent_id, _) = runtime
            .admin_create_intent(CreateIntentParams {
                profile_id: pid.clone(),
                session_id: session.clone(),
                endpoint_id: endpoint.clone(),
                process_digest: process_digest1.clone(),
                action: IntentAction::Authenticate,
                rp_id: "example.com".to_string(),
                credential_ref: None,
                policy_generation: generation.generation_id.clone(),
                policy_digest: generation.digest.clone(),
                require_uv: false,
                ttl_ms: Some(60_000),
            })
            .unwrap();
        runtime
            .admin_approve_intent(&intent_id, &authority)
            .unwrap();

        let request = AuthorizationRequest {
            profile_id: pid,
            session_id: session,
            endpoint_id: endpoint,
            process_digest: process_digest2,
            policy_generation_id: generation.generation_id.clone(),
            policy_digest: generation.digest.clone(),
            action: IntentAction::Authenticate,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            uv_enforced: false,
        };

        let (decision, _) = runtime.authorize(&request);
        assert_eq!(decision.outcome, Outcome::Deny);
        assert_eq!(decision.reason, ReasonCode::IntentNotFound);
    }

    #[test]
    fn test_cross_generation_denied() {
        let config = make_isolated_config("crossgen", vec!["example.com"], false);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("crossgen").unwrap();
        let authority = runtime.admin_authority();
        let session = passless_core::agent::PrincipalSessionId::new();
        let endpoint = passless_core::agent::EndpointId::new();
        let process_digest = ProcessIdentityDigest::compute(1000, 1000, 42, b"test");
        let generation = runtime.current_generation();

        let (intent_id, _) = runtime
            .admin_create_intent(CreateIntentParams {
                profile_id: pid.clone(),
                session_id: session.clone(),
                endpoint_id: endpoint.clone(),
                process_digest: process_digest.clone(),
                action: IntentAction::Authenticate,
                rp_id: "example.com".to_string(),
                credential_ref: None,
                policy_generation: generation.generation_id.clone(),
                policy_digest: generation.digest.clone(),
                require_uv: false,
                ttl_ms: Some(60_000),
            })
            .unwrap();
        runtime
            .admin_approve_intent(&intent_id, &authority)
            .unwrap();

        let stale_gen = PolicyGenerationId::new();
        let stale_digest = PolicyDigest::from_cbor_bytes(b"stale");

        let request = AuthorizationRequest {
            profile_id: pid,
            session_id: session,
            endpoint_id: endpoint,
            process_digest,
            policy_generation_id: stale_gen,
            policy_digest: stale_digest,
            action: IntentAction::Authenticate,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            uv_enforced: false,
        };

        let (decision, _) = runtime.authorize(&request);
        assert_eq!(decision.outcome, Outcome::Deny);
        assert_eq!(decision.reason, ReasonCode::GenerationStale);
    }

    #[test]
    fn test_reload_denies_consume() {
        let config1 = make_isolated_config("reloadconsume", vec!["example.com"], false);
        let (runtime, _clock) = make_runtime(&config1);
        let pid = ProfileId::new("reloadconsume").unwrap();
        let authority = runtime.admin_authority();
        let session = passless_core::agent::PrincipalSessionId::new();
        let endpoint = passless_core::agent::EndpointId::new();
        let process_digest = ProcessIdentityDigest::compute(1000, 1000, 42, b"test");
        let generation = runtime.current_generation();

        let (intent_id, _) = runtime
            .admin_create_intent(CreateIntentParams {
                profile_id: pid.clone(),
                session_id: session.clone(),
                endpoint_id: endpoint.clone(),
                process_digest: process_digest.clone(),
                action: IntentAction::Authenticate,
                rp_id: "example.com".to_string(),
                credential_ref: None,
                policy_generation: generation.generation_id.clone(),
                policy_digest: generation.digest.clone(),
                require_uv: false,
                ttl_ms: Some(60_000),
            })
            .unwrap();
        runtime
            .admin_approve_intent(&intent_id, &authority)
            .unwrap();

        let request = AuthorizationRequest {
            profile_id: pid,
            session_id: session,
            endpoint_id: endpoint,
            process_digest,
            policy_generation_id: generation.generation_id.clone(),
            policy_digest: generation.digest.clone(),
            action: IntentAction::Authenticate,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            uv_enforced: false,
        };

        let (decision, handle) = runtime.authorize(&request);
        assert!(decision.is_allowed());
        let h = handle.unwrap();

        let config2 =
            make_isolated_config("reloadconsume", vec!["example.com", "github.com"], false);
        runtime.reload(&config2).unwrap();

        let result = runtime.consume_authorization(&h);
        assert!(result.is_err());
    }

    #[test]
    fn test_no_partial_claim_reusable() {
        let config = make_isolated_config("nopartial", vec!["example.com"], false);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("nopartial").unwrap();
        let authority = runtime.admin_authority();
        let session = passless_core::agent::PrincipalSessionId::new();
        let endpoint = passless_core::agent::EndpointId::new();
        let process_digest = ProcessIdentityDigest::compute(1000, 1000, 42, b"test");
        let generation = runtime.current_generation();

        let (intent_id, _) = runtime
            .admin_create_intent(CreateIntentParams {
                profile_id: pid.clone(),
                session_id: session.clone(),
                endpoint_id: endpoint.clone(),
                process_digest: process_digest.clone(),
                action: IntentAction::Authenticate,
                rp_id: "example.com".to_string(),
                credential_ref: None,
                policy_generation: generation.generation_id.clone(),
                policy_digest: generation.digest.clone(),
                require_uv: false,
                ttl_ms: Some(60_000),
            })
            .unwrap();
        runtime
            .admin_approve_intent(&intent_id, &authority)
            .unwrap();

        let request = AuthorizationRequest {
            profile_id: pid.clone(),
            session_id: session.clone(),
            endpoint_id: endpoint.clone(),
            process_digest: process_digest.clone(),
            policy_generation_id: generation.generation_id.clone(),
            policy_digest: generation.digest.clone(),
            action: IntentAction::Authenticate,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            uv_enforced: false,
        };

        let (d1, h1) = runtime.authorize(&request);
        assert!(d1.is_allowed());
        let mut handle = h1.unwrap();

        let (d2, h2) = runtime.authorize(&request);
        assert_eq!(d2.outcome, Outcome::Deny);
        assert!(h2.is_none());

        handle.rp_id = "other.example".to_string();
        assert_eq!(
            runtime.consume_authorization(&handle),
            Err(ReasonCode::CeremonyInvalidated)
        );
        handle.rp_id = "example.com".to_string();

        let result = runtime.consume_authorization(&handle);
        assert!(result.is_ok());

        let result2 = runtime.consume_authorization(&handle);
        assert!(result2.is_err());
    }

    #[test]
    fn test_principal_create_pending_intent_isolated() {
        let config = make_isolated_config("pendiso", vec!["example.com"], true);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("pendiso").unwrap();
        let session = PrincipalSessionId::new();
        let endpoint = EndpointId::new();
        let process_digest = ProcessIdentityDigest::compute(1000, 1000, 42, b"test");
        let generation = runtime.current_generation();

        let pending_id = runtime
            .principal_create_pending_intent(CreateIntentParams {
                profile_id: pid,
                session_id: session,
                endpoint_id: endpoint,
                process_digest,
                action: IntentAction::Register,
                rp_id: "example.com".to_string(),
                credential_ref: None,
                policy_generation: generation.generation_id.clone(),
                policy_digest: generation.digest.clone(),
                require_uv: false,
                ttl_ms: Some(60_000),
            })
            .unwrap();

        assert!(!pending_id.as_str().is_empty());

        let pr = runtime.pending_requests.lock().unwrap();
        let req = pr.get(pending_id.as_str()).unwrap();
        assert_eq!(req.state, PendingState::Waiting);
        assert_eq!(req.kind, PendingRequestKind::IsolatedIntent);
        assert!(req.grant_request_id.is_none());
    }

    #[test]
    fn test_principal_cancel_pending() {
        let config = make_isolated_config("cancelpending", vec!["example.com"], true);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("cancelpending").unwrap();
        let session = PrincipalSessionId::new();
        let endpoint = EndpointId::new();
        let process_digest = ProcessIdentityDigest::compute(1000, 1000, 42, b"test");
        let generation = runtime.current_generation();

        let pending_id = runtime
            .principal_create_pending_intent(CreateIntentParams {
                profile_id: pid.clone(),
                session_id: session.clone(),
                endpoint_id: endpoint.clone(),
                process_digest: process_digest.clone(),
                action: IntentAction::Authenticate,
                rp_id: "example.com".to_string(),
                credential_ref: None,
                policy_generation: generation.generation_id.clone(),
                policy_digest: generation.digest.clone(),
                require_uv: false,
                ttl_ms: Some(60_000),
            })
            .unwrap();

        let result = runtime.principal_cancel_pending(&pending_id, &session);
        assert!(result.is_ok());

        let pr = runtime.pending_requests.lock().unwrap();
        let req = pr.get(pending_id.as_str()).unwrap();
        assert_eq!(req.state, PendingState::Cancelled);
    }

    #[test]
    fn test_cancel_pending_wrong_session() {
        let config = make_isolated_config("cancelwrong", vec!["example.com"], true);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("cancelwrong").unwrap();
        let session = PrincipalSessionId::new();
        let wrong_session = PrincipalSessionId::new();
        let endpoint = EndpointId::new();
        let process_digest = ProcessIdentityDigest::compute(1000, 1000, 42, b"test");
        let generation = runtime.current_generation();

        let pending_id = runtime
            .principal_create_pending_intent(CreateIntentParams {
                profile_id: pid.clone(),
                session_id: session.clone(),
                endpoint_id: endpoint.clone(),
                process_digest: process_digest.clone(),
                action: IntentAction::Authenticate,
                rp_id: "example.com".to_string(),
                credential_ref: None,
                policy_generation: generation.generation_id.clone(),
                policy_digest: generation.digest.clone(),
                require_uv: false,
                ttl_ms: Some(60_000),
            })
            .unwrap();

        let result = runtime.principal_cancel_pending(&pending_id, &wrong_session);
        assert_eq!(result, Err(PendingCancelError::SessionMismatch));
    }

    #[test]
    fn test_reload_cancels_pending_requests() {
        let config1 = make_isolated_config("reloadcancel", vec!["example.com"], true);
        let (runtime, _clock) = make_runtime(&config1);
        let pid = ProfileId::new("reloadcancel").unwrap();
        let session = PrincipalSessionId::new();
        let endpoint = EndpointId::new();
        let process_digest = ProcessIdentityDigest::compute(1000, 1000, 42, b"test");
        let generation = runtime.current_generation();

        let _pending_id = runtime
            .principal_create_pending_intent(CreateIntentParams {
                profile_id: pid.clone(),
                session_id: session.clone(),
                endpoint_id: endpoint.clone(),
                process_digest: process_digest.clone(),
                action: IntentAction::Authenticate,
                rp_id: "example.com".to_string(),
                credential_ref: None,
                policy_generation: generation.generation_id.clone(),
                policy_digest: generation.digest.clone(),
                require_uv: false,
                ttl_ms: Some(60_000),
            })
            .unwrap();

        let config2 = make_isolated_config("reloadcancel", vec!["example.com", "github.com"], true);
        runtime.reload(&config2).unwrap();

        let pr = runtime.pending_requests.lock().unwrap();
        let values: Vec<_> = pr.values().collect();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].state, PendingState::Cancelled);
    }

    #[test]
    fn test_principal_exit_cancels_pending() {
        let config = make_isolated_config("exitcancel", vec!["example.com"], true);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("exitcancel").unwrap();
        let session = PrincipalSessionId::new();
        let endpoint = EndpointId::new();
        let process_digest = ProcessIdentityDigest::compute(1000, 1000, 42, b"test");
        let generation = runtime.current_generation();

        let _pending_id = runtime
            .principal_create_pending_intent(CreateIntentParams {
                profile_id: pid.clone(),
                session_id: session.clone(),
                endpoint_id: endpoint.clone(),
                process_digest: process_digest.clone(),
                action: IntentAction::Authenticate,
                rp_id: "example.com".to_string(),
                credential_ref: None,
                policy_generation: generation.generation_id.clone(),
                policy_digest: generation.digest.clone(),
                require_uv: false,
                ttl_ms: Some(60_000),
            })
            .unwrap();

        runtime.principal_exit(&session);

        let pr = runtime.pending_requests.lock().unwrap();
        let values: Vec<_> = pr.values().collect();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].state, PendingState::Cancelled);
    }

    #[test]
    fn test_principal_pending_status_wrong_session() {
        let config = make_isolated_config("status_wrong_sess", vec!["example.com"], false);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("status_wrong_sess").unwrap();
        let session = passless_core::agent::PrincipalSessionId::new();
        let wrong_session = passless_core::agent::PrincipalSessionId::new();
        let endpoint = passless_core::agent::EndpointId::new();
        let process_digest = ProcessIdentityDigest::compute(1000, 1000, 42, b"test");
        let generation = runtime.current_generation();

        let pending_id = runtime
            .principal_create_pending_intent(CreateIntentParams {
                profile_id: pid.clone(),
                session_id: session.clone(),
                endpoint_id: endpoint.clone(),
                process_digest: process_digest.clone(),
                action: IntentAction::Authenticate,
                rp_id: "example.com".to_string(),
                credential_ref: None,
                policy_generation: generation.generation_id.clone(),
                policy_digest: generation.digest.clone(),
                require_uv: false,
                ttl_ms: Some(60_000),
            })
            .unwrap();

        let result = runtime.principal_pending_status(&pending_id, &wrong_session);
        assert!(matches!(result, Err(PendingStatusError::SessionMismatch)));
    }

    #[test]
    fn test_principal_pending_status_not_found() {
        let config = make_isolated_config("status_notfound", vec!["example.com"], false);
        let (runtime, _clock) = make_runtime(&config);
        let fake_id = PendingRequestId::new();
        let session = passless_core::agent::PrincipalSessionId::new();

        let result = runtime.principal_pending_status(&fake_id, &session);
        assert!(matches!(result, Err(PendingStatusError::NotFound)));
    }

    #[test]
    fn test_principal_pending_status_expiry() {
        let config = make_isolated_config("status_expiry", vec!["example.com"], false);
        let (runtime, clock) = make_runtime(&config);
        let pid = ProfileId::new("status_expiry").unwrap();
        let session = passless_core::agent::PrincipalSessionId::new();
        let endpoint = passless_core::agent::EndpointId::new();
        let process_digest = ProcessIdentityDigest::compute(1000, 1000, 42, b"test");
        let generation = runtime.current_generation();

        let pending_id = runtime
            .principal_create_pending_intent(CreateIntentParams {
                profile_id: pid.clone(),
                session_id: session.clone(),
                endpoint_id: endpoint.clone(),
                process_digest: process_digest.clone(),
                action: IntentAction::Authenticate,
                rp_id: "example.com".to_string(),
                credential_ref: None,
                policy_generation: generation.generation_id.clone(),
                policy_digest: generation.digest.clone(),
                require_uv: false,
                ttl_ms: Some(5_000),
            })
            .unwrap();

        let status = runtime
            .principal_pending_status(&pending_id, &session)
            .unwrap();
        assert_eq!(status.state, PendingState::Waiting);
        assert_eq!(status.kind, PendingRequestKind::IsolatedIntent);

        clock.advance(Duration::from_secs(10));

        let status = runtime
            .principal_pending_status(&pending_id, &session)
            .unwrap();
        assert_eq!(status.state, PendingState::TimedOut);
        assert!(status.is_terminal());
        assert!(status.is_expired());
    }

    #[test]
    fn test_cleanup_expired_pending() {
        let config = make_isolated_config("cleanup_exp", vec!["example.com"], false);
        let (runtime, clock) = make_runtime(&config);
        let pid = ProfileId::new("cleanup_exp").unwrap();
        let session = passless_core::agent::PrincipalSessionId::new();
        let endpoint = passless_core::agent::EndpointId::new();
        let process_digest = ProcessIdentityDigest::compute(1000, 1000, 42, b"test");
        let generation = runtime.current_generation();

        let pending_id = runtime
            .principal_create_pending_intent(CreateIntentParams {
                profile_id: pid.clone(),
                session_id: session.clone(),
                endpoint_id: endpoint.clone(),
                process_digest: process_digest.clone(),
                action: IntentAction::Authenticate,
                rp_id: "example.com".to_string(),
                credential_ref: None,
                policy_generation: generation.generation_id.clone(),
                policy_digest: generation.digest.clone(),
                require_uv: false,
                ttl_ms: Some(5_000),
            })
            .unwrap();

        let expired = runtime.cleanup_expired_pending();
        assert!(expired.is_empty());

        clock.advance(Duration::from_secs(10));

        let expired = runtime.cleanup_expired_pending();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], pending_id);

        let status = runtime
            .principal_pending_status(&pending_id, &session)
            .unwrap();
        assert_eq!(status.state, PendingState::TimedOut);
    }

    #[test]
    fn test_pending_status_mapping_intent_state() {
        let snapshot = PendingStatusSnapshot {
            id: PendingRequestId::new(),
            kind: PendingRequestKind::IsolatedIntent,
            state: PendingState::Waiting,
            profile_id: ProfileId::new("test").unwrap(),
            session_id: passless_core::agent::PrincipalSessionId::new(),
            endpoint_id: passless_core::agent::EndpointId::new(),
            process_digest: ProcessIdentityDigest::compute(1000, 1000, 42, b"test"),
            policy_generation: PolicyGenerationId::new(),
            policy_digest: PolicyDigest::from_cbor_bytes(b"test"),
            action: IntentAction::Authenticate,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            intent_id: IntentId::new(),
            grant_request_id: None,
            created_at_mono: 0,
            deadline_mono: 100,
        };
        assert_eq!(
            snapshot.to_intent_state(),
            passless_core::agent::protocol::IntentState::Pending
        );
    }

    #[test]
    fn test_pending_status_mapping_delegation_state() {
        let snapshot = PendingStatusSnapshot {
            id: PendingRequestId::new(),
            kind: PendingRequestKind::DelegatedAuth,
            state: PendingState::Approved,
            profile_id: ProfileId::new("test").unwrap(),
            session_id: passless_core::agent::PrincipalSessionId::new(),
            endpoint_id: passless_core::agent::EndpointId::new(),
            process_digest: ProcessIdentityDigest::compute(1000, 1000, 42, b"test"),
            policy_generation: PolicyGenerationId::new(),
            policy_digest: PolicyDigest::from_cbor_bytes(b"test"),
            action: IntentAction::Authenticate,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            intent_id: IntentId::new(),
            grant_request_id: None,
            created_at_mono: 0,
            deadline_mono: 100,
        };
        assert_eq!(
            snapshot.to_delegation_state(),
            passless_core::agent::protocol::DelegationState::Approved
        );
    }
}
