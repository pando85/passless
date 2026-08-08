use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use passless_core::agent::config::{ANY_RP_ID, validate_rp_id};
use passless_core::agent::protocol::IntentAction;
use passless_core::agent::{
    AgentAuthorization, AgentCeremonyPolicy, AgentConfig, AgentMode, AgentProfileConfig,
    AgentRpRule, CredentialRef, EndpointId, GrantId, IntentId, PendingRequestId, Policy,
    PolicyDigest, PolicyGenerationId, PolicyParams, PrincipalSessionId, ProfileId,
};

use super::browser::Clock;
use super::grant::{
    CeremonyId, ClaimIntent, GrantError, GrantRegistry, GrantRequestId, GrantRequestParams,
};
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
    pub require_uv: bool,
    pub registration_allowed: bool,
    pub allowed_actions: BTreeSet<String>,
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

    pub fn ceremony_policy(
        &self,
        rp_id: &str,
        action: &IntentAction,
    ) -> Option<&AgentCeremonyPolicy> {
        let normalized = validate_rp_id(rp_id).ok()?;
        let rule = self
            .rules
            .iter()
            .find(|rule| rule.rp_id.trim().eq_ignore_ascii_case(&normalized))
            .or_else(|| {
                self.rules
                    .iter()
                    .find(|rule| rule.rp_id.trim() == ANY_RP_ID)
            })?;
        Some(match action {
            IntentAction::Register => &rule.register,
            IntentAction::Authenticate => &rule.authenticate,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PolicyGenerationSnapshot {
    pub generation_id: PolicyGenerationId,
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

impl PendingPrincipalRequest {
    fn matches_tuple(&self, tuple: &CeremonyTuple) -> bool {
        self.profile_id == tuple.profile_id
            && self.session_id == tuple.session_id
            && self.endpoint_id == tuple.endpoint_id
            && self.process_digest == tuple.process_digest
            && self.policy_generation == tuple.policy_generation
            && self.policy_digest == tuple.policy_digest
            && self.action == tuple.action
            && self.rp_id == tuple.rp_id.trim().to_ascii_lowercase()
            && match (&tuple.credential_ref, &self.credential_ref) {
                (Some(a), Some(b)) => a == b,
                (None, None) => true,
                _ => false,
            }
    }
}

pub(crate) struct CeremonyTuple {
    pub profile_id: ProfileId,
    pub session_id: PrincipalSessionId,
    pub endpoint_id: EndpointId,
    pub process_digest: ProcessIdentityDigest,
    pub policy_generation: PolicyGenerationId,
    pub policy_digest: PolicyDigest,
    pub action: IntentAction,
    pub rp_id: String,
    pub credential_ref: Option<CredentialRef>,
}

pub(crate) struct TrustedApproval {
    _sealed: (),
}

impl TrustedApproval {
    pub(crate) fn new() -> Self {
        Self { _sealed: () }
    }
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
    registration_grants: Mutex<HashMap<String, super::grant::RegistrationGrantRegistry>>,
    pending: Mutex<HashMap<String, PendingAuthorization>>,
    pending_requests: Mutex<HashMap<String, PendingPrincipalRequest>>,
    clock: Arc<dyn Clock>,
}

impl PolicyRuntime {
    pub fn new(
        config: &AgentConfig,
        clock: Arc<dyn Clock>,
        monotonic_clock: Arc<dyn MonotonicClock>,
    ) -> Result<Self, PolicyRuntimeError> {
        let generation = Self::compile_generation(config, clock.monotonic_secs())?;
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
            );
            grant_registries.insert(snapshot.profile_id.as_str().to_string(), registry);
        }

        Ok(Self {
            current: RwLock::new(gen_arc),
            intents: Mutex::new(intent_store),
            grants: Mutex::new(grant_registries),
            registration_grants: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            pending_requests: Mutex::new(HashMap::new()),
            clock,
        })
    }

    pub fn compile_generation(
        config: &AgentConfig,
        now_mono: u64,
    ) -> Result<PolicyGenerationSnapshot, PolicyRuntimeError> {
        let mut snapshots = Vec::new();

        for (name, profile_config) in &config.profiles {
            let profile_id = ProfileId::new(name.as_str()).map_err(|e| {
                PolicyRuntimeError::Compilation(format!("invalid profile id '{}': {}", name, e))
            })?;

            let snapshot = Self::compile_snapshot(&profile_id, profile_config)?;
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
            snapshots,
            digest,
            created_at_mono: now_mono,
        })
    }

    fn compile_snapshot(
        profile_id: &ProfileId,
        config: &AgentProfileConfig,
    ) -> Result<PolicySnapshot, PolicyRuntimeError> {
        let mut rules = config.effective_rules();
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
            .any(|rule| rule.authenticate.authorization != AgentAuthorization::Deny)
        {
            allowed_actions.insert("authenticate".to_string());
        }
        if rules
            .iter()
            .any(|rule| rule.register.authorization != AgentAuthorization::Deny)
        {
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
            registration_allowed: config.registration_allowed || config.allows_registration(),
            require_uv: config.require_uv,
            max_concurrent_grants,
            max_grant_ttl: max_grant_ttl_secs,
            max_session_ttl: max_session_ttl_secs,
            principal_user: config.principal_user.clone(),
            device_name: config.device.name.clone(),
            device_phys: config.device.phys.clone(),
            device_uniq: config.device.uniq.clone(),
            device_vendor_id: config.device.vendor_id,
            device_product_id: config.device.product_id,
            start_url: config.start_url.clone(),
            browser_argv: config.browser_command.clone().unwrap_or_default(),
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
            require_uv: config.require_uv,
            registration_allowed: config.registration_allowed || config.allows_registration(),
            allowed_actions,
            rules,
        })
    }

    pub fn current_generation(&self) -> Arc<PolicyGenerationSnapshot> {
        self.current.read().unwrap().clone()
    }

    pub fn ceremony_policy(
        &self,
        profile_id: &ProfileId,
        generation_id: &PolicyGenerationId,
        generation_digest: &PolicyDigest,
        rp_id: &str,
        action: &IntentAction,
    ) -> Option<AgentCeremonyPolicy> {
        let generation = self.current.read().unwrap();
        if generation.generation_id != *generation_id || generation.digest != *generation_digest {
            return None;
        }
        generation
            .find_snapshot(profile_id)
            .and_then(|snapshot| snapshot.ceremony_policy(rp_id, action))
            .cloned()
    }

    pub fn digest(&self) -> PolicyDigest {
        self.current.read().unwrap().digest.clone()
    }

    pub fn authorize_registration(
        &self,
        profile_id: &ProfileId,
        rp_id: &str,
    ) -> (Outcome, ReasonCode) {
        let generation = self.current.read().unwrap();
        let snapshot = match generation.find_snapshot(profile_id) {
            Some(s) => s,
            None => return (Outcome::Deny, ReasonCode::ProfileNotFound),
        };

        if !snapshot.registration_allowed {
            return (Outcome::Deny, ReasonCode::DelegatedRegistrationDenied);
        }

        let normalized = rp_id.trim().to_ascii_lowercase();
        match snapshot
            .rules
            .iter()
            .find(|rule| rule.rp_id.trim().to_ascii_lowercase() == normalized)
        {
            Some(rule) => {
                if rule.register.authorization == AgentAuthorization::Deny {
                    (Outcome::Deny, ReasonCode::ActionNotAllowed)
                } else {
                    (Outcome::Allow, ReasonCode::Allowed)
                }
            }
            None => (Outcome::Deny, ReasonCode::RpIdNotExactMatch),
        }
    }

    pub fn request_registration_grant(
        &self,
        profile_id: ProfileId,
        rp_id: String,
        ttl_secs: u64,
    ) -> Result<passless_core::agent::RegistrationGrantId, super::grant::GrantError> {
        let profile_key = profile_id.as_str().to_string();
        let mut reg_grants = self.registration_grants.lock().unwrap();

        let registry = reg_grants.entry(profile_key).or_insert_with(|| {
            super::grant::RegistrationGrantRegistry::new(Arc::clone(&self.clock), 300)
        });

        let session_id = passless_core::agent::PrincipalSessionId::new();
        let endpoint_id = passless_core::agent::EndpointId::new();

        registry.request_registration(
            profile_id,
            session_id,
            endpoint_id,
            [0u8; 32],
            rp_id,
            ttl_secs,
        )
    }

    pub fn active_registration_grant(
        &self,
        profile_id: &ProfileId,
        rp_id: &str,
    ) -> Option<super::grant::RegistrationGrantSnapshot> {
        let normalized = super::grant::normalize_rp_id(rp_id).ok()?;
        let now = self.clock.monotonic_secs();
        let reg_grants = self.registration_grants.lock().ok()?;
        let registry = reg_grants.get(profile_id.as_str())?;
        registry
            .list_all_snapshots()
            .into_iter()
            .filter(|grant| {
                grant.state == super::grant::GrantState::Active
                    && grant.rp_id == normalized
                    && grant.expiry_mono > now
            })
            .max_by_key(|grant| grant.issued_at_mono)
    }

    pub fn consume_registration_grant(
        &self,
        profile_id: &ProfileId,
        grant_id: &passless_core::agent::RegistrationGrantId,
    ) -> Result<(), super::grant::GrantError> {
        let reg_grants = self.registration_grants.lock().unwrap();
        let registry = reg_grants
            .get(profile_id.as_str())
            .ok_or_else(|| super::grant::GrantError::RegistrationGrantNotFound(grant_id.clone()))?;
        registry.revoke_registration(grant_id)
    }

    pub fn resolve_registration_grant(
        &self,
        profile_id: &ProfileId,
        grant_id: &passless_core::agent::RegistrationGrantId,
        rp_id: &str,
    ) -> Option<super::grant::RegistrationGrantSnapshot> {
        let profile_key = profile_id.as_str().to_string();
        let reg_grants = self.registration_grants.lock().unwrap();
        let registry = reg_grants.get(&profile_key)?;
        registry.resolve_registration_grant(grant_id, rp_id)
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
        let now_mono = self.clock.monotonic_secs();
        let new_generation = Self::compile_generation(config, now_mono)?;
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
    ///    c. Isolated registration: requires approved one-shot intent
    ///    d. Isolated authentication: requires approved one-shot intent
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

        let ceremony_policy = match snapshot.ceremony_policy(&request.rp_id, &request.action) {
            Some(policy) => policy,
            None => {
                return (
                    Decision::deny(ReasonCode::ActionNotAllowed, OperatorAction::None),
                    None,
                );
            }
        };
        if ceremony_policy.authorization == AgentAuthorization::Deny {
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

        if snapshot.require_uv && !request.uv_enforced {
            let _ = intents.rollback_claim(&intent_id);
            return (
                Decision::deny(ReasonCode::UvRequired, OperatorAction::VerifyUser),
                None,
            );
        }

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

    /// Ceremony-only resolution of a pending principal request.
    ///
    /// Lock ordering (documented): pending_requests -> intents -> grants.
    /// All three locks are held for the duration to ensure atomic resolution.
    /// This method MUST only be called from the agent ceremony module after
    /// a successful trusted user prompt.
    ///
    /// Finds exactly one pending request matching the full CTAP tuple,
    /// re-evaluates policy, and after the externally supplied trusted approval
    /// atomically approves the intent and (for delegated auth) creates/approves
    /// the grant. Returns a typed BoundApprovalResult for use with authorize_bound.
    pub(crate) fn ceremony_resolve_pending(
        &self,
        tuple: &CeremonyTuple,
        _approval: &TrustedApproval,
    ) -> Result<BoundApprovalResult, CeremonyResolveError> {
        let mut pending_requests = self.pending_requests.lock().unwrap();

        let matching_keys: Vec<String> = pending_requests
            .values()
            .filter(|pr| pr.state == PendingState::Waiting && pr.matches_tuple(tuple))
            .map(|pr| pr.id.as_str().to_string())
            .collect();

        match matching_keys.len() {
            0 => return Err(CeremonyResolveError::PendingNotFound),
            n if n > 1 => return Err(CeremonyResolveError::AmbiguousPending(n)),
            _ => {}
        }

        let key = matching_keys.into_iter().next().unwrap();
        let pending_req = pending_requests.get(&key).unwrap();

        match pending_req.state {
            PendingState::Waiting => {}
            PendingState::Cancelled => return Err(CeremonyResolveError::Cancelled),
            _ => return Err(CeremonyResolveError::AlreadyResolved),
        }

        let now_mono = self.clock.monotonic_secs();
        if now_mono >= pending_req.deadline_mono {
            if let Some(req) = pending_requests.get_mut(&key) {
                req.state = PendingState::TimedOut;
            }
            return Err(CeremonyResolveError::TimedOut);
        }

        let generation = self.current.read().unwrap().clone();
        if tuple.policy_generation != generation.generation_id
            || tuple.policy_digest != generation.digest
        {
            if let Some(req) = pending_requests.get_mut(&key) {
                req.state = PendingState::Cancelled;
            }
            return Err(CeremonyResolveError::PolicyDenied(
                ReasonCode::GenerationStale,
            ));
        }

        let snapshot = match generation.find_snapshot(&tuple.profile_id) {
            Some(s) => s,
            None => {
                if let Some(req) = pending_requests.get_mut(&key) {
                    req.state = PendingState::Cancelled;
                }
                return Err(CeremonyResolveError::PolicyDenied(
                    ReasonCode::ProfileNotFound,
                ));
            }
        };

        if !snapshot.is_rp_exact_match(&tuple.rp_id) {
            return Err(CeremonyResolveError::PolicyDenied(
                ReasonCode::RpIdNotExactMatch,
            ));
        }

        if let Some(ref cred_ref) = tuple.credential_ref
            && !snapshot.credential_refs.is_empty()
            && !snapshot.credential_ref_set().contains(cred_ref)
        {
            return Err(CeremonyResolveError::PolicyDenied(
                ReasonCode::CredentialNotExactMatch,
            ));
        }

        if !snapshot.action_allowed(&tuple.action) {
            return Err(CeremonyResolveError::PolicyDenied(
                ReasonCode::ActionNotAllowed,
            ));
        }

        let mut intents = self.intents.lock().unwrap();
        let authority = super::intent::admin_authority();

        let saved_intent_id = pending_req.intent_id.clone();
        let saved_kind = pending_req.kind;
        let saved_grant_request_id = pending_req.grant_request_id.clone();
        let saved_profile_id = pending_req.profile_id.clone();
        let saved_session_id = pending_req.session_id.clone();
        let saved_endpoint_id = pending_req.endpoint_id.clone();
        let saved_process_digest = pending_req.process_digest.clone();
        let saved_policy_generation = pending_req.policy_generation.clone();
        let saved_policy_digest = pending_req.policy_digest.clone();
        let saved_action = pending_req.action.clone();
        let saved_rp_id = pending_req.rp_id.clone();
        let saved_credential_ref = pending_req.credential_ref.clone();

        intents
            .approve(&saved_intent_id, &authority)
            .map_err(|e| CeremonyResolveError::IntentApprovalFailed(e.to_string()))?;

        let grant_id = if saved_kind == PendingRequestKind::DelegatedAuth {
            let grant_request_id = saved_grant_request_id.ok_or_else(|| {
                CeremonyResolveError::GrantFailed("missing grant request id".into())
            })?;
            let profile_key = saved_profile_id.as_str().to_string();
            let mut grants_map = self.grants.lock().unwrap();
            let grants = grants_map
                .get_mut(&profile_key)
                .ok_or_else(|| CeremonyResolveError::GrantFailed("profile not found".into()))?;
            let gid = if let Some(existing) = grants.resolved_grant_id(&grant_request_id) {
                existing
            } else {
                grants
                    .approve_grant(&grant_request_id, &authority)
                    .map_err(|e| CeremonyResolveError::GrantFailed(e.to_string()))?
            };
            Some(gid)
        } else {
            None
        };

        if let Some(req) = pending_requests.get_mut(&key) {
            req.state = PendingState::Approved;
        }

        Ok(BoundApprovalResult {
            intent_id: saved_intent_id,
            grant_id,
            profile_id: saved_profile_id,
            session_id: saved_session_id,
            endpoint_id: saved_endpoint_id,
            process_digest: saved_process_digest,
            policy_generation: saved_policy_generation,
            policy_digest: saved_policy_digest,
            action: saved_action,
            rp_id: saved_rp_id,
            credential_ref: saved_credential_ref,
        })
    }

    /// Ceremony-only denial of a pending principal request.
    ///
    /// Lock ordering (documented): pending_requests -> intents -> grants.
    /// Terminally resolves the pending state to Denied.
    pub(crate) fn ceremony_deny_pending(
        &self,
        tuple: &CeremonyTuple,
    ) -> Result<(), CeremonyResolveError> {
        let mut pending_requests = self.pending_requests.lock().unwrap();

        let matching_keys: Vec<String> = pending_requests
            .values()
            .filter(|pr| pr.state == PendingState::Waiting && pr.matches_tuple(tuple))
            .map(|pr| pr.id.as_str().to_string())
            .collect();

        match matching_keys.len() {
            0 => return Err(CeremonyResolveError::PendingNotFound),
            n if n > 1 => return Err(CeremonyResolveError::AmbiguousPending(n)),
            _ => {}
        }

        let key = matching_keys.into_iter().next().unwrap();
        let pending_req = pending_requests.get(&key).unwrap();

        match pending_req.state {
            PendingState::Waiting => {}
            PendingState::Cancelled => return Err(CeremonyResolveError::Cancelled),
            _ => return Err(CeremonyResolveError::AlreadyResolved),
        }

        let mut intents = self.intents.lock().unwrap();
        let authority = super::intent::admin_authority();
        let _ = intents.deny(&pending_req.intent_id, &authority);

        if let Some(ref grant_request_id) = pending_req.grant_request_id {
            let profile_key = pending_req.profile_id.as_str().to_string();
            let mut grants_map = self.grants.lock().unwrap();
            if let Some(grants) = grants_map.get_mut(&profile_key) {
                if let Some(grant_id) = grants.resolved_grant_id(grant_request_id) {
                    let _ = grants.revoke_grant(&grant_id, &authority);
                }
                let _ = grants.cancel_request(grant_request_id);
            }
        }

        if let Some(req) = pending_requests.get_mut(&key) {
            req.state = PendingState::Denied;
        }

        Ok(())
    }

    /// Authorize using a pre-approved BoundApprovalResult from ceremony_resolve_pending.
    ///
    /// Verifies the bound result matches the request, then claims the intent
    /// and grant atomically. Lock ordering: intents -> grants -> pending.
    pub fn authorize_bound(
        &self,
        bound: &BoundApprovalResult,
        request: &AuthorizationRequest,
    ) -> (Decision, Option<AuthorizationHandle>) {
        if bound.profile_id != request.profile_id
            || bound.session_id != request.session_id
            || bound.endpoint_id != request.endpoint_id
            || bound.process_digest != request.process_digest
            || bound.policy_generation != request.policy_generation_id
            || bound.policy_digest != request.policy_digest
            || bound.action != request.action
        {
            return (
                Decision::deny(ReasonCode::SessionMismatch, OperatorAction::Retry),
                None,
            );
        }

        let bound_rp = bound.rp_id.trim().to_ascii_lowercase();
        let req_rp = request.rp_id.trim().to_ascii_lowercase();
        if bound_rp != req_rp {
            return (
                Decision::deny(ReasonCode::RpIdNotExactMatch, OperatorAction::Retry),
                None,
            );
        }

        match (&bound.credential_ref, &request.credential_ref) {
            (Some(a), Some(b)) => {
                if a != b {
                    return (
                        Decision::deny(ReasonCode::CredentialNotExactMatch, OperatorAction::Retry),
                        None,
                    );
                }
            }
            (None, None) => {}
            _ => {
                return (
                    Decision::deny(ReasonCode::CredentialNotExactMatch, OperatorAction::Retry),
                    None,
                );
            }
        }

        let generation = self.current.read().unwrap().clone();
        if bound.policy_generation != generation.generation_id
            || bound.policy_digest != generation.digest
        {
            return (
                Decision::deny(ReasonCode::GenerationStale, OperatorAction::ReloadPolicy),
                None,
            );
        }

        let snapshot = match generation.find_snapshot(&bound.profile_id) {
            Some(s) => s,
            None => {
                return (
                    Decision::deny(ReasonCode::ProfileNotFound, OperatorAction::ContactAdmin),
                    None,
                );
            }
        };

        if snapshot.require_uv && !request.uv_enforced {
            return (
                Decision::deny(ReasonCode::UvRequired, OperatorAction::VerifyUser),
                None,
            );
        }

        let mut intents = self.intents.lock().unwrap();

        let intent_id = match intents.claim_approved(&IntentQueryParams {
            profile_id: bound.profile_id.clone(),
            session_id: bound.session_id.clone(),
            endpoint_id: bound.endpoint_id.clone(),
            process_digest: bound.process_digest.clone(),
            policy_generation: Some(bound.policy_generation.clone()),
            policy_digest: bound.policy_digest.clone(),
            action: bound.action.clone(),
            rp_id: bound.rp_id.clone(),
            credential_ref: bound.credential_ref.clone(),
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

        let ceremony_id = if let Some(ref grant_id) = bound.grant_id {
            let mut grants_map = self.grants.lock().unwrap();
            let profile_key = bound.profile_id.as_str().to_string();
            let grants = match grants_map.get_mut(&profile_key) {
                Some(g) => g,
                None => {
                    let _ = intents.rollback_claim(&intent_id);
                    return (
                        Decision::deny(ReasonCode::ProfileNotFound, OperatorAction::ContactAdmin),
                        None,
                    );
                }
            };

            let claim_intent = ClaimIntent {
                action: match bound.action {
                    IntentAction::Register => "register".to_string(),
                    IntentAction::Authenticate => "authenticate".to_string(),
                },
                rp_id: bound.rp_id.trim().to_ascii_lowercase(),
                credential_ref: bound
                    .credential_ref
                    .clone()
                    .unwrap_or_else(|| CredentialRef::with_default_domain(b"")),
            };

            match grants.claim_for_authorize(grant_id, &bound.session_id, claim_intent) {
                Ok(cid) => cid,
                Err(_) => {
                    let _ = intents.rollback_claim(&intent_id);
                    return (
                        Decision::deny(ReasonCode::PartialClaimFailed, OperatorAction::Retry),
                        None,
                    );
                }
            }
        } else {
            CeremonyId::new()
        };

        let handle = AuthorizationHandle {
            ceremony_id: ceremony_id.clone(),
            grant_id: bound.grant_id.clone(),
            intent_id: Some(intent_id.clone()),
            profile_id: bound.profile_id.clone(),
            session_id: bound.session_id.clone(),
            endpoint_id: bound.endpoint_id.clone(),
            process_digest: bound.process_digest.clone(),
            policy_generation: bound.policy_generation.clone(),
            policy_digest: bound.policy_digest.clone(),
            action: bound.action.clone(),
            rp_id: bound.rp_id.clone(),
            credential_ref: bound.credential_ref.clone(),
        };

        let pending_auth = PendingAuthorization {
            ceremony_id,
            grant_id: bound.grant_id.clone(),
            intent_id: Some(intent_id),
            profile_id: bound.profile_id.clone(),
            session_id: bound.session_id.clone(),
            endpoint_id: bound.endpoint_id.clone(),
            process_digest: bound.process_digest.clone(),
            policy_generation: bound.policy_generation.clone(),
            policy_digest: bound.policy_digest.clone(),
            action: bound.action.clone(),
            rp_id: bound.rp_id.clone(),
            credential_ref: bound.credential_ref.clone(),
            invalidated: false,
        };

        drop(intents);

        {
            let mut pending = self.pending.lock().unwrap();
            pending.insert(pending_auth.ceremony_id.as_str().to_string(), pending_auth);
        }

        (Decision::allow(ReasonCode::Allowed), Some(handle))
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
        AgentAuthorization, AgentCeremonyPolicy, AgentConfig, AgentMode, AgentProfileConfig,
        AgentRpRule, AgentStorageConfig, CredentialRef, DeviceIdentity, ProfileId,
        UserPresenceSource, UserVerificationSource,
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

    fn test_device(name_suffix: &str, vid: u16, pid: u16) -> DeviceIdentity {
        DeviceIdentity {
            name: format!("passless-agent-{}", name_suffix),
            phys: format!("{}-phys", name_suffix),
            uniq: format!("{}-uniq", name_suffix),
            vendor_id: vid,
            product_id: pid,
        }
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
                credential_selection: passless_core::agent::config::CredentialSelection::Single,
                human_verification_prompt:
                    passless_core::agent::config::HumanVerificationPrompt::Always,
                mode: AgentMode::Isolated,
                principal_user: "test-user".to_string(),
                rp_ids: rp_ids.into_iter().map(|s| s.to_string()).collect(),
                require_uv: false,
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: PathBuf::from(format!("/tmp/test-{}/creds", profile_name)),
                    pin_path: PathBuf::from(format!("/tmp/test-{}/pin", profile_name)),
                }),
                registration_allowed,
                rules: vec![],
                device: test_device(profile_name, 0x1234, 0x5678),
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
        }
    }

    fn test_cred_ref(seed: &[u8]) -> CredentialRef {
        CredentialRef::with_default_domain(seed)
    }

    fn make_runtime(config: &AgentConfig) -> (PolicyRuntime, Arc<MockClock>) {
        let clock = test_clock();
        let runtime = PolicyRuntime::new(config, clock.clone(), clock.clone()).unwrap();
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

    #[test]
    fn test_compile_isolated_snapshot() {
        let config = make_isolated_config("test", vec!["example.com"], true);
        let _clock = test_clock();
        let generation = PolicyRuntime::compile_generation(&config, 0).unwrap();

        assert_eq!(generation.snapshots.len(), 1);
        let s = &generation.snapshots[0];
        assert_eq!(s.profile_id.as_str(), "test");
        assert_eq!(s.mode, AgentMode::Isolated);
        assert_eq!(s.normalized_rp_ids, vec!["example.com"]);
        assert!(s.registration_allowed);
        assert!(s.allowed_actions.contains("register"));
        assert!(s.allowed_actions.contains("authenticate"));
    }

    #[test]
    fn test_snapshot_deterministic_digest() {
        let config = make_isolated_config("det", vec!["example.com"], false);
        let gen1 = PolicyRuntime::compile_generation(&config, 0).unwrap();
        let gen2 = PolicyRuntime::compile_generation(&config, 0).unwrap();

        assert_eq!(gen1.snapshots[0].digest, gen2.snapshots[0].digest);
    }

    #[test]
    fn test_compile_explicit_allow_and_deny_rules() {
        let mut config = make_isolated_config("rules", vec![], false);
        let profile = config.profiles.get_mut("rules").unwrap();
        profile.rules = vec![AgentRpRule {
            rp_id: "example.com".to_string(),
            register: AgentCeremonyPolicy::deny(),
            authenticate: AgentCeremonyPolicy {
                authorization: AgentAuthorization::Allow,
                user_presence: UserPresenceSource::Agent,
                user_verification: UserVerificationSource::Agent,
            },
        }];

        let generation = PolicyRuntime::compile_generation(&config, 0).unwrap();
        let snapshot = &generation.snapshots[0];
        assert_eq!(
            snapshot
                .ceremony_policy("example.com", &IntentAction::Authenticate)
                .unwrap()
                .authorization,
            AgentAuthorization::Allow
        );
        assert_eq!(
            snapshot
                .ceremony_policy("example.com", &IntentAction::Register)
                .unwrap()
                .authorization,
            AgentAuthorization::Deny
        );
        assert!(snapshot.action_allowed(&IntentAction::Authenticate));
        assert!(!snapshot.action_allowed(&IntentAction::Register));
    }

    #[test]
    fn test_compile_same_user_wildcard_policy_with_exact_override() {
        let mut config = make_isolated_config("wildcard", vec![], false);
        let profile = config.profiles.get_mut("wildcard").unwrap();
        profile.mode = AgentMode::SameUser;
        profile.storage = None;
        profile.rules = vec![
            AgentRpRule {
                rp_id: ANY_RP_ID.to_string(),
                register: AgentCeremonyPolicy::deny(),
                authenticate: AgentCeremonyPolicy::autonomous(),
            },
            AgentRpRule {
                rp_id: "bank.example.com".to_string(),
                register: AgentCeremonyPolicy::deny(),
                authenticate: AgentCeremonyPolicy::supervised(),
            },
        ];

        let generation = PolicyRuntime::compile_generation(&config, 0).unwrap();
        let snapshot = &generation.snapshots[0];

        assert!(snapshot.is_rp_exact_match("github.com"));
        assert_eq!(
            snapshot
                .ceremony_policy("github.com", &IntentAction::Authenticate)
                .unwrap(),
            &AgentCeremonyPolicy::autonomous()
        );
        assert_eq!(
            snapshot
                .ceremony_policy("bank.example.com", &IntentAction::Authenticate)
                .unwrap(),
            &AgentCeremonyPolicy::supervised()
        );
        assert_eq!(
            snapshot
                .ceremony_policy("github.com", &IntentAction::Register)
                .unwrap(),
            &AgentCeremonyPolicy::deny()
        );
        assert!(!snapshot.is_rp_exact_match("com"));
        assert!(
            snapshot
                .ceremony_policy("com", &IntentAction::Authenticate)
                .is_none()
        );
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

    macro_rules! make_ceremony_tuple {
        ($runtime:expr, $profile_id:expr, $session_id:expr, $endpoint_id:expr,
         $process_digest:expr, $action:expr, $rp_id:expr, $credential_ref:expr $(,)?) => {{
            let generation = $runtime.current_generation();
            CeremonyTuple {
                profile_id: $profile_id,
                session_id: $session_id,
                endpoint_id: $endpoint_id,
                process_digest: $process_digest,
                policy_generation: generation.generation_id.clone(),
                policy_digest: generation.digest.clone(),
                action: $action,
                rp_id: $rp_id.to_string(),
                credential_ref: $credential_ref,
            }
        }};
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
    fn test_ceremony_resolve_pending_isolated_approve() {
        let config = make_isolated_config("resolveiso", vec!["example.com"], true);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("resolveiso").unwrap();
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

        let tuple = make_ceremony_tuple!(
            &runtime,
            pid.clone(),
            session.clone(),
            endpoint.clone(),
            process_digest.clone(),
            IntentAction::Authenticate,
            "example.com",
            None,
        );

        let approval = TrustedApproval::new();
        let bound = runtime.ceremony_resolve_pending(&tuple, &approval).unwrap();

        assert_eq!(bound.profile_id(), &pid);
        assert_eq!(bound.action(), &IntentAction::Authenticate);
        assert_eq!(bound.rp_id(), "example.com");
        assert!(bound.grant_id().is_none());

        let pr = runtime.pending_requests.lock().unwrap();
        let values: Vec<_> = pr.values().collect();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].state, PendingState::Approved);
    }

    #[test]
    fn test_ceremony_resolve_pending_not_found_wrong_tuple() {
        let config = make_isolated_config("wrongtuple", vec!["example.com"], true);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("wrongtuple").unwrap();
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

        let wrong_tuple = make_ceremony_tuple!(
            &runtime,
            pid,
            session,
            endpoint,
            process_digest,
            IntentAction::Authenticate,
            "other.com",
            None,
        );

        let approval = TrustedApproval::new();
        let result = runtime.ceremony_resolve_pending(&wrong_tuple, &approval);
        assert!(matches!(result, Err(CeremonyResolveError::PendingNotFound)));
    }

    #[test]
    fn test_ceremony_resolve_pending_wrong_action() {
        let config = make_isolated_config("wrongaction", vec!["example.com"], true);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("wrongaction").unwrap();
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

        let wrong_tuple = make_ceremony_tuple!(
            &runtime,
            pid,
            session,
            endpoint,
            process_digest,
            IntentAction::Register,
            "example.com",
            None,
        );

        let approval = TrustedApproval::new();
        let result = runtime.ceremony_resolve_pending(&wrong_tuple, &approval);
        assert!(matches!(result, Err(CeremonyResolveError::PendingNotFound)));
    }

    #[test]
    fn test_ceremony_resolve_pending_wrong_session() {
        let config = make_isolated_config("wrongsession", vec!["example.com"], true);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("wrongsession").unwrap();
        let session = PrincipalSessionId::new();
        let wrong_session = PrincipalSessionId::new();
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

        let wrong_tuple = make_ceremony_tuple!(
            &runtime,
            pid,
            wrong_session,
            endpoint,
            process_digest,
            IntentAction::Authenticate,
            "example.com",
            None,
        );

        let approval = TrustedApproval::new();
        let result = runtime.ceremony_resolve_pending(&wrong_tuple, &approval);
        assert!(matches!(result, Err(CeremonyResolveError::PendingNotFound)));
    }

    #[test]
    fn test_ceremony_deny_pending() {
        let config = make_isolated_config("denypending", vec!["example.com"], true);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("denypending").unwrap();
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

        let tuple = make_ceremony_tuple!(
            &runtime,
            pid,
            session,
            endpoint,
            process_digest,
            IntentAction::Authenticate,
            "example.com",
            None,
        );

        let result = runtime.ceremony_deny_pending(&tuple);
        assert!(result.is_ok());

        let pr = runtime.pending_requests.lock().unwrap();
        let values: Vec<_> = pr.values().collect();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].state, PendingState::Denied);
    }

    #[test]
    fn test_ceremony_deny_then_resolve_fails() {
        let config = make_isolated_config("denythenresolve", vec!["example.com"], true);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("denythenresolve").unwrap();
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

        let tuple = make_ceremony_tuple!(
            &runtime,
            pid,
            session,
            endpoint,
            process_digest,
            IntentAction::Authenticate,
            "example.com",
            None,
        );

        runtime.ceremony_deny_pending(&tuple).unwrap();

        let approval = TrustedApproval::new();
        let result = runtime.ceremony_resolve_pending(&tuple, &approval);
        assert!(matches!(result, Err(CeremonyResolveError::PendingNotFound)));
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
    fn test_cancel_after_resolve_fails() {
        let config = make_isolated_config("cancelafter", vec!["example.com"], true);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("cancelafter").unwrap();
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

        let tuple = make_ceremony_tuple!(
            &runtime,
            pid,
            session.clone(),
            endpoint,
            process_digest,
            IntentAction::Authenticate,
            "example.com",
            None,
        );
        let approval = TrustedApproval::new();
        runtime.ceremony_resolve_pending(&tuple, &approval).unwrap();

        let result = runtime.principal_cancel_pending(&pending_id, &session);
        assert_eq!(result, Err(PendingCancelError::AlreadyResolved));
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
    fn test_authorize_bound_isolated() {
        let config = make_isolated_config("boundiso", vec!["example.com"], true);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("boundiso").unwrap();
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

        let tuple = make_ceremony_tuple!(
            &runtime,
            pid.clone(),
            session.clone(),
            endpoint.clone(),
            process_digest.clone(),
            IntentAction::Authenticate,
            "example.com",
            None,
        );
        let approval = TrustedApproval::new();
        let bound = runtime.ceremony_resolve_pending(&tuple, &approval).unwrap();

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

        let (decision, handle) = runtime.authorize_bound(&bound, &request);
        assert!(decision.is_allowed());
        assert!(handle.is_some());

        let h = handle.unwrap();
        let consume_result = runtime.consume_authorization(&h);
        assert!(consume_result.is_ok());
    }

    #[test]
    fn test_authorize_bound_tuple_mismatch() {
        let config = make_isolated_config("boundmismatch", vec!["example.com"], true);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("boundmismatch").unwrap();
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

        let tuple = make_ceremony_tuple!(
            &runtime,
            pid.clone(),
            session.clone(),
            endpoint.clone(),
            process_digest.clone(),
            IntentAction::Authenticate,
            "example.com",
            None,
        );
        let approval = TrustedApproval::new();
        let bound = runtime.ceremony_resolve_pending(&tuple, &approval).unwrap();

        let wrong_request = AuthorizationRequest {
            profile_id: pid,
            session_id: session,
            endpoint_id: endpoint,
            process_digest,
            policy_generation_id: generation.generation_id.clone(),
            policy_digest: generation.digest.clone(),
            action: IntentAction::Register,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            uv_enforced: false,
        };

        let (decision, handle) = runtime.authorize_bound(&bound, &wrong_request);
        assert_eq!(decision.outcome, Outcome::Deny);
        assert!(handle.is_none());
    }

    #[test]
    fn test_authorize_bound_double_consume_fails() {
        let config = make_isolated_config("bounddouble", vec!["example.com"], true);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("bounddouble").unwrap();
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

        let tuple = make_ceremony_tuple!(
            &runtime,
            pid.clone(),
            session.clone(),
            endpoint.clone(),
            process_digest.clone(),
            IntentAction::Authenticate,
            "example.com",
            None,
        );
        let approval = TrustedApproval::new();
        let bound = runtime.ceremony_resolve_pending(&tuple, &approval).unwrap();

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

        let (_d1, h1) = runtime.authorize_bound(&bound, &request);
        assert!(h1.is_some());

        let (_d2, h2) = runtime.authorize_bound(&bound, &request);
        assert!(h2.is_none());
    }

    #[test]
    fn test_resolve_pending_after_cancel_fails() {
        let config = make_isolated_config("resolveaftercancel", vec!["example.com"], true);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("resolveaftercancel").unwrap();
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

        runtime
            .principal_cancel_pending(&pending_id, &session)
            .unwrap();

        let tuple = make_ceremony_tuple!(
            &runtime,
            pid,
            session,
            endpoint,
            process_digest,
            IntentAction::Authenticate,
            "example.com",
            None,
        );
        let approval = TrustedApproval::new();
        let result = runtime.ceremony_resolve_pending(&tuple, &approval);
        assert!(matches!(result, Err(CeremonyResolveError::PendingNotFound)));
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
    fn test_credential_ref_mismatch_pending_not_found() {
        let config = make_isolated_config("credmismatch", vec!["example.com"], true);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("credmismatch").unwrap();
        let session = PrincipalSessionId::new();
        let endpoint = EndpointId::new();
        let process_digest = ProcessIdentityDigest::compute(1000, 1000, 42, b"test");
        let generation = runtime.current_generation();
        let cr = test_cred_ref(b"cred-a");

        let _pending_id = runtime
            .principal_create_pending_intent(CreateIntentParams {
                profile_id: pid.clone(),
                session_id: session.clone(),
                endpoint_id: endpoint.clone(),
                process_digest: process_digest.clone(),
                action: IntentAction::Authenticate,
                rp_id: "example.com".to_string(),
                credential_ref: Some(cr.clone()),
                policy_generation: generation.generation_id.clone(),
                policy_digest: generation.digest.clone(),
                require_uv: false,
                ttl_ms: Some(60_000),
            })
            .unwrap();

        let wrong_cr = test_cred_ref(b"cred-b");
        let tuple = make_ceremony_tuple!(
            &runtime,
            pid,
            session,
            endpoint,
            process_digest,
            IntentAction::Authenticate,
            "example.com",
            Some(wrong_cr),
        );

        let approval = TrustedApproval::new();
        let result = runtime.ceremony_resolve_pending(&tuple, &approval);
        assert!(matches!(result, Err(CeremonyResolveError::PendingNotFound)));
    }

    #[test]
    fn test_endpoint_mismatch_pending_not_found() {
        let config = make_isolated_config("endpmismatch", vec!["example.com"], true);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("endpmismatch").unwrap();
        let session = PrincipalSessionId::new();
        let endpoint = EndpointId::new();
        let wrong_endpoint = EndpointId::new();
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

        let tuple = make_ceremony_tuple!(
            &runtime,
            pid,
            session,
            wrong_endpoint,
            process_digest,
            IntentAction::Authenticate,
            "example.com",
            None,
        );

        let approval = TrustedApproval::new();
        let result = runtime.ceremony_resolve_pending(&tuple, &approval);
        assert!(matches!(result, Err(CeremonyResolveError::PendingNotFound)));
    }

    #[test]
    fn test_process_mismatch_pending_not_found() {
        let config = make_isolated_config("procmismatch", vec!["example.com"], true);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("procmismatch").unwrap();
        let session = PrincipalSessionId::new();
        let endpoint = EndpointId::new();
        let process_digest = ProcessIdentityDigest::compute(1000, 1000, 42, b"test");
        let wrong_process = ProcessIdentityDigest::compute(2000, 2000, 99, b"other");
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

        let tuple = make_ceremony_tuple!(
            &runtime,
            pid,
            session,
            endpoint,
            wrong_process,
            IntentAction::Authenticate,
            "example.com",
            None,
        );

        let approval = TrustedApproval::new();
        let result = runtime.ceremony_resolve_pending(&tuple, &approval);
        assert!(matches!(result, Err(CeremonyResolveError::PendingNotFound)));
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

    #[test]
    fn test_authorize_registration_allowed() {
        let mut config = make_isolated_config("reg-test", vec!["example.com"], true);
        let profile = config.profiles.get_mut("reg-test").unwrap();
        profile.rules = vec![AgentRpRule {
            rp_id: "example.com".to_string(),
            register: AgentCeremonyPolicy {
                authorization: AgentAuthorization::Allow,
                user_presence: UserPresenceSource::None,
                user_verification: UserVerificationSource::None,
            },
            authenticate: AgentCeremonyPolicy::deny(),
        }];

        let (runtime, _clock) = make_runtime(&config);
        let profile_id = ProfileId::new("reg-test").unwrap();

        let (outcome, reason) = runtime.authorize_registration(&profile_id, "example.com");
        assert_eq!(outcome, Outcome::Allow);
        assert_eq!(reason, ReasonCode::Allowed);
    }

    #[test]
    fn test_authorize_registration_denied_by_rule() {
        let mut config = make_isolated_config("reg-deny", vec!["example.com"], true);
        let profile = config.profiles.get_mut("reg-deny").unwrap();
        profile.rules = vec![AgentRpRule {
            rp_id: "example.com".to_string(),
            register: AgentCeremonyPolicy::deny(),
            authenticate: AgentCeremonyPolicy {
                authorization: AgentAuthorization::Allow,
                user_presence: UserPresenceSource::None,
                user_verification: UserVerificationSource::None,
            },
        }];

        let (runtime, _clock) = make_runtime(&config);
        let profile_id = ProfileId::new("reg-deny").unwrap();

        let (outcome, reason) = runtime.authorize_registration(&profile_id, "example.com");
        assert_eq!(outcome, Outcome::Deny);
        assert_eq!(reason, ReasonCode::ActionNotAllowed);
    }

    #[test]
    fn test_authorize_registration_denied_global() {
        let config = make_isolated_config("reg-global", vec!["example.com"], false);

        let (runtime, _clock) = make_runtime(&config);
        let profile_id = ProfileId::new("reg-global").unwrap();

        let (outcome, reason) = runtime.authorize_registration(&profile_id, "example.com");
        assert_eq!(outcome, Outcome::Deny);
        assert_eq!(reason, ReasonCode::DelegatedRegistrationDenied);
    }

    #[test]
    fn test_authorize_registration_profile_not_found() {
        let config = make_isolated_config("existing", vec!["example.com"], true);

        let (runtime, _clock) = make_runtime(&config);
        let profile_id = ProfileId::new("nonexistent").unwrap();

        let (outcome, reason) = runtime.authorize_registration(&profile_id, "example.com");
        assert_eq!(outcome, Outcome::Deny);
        assert_eq!(reason, ReasonCode::ProfileNotFound);
    }

    #[test]
    fn test_authorize_registration_rp_not_in_rules() {
        let mut config = make_isolated_config("reg-norp", vec!["example.com"], true);
        let profile = config.profiles.get_mut("reg-norp").unwrap();
        profile.rules = vec![AgentRpRule {
            rp_id: "example.com".to_string(),
            register: AgentCeremonyPolicy {
                authorization: AgentAuthorization::Allow,
                user_presence: UserPresenceSource::None,
                user_verification: UserVerificationSource::None,
            },
            authenticate: AgentCeremonyPolicy::deny(),
        }];

        let (runtime, _clock) = make_runtime(&config);
        let profile_id = ProfileId::new("reg-norp").unwrap();

        let (outcome, reason) = runtime.authorize_registration(&profile_id, "other.com");
        assert_eq!(outcome, Outcome::Deny);
        assert_eq!(reason, ReasonCode::RpIdNotExactMatch);
    }

    #[test]
    fn test_authorize_registration_rp_normalization() {
        let mut config = make_isolated_config("reg-norm", vec!["example.com"], true);
        let profile = config.profiles.get_mut("reg-norm").unwrap();
        profile.rules = vec![AgentRpRule {
            rp_id: "example.com".to_string(),
            register: AgentCeremonyPolicy {
                authorization: AgentAuthorization::Allow,
                user_presence: UserPresenceSource::None,
                user_verification: UserVerificationSource::None,
            },
            authenticate: AgentCeremonyPolicy::deny(),
        }];

        let (runtime, _clock) = make_runtime(&config);
        let profile_id = ProfileId::new("reg-norm").unwrap();

        let (outcome, reason) = runtime.authorize_registration(&profile_id, "EXAMPLE.COM");
        assert_eq!(outcome, Outcome::Allow);
        assert_eq!(reason, ReasonCode::Allowed);
    }
}
