use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::Duration;

use passless_core::agent::config::{ANY_RP_ID, validate_rp_id};
use passless_core::agent::protocol::IntentAction;
use passless_core::agent::{
    AgentConfig, AgentMode, AgentProfileConfig, AgentRpRule, CredentialRef, CredentialSelection,
    EndpointId, GrantId, GrantSource, MatchedRule, NoGrantedRules, PendingRequestId, Policy,
    PolicyAction, PolicyDigest, PolicyGenerationId, PolicyParams, PrincipalSessionId, ProfileId,
    RuleAction, resolve_rules,
};

use super::audit::AuditGate;
use super::browser::Clock;
use super::grant::{GrantError, GrantRegistry, GrantRequestId, GrantRequestParams};
use super::identity::{AdminAuthority, ProcessIdentityDigest};
use super::lock_order::{self, LockLevel, Tracked};

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
    /// Operation budget of one bearer session, read live by every ceremony (ADR 0014 section 9).
    pub max_operations: u16,
    /// Cap on the profile's persistent granted rules (ADR 0014 section 8.4), read live.
    pub max_granted_rules: u16,
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

/// What an escalation needs from the live policy of its profile.
#[derive(Debug, Clone)]
pub struct EscalationProfile {
    pub mode: AgentMode,
    pub principal_user: String,
    pub max_granted_rules: usize,
    /// `agents.escalation_timeout`, when set.
    pub escalation_timeout: Option<Duration>,
}

/// The global escalation keys that are part of every profile's policy digest.
#[derive(Debug, Clone, Copy)]
struct EscalationSettings {
    timeout_secs: u64,
    cooldown_secs: u64,
}

impl EscalationSettings {
    fn of(config: &AgentConfig) -> Self {
        Self {
            timeout_secs: config.escalation_timeout.unwrap_or(0),
            cooldown_secs: config.escalation_cooldown,
        }
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
    /// Digest of the principal the grant was issued to; a session must match it (ADR 0014 section 7).
    pub principal_digest: [u8; 32],
    pub rp_ids: Vec<String>,
    pub credential_refs: Vec<CredentialRef>,
    pub state: super::grant::GrantState,
    pub expiry_mono: u64,
    pub is_revoked: bool,
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
    profile_id: ProfileId,
    session_id: PrincipalSessionId,
    endpoint_id: EndpointId,
    process_digest: ProcessIdentityDigest,
    policy_generation: PolicyGenerationId,
    policy_digest: PolicyDigest,
    action: IntentAction,
    rp_id: String,
    credential_ref: Option<CredentialRef>,
    grant_request_id: Option<GrantRequestId>,
    state: PendingState,
    created_at_mono: u64,
    deadline_mono: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingCreateError {
    GrantRequestFailed(GrantError),
    DuplicatePending,
    Internal(String),
}

impl fmt::Display for PendingCreateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GrantRequestFailed(e) => write!(f, "grant request failed: {}", e),
            Self::DuplicatePending => write!(f, "duplicate pending request for this tuple"),
            Self::Internal(s) => write!(f, "internal error: {}", s),
        }
    }
}

impl std::error::Error for PendingCreateError {}

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
    grants: Mutex<HashMap<String, GrantRegistry>>,
    pending_requests: Mutex<HashMap<String, PendingPrincipalRequest>>,
    clock: Arc<dyn Clock>,
    audit_gate: Option<Arc<AuditGate>>,
    /// The granted-rules store consulted to upgrade a `request` (ADR 0014 sections 6.2 and 8.4).
    granted_rules: Arc<dyn GrantSource>,
    /// Serializes reloads, so the numeric generation is read, bumped and published atomically:
    /// concurrent reloads get distinct, strictly increasing generations.
    reload_lock: Mutex<()>,
    /// Revocation epoch (ADR 0014 section 6.4, plan R16): bumped by a reload that changes the
    /// effective policy, a granted-rule revocation and any other config change. Every bearer
    /// session records it at creation and is revoked once it moves.
    revocation_epoch: AtomicU64,
    /// Grant epoch: bumped when a granted rule is added (P7). It never revokes sessions.
    grant_epoch: AtomicU64,
    /// Key-use gate for the revocation epoch (review M1): ceremonies hold the read side from the
    /// pre-key-use re-check to the end of key use; [`Self::bump_revocation_epoch`] takes the
    /// write side, so once a bump returns no ceremony that checked the old epoch can still use a
    /// key.
    key_use_gate: RwLock<()>,
}

/// What a successful [`PolicyRuntime::reload`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadOutcome {
    /// The digest now in force.
    pub digest: PolicyDigest,
    /// The numeric generation now in force.
    pub generation: u64,
    /// Whether the effective policy changed. An unchanged digest leaves the generation, the
    /// session grants and the revocation epoch untouched.
    pub changed: bool,
    /// The revocation epoch now in force.
    pub revocation_epoch: u64,
}

impl PolicyRuntime {
    pub fn new(
        config: &AgentConfig,
        clock: Arc<dyn Clock>,
        audit_gate: Option<Arc<AuditGate>>,
    ) -> Result<Self, PolicyRuntimeError> {
        let generation = Self::compile_generation(config, clock.monotonic_secs(), 1)?;
        let gen_arc = Arc::new(generation);

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
            )
            .with_max_session_ttl(snapshot.max_session_ttl_secs);
            grant_registries.insert(snapshot.profile_id.as_str().to_string(), registry);
        }

        Ok(Self {
            current: RwLock::new(gen_arc),
            grants: Mutex::new(grant_registries),
            pending_requests: Mutex::new(HashMap::new()),
            clock,
            audit_gate,
            granted_rules: Arc::new(NoGrantedRules),
            reload_lock: Mutex::new(()),
            revocation_epoch: AtomicU64::new(1),
            grant_epoch: AtomicU64::new(1),
            key_use_gate: RwLock::new(()),
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
                EscalationSettings::of(config),
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
        escalation: EscalationSettings,
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
            max_granted_rules: u64::from(config.max_granted_rules),
            escalation_timeout: escalation.timeout_secs,
            escalation_cooldown: escalation.cooldown_secs,
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
            max_operations: config.max_operations,
            max_granted_rules: config.max_granted_rules,
            allowed_actions,
            credential_selection: config.credential_selection.clone(),
            rules,
        })
    }

    pub fn current_generation(&self) -> Arc<PolicyGenerationSnapshot> {
        let _level = lock_order::enter(LockLevel::Policy);
        self.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn lock_grants(&self) -> Tracked<MutexGuard<'_, HashMap<String, GrantRegistry>>> {
        lock_order::lock(&self.grants, LockLevel::Policy)
    }

    fn lock_pending_requests(
        &self,
    ) -> Tracked<MutexGuard<'_, HashMap<String, PendingPrincipalRequest>>> {
        lock_order::lock(&self.pending_requests, LockLevel::Policy)
    }

    /// The live revocation epoch (ADR 0014 section 6.4).
    pub fn revocation_epoch(&self) -> u64 {
        self.revocation_epoch.load(Ordering::Acquire)
    }

    /// The live grant epoch. Adding a granted rule bumps it; it never revokes sessions.
    pub fn grant_epoch(&self) -> u64 {
        self.grant_epoch.load(Ordering::Acquire)
    }

    /// Revoke every bearer session: bump the revocation epoch. Called for a policy change, a
    /// granted-rule revocation (P7) and any other configuration change. Returns the new epoch.
    ///
    /// Waits for every ceremony between its pre-key-use re-check and the end of key use.
    pub fn bump_revocation_epoch(&self) -> u64 {
        let _gate = lock_order::write(&self.key_use_gate, LockLevel::EpochKeyUse);
        self.revocation_epoch.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Hold off a revocation-epoch bump until the guard is dropped (review M1). Ceremonies take it
    /// right before the pre-key-use re-check and keep it until key use has finished.
    pub fn key_use_guard(&self) -> Tracked<std::sync::RwLockReadGuard<'_, ()>> {
        lock_order::read(&self.key_use_gate, LockLevel::EpochKeyUse)
    }

    /// Record an additive grant (P7). Additive grants are not a policy change (invariant 18).
    pub fn bump_grant_epoch(&self) -> u64 {
        self.grant_epoch.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// The live operation budget of a profile's sessions, if the profile exists.
    pub fn max_operations(&self, profile_id: &ProfileId) -> Option<u16> {
        self.current_generation()
            .find_snapshot(profile_id)
            .map(|snapshot| snapshot.max_operations)
    }

    /// The live escalation settings of a profile (ADR 0014 section 8), if the profile exists.
    pub fn escalation_profile(&self, profile_id: &ProfileId) -> Option<EscalationProfile> {
        self.current_generation()
            .find_snapshot(profile_id)
            .map(|snapshot| EscalationProfile {
                mode: snapshot.mode,
                principal_user: snapshot.policy.principal_user.clone(),
                max_granted_rules: usize::from(snapshot.max_granted_rules),
                escalation_timeout: (snapshot.policy.escalation_timeout > 0)
                    .then(|| Duration::from_secs(snapshot.policy.escalation_timeout)),
            })
    }

    /// The credential references that registration grants pinned for exactly `rp_id` (ADR 0014
    /// section 8.3), read live from the granted-rules store.
    pub fn granted_credential_refs(
        &self,
        profile_id: &ProfileId,
        rp_id: &str,
    ) -> Vec<CredentialRef> {
        self.granted_rules
            .granted_credential_refs(profile_id, rp_id)
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
        let generation = self.current_generation();
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
        self.current_generation().generation
    }

    pub fn digest(&self) -> PolicyDigest {
        self.current_generation().digest.clone()
    }

    pub fn list_grants(
        &self,
        profile_filter: Option<&ProfileId>,
    ) -> Vec<super::grant::GrantSnapshot> {
        let grants = self.lock_grants();
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
        let grants = self.lock_grants();
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
        let authority = super::identity::admin_authority();
        let grants = self.lock_grants();
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
        let grants = self.lock_grants();
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
        let grants = self.lock_grants();
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
        let mut grants_map = self.lock_grants();
        let registry = grants_map.get_mut(profile_id.as_str())?;
        let _ = registry.check_expired();
        let snap = registry.snapshot_for_sign(grant_id)?;
        let is_revoked = snap.state == super::grant::GrantState::Revoked;
        Some(GrantSignSnapshot {
            grant_id: snap.grant_id,
            profile_id: snap.profile_id,
            principal_digest: snap.principal_digest,
            rp_ids: snap.rp_ids,
            credential_refs: snap.credential_refs,
            state: snap.state,
            expiry_mono: snap.expiry_mono,
            is_revoked,
        })
    }
    pub fn active_grant_count_for_profile(&self, profile_id: &ProfileId) -> u32 {
        let grants = self.lock_grants();
        grants
            .get(profile_id.as_str())
            .map(|r| r.active_count() as u32)
            .unwrap_or(0)
    }

    /// Replace the compiled policy with `config` (already read and validated by the caller).
    ///
    /// A reload whose digest is unchanged is a no-op: the generation, the session grants and the
    /// revocation epoch stay as they are, so live sessions continue. A reload that changes the
    /// effective policy compiles a new generation, replaces the session-grant registries, cancels
    /// pending delegation requests and bumps the revocation epoch, which revokes every bearer session (ADR 0014
    /// sections 6.4 and 9, invariant 18). An invalid configuration leaves everything untouched.
    pub fn reload(&self, config: &AgentConfig) -> Result<ReloadOutcome, PolicyRuntimeError> {
        let _reload = lock_order::lock(&self.reload_lock, LockLevel::PolicyReload);
        let current = self.current_generation();
        let now_mono = self.clock.monotonic_secs();
        let next_generation = current.generation.saturating_add(1);
        let new_generation = Self::compile_generation(config, now_mono, next_generation)?;
        if new_generation.digest == current.digest {
            return Ok(ReloadOutcome {
                digest: current.digest.clone(),
                generation: current.generation,
                changed: false,
                revocation_epoch: self.revocation_epoch(),
            });
        }
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
            )
            .with_max_session_ttl(snapshot.max_session_ttl_secs);
            new_registries.insert(snapshot.profile_id.as_str().to_string(), registry);
        }

        // Each policy lock is taken alone (LOCKING.md): no policy guard is held across another.
        for pr in self.lock_pending_requests().values_mut() {
            if pr.state == PendingState::Waiting {
                pr.state = PendingState::Cancelled;
            }
        }
        *self.lock_grants() = new_registries;
        {
            let _level = lock_order::enter(LockLevel::Policy);
            let mut current = self
                .current
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *current = Arc::new(new_generation);
        }
        // Published after the new generation, so a ceremony that sees the new epoch also sees the
        // new rules when it re-resolves.
        let revocation_epoch = self.bump_revocation_epoch();

        Ok(ReloadOutcome {
            digest: new_digest,
            generation: next_generation,
            changed: true,
            revocation_epoch,
        })
    }

    /// Withdraw the grant requests of pending principal requests that were just cancelled or
    /// timed out. Runs after the `pending_requests` guard is released.
    fn abandon_pending(&self, abandoned: Vec<(ProfileId, Option<GrantRequestId>)>) {
        if abandoned.is_empty() {
            return;
        }
        let authority = super::identity::admin_authority();
        let mut grants_map = self.lock_grants();
        for (profile_id, grant_request_id) in &abandoned {
            if let Some(grant_request_id) = grant_request_id
                && let Some(grants) = grants_map.get_mut(profile_id.as_str())
            {
                if let Some(grant_id) = grants.resolved_grant_id(grant_request_id) {
                    let _ = grants.revoke_grant(&grant_id, &authority);
                }
                let _ = grants.cancel_request(grant_request_id);
            }
        }
    }

    pub fn admin_request_grant(
        &self,
        params: GrantRequestParams,
    ) -> Result<super::grant::GrantRequestId, GrantError> {
        let profile_key = params.profile_id.as_str().to_string();
        let mut grants_map = self.lock_grants();
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
        let mut grants_map = self.lock_grants();
        let grants = grants_map
            .get_mut(&profile_key)
            .ok_or(GrantError::ProfileMismatch)?;
        grants.request_dynamic_grant(params)
    }

    /// Request the grant behind a browser bearer session, bounded by the profile's
    /// `max_session_ttl` (defect B5) rather than `max_grant_ttl`.
    pub fn admin_request_session_grant(
        &self,
        params: GrantRequestParams,
        dynamic: bool,
    ) -> Result<super::grant::GrantRequestId, GrantError> {
        let profile_key = params.profile_id.as_str().to_string();
        let mut grants_map = self.lock_grants();
        let grants = grants_map
            .get_mut(&profile_key)
            .ok_or(GrantError::ProfileMismatch)?;
        grants.request_session_grant(params, dynamic)
    }

    pub fn admin_approve_grant(
        &self,
        request_id: &super::grant::GrantRequestId,
        authority: &AdminAuthority,
    ) -> Result<passless_core::agent::GrantId, GrantError> {
        let mut grants_map = self.lock_grants();
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
        let mut grants_map = self.lock_grants();
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

        result
    }

    pub fn rollback_grant(&self, grant_id: &passless_core::agent::GrantId) {
        let authority = super::identity::admin_authority();
        let _ = self.admin_revoke_grant(grant_id, &authority);
    }

    pub fn resolved_grant_id_for_request(
        &self,
        profile_id: &ProfileId,
        grant_request_id: &super::grant::GrantRequestId,
    ) -> Option<passless_core::agent::GrantId> {
        let grants = self.lock_grants();
        let profile_key = profile_id.as_str().to_string();
        grants
            .get(&profile_key)
            .and_then(|g| g.resolved_grant_id(grant_request_id))
    }

    pub fn principal_exit(&self, session_id: &PrincipalSessionId) {
        {
            let mut grants_map = self.lock_grants();
            for grants in grants_map.values_mut() {
                grants.on_principal_exit(session_id);
                grants.cancel_claims_for_session(session_id);
            }
        }
        {
            let mut pending_requests = self.lock_pending_requests();
            for pr in pending_requests.values_mut() {
                if pr.session_id == *session_id && pr.state == PendingState::Waiting {
                    pr.state = PendingState::Cancelled;
                }
            }
        }
    }

    #[cfg(test)]
    pub fn admin_authority(&self) -> AdminAuthority {
        super::identity::admin_authority()
    }

    pub fn principal_create_pending_delegated(
        &self,
        params: PendingDelegationParams,
        grant_params: GrantRequestParams,
    ) -> Result<(PendingRequestId, super::grant::GrantRequestId), PendingCreateError> {
        let now_mono = self.clock.monotonic_secs();
        let ttl_ms = params.ttl_ms.unwrap_or(300_000);
        let ttl_secs = ttl_ms.div_ceil(1000);

        let normalized_rp = params.rp_id.trim().to_ascii_lowercase();
        let PendingDelegationParams {
            profile_id,
            session_id,
            endpoint_id,
            process_digest,
            policy_generation,
            policy_digest,
            action,
            credential_ref,
            ..
        } = params;

        let grant_request_id =
            {
                let profile_key = profile_id.as_str().to_string();
                let mut grants_map = self.lock_grants();
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
            profile_id,
            session_id,
            endpoint_id,
            process_digest,
            policy_generation,
            policy_digest,
            action,
            rp_id: normalized_rp,
            credential_ref,
            grant_request_id: Some(grant_request_id.clone()),
            state: PendingState::Waiting,
            created_at_mono: now_mono,
            deadline_mono: now_mono.saturating_add(ttl_secs),
        };

        let mut pending_requests = self.lock_pending_requests();
        pending_requests.insert(pending_id.as_str().to_string(), request);
        Ok((pending_id, grant_request_id))
    }

    pub fn principal_cancel_pending(
        &self,
        pending_id: &PendingRequestId,
        session_id: &PrincipalSessionId,
    ) -> Result<(), PendingCancelError> {
        let mut pending_requests = self.lock_pending_requests();
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
        let abandoned = vec![(request.profile_id.clone(), request.grant_request_id.clone())];
        drop(pending_requests);
        self.abandon_pending(abandoned);

        Ok(())
    }

    pub fn principal_pending_status(
        &self,
        pending_id: &PendingRequestId,
        session_id: &PrincipalSessionId,
    ) -> Result<PendingStatusSnapshot, PendingStatusError> {
        let pending_requests = self.lock_pending_requests();
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
            grant_request_id: request.grant_request_id.clone(),
            created_at_mono: request.created_at_mono,
            deadline_mono: request.deadline_mono,
        })
    }

    pub fn cleanup_expired_pending(&self) -> Vec<PendingRequestId> {
        let now_mono = self.clock.monotonic_secs();
        let mut expired = Vec::new();
        let mut abandoned = Vec::new();
        for request in self.lock_pending_requests().values_mut() {
            if request.state == PendingState::Waiting && now_mono >= request.deadline_mono {
                request.state = PendingState::TimedOut;
                expired.push(request.id.clone());
                abandoned.push((request.profile_id.clone(), request.grant_request_id.clone()));
            }
        }
        self.abandon_pending(abandoned);
        expired
    }

    pub fn cancel_pending_for_session(&self, session_id: &PrincipalSessionId) {
        let mut abandoned = Vec::new();
        for request in self.lock_pending_requests().values_mut() {
            if request.session_id == *session_id && request.state == PendingState::Waiting {
                request.state = PendingState::Cancelled;
                abandoned.push((request.profile_id.clone(), request.grant_request_id.clone()));
            }
        }
        self.abandon_pending(abandoned);
    }
}

/// The request half of a pending delegation (the grant request is separate).
pub struct PendingDelegationParams {
    pub profile_id: ProfileId,
    pub session_id: PrincipalSessionId,
    pub endpoint_id: EndpointId,
    pub process_digest: ProcessIdentityDigest,
    pub action: IntentAction,
    pub rp_id: String,
    pub credential_ref: Option<CredentialRef>,
    pub policy_generation: PolicyGenerationId,
    pub policy_digest: PolicyDigest,
    pub ttl_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct PendingStatusSnapshot {
    pub id: PendingRequestId,
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

#[cfg(test)]
mod tests {
    use super::*;
    use passless_core::agent::{
        AgentConfig, AgentMode, AgentProfileConfig, AgentRpRule, AgentStorageConfig, BrowserScope,
        ProfileId, RuleAction, RuleIdentity,
    };
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use super::super::browser::Clock;
    use super::super::identity::ProcessIdentityDigest;
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
                max_granted_rules: 64,
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
            notify_user: None,
            state_dir: None,
            escalation_timeout: None,
            escalation_cooldown: 600,
            limits: Default::default(),
            enabled: true,
            profiles,
            audit_path: Some(PathBuf::from("/tmp/test-audit")),
            acknowledge_global_same_user: vec![],
            acknowledge_same_user_registration: vec![],
        }
    }

    fn make_runtime(config: &AgentConfig) -> (PolicyRuntime, Arc<MockClock>) {
        let clock = test_clock();
        let runtime = PolicyRuntime::new(config, clock.clone(), None).unwrap();
        (runtime, clock)
    }

    /// Register a waiting delegation request directly (the principal path is refused by the
    /// runtime; the pending-request bookkeeping is what these tests exercise).
    fn insert_pending(
        runtime: &PolicyRuntime,
        profile_id: &ProfileId,
        session_id: &PrincipalSessionId,
        ttl_ms: u64,
    ) -> PendingRequestId {
        let generation = runtime.current_generation();
        let now_mono = runtime.clock.monotonic_secs();
        let id = PendingRequestId::new();
        runtime.lock_pending_requests().insert(
            id.as_str().to_string(),
            PendingPrincipalRequest {
                id: id.clone(),
                profile_id: profile_id.clone(),
                session_id: session_id.clone(),
                endpoint_id: EndpointId::new(),
                process_digest: ProcessIdentityDigest::compute(1000, 1000, 42, b"test"),
                policy_generation: generation.generation_id.clone(),
                policy_digest: generation.digest.clone(),
                action: IntentAction::Authenticate,
                rp_id: "example.com".to_string(),
                credential_ref: None,
                grant_request_id: None,
                state: PendingState::Waiting,
                created_at_mono: now_mono,
                deadline_mono: now_mono.saturating_add(ttl_ms.div_ceil(1000)),
            },
        );
        id
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
        let runtime = PolicyRuntime::new(&config, clock, None)
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
        let runtime = PolicyRuntime::new(&config, clock, None)
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
        let runtime = PolicyRuntime::new(&config, clock, None)
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
        let runtime = PolicyRuntime::new(&config, clock, None)
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
    fn test_generation_number_starts_at_one_and_increments_on_a_changed_reload() {
        let config = make_isolated_config("gen", vec!["example.com"], false);
        let (runtime, _clock) = make_runtime(&config);
        assert_eq!(runtime.generation_number(), 1);
        assert_eq!(runtime.current_generation().generation, 1);
        assert_eq!(runtime.revocation_epoch(), 1);

        let digest_before = runtime.digest();
        let generation_id_before = runtime.current_generation().generation_id.clone();

        // A reload with an unchanged digest is a no-op: same generation, same generation id, and
        // no session is revoked (the revocation epoch stays).
        let outcome = runtime.reload(&config).unwrap();
        assert!(!outcome.changed);
        assert_eq!(outcome.digest, digest_before);
        assert_eq!(runtime.digest(), digest_before);
        assert_eq!(runtime.generation_number(), 1);
        assert_eq!(
            runtime.current_generation().generation_id,
            generation_id_before
        );
        assert_eq!(runtime.revocation_epoch(), 1);

        let mut changed = config.clone();
        changed.profiles.get_mut("gen").unwrap().rules[0].authenticate = RuleAction::Request;
        let outcome = runtime.reload(&changed).unwrap();
        assert!(outcome.changed);
        assert_ne!(outcome.digest, digest_before);
        assert_eq!(runtime.generation_number(), 2);
        assert_eq!(outcome.revocation_epoch, 2);
        assert_eq!(runtime.revocation_epoch(), 2);
        assert_eq!(
            runtime.grant_epoch(),
            1,
            "a reload never touches the grant epoch"
        );
    }

    #[test]
    fn test_unchanged_reload_keeps_session_grants_and_changed_reload_drops_them() {
        let config = make_isolated_config("keep", vec!["example.com"], false);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("keep").unwrap();
        let request = runtime
            .admin_request_session_grant(
                GrantRequestParams {
                    profile_id: pid.clone(),
                    session_id: PrincipalSessionId::new(),
                    endpoint_id: EndpointId::new(),
                    principal_digest: [3u8; 32],
                    rp_ids: vec!["example.com".to_string()],
                    credentials: Vec::new(),
                    requested_ttl_secs: 60,
                },
                true,
            )
            .unwrap();
        let grant_id = runtime
            .admin_approve_grant(&request, &super::super::identity::admin_authority())
            .unwrap();

        runtime.reload(&config).unwrap();
        let grant = runtime.resolve_grant_for_sign(&pid, &grant_id).unwrap();
        assert_eq!(grant.state, super::super::grant::GrantState::Active);
        assert_eq!(grant.principal_digest, [3u8; 32]);

        let mut changed = config.clone();
        changed.profiles.get_mut("keep").unwrap().max_operations = 7;
        runtime.reload(&changed).unwrap();
        assert!(runtime.resolve_grant_for_sign(&pid, &grant_id).is_none());
        assert_eq!(
            runtime.max_operations(&pid),
            Some(7),
            "the budget is read live"
        );
    }

    #[test]
    fn test_session_grant_ttl_is_bounded_by_max_session_ttl_not_max_grant_ttl() {
        // Defect B5: a `max_session_ttl` above 300 s (the default `max_grant_ttl`) used to fail
        // session grant creation with `TtlExceedsProfileMax`.
        let mut config = make_isolated_config("b5", vec!["example.com"], false);
        config.profiles.get_mut("b5").unwrap().max_session_ttl =
            Some(passless_core::agent::BoundedDuration::new(3600).unwrap());
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("b5").unwrap();
        let params = |ttl| GrantRequestParams {
            profile_id: pid.clone(),
            session_id: PrincipalSessionId::new(),
            endpoint_id: EndpointId::new(),
            principal_digest: [0u8; 32],
            rp_ids: vec!["example.com".to_string()],
            credentials: Vec::new(),
            requested_ttl_secs: ttl,
        };
        let request = runtime
            .admin_request_session_grant(params(3600), true)
            .expect("a session grant up to max_session_ttl is accepted");
        let grant_id = runtime
            .admin_approve_grant(&request, &super::super::identity::admin_authority())
            .unwrap();
        let grant = runtime.resolve_grant_for_sign(&pid, &grant_id).unwrap();
        assert_eq!(grant.expiry_mono, 3600, "the full session TTL is granted");
        assert!(matches!(
            runtime.admin_request_session_grant(params(3601), true),
            Err(GrantError::TtlExceedsProfileMax { max: 3600, .. })
        ));
        // Intent grants are still bounded by `max_grant_ttl`.
        assert!(matches!(
            runtime.admin_request_dynamic_grant(params(301)),
            Err(GrantError::TtlExceedsProfileMax { max: 300, .. })
        ));
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
            for thread in 0..THREADS {
                let runtime = &runtime;
                let config = &config;
                let observed = &observed;
                scope.spawn(move || {
                    for reload in 0..RELOADS_PER_THREAD {
                        // Every reload has its own digest, so every one is a change.
                        let mut next = config.clone();
                        next.profiles.get_mut("genrace").unwrap().max_operations =
                            u16::try_from(2 + thread * RELOADS_PER_THREAD + reload).unwrap();
                        let outcome = runtime.reload(&next).unwrap();
                        assert!(outcome.changed);
                        observed.lock().unwrap().push(outcome.generation);
                    }
                });
            }
        });
        // Every reload bumped the generation and the revocation epoch exactly once: none was lost
        // to a racing reload, and no two reloads got the same generation.
        assert_eq!(
            runtime.generation_number(),
            1 + THREADS * RELOADS_PER_THREAD
        );
        assert_eq!(runtime.revocation_epoch(), 1 + THREADS * RELOADS_PER_THREAD);
        let mut observed = observed.into_inner().unwrap();
        observed.sort_unstable();
        observed.dedup();
        assert_eq!(observed.len() as u64, THREADS * RELOADS_PER_THREAD);
    }

    #[test]
    fn test_digest_covers_escalation_settings_and_grant_cap() {
        let base = make_isolated_config("esc", vec!["example.com"], false);
        let digest = |config: &AgentConfig| {
            PolicyRuntime::compile_generation(config, 0, 1)
                .unwrap()
                .digest
        };
        let mut cooldown = base.clone();
        cooldown.escalation_cooldown += 1;
        let mut timeout = base.clone();
        timeout.escalation_timeout = Some(300);
        let mut cap = base.clone();
        cap.profiles.get_mut("esc").unwrap().max_granted_rules = 8;
        for changed in [&cooldown, &timeout, &cap] {
            assert_ne!(digest(&base), digest(changed));
        }
        // Restart-only keys are not policy: they never reach the digest.
        let mut restart_only = base.clone();
        restart_only.notify_user = Some("someone".to_string());
        restart_only.state_dir = Some(PathBuf::from("/srv/state"));
        assert_eq!(digest(&base), digest(&restart_only));
        let snapshot_cap = PolicyRuntime::compile_generation(&cap, 0, 1).unwrap();
        assert_eq!(
            snapshot_cap
                .find_snapshot(&ProfileId::new("esc").unwrap())
                .unwrap()
                .max_granted_rules,
            8
        );
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
    fn test_principal_cancel_pending() {
        let config = make_isolated_config("cancelpending", vec!["example.com"], true);
        let (runtime, _clock) = make_runtime(&config);
        let pid = ProfileId::new("cancelpending").unwrap();
        let session = PrincipalSessionId::new();

        let pending_id = insert_pending(&runtime, &pid, &session, 60_000);

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

        let pending_id = insert_pending(&runtime, &pid, &session, 60_000);

        let result = runtime.principal_cancel_pending(&pending_id, &wrong_session);
        assert_eq!(result, Err(PendingCancelError::SessionMismatch));
    }

    #[test]
    fn test_reload_cancels_pending_requests() {
        let config1 = make_isolated_config("reloadcancel", vec!["example.com"], true);
        let (runtime, _clock) = make_runtime(&config1);
        let pid = ProfileId::new("reloadcancel").unwrap();
        let session = PrincipalSessionId::new();

        let _pending_id = insert_pending(&runtime, &pid, &session, 60_000);

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

        let _pending_id = insert_pending(&runtime, &pid, &session, 60_000);

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

        let pending_id = insert_pending(&runtime, &pid, &session, 60_000);

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

        let pending_id = insert_pending(&runtime, &pid, &session, 5_000);

        let status = runtime
            .principal_pending_status(&pending_id, &session)
            .unwrap();
        assert_eq!(status.state, PendingState::Waiting);

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

        let pending_id = insert_pending(&runtime, &pid, &session, 5_000);

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
    fn test_pending_status_mapping_delegation_state() {
        let snapshot = PendingStatusSnapshot {
            id: PendingRequestId::new(),
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
