use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::Duration;

use passless_core::agent::config::{ANY_RP_ID, validate_rp_id};
use passless_core::agent::protocol::GrantAction;
use passless_core::agent::{
    AgentConfig, AgentMode, AgentProfileConfig, AgentRpRule, CredentialRef, CredentialSelection,
    GrantId, GrantSource, MatchedRule, NoGrantedRules, Policy, PolicyAction, PolicyDigest,
    PolicyGenerationId, PolicyParams, PrincipalSessionId, ProfileId, RuleAction, resolve_rules,
};

use super::audit::AuditGate;
use super::browser::Clock;
use super::grant::{GrantError, GrantRegistry, GrantRequestParams};
use super::identity::AdminAuthority;
use super::lock_order::{self, LockLevel, Tracked};

#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    pub profile_id: ProfileId,
    pub policy: Policy,
    pub digest: PolicyDigest,
    pub mode: AgentMode,
    pub normalized_rp_ids: Vec<String>,
    /// Profile `credential_refs` (empty when unset; see [`Self::credential_refs_configured`]).
    pub credential_refs: Vec<CredentialRef>,
    /// Profile `credential_refs` is set: exact-rule matches are pinned to it (plus the
    /// registration-granted credentials). Unset: exact-rule matches discover. `*` matches never
    /// use the pins (ADR 0014 amendment section 2.1).
    pub credential_refs_configured: bool,
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
    /// The profile is listed in `agents.acknowledge_global_registration`.
    pub acknowledged_global_registration: bool,
    /// Cap on the profile's wildcard registration grants, read live.
    pub max_wildcard_registrations: u16,
    /// Wildcard registration prompts per rolling 24 hours, read live.
    pub wildcard_registration_prompts_per_day: u16,
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

    pub fn action_allowed(&self, action: &GrantAction) -> bool {
        let action_str = match action {
            GrantAction::Register => "register",
            GrantAction::Authenticate => "authenticate",
        };
        self.allowed_actions.contains(action_str)
    }

    /// Resolve `(action, rp_id)` over this snapshot's rules (ADR 0014 section 6.2).
    pub fn resolve(
        &self,
        action: &GrantAction,
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

fn policy_action(action: &GrantAction) -> PolicyAction {
    match action {
        GrantAction::Register => PolicyAction::Register,
        GrantAction::Authenticate => PolicyAction::Authenticate,
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
    /// Registration through the `*` rule is acknowledged (`acknowledge_global_registration`).
    /// Validation already requires it; the escalation checks it again (fail closed).
    pub wildcard_registration_acknowledged: bool,
    /// The live `max_wildcard_registrations`.
    pub max_wildcard_registrations: usize,
    /// The live `wildcard_registration_prompts_per_day`.
    pub wildcard_registration_prompts_per_day: usize,
}

/// A profile's `credential_refs` as the sign path sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfilePins {
    /// `credential_refs` is set (possibly to an empty list): exact-rule matches are pinned.
    Configured(Vec<CredentialRef>),
    /// `credential_refs` is not set: exact-rule matches discover per RP.
    Unset,
}

/// Which dangerous-profile acknowledgements list a profile.
#[derive(Debug, Clone, Copy)]
struct Acknowledgements {
    global_same_user: bool,
    same_user_registration: bool,
    global_registration: bool,
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
                Acknowledgements {
                    global_same_user: config.acknowledge_global_same_user.contains(name),
                    same_user_registration: config
                        .acknowledge_same_user_registration
                        .contains(name),
                    global_registration: config.acknowledge_global_registration.contains(name),
                },
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
        acknowledged: Acknowledgements,
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
        let credential_refs_configured = config.credential_refs.is_some();
        let max_wildcard_registrations = config.effective_max_wildcard_registrations();
        let wildcard_registration_prompts_per_day =
            config.effective_wildcard_registration_prompts_per_day();

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
            acknowledged_global_same_user: acknowledged.global_same_user,
            acknowledged_same_user_registration: acknowledged.same_user_registration,
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
            credential_refs_configured,
            acknowledged_global_registration: acknowledged.global_registration,
            max_wildcard_registrations: u64::from(max_wildcard_registrations),
            wildcard_registration_prompts_per_day: u64::from(wildcard_registration_prompts_per_day),
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
            credential_refs_configured,
            max_grant_ttl_secs,
            max_session_ttl_secs,
            max_concurrent_grants,
            max_operations: config.max_operations,
            max_granted_rules: config.max_granted_rules,
            allowed_actions,
            credential_selection: config.credential_selection.clone(),
            rules,
            acknowledged_global_registration: acknowledged.global_registration,
            max_wildcard_registrations,
            wildcard_registration_prompts_per_day,
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
                wildcard_registration_acknowledged: snapshot.acknowledged_global_registration,
                max_wildcard_registrations: usize::from(snapshot.max_wildcard_registrations),
                wildcard_registration_prompts_per_day: usize::from(
                    snapshot.wildcard_registration_prompts_per_day,
                ),
            })
    }

    /// The profile's configured pins, read from the LIVE snapshot rather than a copy frozen into
    /// the session grant (ADR 0014 amendment 2.1). `None` when the profile does not exist.
    pub fn profile_pins(&self, profile_id: &ProfileId) -> Option<ProfilePins> {
        self.current_generation()
            .find_snapshot(profile_id)
            .map(|snapshot| {
                if snapshot.credential_refs_configured {
                    ProfilePins::Configured(snapshot.credential_refs.clone())
                } else {
                    ProfilePins::Unset
                }
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
        action: &GrantAction,
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
    /// and bumps the revocation epoch, which revokes every bearer session (ADR 0014
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
        let mut grants_map = self.lock_grants();
        for grants in grants_map.values_mut() {
            grants.on_principal_exit(session_id);
            grants.cancel_claims_for_session(session_id);
        }
    }

    #[cfg(test)]
    pub fn admin_authority(&self) -> AdminAuthority {
        super::identity::admin_authority()
    }
}

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
    use passless_core::agent::protocol::GrantAction;

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
        register_allowed: bool,
    ) -> AgentConfig {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            profile_name.to_string(),
            AgentProfileConfig {
                max_wildcard_registrations: None,
                wildcard_registration_prompts_per_day: None,
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
                        register: if register_allowed {
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
            acknowledge_global_registration: vec![],
            notify_user: None,
            state_dir: None,
            escalation_timeout: None,
            escalation_cooldown: 600,
            allow_automatic_human_path: false,
            browser_path: None,
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
    fn snapshot_carries_live_pins_and_the_wildcard_registration_settings() {
        let pinned = CredentialRef::with_default_domain(b"pinned");
        let mut config = same_user_config(
            "coding",
            vec![
                AgentRpRule {
                    rp_id: "*".to_string(),
                    register: RuleAction::Request,
                    authenticate: RuleAction::Request,
                    credential_selection: None,
                },
                AgentRpRule {
                    rp_id: "github.com".to_string(),
                    register: RuleAction::Deny,
                    authenticate: RuleAction::Allow,
                    credential_selection: None,
                },
            ],
        );
        config.acknowledge_same_user_registration = vec!["coding".to_string()];
        config.acknowledge_global_registration = vec!["coding".to_string()];
        {
            let profile = config.profiles.get_mut("coding").unwrap();
            profile.credential_refs = Some(vec![pinned.clone()]);
            profile.max_wildcard_registrations = Some(7);
        }
        let runtime = PolicyRuntime::new(&config, test_clock(), None).unwrap();
        let id = ProfileId::new("coding").unwrap();
        assert_eq!(
            runtime.profile_pins(&id),
            Some(ProfilePins::Configured(vec![pinned]))
        );
        assert_eq!(
            runtime.profile_pins(&ProfileId::new("missing").unwrap()),
            None
        );
        let escalation = runtime.escalation_profile(&id).unwrap();
        assert!(escalation.wildcard_registration_acknowledged);
        assert_eq!(escalation.max_wildcard_registrations, 7);
        assert_eq!(escalation.wildcard_registration_prompts_per_day, 3);

        // A reload that drops the pins (or the acknowledgement) is a policy change: new digest,
        // and the live snapshot reflects it.
        let before = runtime.digest();
        let mut unpinned = config.clone();
        unpinned.profiles.get_mut("coding").unwrap().credential_refs = None;
        assert!(runtime.reload(&unpinned).unwrap().changed);
        assert_ne!(runtime.digest(), before);
        assert_eq!(runtime.profile_pins(&id), Some(ProfilePins::Unset));
        // An empty pin list is not the same as no pin list (digest version 6).
        let mut empty = unpinned.clone();
        empty.profiles.get_mut("coding").unwrap().credential_refs = Some(vec![]);
        assert!(runtime.reload(&empty).unwrap().changed);
        assert_eq!(
            runtime.profile_pins(&id),
            Some(ProfilePins::Configured(vec![]))
        );
        let mut unacknowledged = empty.clone();
        unacknowledged.acknowledge_global_registration.clear();
        assert!(runtime.reload(&unacknowledged).unwrap().changed);
        assert!(
            !runtime
                .escalation_profile(&id)
                .unwrap()
                .wildcard_registration_acknowledged
        );
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
        let auth = runtime.resolve(&pid, &GrantAction::Authenticate, "example.com");
        assert_eq!(auth.action, RuleAction::Allow);
        assert_eq!(auth.rule, RuleIdentity::Exact("example.com".to_string()));
        let reg = runtime.resolve(&pid, &GrantAction::Register, "example.com");
        assert_eq!(reg.action, RuleAction::Deny);

        let generation = runtime.current_generation();
        let snapshot = &generation.snapshots[0];
        assert!(snapshot.action_allowed(&GrantAction::Authenticate));
        assert!(!snapshot.action_allowed(&GrantAction::Register));
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
        for action in [GrantAction::Authenticate, GrantAction::Register] {
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

        let github = runtime.resolve(&pid, &GrantAction::Authenticate, "github.com");
        assert_eq!(github.action, RuleAction::Allow);
        assert!(github.is_wildcard());
        assert_eq!(github.audit_rule(), Some("*"));

        let bank = runtime.resolve(&pid, &GrantAction::Authenticate, "bank.example.com");
        assert_eq!(bank.configured, RuleAction::Request);
        assert_eq!(bank.action, RuleAction::Request);
        assert_eq!(bank.audit_rule(), Some("bank.example.com"));

        assert_eq!(
            runtime
                .resolve(&pid, &GrantAction::Register, "github.com")
                .action,
            RuleAction::Deny
        );
        assert_eq!(
            runtime
                .resolve(&pid, &GrantAction::Authenticate, "com")
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

        let blocked = runtime.resolve(&pid, &GrantAction::Authenticate, "blocked.example.com");
        assert_eq!(blocked.action, RuleAction::Deny);
        assert_eq!(
            blocked.rule,
            RuleIdentity::Exact("blocked.example.com".to_string())
        );
        let other = runtime.resolve(&pid, &GrantAction::Authenticate, "other.example.com");
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
        let auth = GrantAction::Authenticate;

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

        let denied = runtime.resolve(&pid, &GrantAction::Authenticate, "denied.example.com");
        assert_eq!(denied.action, RuleAction::Deny);
        assert!(!denied.granted);

        let removed = runtime.resolve(&pid, &GrantAction::Authenticate, "removed.example.com");
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
        let reg = runtime.resolve(&pid, &GrantAction::Register, "example.com");
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
                .resolve(&pid, &GrantAction::Authenticate, "example.com")
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
                .resolve(&pid, &GrantAction::Authenticate, "localhost")
                .action,
            RuleAction::Deny
        );
        assert_eq!(
            runtime
                .resolve(&pid, &GrantAction::Register, "example.com")
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

        let wild = runtime.resolve(&pid, &GrantAction::Authenticate, "any.example.com");
        assert_eq!(wild.selection, CredentialSelection::Single);
        let exact = runtime.resolve(&pid, &GrantAction::Authenticate, "exact.example.com");
        assert_eq!(exact.selection, CredentialSelection::Newest);
    }

    #[test]
    fn test_resolve_unknown_profile_denies() {
        let config = make_isolated_config("known", vec!["example.com"], false);
        let (runtime, _clock) = make_runtime(&config);
        let unknown = ProfileId::new("unknown").unwrap();
        for action in [GrantAction::Authenticate, GrantAction::Register] {
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
        let auth = GrantAction::Authenticate;
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
}
