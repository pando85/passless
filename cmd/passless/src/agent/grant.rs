use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use passless_core::agent::{
    CredentialRef, EndpointId, GrantId, PolicyDigest, PolicyGenerationId, PrincipalSessionId,
    ProfileId, RegistrationGrantId,
};

use super::browser::Clock;
use super::intent::AdminAuthority;

const GRANT_STATE_ACTIVE: u8 = 0;
const GRANT_STATE_REVOKED: u8 = 1;
const GRANT_STATE_EXPIRED: u8 = 2;

const CLAIM_NONCE_BYTES: usize = 32;
const MAX_RP_ID_LEN: usize = 253;
const MAX_CREDENTIALS_PER_GRANT: usize = 64;
const MAX_RP_IDS_PER_GRANT: usize = 32;
const MIN_TTL_SECS: u64 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantError {
    EmptyCredentialSet,
    EmptyRpIdSet,
    WildcardRpId(String),
    RpIdTooLong(String),
    TooManyRpIds(usize),
    TooManyCredentials(usize),
    TtlExceedsProfileMax {
        requested: u64,
        max: u64,
    },
    TtlZero,
    GrantNotActive(GrantId),
    GrantNotFound(GrantId),
    ClaimAlreadyConsumed(CeremonyId),
    ClaimNotFound,
    RpIdNotInGrant(String),
    CredentialNotInGrant(String),
    ActionNotInGrant(String),
    PolicyMismatch,
    SessionMismatch,
    ProfileMismatch,
    ClockAmbiguity,
    PendingRequestNotFound(GrantRequestId),
    RequestAlreadyResolved(GrantRequestId),
    MaxConcurrentGrantsExceeded {
        limit: u64,
    },
    RegistrationGrantNotFound(RegistrationGrantId),
    RegistrationGrantNotActive(RegistrationGrantId),
    RegistrationRpIdMismatch {
        grant_rp: String,
        request_rp: String,
    },
}

impl fmt::Display for GrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCredentialSet => write!(f, "credential set must not be empty"),
            Self::EmptyRpIdSet => write!(f, "RP ID set must not be empty"),
            Self::WildcardRpId(id) => write!(f, "wildcard RP ID not allowed: {}", id),
            Self::RpIdTooLong(id) => write!(f, "RP ID too long: {}", id),
            Self::TooManyRpIds(n) => {
                write!(f, "too many RP IDs: {} (max {})", n, MAX_RP_IDS_PER_GRANT)
            }
            Self::TooManyCredentials(n) => write!(
                f,
                "too many credentials: {} (max {})",
                n, MAX_CREDENTIALS_PER_GRANT
            ),
            Self::TtlExceedsProfileMax { requested, max } => {
                write!(f, "TTL {}s exceeds profile max {}s", requested, max)
            }
            Self::TtlZero => write!(f, "TTL must be at least 1 second"),
            Self::GrantNotActive(id) => write!(f, "grant {} is not active", id),
            Self::GrantNotFound(id) => write!(f, "grant {} not found", id),
            Self::ClaimAlreadyConsumed(id) => write!(f, "claim {} already consumed", id),
            Self::ClaimNotFound => write!(f, "claim not found"),
            Self::RpIdNotInGrant(id) => write!(f, "RP ID {} not in grant scope", id),
            Self::CredentialNotInGrant(id) => write!(f, "credential {} not in grant scope", id),
            Self::ActionNotInGrant(action) => write!(f, "action {} not in grant scope", action),
            Self::PolicyMismatch => write!(f, "policy generation or digest mismatch"),
            Self::SessionMismatch => write!(f, "principal session mismatch"),
            Self::ProfileMismatch => write!(f, "profile mismatch"),
            Self::ClockAmbiguity => write!(f, "monotonic clock ambiguity detected"),
            Self::PendingRequestNotFound(id) => write!(f, "pending request {} not found", id),
            Self::RequestAlreadyResolved(id) => write!(f, "request {} already resolved", id),
            Self::MaxConcurrentGrantsExceeded { limit } => {
                write!(f, "max concurrent grants exceeded (limit: {})", limit)
            }
            Self::RegistrationGrantNotFound(id) => {
                write!(f, "registration grant {} not found", id)
            }
            Self::RegistrationGrantNotActive(id) => {
                write!(f, "registration grant {} is not active", id)
            }
            Self::RegistrationRpIdMismatch {
                grant_rp,
                request_rp,
            } => {
                write!(
                    f,
                    "registration grant RP ID '{}' does not match request RP ID '{}'",
                    grant_rp, request_rp
                )
            }
        }
    }
}

impl std::error::Error for GrantError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantState {
    Active,
    Revoked,
    Expired,
}

impl GrantState {
    fn from_atomic(v: u8) -> Option<Self> {
        match v {
            GRANT_STATE_ACTIVE => Some(Self::Active),
            GRANT_STATE_REVOKED => Some(Self::Revoked),
            GRANT_STATE_EXPIRED => Some(Self::Expired),
            _ => None,
        }
    }

    fn to_atomic(self) -> u8 {
        match self {
            Self::Active => GRANT_STATE_ACTIVE,
            Self::Revoked => GRANT_STATE_REVOKED,
            Self::Expired => GRANT_STATE_EXPIRED,
        }
    }
}

impl fmt::Display for GrantState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Revoked => write!(f, "revoked"),
            Self::Expired => write!(f, "expired"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CredentialSet {
    sorted: Vec<CredentialRef>,
}

impl CredentialSet {
    pub fn new(mut creds: Vec<CredentialRef>) -> Result<Self, GrantError> {
        if creds.is_empty() {
            return Err(GrantError::EmptyCredentialSet);
        }
        if creds.len() > MAX_CREDENTIALS_PER_GRANT {
            return Err(GrantError::TooManyCredentials(creds.len()));
        }
        creds.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        creds.dedup_by(|a, b| a.as_bytes() == b.as_bytes());
        Ok(Self { sorted: creds })
    }

    pub fn contains(&self, cred: &CredentialRef) -> bool {
        self.sorted
            .binary_search_by(|c| c.as_bytes().cmp(cred.as_bytes()))
            .is_ok()
    }

    pub fn len(&self) -> usize {
        self.sorted.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sorted.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &CredentialRef> {
        self.sorted.iter()
    }
}

impl PartialEq for CredentialSet {
    fn eq(&self, other: &Self) -> bool {
        if self.sorted.len() != other.sorted.len() {
            return false;
        }
        self.sorted
            .iter()
            .zip(other.sorted.iter())
            .all(|(a, b)| a.as_bytes() == b.as_bytes())
    }
}

impl Eq for CredentialSet {}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct GrantRequestId(String);

impl GrantRequestId {
    pub fn new() -> Self {
        Self(GrantId::new().into_inner())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for GrantRequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for GrantRequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for GrantRequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GrantRequestId(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CeremonyId(String);

impl CeremonyId {
    pub fn new() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..CLAIM_NONCE_BYTES).map(|_| rng.r#gen()).collect();
        Self(hex::encode(bytes))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for CeremonyId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CeremonyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for CeremonyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CeremonyId(<redacted>)")
    }
}

pub fn normalize_rp_id(raw: &str) -> Result<String, GrantError> {
    let trimmed = raw.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return Err(GrantError::EmptyRpIdSet);
    }
    if trimmed.len() > MAX_RP_ID_LEN {
        return Err(GrantError::RpIdTooLong(trimmed.clone()));
    }
    if trimmed.contains('*') || trimmed.starts_with('.') {
        return Err(GrantError::WildcardRpId(trimmed));
    }
    Ok(trimmed)
}

fn validate_rp_ids(rp_ids: &[String]) -> Result<BTreeSet<String>, GrantError> {
    if rp_ids.is_empty() {
        return Err(GrantError::EmptyRpIdSet);
    }
    if rp_ids.len() > MAX_RP_IDS_PER_GRANT {
        return Err(GrantError::TooManyRpIds(rp_ids.len()));
    }
    let mut normalized = BTreeSet::new();
    for raw in rp_ids {
        let n = normalize_rp_id(raw)?;
        normalized.insert(n);
    }
    Ok(normalized)
}

pub struct GrantRequestParams {
    pub profile_id: ProfileId,
    pub session_id: PrincipalSessionId,
    pub endpoint_id: EndpointId,
    pub principal_digest: [u8; 32],
    pub rp_ids: Vec<String>,
    pub credentials: Vec<CredentialRef>,
    pub requested_ttl_secs: u64,
}

#[derive(Debug, Clone)]
pub struct GrantRequest {
    pub profile_id: ProfileId,
    pub session_id: PrincipalSessionId,
    pub endpoint_id: EndpointId,
    pub principal_digest: [u8; 32],
    pub rp_ids: Vec<String>,
    pub credentials: Vec<CredentialRef>,
    pub requested_ttl_secs: u64,
    pub resolved: bool,
    pub resolved_grant_id: Option<GrantId>,
}

#[derive(Debug)]
pub struct Grant {
    pub id: GrantId,
    pub profile_id: ProfileId,
    pub session_id: PrincipalSessionId,
    pub endpoint_id: EndpointId,
    pub principal_digest: [u8; 32],
    pub policy_generation: PolicyGenerationId,
    pub policy_digest: PolicyDigest,
    pub rp_ids: BTreeSet<String>,
    pub credentials: CredentialSet,
    pub issued_at_mono: u64,
    pub expiry_mono: u64,
    state: AtomicU8,
}

impl Grant {
    pub fn state(&self) -> GrantState {
        GrantState::from_atomic(self.state.load(Ordering::Acquire)).unwrap_or(GrantState::Revoked)
    }

    fn try_transition(&self, from: GrantState, to: GrantState) -> bool {
        self.state
            .compare_exchange(
                from.to_atomic(),
                to.to_atomic(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimIntent {
    pub action: String,
    pub rp_id: String,
    pub credential_ref: CredentialRef,
}

pub struct AuthorizationClaim {
    pub ceremony_id: CeremonyId,
    pub grant_id: GrantId,
    pub intent: ClaimIntent,
    consumed: AtomicBool,
}

impl AuthorizationClaim {
    fn new(ceremony_id: CeremonyId, grant_id: GrantId, intent: ClaimIntent) -> Self {
        Self {
            ceremony_id,
            grant_id,
            intent,
            consumed: AtomicBool::new(false),
        }
    }

    pub fn try_consume(&self) -> Result<&ClaimIntent, GrantError> {
        if self
            .consumed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            Ok(&self.intent)
        } else {
            Err(GrantError::ClaimAlreadyConsumed(self.ceremony_id.clone()))
        }
    }
}

impl fmt::Debug for AuthorizationClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizationClaim")
            .field("ceremony_id", &self.ceremony_id)
            .field("grant_id", &self.grant_id)
            .field("intent", &self.intent)
            .field("consumed", &self.consumed.load(Ordering::Acquire))
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct GrantSnapshotForSign {
    pub grant_id: GrantId,
    pub profile_id: ProfileId,
    pub rp_ids: Vec<String>,
    pub credential_refs: Vec<CredentialRef>,
    pub state: GrantState,
    pub expiry_mono: u64,
}

#[derive(Debug, Clone)]
pub struct GrantSnapshot {
    pub id: GrantId,
    pub profile_id: ProfileId,
    pub state: GrantState,
    pub rp_ids: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub struct GrantDetails {
    pub id: GrantId,
    pub profile_id: ProfileId,
    pub state: GrantState,
    pub first_rp_id: String,
    pub first_credential_ref: Option<CredentialRef>,
    pub issued_at_mono: u64,
    pub expiry_mono: u64,
}

pub struct GrantQueryParams<'a> {
    pub profile_id: &'a ProfileId,
    pub session_id: &'a PrincipalSessionId,
    pub endpoint_id: &'a EndpointId,
    pub principal_digest: &'a [u8; 32],
    pub policy_generation: &'a PolicyGenerationId,
    pub policy_digest: &'a PolicyDigest,
    pub rp_id: &'a str,
    pub credential_ref: Option<&'a CredentialRef>,
}

pub struct GrantRegistry {
    grants: HashMap<GrantId, Grant>,
    pending_requests: HashMap<GrantRequestId, GrantRequest>,
    claims: HashMap<CeremonyId, AuthorizationClaim>,
    clock: Arc<dyn Clock>,
    policy_generation: PolicyGenerationId,
    policy_digest: PolicyDigest,
    max_ttl_secs: u64,
    allowed_actions: BTreeSet<String>,
    max_concurrent_grants: u64,
    last_seen_mono: u64,
}

impl GrantRegistry {
    pub fn new(
        clock: Arc<dyn Clock>,
        policy_generation: PolicyGenerationId,
        policy_digest: PolicyDigest,
        max_ttl_secs: u64,
        allowed_actions: BTreeSet<String>,
        max_concurrent_grants: u64,
    ) -> Self {
        Self {
            grants: HashMap::new(),
            pending_requests: HashMap::new(),
            claims: HashMap::new(),
            clock,
            policy_generation,
            policy_digest,
            max_ttl_secs,
            allowed_actions,
            max_concurrent_grants,
            last_seen_mono: 0,
        }
    }

    fn check_clock(&mut self) -> Result<(), GrantError> {
        let now = self.clock.monotonic_secs();
        if now < self.last_seen_mono {
            self.fail_closed_all();
            return Err(GrantError::ClockAmbiguity);
        }
        self.last_seen_mono = now;
        Ok(())
    }

    pub fn request_grant(
        &mut self,
        params: GrantRequestParams,
    ) -> Result<GrantRequestId, GrantError> {
        self.check_clock()?;

        validate_rp_ids(&params.rp_ids)?;

        let cred_set = CredentialSet::new(params.credentials)?;

        if params.requested_ttl_secs == 0 {
            return Err(GrantError::TtlZero);
        }
        if params.requested_ttl_secs > self.max_ttl_secs {
            return Err(GrantError::TtlExceedsProfileMax {
                requested: params.requested_ttl_secs,
                max: self.max_ttl_secs,
            });
        }

        let request_id = GrantRequestId::new();
        let request = GrantRequest {
            profile_id: params.profile_id,
            session_id: params.session_id,
            endpoint_id: params.endpoint_id,
            principal_digest: params.principal_digest,
            rp_ids: params.rp_ids,
            credentials: cred_set.sorted,
            requested_ttl_secs: params.requested_ttl_secs,
            resolved: false,
            resolved_grant_id: None,
        };

        self.pending_requests.insert(request_id.clone(), request);
        Ok(request_id)
    }

    pub fn approve_grant(
        &mut self,
        request_id: &GrantRequestId,
        _authority: &AdminAuthority,
    ) -> Result<GrantId, GrantError> {
        self.check_clock()?;

        let request = self
            .pending_requests
            .get(request_id)
            .ok_or_else(|| GrantError::PendingRequestNotFound(request_id.clone()))?;

        if request.resolved {
            return Err(GrantError::RequestAlreadyResolved(request_id.clone()));
        }

        let active_count = self
            .grants
            .values()
            .filter(|g| g.state() == GrantState::Active)
            .count() as u64;
        if active_count >= self.max_concurrent_grants {
            return Err(GrantError::MaxConcurrentGrantsExceeded {
                limit: self.max_concurrent_grants,
            });
        }

        let validated_rps = validate_rp_ids(&request.rp_ids)?;
        let cred_set = CredentialSet::new(request.credentials.clone())?;
        let ttl = clamp_ttl(request.requested_ttl_secs, self.max_ttl_secs);
        let now = self.clock.monotonic_secs();

        let grant_id = GrantId::new();
        let grant = Grant {
            id: grant_id.clone(),
            profile_id: request.profile_id.clone(),
            session_id: request.session_id.clone(),
            endpoint_id: request.endpoint_id.clone(),
            principal_digest: request.principal_digest,
            policy_generation: self.policy_generation.clone(),
            policy_digest: self.policy_digest.clone(),
            rp_ids: validated_rps,
            credentials: cred_set,
            issued_at_mono: now,
            expiry_mono: now.saturating_add(ttl),
            state: AtomicU8::new(GRANT_STATE_ACTIVE),
        };

        self.grants.insert(grant_id.clone(), grant);

        if let Some(req) = self.pending_requests.get_mut(request_id) {
            req.resolved = true;
            req.resolved_grant_id = Some(grant_id.clone());
        }

        Ok(grant_id)
    }

    pub fn resolved_grant_id(&self, request_id: &GrantRequestId) -> Option<GrantId> {
        self.pending_requests
            .get(request_id)
            .and_then(|r| r.resolved_grant_id.clone())
    }

    pub fn revoke_grant(
        &self,
        grant_id: &GrantId,
        _authority: &AdminAuthority,
    ) -> Result<GrantState, GrantError> {
        let grant = self
            .grants
            .get(grant_id)
            .ok_or_else(|| GrantError::GrantNotFound(grant_id.clone()))?;

        let current = grant.state();
        if current != GrantState::Active {
            return Err(GrantError::GrantNotActive(grant_id.clone()));
        }

        if grant.try_transition(GrantState::Active, GrantState::Revoked) {
            Ok(GrantState::Revoked)
        } else {
            Err(GrantError::GrantNotActive(grant_id.clone()))
        }
    }

    pub fn show_grant(&self, grant_id: &GrantId) -> Option<GrantSnapshot> {
        let grant = self.grants.get(grant_id)?;
        Some(GrantSnapshot {
            id: grant.id.clone(),
            profile_id: grant.profile_id.clone(),
            state: grant.state(),
            rp_ids: grant.rp_ids.clone(),
        })
    }

    pub fn list_all_snapshots(&self) -> Vec<GrantSnapshot> {
        self.grants
            .values()
            .map(|grant| GrantSnapshot {
                id: grant.id.clone(),
                profile_id: grant.profile_id.clone(),
                state: grant.state(),
                rp_ids: grant.rp_ids.clone(),
            })
            .collect()
    }

    pub fn find_grant_with_details(&self, grant_id: &GrantId) -> Option<GrantDetails> {
        let grant = self.grants.get(grant_id)?;
        let first_rp = grant.rp_ids.iter().next().cloned().unwrap_or_default();
        let first_cred = grant.credentials.iter().next().cloned();
        Some(GrantDetails {
            id: grant.id.clone(),
            profile_id: grant.profile_id.clone(),
            state: grant.state(),
            first_rp_id: first_rp,
            first_credential_ref: first_cred,
            issued_at_mono: grant.issued_at_mono,
            expiry_mono: grant.expiry_mono,
        })
    }

    pub fn find_grant_id_by_credential(&self, cred_ref: &CredentialRef) -> Vec<GrantId> {
        self.grants
            .values()
            .filter(|g| g.state() == GrantState::Active && g.credentials.contains(cred_ref))
            .map(|g| g.id.clone())
            .collect()
    }

    pub fn cancel_request(&mut self, request_id: &GrantRequestId) -> Result<(), GrantError> {
        let request = self
            .pending_requests
            .get_mut(request_id)
            .ok_or_else(|| GrantError::PendingRequestNotFound(request_id.clone()))?;

        if request.resolved {
            return Err(GrantError::RequestAlreadyResolved(request_id.clone()));
        }

        request.resolved = true;
        Ok(())
    }

    pub fn on_policy_reload(
        &mut self,
        new_generation: PolicyGenerationId,
        new_digest: PolicyDigest,
        new_max_ttl: u64,
        new_actions: BTreeSet<String>,
    ) {
        self.fail_closed_all();
        self.policy_generation = new_generation;
        self.policy_digest = new_digest;
        self.max_ttl_secs = new_max_ttl;
        self.allowed_actions = new_actions;
        self.pending_requests.clear();
        self.claims.clear();
    }

    pub fn on_principal_exit(&mut self, session_id: &PrincipalSessionId) {
        for grant in self.grants.values() {
            if grant.session_id == *session_id && grant.state() == GrantState::Active {
                let _ = grant.try_transition(GrantState::Active, GrantState::Revoked);
            }
        }
        self.pending_requests
            .retain(|_, req| req.session_id != *session_id);
        self.claims.retain(|_, c| {
            self.grants
                .get(&c.grant_id)
                .is_some_and(|g| g.session_id != *session_id || g.state() != GrantState::Active)
        });
    }

    pub fn on_daemon_restart(&mut self) {
        self.grants.clear();
        self.pending_requests.clear();
        self.claims.clear();
        self.last_seen_mono = 0;
    }

    pub fn check_expired(&mut self) -> Vec<GrantId> {
        let now = self.clock.monotonic_secs();
        let mut expired = Vec::new();

        for (id, grant) in &self.grants {
            if grant.state() == GrantState::Active && now >= grant.expiry_mono {
                expired.push(id.clone());
            }
        }

        for id in &expired {
            if let Some(grant) = self.grants.get(id) {
                let _ = grant.try_transition(GrantState::Active, GrantState::Expired);
            }
        }

        expired
    }

    fn fail_closed_all(&mut self) {
        for grant in self.grants.values() {
            if grant.state() == GrantState::Active {
                let _ = grant.try_transition(GrantState::Active, GrantState::Revoked);
            }
        }
    }

    pub fn grant_count(&self) -> usize {
        self.grants.len()
    }

    pub fn active_count(&self) -> usize {
        self.grants
            .values()
            .filter(|g| g.state() == GrantState::Active)
            .count()
    }

    pub fn pending_count(&self) -> usize {
        self.pending_requests
            .values()
            .filter(|r| !r.resolved)
            .count()
    }

    pub fn show_grant_by_profile_rp(&self, query: &GrantQueryParams) -> Option<GrantId> {
        let now = self.clock.monotonic_secs();
        let normalized_rp = query.rp_id.trim().to_ascii_lowercase();
        self.grants
            .values()
            .find(|g| {
                g.state() == GrantState::Active
                    && g.profile_id == *query.profile_id
                    && g.session_id == *query.session_id
                    && g.endpoint_id == *query.endpoint_id
                    && g.principal_digest == *query.principal_digest
                    && g.policy_generation == *query.policy_generation
                    && g.policy_digest == *query.policy_digest
                    && g.rp_ids.contains(&normalized_rp)
                    && g.expiry_mono > now
                    && match (query.credential_ref, g.credentials.iter().next()) {
                        (Some(cr), _) => g.credentials.contains(cr),
                        (None, _) => true,
                    }
            })
            .map(|g| g.id.clone())
    }

    pub fn claim_for_authorize(
        &mut self,
        grant_id: &GrantId,
        session_id: &PrincipalSessionId,
        intent: ClaimIntent,
    ) -> Result<CeremonyId, GrantError> {
        self.check_clock()?;
        self.check_expired();

        let normalized_rp = normalize_rp_id(&intent.rp_id)?;

        let grant = self
            .grants
            .get(grant_id)
            .ok_or_else(|| GrantError::GrantNotFound(grant_id.clone()))?;

        if grant.state() != GrantState::Active {
            return Err(GrantError::GrantNotActive(grant_id.clone()));
        }

        if grant.session_id != *session_id {
            return Err(GrantError::SessionMismatch);
        }

        if grant.policy_generation != self.policy_generation
            || grant.policy_digest != self.policy_digest
        {
            return Err(GrantError::PolicyMismatch);
        }

        if !grant.rp_ids.contains(&normalized_rp) {
            return Err(GrantError::RpIdNotInGrant(normalized_rp));
        }

        if !grant.credentials.contains(&intent.credential_ref) {
            return Err(GrantError::CredentialNotInGrant(
                intent.credential_ref.to_hex(),
            ));
        }

        if !self.allowed_actions.contains(&intent.action) {
            return Err(GrantError::ActionNotInGrant(intent.action.clone()));
        }

        let ceremony_id = CeremonyId::new();
        let bound_intent = ClaimIntent {
            action: intent.action,
            rp_id: normalized_rp,
            credential_ref: intent.credential_ref,
        };

        let claim = AuthorizationClaim::new(ceremony_id.clone(), grant_id.clone(), bound_intent);
        self.claims.insert(ceremony_id.clone(), claim);
        Ok(ceremony_id)
    }

    pub fn cancel_claim(&mut self, ceremony_id: &CeremonyId) {
        self.claims.remove(ceremony_id);
    }

    pub fn consume_claim_by_ceremony(
        &self,
        ceremony_id: &CeremonyId,
    ) -> Result<&ClaimIntent, GrantError> {
        let claim = self
            .claims
            .get(ceremony_id)
            .ok_or(GrantError::ClaimNotFound)?;
        claim.try_consume()
    }

    #[cfg(test)]
    pub fn claim(
        &mut self,
        grant_id: &GrantId,
        session_id: &PrincipalSessionId,
        intent: ClaimIntent,
    ) -> Result<&AuthorizationClaim, GrantError> {
        let ceremony_id = self.claim_for_authorize(grant_id, session_id, intent)?;
        self.claims
            .get(&ceremony_id)
            .ok_or(GrantError::ClaimNotFound)
    }

    #[cfg(test)]
    pub fn consume_claim(&self, ceremony_id: &CeremonyId) -> Result<&ClaimIntent, GrantError> {
        self.consume_claim_by_ceremony(ceremony_id)
    }

    pub fn is_grant_active(&self, grant_id: &GrantId) -> bool {
        self.grants
            .get(grant_id)
            .is_some_and(|g| g.state() == GrantState::Active)
    }

    pub fn snapshot_for_sign(&self, grant_id: &GrantId) -> Option<GrantSnapshotForSign> {
        let grant = self.grants.get(grant_id)?;
        let state = grant.state();
        let rp_ids: Vec<String> = grant.rp_ids.iter().cloned().collect();
        let cred_refs: Vec<CredentialRef> = grant.credentials.iter().cloned().collect();
        Some(GrantSnapshotForSign {
            grant_id: grant.id.clone(),
            profile_id: grant.profile_id.clone(),
            rp_ids,
            credential_refs: cred_refs,
            state,
            expiry_mono: grant.expiry_mono,
        })
    }

    pub fn grant_policy_generation(&self, grant_id: &GrantId) -> Option<&PolicyGenerationId> {
        self.grants.get(grant_id).map(|g| &g.policy_generation)
    }

    pub fn grant_policy_digest(&self, grant_id: &GrantId) -> Option<&PolicyDigest> {
        self.grants.get(grant_id).map(|g| &g.policy_digest)
    }

    pub fn current_policy_generation(&self) -> &PolicyGenerationId {
        &self.policy_generation
    }

    pub fn current_policy_digest(&self) -> &PolicyDigest {
        &self.policy_digest
    }

    pub fn cancel_claims_for_session(&mut self, session_id: &PrincipalSessionId) {
        self.claims.retain(|_, c| {
            self.grants
                .get(&c.grant_id)
                .is_some_and(|g| g.session_id != *session_id)
        });
    }

    pub fn cancel_claims_for_grant(&mut self, grant_id: &GrantId) {
        self.claims.retain(|_, c| c.grant_id != *grant_id);
    }
}

#[derive(Debug)]
pub struct RegistrationGrant {
    pub id: RegistrationGrantId,
    pub profile_id: ProfileId,
    pub session_id: PrincipalSessionId,
    pub endpoint_id: EndpointId,
    pub principal_digest: [u8; 32],
    pub rp_id: String,
    pub issued_at_mono: u64,
    pub expiry_mono: u64,
    state: AtomicU8,
}

impl RegistrationGrant {
    pub fn state(&self) -> GrantState {
        GrantState::from_atomic(self.state.load(Ordering::Acquire)).unwrap_or(GrantState::Revoked)
    }

    fn try_transition(&self, from: GrantState, to: GrantState) -> bool {
        self.state
            .compare_exchange(
                from.to_atomic(),
                to.to_atomic(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

#[derive(Debug, Clone)]
pub struct RegistrationGrantSnapshot {
    pub grant_id: RegistrationGrantId,
    pub profile_id: ProfileId,
    pub rp_id: String,
    pub state: GrantState,
    pub issued_at_mono: u64,
    pub expiry_mono: u64,
}

pub struct RegistrationGrantRegistry {
    grants: HashMap<RegistrationGrantId, RegistrationGrant>,
    clock: Arc<dyn Clock>,
    max_ttl_secs: u64,
    last_seen_mono: u64,
}

impl RegistrationGrantRegistry {
    pub fn new(clock: Arc<dyn Clock>, max_ttl_secs: u64) -> Self {
        Self {
            grants: HashMap::new(),
            clock,
            max_ttl_secs,
            last_seen_mono: 0,
        }
    }

    fn check_clock(&mut self) -> Result<(), GrantError> {
        let now = self.clock.monotonic_secs();
        if now < self.last_seen_mono {
            self.fail_closed_all();
            return Err(GrantError::ClockAmbiguity);
        }
        self.last_seen_mono = now;
        Ok(())
    }

    pub fn request_registration(
        &mut self,
        profile_id: ProfileId,
        session_id: PrincipalSessionId,
        endpoint_id: EndpointId,
        principal_digest: [u8; 32],
        rp_id: String,
        ttl_secs: u64,
    ) -> Result<RegistrationGrantId, GrantError> {
        self.check_clock()?;

        let normalized_rp = normalize_rp_id(&rp_id)?;

        if ttl_secs == 0 {
            return Err(GrantError::TtlZero);
        }
        if ttl_secs > self.max_ttl_secs {
            return Err(GrantError::TtlExceedsProfileMax {
                requested: ttl_secs,
                max: self.max_ttl_secs,
            });
        }

        let ttl = clamp_ttl(ttl_secs, self.max_ttl_secs);
        let now = self.clock.monotonic_secs();
        let grant_id = RegistrationGrantId::new();

        let grant = RegistrationGrant {
            id: grant_id.clone(),
            profile_id,
            session_id,
            endpoint_id,
            principal_digest,
            rp_id: normalized_rp,
            issued_at_mono: now,
            expiry_mono: now.saturating_add(ttl),
            state: AtomicU8::new(GRANT_STATE_ACTIVE),
        };

        self.grants.insert(grant_id.clone(), grant);
        Ok(grant_id)
    }

    pub fn resolve_registration_grant(
        &self,
        grant_id: &RegistrationGrantId,
        rp_id: &str,
    ) -> Option<RegistrationGrantSnapshot> {
        let grant = self.grants.get(grant_id)?;
        let normalized_rp = normalize_rp_id(rp_id).ok()?;

        if grant.state() != GrantState::Active {
            return None;
        }

        let now = self.clock.monotonic_secs();
        if now >= grant.expiry_mono {
            return None;
        }

        if grant.rp_id != normalized_rp {
            return None;
        }

        Some(RegistrationGrantSnapshot {
            grant_id: grant.id.clone(),
            profile_id: grant.profile_id.clone(),
            rp_id: grant.rp_id.clone(),
            state: grant.state(),
            issued_at_mono: grant.issued_at_mono,
            expiry_mono: grant.expiry_mono,
        })
    }

    pub fn revoke_registration(&self, grant_id: &RegistrationGrantId) -> Result<(), GrantError> {
        let grant = self
            .grants
            .get(grant_id)
            .ok_or_else(|| GrantError::RegistrationGrantNotFound(grant_id.clone()))?;

        let current = grant.state();
        if current != GrantState::Active {
            return Err(GrantError::RegistrationGrantNotActive(grant_id.clone()));
        }

        if grant.try_transition(GrantState::Active, GrantState::Revoked) {
            Ok(())
        } else {
            Err(GrantError::RegistrationGrantNotActive(grant_id.clone()))
        }
    }

    pub fn check_expired(&mut self) -> Vec<RegistrationGrantId> {
        let now = self.clock.monotonic_secs();
        let mut expired = Vec::new();

        for (id, grant) in &self.grants {
            if grant.state() == GrantState::Active && now >= grant.expiry_mono {
                expired.push(id.clone());
            }
        }

        for id in &expired {
            if let Some(grant) = self.grants.get(id) {
                let _ = grant.try_transition(GrantState::Active, GrantState::Expired);
            }
        }

        expired
    }

    pub fn on_principal_exit(&mut self, session_id: &PrincipalSessionId) {
        for grant in self.grants.values() {
            if grant.session_id == *session_id && grant.state() == GrantState::Active {
                let _ = grant.try_transition(GrantState::Active, GrantState::Revoked);
            }
        }
    }

    pub fn on_daemon_restart(&mut self) {
        self.grants.clear();
        self.last_seen_mono = 0;
    }

    fn fail_closed_all(&mut self) {
        for grant in self.grants.values() {
            if grant.state() == GrantState::Active {
                let _ = grant.try_transition(GrantState::Active, GrantState::Revoked);
            }
        }
    }

    pub fn grant_count(&self) -> usize {
        self.grants.len()
    }

    pub fn active_count(&self) -> usize {
        self.grants
            .values()
            .filter(|g| g.state() == GrantState::Active)
            .count()
    }

    pub fn list_all_snapshots(&self) -> Vec<RegistrationGrantSnapshot> {
        self.grants
            .values()
            .map(|grant| RegistrationGrantSnapshot {
                grant_id: grant.id.clone(),
                profile_id: grant.profile_id.clone(),
                rp_id: grant.rp_id.clone(),
                state: grant.state(),
                issued_at_mono: grant.issued_at_mono,
                expiry_mono: grant.expiry_mono,
            })
            .collect()
    }
}

fn clamp_ttl(requested: u64, max: u64) -> u64 {
    if requested < MIN_TTL_SECS {
        MIN_TTL_SECS
    } else if requested > max {
        max
    } else {
        requested
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use sha2::{Digest, Sha256};

    const PRINCIPAL_DIGEST_DOMAIN: &str = "passless/principal-digest/v1";

    fn compute_principal_digest(pid: u32, start_time_ticks: u64, cgroup: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(PRINCIPAL_DIGEST_DOMAIN.as_bytes());
        hasher.update(pid.to_le_bytes());
        hasher.update(start_time_ticks.to_le_bytes());
        hasher.update(cgroup.as_bytes());
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    impl GrantState {
        fn is_terminal(self) -> bool {
            matches!(self, Self::Revoked | Self::Expired)
        }
    }

    impl CredentialSet {
        fn is_subset_of(&self, other: &CredentialSet) -> bool {
            self.sorted.iter().all(|c| other.contains(c))
        }

        fn is_superset_of(&self, other: &CredentialSet) -> bool {
            other.is_subset_of(self)
        }
    }

    impl AuthorizationClaim {
        fn is_consumed(&self) -> bool {
            self.consumed.load(Ordering::Acquire)
        }
    }

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

    fn test_profile_id() -> ProfileId {
        ProfileId::new("test-profile").unwrap()
    }

    fn test_session_id() -> PrincipalSessionId {
        PrincipalSessionId::new()
    }

    fn test_endpoint_id() -> EndpointId {
        EndpointId::new()
    }

    fn test_policy_gen() -> PolicyGenerationId {
        PolicyGenerationId::new()
    }

    fn test_policy_digest() -> PolicyDigest {
        let policy = passless_core::agent::Policy::new(
            &test_profile_id(),
            vec!["make_credential".to_string(), "get_assertion".to_string()],
            5,
            true,
            300,
        )
        .unwrap();
        policy.digest()
    }

    fn test_actions() -> BTreeSet<String> {
        BTreeSet::from(["make_credential".to_string(), "get_assertion".to_string()])
    }

    fn test_cred(id: &[u8]) -> CredentialRef {
        CredentialRef::with_default_domain(id)
    }

    fn test_digest(pid: u32) -> [u8; 32] {
        compute_principal_digest(pid, 12345, "/user.slice")
    }

    fn make_registry(clock: &Arc<MockClock>) -> GrantRegistry {
        GrantRegistry::new(
            clock.clone(),
            test_policy_gen(),
            test_policy_digest(),
            300,
            test_actions(),
            10,
        )
    }

    fn request_and_approve(
        registry: &mut GrantRegistry,
        session: &PrincipalSessionId,
        rp_ids: Vec<String>,
        creds: Vec<CredentialRef>,
        ttl: u64,
    ) -> GrantId {
        let authority = super::super::intent::admin_authority();
        let req_id = registry
            .request_grant(GrantRequestParams {
                profile_id: test_profile_id(),
                session_id: session.clone(),
                endpoint_id: test_endpoint_id(),
                principal_digest: test_digest(1000),
                rp_ids,
                credentials: creds,
                requested_ttl_secs: ttl,
            })
            .unwrap();
        registry.approve_grant(&req_id, &authority).unwrap()
    }

    #[test]
    fn test_grant_state_display() {
        assert_eq!(GrantState::Active.to_string(), "active");
        assert_eq!(GrantState::Revoked.to_string(), "revoked");
        assert_eq!(GrantState::Expired.to_string(), "expired");
    }

    #[test]
    fn test_grant_state_is_terminal() {
        assert!(!GrantState::Active.is_terminal());
        assert!(GrantState::Revoked.is_terminal());
        assert!(GrantState::Expired.is_terminal());
    }

    #[test]
    fn test_normalize_rp_id_basic() {
        assert_eq!(normalize_rp_id("Example.COM").unwrap(), "example.com");
        assert_eq!(normalize_rp_id("  example.com  ").unwrap(), "example.com");
    }

    #[test]
    fn test_normalize_rp_id_rejects_wildcard() {
        assert!(matches!(
            normalize_rp_id("*.example.com"),
            Err(GrantError::WildcardRpId(_))
        ));
    }

    #[test]
    fn test_normalize_rp_id_rejects_empty() {
        assert!(normalize_rp_id("").is_err());
        assert!(normalize_rp_id("   ").is_err());
    }

    #[test]
    fn test_normalize_rp_id_rejects_leading_dot() {
        assert!(matches!(
            normalize_rp_id(".example.com"),
            Err(GrantError::WildcardRpId(_))
        ));
    }

    #[test]
    fn test_credential_set_creation() {
        let creds = vec![test_cred(b"a"), test_cred(b"b")];
        let set = CredentialSet::new(creds).unwrap();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_credential_set_rejects_empty() {
        assert!(matches!(
            CredentialSet::new(vec![]),
            Err(GrantError::EmptyCredentialSet)
        ));
    }

    #[test]
    fn test_credential_set_deduplicates() {
        let c = test_cred(b"same");
        let set = CredentialSet::new(vec![c.clone(), c.clone()]).unwrap();
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_credential_set_contains() {
        let a = test_cred(b"a");
        let b = test_cred(b"b");
        let c = test_cred(b"c");
        let set = CredentialSet::new(vec![a.clone(), b.clone()]).unwrap();
        assert!(set.contains(&a));
        assert!(set.contains(&b));
        assert!(!set.contains(&c));
    }

    #[test]
    fn test_credential_set_subset() {
        let a = test_cred(b"a");
        let b = test_cred(b"b");
        let c = test_cred(b"c");
        let small = CredentialSet::new(vec![a.clone()]).unwrap();
        let big = CredentialSet::new(vec![a.clone(), b.clone(), c.clone()]).unwrap();
        assert!(small.is_subset_of(&big));
        assert!(!big.is_subset_of(&small));
    }

    #[test]
    fn test_credential_set_superset() {
        let a = test_cred(b"a");
        let b = test_cred(b"b");
        let small = CredentialSet::new(vec![a.clone()]).unwrap();
        let big = CredentialSet::new(vec![a.clone(), b.clone()]).unwrap();
        assert!(big.is_superset_of(&small));
        assert!(!small.is_superset_of(&big));
    }

    #[test]
    fn test_credential_set_equality() {
        let a = test_cred(b"a");
        let b = test_cred(b"b");
        let s1 = CredentialSet::new(vec![a.clone(), b.clone()]).unwrap();
        let s2 = CredentialSet::new(vec![b.clone(), a.clone()]).unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_grant_id_collision() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();
        let creds = vec![test_cred(b"cred1")];

        let g1 = request_and_approve(
            &mut registry,
            &session,
            vec!["example.com".to_string()],
            creds.clone(),
            60,
        );
        let g2 = request_and_approve(
            &mut registry,
            &session,
            vec!["example.com".to_string()],
            creds.clone(),
            60,
        );

        assert_ne!(g1, g2);
    }

    #[test]
    fn test_grant_creation_basic() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();
        let gid = request_and_approve(
            &mut registry,
            &session,
            vec!["example.com".to_string()],
            vec![test_cred(b"c1")],
            60,
        );

        let snap = registry.show_grant(&gid).unwrap();
        assert_eq!(snap.state, GrantState::Active);
        assert_eq!(snap.profile_id, test_profile_id());
        assert!(snap.rp_ids.contains("example.com"));
    }

    #[test]
    fn test_grant_ttl_clamped_to_profile_max() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();

        let result = registry.request_grant(GrantRequestParams {
            profile_id: test_profile_id(),
            session_id: session.clone(),
            endpoint_id: test_endpoint_id(),
            principal_digest: test_digest(1000),
            rp_ids: vec!["example.com".to_string()],
            credentials: vec![test_cred(b"c1")],
            requested_ttl_secs: 999,
        });
        assert!(matches!(
            result,
            Err(GrantError::TtlExceedsProfileMax { .. })
        ));
    }

    #[test]
    fn test_grant_ttl_zero_rejected() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();

        let result = registry.request_grant(GrantRequestParams {
            profile_id: test_profile_id(),
            session_id: session,
            endpoint_id: test_endpoint_id(),
            principal_digest: test_digest(1000),
            rp_ids: vec!["example.com".to_string()],
            credentials: vec![test_cred(b"c1")],
            requested_ttl_secs: 0,
        });
        assert!(matches!(result, Err(GrantError::TtlZero)));
    }

    #[test]
    fn test_grant_expiry() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();
        let gid = request_and_approve(
            &mut registry,
            &session,
            vec!["example.com".to_string()],
            vec![test_cred(b"c1")],
            10,
        );

        assert_eq!(registry.show_grant(&gid).unwrap().state, GrantState::Active);

        clock.advance(Duration::from_secs(11));
        let expired = registry.check_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(
            registry.show_grant(&gid).unwrap().state,
            GrantState::Expired
        );
    }

    #[test]
    fn test_revocation() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();
        let gid = request_and_approve(
            &mut registry,
            &session,
            vec!["example.com".to_string()],
            vec![test_cred(b"c1")],
            60,
        );

        let authority = super::super::intent::admin_authority();
        let state = registry.revoke_grant(&gid, &authority).unwrap();
        assert_eq!(state, GrantState::Revoked);
        assert_eq!(
            registry.show_grant(&gid).unwrap().state,
            GrantState::Revoked
        );
    }

    #[test]
    fn test_revocation_race() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();
        let authority = super::super::intent::admin_authority();
        let gid = request_and_approve(
            &mut registry,
            &session,
            vec!["example.com".to_string()],
            vec![test_cred(b"c1")],
            60,
        );

        let r1 = registry.revoke_grant(&gid, &authority);
        let r2 = registry.revoke_grant(&gid, &authority);

        assert!(r1.is_ok());
        assert!(matches!(r2, Err(GrantError::GrantNotActive(_))));
    }

    #[test]
    fn test_revocation_of_nonexistent() {
        let clock = test_clock();
        let registry = make_registry(&clock);
        let authority = super::super::intent::admin_authority();
        let fake_id = GrantId::new();
        assert!(matches!(
            registry.revoke_grant(&fake_id, &authority),
            Err(GrantError::GrantNotFound(_))
        ));
    }

    #[test]
    fn test_claim_basic() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();
        let cred = test_cred(b"c1");
        let gid = request_and_approve(
            &mut registry,
            &session,
            vec!["example.com".to_string()],
            vec![cred.clone()],
            60,
        );

        let intent = ClaimIntent {
            action: "get_assertion".to_string(),
            rp_id: "example.com".to_string(),
            credential_ref: cred,
        };

        let claim = registry.claim(&gid, &session, intent).unwrap();
        assert!(!claim.is_consumed());
    }

    #[test]
    fn test_claim_one_shot_cannot_reuse() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();
        let cred = test_cred(b"c1");
        let gid = request_and_approve(
            &mut registry,
            &session,
            vec!["example.com".to_string()],
            vec![cred.clone()],
            60,
        );

        let intent = ClaimIntent {
            action: "get_assertion".to_string(),
            rp_id: "example.com".to_string(),
            credential_ref: cred,
        };

        let claim = registry.claim(&gid, &session, intent.clone()).unwrap();
        let ceremony_id = claim.ceremony_id.clone();

        let first = registry.consume_claim(&ceremony_id);
        assert!(first.is_ok());

        let second = registry.consume_claim(&ceremony_id);
        assert!(matches!(second, Err(GrantError::ClaimAlreadyConsumed(_))));
    }

    #[test]
    fn test_claim_rp_id_not_in_grant() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();
        let cred = test_cred(b"c1");
        let gid = request_and_approve(
            &mut registry,
            &session,
            vec!["example.com".to_string()],
            vec![cred.clone()],
            60,
        );

        let intent = ClaimIntent {
            action: "get_assertion".to_string(),
            rp_id: "other.com".to_string(),
            credential_ref: cred,
        };

        assert!(matches!(
            registry.claim(&gid, &session, intent),
            Err(GrantError::RpIdNotInGrant(_))
        ));
    }

    #[test]
    fn test_claim_credential_not_in_grant() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();
        let gid = request_and_approve(
            &mut registry,
            &session,
            vec!["example.com".to_string()],
            vec![test_cred(b"c1")],
            60,
        );

        let intent = ClaimIntent {
            action: "get_assertion".to_string(),
            rp_id: "example.com".to_string(),
            credential_ref: test_cred(b"wrong"),
        };

        assert!(matches!(
            registry.claim(&gid, &session, intent),
            Err(GrantError::CredentialNotInGrant(_))
        ));
    }

    #[test]
    fn test_claim_action_not_in_grant() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();
        let cred = test_cred(b"c1");
        let gid = request_and_approve(
            &mut registry,
            &session,
            vec!["example.com".to_string()],
            vec![cred.clone()],
            60,
        );

        let intent = ClaimIntent {
            action: "delete_credential".to_string(),
            rp_id: "example.com".to_string(),
            credential_ref: cred,
        };

        assert!(matches!(
            registry.claim(&gid, &session, intent),
            Err(GrantError::ActionNotInGrant(_))
        ));
    }

    #[test]
    fn test_claim_cross_session_rejected() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session1 = test_session_id();
        let session2 = test_session_id();
        let cred = test_cred(b"c1");
        let gid = request_and_approve(
            &mut registry,
            &session1,
            vec!["example.com".to_string()],
            vec![cred.clone()],
            60,
        );

        let intent = ClaimIntent {
            action: "get_assertion".to_string(),
            rp_id: "example.com".to_string(),
            credential_ref: cred,
        };

        assert!(matches!(
            registry.claim(&gid, &session2, intent),
            Err(GrantError::SessionMismatch)
        ));
    }

    #[test]
    fn test_claim_cross_profile_rejected() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();
        let cred = test_cred(b"c1");

        let authority = super::super::intent::admin_authority();
        let req_id = registry
            .request_grant(GrantRequestParams {
                profile_id: ProfileId::new("profile-a").unwrap(),
                session_id: session.clone(),
                endpoint_id: test_endpoint_id(),
                principal_digest: test_digest(1000),
                rp_ids: vec!["example.com".to_string()],
                credentials: vec![cred.clone()],
                requested_ttl_secs: 60,
            })
            .unwrap();
        let gid = registry.approve_grant(&req_id, &authority).unwrap();

        let snap = registry.show_grant(&gid).unwrap();
        assert_eq!(snap.profile_id.as_str(), "profile-a");

        let mut other_registry = GrantRegistry::new(
            clock.clone(),
            test_policy_gen(),
            test_policy_digest(),
            300,
            test_actions(),
            10,
        );

        let authority = super::super::intent::admin_authority();
        let req_id2 = other_registry
            .request_grant(GrantRequestParams {
                profile_id: ProfileId::new("profile-b").unwrap(),
                session_id: session.clone(),
                endpoint_id: test_endpoint_id(),
                principal_digest: test_digest(2000),
                rp_ids: vec!["example.com".to_string()],
                credentials: vec![cred.clone()],
                requested_ttl_secs: 60,
            })
            .unwrap();
        let gid2 = other_registry.approve_grant(&req_id2, &authority).unwrap();

        let snap2 = other_registry.show_grant(&gid2).unwrap();
        assert_eq!(snap2.profile_id.as_str(), "profile-b");
        assert_ne!(snap.profile_id, snap2.profile_id);
    }

    #[test]
    fn test_claim_cross_policy_rejected() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();
        let cred = test_cred(b"c1");
        let gid = request_and_approve(
            &mut registry,
            &session,
            vec!["example.com".to_string()],
            vec![cred.clone()],
            60,
        );

        let new_gen = test_policy_gen();
        let new_profile = passless_core::agent::Policy::new(
            &test_profile_id(),
            vec!["different_action".to_string()],
            5,
            true,
            300,
        )
        .unwrap();
        let new_digest = new_profile.digest();

        registry.on_policy_reload(new_gen, new_digest, 300, test_actions());

        let intent = ClaimIntent {
            action: "get_assertion".to_string(),
            rp_id: "example.com".to_string(),
            credential_ref: cred,
        };

        assert!(matches!(
            registry.claim(&gid, &session, intent),
            Err(GrantError::GrantNotActive(_))
        ));
    }

    #[test]
    fn test_concurrent_claim_only_one_succeeds() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();
        let cred = test_cred(b"c1");
        let gid = request_and_approve(
            &mut registry,
            &session,
            vec!["example.com".to_string()],
            vec![cred.clone()],
            60,
        );

        let intent = ClaimIntent {
            action: "get_assertion".to_string(),
            rp_id: "example.com".to_string(),
            credential_ref: cred,
        };

        let claim = registry.claim(&gid, &session, intent).unwrap();
        let ceremony_id = claim.ceremony_id.clone();

        let claim_ref = registry.claims.get(&ceremony_id).unwrap();
        let results: Vec<_> = (0..10).map(|_| claim_ref.try_consume().is_ok()).collect();

        let successes = results.iter().filter(|&&r| r).count();
        assert_eq!(successes, 1);
    }

    #[test]
    fn test_policy_reload_fails_closed() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();

        let g1 = request_and_approve(
            &mut registry,
            &session,
            vec!["a.com".to_string()],
            vec![test_cred(b"1")],
            60,
        );
        let g2 = request_and_approve(
            &mut registry,
            &session,
            vec!["b.com".to_string()],
            vec![test_cred(b"2")],
            60,
        );

        assert_eq!(registry.active_count(), 2);

        registry.on_policy_reload(test_policy_gen(), test_policy_digest(), 300, test_actions());

        assert_eq!(registry.active_count(), 0);
        assert_eq!(registry.show_grant(&g1).unwrap().state, GrantState::Revoked);
        assert_eq!(registry.show_grant(&g2).unwrap().state, GrantState::Revoked);
    }

    #[test]
    fn test_principal_exit_fails_closed() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session1 = test_session_id();
        let session2 = test_session_id();

        let g1 = request_and_approve(
            &mut registry,
            &session1,
            vec!["a.com".to_string()],
            vec![test_cred(b"1")],
            60,
        );
        let _g2 = request_and_approve(
            &mut registry,
            &session2,
            vec!["b.com".to_string()],
            vec![test_cred(b"2")],
            60,
        );

        assert_eq!(registry.active_count(), 2);

        registry.on_principal_exit(&session1);

        assert_eq!(registry.show_grant(&g1).unwrap().state, GrantState::Revoked);
        assert_eq!(registry.active_count(), 1);
    }

    #[test]
    fn test_daemon_restart_clears_all() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();

        let _gid = request_and_approve(
            &mut registry,
            &session,
            vec!["example.com".to_string()],
            vec![test_cred(b"c1")],
            60,
        );

        assert_eq!(registry.grant_count(), 1);

        registry.on_daemon_restart();

        assert_eq!(registry.grant_count(), 0);
        assert_eq!(registry.active_count(), 0);
        assert_eq!(registry.pending_count(), 0);
    }

    #[test]
    fn test_clock_ambiguity_fails_closed() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();

        let _gid = request_and_approve(
            &mut registry,
            &session,
            vec!["example.com".to_string()],
            vec![test_cred(b"c1")],
            60,
        );

        assert_eq!(registry.active_count(), 1);

        clock.advance(Duration::from_secs(10));
        registry.last_seen_mono = 20;

        clock.advance(Duration::from_secs(0));

        let result = registry.request_grant(GrantRequestParams {
            profile_id: test_profile_id(),
            session_id: session,
            endpoint_id: test_endpoint_id(),
            principal_digest: test_digest(1000),
            rp_ids: vec!["example.com".to_string()],
            credentials: vec![test_cred(b"c2")],
            requested_ttl_secs: 60,
        });

        assert!(matches!(result, Err(GrantError::ClockAmbiguity)));
        assert_eq!(registry.active_count(), 0);
    }

    #[test]
    fn test_no_wildcard_rp_ids() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();

        let result = registry.request_grant(GrantRequestParams {
            profile_id: test_profile_id(),
            session_id: session,
            endpoint_id: test_endpoint_id(),
            principal_digest: test_digest(1000),
            rp_ids: vec!["*.example.com".to_string()],
            credentials: vec![test_cred(b"c1")],
            requested_ttl_secs: 60,
        });

        assert!(matches!(result, Err(GrantError::WildcardRpId(_))));
    }

    #[test]
    fn test_principal_cannot_approve() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();
        let authority = super::super::intent::admin_authority();

        let req_id = registry
            .request_grant(GrantRequestParams {
                profile_id: test_profile_id(),
                session_id: session.clone(),
                endpoint_id: test_endpoint_id(),
                principal_digest: test_digest(1000),
                rp_ids: vec!["example.com".to_string()],
                credentials: vec![test_cred(b"c1")],
                requested_ttl_secs: 60,
            })
            .unwrap();

        assert!(registry.pending_count() == 1);

        let gid = registry.approve_grant(&req_id, &authority).unwrap();
        assert!(registry.show_grant(&gid).is_some());

        let double = registry.approve_grant(&req_id, &authority);
        assert!(matches!(double, Err(GrantError::RequestAlreadyResolved(_))));
    }

    #[test]
    fn test_cancel_pending_request() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();
        let authority = super::super::intent::admin_authority();

        let req_id = registry
            .request_grant(GrantRequestParams {
                profile_id: test_profile_id(),
                session_id: session,
                endpoint_id: test_endpoint_id(),
                principal_digest: test_digest(1000),
                rp_ids: vec!["example.com".to_string()],
                credentials: vec![test_cred(b"c1")],
                requested_ttl_secs: 60,
            })
            .unwrap();

        assert_eq!(registry.pending_count(), 1);

        registry.cancel_request(&req_id).unwrap();
        assert_eq!(registry.pending_count(), 0);

        let result = registry.approve_grant(&req_id, &authority);
        assert!(matches!(result, Err(GrantError::RequestAlreadyResolved(_))));
    }

    #[test]
    fn test_show_grant() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();
        let gid = request_and_approve(
            &mut registry,
            &session,
            vec!["example.com".to_string()],
            vec![test_cred(b"c1")],
            60,
        );

        clock.advance(Duration::from_secs(10));

        let snap = registry.show_grant(&gid).unwrap();
        assert_eq!(snap.id, gid);
        assert_eq!(snap.state, GrantState::Active);
    }

    #[test]
    fn test_show_nonexistent_grant() {
        let clock = test_clock();
        let registry = make_registry(&clock);
        assert!(registry.show_grant(&GrantId::new()).is_none());
    }

    #[test]
    fn test_claim_on_revoked_grant_rejected() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();
        let authority = super::super::intent::admin_authority();
        let cred = test_cred(b"c1");
        let gid = request_and_approve(
            &mut registry,
            &session,
            vec!["example.com".to_string()],
            vec![cred.clone()],
            60,
        );

        registry.revoke_grant(&gid, &authority).unwrap();

        let intent = ClaimIntent {
            action: "get_assertion".to_string(),
            rp_id: "example.com".to_string(),
            credential_ref: cred,
        };

        assert!(matches!(
            registry.claim(&gid, &session, intent),
            Err(GrantError::GrantNotActive(_))
        ));
    }

    #[test]
    fn test_claim_on_expired_grant_rejected() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();
        let cred = test_cred(b"c1");
        let gid = request_and_approve(
            &mut registry,
            &session,
            vec!["example.com".to_string()],
            vec![cred.clone()],
            5,
        );

        clock.advance(Duration::from_secs(6));
        registry.check_expired();

        let intent = ClaimIntent {
            action: "get_assertion".to_string(),
            rp_id: "example.com".to_string(),
            credential_ref: cred,
        };

        assert!(matches!(
            registry.claim(&gid, &session, intent),
            Err(GrantError::GrantNotActive(_))
        ));
    }

    #[test]
    fn test_multiple_rp_ids_in_grant() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();
        let cred = test_cred(b"c1");
        let gid = request_and_approve(
            &mut registry,
            &session,
            vec![
                "example.com".to_string(),
                "example.org".to_string(),
                "test.io".to_string(),
            ],
            vec![cred.clone()],
            60,
        );

        for rp in &["example.com", "example.org", "test.io"] {
            let intent = ClaimIntent {
                action: "get_assertion".to_string(),
                rp_id: rp.to_string(),
                credential_ref: cred.clone(),
            };
            assert!(registry.claim(&gid, &session, intent).is_ok());
        }
    }

    #[test]
    fn test_multiple_credentials_in_grant() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();
        let c1 = test_cred(b"c1");
        let c2 = test_cred(b"c2");
        let gid = request_and_approve(
            &mut registry,
            &session,
            vec!["example.com".to_string()],
            vec![c1.clone(), c2.clone()],
            60,
        );

        let snap = registry.show_grant(&gid).unwrap();
        assert_eq!(snap.rp_ids.len(), 1);

        for cred in &[c1, c2] {
            let intent = ClaimIntent {
                action: "get_assertion".to_string(),
                rp_id: "example.com".to_string(),
                credential_ref: cred.clone(),
            };
            assert!(registry.claim(&gid, &session, intent).is_ok());
        }
    }

    #[test]
    fn test_rp_id_normalization_in_claim() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();
        let cred = test_cred(b"c1");
        let gid = request_and_approve(
            &mut registry,
            &session,
            vec!["Example.COM".to_string()],
            vec![cred.clone()],
            60,
        );

        let intent = ClaimIntent {
            action: "get_assertion".to_string(),
            rp_id: "EXAMPLE.com".to_string(),
            credential_ref: cred,
        };

        assert!(registry.claim(&gid, &session, intent).is_ok());
    }

    #[test]
    fn test_principal_digest_deterministic() {
        let d1 = compute_principal_digest(1000, 12345, "/user.slice");
        let d2 = compute_principal_digest(1000, 12345, "/user.slice");
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_principal_digest_differs_by_pid() {
        let d1 = compute_principal_digest(1000, 12345, "/user.slice");
        let d2 = compute_principal_digest(2000, 12345, "/user.slice");
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_principal_digest_differs_by_cgroup() {
        let d1 = compute_principal_digest(1000, 12345, "/user.slice");
        let d2 = compute_principal_digest(1000, 12345, "/system.slice");
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_empty_rp_ids_rejected() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();

        let result = registry.request_grant(GrantRequestParams {
            profile_id: test_profile_id(),
            session_id: session,
            endpoint_id: test_endpoint_id(),
            principal_digest: test_digest(1000),
            rp_ids: vec![],
            credentials: vec![test_cred(b"c1")],
            requested_ttl_secs: 60,
        });
        assert!(matches!(result, Err(GrantError::EmptyRpIdSet)));
    }

    #[test]
    fn test_empty_credentials_rejected() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();

        let result = registry.request_grant(GrantRequestParams {
            profile_id: test_profile_id(),
            session_id: session,
            endpoint_id: test_endpoint_id(),
            principal_digest: test_digest(1000),
            rp_ids: vec!["example.com".to_string()],
            credentials: vec![],
            requested_ttl_secs: 60,
        });
        assert!(matches!(result, Err(GrantError::EmptyCredentialSet)));
    }

    #[test]
    fn test_grant_counts() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();
        let authority = super::super::intent::admin_authority();

        assert_eq!(registry.grant_count(), 0);
        assert_eq!(registry.active_count(), 0);

        let g1 = request_and_approve(
            &mut registry,
            &session,
            vec!["a.com".to_string()],
            vec![test_cred(b"1")],
            60,
        );
        let _g2 = request_and_approve(
            &mut registry,
            &session,
            vec!["b.com".to_string()],
            vec![test_cred(b"2")],
            60,
        );

        assert_eq!(registry.grant_count(), 2);
        assert_eq!(registry.active_count(), 2);

        registry.revoke_grant(&g1, &authority).unwrap();
        assert_eq!(registry.active_count(), 1);
        assert_eq!(registry.grant_count(), 2);
    }

    #[test]
    fn test_policy_reload_clears_pending_and_claims() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();

        let _req_id = registry
            .request_grant(GrantRequestParams {
                profile_id: test_profile_id(),
                session_id: session.clone(),
                endpoint_id: test_endpoint_id(),
                principal_digest: test_digest(1000),
                rp_ids: vec!["example.com".to_string()],
                credentials: vec![test_cred(b"c1")],
                requested_ttl_secs: 60,
            })
            .unwrap();

        assert_eq!(registry.pending_count(), 1);

        registry.on_policy_reload(test_policy_gen(), test_policy_digest(), 300, test_actions());

        assert_eq!(registry.pending_count(), 0);
    }

    #[test]
    fn test_credential_set_too_many() {
        let creds: Vec<CredentialRef> = (0..MAX_CREDENTIALS_PER_GRANT + 1)
            .map(|i| test_cred(format!("c{}", i).as_bytes()))
            .collect();
        assert!(matches!(
            CredentialSet::new(creds),
            Err(GrantError::TooManyCredentials(_))
        ));
    }

    #[test]
    fn test_too_many_rp_ids() {
        let rps: Vec<String> = (0..MAX_RP_IDS_PER_GRANT + 1)
            .map(|i| format!("site{}.com", i))
            .collect();
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();

        let result = registry.request_grant(GrantRequestParams {
            profile_id: test_profile_id(),
            session_id: session,
            endpoint_id: test_endpoint_id(),
            principal_digest: test_digest(1000),
            rp_ids: rps,
            credentials: vec![test_cred(b"c1")],
            requested_ttl_secs: 60,
        });
        assert!(matches!(result, Err(GrantError::TooManyRpIds(_))));
    }

    #[test]
    fn test_clamp_ttl_below_min() {
        assert_eq!(clamp_ttl(0, 300), MIN_TTL_SECS);
    }

    #[test]
    fn test_clamp_ttl_above_max() {
        assert_eq!(clamp_ttl(999, 300), 300);
    }

    #[test]
    fn test_clamp_ttl_in_range() {
        assert_eq!(clamp_ttl(60, 300), 60);
    }

    #[test]
    fn test_grant_atomic_state_transition() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();
        let gid = request_and_approve(
            &mut registry,
            &session,
            vec!["example.com".to_string()],
            vec![test_cred(b"c1")],
            60,
        );

        let grant = registry.grants.get(&gid).unwrap();
        assert!(grant.try_transition(GrantState::Active, GrantState::Revoked));
        assert!(!grant.try_transition(GrantState::Active, GrantState::Expired));
        assert_eq!(grant.state(), GrantState::Revoked);
    }

    #[test]
    fn test_claim_intent_binding_exact() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let session = test_session_id();
        let cred = test_cred(b"c1");
        let gid = request_and_approve(
            &mut registry,
            &session,
            vec!["example.com".to_string()],
            vec![cred.clone()],
            60,
        );

        let intent = ClaimIntent {
            action: "get_assertion".to_string(),
            rp_id: "example.com".to_string(),
            credential_ref: cred.clone(),
        };

        let claim = registry.claim(&gid, &session, intent).unwrap();
        let consumed_intent = claim.try_consume().unwrap();

        assert_eq!(consumed_intent.action, "get_assertion");
        assert_eq!(consumed_intent.rp_id, "example.com");
        assert_eq!(consumed_intent.credential_ref, cred);
    }

    #[test]
    fn test_cross_session_grants_independent() {
        let clock = test_clock();
        let mut registry = make_registry(&clock);
        let s1 = test_session_id();
        let s2 = test_session_id();

        let g1 = request_and_approve(
            &mut registry,
            &s1,
            vec!["a.com".to_string()],
            vec![test_cred(b"1")],
            60,
        );
        let g2 = request_and_approve(
            &mut registry,
            &s2,
            vec!["b.com".to_string()],
            vec![test_cred(b"2")],
            60,
        );

        registry.on_principal_exit(&s1);

        assert_eq!(registry.show_grant(&g1).unwrap().state, GrantState::Revoked);
        assert_eq!(registry.show_grant(&g2).unwrap().state, GrantState::Active);
    }

    #[test]
    fn test_ceremony_id_unique() {
        let ids: Vec<String> = (0..100)
            .map(|_| CeremonyId::new().as_str().to_string())
            .collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len());
    }

    #[test]
    fn test_grant_request_id_unique() {
        let ids: Vec<String> = (0..100)
            .map(|_| GrantRequestId::new().as_str().to_string())
            .collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len());
    }

    fn make_reg_registry(clock: &Arc<MockClock>) -> RegistrationGrantRegistry {
        RegistrationGrantRegistry::new(clock.clone(), 300)
    }

    #[test]
    fn test_registration_grant_creation() {
        let clock = test_clock();
        let mut registry = make_reg_registry(&clock);
        let session = test_session_id();

        let gid = registry
            .request_registration(
                test_profile_id(),
                session,
                test_endpoint_id(),
                test_digest(1000),
                "example.com".to_string(),
                60,
            )
            .unwrap();

        let snap = registry
            .resolve_registration_grant(&gid, "example.com")
            .unwrap();
        assert_eq!(snap.state, GrantState::Active);
        assert_eq!(snap.rp_id, "example.com");
        assert_eq!(snap.profile_id, test_profile_id());
    }

    #[test]
    fn test_registration_grant_rp_id_mismatch() {
        let clock = test_clock();
        let mut registry = make_reg_registry(&clock);
        let session = test_session_id();

        let gid = registry
            .request_registration(
                test_profile_id(),
                session,
                test_endpoint_id(),
                test_digest(1000),
                "example.com".to_string(),
                60,
            )
            .unwrap();

        assert!(
            registry
                .resolve_registration_grant(&gid, "other.com")
                .is_none()
        );
    }

    #[test]
    fn test_registration_grant_expiry() {
        let clock = test_clock();
        let mut registry = make_reg_registry(&clock);
        let session = test_session_id();

        let gid = registry
            .request_registration(
                test_profile_id(),
                session,
                test_endpoint_id(),
                test_digest(1000),
                "example.com".to_string(),
                10,
            )
            .unwrap();

        assert!(
            registry
                .resolve_registration_grant(&gid, "example.com")
                .is_some()
        );

        clock.advance(Duration::from_secs(11));
        let expired = registry.check_expired();
        assert_eq!(expired.len(), 1);

        assert!(
            registry
                .resolve_registration_grant(&gid, "example.com")
                .is_none()
        );
    }

    #[test]
    fn test_registration_grant_revocation() {
        let clock = test_clock();
        let mut registry = make_reg_registry(&clock);
        let session = test_session_id();

        let gid = registry
            .request_registration(
                test_profile_id(),
                session,
                test_endpoint_id(),
                test_digest(1000),
                "example.com".to_string(),
                60,
            )
            .unwrap();

        registry.revoke_registration(&gid).unwrap();

        assert!(
            registry
                .resolve_registration_grant(&gid, "example.com")
                .is_none()
        );
    }

    #[test]
    fn test_registration_grant_revoke_nonexistent() {
        let clock = test_clock();
        let registry = make_reg_registry(&clock);
        let fake_id = RegistrationGrantId::new();

        assert!(matches!(
            registry.revoke_registration(&fake_id),
            Err(GrantError::RegistrationGrantNotFound(_))
        ));
    }

    #[test]
    fn test_registration_grant_ttl_zero_rejected() {
        let clock = test_clock();
        let mut registry = make_reg_registry(&clock);
        let session = test_session_id();

        let result = registry.request_registration(
            test_profile_id(),
            session,
            test_endpoint_id(),
            test_digest(1000),
            "example.com".to_string(),
            0,
        );
        assert!(matches!(result, Err(GrantError::TtlZero)));
    }

    #[test]
    fn test_registration_grant_ttl_exceeds_max() {
        let clock = test_clock();
        let mut registry = make_reg_registry(&clock);
        let session = test_session_id();

        let result = registry.request_registration(
            test_profile_id(),
            session,
            test_endpoint_id(),
            test_digest(1000),
            "example.com".to_string(),
            999,
        );
        assert!(matches!(
            result,
            Err(GrantError::TtlExceedsProfileMax { .. })
        ));
    }

    #[test]
    fn test_registration_grant_wildcard_rp_rejected() {
        let clock = test_clock();
        let mut registry = make_reg_registry(&clock);
        let session = test_session_id();

        let result = registry.request_registration(
            test_profile_id(),
            session,
            test_endpoint_id(),
            test_digest(1000),
            "*.example.com".to_string(),
            60,
        );
        assert!(matches!(result, Err(GrantError::WildcardRpId(_))));
    }

    #[test]
    fn test_registration_grant_rp_normalization() {
        let clock = test_clock();
        let mut registry = make_reg_registry(&clock);
        let session = test_session_id();

        let gid = registry
            .request_registration(
                test_profile_id(),
                session,
                test_endpoint_id(),
                test_digest(1000),
                "Example.COM".to_string(),
                60,
            )
            .unwrap();

        let snap = registry
            .resolve_registration_grant(&gid, "EXAMPLE.com")
            .unwrap();
        assert_eq!(snap.rp_id, "example.com");
    }

    #[test]
    fn test_registration_grant_principal_exit() {
        let clock = test_clock();
        let mut registry = make_reg_registry(&clock);
        let s1 = test_session_id();
        let s2 = test_session_id();

        let g1 = registry
            .request_registration(
                test_profile_id(),
                s1.clone(),
                test_endpoint_id(),
                test_digest(1000),
                "a.com".to_string(),
                60,
            )
            .unwrap();
        let g2 = registry
            .request_registration(
                test_profile_id(),
                s2.clone(),
                test_endpoint_id(),
                test_digest(2000),
                "b.com".to_string(),
                60,
            )
            .unwrap();

        assert_eq!(registry.active_count(), 2);

        registry.on_principal_exit(&s1);

        assert!(registry.resolve_registration_grant(&g1, "a.com").is_none());
        assert!(registry.resolve_registration_grant(&g2, "b.com").is_some());
    }

    #[test]
    fn test_registration_grant_daemon_restart() {
        let clock = test_clock();
        let mut registry = make_reg_registry(&clock);
        let session = test_session_id();

        let _gid = registry
            .request_registration(
                test_profile_id(),
                session,
                test_endpoint_id(),
                test_digest(1000),
                "example.com".to_string(),
                60,
            )
            .unwrap();

        assert_eq!(registry.grant_count(), 1);

        registry.on_daemon_restart();

        assert_eq!(registry.grant_count(), 0);
        assert_eq!(registry.active_count(), 0);
    }

    #[test]
    fn test_registration_grant_id_unique() {
        let ids: Vec<String> = (0..100)
            .map(|_| RegistrationGrantId::new().as_str().to_string())
            .collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len());
    }

    #[test]
    fn test_registration_grant_counts() {
        let clock = test_clock();
        let mut registry = make_reg_registry(&clock);
        let session = test_session_id();

        assert_eq!(registry.grant_count(), 0);
        assert_eq!(registry.active_count(), 0);

        let g1 = registry
            .request_registration(
                test_profile_id(),
                session.clone(),
                test_endpoint_id(),
                test_digest(1000),
                "a.com".to_string(),
                60,
            )
            .unwrap();
        let _g2 = registry
            .request_registration(
                test_profile_id(),
                session,
                test_endpoint_id(),
                test_digest(1000),
                "b.com".to_string(),
                60,
            )
            .unwrap();

        assert_eq!(registry.grant_count(), 2);
        assert_eq!(registry.active_count(), 2);

        registry.revoke_registration(&g1).unwrap();
        assert_eq!(registry.active_count(), 1);
        assert_eq!(registry.grant_count(), 2);
    }

    #[test]
    fn test_registration_grant_list_snapshots() {
        let clock = test_clock();
        let mut registry = make_reg_registry(&clock);
        let session = test_session_id();

        let _g1 = registry
            .request_registration(
                test_profile_id(),
                session.clone(),
                test_endpoint_id(),
                test_digest(1000),
                "a.com".to_string(),
                60,
            )
            .unwrap();
        let _g2 = registry
            .request_registration(
                test_profile_id(),
                session,
                test_endpoint_id(),
                test_digest(1000),
                "b.com".to_string(),
                60,
            )
            .unwrap();

        let snapshots = registry.list_all_snapshots();
        assert_eq!(snapshots.len(), 2);
    }
}
