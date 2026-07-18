use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use passless_core::agent::protocol::IntentAction;
use passless_core::agent::{
    CredentialRef, EndpointId, IntentId, PolicyDigest, PolicyGenerationId, PrincipalSessionId,
    ProfileId,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const DEFAULT_MAX_INTENTS: usize = 256;
const DEFAULT_INTENT_TTL_MS: u64 = 300_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentError {
    NotFound,
    StoreFull,
    InvalidTransition { from: String, to: String },
    Expired,
    AlreadyClaimed,
    AlreadyConsumed,
    ClaimTokenMismatch,
    PrincipalCannotApprove,
    ReplayDetected,
    Shutdown,
}

impl fmt::Display for IntentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "intent not found"),
            Self::StoreFull => write!(f, "intent store is full"),
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid state transition: {} -> {}", from, to)
            }
            Self::Expired => write!(f, "intent has expired"),
            Self::AlreadyClaimed => write!(f, "intent is already claimed"),
            Self::AlreadyConsumed => write!(f, "intent is already consumed"),
            Self::ClaimTokenMismatch => write!(f, "claim token does not match"),
            Self::PrincipalCannotApprove => {
                write!(f, "principal cannot approve their own intent")
            }
            Self::ReplayDetected => write!(f, "replay detected"),
            Self::Shutdown => write!(f, "intent store is shut down"),
        }
    }
}

impl std::error::Error for IntentError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonotonicTime(u64);

impl MonotonicTime {
    pub fn from_millis(ms: u64) -> Self {
        Self(ms)
    }

    pub fn as_millis(&self) -> u64 {
        self.0
    }

    pub fn checked_add(&self, duration_ms: u64) -> Option<Self> {
        self.0.checked_add(duration_ms).map(Self)
    }

    pub fn saturating_duration_since(&self, earlier: MonotonicTime) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

pub trait MonotonicClock: Send + Sync {
    fn now(&self) -> MonotonicTime;
}

pub struct SystemClock {
    epoch: Instant,
}

impl SystemClock {
    pub fn new() -> Self {
        Self {
            epoch: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock for SystemClock {
    fn now(&self) -> MonotonicTime {
        let elapsed = self.epoch.elapsed();
        MonotonicTime::from_millis(elapsed.as_millis() as u64)
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ProcessIdentityDigest([u8; 32]);

pub struct SessionIdentityParams {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
    pub start_time: u64,
    pub cgroup_path: String,
    pub ns_user: u64,
    pub ns_pid: u64,
    pub ns_mnt: u64,
}

impl ProcessIdentityDigest {
    pub fn compute(uid: u32, gid: u32, pid: u32, exe_hash: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"passless/process-identity/v1");
        hasher.update(uid.to_le_bytes());
        hasher.update(gid.to_le_bytes());
        hasher.update(pid.to_le_bytes());
        hasher.update(exe_hash);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    pub fn compute_from_session_identity(params: &SessionIdentityParams) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"passless/session-identity/v2\x00");
        hasher.update(params.uid.to_le_bytes());
        hasher.update(params.gid.to_le_bytes());
        hasher.update((params.pid as u32).to_le_bytes());
        hasher.update(params.start_time.to_le_bytes());
        hasher.update((params.cgroup_path.len() as u32).to_le_bytes());
        hasher.update(params.cgroup_path.as_bytes());
        hasher.update(params.ns_user.to_le_bytes());
        hasher.update(params.ns_pid.to_le_bytes());
        hasher.update(params.ns_mnt.to_le_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ProcessIdentityDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ProcessIdentityDigest")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl fmt::Display for ProcessIdentityDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ClaimToken([u8; 32]);

impl ClaimToken {
    pub fn generate() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        Self(bytes)
    }

    pub fn verify(&self, other: &ClaimToken) -> bool {
        let mut acc: u8 = 0;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            acc |= a ^ b;
        }
        acc == 0
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for ClaimToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for ClaimToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClaimToken(<redacted>)")
    }
}

impl fmt::Display for ClaimToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[derive(Debug, Clone)]
pub struct AdminAuthority {
    _sealed: std::marker::PhantomData<()>,
}

impl AdminAuthority {
    fn new() -> Self {
        Self {
            _sealed: std::marker::PhantomData,
        }
    }
}

static ADMIN_AUTHORITY_TOKEN: AtomicU64 = AtomicU64::new(0);

pub(crate) fn admin_authority() -> AdminAuthority {
    ADMIN_AUTHORITY_TOKEN.fetch_add(1, Ordering::Relaxed);
    AdminAuthority::new()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntentState {
    Pending,
    Approved,
    Denied,
    Cancelled,
    Expired,
    Claimed,
    Consumed,
}

impl IntentState {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Denied | Self::Cancelled | Self::Expired | Self::Consumed
        )
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Claimed => "claimed",
            Self::Consumed => "consumed",
        }
    }
}

impl fmt::Display for IntentState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

pub struct Intent {
    id: IntentId,
    profile_id: ProfileId,
    session_id: PrincipalSessionId,
    endpoint_id: EndpointId,
    process_digest: ProcessIdentityDigest,
    action: IntentAction,
    rp_id: String,
    credential_ref: Option<CredentialRef>,
    policy_generation: PolicyGenerationId,
    policy_digest: PolicyDigest,
    require_uv: bool,
    created_at: MonotonicTime,
    deadline: MonotonicTime,
    state: IntentState,
    claim_token: Option<ClaimToken>,
    boot_nonce: u64,
}

impl Intent {
    pub fn id(&self) -> &IntentId {
        &self.id
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

    pub fn action(&self) -> &IntentAction {
        &self.action
    }

    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    pub fn credential_ref(&self) -> Option<&CredentialRef> {
        self.credential_ref.as_ref()
    }

    pub fn policy_generation(&self) -> &PolicyGenerationId {
        &self.policy_generation
    }

    pub fn policy_digest(&self) -> &PolicyDigest {
        &self.policy_digest
    }

    pub fn require_uv(&self) -> bool {
        self.require_uv
    }

    pub fn created_at(&self) -> MonotonicTime {
        self.created_at
    }

    pub fn deadline(&self) -> MonotonicTime {
        self.deadline
    }

    pub fn state(&self) -> &IntentState {
        &self.state
    }

    fn matches_query(&self, query: &IntentQueryParams, require_approved: bool) -> bool {
        let normalized_rp = query.rp_id.trim().to_ascii_lowercase();
        let state_ok = if require_approved {
            self.state == IntentState::Approved
        } else {
            !self.state.is_terminal()
        };
        state_ok
            && self.profile_id == query.profile_id
            && self.session_id == query.session_id
            && self.endpoint_id == query.endpoint_id
            && self.process_digest == query.process_digest
            && query
                .policy_generation
                .as_ref()
                .is_none_or(|pg| self.policy_generation == *pg)
            && self.policy_digest == query.policy_digest
            && self.action == query.action
            && self.rp_id == normalized_rp
            && match (&query.credential_ref, &self.credential_ref) {
                (Some(qr), Some(icr)) => qr == icr,
                (None, None) => true,
                _ => false,
            }
    }

    fn transition_to(&mut self, new_state: IntentState) -> Result<(), IntentError> {
        let valid = matches!(
            (&self.state, &new_state),
            (IntentState::Pending, IntentState::Approved)
                | (IntentState::Pending, IntentState::Denied)
                | (IntentState::Pending, IntentState::Cancelled)
                | (IntentState::Pending, IntentState::Expired)
                | (IntentState::Approved, IntentState::Claimed)
                | (IntentState::Approved, IntentState::Expired)
                | (IntentState::Claimed, IntentState::Consumed)
        );

        if !valid {
            return Err(IntentError::InvalidTransition {
                from: self.state.label().to_string(),
                to: new_state.label().to_string(),
            });
        }

        self.state = new_state;
        Ok(())
    }
}

impl fmt::Debug for Intent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Intent")
            .field("id", &self.id)
            .field("profile_id", &self.profile_id)
            .field("session_id", &self.session_id)
            .field("endpoint_id", &self.endpoint_id)
            .field("process_digest", &self.process_digest)
            .field("action", &self.action)
            .field("rp_id", &self.rp_id)
            .field("credential_ref", &self.credential_ref)
            .field("policy_generation", &self.policy_generation)
            .field("policy_digest", &self.policy_digest)
            .field("require_uv", &self.require_uv)
            .field("created_at", &self.created_at)
            .field("deadline", &self.deadline)
            .field("state", &self.state)
            .field("claim_token", &"<redacted>")
            .field("boot_nonce", &self.boot_nonce)
            .finish()
    }
}

pub struct CreateIntentParams {
    pub profile_id: ProfileId,
    pub session_id: PrincipalSessionId,
    pub endpoint_id: EndpointId,
    pub process_digest: ProcessIdentityDigest,
    pub action: IntentAction,
    pub rp_id: String,
    pub credential_ref: Option<CredentialRef>,
    pub policy_generation: PolicyGenerationId,
    pub policy_digest: PolicyDigest,
    pub require_uv: bool,
    pub ttl_ms: Option<u64>,
}

pub struct IntentQueryParams {
    pub profile_id: ProfileId,
    pub session_id: PrincipalSessionId,
    pub endpoint_id: EndpointId,
    pub process_digest: ProcessIdentityDigest,
    pub policy_generation: Option<PolicyGenerationId>,
    pub policy_digest: PolicyDigest,
    pub action: IntentAction,
    pub rp_id: String,
    pub credential_ref: Option<CredentialRef>,
}

pub struct IntentStore {
    intents: HashMap<String, Intent>,
    clock: Box<dyn MonotonicClock>,
    max_intents: usize,
    boot_nonce: u64,
}

impl IntentStore {
    pub fn new(clock: Box<dyn MonotonicClock>, max_intents: usize) -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let boot_nonce: u64 = rng.r#gen();

        Self {
            intents: HashMap::new(),
            clock,
            max_intents,
            boot_nonce,
        }
    }

    pub fn with_defaults(clock: Box<dyn MonotonicClock>) -> Self {
        Self::new(clock, DEFAULT_MAX_INTENTS)
    }

    pub fn boot_nonce(&self) -> u64 {
        self.boot_nonce
    }

    pub fn invalidate_all(&mut self) {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        self.boot_nonce = rng.r#gen();
        self.intents.clear();
    }

    pub fn create(
        &mut self,
        params: CreateIntentParams,
    ) -> Result<(IntentId, ClaimToken), IntentError> {
        self.cleanup_expired();

        let active_count = self
            .intents
            .values()
            .filter(|i| !i.state.is_terminal())
            .count();
        if active_count >= self.max_intents {
            return Err(IntentError::StoreFull);
        }

        let now = self.clock.now();
        let ttl_ms = params.ttl_ms.unwrap_or(DEFAULT_INTENT_TTL_MS);
        let deadline = now.checked_add(ttl_ms).ok_or(IntentError::StoreFull)?;

        let id = IntentId::new();
        let claim_token = ClaimToken::generate();

        let intent = Intent {
            id: id.clone(),
            profile_id: params.profile_id,
            session_id: params.session_id,
            endpoint_id: params.endpoint_id,
            process_digest: params.process_digest,
            action: params.action,
            rp_id: params.rp_id,
            credential_ref: params.credential_ref,
            policy_generation: params.policy_generation,
            policy_digest: params.policy_digest,
            require_uv: params.require_uv,
            created_at: now,
            deadline,
            state: IntentState::Pending,
            claim_token: Some(claim_token.clone()),
            boot_nonce: self.boot_nonce,
        };

        self.intents.insert(id.as_str().to_string(), intent);
        Ok((id, claim_token))
    }

    pub fn get(&self, intent_id: &IntentId) -> Option<&Intent> {
        self.intents.get(intent_id.as_str())
    }

    pub fn state(&self, intent_id: &IntentId) -> Option<&IntentState> {
        self.intents.get(intent_id.as_str()).map(|i| &i.state)
    }

    pub fn approve(
        &mut self,
        intent_id: &IntentId,
        _authority: &AdminAuthority,
    ) -> Result<(), IntentError> {
        self.expire_if_needed(intent_id)?;

        let intent = self
            .intents
            .get_mut(intent_id.as_str())
            .ok_or(IntentError::NotFound)?;

        intent.transition_to(IntentState::Approved)?;
        Ok(())
    }

    pub fn deny(
        &mut self,
        intent_id: &IntentId,
        _authority: &AdminAuthority,
    ) -> Result<(), IntentError> {
        self.expire_if_needed(intent_id)?;

        let intent = self
            .intents
            .get_mut(intent_id.as_str())
            .ok_or(IntentError::NotFound)?;

        intent.transition_to(IntentState::Denied)?;
        Ok(())
    }

    pub fn cancel_by_principal(
        &mut self,
        intent_id: &IntentId,
        profile_id: &ProfileId,
        session_id: &PrincipalSessionId,
    ) -> Result<(), IntentError> {
        self.expire_if_needed(intent_id)?;

        let intent = self
            .intents
            .get_mut(intent_id.as_str())
            .ok_or(IntentError::NotFound)?;

        if intent.profile_id != *profile_id || intent.session_id != *session_id {
            return Err(IntentError::NotFound);
        }

        intent.transition_to(IntentState::Cancelled)?;
        Ok(())
    }

    pub fn claim(&mut self, intent_id: &IntentId, token: &ClaimToken) -> Result<(), IntentError> {
        self.expire_if_needed(intent_id)?;

        let intent = self
            .intents
            .get_mut(intent_id.as_str())
            .ok_or(IntentError::NotFound)?;

        if intent.state != IntentState::Approved {
            return Err(IntentError::InvalidTransition {
                from: intent.state.label().to_string(),
                to: IntentState::Claimed.label().to_string(),
            });
        }

        let stored_token = intent
            .claim_token
            .as_ref()
            .ok_or(IntentError::AlreadyClaimed)?;

        if !stored_token.verify(token) {
            return Err(IntentError::ClaimTokenMismatch);
        }

        intent.transition_to(IntentState::Claimed)?;
        intent.claim_token.take();
        Ok(())
    }

    pub fn consume(&mut self, intent_id: &IntentId) -> Result<IntentConsumeInfo, IntentError> {
        let intent = self
            .intents
            .get_mut(intent_id.as_str())
            .ok_or(IntentError::NotFound)?;

        if intent.state == IntentState::Consumed {
            return Err(IntentError::AlreadyConsumed);
        }

        intent.transition_to(IntentState::Consumed)?;

        Ok(IntentConsumeInfo {
            profile_id: intent.profile_id.clone(),
            action: intent.action.clone(),
            rp_id: intent.rp_id.clone(),
            credential_ref: intent.credential_ref.clone(),
            require_uv: intent.require_uv,
        })
    }

    pub fn cleanup_expired(&mut self) {
        let now = self.clock.now();
        for intent in self.intents.values_mut() {
            if (intent.state == IntentState::Pending || intent.state == IntentState::Approved)
                && now >= intent.deadline
            {
                let _ = intent.transition_to(IntentState::Expired);
            }
        }
    }

    fn expire_if_needed(&mut self, intent_id: &IntentId) -> Result<(), IntentError> {
        let now = self.clock.now();
        let intent = self
            .intents
            .get_mut(intent_id.as_str())
            .ok_or(IntentError::NotFound)?;

        if (intent.state == IntentState::Pending || intent.state == IntentState::Approved)
            && now >= intent.deadline
        {
            intent.transition_to(IntentState::Expired)?;
            return Err(IntentError::Expired);
        }
        Ok(())
    }

    pub fn cleanup_terminal(&mut self) {
        self.intents.retain(|_, intent| !intent.state.is_terminal());
    }

    pub fn active_count(&self) -> usize {
        self.intents
            .values()
            .filter(|i| !i.state.is_terminal())
            .count()
    }

    pub fn total_count(&self) -> usize {
        self.intents.len()
    }

    pub fn verify_boot_nonce(&self, nonce: u64) -> bool {
        self.boot_nonce == nonce
    }

    pub fn find_approved(&self, query: &IntentQueryParams) -> Option<IntentId> {
        self.intents
            .values()
            .find(|i| i.matches_query(query, true))
            .map(|i| i.id.clone())
    }

    pub fn claim_approved(&mut self, query: &IntentQueryParams) -> Result<IntentId, IntentError> {
        self.cleanup_expired();
        let intent = self
            .intents
            .values_mut()
            .find(|i| i.matches_query(query, true))
            .ok_or(IntentError::NotFound)?;
        intent.transition_to(IntentState::Claimed)?;
        intent.claim_token.take();
        Ok(intent.id.clone())
    }

    pub fn rollback_claim(&mut self, intent_id: &IntentId) -> Result<(), IntentError> {
        let intent = self
            .intents
            .get_mut(intent_id.as_str())
            .ok_or(IntentError::NotFound)?;
        if intent.state != IntentState::Claimed {
            return Err(IntentError::InvalidTransition {
                from: intent.state.label().to_string(),
                to: IntentState::Approved.label().to_string(),
            });
        }
        intent.state = IntentState::Approved;
        Ok(())
    }

    pub fn consume_claimed(
        &mut self,
        intent_id: &IntentId,
    ) -> Result<IntentConsumeInfo, IntentError> {
        let intent = self
            .intents
            .get_mut(intent_id.as_str())
            .ok_or(IntentError::NotFound)?;
        if intent.state != IntentState::Claimed {
            return Err(IntentError::InvalidTransition {
                from: intent.state.label().to_string(),
                to: IntentState::Consumed.label().to_string(),
            });
        }
        intent.transition_to(IntentState::Consumed)?;
        Ok(IntentConsumeInfo {
            profile_id: intent.profile_id.clone(),
            action: intent.action.clone(),
            rp_id: intent.rp_id.clone(),
            credential_ref: intent.credential_ref.clone(),
            require_uv: intent.require_uv,
        })
    }

    pub fn cancel_by_session(&mut self, session_id: &PrincipalSessionId) {
        for intent in self.intents.values_mut() {
            if intent.session_id == *session_id && !intent.state.is_terminal() {
                let _ = intent.transition_to(IntentState::Cancelled);
            }
        }
    }

    pub fn check_replay(&self, query: &IntentQueryParams) -> bool {
        self.intents.values().any(|i| i.matches_query(query, false))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct IntentConsumeInfo {
    pub profile_id: ProfileId,
    pub action: IntentAction,
    pub rp_id: String,
    pub credential_ref: Option<CredentialRef>,
    pub require_uv: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct FakeClock {
        now: Arc<Mutex<MonotonicTime>>,
    }

    impl FakeClock {
        fn new(ms: u64) -> Self {
            Self {
                now: Arc::new(Mutex::new(MonotonicTime::from_millis(ms))),
            }
        }

        fn advance(&self, ms: u64) {
            let mut t = self.now.lock().unwrap();
            *t = MonotonicTime::from_millis(t.as_millis() + ms);
        }

        fn set(&self, ms: u64) {
            let mut t = self.now.lock().unwrap();
            *t = MonotonicTime::from_millis(ms);
        }
    }

    impl MonotonicClock for FakeClock {
        fn now(&self) -> MonotonicTime {
            *self.now.lock().unwrap()
        }
    }

    fn test_profile_id() -> ProfileId {
        ProfileId::new("test-profile").unwrap()
    }

    fn test_process_digest() -> ProcessIdentityDigest {
        ProcessIdentityDigest::compute(1000, 1000, 42, b"test-exe-hash")
    }

    fn test_params() -> CreateIntentParams {
        CreateIntentParams {
            profile_id: test_profile_id(),
            session_id: PrincipalSessionId::new(),
            endpoint_id: EndpointId::new(),
            process_digest: test_process_digest(),
            action: IntentAction::Register,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            policy_generation: PolicyGenerationId::new(),
            policy_digest: PolicyDigest::from_cbor_bytes(b"test-policy"),
            require_uv: true,
            ttl_ms: Some(60_000),
        }
    }

    #[test]
    fn test_create_intent_returns_id_and_token() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let params = test_params();

        let (id, token) = store.create(params).unwrap();
        assert!(!id.as_str().is_empty());
        assert_eq!(token.as_bytes().len(), 32);
    }

    #[test]
    fn test_intent_starts_pending() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let params = test_params();

        let (id, _token) = store.create(params).unwrap();
        assert_eq!(store.state(&id), Some(&IntentState::Pending));
    }

    #[test]
    fn test_admin_approve_transitions_to_approved() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let params = test_params();
        let authority = admin_authority();

        let (id, _token) = store.create(params).unwrap();
        store.approve(&id, &authority).unwrap();
        assert_eq!(store.state(&id), Some(&IntentState::Approved));
    }

    #[test]
    fn test_admin_deny_transitions_to_denied() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let params = test_params();
        let authority = admin_authority();

        let (id, _token) = store.create(params).unwrap();
        store.deny(&id, &authority).unwrap();
        assert_eq!(store.state(&id), Some(&IntentState::Denied));
    }

    #[test]
    fn test_principal_cancel() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let session_id = PrincipalSessionId::new();
        let profile_id = test_profile_id();
        let params = CreateIntentParams {
            profile_id: profile_id.clone(),
            session_id: session_id.clone(),
            endpoint_id: EndpointId::new(),
            process_digest: test_process_digest(),
            action: IntentAction::Register,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            policy_generation: PolicyGenerationId::new(),
            policy_digest: PolicyDigest::from_cbor_bytes(b"test-policy"),
            require_uv: true,
            ttl_ms: Some(60_000),
        };

        let (id, _token) = store.create(params).unwrap();
        store
            .cancel_by_principal(&id, &profile_id, &session_id)
            .unwrap();
        assert_eq!(store.state(&id), Some(&IntentState::Cancelled));
    }

    #[test]
    fn test_principal_cannot_cancel_other_profile() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let session_id = PrincipalSessionId::new();
        let params = test_params();

        let (id, _token) = store.create(params).unwrap();
        let other_profile = ProfileId::new("other-profile").unwrap();
        let result = store.cancel_by_principal(&id, &other_profile, &session_id);
        assert_eq!(result, Err(IntentError::NotFound));
    }

    #[test]
    fn test_principal_cannot_cancel_other_session() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let params = test_params();

        let (id, _token) = store.create(params).unwrap();
        let other_session = PrincipalSessionId::new();
        let result = store.cancel_by_principal(&id, &test_profile_id(), &other_session);
        assert_eq!(result, Err(IntentError::NotFound));
    }

    #[test]
    fn test_claim_with_valid_token() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let authority = admin_authority();
        let params = test_params();

        let (id, token) = store.create(params).unwrap();
        store.approve(&id, &authority).unwrap();
        store.claim(&id, &token).unwrap();
        assert_eq!(store.state(&id), Some(&IntentState::Claimed));
    }

    #[test]
    fn test_claim_with_wrong_token_fails() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let authority = admin_authority();
        let params = test_params();

        let (id, _token) = store.create(params).unwrap();
        store.approve(&id, &authority).unwrap();
        let wrong_token = ClaimToken::generate();
        let result = store.claim(&id, &wrong_token);
        assert_eq!(result, Err(IntentError::ClaimTokenMismatch));
    }

    #[test]
    fn test_double_spend_claim() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let authority = admin_authority();
        let params = test_params();

        let (id, token) = store.create(params).unwrap();
        store.approve(&id, &authority).unwrap();
        store.claim(&id, &token).unwrap();

        let result = store.claim(&id, &token);
        assert!(matches!(result, Err(IntentError::InvalidTransition { .. })));
    }

    #[test]
    fn test_consume_exactly_once() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let authority = admin_authority();
        let params = test_params();

        let (id, token) = store.create(params).unwrap();
        store.approve(&id, &authority).unwrap();
        store.claim(&id, &token).unwrap();
        let info = store.consume(&id).unwrap();
        assert_eq!(info.rp_id, "example.com");
        assert_eq!(info.action, IntentAction::Register);
        assert!(info.require_uv);
    }

    #[test]
    fn test_double_spend_consume() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let authority = admin_authority();
        let params = test_params();

        let (id, token) = store.create(params).unwrap();
        store.approve(&id, &authority).unwrap();
        store.claim(&id, &token).unwrap();
        let _ = store.consume(&id).unwrap();

        let result = store.consume(&id);
        assert_eq!(result, Err(IntentError::AlreadyConsumed));
    }

    #[test]
    fn test_consume_without_claim_fails() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let authority = admin_authority();
        let params = test_params();

        let (id, _token) = store.create(params).unwrap();
        store.approve(&id, &authority).unwrap();

        let result = store.consume(&id);
        assert!(result.is_err());
    }

    #[test]
    fn test_expiry_edge_pending() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock.clone()));
        let params = CreateIntentParams {
            profile_id: test_profile_id(),
            session_id: PrincipalSessionId::new(),
            endpoint_id: EndpointId::new(),
            process_digest: test_process_digest(),
            action: IntentAction::Register,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            policy_generation: PolicyGenerationId::new(),
            policy_digest: PolicyDigest::from_cbor_bytes(b"test-policy"),
            require_uv: true,
            ttl_ms: Some(1000),
        };

        let (id, _token) = store.create(params).unwrap();
        assert_eq!(store.state(&id), Some(&IntentState::Pending));

        clock.advance(999);
        store.cleanup_expired();
        assert_eq!(store.state(&id), Some(&IntentState::Pending));

        clock.advance(2);
        store.cleanup_expired();
        assert_eq!(store.state(&id), Some(&IntentState::Expired));
    }

    #[test]
    fn test_expiry_edge_approved() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock.clone()));
        let authority = admin_authority();
        let params = CreateIntentParams {
            profile_id: test_profile_id(),
            session_id: PrincipalSessionId::new(),
            endpoint_id: EndpointId::new(),
            process_digest: test_process_digest(),
            action: IntentAction::Authenticate,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            policy_generation: PolicyGenerationId::new(),
            policy_digest: PolicyDigest::from_cbor_bytes(b"test-policy"),
            require_uv: false,
            ttl_ms: Some(500),
        };

        let (id, _token) = store.create(params).unwrap();
        store.approve(&id, &authority).unwrap();

        clock.advance(501);
        let result = store.approve(&id, &authority);
        assert!(result.is_err());
        assert_eq!(store.state(&id), Some(&IntentState::Expired));
    }

    #[test]
    fn test_expiry_prevents_claim() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock.clone()));
        let authority = admin_authority();
        let params = CreateIntentParams {
            profile_id: test_profile_id(),
            session_id: PrincipalSessionId::new(),
            endpoint_id: EndpointId::new(),
            process_digest: test_process_digest(),
            action: IntentAction::Register,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            policy_generation: PolicyGenerationId::new(),
            policy_digest: PolicyDigest::from_cbor_bytes(b"test-policy"),
            require_uv: true,
            ttl_ms: Some(100),
        };

        let (id, token) = store.create(params).unwrap();
        store.approve(&id, &authority).unwrap();

        clock.advance(101);
        let result = store.claim(&id, &token);
        assert!(result.is_err());
    }

    #[test]
    fn test_cancel_approve_race_cancel_wins() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let session_id = PrincipalSessionId::new();
        let profile_id = test_profile_id();
        let authority = admin_authority();
        let params = CreateIntentParams {
            profile_id: profile_id.clone(),
            session_id: session_id.clone(),
            endpoint_id: EndpointId::new(),
            process_digest: test_process_digest(),
            action: IntentAction::Register,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            policy_generation: PolicyGenerationId::new(),
            policy_digest: PolicyDigest::from_cbor_bytes(b"test-policy"),
            require_uv: true,
            ttl_ms: Some(60_000),
        };

        let (id, _token) = store.create(params).unwrap();
        store
            .cancel_by_principal(&id, &profile_id, &session_id)
            .unwrap();
        assert_eq!(store.state(&id), Some(&IntentState::Cancelled));

        let result = store.approve(&id, &authority);
        assert!(result.is_err());
        assert_eq!(store.state(&id), Some(&IntentState::Cancelled));
    }

    #[test]
    fn test_cancel_approve_race_approve_wins() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let session_id = PrincipalSessionId::new();
        let profile_id = test_profile_id();
        let authority = admin_authority();
        let params = CreateIntentParams {
            profile_id: profile_id.clone(),
            session_id: session_id.clone(),
            endpoint_id: EndpointId::new(),
            process_digest: test_process_digest(),
            action: IntentAction::Register,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            policy_generation: PolicyGenerationId::new(),
            policy_digest: PolicyDigest::from_cbor_bytes(b"test-policy"),
            require_uv: true,
            ttl_ms: Some(60_000),
        };

        let (id, _token) = store.create(params).unwrap();
        store.approve(&id, &authority).unwrap();
        assert_eq!(store.state(&id), Some(&IntentState::Approved));

        let result = store.cancel_by_principal(&id, &profile_id, &session_id);
        assert!(result.is_err());
        assert_eq!(store.state(&id), Some(&IntentState::Approved));
    }

    #[test]
    fn test_cross_profile_replay_detected() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let session_id = PrincipalSessionId::new();
        let endpoint_id = EndpointId::new();
        let process_digest = test_process_digest();
        let policy_digest = PolicyDigest::from_cbor_bytes(b"test-policy");

        let params1 = CreateIntentParams {
            profile_id: ProfileId::new("profile-a").unwrap(),
            session_id: session_id.clone(),
            endpoint_id: endpoint_id.clone(),
            process_digest: process_digest.clone(),
            action: IntentAction::Register,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            policy_generation: PolicyGenerationId::new(),
            policy_digest: policy_digest.clone(),
            require_uv: true,
            ttl_ms: Some(60_000),
        };

        let params2 = CreateIntentParams {
            profile_id: ProfileId::new("profile-b").unwrap(),
            session_id: session_id.clone(),
            endpoint_id: endpoint_id.clone(),
            process_digest: process_digest.clone(),
            action: IntentAction::Register,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            policy_generation: PolicyGenerationId::new(),
            policy_digest: policy_digest.clone(),
            require_uv: true,
            ttl_ms: Some(60_000),
        };

        let (_id1, _) = store.create(params1).unwrap();
        let is_replay = store.check_replay(&IntentQueryParams {
            profile_id: ProfileId::new("profile-b").unwrap(),
            session_id: session_id.clone(),
            endpoint_id: endpoint_id.clone(),
            process_digest: process_digest.clone(),
            policy_generation: None,
            policy_digest: policy_digest.clone(),
            action: IntentAction::Register,
            rp_id: "example.com".to_string(),
            credential_ref: None,
        });
        assert!(!is_replay);

        let (_id2, _) = store.create(params2).unwrap();
        assert_eq!(store.active_count(), 2);
    }

    #[test]
    fn test_cross_session_replay_not_detected() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let profile_id = test_profile_id();
        let endpoint_id = EndpointId::new();
        let process_digest = test_process_digest();
        let policy_digest = PolicyDigest::from_cbor_bytes(b"test-policy");

        let params = CreateIntentParams {
            profile_id: profile_id.clone(),
            session_id: PrincipalSessionId::new(),
            endpoint_id: endpoint_id.clone(),
            process_digest: process_digest.clone(),
            action: IntentAction::Register,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            policy_generation: PolicyGenerationId::new(),
            policy_digest: policy_digest.clone(),
            require_uv: true,
            ttl_ms: Some(60_000),
        };

        let (_id, _) = store.create(params).unwrap();

        let is_replay = store.check_replay(&IntentQueryParams {
            profile_id: profile_id.clone(),
            session_id: PrincipalSessionId::new(),
            endpoint_id: endpoint_id.clone(),
            process_digest: process_digest.clone(),
            policy_generation: None,
            policy_digest: policy_digest.clone(),
            action: IntentAction::Register,
            rp_id: "example.com".to_string(),
            credential_ref: None,
        });
        assert!(!is_replay);
    }

    #[test]
    fn test_cross_endpoint_replay_not_detected() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let profile_id = test_profile_id();
        let session_id = PrincipalSessionId::new();
        let process_digest = test_process_digest();
        let policy_digest = PolicyDigest::from_cbor_bytes(b"test-policy");

        let params = CreateIntentParams {
            profile_id: profile_id.clone(),
            session_id: session_id.clone(),
            endpoint_id: EndpointId::new(),
            process_digest: process_digest.clone(),
            action: IntentAction::Register,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            policy_generation: PolicyGenerationId::new(),
            policy_digest: policy_digest.clone(),
            require_uv: true,
            ttl_ms: Some(60_000),
        };

        let (_id, _) = store.create(params).unwrap();

        let is_replay = store.check_replay(&IntentQueryParams {
            profile_id: profile_id.clone(),
            session_id: session_id.clone(),
            endpoint_id: EndpointId::new(),
            process_digest: process_digest.clone(),
            policy_generation: None,
            policy_digest: policy_digest.clone(),
            action: IntentAction::Register,
            rp_id: "example.com".to_string(),
            credential_ref: None,
        });
        assert!(!is_replay);
    }

    #[test]
    fn test_cross_process_replay_not_detected() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let profile_id = test_profile_id();
        let session_id = PrincipalSessionId::new();
        let endpoint_id = EndpointId::new();
        let policy_digest = PolicyDigest::from_cbor_bytes(b"test-policy");

        let params = CreateIntentParams {
            profile_id: profile_id.clone(),
            session_id: session_id.clone(),
            endpoint_id: endpoint_id.clone(),
            process_digest: ProcessIdentityDigest::compute(1000, 1000, 42, b"exe-a"),
            action: IntentAction::Register,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            policy_generation: PolicyGenerationId::new(),
            policy_digest: policy_digest.clone(),
            require_uv: true,
            ttl_ms: Some(60_000),
        };

        let (_id, _) = store.create(params).unwrap();

        let different_process = ProcessIdentityDigest::compute(1000, 1000, 42, b"exe-b");
        let is_replay = store.check_replay(&IntentQueryParams {
            profile_id: profile_id.clone(),
            session_id: session_id.clone(),
            endpoint_id: endpoint_id.clone(),
            process_digest: different_process,
            policy_generation: None,
            policy_digest: policy_digest.clone(),
            action: IntentAction::Register,
            rp_id: "example.com".to_string(),
            credential_ref: None,
        });
        assert!(!is_replay);
    }

    #[test]
    fn test_cross_policy_replay_not_detected() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let profile_id = test_profile_id();
        let session_id = PrincipalSessionId::new();
        let endpoint_id = EndpointId::new();
        let process_digest = test_process_digest();

        let params = CreateIntentParams {
            profile_id: profile_id.clone(),
            session_id: session_id.clone(),
            endpoint_id: endpoint_id.clone(),
            process_digest: process_digest.clone(),
            action: IntentAction::Register,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            policy_generation: PolicyGenerationId::new(),
            policy_digest: PolicyDigest::from_cbor_bytes(b"policy-a"),
            require_uv: true,
            ttl_ms: Some(60_000),
        };

        let (_id, _) = store.create(params).unwrap();

        let different_policy = PolicyDigest::from_cbor_bytes(b"policy-b");
        let is_replay = store.check_replay(&IntentQueryParams {
            profile_id: profile_id.clone(),
            session_id: session_id.clone(),
            endpoint_id: endpoint_id.clone(),
            process_digest: process_digest.clone(),
            policy_generation: None,
            policy_digest: different_policy,
            action: IntentAction::Register,
            rp_id: "example.com".to_string(),
            credential_ref: None,
        });
        assert!(!is_replay);
    }

    #[test]
    fn test_exact_replay_detected() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let profile_id = test_profile_id();
        let session_id = PrincipalSessionId::new();
        let endpoint_id = EndpointId::new();
        let process_digest = test_process_digest();
        let policy_digest = PolicyDigest::from_cbor_bytes(b"test-policy");

        let params = CreateIntentParams {
            profile_id: profile_id.clone(),
            session_id: session_id.clone(),
            endpoint_id: endpoint_id.clone(),
            process_digest: process_digest.clone(),
            action: IntentAction::Register,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            policy_generation: PolicyGenerationId::new(),
            policy_digest: policy_digest.clone(),
            require_uv: true,
            ttl_ms: Some(60_000),
        };

        let (_id, _) = store.create(params).unwrap();

        let is_replay = store.check_replay(&IntentQueryParams {
            profile_id: profile_id.clone(),
            session_id: session_id.clone(),
            endpoint_id: endpoint_id.clone(),
            process_digest: process_digest.clone(),
            policy_generation: None,
            policy_digest: policy_digest.clone(),
            action: IntentAction::Register,
            rp_id: "example.com".to_string(),
            credential_ref: None,
        });
        assert!(is_replay);
    }

    #[test]
    fn test_different_action_not_replay() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let profile_id = test_profile_id();
        let session_id = PrincipalSessionId::new();
        let endpoint_id = EndpointId::new();
        let process_digest = test_process_digest();
        let policy_digest = PolicyDigest::from_cbor_bytes(b"test-policy");

        let params = CreateIntentParams {
            profile_id: profile_id.clone(),
            session_id: session_id.clone(),
            endpoint_id: endpoint_id.clone(),
            process_digest: process_digest.clone(),
            action: IntentAction::Register,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            policy_generation: PolicyGenerationId::new(),
            policy_digest: policy_digest.clone(),
            require_uv: true,
            ttl_ms: Some(60_000),
        };

        let (_id, _) = store.create(params).unwrap();

        let is_replay = store.check_replay(&IntentQueryParams {
            profile_id: profile_id.clone(),
            session_id: session_id.clone(),
            endpoint_id: endpoint_id.clone(),
            process_digest: process_digest.clone(),
            policy_generation: None,
            policy_digest: policy_digest.clone(),
            action: IntentAction::Authenticate,
            rp_id: "example.com".to_string(),
            credential_ref: None,
        });
        assert!(!is_replay);
    }

    #[test]
    fn test_different_rp_id_not_replay() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let profile_id = test_profile_id();
        let session_id = PrincipalSessionId::new();
        let endpoint_id = EndpointId::new();
        let process_digest = test_process_digest();
        let policy_digest = PolicyDigest::from_cbor_bytes(b"test-policy");

        let params = CreateIntentParams {
            profile_id: profile_id.clone(),
            session_id: session_id.clone(),
            endpoint_id: endpoint_id.clone(),
            process_digest: process_digest.clone(),
            action: IntentAction::Register,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            policy_generation: PolicyGenerationId::new(),
            policy_digest: policy_digest.clone(),
            require_uv: true,
            ttl_ms: Some(60_000),
        };

        let (_id, _) = store.create(params).unwrap();

        let is_replay = store.check_replay(&IntentQueryParams {
            profile_id: profile_id.clone(),
            session_id: session_id.clone(),
            endpoint_id: endpoint_id.clone(),
            process_digest: process_digest.clone(),
            policy_generation: None,
            policy_digest: policy_digest.clone(),
            action: IntentAction::Register,
            rp_id: "other.com".to_string(),
            credential_ref: None,
        });
        assert!(!is_replay);
    }

    #[test]
    fn test_bounded_store_rejects_when_full() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::new(Box::new(clock), 2);

        let params1 = test_params();
        let params2 = CreateIntentParams {
            session_id: PrincipalSessionId::new(),
            ..test_params()
        };
        let params3 = CreateIntentParams {
            session_id: PrincipalSessionId::new(),
            ..test_params()
        };

        let _ = store.create(params1).unwrap();
        let _ = store.create(params2).unwrap();
        let result = store.create(params3);
        assert_eq!(result, Err(IntentError::StoreFull));
    }

    #[test]
    fn test_bounded_store_allows_after_cleanup() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::new(Box::new(clock.clone()), 1);

        let params = CreateIntentParams {
            ttl_ms: Some(100),
            ..test_params()
        };
        let (id, _) = store.create(params).unwrap();

        clock.advance(101);
        store.cleanup_expired();
        assert_eq!(store.state(&id), Some(&IntentState::Expired));

        store.cleanup_terminal();
        assert_eq!(store.active_count(), 0);

        let new_params = CreateIntentParams {
            session_id: PrincipalSessionId::new(),
            ..test_params()
        };
        let result = store.create(new_params);
        assert!(result.is_ok());
    }

    #[test]
    fn test_restart_invalidates_all_intents() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let params = test_params();

        let (id, _) = store.create(params).unwrap();
        assert_eq!(store.active_count(), 1);
        let old_nonce = store.boot_nonce();

        store.invalidate_all();
        assert_eq!(store.active_count(), 0);
        assert_ne!(store.boot_nonce(), old_nonce);
        assert!(store.get(&id).is_none());
    }

    #[test]
    fn test_boot_nonce_verification() {
        let clock = FakeClock::new(0);
        let store = IntentStore::with_defaults(Box::new(clock));
        let nonce = store.boot_nonce();
        assert!(store.verify_boot_nonce(nonce));
        assert!(!store.verify_boot_nonce(nonce + 1));
    }

    #[test]
    fn test_claim_token_not_in_debug() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let params = test_params();

        let (id, _token) = store.create(params).unwrap();
        let intent = store.get(&id).unwrap();
        let debug_str = format!("{:?}", intent);
        assert!(debug_str.contains("<redacted>"));
        assert!(!debug_str.contains("ClaimToken("));
    }

    #[test]
    fn test_claim_token_display_redacted() {
        let token = ClaimToken::generate();
        let display = format!("{}", token);
        assert_eq!(display, "<redacted>");
    }

    #[test]
    fn test_claim_token_debug_redacted() {
        let token = ClaimToken::generate();
        let debug = format!("{:?}", token);
        assert_eq!(debug, "ClaimToken(<redacted>)");
    }

    #[test]
    fn test_monotonic_time_ordering() {
        let t1 = MonotonicTime::from_millis(100);
        let t2 = MonotonicTime::from_millis(200);
        assert!(t1 < t2);
        assert!(t2 > t1);
        assert_eq!(t1, MonotonicTime::from_millis(100));
    }

    #[test]
    fn test_monotonic_time_arithmetic() {
        let t = MonotonicTime::from_millis(100);
        let t2 = t.checked_add(50).unwrap();
        assert_eq!(t2.as_millis(), 150);
        assert_eq!(t2.saturating_duration_since(t), 50);
    }

    #[test]
    fn test_process_identity_digest_deterministic() {
        let d1 = ProcessIdentityDigest::compute(1000, 1000, 42, b"hash");
        let d2 = ProcessIdentityDigest::compute(1000, 1000, 42, b"hash");
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_process_identity_digest_different_inputs() {
        let d1 = ProcessIdentityDigest::compute(1000, 1000, 42, b"hash-a");
        let d2 = ProcessIdentityDigest::compute(1000, 1000, 42, b"hash-b");
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_full_lifecycle() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let authority = admin_authority();
        let params = test_params();

        let (id, token) = store.create(params).unwrap();
        assert_eq!(store.state(&id), Some(&IntentState::Pending));

        store.approve(&id, &authority).unwrap();
        assert_eq!(store.state(&id), Some(&IntentState::Approved));

        store.claim(&id, &token).unwrap();
        assert_eq!(store.state(&id), Some(&IntentState::Claimed));

        let info = store.consume(&id).unwrap();
        assert_eq!(store.state(&id), Some(&IntentState::Consumed));
        assert_eq!(info.rp_id, "example.com");
        assert_eq!(info.action, IntentAction::Register);
        assert!(info.require_uv);
    }

    #[test]
    fn test_terminal_state_counts() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let authority = admin_authority();

        let params1 = test_params();
        let params2 = CreateIntentParams {
            session_id: PrincipalSessionId::new(),
            ..test_params()
        };

        let (id1, _) = store.create(params1).unwrap();
        let (id2, _) = store.create(params2).unwrap();

        store.deny(&id1, &authority).unwrap();
        assert_eq!(store.active_count(), 1);
        assert_eq!(store.total_count(), 2);

        let _ = id2;
    }

    #[test]
    fn test_cleanup_terminal() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let authority = admin_authority();

        let params = test_params();
        let (id, _) = store.create(params).unwrap();
        store.deny(&id, &authority).unwrap();

        assert_eq!(store.total_count(), 1);
        store.cleanup_terminal();
        assert_eq!(store.total_count(), 0);
    }

    #[test]
    fn test_intent_with_credential_ref() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let authority = admin_authority();
        let cred_ref = CredentialRef::with_default_domain(b"test-credential");
        let params = CreateIntentParams {
            profile_id: test_profile_id(),
            session_id: PrincipalSessionId::new(),
            endpoint_id: EndpointId::new(),
            process_digest: test_process_digest(),
            action: IntentAction::Authenticate,
            rp_id: "example.com".to_string(),
            credential_ref: Some(cred_ref.clone()),
            policy_generation: PolicyGenerationId::new(),
            policy_digest: PolicyDigest::from_cbor_bytes(b"test-policy"),
            require_uv: true,
            ttl_ms: Some(60_000),
        };

        let (id, token) = store.create(params).unwrap();
        store.approve(&id, &authority).unwrap();
        store.claim(&id, &token).unwrap();
        let info = store.consume(&id).unwrap();

        assert_eq!(info.credential_ref, Some(cred_ref));
        assert_eq!(info.action, IntentAction::Authenticate);
    }

    #[test]
    fn test_expired_intent_not_found_for_approve() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock.clone()));
        let authority = admin_authority();
        let params = CreateIntentParams {
            ttl_ms: Some(100),
            ..test_params()
        };

        let (id, _) = store.create(params).unwrap();
        clock.advance(101);

        let result = store.approve(&id, &authority);
        assert_eq!(result, Err(IntentError::Expired));
    }

    #[test]
    fn test_nonexistent_intent_operations() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let authority = admin_authority();
        let fake_id = IntentId::new();

        assert!(store.get(&fake_id).is_none());
        assert!(store.state(&fake_id).is_none());
        assert_eq!(
            store.approve(&fake_id, &authority),
            Err(IntentError::NotFound)
        );
        assert_eq!(store.deny(&fake_id, &authority), Err(IntentError::NotFound));
        assert_eq!(store.consume(&fake_id), Err(IntentError::NotFound));
    }

    #[test]
    fn test_terminal_state_not_counted_as_replay() {
        let clock = FakeClock::new(0);
        let mut store = IntentStore::with_defaults(Box::new(clock));
        let authority = admin_authority();
        let profile_id = test_profile_id();
        let session_id = PrincipalSessionId::new();
        let endpoint_id = EndpointId::new();
        let process_digest = test_process_digest();
        let policy_digest = PolicyDigest::from_cbor_bytes(b"test-policy");

        let params = CreateIntentParams {
            profile_id: profile_id.clone(),
            session_id: session_id.clone(),
            endpoint_id: endpoint_id.clone(),
            process_digest: process_digest.clone(),
            action: IntentAction::Register,
            rp_id: "example.com".to_string(),
            credential_ref: None,
            policy_generation: PolicyGenerationId::new(),
            policy_digest: policy_digest.clone(),
            require_uv: true,
            ttl_ms: Some(60_000),
        };

        let (id, _) = store.create(params).unwrap();
        store.deny(&id, &authority).unwrap();

        let is_replay = store.check_replay(&IntentQueryParams {
            profile_id: profile_id.clone(),
            session_id: session_id.clone(),
            endpoint_id: endpoint_id.clone(),
            process_digest: process_digest.clone(),
            policy_generation: None,
            policy_digest: policy_digest.clone(),
            action: IntentAction::Register,
            rp_id: "example.com".to_string(),
            credential_ref: None,
        });
        assert!(!is_replay);
    }

    #[test]
    fn test_session_identity_digest_two_sessions_differ() {
        let d1 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1000,
            gid: 1000,
            pid: 100,
            start_time: 5000,
            cgroup_path: "/user.slice".to_string(),
            ns_user: 4026531837,
            ns_pid: 4026531836,
            ns_mnt: 4026531840,
        });
        let d2 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1000,
            gid: 1000,
            pid: 200,
            start_time: 6000,
            cgroup_path: "/user.slice".to_string(),
            ns_user: 4026531837,
            ns_pid: 4026531836,
            ns_mnt: 4026531840,
        });
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_session_identity_digest_same_inputs_same_output() {
        let d1 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1000,
            gid: 1000,
            pid: 100,
            start_time: 5000,
            cgroup_path: "/user.slice".to_string(),
            ns_user: 1,
            ns_pid: 2,
            ns_mnt: 3,
        });
        let d2 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1000,
            gid: 1000,
            pid: 100,
            start_time: 5000,
            cgroup_path: "/user.slice".to_string(),
            ns_user: 1,
            ns_pid: 2,
            ns_mnt: 3,
        });
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_session_identity_digest_differs_by_cgroup() {
        let d1 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1000,
            gid: 1000,
            pid: 100,
            start_time: 5000,
            cgroup_path: "/user.slice/a".to_string(),
            ns_user: 1,
            ns_pid: 2,
            ns_mnt: 3,
        });
        let d2 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1000,
            gid: 1000,
            pid: 100,
            start_time: 5000,
            cgroup_path: "/user.slice/b".to_string(),
            ns_user: 1,
            ns_pid: 2,
            ns_mnt: 3,
        });
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_session_identity_digest_differs_by_ns_inodes() {
        let d1 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1000,
            gid: 1000,
            pid: 100,
            start_time: 5000,
            cgroup_path: "/user.slice".to_string(),
            ns_user: 1,
            ns_pid: 2,
            ns_mnt: 3,
        });
        let d2 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1000,
            gid: 1000,
            pid: 100,
            start_time: 5000,
            cgroup_path: "/user.slice".to_string(),
            ns_user: 4,
            ns_pid: 5,
            ns_mnt: 6,
        });
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_session_identity_digest_differs_by_uid_gid() {
        let d1 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1000,
            gid: 1000,
            pid: 100,
            start_time: 5000,
            cgroup_path: "/user.slice".to_string(),
            ns_user: 1,
            ns_pid: 2,
            ns_mnt: 3,
        });
        let d2 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1001,
            gid: 1001,
            pid: 100,
            start_time: 5000,
            cgroup_path: "/user.slice".to_string(),
            ns_user: 1,
            ns_pid: 2,
            ns_mnt: 3,
        });
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_session_identity_digest_differs_by_start_time() {
        let d1 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1000,
            gid: 1000,
            pid: 100,
            start_time: 5000,
            cgroup_path: "/user.slice".to_string(),
            ns_user: 1,
            ns_pid: 2,
            ns_mnt: 3,
        });
        let d2 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1000,
            gid: 1000,
            pid: 100,
            start_time: 5001,
            cgroup_path: "/user.slice".to_string(),
            ns_user: 1,
            ns_pid: 2,
            ns_mnt: 3,
        });
        assert_ne!(d1, d2);
    }

    #[test]
    fn test_session_identity_digest_domain_separated_from_v1() {
        let d_v1 = ProcessIdentityDigest::compute(1000, 1000, 100, b"test");
        let d_v2 = ProcessIdentityDigest::compute_from_session_identity(&SessionIdentityParams {
            uid: 1000,
            gid: 1000,
            pid: 100,
            start_time: 0,
            cgroup_path: "".to_string(),
            ns_user: 0,
            ns_pid: 0,
            ns_mnt: 0,
        });
        assert_ne!(d_v1, d_v2);
    }
}
