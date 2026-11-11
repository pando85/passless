use std::collections::HashMap;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use log::{debug, warn};
use sha2::{Digest, Sha256};

use passless_core::agent::config::{ANY_RP_ID, CredentialSelection, LOCALHOST_RP_ID};
use passless_core::agent::protocol::{
    ErrorCode, IntentAction, PrincipalResponse, ProtocolError, RecommendedAction,
    SignAssertionRequest, SignAssertionResponse,
};
use passless_core::agent::{CredentialRef, ProfileId, RuleAction, RuleIdentity};
use passless_core::config::SecurityConfig;

use super::audit::AuditGate;
use super::audit_events::{AuditAction, PolicyAllowBuilder, PolicyDenyBuilder, PolicyDenyReason};
use super::escalation::{
    EscalationOutcome, EscalationRefusal, EscalationRequest, EscalationService, NoPark, ParkHook,
    WaiterSession,
};
use super::granted_rules::PermittingRule;
use super::lock_order::{self, LockLevel, Tracked};
use super::policy_engine::PolicyRuntime;
use super::register::{RegisterContext, RegisterHandler};
use super::session::{
    AgentSession, CeremonyAction, CeremonyOutcome, CeremonyResult, ChallengeDigest, Claim,
    ClaimGuard, ClaimRejection, JoinResult, ReplayKey, SessionInvalid, ceremony_deadline,
};

use crate::storage::CredentialStorage;

use soft_fido2::CredentialKeyProvider;

const B64U_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn b64u_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 4).div_ceil(3));
    let mut i = 0;
    while i + 2 < data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(B64U_CHARS[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64U_CHARS[((n >> 12) & 0x3F) as usize] as char);
        out.push(B64U_CHARS[((n >> 6) & 0x3F) as usize] as char);
        out.push(B64U_CHARS[(n & 0x3F) as usize] as char);
        i += 3;
    }
    let remaining = data.len() - i;
    if remaining == 1 {
        let n = (data[i] as u32) << 16;
        out.push(B64U_CHARS[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64U_CHARS[((n >> 12) & 0x3F) as usize] as char);
    } else if remaining == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        out.push(B64U_CHARS[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64U_CHARS[((n >> 12) & 0x3F) as usize] as char);
        out.push(B64U_CHARS[((n >> 6) & 0x3F) as usize] as char);
    }
    out
}

pub fn b64u_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in s.as_bytes() {
        let val = match b {
            b'A'..=b'Z' => (b - b'A') as u32,
            b'a'..=b'z' => (b - b'a' + 26) as u32,
            b'0'..=b'9' => (b - b'0' + 52) as u32,
            b'-' => 62,
            b'_' => 63,
            b'=' => continue,
            _ => return Err(format!("invalid base64url byte: {}", b)),
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
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

pub fn build_client_data_json(
    origin: &str,
    challenge_b64u: &str,
    cross_origin: bool,
    top_origin: Option<&str>,
) -> Vec<u8> {
    let mut cdj = String::with_capacity(160);
    cdj.push_str("{\"type\":\"webauthn.get\",\"challenge\":\"");
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

pub fn build_authenticator_data(
    rp_id: &str,
    up: bool,
    uv: bool,
    backup_flags: u8,
    sign_count: u32,
) -> Vec<u8> {
    let mut auth_data = Vec::with_capacity(37);
    let mut hasher = Sha256::new();
    hasher.update(rp_id.as_bytes());
    auth_data.extend_from_slice(&hasher.finalize());
    let mut flags = 0u8;
    if up {
        flags |= 0x01;
    }
    if uv {
        flags |= 0x04;
    }
    flags |= backup_flags;
    auth_data.push(flags);
    auth_data.extend_from_slice(&sign_count.to_be_bytes());
    auth_data
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginScheme {
    Https,
    /// Accepted only for exactly `localhost` (ADR 0014 section 6.1, plan R15).
    Http,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedOrigin {
    pub scheme: OriginScheme,
    pub host: String,
    pub port: Option<u16>,
}

/// Parse a web origin. `https://host[:port]` is accepted for any host; `http://` is accepted only
/// for exactly `localhost[:port]`, never for `*.localhost` or any other host.
pub fn parse_origin(origin: &str) -> Option<ParsedOrigin> {
    let (scheme, rest) = if let Some(rest) = origin.strip_prefix("https://") {
        (OriginScheme::Https, rest)
    } else {
        (OriginScheme::Http, origin.strip_prefix("http://")?)
    };
    if rest.is_empty() {
        return None;
    }
    if rest.contains('/') && !rest.ends_with('/') {
        return None;
    }
    let host_part = rest.trim_end_matches('/');
    if host_part.is_empty() {
        return None;
    }
    if host_part.contains('?') || host_part.contains('#') || host_part.contains('@') {
        return None;
    }
    let (host, port) = if host_part.contains(':') {
        let (host, port_str) = host_part.rsplit_once(':').unwrap();
        if host.is_empty() {
            return None;
        }
        // ASCII digits only (`u16::from_str` also accepts a leading `+`), and port 0 is not a port.
        if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let port: u16 = port_str.parse().ok().filter(|port| *port != 0)?;
        (host.to_ascii_lowercase(), Some(port))
    } else {
        (host_part.to_ascii_lowercase(), None)
    };
    if scheme == OriginScheme::Http && host != LOCALHOST_RP_ID {
        return None;
    }
    Some(ParsedOrigin { scheme, host, port })
}

pub fn verify_origin_structural(origin: &str, rp_id: &str) -> bool {
    let parsed = match parse_origin(origin) {
        Some(p) => p,
        None => return false,
    };
    let normalized_rp = rp_id.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized_rp.is_empty() {
        return false;
    }
    // `localhost` is an exact-match RP: `foo.localhost` is never a valid origin for it.
    if normalized_rp == LOCALHOST_RP_ID {
        return parsed.host == LOCALHOST_RP_ID;
    }
    parsed.host == normalized_rp || parsed.host.ends_with(&format!(".{normalized_rp}"))
}

pub fn verify_origin_context(
    origin: &str,
    top_origin: Option<&str>,
    cross_origin: bool,
    rp_id: &str,
) -> bool {
    if !verify_origin_structural(origin, rp_id) {
        return false;
    }
    // Cross-origin frames fail closed (ADR 0014 §11, `sameOriginWithAncestors = false`): never allowed.
    if cross_origin {
        return false;
    }
    match top_origin {
        Some(top) => parse_origin(top).is_some_and(|parsed| {
            parse_origin(origin).is_some_and(|frame| {
                parsed.scheme == frame.scheme
                    && parsed.host == frame.host
                    && parsed.port == frame.port
            })
        }),
        None => true,
    }
}

fn normalize_rp_id(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let max_len = if a.len() > b.len() { a.len() } else { b.len() };
    let mut diff: usize = a.len() ^ b.len();
    for i in 0..max_len {
        let ab = if i < a.len() { a[i] } else { 0 };
        let bb = if i < b.len() { b[i] } else { 0 };
        diff |= (ab ^ bb) as usize;
    }
    diff == 0
}

pub fn generate_bearer_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    let mut rng = std::fs::File::open("/dev/urandom").map_err(|e| format!("urandom: {}", e))?;
    rng.read_exact(&mut bytes)
        .map_err(|e| format!("urandom read: {}", e))?;
    Ok(b64u_encode(&bytes))
}

#[derive(Clone)]
pub struct LeaseEntry {
    pub context: SignContext,
    pub handler: Arc<SignHandler>,
    pub lease_id: Option<String>,
}

pub struct SignContextRegistry {
    entries: Mutex<HashMap<String, LeaseEntry>>,
    registration_entries: Mutex<HashMap<String, RegistrationLeaseEntry>>,
    revoked_registrations: Mutex<RevokedRegistrations>,
}

/// A registration bearer is bound to the browser lease it was issued for, like a sign bearer, and is
/// revoked with it (ADR 0014 section 9). It shares the sign bearer's session (replay table, budget,
/// revocation).
#[derive(Clone)]
pub struct RegistrationLeaseEntry {
    pub context: RegisterContext,
    pub handler: Arc<RegisterHandler>,
    pub lease_id: Option<String>,
}

/// Most revoked registration bearers remembered so a late use can be refused and audited.
const MAX_REVOKED_REGISTRATIONS: usize = 256;
/// Refusals recorded per revoked bearer; later attempts are still refused but not audited again,
/// so a browser holding an old bearer cannot flood the audit log.
const MAX_AUDITED_REFUSALS_PER_BEARER: usize = 16;

/// What is kept of a revoked registration bearer: enough to audit a late use, never to serve it.
#[derive(Clone)]
pub struct RevokedRegistration {
    context: RegisterContext,
    handler: Arc<RegisterHandler>,
    refusals: Arc<std::sync::atomic::AtomicUsize>,
}

impl RevokedRegistration {
    /// Audit a refused registration (bounded per bearer, see `MAX_AUDITED_REFUSALS_PER_BEARER`).
    /// `rp_id` is the untrusted RP ID of the refused request, if it named one.
    pub fn refuse(&self, rp_id: Option<&str>) {
        if self.refusals.fetch_add(1, Ordering::AcqRel) < MAX_AUDITED_REFUSALS_PER_BEARER {
            self.handler.refuse_revoked_bearer(&self.context, rp_id);
        }
    }
}

#[derive(Default)]
struct RevokedRegistrations {
    order: std::collections::VecDeque<String>,
    entries: HashMap<String, RevokedRegistration>,
}

impl RevokedRegistrations {
    fn remember(&mut self, token: String, entry: &RegistrationLeaseEntry) {
        if self.entries.contains_key(&token) {
            return;
        }
        while self.order.len() >= MAX_REVOKED_REGISTRATIONS {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        self.order.push_back(token.clone());
        self.entries.insert(
            token,
            RevokedRegistration {
                context: entry.context.clone(),
                handler: entry.handler.clone(),
                refusals: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            },
        );
    }
}

/// A bearer looked up for a request: the sign or the registration context behind it.
#[derive(Clone)]
pub enum BearerEntry {
    Sign(LeaseEntry),
    Register(RegistrationLeaseEntry),
}

impl BearerEntry {
    pub fn session(&self) -> &Arc<AgentSession> {
        match self {
            Self::Sign(entry) => &entry.context.session,
            Self::Register(entry) => &entry.context.session,
        }
    }

    pub fn profile_id(&self) -> &ProfileId {
        match self {
            Self::Sign(entry) => &entry.context.profile_id,
            Self::Register(entry) => &entry.context.profile_id,
        }
    }

    pub fn audit_gate(&self) -> &Arc<AuditGate> {
        match self {
            Self::Sign(entry) => &entry.handler.audit_gate,
            Self::Register(entry) => &entry.handler.audit_gate,
        }
    }

    pub fn policy_runtime(&self) -> &Arc<PolicyRuntime> {
        match self {
            Self::Sign(entry) => &entry.handler.policy_runtime,
            Self::Register(entry) => &entry.handler.policy_runtime,
        }
    }
}

impl SignContextRegistry {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            registration_entries: Mutex::new(HashMap::new()),
            revoked_registrations: Mutex::new(RevokedRegistrations::default()),
        }
    }

    fn lock_entries(&self) -> Tracked<MutexGuard<'_, HashMap<String, LeaseEntry>>> {
        lock_order::lock(&self.entries, LockLevel::SignRegistry)
    }

    fn lock_registration_entries(
        &self,
    ) -> Tracked<MutexGuard<'_, HashMap<String, RegistrationLeaseEntry>>> {
        lock_order::lock(&self.registration_entries, LockLevel::SignRegistry)
    }

    fn lock_revoked_registrations(&self) -> Tracked<MutexGuard<'_, RevokedRegistrations>> {
        lock_order::lock(&self.revoked_registrations, LockLevel::SignRegistry)
    }

    /// The session already registered for `token` by the other context kind, if any.
    fn existing_session(&self, token: &str) -> Option<Arc<AgentSession>> {
        if let Some(entry) = self.lock_entries().get(token) {
            return Some(entry.context.session.clone());
        }
        self.lock_registration_entries()
            .get(token)
            .map(|entry| entry.context.session.clone())
    }

    /// One bearer has one session: a sign and a registration context of the same token must share it.
    fn check_same_session(&self, token: &str, session: &Arc<AgentSession>) -> Result<(), String> {
        match self.existing_session(token) {
            Some(existing) if !Arc::ptr_eq(&existing, session) => {
                Err("bearer session mismatch".into())
            }
            _ => Ok(()),
        }
    }

    pub fn register_pending_registration(
        &self,
        token: String,
        context: RegisterContext,
        handler: Arc<RegisterHandler>,
    ) -> Result<(), String> {
        self.check_same_session(&token, &context.session)?;
        let mut map = self.lock_registration_entries();
        if map.contains_key(&token) {
            return Err("duplicate token".into());
        }
        map.insert(
            token,
            RegistrationLeaseEntry {
                context,
                handler,
                lease_id: None,
            },
        );
        Ok(())
    }

    /// Bind a registration bearer to its browser lease. Until it is bound the bearer is unusable,
    /// exactly like a sign bearer.
    pub fn bind_registration_lease(&self, token: &str, lease_id: String) -> Result<(), String> {
        let mut map = self.lock_registration_entries();
        let entry = map.get_mut(token).ok_or("token not found")?;
        if entry.lease_id.is_some() {
            return Err("already bound".into());
        }
        entry.lease_id = Some(lease_id);
        Ok(())
    }

    /// A live (bound, not revoked) registration bearer.
    pub fn lookup_registration(&self, token: &str) -> Option<RegistrationLeaseEntry> {
        let map = self.lock_registration_entries();
        let mut found = None;
        for (k, v) in map.iter() {
            if constant_time_eq(token.as_bytes(), k.as_bytes()) {
                found = Some(v);
            }
        }
        found.filter(|entry| entry.lease_id.is_some()).cloned()
    }

    /// A bearer the transport may accept at `hello` (ADR 0014 section 11, plan D6.1): a sign or a
    /// registration bearer, bound to its lease or not yet bound (the browser's worker says hello
    /// while the browser is still launching). Requests still require the binding, and re-validate
    /// the bearer from scratch ([`Self::lookup_bound`], [`Self::lookup_registration`]).
    pub fn lookup_for_hello(&self, token: &str) -> Option<BearerEntry> {
        let sign = {
            let map = self.lock_entries();
            let mut found = None;
            for (k, v) in map.iter() {
                if constant_time_eq(token.as_bytes(), k.as_bytes()) {
                    found = Some(v.clone());
                }
            }
            found
        };
        if let Some(entry) = sign {
            return Some(BearerEntry::Sign(entry));
        }
        let map = self.lock_registration_entries();
        let mut found = None;
        for (k, v) in map.iter() {
            if constant_time_eq(token.as_bytes(), k.as_bytes()) {
                found = Some(v.clone());
            }
        }
        found.map(BearerEntry::Register)
    }

    /// A registration bearer that was revoked; used only to refuse and audit a late registration.
    pub fn lookup_revoked_registration(&self, token: &str) -> Option<RevokedRegistration> {
        let revoked = self.lock_revoked_registrations();
        let mut found = None;
        for (k, v) in revoked.entries.iter() {
            if constant_time_eq(token.as_bytes(), k.as_bytes()) {
                found = Some(v);
            }
        }
        found.cloned()
    }

    pub fn revoke_registration(&self, token: &str) -> bool {
        let removed = self.lock_registration_entries().remove(token);
        let Some(entry) = removed else {
            return false;
        };
        // Fail any request of this bearer that is already past authentication.
        entry.context.session.revoke();
        self.lock_revoked_registrations()
            .remember(token.to_string(), &entry);
        true
    }

    pub fn register_pending(
        &self,
        token: String,
        context: SignContext,
        handler: Arc<SignHandler>,
    ) -> Result<(), String> {
        self.check_same_session(&token, &context.session)?;
        let mut map = self.lock_entries();
        if map.contains_key(&token) {
            return Err("duplicate token".into());
        }
        map.insert(
            token,
            LeaseEntry {
                context,
                handler,
                lease_id: None,
            },
        );
        Ok(())
    }

    pub fn bind_lease(&self, token: &str, lease_id: String) -> Result<(), String> {
        let mut map = self.lock_entries();
        let entry = map.get_mut(token).ok_or("token not found")?;
        if entry.lease_id.is_some() {
            return Err("already bound".into());
        }
        entry.lease_id = Some(lease_id);
        Ok(())
    }

    pub fn lookup_bound(&self, token: &str) -> Option<LeaseEntry> {
        let map = self.lock_entries();
        let mut found = None;
        for (k, v) in map.iter() {
            if constant_time_eq(token.as_bytes(), k.as_bytes()) {
                found = Some(v);
            }
        }
        found.filter(|entry| entry.lease_id.is_some()).cloned()
    }

    pub fn revoke(&self, token: &str) -> bool {
        match self.lock_entries().remove(token) {
            Some(entry) => {
                entry.context.session.revoke();
                true
            }
            None => false,
        }
    }

    pub fn revoke_by_lease(&self, lease_id: &str) -> usize {
        let removed: Vec<LeaseEntry> = {
            let mut map = self.lock_entries();
            let keys: Vec<String> = map
                .iter()
                .filter(|(_, e)| e.lease_id.as_deref() == Some(lease_id))
                .map(|(k, _)| k.clone())
                .collect();
            keys.iter().filter_map(|k| map.remove(k)).collect()
        };
        let mut count = removed.len();
        for entry in &removed {
            entry.context.session.revoke();
        }

        // Registration bearers die with the lease too.
        let registration_keys: Vec<String> = self
            .lock_registration_entries()
            .iter()
            .filter(|(_, e)| e.lease_id.as_deref() == Some(lease_id))
            .map(|(k, _)| k.clone())
            .collect();
        for key in registration_keys {
            if self.revoke_registration(&key) {
                count += 1;
            }
        }
        count
    }

    /// Revoke every bearer whose session was created before `current_epoch` (a policy reload or a
    /// revocation bumped it). In-flight requests of those bearers fail before key use because they
    /// re-check the epoch; this also drops the entries so the bearers are refused up front.
    pub fn revoke_stale_sessions(&self, current_epoch: u64) -> usize {
        let stale_sign: Vec<LeaseEntry> = {
            let mut map = self.lock_entries();
            let keys: Vec<String> = map
                .iter()
                .filter(|(_, e)| e.context.session.revocation_epoch() != current_epoch)
                .map(|(k, _)| k.clone())
                .collect();
            keys.iter().filter_map(|k| map.remove(k)).collect()
        };
        for entry in &stale_sign {
            entry.context.session.revoke();
        }
        let stale_registration: Vec<String> = self
            .lock_registration_entries()
            .iter()
            .filter(|(_, e)| e.context.session.revocation_epoch() != current_epoch)
            .map(|(k, _)| k.clone())
            .collect();
        let mut count = stale_sign.len();
        for key in stale_registration {
            if self.revoke_registration(&key) {
                count += 1;
            }
        }
        count
    }

    pub fn revoke_all(&self) {
        for entry in self.lock_entries().drain() {
            entry.1.context.session.revoke();
        }
        for entry in self.lock_registration_entries().drain() {
            entry.1.context.session.revoke();
        }
        *self.lock_revoked_registrations() = RevokedRegistrations::default();
    }

    pub fn len(&self) -> usize {
        self.lock_entries().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// `(used, max)` operations of the session bound to `lease_id`; `max` is the live budget.
    pub fn budget_snapshot_for_lease(&self, lease_id: &str) -> Option<(usize, usize)> {
        let entry = self
            .lock_entries()
            .values()
            .find(|entry| entry.lease_id.as_deref() == Some(lease_id))
            .cloned()?;
        let max = entry
            .handler
            .policy_runtime
            .max_operations(&entry.context.profile_id)?;
        let used = entry.context.session.operations_used();
        Some((used as usize, usize::from(max)))
    }

    #[cfg(test)]
    pub fn all_entries(&self) -> Vec<LeaseEntry> {
        self.lock_entries().values().cloned().collect()
    }
}

impl Default for SignContextRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// The WebAuthn DOMException name the page receives for a daemon error (ADR 0014 sections
/// 10.2-10.3 and 11). The extension passes it to `complete*Request` and never invents one.
pub fn dom_exception_name(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::NotSupported => "NotSupportedError",
        ErrorCode::InvalidState => "InvalidStateError",
        ErrorCode::OriginInvalid => "SecurityError",
        ErrorCode::Aborted => "AbortError",
        // Policy denials, revocation, replay, budget, `busy`, timeouts and internal failures all
        // look the same to the page (ADR 0014 section 7).
        _ => "NotAllowedError",
    }
}

/// The assertion inside a replayed or joined outcome. The replay key includes the action, so an
/// authentication key never holds an attestation.
fn assertion_outcome(outcome: CeremonyOutcome) -> Result<PrincipalResponse, ProtocolError> {
    match outcome {
        Ok(CeremonyResult::Assertion(response)) => Ok(*response),
        Ok(CeremonyResult::Attestation(_)) => Err(ProtocolError::new(
            ErrorCode::Internal,
            "replay outcome has the wrong ceremony type",
            RecommendedAction::Abort,
        )),
        Err(e) => Err(e),
    }
}

#[derive(Clone)]
pub struct SignContext {
    pub profile_id: ProfileId,
    pub active_grant_id: passless_core::agent::GrantId,
    /// The bearer session: principal binding, revocation epoch at creation, TTL, replay table and
    /// budget usage. The budget limit itself (`max_operations`) is read from the live policy on
    /// every request, never copied here (plan R16).
    pub session: Arc<AgentSession>,
    /// Activates the browser lease after an assertion, outside every backend lock (review H1).
    /// `None` when the lease needs no activation.
    pub lease_activation: Option<Arc<dyn LeaseActivation>>,
}

/// Activation of a browser lease by its first assertion.
pub trait LeaseActivation: Send + Sync {
    /// Activate the lease, or confirm it is active. Called with no backend lock held; the
    /// assertion is released to the page only if this succeeds.
    fn activate(&self) -> Result<(), String>;
}

/// Activates a managed browser's lease (`AuthenticationPending` to `Active`) after its first
/// assertion. Once it has succeeded it never touches the browser manager again, so later
/// ceremonies never wait on another profile's launch or termination.
pub struct BrowserLeaseActivation {
    browser_manager: Arc<Mutex<super::browser::BrowserProcessManager>>,
    lease_id: passless_core::agent::BrowserLeaseId,
    active_ttl: Duration,
    activated: AtomicBool,
}

impl BrowserLeaseActivation {
    pub fn new(
        browser_manager: Arc<Mutex<super::browser::BrowserProcessManager>>,
        lease_id: passless_core::agent::BrowserLeaseId,
        active_ttl: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            browser_manager,
            lease_id,
            active_ttl,
            activated: AtomicBool::new(false),
        })
    }
}

impl LeaseActivation for BrowserLeaseActivation {
    fn activate(&self) -> Result<(), String> {
        if self.activated.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut browser_manager =
            lock_order::lock(&self.browser_manager, LockLevel::BrowserManager);
        let state = browser_manager
            .snapshot(&self.lease_id)
            .ok_or_else(|| "browser lease not found".to_string())?
            .state;
        match state {
            super::browser::LeaseState::AuthenticationPending => {
                browser_manager
                    .activate_after_assertion(&self.lease_id, self.active_ttl)
                    .map_err(|e| {
                        format!("failed to activate browser lease after assertion: {e}")
                    })?;
            }
            super::browser::LeaseState::Active => {}
            current => {
                return Err(format!(
                    "browser lease cannot activate after assertion from state {current}"
                ));
            }
        }
        self.activated.store(true, Ordering::Release);
        Ok(())
    }
}

#[derive(Clone)]
pub struct SignHandler {
    pub credential_storage: Arc<Mutex<Box<dyn CredentialStorage>>>,
    pub policy_runtime: Arc<PolicyRuntime>,
    pub audit_gate: Arc<AuditGate>,
    pub security_config: SecurityConfig,
    pub key_provider: Arc<dyn CredentialKeyProvider + Send + Sync>,
    pub operation_lock: Arc<Mutex<()>>,
    /// The escalation coordinator a `request` resolution waits on (ADR 0014 section 8).
    pub escalation: Arc<EscalationService>,
}

/// Client extensions an authentication request may name. `appid` is honored by never matching a
/// U2F AppID credential (its output is `false`). `remoteDesktopClientOverride` is browser metadata,
/// not an RP extension (ADR 0014 section 10.2): the transport strips it while it parses the
/// request, so it never reaches this list.
const SUPPORTED_GET_EXTENSIONS: &[&str] = &["appid"];
/// Most extension identifiers a request may name, and their longest accepted length.
pub(crate) const MAX_EXTENSIONS: usize = 32;
pub(crate) const MAX_EXTENSION_ID_LEN: usize = 64;

/// Check the extension identifiers of a request against `supported`. `Ok(false)` means an
/// unsupported extension was requested (`NotSupportedError`); `Err` means the list is malformed.
pub(crate) fn extensions_supported(
    requested: &[String],
    supported: &[&str],
) -> Result<bool, ProtocolError> {
    if requested.len() > MAX_EXTENSIONS
        || requested
            .iter()
            .any(|id| id.is_empty() || id.len() > MAX_EXTENSION_ID_LEN)
    {
        return Err(ProtocolError::new(
            ErrorCode::BadRequest,
            "malformed extension list",
            RecommendedAction::FixRequest,
        ));
    }
    Ok(requested.iter().all(|id| supported.contains(&id.as_str())))
}

/// Map a session that can no longer be used to its audit reason and error.
pub(crate) fn session_invalid_error(invalid: SessionInvalid) -> (PolicyDenyReason, ProtocolError) {
    match invalid {
        SessionInvalid::Revoked => (
            PolicyDenyReason::BearerRevoked,
            ProtocolError::new(
                ErrorCode::Unauthorized,
                "bearer session was revoked",
                RecommendedAction::Abort,
            ),
        ),
        SessionInvalid::EpochChanged => (
            PolicyDenyReason::PolicyRevoked,
            ProtocolError::new(
                ErrorCode::Unauthorized,
                "bearer session was revoked by a policy change",
                RecommendedAction::Abort,
            ),
        ),
        SessionInvalid::Expired => (
            PolicyDenyReason::SessionExpired,
            ProtocolError::new(
                ErrorCode::Unauthorized,
                "bearer session expired",
                RecommendedAction::Abort,
            ),
        ),
    }
}

/// Map a refused claim to its audit reason and error. None of these consumed budget.
pub(crate) fn claim_rejection_error(
    rejection: ClaimRejection,
) -> (PolicyDenyReason, ProtocolError) {
    match rejection {
        ClaimRejection::Replayed => (
            PolicyDenyReason::Replayed,
            ProtocolError::new(
                ErrorCode::Replayed,
                "this request was already processed in this session",
                RecommendedAction::Abort,
            ),
        ),
        ClaimRejection::ChallengeReused => (
            PolicyDenyReason::ChallengeReused,
            ProtocolError::new(
                ErrorCode::Replayed,
                "this challenge was already used by a different request",
                RecommendedAction::Abort,
            ),
        ),
        ClaimRejection::BudgetExhausted => (
            PolicyDenyReason::BudgetExhausted,
            ProtocolError::new(
                ErrorCode::BudgetExhausted,
                "session operation budget exhausted",
                RecommendedAction::Abort,
            ),
        ),
    }
}

/// The error of a duplicate that did not get the original's outcome.
pub(crate) fn join_failure(result: JoinResult) -> ProtocolError {
    match result {
        JoinResult::Detached => ProtocolError::new(
            ErrorCode::Aborted,
            "request aborted while waiting for an identical request",
            RecommendedAction::Abort,
        ),
        _ => ProtocolError::new(
            ErrorCode::Timeout,
            "ceremony deadline passed while waiting for an identical request",
            RecommendedAction::Abort,
        ),
    }
}

/// The browser cancelled the request before key use (ADR 0014 section 11: `onRequestCanceled`).
pub(crate) fn aborted_error() -> (PolicyDenyReason, ProtocolError) {
    (
        PolicyDenyReason::Aborted,
        ProtocolError::new(
            ErrorCode::Aborted,
            "the request was cancelled before key use",
            RecommendedAction::Abort,
        ),
    )
}

/// What a ceremony's audit records carry about its request (ADR 0014 section 12): the RP ID and
/// the origin context. On the proxy path the browser never supplies a top origin, so it is
/// recorded as null.
#[derive(Clone, Copy)]
pub(crate) struct AuditTarget<'a> {
    pub rp_id: &'a str,
    pub origin: Option<&'a str>,
    pub top_origin: Option<&'a str>,
    pub cross_origin: Option<bool>,
}

impl<'a> AuditTarget<'a> {
    pub fn of_request(
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
        }
    }

    /// A record about an RP only (a refused request whose origin is not known).
    pub fn rp_only(rp_id: &'a str) -> Self {
        Self {
            rp_id,
            origin: None,
            top_origin: None,
            cross_origin: None,
        }
    }
}

/// The audit reason and error of a refused escalation (nothing was prompted).
pub(crate) fn escalation_refusal_error(
    refusal: EscalationRefusal,
) -> (PolicyDenyReason, ProtocolError) {
    let reason = refusal.deny_reason();
    let error = match refusal {
        EscalationRefusal::AuditFailure => ProtocolError::new(
            ErrorCode::Internal,
            "the escalation request could not be audited",
            RecommendedAction::Retry,
        ),
        EscalationRefusal::Unavailable => ProtocolError::new(
            ErrorCode::Forbidden,
            "escalation is unavailable: policy requires approval and no prompt can be shown",
            RecommendedAction::FixRequest,
        ),
        _ => ProtocolError::new(
            ErrorCode::Forbidden,
            format!(
                "escalation refused: {}",
                serde_json::to_value(reason)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_string))
                    .unwrap_or_default()
            ),
            RecommendedAction::Abort,
        ),
    };
    (reason, error)
}

/// One ceremony's escalation (ADR 0014 section 8.1): what it is for and where it waits.
pub(crate) struct Escalation<'a> {
    pub service: &'a Arc<EscalationService>,
    pub policy_runtime: &'a PolicyRuntime,
    pub session: &'a Arc<AgentSession>,
    pub profile_id: &'a ProfileId,
    pub action: CeremonyAction,
    /// The normalized RP ID.
    pub rp_id: &'a str,
    pub origin: &'a str,
    /// The configured rule that resolved to `request`.
    pub rule: &'a RuleIdentity,
}

/// An escalation request that passed the pre-checks (cooldown, grant cap and store, bus, queue,
/// waiter caps, a pending registration), before the replay key is taken.
pub(crate) struct PreparedEscalation {
    request: EscalationRequest,
    /// `agents.escalation_timeout`, when set.
    timeout: Option<Duration>,
}

impl Escalation<'_> {
    /// Build the request from the live policy and run the coordinator's pre-checks. A refusal
    /// is returned before the replay key is consumed and before anything is prompted (plan P7
    /// section 2).
    pub fn prepare(&self) -> Result<PreparedEscalation, (PolicyDenyReason, ProtocolError)> {
        let profile = self
            .policy_runtime
            .escalation_profile(self.profile_id)
            .ok_or_else(|| {
                (
                    PolicyDenyReason::PolicyRevoked,
                    ProtocolError::new(
                        ErrorCode::Forbidden,
                        "the profile no longer exists",
                        RecommendedAction::Abort,
                    ),
                )
            })?;
        let rule = match self.rule {
            RuleIdentity::Exact(_) => PermittingRule::Exact,
            RuleIdentity::Wildcard => PermittingRule::Wildcard,
            RuleIdentity::None => {
                return Err((
                    PolicyDenyReason::ActionNotAllowed,
                    ProtocolError::new(
                        ErrorCode::Forbidden,
                        "no rule permits an escalation",
                        RecommendedAction::FixRequest,
                    ),
                ));
            }
        };
        let request = EscalationRequest {
            profile: self.profile_id.clone(),
            rp_id: self.rp_id.to_string(),
            action: self.action,
            origin: self.origin.to_string(),
            rule,
            session: WaiterSession::of(self.session),
            mode: profile.mode,
            principal_user: profile.principal_user.clone(),
            max_granted_rules: profile.max_granted_rules,
        };
        self.service
            .precheck(&request)
            .map_err(escalation_refusal_error)?;
        Ok(PreparedEscalation {
            request,
            timeout: profile.escalation_timeout,
        })
    }

    /// Create or join the escalation and park until it ends (a fresh replay key only; a
    /// duplicate joins the in-flight slot instead, so it never adds a second waiter). Returns
    /// the approval ([`EscalationOutcome::Approved`] or
    /// [`EscalationOutcome::RegistrationApproved`]), or the audit reason and error that end the
    /// ceremony. No lock is held while parked (LOCKING.md rule 3); `park` suspends the
    /// ceremony's capacity permit for the wait.
    ///
    /// The wait ends at the earliest of `deadline` (the transport's Chromium-clamped ceremony
    /// deadline), `agents.escalation_timeout` and the session's expiry. An abort within
    /// [`super::escalation::DEADLINE_ABORT_GRACE`] of that point counts as a timeout (plan P7
    /// gap 8).
    pub fn wait(
        &self,
        prepared: PreparedEscalation,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
        park: &mut dyn ParkHook,
    ) -> Result<EscalationOutcome, (PolicyDenyReason, ProtocolError)> {
        let PreparedEscalation { request, timeout } = prepared;
        let waiter = self
            .service
            .join_or_create(request)
            .map_err(escalation_refusal_error)?;

        let now = Instant::now();
        let mut wait_deadline = deadline.min(self.session.expires_at());
        if let Some(timeout) = timeout {
            wait_deadline = wait_deadline.min(now + timeout);
        }
        let still_valid = || {
            self.session
                .validity(self.policy_runtime.revocation_epoch(), Instant::now())
                .is_ok()
        };
        let escalation_id = waiter.escalation_id().clone();
        let outcome = waiter.wait(wait_deadline, cancelled, &still_valid, park);
        debug!("escalation {}: wait ended: {:?}", escalation_id, outcome);
        match outcome {
            EscalationOutcome::Approved { .. } | EscalationOutcome::RegistrationApproved(_) => {
                Ok(outcome)
            }
            EscalationOutcome::Denied { reason, .. } => Err((
                reason.unwrap_or(PolicyDenyReason::EscalationDenied),
                ProtocolError::new(
                    ErrorCode::Forbidden,
                    "the escalation was denied",
                    RecommendedAction::Abort,
                ),
            )),
            EscalationOutcome::ServerLost { .. } => Err((
                PolicyDenyReason::EscalationExpired,
                ProtocolError::new(
                    ErrorCode::Forbidden,
                    "the notification server went away before a decision",
                    RecommendedAction::Retry,
                ),
            )),
            EscalationOutcome::TimedOut => Err((
                PolicyDenyReason::EscalationExpired,
                ProtocolError::new(
                    ErrorCode::Timeout,
                    "no escalation decision before the ceremony deadline",
                    RecommendedAction::Abort,
                ),
            )),
            EscalationOutcome::Revoked { .. } => Err((
                PolicyDenyReason::PolicyRevoked,
                ProtocolError::new(
                    ErrorCode::Forbidden,
                    "a policy reload cancelled the escalation",
                    RecommendedAction::Abort,
                ),
            )),
            EscalationOutcome::Aborted => Err(aborted_error()),
            EscalationOutcome::SessionInvalid => Err(session_invalid_error(
                self.session
                    .validity(self.policy_runtime.revocation_epoch(), Instant::now())
                    .err()
                    .unwrap_or(SessionInvalid::Revoked),
            )),
        }
    }
}

/// Decode the request challenge; a malformed one is rejected before the replay key (no budget).
pub(crate) fn decode_challenge(challenge_b64u: &str) -> Result<Vec<u8>, ProtocolError> {
    match b64u_decode(challenge_b64u) {
        Ok(challenge) if !challenge.is_empty() => Ok(challenge),
        _ => Err(ProtocolError::new(
            ErrorCode::BadRequest,
            "invalid challenge_b64u encoding",
            RecommendedAction::FixRequest,
        )),
    }
}

impl SignHandler {
    fn record_policy_deny(
        &self,
        ctx: &SignContext,
        target: &AuditTarget,
        reason: PolicyDenyReason,
    ) {
        let deny_event = PolicyDenyBuilder::new(
            ctx.profile_id.clone(),
            AuditAction::Authenticate,
            target.rp_id,
            reason,
        )
        .origin_context(target.origin, target.top_origin, target.cross_origin)
        .build();
        let _ = self.audit_gate.record(deny_event);
    }

    fn deny(
        &self,
        ctx: &SignContext,
        target: &AuditTarget,
        (reason, error): (PolicyDenyReason, ProtocolError),
    ) -> ProtocolError {
        self.record_policy_deny(ctx, target, reason);
        error
    }

    /// Authenticate with the default ceremony deadline and no cancellation (tests and direct use).
    pub fn sign(
        &self,
        ctx: &SignContext,
        req: &SignAssertionRequest,
    ) -> Result<PrincipalResponse, ProtocolError> {
        let deadline = ceremony_deadline(req.timeout_ms, Instant::now());
        self.sign_with(ctx, req, deadline, &|| false)
    }

    /// The bearer session is usable and bound to this context's profile.
    fn check_session(&self, ctx: &SignContext, target: &AuditTarget) -> Result<(), ProtocolError> {
        if ctx.session.profile_id() != &ctx.profile_id {
            return Err(self.deny(
                ctx,
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
            .map_err(|invalid| self.deny(ctx, target, session_invalid_error(invalid)))
    }

    /// The session grant is active, was issued to this session's principal, and covers `rp_id`.
    fn check_grant(
        &self,
        ctx: &SignContext,
        target: &AuditTarget,
    ) -> Result<super::policy_engine::GrantSignSnapshot, ProtocolError> {
        let rp_id = target.rp_id;
        let grant = self
            .policy_runtime
            .resolve_grant_for_sign(&ctx.profile_id, &ctx.active_grant_id)
            .ok_or_else(|| {
                self.deny(
                    ctx,
                    target,
                    (
                        PolicyDenyReason::GrantNotFound,
                        ProtocolError::new(
                            ErrorCode::Forbidden,
                            "active grant not valid",
                            RecommendedAction::FixRequest,
                        ),
                    ),
                )
            })?;
        if grant.is_revoked {
            return Err(self.deny(
                ctx,
                target,
                (
                    PolicyDenyReason::GrantRevoked,
                    ProtocolError::new(
                        ErrorCode::Forbidden,
                        "grant revoked",
                        RecommendedAction::FixRequest,
                    ),
                ),
            ));
        }
        if grant.state != super::grant::GrantState::Active {
            return Err(self.deny(
                ctx,
                target,
                (
                    PolicyDenyReason::GrantExpired,
                    ProtocolError::new(
                        ErrorCode::Forbidden,
                        "grant expired",
                        RecommendedAction::FixRequest,
                    ),
                ),
            ));
        }
        // The session is bound to the principal it was created for (ADR 0014 sections 7 and 9).
        if grant.profile_id != ctx.profile_id
            || !constant_time_eq(&grant.principal_digest, ctx.session.principal_digest())
        {
            return Err(self.deny(
                ctx,
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
        if !grant.rp_ids.iter().any(|id| {
            let scope_rp = normalize_rp_id(id);
            scope_rp == rp_id || (scope_rp == ANY_RP_ID && rp_id != LOCALHOST_RP_ID)
        }) {
            return Err(self.deny(
                ctx,
                target,
                (
                    PolicyDenyReason::RpIdNotMatch,
                    ProtocolError::new(
                        ErrorCode::Forbidden,
                        "RP ID not in active grant",
                        RecommendedAction::FixRequest,
                    ),
                ),
            ));
        }
        Ok(grant)
    }

    /// Authenticate. The checks run in the order of ADR 0014 section 9 and plan R4; each step
    /// that rejects returns before any later step, so a rejected request never reaches the replay
    /// table, the budget, the audit reservation or the key:
    ///
    /// 1. bearer session: not revoked, revocation epoch unchanged, TTL not passed, same profile;
    /// 2. origin and RP validation;
    /// 3. session grant: active, bound to the session's principal digest, RP in scope;
    /// 4. resolve the rule against the live policy and granted rules (`deny`, `request`, `allow`);
    /// 5. options the authenticator cannot honor (`NotSupportedError`) and a malformed challenge;
    /// 6. replay key, then budget ([`AgentSession::claim`]); for `request`, the escalation
    ///    pre-checks (cooldown, grant cap, bus, queue, waiter caps), then the replay key only
    ///    ([`AgentSession::claim_key`]), then the escalation wait with no lock held, and after
    ///    approval a re-resolve to a granted `allow` and the budget ([`Self::sign_escalated`]);
    /// 7. backend operation lock and credential selection ([`Self::sign_fresh`]);
    /// 8. durable audit reservation;
    /// 9. immediately before key use: revocation epoch, live re-resolve, session and grant validity;
    /// 10. key use: counter update, then the signature.
    pub fn sign_with(
        &self,
        ctx: &SignContext,
        req: &SignAssertionRequest,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<PrincipalResponse, ProtocolError> {
        self.sign_parked(ctx, req, deadline, cancelled, &mut NoPark)
    }

    /// [`Self::sign_with`] for a transport-carried ceremony: `park` suspends the request's
    /// capacity permit while the ceremony waits on an escalation.
    pub fn sign_parked(
        &self,
        ctx: &SignContext,
        req: &SignAssertionRequest,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
        park: &mut dyn ParkHook,
    ) -> Result<PrincipalResponse, ProtocolError> {
        let normalized_rp = normalize_rp_id(&req.rp_id);
        let target = AuditTarget::of_request(
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
                ctx,
                target,
                (
                    reason,
                    ProtocolError::new(code, message, RecommendedAction::FixRequest),
                ),
            ));
        }

        // 3. Session grant and principal binding.
        let grant = self.check_grant(ctx, target)?;

        // 4. Resolve against the live policy and granted rules on every request, never against a
        //    copy of the profile configuration frozen into the session (plan R16).
        let matched = self.policy_runtime.resolve(
            &ctx.profile_id,
            &IntentAction::Authenticate,
            &normalized_rp,
        );
        match matched.action {
            RuleAction::Deny => {
                return Err(self.deny(
                    ctx,
                    target,
                    (
                        PolicyDenyReason::ActionNotAllowed,
                        ProtocolError::new(
                            ErrorCode::Forbidden,
                            if matched.rule == RuleIdentity::None {
                                "RP policy does not allow signing"
                            } else {
                                "RP policy denies signing"
                            },
                            RecommendedAction::FixRequest,
                        ),
                    ),
                ));
            }
            // `request` (ADR 0014 section 8.1): steps 5 and 6 run unchanged; the replay key is
            // taken without budget, then the ceremony escalates (`Self::sign_escalated`).
            RuleAction::Request => {}
            RuleAction::Allow => {}
        }

        // 5. Unsupported options fail with `NotSupportedError` before any budget is claimed.
        if !extensions_supported(&req.extensions, SUPPORTED_GET_EXTENSIONS)? {
            return Err(self.deny(
                ctx,
                target,
                (
                    PolicyDenyReason::UnsupportedOption,
                    ProtocolError::new(
                        ErrorCode::NotSupported,
                        "a requested extension is not supported",
                        RecommendedAction::FixRequest,
                    ),
                ),
            ));
        }
        let challenge = decode_challenge(&req.challenge_b64u)?;

        // The browser already cancelled the request: stop before the replay key is consumed.
        if cancelled() {
            return Err(self.deny(ctx, target, aborted_error()));
        }

        // 6. Replay key, then budget (R1, R4). The budget limit is the live `max_operations`. A
        //    `request` resolution runs the escalation pre-checks first (a refusal consumes
        //    nothing), then takes the replay key only: its budget is claimed after approval
        //    (V-H2), and a duplicate joins the in-flight slot instead of prompting again.
        let key = ReplayKey::derive(
            CeremonyAction::Authenticate,
            &normalized_rp,
            &req.origin,
            req.top_origin.as_deref(),
            &challenge,
        );
        let escalation = Escalation {
            service: &self.escalation,
            policy_runtime: &self.policy_runtime,
            session: &ctx.session,
            profile_id: &ctx.profile_id,
            action: CeremonyAction::Authenticate,
            rp_id: target.rp_id,
            origin: &req.origin,
            rule: &matched.rule,
        };
        let prepared = if matched.action == RuleAction::Request {
            Some(
                escalation
                    .prepare()
                    .map_err(|refused| self.deny(ctx, target, refused))?,
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
                    self.sign_escalated(
                        ctx,
                        req,
                        target,
                        &grant,
                        (&escalation, prepared),
                        &mut guard,
                        deadline,
                        cancelled,
                        park,
                        &mut key_used,
                    )
                } else {
                    self.sign_fresh(ctx, req, target, &grant, &matched, cancelled, &mut key_used)
                };
                // The operation lock is released: activate the browser lease now (review H1).
                // The assertion is released only if activation succeeds.
                let outcome = outcome
                    .and_then(|response| self.activate_lease(ctx, target).map(|()| response));
                let ceremony = outcome
                    .clone()
                    .map(|response| CeremonyResult::Assertion(Box::new(response)));
                if key_used {
                    guard.complete(&ceremony);
                } else {
                    // Ended before key use: the key stays consumed, a claimed budget is given
                    // back (none was claimed for an escalation that did not end in approval).
                    guard.complete_without_key_use(&ceremony);
                }
                outcome
            }
            Claim::Join(in_flight, audit) => match in_flight.join(deadline, cancelled) {
                JoinResult::Completed(outcome) => {
                    self.serve_duplicate(ctx, target, audit)?;
                    assertion_outcome(outcome)
                }
                // The browser cancelled the duplicate while it waited: audited like any abort.
                JoinResult::Detached => Err(self.deny(ctx, target, aborted_error())),
                other => Err(join_failure(other)),
            },
            Claim::Completed(outcome, audit) => {
                self.serve_duplicate(ctx, target, audit)?;
                assertion_outcome(outcome)
            }
            Claim::Rejected(rejection) => {
                Err(self.deny(ctx, target, claim_rejection_error(rejection)))
            }
        }
    }

    /// The escalated path of a fresh replay key (ADR 0014 section 8.1): create or join the
    /// escalation and wait for it holding no lock; on approval re-resolve (the result must be a
    /// granted `allow`), claim the budget, and continue as [`Self::sign_fresh`], whose pre-key-use
    /// re-check is unchanged. A deny, expiry or abort ends the ceremony with no budget claimed.
    #[allow(clippy::too_many_arguments)]
    fn sign_escalated(
        &self,
        ctx: &SignContext,
        req: &SignAssertionRequest,
        target: &AuditTarget,
        grant: &super::policy_engine::GrantSignSnapshot,
        (escalation, prepared): (&Escalation<'_>, PreparedEscalation),
        guard: &mut ClaimGuard,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
        park: &mut dyn ParkHook,
        key_used: &mut bool,
    ) -> Result<PrincipalResponse, ProtocolError> {
        match escalation.wait(prepared, deadline, cancelled, park) {
            Ok(EscalationOutcome::Approved { .. }) => {}
            Ok(_) => {
                return Err(ProtocolError::new(
                    ErrorCode::Internal,
                    "an authentication escalation ended with a registration approval",
                    RecommendedAction::Abort,
                ));
            }
            Err(denied) => return Err(self.deny(ctx, target, denied)),
        }

        // The approval persisted a grant: the live resolution must now be a granted `allow`.
        let approved =
            self.policy_runtime
                .resolve(&ctx.profile_id, &IntentAction::Authenticate, target.rp_id);
        if approved.action != RuleAction::Allow || !approved.granted {
            return Err(self.deny(
                ctx,
                target,
                (
                    PolicyDenyReason::PolicyRevoked,
                    ProtocolError::new(
                        ErrorCode::Forbidden,
                        "policy no longer permits this operation after approval",
                        RecommendedAction::Abort,
                    ),
                ),
            ));
        }
        let max_operations = self
            .policy_runtime
            .max_operations(&ctx.profile_id)
            .unwrap_or(0);
        guard
            .claim_budget(u32::from(max_operations))
            .map_err(|rejection| self.deny(ctx, target, claim_rejection_error(rejection)))?;
        self.sign_fresh(ctx, req, target, grant, &approved, cancelled, key_used)
    }

    /// Before a duplicate gets the stored outcome, its session must still be valid (review L3):
    /// a revoked or re-epoched session is not served. Served duplicates are audited, at most
    /// `MAX_AUDITED_SERVES_PER_KEY` per key.
    fn serve_duplicate(
        &self,
        ctx: &SignContext,
        target: &AuditTarget,
        audit: bool,
    ) -> Result<(), ProtocolError> {
        ctx.session
            .validity(self.policy_runtime.revocation_epoch(), Instant::now())
            .map_err(|invalid| self.deny(ctx, target, session_invalid_error(invalid)))?;
        if audit {
            self.record_policy_deny(ctx, target, PolicyDenyReason::ReplayServed);
        }
        Ok(())
    }

    /// Activate the browser lease after key use, with no backend lock held (review H1).
    fn activate_lease(&self, ctx: &SignContext, target: &AuditTarget) -> Result<(), ProtocolError> {
        let Some(activation) = &ctx.lease_activation else {
            return Ok(());
        };
        activation.activate().map_err(|e| {
            warn!("agent sign: {}", e);
            self.deny(
                ctx,
                target,
                (
                    PolicyDenyReason::LeaseActivationFailed,
                    ProtocolError::new(
                        ErrorCode::Internal,
                        "browser lease activation failed",
                        RecommendedAction::Retry,
                    ),
                ),
            )
        })
    }

    /// Steps 7-10 for a fresh replay key. The backend operation lock is held only here: never
    /// across a join, an escalation wait, the browser manager or a policy guard (LOCKING.md).
    /// `key_used` is set right before the key provider signs.
    #[allow(clippy::too_many_arguments)]
    fn sign_fresh(
        &self,
        ctx: &SignContext,
        req: &SignAssertionRequest,
        target: &AuditTarget,
        grant: &super::policy_engine::GrantSignSnapshot,
        matched: &passless_core::agent::MatchedRule,
        cancelled: &dyn Fn() -> bool,
        key_used: &mut bool,
    ) -> Result<PrincipalResponse, ProtocolError> {
        let normalized_rp = target.rp_id;
        // `allow` is the only agent evidence: UP and UV come from the validated agent session,
        // never from a rule field or the RP's `userVerification` request (ADR 0014 section 7).
        let up = true;
        let uv = true;

        // 7. Backend operation lock, then storage, for selection, reservation and key use.
        let _op_lock = lock_order::lock(&self.operation_lock, LockLevel::Operation);
        let mut storage = lock_order::lock(&self.credential_storage, LockLevel::Storage);

        let credential_scope = if grant.credential_refs.is_empty() {
            let mut discovered = Vec::new();
            if let Ok(mut credential) = storage.read_first(crate::storage::CredentialFilter::None) {
                loop {
                    if credential.rp.id.eq_ignore_ascii_case(normalized_rp) {
                        discovered.push(CredentialRef::with_default_domain(&credential.id));
                    }
                    match storage.read_next() {
                        Ok(next) => credential = next,
                        Err(_) => break,
                    }
                }
            }
            discovered
        } else {
            // Configured pins (a frozen session snapshot) plus the credentials registration
            // grants pinned for this RP (live; ADR 0014 section 8.3). With no configured pins,
            // discovery above already finds a registered credential.
            let mut pinned = grant.credential_refs.clone();
            for granted in self
                .policy_runtime
                .granted_credential_refs(&ctx.profile_id, normalized_rp)
            {
                if !pinned.contains(&granted) {
                    pinned.push(granted);
                }
            }
            pinned
        };

        let mut candidates = Vec::new();
        for credential_ref in &credential_scope {
            if let Ok(credential_id) =
                Self::resolve_credential_id(&mut storage, credential_ref, normalized_rp)
                && let Ok(credential) = storage.read(&credential_id)
            {
                candidates.push((credential_id, credential_ref.clone(), credential.created));
            }
        }

        // ADR 0014 section 10.1: pinning (`credential_refs`, then `credential:<ref>`) narrows the
        // candidate set first, and a non-empty `allowCredentials` chooses within that pinned set.
        let candidates =
            Self::narrow_candidates(candidates, &req.allow_credentials, &matched.selection);
        if candidates.is_empty() && !req.allow_credentials.is_empty() {
            self.record_policy_deny(ctx, target, PolicyDenyReason::AllowCredentialsMismatch);
            return Err(ProtocolError::new(
                ErrorCode::Forbidden,
                "allowCredentials does not contain a permitted credential",
                RecommendedAction::FixRequest,
            ));
        }

        let cred_id =
            Self::select_credential(candidates, &matched.selection).inspect_err(|_| {
                self.record_policy_deny(ctx, target, PolicyDenyReason::CredentialNotMatch);
            })?;

        // 8. Durable audit reservation before key use (invariant 16).
        let allow_event = PolicyAllowBuilder::new(
            ctx.profile_id.clone(),
            AuditAction::Authenticate,
            normalized_rp,
        )
        .evidence_sources("allow", "agent", "agent")
        .origin_context(target.origin, target.top_origin, target.cross_origin)
        .build();
        self.audit_gate.record(allow_event).map_err(|_| {
            ProtocolError::new(
                ErrorCode::Internal,
                "audit record failed",
                RecommendedAction::Retry,
            )
        })?;

        let cred = storage.read(&cred_id).map_err(|_| {
            ProtocolError::new(
                ErrorCode::NotFound,
                "credential not found in storage",
                RecommendedAction::FixRequest,
            )
        })?;
        if cred.extensions.cred_protect == Some(3) && !uv {
            self.record_policy_deny(ctx, target, PolicyDenyReason::UvRequired);
            return Err(ProtocolError::new(
                ErrorCode::Forbidden,
                "credential protection policy requires user verification",
                RecommendedAction::FixRequest,
            ));
        }

        // 9. Immediately before key use (invariant 13): the revocation epoch, the rule re-resolved
        //    against the live policy and grants, and the session and its grant. A failure here
        //    is the terminal record of the reservation above. The key-use gates are held from
        //    here to the end of key use, so a revocation (session revoke or epoch bump) either
        //    happens before this check or waits for the signature (review M1).
        #[cfg(test)]
        super::session::test_hooks::before_key_use();
        let _session_gate = ctx.session.key_use_guard();
        let _epoch_gate = self.policy_runtime.key_use_guard();
        self.recheck_before_key_use(ctx, target, cancelled)?;

        // 10. Key use: persist the counter, release storage, then sign. The browser lease is
        //     activated by the caller after the operation lock is released (review H1).
        let new_sign_count =
            if self.security_config.constant_signature_counter || !cred.discoverable {
                0
            } else {
                cred.sign_count.saturating_add(1)
            };

        let write_back = !self.security_config.constant_signature_counter && cred.discoverable;
        if write_back {
            let mut updated_cred = cred.clone();
            updated_cred.sign_count = new_sign_count;
            let cred_ref = soft_fido2::CredentialRef {
                id: &updated_cred.id,
                rp_id: &updated_cred.rp.id,
                rp_name: updated_cred.rp.name.as_deref(),
                user_id: &updated_cred.user.id,
                user_name: updated_cred.user.name.as_deref(),
                user_display_name: updated_cred.user.display_name.as_deref(),
                sign_count: &updated_cred.sign_count,
                alg: &updated_cred.alg,
                key: &updated_cred.key,
                created: &updated_cred.created,
                discoverable: &updated_cred.discoverable,
                cred_protect: updated_cred.extensions.cred_protect.as_ref(),
                backup_state: &updated_cred.backup_state,
                cred_random: updated_cred.extensions.cred_random.as_ref(),
            };
            storage.write(cred_ref).map_err(|_| {
                self.record_policy_deny(ctx, target, PolicyDenyReason::CounterPersistenceFailure);
                ProtocolError::new(
                    ErrorCode::Internal,
                    "failed to write updated credential",
                    RecommendedAction::Retry,
                )
            })?;
        }
        drop(storage);

        let backup_flags = cred.backup_state.flags();

        let authenticator_data =
            build_authenticator_data(normalized_rp, up, uv, backup_flags, new_sign_count);

        let client_data_json = build_client_data_json(
            &req.origin,
            &req.challenge_b64u,
            req.cross_origin,
            req.top_origin.as_deref(),
        );
        let client_data_hash = Sha256::digest(&client_data_json);

        let sig_input = [&authenticator_data[..], &client_data_hash[..]].concat();
        *key_used = true;
        let signature = self
            .key_provider
            .sign(&cred.key, cred.alg, &sig_input)
            .map_err(|_| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    "signing failed",
                    RecommendedAction::Retry,
                )
            })?;

        Ok(PrincipalResponse::SignAssertionResult(
            SignAssertionResponse {
                credential_id_b64u: b64u_encode(&cred.id),
                authenticator_data_b64u: b64u_encode(&authenticator_data),
                signature_b64u: b64u_encode(&signature),
                user_handle_b64u: b64u_encode(&cred.user.id),
                client_data_json_b64u: b64u_encode(&client_data_json),
            },
        ))
    }

    /// Invariant 13: re-check the revocation epoch and the session, re-resolve the rule against
    /// the live policy and grants, and re-check the grant, immediately before key use. A request
    /// the browser cancelled meanwhile stops here too; this is the terminal record of its
    /// reservation.
    fn recheck_before_key_use(
        &self,
        ctx: &SignContext,
        target: &AuditTarget,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), ProtocolError> {
        let rp_id = target.rp_id;
        if cancelled() {
            return Err(self.deny(ctx, target, aborted_error()));
        }
        ctx.session
            .validity(self.policy_runtime.revocation_epoch(), Instant::now())
            .map_err(|invalid| self.deny(ctx, target, session_invalid_error(invalid)))?;
        let matched =
            self.policy_runtime
                .resolve(&ctx.profile_id, &IntentAction::Authenticate, rp_id);
        if matched.action != RuleAction::Allow {
            return Err(self.deny(
                ctx,
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
        let grant_active = self
            .policy_runtime
            .resolve_grant_for_sign(&ctx.profile_id, &ctx.active_grant_id)
            .is_some_and(|grant| grant.state == super::grant::GrantState::Active);
        if !grant_active {
            return Err(self.deny(
                ctx,
                target,
                (
                    PolicyDenyReason::GrantRevoked,
                    ProtocolError::new(
                        ErrorCode::Forbidden,
                        "grant is no longer active",
                        RecommendedAction::Abort,
                    ),
                ),
            ));
        }
        Ok(())
    }

    /// Narrow the candidate set (ADR 0014 section 10.1): a `credential:<ref>` selection pins
    /// first, then a non-empty `allowCredentials` keeps only the listed credentials. The pin is
    /// applied before `allowCredentials`, so an `allowCredentials` entry never overrides it.
    fn narrow_candidates(
        mut candidates: Vec<(Vec<u8>, CredentialRef, i64)>,
        allow_credentials: &[String],
        selection: &CredentialSelection,
    ) -> Vec<(Vec<u8>, CredentialRef, i64)> {
        if let CredentialSelection::Credential(pinned) = selection {
            candidates.retain(|(_, candidate_ref, _)| candidate_ref == pinned);
        }
        if !allow_credentials.is_empty() {
            candidates.retain(|(id, _, _)| allow_credentials.contains(&b64u_encode(id)));
        }
        candidates
    }

    fn select_credential(
        mut candidates: Vec<(Vec<u8>, CredentialRef, i64)>,
        selection: &CredentialSelection,
    ) -> Result<Vec<u8>, ProtocolError> {
        if candidates.is_empty() {
            return Err(ProtocolError::new(
                ErrorCode::NotFound,
                "no permitted credential matches this WebAuthn request",
                RecommendedAction::FixRequest,
            ));
        }

        // Exactly one permitted credential remains: use it.
        if candidates.len() == 1 {
            return Ok(candidates.remove(0).0);
        }

        match selection {
            CredentialSelection::Credential(_) | CredentialSelection::Single => {
                Err(ProtocolError::new(
                    ErrorCode::Conflict,
                    "multiple discoverable credentials match; configure credential_selection",
                    RecommendedAction::FixRequest,
                ))
            }
            CredentialSelection::FirstMatching => {
                candidates.sort_by(|a, b| a.0.cmp(&b.0));
                Ok(candidates.remove(0).0)
            }
            CredentialSelection::Newest => {
                candidates.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
                Ok(candidates.remove(0).0)
            }
        }
    }

    fn resolve_credential_id(
        storage: &mut Box<dyn CredentialStorage>,
        cred_ref: &CredentialRef,
        rp_id: &str,
    ) -> Result<Vec<u8>, ProtocolError> {
        let cred = storage
            .read_first(crate::storage::CredentialFilter::ByRp(rp_id.to_string()))
            .map_err(|_| {
                ProtocolError::new(
                    ErrorCode::NotFound,
                    "no credentials for RP in storage",
                    RecommendedAction::FixRequest,
                )
            })?;
        let href = CredentialRef::with_default_domain(&cred.id);
        if href == *cred_ref {
            return Ok(cred.id.clone());
        }
        while let Ok(cred) = storage.read_next() {
            let href = CredentialRef::with_default_domain(&cred.id);
            if href == *cred_ref {
                return Ok(cred.id.clone());
            }
        }
        Err(ProtocolError::new(
            ErrorCode::NotFound,
            "credential ref not found in storage",
            RecommendedAction::FixRequest,
        ))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::thread;

    use passless_core::agent::protocol::RegisterCredentialRequest;

    /// A bearer session for `profile_id`, bound like a session issued with an all-zero principal
    /// digest at revocation epoch 1 (a fresh `PolicyRuntime`).
    fn test_session(profile_id: &ProfileId) -> Arc<AgentSession> {
        test_session_at(profile_id, 1)
    }

    /// A bearer session created at revocation epoch `epoch`.
    fn test_session_at(profile_id: &ProfileId, epoch: u64) -> Arc<AgentSession> {
        AgentSession::new(super::super::session::SessionBinding {
            profile_id: profile_id.clone(),
            principal_digest: [0u8; 32],
            revocation_epoch: epoch,
            ttl: Duration::from_secs(600),
        })
    }

    #[test]
    fn test_client_data_json_no_cross_origin() {
        let cdj = build_client_data_json("https://example.com", "dGVzdA", false, None);
        let expected =
            br#"{"type":"webauthn.get","challenge":"dGVzdA","origin":"https://example.com"}"#;
        assert_eq!(cdj, expected);
    }

    #[test]
    fn test_client_data_json_with_cross_origin() {
        let cdj = build_client_data_json(
            "https://example.com",
            "dGVzdA",
            true,
            Some("https://top.example"),
        );
        let expected = br#"{"type":"webauthn.get","challenge":"dGVzdA","origin":"https://example.com","crossOrigin":true,"topOrigin":"https://top.example"}"#;
        assert_eq!(cdj, expected);
    }

    #[test]
    fn test_client_data_json_cross_origin_false_omitted() {
        let cdj = build_client_data_json("https://example.com", "dGVzdA", false, None);
        let s = std::str::from_utf8(&cdj).unwrap();
        assert!(!s.contains("crossOrigin"));
    }

    #[test]
    fn test_client_data_json_escaping() {
        let cdj = build_client_data_json("https://ex\"ample.com", "dGVzdA", false, None);
        let s = std::str::from_utf8(&cdj).unwrap();
        assert!(s.contains("ex\\\"ample.com"));
    }

    #[test]
    fn test_authenticator_data_bytes() {
        let auth_data = build_authenticator_data("example.com", true, true, 0x08, 42);
        assert_eq!(auth_data.len(), 37);
        let mut hasher = Sha256::new();
        hasher.update(b"example.com");
        let expected_rp_hash = hasher.finalize();
        assert_eq!(&auth_data[0..32], expected_rp_hash.as_slice());
        assert_eq!(auth_data[32], 0x01 | 0x04 | 0x08);
        assert_eq!(&auth_data[33..37], &42u32.to_be_bytes());
    }

    #[test]
    fn test_authenticator_data_no_flags() {
        let auth_data = build_authenticator_data("example.com", false, false, 0, 0);
        assert_eq!(auth_data[32], 0x00);
        assert_eq!(&auth_data[33..37], &0u32.to_be_bytes());
    }

    #[test]
    fn test_authenticator_data_backup_flags() {
        let auth_data = build_authenticator_data("example.com", true, false, 0x08, 0);
        assert_eq!(auth_data[32], 0x01 | 0x08);
    }

    #[test]
    fn test_origin_verification_exact_match() {
        assert!(verify_origin_structural(
            "https://example.com",
            "example.com"
        ));
    }

    #[test]
    fn test_origin_verification_denied() {
        assert!(!verify_origin_structural("https://evil.com", "example.com"));
    }

    #[test]
    fn test_origin_verification_rejects_http() {
        // Plain `http://` is rejected for every host except exactly `localhost`.
        assert!(!verify_origin_structural(
            "http://example.com",
            "example.com"
        ));
        assert!(!verify_origin_structural(
            "http://login.example.com",
            "example.com"
        ));
    }

    #[test]
    fn test_origin_verification_accepts_port() {
        assert!(verify_origin_structural(
            "https://example.com:8443",
            "example.com"
        ));
    }

    #[test]
    fn test_origin_verification_accepts_rp_subdomain_origin() {
        assert!(verify_origin_structural(
            "https://login.example.com",
            "example.com"
        ));
    }

    #[test]
    fn test_cross_origin_always_fails_closed() {
        assert!(!verify_origin_context(
            "https://login.example.com",
            None,
            true,
            "example.com"
        ));
        assert!(!verify_origin_context(
            "https://login.example.com",
            Some("https://portal.example.net"),
            true,
            "example.com"
        ));
        assert!(verify_origin_context(
            "https://login.example.com",
            Some("https://login.example.com"),
            false,
            "example.com"
        ));
    }

    #[test]
    fn test_origin_verification_rejects_path() {
        assert!(!verify_origin_structural(
            "https://example.com/path",
            "example.com"
        ));
    }

    #[test]
    fn test_origin_verification_rejects_query() {
        assert!(!verify_origin_structural(
            "https://example.com?foo=bar",
            "example.com"
        ));
    }

    #[test]
    fn test_origin_verification_rejects_fragment() {
        assert!(!verify_origin_structural(
            "https://example.com#frag",
            "example.com"
        ));
    }

    #[test]
    fn test_origin_verification_rejects_credentials() {
        assert!(!verify_origin_structural(
            "https://user:pass@example.com",
            "example.com"
        ));
    }

    #[test]
    fn test_origin_verification_case_insensitive_host() {
        assert!(verify_origin_structural(
            "https://Example.COM",
            "example.com"
        ));
    }

    #[test]
    fn test_parse_origin_valid() {
        let parsed = parse_origin("https://example.com").unwrap();
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, None);
    }

    #[test]
    fn test_parse_origin_with_port() {
        let parsed = parse_origin("https://example.com:8443").unwrap();
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, Some(8443));
    }

    #[test]
    fn test_parse_origin_rejects_bad_ports_and_confusable_origins() {
        for origin in [
            "http://localhost:0",
            "https://example.com:0",
            "http://localhost:+80",
            "https://example.com:+443",
            "http://localhost:",
            "http://localhost:-1",
            "http://localhost:65536",
            "http://localhost:80a",
            "ws://localhost",
            "wss://localhost",
            "http://a@localhost",
            "http://localhost@evil.com",
            "http://localhost.",
            "http://localhost.evil.com",
            "http://foo.localhost",
            "http://LOCALHOST.",
        ] {
            assert!(parse_origin(origin).is_none(), "{origin} must be rejected");
        }
        assert_eq!(
            parse_origin("http://localhost:65535").unwrap().port,
            Some(65535)
        );
        assert_eq!(
            parse_origin("http://LOCALHOST:8080").unwrap().host,
            "localhost"
        );
        // A trailing-dot localhost never satisfies the exact `localhost` RP.
        assert!(!verify_origin_structural("https://localhost.", "localhost"));
        assert!(!verify_origin_structural("http://localhost:0", "localhost"));
    }

    #[test]
    fn test_parse_origin_invalid_scheme() {
        assert!(parse_origin("http://example.com").is_none());
        assert!(parse_origin("ftp://example.com").is_none());
        assert!(parse_origin("example.com").is_none());
    }

    #[test]
    fn test_parse_origin_accepts_http_localhost_only() {
        let plain = parse_origin("http://localhost").unwrap();
        assert_eq!(plain.scheme, OriginScheme::Http);
        assert_eq!(plain.host, "localhost");
        assert_eq!(plain.port, None);

        let with_port = parse_origin("http://localhost:8080").unwrap();
        assert_eq!(with_port.scheme, OriginScheme::Http);
        assert_eq!(with_port.port, Some(8080));

        let https = parse_origin("https://localhost").unwrap();
        assert_eq!(https.scheme, OriginScheme::Https);
        assert_eq!(parse_origin("http://LOCALHOST").unwrap().host, "localhost");

        // `http://` is never accepted for another host, including subdomains of localhost.
        for rejected in [
            "http://example.com",
            "http://foo.localhost",
            "http://localhost.evil.com",
            "http://127.0.0.1",
            "http://[::1]",
            "http://localhost@evil.com",
            "http://localhost/path",
            "http://localhost?x=1",
        ] {
            assert!(parse_origin(rejected).is_none(), "{rejected}");
        }
    }

    #[test]
    fn test_origin_verification_localhost_is_exact() {
        for accepted in [
            "http://localhost",
            "http://localhost:8080",
            "https://localhost",
            "https://localhost:8443",
        ] {
            assert!(
                verify_origin_structural(accepted, "localhost"),
                "{accepted}"
            );
        }
        for rejected in [
            "http://example.com",
            "http://foo.localhost",
            "http://localhost.evil.com",
            "https://foo.localhost",
            "https://localhost.evil.com",
            "http://127.0.0.1",
            "https://127.0.0.1",
        ] {
            assert!(
                !verify_origin_structural(rejected, "localhost"),
                "{rejected}"
            );
        }
    }

    #[test]
    fn test_http_localhost_origin_is_not_valid_for_other_rps() {
        assert!(!verify_origin_structural("http://localhost", "example.com"));
        assert!(!verify_origin_structural(
            "http://localhost:8080",
            "example.com"
        ));
        assert!(!verify_origin_structural(
            "https://example.com",
            "localhost"
        ));
    }

    #[test]
    fn test_verify_origin_context_rejects_scheme_mismatch_with_top_origin() {
        assert!(!verify_origin_context(
            "http://localhost",
            Some("https://localhost"),
            false,
            "localhost"
        ));
        assert!(!verify_origin_context(
            "https://localhost",
            Some("http://localhost"),
            false,
            "localhost"
        ));
        assert!(verify_origin_context(
            "http://localhost:8080",
            Some("http://localhost:8080"),
            false,
            "localhost"
        ));
        assert!(!verify_origin_context(
            "http://localhost:8080",
            Some("http://localhost:9090"),
            false,
            "localhost"
        ));
    }

    #[test]
    fn test_parse_origin_empty_host() {
        assert!(parse_origin("https://").is_none());
    }

    #[test]
    fn test_b64u_roundtrip() {
        let data = b"hello world";
        let encoded = b64u_encode(data);
        let decoded = b64u_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_b64u_no_padding() {
        assert!(!b64u_encode(b"a").contains('='));
        assert!(!b64u_encode(b"ab").contains('='));
        assert!(!b64u_encode(b"abc").contains('='));
    }

    #[test]
    fn test_b64u_empty() {
        assert_eq!(b64u_encode(b""), "");
        assert_eq!(b64u_decode("").unwrap(), b"");
    }

    #[test]
    fn test_constant_time_eq_equal() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn test_constant_time_eq_not_equal() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn test_constant_time_eq_different_length() {
        assert!(!constant_time_eq(b"hello", b"hell"));
    }

    #[test]
    fn test_constant_time_eq_43_vs_299_bytes() {
        let a = vec![0u8; 43];
        let b = vec![0u8; 299];
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn test_constant_time_eq_empty_nonempty() {
        assert!(!constant_time_eq(b"", b"x"));
        assert!(!constant_time_eq(b"x", b""));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn test_generate_bearer_token_entropy() {
        let token = generate_bearer_token().unwrap();
        let decoded = b64u_decode(&token).unwrap();
        assert_eq!(decoded.len(), 32);
        assert!(!token.contains('='));
        assert!(!token.contains('+'));
        assert!(!token.contains('/'));
    }

    #[test]
    fn test_generate_bearer_token_unique() {
        let t1 = generate_bearer_token().unwrap();
        let t2 = generate_bearer_token().unwrap();
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_generate_bearer_token_format() {
        let token = generate_bearer_token().unwrap();
        assert_eq!(token.len(), 43);
        for ch in token.chars() {
            assert!(
                ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
                "invalid char in token: {}",
                ch
            );
        }
    }

    #[test]
    fn test_registry_register_and_lookup_denies_unbound() {
        let registry = SignContextRegistry::new();
        let token = generate_bearer_token().unwrap();
        let f = sign_handler_tests::TestFixture::new(true);
        let handler = Arc::new(f.make_handler());
        let ctx = f.make_ctx();
        registry
            .register_pending(token.clone(), ctx, handler)
            .unwrap();
        assert!(registry.lookup_bound(&token).is_none());
    }

    #[test]
    fn test_registry_bind_and_lookup() {
        let registry = SignContextRegistry::new();
        let token = generate_bearer_token().unwrap();
        let f = sign_handler_tests::TestFixture::new(true);
        let handler = Arc::new(f.make_handler());
        let ctx = f.make_ctx();
        registry
            .register_pending(token.clone(), ctx, handler)
            .unwrap();
        registry.bind_lease(&token, "lease-1".to_string()).unwrap();
        assert!(registry.lookup_bound(&token).is_some());
    }

    #[test]
    fn test_registry_duplicate_token() {
        let registry = SignContextRegistry::new();
        let token = generate_bearer_token().unwrap();
        let f = sign_handler_tests::TestFixture::new(true);
        let handler = Arc::new(f.make_handler());
        let ctx = f.make_ctx();
        registry
            .register_pending(token.clone(), ctx.clone(), handler.clone())
            .unwrap();
        assert!(registry.register_pending(token, ctx, handler).is_err());
    }

    #[test]
    fn test_registry_duplicate_lease_binding() {
        let registry = SignContextRegistry::new();
        let token = generate_bearer_token().unwrap();
        let f = sign_handler_tests::TestFixture::new(true);
        let handler = Arc::new(f.make_handler());
        let ctx = f.make_ctx();
        registry
            .register_pending(token.clone(), ctx, handler)
            .unwrap();
        registry.bind_lease(&token, "lease-1".to_string()).unwrap();
        assert!(registry.bind_lease(&token, "lease-2".to_string()).is_err());
    }

    #[test]
    fn test_registry_two_token_isolation() {
        let registry = SignContextRegistry::new();
        let t1 = generate_bearer_token().unwrap();
        let t2 = generate_bearer_token().unwrap();
        let f = sign_handler_tests::TestFixture::new(true);
        let handler = Arc::new(f.make_handler());
        let ctx = f.make_ctx();
        registry
            .register_pending(t1.clone(), ctx.clone(), handler.clone())
            .unwrap();
        registry.register_pending(t2.clone(), ctx, handler).unwrap();
        registry.bind_lease(&t1, "lease-a".to_string()).unwrap();
        registry.bind_lease(&t2, "lease-b".to_string()).unwrap();
        let e1 = registry.lookup_bound(&t1).unwrap();
        let e2 = registry.lookup_bound(&t2).unwrap();
        assert_eq!(e1.lease_id.as_deref(), Some("lease-a"));
        assert_eq!(e2.lease_id.as_deref(), Some("lease-b"));
    }

    #[test]
    fn test_registry_unknown_token() {
        let registry = SignContextRegistry::new();
        assert!(registry.lookup_bound("nonexistent").is_none());
    }

    #[test]
    fn test_registry_revoke() {
        let registry = SignContextRegistry::new();
        let token = generate_bearer_token().unwrap();
        let f = sign_handler_tests::TestFixture::new(true);
        let handler = Arc::new(f.make_handler());
        let ctx = f.make_ctx();
        registry
            .register_pending(token.clone(), ctx, handler)
            .unwrap();
        registry.bind_lease(&token, "lease-1".to_string()).unwrap();
        assert!(registry.revoke(&token));
        assert!(registry.lookup_bound(&token).is_none());
        assert!(!registry.revoke(&token));
    }

    #[test]
    fn test_registry_revoke_by_lease() {
        let registry = SignContextRegistry::new();
        let t1 = generate_bearer_token().unwrap();
        let t2 = generate_bearer_token().unwrap();
        let t3 = generate_bearer_token().unwrap();
        let f = sign_handler_tests::TestFixture::new(true);
        let handler = Arc::new(f.make_handler());
        let ctx = f.make_ctx();
        registry
            .register_pending(t1.clone(), ctx.clone(), handler.clone())
            .unwrap();
        registry
            .register_pending(t2.clone(), ctx.clone(), handler.clone())
            .unwrap();
        registry.register_pending(t3.clone(), ctx, handler).unwrap();
        registry.bind_lease(&t1, "lease-x".to_string()).unwrap();
        registry.bind_lease(&t2, "lease-x".to_string()).unwrap();
        registry.bind_lease(&t3, "lease-y".to_string()).unwrap();
        assert_eq!(registry.revoke_by_lease("lease-x"), 2);
        assert_eq!(registry.len(), 1);
        assert!(registry.lookup_bound(&t3).is_some());
    }

    #[test]
    fn test_registry_revoke_all() {
        let registry = SignContextRegistry::new();
        let f = sign_handler_tests::TestFixture::new(true);
        let handler = Arc::new(f.make_handler());
        let ctx = f.make_ctx();
        for i in 0..3 {
            let token = generate_bearer_token().unwrap();
            registry
                .register_pending(token.clone(), ctx.clone(), handler.clone())
                .unwrap();
            registry.bind_lease(&token, format!("lease-{}", i)).unwrap();
        }
        assert_eq!(registry.len(), 3);
        registry.revoke_all();
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_registry_revoke_stale_sessions_keeps_current_ones() {
        let registry = SignContextRegistry::new();
        let f = sign_handler_tests::TestFixture::new(true);
        let handler = Arc::new(f.make_handler());
        let profile = ProfileId::new("test-profile").unwrap();
        let mut stale_ctx = f.make_ctx();
        stale_ctx.session = test_session_at(&profile, 1);
        let mut current_ctx = f.make_ctx();
        current_ctx.session = test_session_at(&profile, 2);
        let stale = generate_bearer_token().unwrap();
        let current = generate_bearer_token().unwrap();
        for (token, ctx) in [(&stale, &stale_ctx), (&current, &current_ctx)] {
            registry
                .register_pending(token.clone(), ctx.clone(), handler.clone())
                .unwrap();
            registry
                .bind_lease(token, format!("lease-{token}"))
                .unwrap();
        }
        assert_eq!(registry.revoke_stale_sessions(2), 1);
        assert!(registry.lookup_bound(&stale).is_none());
        assert!(stale_ctx.session.is_revoked());
        assert!(registry.lookup_bound(&current).is_some());
        assert!(!current_ctx.session.is_revoked());
    }

    #[test]
    fn test_registry_concurrent_lookup_revoke() {
        let registry = Arc::new(SignContextRegistry::new());
        let f = sign_handler_tests::TestFixture::new(true);
        let handler = Arc::new(f.make_handler());
        let ctx = f.make_ctx();
        let mut tokens = Vec::new();
        for i in 0..20 {
            let token = generate_bearer_token().unwrap();
            registry
                .register_pending(token.clone(), ctx.clone(), handler.clone())
                .unwrap();
            registry.bind_lease(&token, format!("lease-{}", i)).unwrap();
            tokens.push(token);
        }
        let mut handles = Vec::new();
        for token in tokens.clone() {
            let reg = registry.clone();
            handles.push(thread::spawn(move || {
                let _ = reg.lookup_bound(&token);
                let _ = reg.revoke(&token);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn test_agent_endpoint_metadata_contains_sign_socket_path_and_bearer() {
        use crate::agent::browser::AgentEndpointMetadata;
        let token = generate_bearer_token().unwrap();
        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: token.clone(),
        };
        assert_eq!(metadata.socket_path, "/tmp/test/sock");
        assert_eq!(metadata.bearer_token, token);
    }

    #[test]
    fn test_register_then_revoke_cleans_up_before_bind() {
        let registry = SignContextRegistry::new();
        let f = sign_handler_tests::TestFixture::new(true);
        let handler = Arc::new(f.make_handler());
        let ctx = f.make_ctx();
        let token = generate_bearer_token().unwrap();
        registry
            .register_pending(token.clone(), ctx, handler)
            .unwrap();
        assert!(registry.lookup_bound(&token).is_none());
        assert_eq!(registry.len(), 1);
        assert!(registry.revoke(&token));
        assert_eq!(registry.len(), 0);
        assert!(registry.lookup_bound(&token).is_none());
    }

    #[test]
    fn test_register_bind_then_revoke_cleans_up() {
        let registry = SignContextRegistry::new();
        let f = sign_handler_tests::TestFixture::new(true);
        let handler = Arc::new(f.make_handler());
        let ctx = f.make_ctx();
        let token = generate_bearer_token().unwrap();
        registry
            .register_pending(token.clone(), ctx, handler)
            .unwrap();
        registry
            .bind_lease(&token, "lease-rollback".to_string())
            .unwrap();
        assert!(registry.lookup_bound(&token).is_some());
        assert!(registry.revoke(&token));
        assert_eq!(registry.len(), 0);
        assert!(registry.lookup_bound(&token).is_none());
    }

    #[test]
    fn test_p256_sign_verify_through_provider() {
        let provider = soft_fido2::SoftwareCredentialKeyProvider;
        let generated = provider.generate(-7).unwrap();
        let message = b"test message for signing";
        let signature = provider.sign(&generated.key, -7, message).unwrap();
        assert!(!signature.is_empty());
    }

    pub(crate) mod sign_handler_tests {
        use super::*;
        use crate::agent::audit::AuditGate;
        use crate::agent::browser;
        use crate::agent::grant::GrantRequestParams;
        use crate::agent::identity;
        use crate::agent::policy_engine::PolicyRuntime;
        use crate::storage::{CredentialFilter, CredentialStorage};
        use passless_core::agent::{
            AgentConfig, AgentMode, AgentProfileConfig, AgentRpRule, BrowserScope,
            CredentialSelection, GrantSource,
        };
        use passless_core::config::SecurityConfig;
        use soft_fido2::{
            CredentialBackupState, CredentialKey, CredentialKeyError, CredentialKeyProviderId,
            GeneratedCredentialKey, RelyingParty, SoftwareCredentialKeyProvider, User,
        };
        use std::collections::BTreeMap;
        use std::sync::atomic::{AtomicU64, AtomicUsize};
        use std::time::Instant;

        pub struct MockClock {
            inner: Mutex<MockClockInner>,
        }
        struct MockClockInner {
            base: Instant,
            offset: Duration,
        }
        impl MockClock {
            pub fn new() -> Self {
                Self {
                    inner: Mutex::new(MockClockInner {
                        base: Instant::now(),
                        offset: Duration::ZERO,
                    }),
                }
            }
            pub fn advance(&self, d: Duration) {
                self.inner.lock().unwrap().offset += d;
            }
        }
        impl browser::Clock for MockClock {
            fn now(&self) -> Instant {
                let inner = self.inner.lock().unwrap();
                inner.base + inner.offset
            }
            fn monotonic_secs(&self) -> u64 {
                self.inner.lock().unwrap().offset.as_secs()
            }
        }

        pub struct RecordingKeyProvider {
            inner: SoftwareCredentialKeyProvider,
            sign_count: AtomicUsize,
            /// Runs inside `sign`, before the signature, on whatever thread signs.
            on_sign: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
        }
        impl RecordingKeyProvider {
            pub fn new() -> Self {
                Self {
                    inner: SoftwareCredentialKeyProvider,
                    sign_count: AtomicUsize::new(0),
                    on_sign: Mutex::new(None),
                }
            }
            pub fn sign_calls(&self) -> usize {
                self.sign_count.load(Ordering::Acquire)
            }
            pub fn set_on_sign(&self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
                *self.on_sign.lock().unwrap() = hook;
            }
        }
        impl soft_fido2::CredentialKeyProvider for RecordingKeyProvider {
            fn provider_id(&self) -> CredentialKeyProviderId {
                self.inner.provider_id()
            }
            fn supports_algorithm(&self, algorithm: i32) -> bool {
                self.inner.supports_algorithm(algorithm)
            }
            fn generate(
                &self,
                algorithm: i32,
            ) -> core::result::Result<GeneratedCredentialKey, CredentialKeyError> {
                self.inner.generate(algorithm)
            }
            fn sign(
                &self,
                key: &CredentialKey,
                algorithm: i32,
                data: &[u8],
            ) -> core::result::Result<Vec<u8>, CredentialKeyError> {
                let hook = self.on_sign.lock().unwrap().clone();
                if let Some(hook) = hook {
                    hook();
                }
                self.sign_count.fetch_add(1, Ordering::AcqRel);
                self.inner.sign(key, algorithm, data)
            }
        }

        pub struct WriteCountingStorage {
            creds: Mutex<Vec<soft_fido2::Credential>>,
            write_count: AtomicU64,
            /// Remaining matches of the iteration started by the last `read_first`.
            queue: std::collections::VecDeque<soft_fido2::Credential>,
        }
        impl WriteCountingStorage {
            pub fn new() -> Self {
                Self {
                    creds: Mutex::new(Vec::new()),
                    write_count: AtomicU64::new(0),
                    queue: std::collections::VecDeque::new(),
                }
            }
            pub fn writes(&self) -> u64 {
                self.write_count.load(Ordering::Acquire)
            }
            pub fn add_cred(&self, cred: soft_fido2::Credential) {
                self.creds.lock().unwrap().push(cred);
            }
        }
        impl CredentialStorage for WriteCountingStorage {
            fn read_first(
                &mut self,
                filter: CredentialFilter,
            ) -> soft_fido2::Result<soft_fido2::Credential> {
                let matches: Vec<soft_fido2::Credential> = {
                    let creds = self.creds.lock().unwrap();
                    match filter {
                        CredentialFilter::ByRp(rp_id) => {
                            creds.iter().filter(|c| c.rp.id == rp_id).cloned().collect()
                        }
                        CredentialFilter::None => creds.clone(),
                        CredentialFilter::ById(id) => {
                            creds.iter().filter(|c| c.id == id).cloned().collect()
                        }
                        CredentialFilter::ByHash(_) => Vec::new(),
                    }
                };
                self.queue = matches.into();
                self.queue.pop_front().ok_or(soft_fido2::Error::Other)
            }
            fn read_next(&mut self) -> soft_fido2::Result<soft_fido2::Credential> {
                self.queue.pop_front().ok_or(soft_fido2::Error::Other)
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
        }

        /// A granted-rules store whose answer a test flips at runtime (plan R16: ceremonies resolve
        /// live, never against state copied at session creation).
        #[derive(Default)]
        pub struct ToggleGrants(pub std::sync::atomic::AtomicBool);
        impl ToggleGrants {
            pub fn set(&self, granted: bool) {
                self.0.store(granted, Ordering::Release);
            }
        }
        impl GrantSource for ToggleGrants {
            fn is_granted(&self, _profile_id: &ProfileId, _rp_id: &str) -> bool {
                self.0.load(Ordering::Acquire)
            }
        }

        pub fn rule(rp_id: &str, authenticate: RuleAction, register: RuleAction) -> AgentRpRule {
            AgentRpRule {
                rp_id: rp_id.to_string(),
                register,
                authenticate,
                credential_selection: None,
            }
        }

        pub fn allow_rule(rp_id: &str) -> AgentRpRule {
            rule(rp_id, RuleAction::Allow, RuleAction::Deny)
        }

        pub fn request_rule(rp_id: &str) -> AgentRpRule {
            rule(rp_id, RuleAction::Request, RuleAction::Deny)
        }

        pub fn deny_rule(rp_id: &str) -> AgentRpRule {
            rule(rp_id, RuleAction::Deny, RuleAction::Deny)
        }

        pub fn test_profile_config(
            rules: Vec<AgentRpRule>,
            credential_refs: Option<Vec<passless_core::agent::CredentialRef>>,
            selection: CredentialSelection,
        ) -> AgentProfileConfig {
            AgentProfileConfig {
                max_granted_rules: 64,
                max_operations: 64,
                max_concurrent_sessions: 1,
                browser_scope: BrowserScope::Session,
                credential_selection: selection,
                mode: AgentMode::SameUser,
                principal_user: String::new(),
                credential_refs,
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

        pub fn test_agent_config(profile_config: AgentProfileConfig) -> AgentConfig {
            let mut profiles = BTreeMap::new();
            profiles.insert("test-profile".to_string(), profile_config);
            AgentConfig {
                notify_user: None,
                state_dir: None,
                escalation_timeout: None,
                escalation_cooldown: 600,
                limits: Default::default(),
                enabled: true,
                profiles,
                audit_path: Some(std::path::PathBuf::from("/tmp/test-audit")),
                acknowledge_global_same_user: vec!["test-profile".to_string()],
                acknowledge_same_user_registration: vec!["test-profile".to_string()],
            }
        }

        pub struct TestFixture {
            profile_id: ProfileId,
            grant_id: passless_core::agent::GrantId,
            pub clock: Arc<MockClock>,
            policy_runtime: Arc<PolicyRuntime>,
            storage: Arc<Mutex<Box<dyn CredentialStorage>>>,
            key_provider: Arc<RecordingKeyProvider>,
            audit_gate: Arc<AuditGate>,
            operation_lock: Arc<Mutex<()>>,
            security_config: SecurityConfig,
        }

        impl TestFixture {
            pub fn new(constant_counter: bool) -> Self {
                let tmp = tempfile::tempdir().unwrap();
                let audit_path = tmp.path().to_path_buf();
                drop(tmp);
                std::fs::create_dir_all(&audit_path).unwrap();
                std::fs::set_permissions(
                    &audit_path,
                    std::os::unix::fs::PermissionsExt::from_mode(0o700),
                )
                .unwrap();
                let audit_gate = Arc::new(AuditGate::open(&audit_path).unwrap());

                let profile_id = ProfileId::new("test-profile").unwrap();
                let cred_id = vec![1u8; 32];
                let cred_ref = passless_core::agent::CredentialRef::with_default_domain(&cred_id);

                let provider = SoftwareCredentialKeyProvider;
                let generated = provider.generate(-7).unwrap();
                let key = generated.key;

                let cred = soft_fido2::Credential {
                    id: cred_id.clone(),
                    rp: RelyingParty::new("example.com".into()),
                    user: User::new(vec![1, 2, 3]),
                    sign_count: 0,
                    alg: -7,
                    key: key.clone(),
                    created: 0,
                    discoverable: true,
                    backup_state: CredentialBackupState::NotEligible,
                    extensions: soft_fido2::Extensions::default(),
                };

                let storage = Arc::new(Mutex::new(Box::new({
                    let s = WriteCountingStorage::new();
                    s.add_cred(cred);
                    s
                })
                    as Box<dyn CredentialStorage>));

                let profile_config = test_profile_config(
                    vec![allow_rule("example.com")],
                    Some(vec![cred_ref.clone()]),
                    CredentialSelection::Single,
                );
                let agent_config = test_agent_config(profile_config);

                let clock = Arc::new(MockClock::new());

                let policy_runtime =
                    Arc::new(PolicyRuntime::new(&agent_config, clock.clone(), None).unwrap());

                let session_id = passless_core::agent::PrincipalSessionId::new();
                let endpoint_id = passless_core::agent::EndpointId::new();

                let grant_req_id = policy_runtime
                    .admin_request_grant(GrantRequestParams {
                        profile_id: profile_id.clone(),
                        session_id: session_id.clone(),
                        endpoint_id: endpoint_id.clone(),
                        principal_digest: [0u8; 32],
                        rp_ids: vec!["example.com".to_string()],
                        credentials: vec![cred_ref.clone()],
                        requested_ttl_secs: 300,
                    })
                    .unwrap();

                let authority = identity::admin_authority();
                let grant_id = policy_runtime
                    .admin_approve_grant(&grant_req_id, &authority)
                    .unwrap();

                let key_provider = Arc::new(RecordingKeyProvider::new());
                let operation_lock = Arc::new(Mutex::new(()));
                let security_config = SecurityConfig {
                    check_mlock: false,
                    disable_core_dumps: false,
                    constant_signature_counter: constant_counter,
                    enable_credential_backup: false,
                    always_uv: false,
                    user_verification_registration: false,
                    user_verification_authentication: false,
                    notification_timeout: 0,
                };

                Self {
                    profile_id,
                    grant_id,
                    clock,
                    policy_runtime,
                    storage,
                    key_provider,
                    audit_gate,
                    operation_lock,
                    security_config,
                }
            }

            pub fn make_handler(&self) -> SignHandler {
                SignHandler {
                    credential_storage: self.storage.clone(),
                    policy_runtime: self.policy_runtime.clone(),
                    audit_gate: self.audit_gate.clone(),
                    security_config: self.security_config.clone(),
                    key_provider: self.key_provider.clone(),
                    operation_lock: self.operation_lock.clone(),
                    escalation: crate::agent::escalation::test_support::idle_service(
                        self.audit_gate.clone(),
                    ),
                }
            }

            pub fn make_ctx(&self) -> SignContext {
                SignContext {
                    lease_activation: None,
                    profile_id: self.profile_id.clone(),
                    active_grant_id: self.grant_id.clone(),
                    session: test_session_at(
                        &self.profile_id,
                        self.policy_runtime.revocation_epoch(),
                    ),
                }
            }

            fn make_req(&self) -> SignAssertionRequest {
                SignAssertionRequest {
                    extensions: Vec::new(),
                    timeout_ms: None,
                    origin: "https://example.com".to_string(),
                    top_origin: None,
                    rp_id: "example.com".to_string(),
                    challenge_b64u: "dGVzdA".to_string(),
                    allow_credentials: vec![],
                    user_verification: false,
                    cross_origin: false,
                }
            }
        }

        fn assert_denied(
            result: &Result<PrincipalResponse, ProtocolError>,
            provider: &RecordingKeyProvider,
            storage_writes_before: u64,
            storage: &WriteCountingStorage,
        ) {
            assert!(result.is_err());
            assert_eq!(provider.sign_calls(), 0);
            assert_eq!(storage.writes(), storage_writes_before);
        }

        pub fn get_write_counting_storage(
            storage: &Arc<Mutex<Box<dyn CredentialStorage>>>,
        ) -> &WriteCountingStorage {
            let boxed = storage.lock().unwrap();
            unsafe {
                &*(boxed.as_ref() as *const dyn CredentialStorage as *const WriteCountingStorage)
            }
        }

        #[test]
        fn sign_allow_and_verify() {
            let f = TestFixture::new(true);
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let req = f.make_req();
            let result = handler.sign(&ctx, &req);
            assert!(result.is_ok());
            assert_eq!(f.key_provider.sign_calls(), 1);
        }

        #[test]
        fn dynamic_grant_discovers_credential_created_after_approval() {
            let f = TestFixture::new(true);
            f.storage.lock().unwrap().delete(&[1u8; 32]).unwrap();

            let grant_request = f
                .policy_runtime
                .admin_request_dynamic_grant(GrantRequestParams {
                    profile_id: f.profile_id.clone(),
                    session_id: passless_core::agent::PrincipalSessionId::new(),
                    endpoint_id: passless_core::agent::EndpointId::new(),
                    principal_digest: [0u8; 32],
                    rp_ids: vec!["example.com".to_string()],
                    credentials: vec![],
                    requested_ttl_secs: 300,
                })
                .unwrap();
            let dynamic_grant_id = f
                .policy_runtime
                .admin_approve_grant(&grant_request, &identity::admin_authority())
                .unwrap();

            let new_credential_id = vec![2u8; 32];
            let generated = SoftwareCredentialKeyProvider.generate(-7).unwrap();
            get_write_counting_storage(&f.storage).add_cred(soft_fido2::Credential {
                id: new_credential_id.clone(),
                rp: RelyingParty::new("example.com".into()),
                user: User::new(vec![4, 5, 6]),
                sign_count: 0,
                alg: -7,
                key: generated.key,
                created: 1,
                discoverable: true,
                backup_state: CredentialBackupState::NotEligible,
                extensions: soft_fido2::Extensions::default(),
            });

            let ctx = SignContext {
                lease_activation: None,
                profile_id: f.profile_id.clone(),
                active_grant_id: dynamic_grant_id,
                session: test_session(&f.profile_id),
            };
            let mut req = f.make_req();
            req.allow_credentials = vec![b64u_encode(&new_credential_id)];

            let result = f.make_handler().sign(&ctx, &req);
            assert!(result.is_ok());
            assert_eq!(f.key_provider.sign_calls(), 1);
        }

        #[test]
        fn sign_wrong_origin_denied() {
            let f = TestFixture::new(true);
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let mut req = f.make_req();
            req.origin = "https://evil.com".to_string();
            let writes_before = get_write_counting_storage(&f.storage).writes();
            let result = handler.sign(&ctx, &req);
            assert_denied(
                &result,
                &f.key_provider,
                writes_before,
                get_write_counting_storage(&f.storage),
            );
        }

        #[test]
        fn sign_wrong_rp_denied() {
            let f = TestFixture::new(true);
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let mut req = f.make_req();
            req.rp_id = "other.com".to_string();
            req.origin = "https://other.com".to_string();
            let writes_before = get_write_counting_storage(&f.storage).writes();
            let result = handler.sign(&ctx, &req);
            assert_denied(
                &result,
                &f.key_provider,
                writes_before,
                get_write_counting_storage(&f.storage),
            );
        }

        #[test]
        fn sign_wrong_allow_credentials_denied() {
            let f = TestFixture::new(true);
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let mut req = f.make_req();
            req.allow_credentials = vec!["d3Jvbmc".to_string()];
            let writes_before = get_write_counting_storage(&f.storage).writes();
            let result = handler.sign(&ctx, &req);
            assert_denied(
                &result,
                &f.key_provider,
                writes_before,
                get_write_counting_storage(&f.storage),
            );
        }

        #[test]
        fn sign_wrong_grant_denied() {
            let f = TestFixture::new(true);
            let handler = f.make_handler();
            let fake_grant_id = passless_core::agent::GrantId::new();
            let ctx = SignContext {
                lease_activation: None,
                profile_id: f.profile_id.clone(),
                active_grant_id: fake_grant_id,
                session: test_session(&f.profile_id),
            };
            let req = f.make_req();
            let writes_before = get_write_counting_storage(&f.storage).writes();
            let result = handler.sign(&ctx, &req);
            assert_denied(
                &result,
                &f.key_provider,
                writes_before,
                get_write_counting_storage(&f.storage),
            );
        }

        #[test]
        fn sign_wrong_profile_denied() {
            let f = TestFixture::new(true);
            let handler = f.make_handler();
            let wrong_profile = ProfileId::new("wrong-profile").unwrap();
            let ctx = SignContext {
                lease_activation: None,
                session: test_session(&wrong_profile),
                profile_id: wrong_profile,
                active_grant_id: f.grant_id.clone(),
            };
            let req = f.make_req();
            let writes_before = get_write_counting_storage(&f.storage).writes();
            let result = handler.sign(&ctx, &req);
            assert_denied(
                &result,
                &f.key_provider,
                writes_before,
                get_write_counting_storage(&f.storage),
            );
        }

        #[test]
        fn sign_expired_grant_denied() {
            let f = TestFixture::new(true);
            f.clock.advance(Duration::from_secs(301));
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let req = f.make_req();
            let writes_before = get_write_counting_storage(&f.storage).writes();
            let result = handler.sign(&ctx, &req);
            assert_denied(
                &result,
                &f.key_provider,
                writes_before,
                get_write_counting_storage(&f.storage),
            );
        }

        #[test]
        fn sign_revoked_grant_denied() {
            let f = TestFixture::new(true);
            f.policy_runtime.revoke_grant_by_id(&f.grant_id).unwrap();
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let req = f.make_req();
            let writes_before = get_write_counting_storage(&f.storage).writes();
            let result = handler.sign(&ctx, &req);
            assert_denied(
                &result,
                &f.key_provider,
                writes_before,
                get_write_counting_storage(&f.storage),
            );
        }

        #[test]
        fn constant_counter_no_write() {
            let f = TestFixture::new(true);
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let req = f.make_req();
            let writes_before = get_write_counting_storage(&f.storage).writes();
            let result = handler.sign(&ctx, &req);
            assert!(result.is_ok());
            assert_eq!(
                get_write_counting_storage(&f.storage).writes(),
                writes_before
            );
        }

        #[test]
        fn monotonic_sequential_counter() {
            let f = TestFixture::new(false);
            for i in 0..3u32 {
                let handler = f.make_handler();
                let ctx = f.make_ctx();
                let req = f.make_req();
                let result = handler.sign(&ctx, &req);
                assert!(result.is_ok());
                assert_eq!(
                    get_write_counting_storage(&f.storage).writes(),
                    (i + 1) as u64
                );
            }
        }

        #[test]
        fn concurrent_counter_serialization() {
            let f = TestFixture::new(false);
            let handler = Arc::new(f.make_handler());
            let ctx = Arc::new(f.make_ctx());
            let mut handles = Vec::new();
            for i in 0..4u8 {
                let h = handler.clone();
                let c = ctx.clone();
                handles.push(std::thread::spawn(move || {
                    // Distinct challenges: four distinct operations, serialized on the counter.
                    let req = SignAssertionRequest {
                        extensions: Vec::new(),
                        timeout_ms: None,
                        origin: "https://example.com".to_string(),
                        top_origin: None,
                        rp_id: "example.com".to_string(),
                        challenge_b64u: b64u_encode(&[b't', i]),
                        allow_credentials: vec![],
                        user_verification: false,
                        cross_origin: false,
                    };
                    h.sign(&c, &req)
                }));
            }
            let mut success_count = 0;
            for h in handles {
                if h.join().unwrap().is_ok() {
                    success_count += 1;
                }
            }
            assert_eq!(success_count, 4);
            assert_eq!(get_write_counting_storage(&f.storage).writes(), 4);
        }

        #[test]
        fn persisted_counter_visible_after_reconstruct() {
            let f = TestFixture::new(false);
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let req = f.make_req();
            let result = handler.sign(&ctx, &req);
            assert!(result.is_ok());
            assert_eq!(get_write_counting_storage(&f.storage).writes(), 1);

            let handler2 = f.make_handler();
            let ctx2 = f.make_ctx();
            let req2 = f.make_req();
            let result2 = handler2.sign(&ctx2, &req2);
            assert!(result2.is_ok());
            assert_eq!(get_write_counting_storage(&f.storage).writes(), 2);
        }

        #[test]
        fn ipc_dispatch_uses_same_sign_core_as_delegation() {
            let f = TestFixture::new(true);
            let delegation_handler = f.make_handler();
            let delegation_ctx = f.make_ctx();
            let delegation_req = f.make_req();
            let delegation_result = delegation_handler.sign(&delegation_ctx, &delegation_req);
            assert!(delegation_result.is_ok());

            let ipc_handler = f.make_handler();
            let ipc_ctx = f.make_ctx();
            let ipc_req = f.make_req();
            let ipc_result = ipc_handler.sign(&ipc_ctx, &ipc_req);
            assert!(ipc_result.is_ok());

            match (&delegation_result, &ipc_result) {
                (
                    Ok(PrincipalResponse::SignAssertionResult(dr)),
                    Ok(PrincipalResponse::SignAssertionResult(ir)),
                ) => {
                    assert_eq!(dr.credential_id_b64u, ir.credential_id_b64u);
                    assert_eq!(dr.signature_b64u, ir.signature_b64u);
                    assert_eq!(dr.authenticator_data_b64u, ir.authenticator_data_b64u);
                }
                _ => panic!("expected SignAssertionResult from both"),
            }
        }
    }

    mod audit_and_policy_tests {
        use super::sign_handler_tests::*;
        use super::*;

        use crate::agent::audit::AuditGate;
        use crate::agent::escalation::test_support::{self, ScriptedPrompter};
        use crate::agent::escalation::{EscalationService, PromptEvent};
        use crate::agent::grant::GrantRequestParams;
        use crate::agent::granted_rules::GrantedRulesStore;
        use crate::agent::identity;
        use crate::agent::policy_engine::PolicyRuntime;
        use crate::storage::CredentialStorage;

        use passless_core::agent::{
            AgentProfileConfig, AgentRpRule, CredentialSelection, GrantSource,
        };
        use passless_core::config::SecurityConfig;

        use soft_fido2::{
            CredentialBackupState, CredentialKeyProvider, RelyingParty,
            SoftwareCredentialKeyProvider, User,
        };

        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        const FRAME_MAGIC: u32 = 0x41554449;
        const HEADER_SIZE: usize = 88;

        fn read_audit_events(audit_dir: &std::path::Path) -> Vec<serde_json::Value> {
            let mut events = Vec::new();
            let mut entries: Vec<_> = std::fs::read_dir(audit_dir)
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| {
                    let name = e.file_name();
                    let name = name.to_string_lossy();
                    name.starts_with("audit-") && name.ends_with(".log")
                })
                .collect();
            entries.sort_by_key(|e| e.file_name());

            for entry in entries {
                let data = std::fs::read(entry.path()).unwrap();
                if data.len() <= HEADER_SIZE {
                    continue;
                }
                let mut offset = HEADER_SIZE;
                while offset + 12 <= data.len() {
                    let magic = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
                    if magic != FRAME_MAGIC {
                        break;
                    }
                    let frame_len =
                        u64::from_le_bytes(data[offset + 4..offset + 12].try_into().unwrap())
                            as usize;
                    if offset + 12 + frame_len > data.len() {
                        break;
                    }
                    let body = &data[offset + 12..offset + 12 + frame_len];
                    if body.len() < 28 {
                        break;
                    }
                    let payload_len = u32::from_le_bytes(body[24..28].try_into().unwrap()) as usize;
                    if body.len() < 28 + payload_len + 64 {
                        break;
                    }
                    let payload = &body[28..28 + payload_len];
                    let event: serde_json::Value = serde_json::from_slice(payload).unwrap();
                    events.push(event);
                    offset += 12 + frame_len;
                }
            }
            events
        }

        fn find_policy_events(events: &[serde_json::Value]) -> Vec<&serde_json::Value> {
            events
                .iter()
                .filter(|e| {
                    e.get("kind").and_then(|k| k.as_str()).is_some_and(|k| {
                        k == "policy.allow" || k == "policy.deny" || k == "policy.replay_served"
                    })
                })
                .collect()
        }

        /// One credential held by the fixture's storage.
        #[derive(Clone)]
        struct StoredCred {
            id: Vec<u8>,
            rp_id: &'static str,
            created: i64,
        }

        fn stored(id: u8, rp_id: &'static str, created: i64) -> StoredCred {
            StoredCred {
                id: vec![id; 32],
                rp_id,
                created,
            }
        }

        fn cred_ref_of(id: &[u8]) -> passless_core::agent::CredentialRef {
            passless_core::agent::CredentialRef::with_default_domain(id)
        }

        /// How a fixture is built. The default is one credential for `example.com`, an explicit
        /// grant naming that credential, and profile selection `single`.
        #[derive(Clone)]
        struct FixtureSpec {
            rules: Vec<AgentRpRule>,
            grant_rp_ids: Vec<&'static str>,
            selection: CredentialSelection,
            credentials: Vec<StoredCred>,
            /// A dynamic grant (empty credential list: discover per request) instead of an
            /// explicit grant naming every stored credential.
            dynamic_grant: bool,
            /// Escalate through a real coordinator, granted-rules store and scripted prompter
            /// (the store is then the policy's grant source); otherwise no prompt can be shown
            /// and `ToggleGrants` is the grant source.
            escalation: bool,
        }

        impl FixtureSpec {
            fn new(rules: Vec<AgentRpRule>, grant_rp_ids: Vec<&'static str>) -> Self {
                Self {
                    rules,
                    grant_rp_ids,
                    selection: CredentialSelection::Single,
                    credentials: vec![stored(1, "example.com", 0)],
                    dynamic_grant: false,
                    escalation: false,
                }
            }
        }

        struct AuditTestFixture {
            spec: FixtureSpec,
            profile_id: ProfileId,
            grant_id: passless_core::agent::GrantId,
            clock: Arc<MockClock>,
            policy_runtime: Arc<PolicyRuntime>,
            granted_rules: Arc<ToggleGrants>,
            storage: Arc<Mutex<Box<dyn CredentialStorage>>>,
            key_provider: Arc<RecordingKeyProvider>,
            audit_gate: Arc<AuditGate>,
            operation_lock: Arc<Mutex<()>>,
            security_config: SecurityConfig,
            audit_dir: std::path::PathBuf,
            escalation: Arc<EscalationService>,
            prompter: Arc<ScriptedPrompter>,
            store: Arc<GrantedRulesStore>,
            _state_dir: tempfile::TempDir,
        }

        impl AuditTestFixture {
            fn new(rules: Vec<AgentRpRule>, grant_rp_ids: Vec<&'static str>) -> Self {
                Self::from_spec(FixtureSpec::new(rules, grant_rp_ids))
            }

            fn profile_config(spec: &FixtureSpec) -> AgentProfileConfig {
                let credential_refs = if spec.dynamic_grant {
                    None
                } else {
                    Some(
                        spec.credentials
                            .iter()
                            .map(|c| cred_ref_of(&c.id))
                            .collect(),
                    )
                };
                test_profile_config(spec.rules.clone(), credential_refs, spec.selection.clone())
            }

            fn from_spec(spec: FixtureSpec) -> Self {
                let tmp = tempfile::tempdir().unwrap();
                let audit_path = tmp.path().to_path_buf();
                drop(tmp);
                std::fs::create_dir_all(&audit_path).unwrap();
                std::fs::set_permissions(
                    &audit_path,
                    std::os::unix::fs::PermissionsExt::from_mode(0o700),
                )
                .unwrap();
                let audit_gate = Arc::new(AuditGate::open(&audit_path).unwrap());

                let profile_id = ProfileId::new("test-profile").unwrap();
                let provider = SoftwareCredentialKeyProvider;

                let storage_impl = WriteCountingStorage::new();
                for stored in &spec.credentials {
                    storage_impl.add_cred(soft_fido2::Credential {
                        id: stored.id.clone(),
                        rp: RelyingParty::new(stored.rp_id.into()),
                        user: User::new(vec![1, 2, 3, stored.id[0]]),
                        sign_count: 0,
                        alg: -7,
                        key: provider.generate(-7).unwrap().key,
                        created: stored.created,
                        discoverable: true,
                        backup_state: CredentialBackupState::NotEligible,
                        extensions: soft_fido2::Extensions::default(),
                    });
                }
                let storage = Arc::new(Mutex::new(
                    Box::new(storage_impl) as Box<dyn CredentialStorage>
                ));

                let agent_config = test_agent_config(Self::profile_config(&spec));

                let clock = Arc::new(MockClock::new());
                let granted_rules = Arc::new(ToggleGrants::default());
                let state_dir = tempfile::tempdir().unwrap();
                let store = Arc::new(GrantedRulesStore::open(
                    state_dir.path(),
                    [profile_id.clone()],
                ));
                let grant_source: Arc<dyn GrantSource> = if spec.escalation {
                    store.clone()
                } else {
                    granted_rules.clone()
                };

                let policy_runtime = Arc::new(
                    PolicyRuntime::new(&agent_config, clock.clone(), None)
                        .unwrap()
                        .with_grant_source(grant_source),
                );
                let prompter = Arc::new(ScriptedPrompter::default());
                let escalation = if spec.escalation {
                    test_support::service(
                        audit_gate.clone(),
                        store.clone(),
                        policy_runtime.clone(),
                        prompter.clone(),
                        Duration::from_secs(600),
                    )
                } else {
                    test_support::idle_service(audit_gate.clone())
                };

                let grant_id = Self::approve_grant(&policy_runtime, &profile_id, &spec);

                let key_provider = Arc::new(RecordingKeyProvider::new());
                let operation_lock = Arc::new(Mutex::new(()));
                let security_config = SecurityConfig {
                    check_mlock: false,
                    disable_core_dumps: false,
                    constant_signature_counter: true,
                    enable_credential_backup: false,
                    // The RP-facing UV knobs must not matter under `allow`.
                    always_uv: false,
                    user_verification_registration: false,
                    user_verification_authentication: false,
                    notification_timeout: 0,
                };

                Self {
                    spec,
                    profile_id,
                    grant_id,
                    clock,
                    policy_runtime,
                    granted_rules,
                    storage,
                    key_provider,
                    audit_gate,
                    operation_lock,
                    security_config,
                    audit_dir: audit_path,
                    escalation,
                    prompter,
                    store,
                    _state_dir: state_dir,
                }
            }

            fn approve_grant(
                policy_runtime: &PolicyRuntime,
                profile_id: &ProfileId,
                spec: &FixtureSpec,
            ) -> passless_core::agent::GrantId {
                let params = GrantRequestParams {
                    profile_id: profile_id.clone(),
                    session_id: passless_core::agent::PrincipalSessionId::new(),
                    endpoint_id: passless_core::agent::EndpointId::new(),
                    principal_digest: [0u8; 32],
                    rp_ids: spec.grant_rp_ids.iter().map(|s| s.to_string()).collect(),
                    credentials: if spec.dynamic_grant {
                        vec![]
                    } else {
                        spec.credentials
                            .iter()
                            .map(|c| cred_ref_of(&c.id))
                            .collect()
                    },
                    requested_ttl_secs: 300,
                };
                let request_id = if spec.dynamic_grant {
                    policy_runtime.admin_request_dynamic_grant(params).unwrap()
                } else {
                    policy_runtime.admin_request_grant(params).unwrap()
                };
                policy_runtime
                    .admin_approve_grant(&request_id, &identity::admin_authority())
                    .unwrap()
            }

            /// Replace the live policy with `rules`. A reload revokes every grant (ADR 0014
            /// section 6.4: the revocation epoch), so a fresh grant is approved on the new
            /// generation; the handler is untouched and the context carries nothing but the new
            /// grant id, so only the live policy can explain the next result.
            fn reload_rules(&mut self, rules: Vec<AgentRpRule>) {
                self.spec.rules = rules;
                let config = test_agent_config(Self::profile_config(&self.spec));
                self.policy_runtime.reload(&config).unwrap();
                self.grant_id =
                    Self::approve_grant(&self.policy_runtime, &self.profile_id, &self.spec);
            }

            fn default_allow() -> Self {
                Self::new(vec![allow_rule("example.com")], vec!["example.com"])
            }

            fn make_handler(&self) -> SignHandler {
                SignHandler {
                    credential_storage: self.storage.clone(),
                    policy_runtime: self.policy_runtime.clone(),
                    audit_gate: self.audit_gate.clone(),
                    security_config: self.security_config.clone(),
                    key_provider: self.key_provider.clone(),
                    operation_lock: self.operation_lock.clone(),
                    escalation: self.escalation.clone(),
                }
            }

            fn make_ctx(&self) -> SignContext {
                SignContext {
                    lease_activation: None,
                    profile_id: self.profile_id.clone(),
                    active_grant_id: self.grant_id.clone(),
                    session: test_session_at(
                        &self.profile_id,
                        self.policy_runtime.revocation_epoch(),
                    ),
                }
            }

            fn make_req(&self) -> SignAssertionRequest {
                SignAssertionRequest {
                    extensions: Vec::new(),
                    timeout_ms: None,
                    origin: "https://example.com".to_string(),
                    top_origin: None,
                    rp_id: "example.com".to_string(),
                    challenge_b64u: "dGVzdA".to_string(),
                    allow_credentials: vec![],
                    user_verification: false,
                    cross_origin: false,
                }
            }

            /// A request for `localhost` (an `http://` origin, as a local dev server would send).
            fn make_localhost_req(&self) -> SignAssertionRequest {
                SignAssertionRequest {
                    origin: "http://localhost:8080".to_string(),
                    rp_id: "localhost".to_string(),
                    ..self.make_req()
                }
            }

            /// The `(kind, reason)` of every policy record, oldest first.
            fn policy_records(&self) -> Vec<(String, Option<String>)> {
                find_policy_events(&read_audit_events(&self.audit_dir))
                    .iter()
                    .map(|e| {
                        (
                            e["kind"].as_str().unwrap().to_string(),
                            e["reason"].as_str().map(str::to_string),
                        )
                    })
                    .collect()
            }
        }

        fn signed_credential(result: Result<PrincipalResponse, ProtocolError>) -> Vec<u8> {
            match result.expect("sign should succeed") {
                PrincipalResponse::SignAssertionResult(resp) => {
                    super::b64u_decode(&resp.credential_id_b64u).unwrap()
                }
                _ => panic!("expected SignAssertionResult"),
            }
        }

        #[test]
        fn audit_allow_event_on_successful_sign() {
            let f = AuditTestFixture::default_allow();
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let req = f.make_req();
            let result = handler.sign(&ctx, &req);
            assert!(result.is_ok());

            let events = read_audit_events(&f.audit_dir);
            let policy_events = find_policy_events(&events);
            assert!(!policy_events.is_empty());
            let last = policy_events.last().unwrap();
            assert_eq!(last["kind"], "policy.allow");
            assert_eq!(last["profile_id"], "test-profile");
            assert_eq!(last["action"], "authenticate");
            assert_eq!(last["rp_id"], "example.com");
        }

        #[test]
        fn audit_deny_event_on_origin_mismatch() {
            let f = AuditTestFixture::default_allow();
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let mut req = f.make_req();
            req.origin = "https://evil.com".to_string();
            let result = handler.sign(&ctx, &req);
            assert!(result.is_err());

            let events = read_audit_events(&f.audit_dir);
            let policy_events = find_policy_events(&events);
            assert!(!policy_events.is_empty());
            let last = policy_events.last().unwrap();
            assert_eq!(last["kind"], "policy.deny");
            assert_eq!(last["reason"], "origin_invalid");
        }

        #[test]
        fn audit_deny_event_on_expired_grant() {
            let f = AuditTestFixture::default_allow();
            f.clock.advance(Duration::from_secs(301));
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let req = f.make_req();
            let result = handler.sign(&ctx, &req);
            assert!(result.is_err());

            let events = read_audit_events(&f.audit_dir);
            let policy_events = find_policy_events(&events);
            assert!(!policy_events.is_empty());
            let last = policy_events.last().unwrap();
            assert_eq!(last["kind"], "policy.deny");
            assert_eq!(last["reason"], "grant_expired");
        }

        #[test]
        fn audit_deny_event_on_revoked_grant() {
            let f = AuditTestFixture::default_allow();
            f.policy_runtime.revoke_grant_by_id(&f.grant_id).unwrap();
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let req = f.make_req();
            let result = handler.sign(&ctx, &req);
            assert!(result.is_err());

            let events = read_audit_events(&f.audit_dir);
            let policy_events = find_policy_events(&events);
            assert!(!policy_events.is_empty());
            let last = policy_events.last().unwrap();
            assert_eq!(last["kind"], "policy.deny");
            assert_eq!(last["reason"], "grant_revoked");
        }

        #[test]
        fn audit_deny_event_on_rp_mismatch() {
            let f = AuditTestFixture::default_allow();
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let mut req = f.make_req();
            req.rp_id = "other.com".to_string();
            req.origin = "https://other.com".to_string();
            let result = handler.sign(&ctx, &req);
            assert!(result.is_err());

            let events = read_audit_events(&f.audit_dir);
            let policy_events = find_policy_events(&events);
            assert!(!policy_events.is_empty());
            let last = policy_events.last().unwrap();
            assert_eq!(last["kind"], "policy.deny");
            assert_eq!(last["reason"], "rp_id_not_match");
        }

        #[test]
        fn audit_deny_event_on_credential_mismatch() {
            let f = AuditTestFixture::default_allow();
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let mut req = f.make_req();
            req.allow_credentials = vec!["d3Jvbmc".to_string()];
            let result = handler.sign(&ctx, &req);
            assert!(result.is_err());

            let events = read_audit_events(&f.audit_dir);
            let policy_events = find_policy_events(&events);
            assert!(!policy_events.is_empty());
            let last = policy_events.last().unwrap();
            assert_eq!(last["kind"], "policy.deny");
            assert_eq!(last["reason"], "allow_credentials_mismatch");
        }

        #[test]
        fn audit_pre_write_blocks_sign() {
            let tmp = tempfile::tempdir().unwrap();
            let bad_path = tmp.path().join("not_a_dir");
            std::fs::write(&bad_path, b"block").unwrap();

            let result = AuditGate::open(&bad_path);
            assert!(result.is_err());
        }

        #[test]
        fn counter_zero_in_constant_mode_response() {
            let f = AuditTestFixture::default_allow();
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let req = f.make_req();
            let result = handler.sign(&ctx, &req);
            assert!(result.is_ok());

            match result.unwrap() {
                PrincipalResponse::SignAssertionResult(resp) => {
                    let auth_data = super::b64u_decode(&resp.authenticator_data_b64u).unwrap();
                    assert!(auth_data.len() >= 37);
                    let counter = u32::from_be_bytes(auth_data[33..37].try_into().unwrap());
                    assert_eq!(counter, 0);
                }
                _ => panic!("expected SignAssertionResult"),
            }
        }

        #[test]
        fn counter_increments_in_monotonic_mode_response() {
            let mut f = AuditTestFixture::new(vec![allow_rule("example.com")], vec!["example.com"]);
            f.security_config.constant_signature_counter = false;

            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let req = f.make_req();
            let result1 = handler.sign(&ctx, &req);
            assert!(result1.is_ok());

            let handler2 = f.make_handler();
            let ctx2 = f.make_ctx();
            let req2 = f.make_req();
            let result2 = handler2.sign(&ctx2, &req2);
            assert!(result2.is_ok());

            match result1.unwrap() {
                PrincipalResponse::SignAssertionResult(resp) => {
                    let auth_data = super::b64u_decode(&resp.authenticator_data_b64u).unwrap();
                    let counter = u32::from_be_bytes(auth_data[33..37].try_into().unwrap());
                    assert_eq!(counter, 1);
                }
                _ => panic!("expected SignAssertionResult"),
            }

            match result2.unwrap() {
                PrincipalResponse::SignAssertionResult(resp) => {
                    let auth_data = super::b64u_decode(&resp.authenticator_data_b64u).unwrap();
                    let counter = u32::from_be_bytes(auth_data[33..37].try_into().unwrap());
                    assert_eq!(counter, 2);
                }
                _ => panic!("expected SignAssertionResult"),
            }
        }

        #[test]
        fn request_rule_without_a_prompt_denies_with_escalation_unavailable_and_signs_nothing() {
            let f = AuditTestFixture::new(vec![request_rule("example.com")], vec!["example.com"]);
            let writes_before = get_write_counting_storage(&f.storage).writes();
            let err = f
                .make_handler()
                .sign(&f.make_ctx(), &f.make_req())
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::Forbidden);
            assert_ne!(err.code, ErrorCode::InteractionRequired);
            assert!(err.message.contains("escalation is unavailable"));
            assert_eq!(f.key_provider.sign_calls(), 0, "no signature");
            assert_eq!(
                get_write_counting_storage(&f.storage).writes(),
                writes_before
            );
            assert_eq!(
                f.policy_records(),
                vec![(
                    "policy.deny".to_string(),
                    Some("escalation_unavailable".into())
                )]
            );
        }

        #[test]
        fn deny_rule_denies_with_action_not_allowed_and_signs_nothing() {
            let f = AuditTestFixture::new(vec![deny_rule("example.com")], vec!["example.com"]);
            let err = f
                .make_handler()
                .sign(&f.make_ctx(), &f.make_req())
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::Forbidden);
            assert_eq!(f.key_provider.sign_calls(), 0, "no signature");
            assert_eq!(
                f.policy_records(),
                vec![("policy.deny".to_string(), Some("action_not_allowed".into()))]
            );
        }

        #[test]
        fn unmatched_rp_denies_with_action_not_allowed() {
            // The grant covers the RP, but no rule does: default deny.
            let f = AuditTestFixture::new(vec![allow_rule("other.com")], vec!["example.com"]);
            let err = f
                .make_handler()
                .sign(&f.make_ctx(), &f.make_req())
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::Forbidden);
            assert_eq!(f.key_provider.sign_calls(), 0);
            assert_eq!(
                f.policy_records(),
                vec![("policy.deny".to_string(), Some("action_not_allowed".into()))]
            );
        }

        // Without a notification bus `request` is denied: `forbidden`, an audited deny, no allow
        // record, no prompt and no human or native path.
        #[test]
        fn request_rule_is_denied_as_forbidden_and_audited_without_human_path() {
            let f = AuditTestFixture::new(vec![request_rule("example.com")], vec!["example.com"]);
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let err = handler.sign(&ctx, &f.make_req()).unwrap_err();
            assert_eq!(err.code, ErrorCode::Forbidden);
            assert_ne!(err.code, ErrorCode::InteractionRequired);
            assert_eq!(
                crate::agent::transport::wire_error_code(err.code),
                "forbidden"
            );
            assert_eq!(dom_exception_name(err.code), "NotAllowedError");

            let events = read_audit_events(&f.audit_dir);
            let policy_events = find_policy_events(&events);
            assert_eq!(
                policy_events.len(),
                1,
                "exactly one policy record: {policy_events:?}"
            );
            assert_eq!(policy_events[0]["kind"], "policy.deny");
            assert_eq!(policy_events[0]["action"], "authenticate");
            assert_eq!(policy_events[0]["reason"], "escalation_unavailable");
        }

        #[test]
        fn allow_signs_with_agent_evidence_and_up_uv_flags_even_without_rp_uv_request() {
            let f = AuditTestFixture::default_allow();
            let mut req = f.make_req();
            // The RP does not ask for UV, and `always_uv` is off: UP and UV are still set because
            // `allow` is agent-session evidence (ADR 0014 section 7).
            req.user_verification = false;
            assert!(!f.security_config.always_uv);

            let result = f.make_handler().sign(&f.make_ctx(), &req);
            let resp = match result.unwrap() {
                PrincipalResponse::SignAssertionResult(resp) => resp,
                _ => panic!("expected SignAssertionResult"),
            };
            let auth_data = super::b64u_decode(&resp.authenticator_data_b64u).unwrap();
            assert_eq!(auth_data[32] & 0x05, 0x05, "UP and UV flags");
            assert_eq!(f.key_provider.sign_calls(), 1);

            let events = read_audit_events(&f.audit_dir);
            let allow = find_policy_events(&events)
                .into_iter()
                .find(|e| e["kind"] == "policy.allow")
                .expect("allow event");
            assert_eq!(
                (
                    allow["authorization"].as_str(),
                    allow["user_presence"].as_str(),
                    allow["user_verification"].as_str(),
                ),
                (Some("allow"), Some("agent"), Some("agent")),
                "{allow}"
            );
        }

        #[test]
        fn allow_sets_up_and_uv_when_the_rp_requests_uv_too() {
            let f = AuditTestFixture::default_allow();
            let mut req = f.make_req();
            req.user_verification = true;
            let resp = match f.make_handler().sign(&f.make_ctx(), &req).unwrap() {
                PrincipalResponse::SignAssertionResult(resp) => resp,
                _ => panic!("expected SignAssertionResult"),
            };
            let auth_data = super::b64u_decode(&resp.authenticator_data_b64u).unwrap();
            assert_eq!(auth_data[32] & 0x05, 0x05);
        }

        // --- live resolution (plan R16) ---

        #[test]
        fn granted_rule_upgrades_request_live_through_the_same_context() {
            // The granted-rules store changes while the handler and context stay as they were:
            // `request` is denied, then allowed once the store grants it, then denied again when
            // the grant is withdrawn.
            let f = AuditTestFixture::new(vec![request_rule("example.com")], vec!["example.com"]);
            let handler = f.make_handler();
            let ctx = f.make_ctx();

            let err = handler.sign(&ctx, &f.make_req()).unwrap_err();
            assert!(err.message.contains("escalation is unavailable"));
            assert_eq!(f.key_provider.sign_calls(), 0);

            f.granted_rules.set(true);
            handler
                .sign(&ctx, &f.make_req())
                .expect("a granted request rule is an allow");
            assert_eq!(f.key_provider.sign_calls(), 1);

            f.granted_rules.set(false);
            assert!(handler.sign(&ctx, &f.make_req()).is_err());
            assert_eq!(f.key_provider.sign_calls(), 1, "no further signature");
        }

        #[test]
        fn orphaned_grant_is_inert_when_the_rule_is_deny() {
            let f = AuditTestFixture::new(vec![deny_rule("example.com")], vec!["example.com"]);
            f.granted_rules.set(true);
            let err = f
                .make_handler()
                .sign(&f.make_ctx(), &f.make_req())
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::Forbidden);
            assert_eq!(f.key_provider.sign_calls(), 0);
            assert_eq!(
                f.policy_records(),
                vec![("policy.deny".to_string(), Some("action_not_allowed".into()))]
            );
        }

        #[test]
        fn reload_to_deny_is_enforced_by_the_unchanged_handler() {
            let mut f = AuditTestFixture::default_allow();
            let handler = f.make_handler();
            handler
                .sign(&f.make_ctx(), &f.make_req())
                .expect("allowed before the reload");
            assert_eq!(f.key_provider.sign_calls(), 1);

            f.reload_rules(vec![deny_rule("example.com")]);
            let err = handler.sign(&f.make_ctx(), &f.make_req()).unwrap_err();
            assert_eq!(err.code, ErrorCode::Forbidden);
            assert_eq!(
                f.key_provider.sign_calls(),
                1,
                "no signature after the reload"
            );
            assert_eq!(
                f.policy_records().last().unwrap(),
                &("policy.deny".to_string(), Some("action_not_allowed".into()))
            );

            // Removing the rule entirely is the same default deny.
            f.reload_rules(vec![]);
            assert!(handler.sign(&f.make_ctx(), &f.make_req()).is_err());
            assert_eq!(f.key_provider.sign_calls(), 1);
        }

        #[test]
        fn reload_from_deny_to_allow_is_enforced_by_the_unchanged_handler() {
            let mut f = AuditTestFixture::new(vec![deny_rule("example.com")], vec!["example.com"]);
            let handler = f.make_handler();
            assert!(handler.sign(&f.make_ctx(), &f.make_req()).is_err());
            assert_eq!(f.key_provider.sign_calls(), 0);

            f.reload_rules(vec![allow_rule("example.com")]);
            handler
                .sign(&f.make_ctx(), &f.make_req())
                .expect("allowed after the reload");
            assert_eq!(f.key_provider.sign_calls(), 1);

            f.reload_rules(vec![request_rule("example.com")]);
            let err = handler.sign(&f.make_ctx(), &f.make_req()).unwrap_err();
            assert!(err.message.contains("escalation is unavailable"));
            assert_eq!(f.key_provider.sign_calls(), 1);
        }

        #[test]
        fn session_from_before_a_changed_reload_is_revoked() {
            // A reload that changes the policy bumps the revocation epoch: a session created before
            // it is revoked, whatever the new rules say (ADR 0014 sections 6.4 and 9).
            let mut f = AuditTestFixture::default_allow();
            let stale_ctx = f.make_ctx();
            f.reload_rules(vec![allow_rule("example.com"), allow_rule("other.example")]);
            let err = f
                .make_handler()
                .sign(&stale_ctx, &f.make_req())
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::Unauthorized);
            assert_eq!(f.key_provider.sign_calls(), 0);
            assert_eq!(
                f.policy_records().last().unwrap().1.as_deref(),
                Some("policy_revoked")
            );
            assert_eq!(stale_ctx.session.operations_used(), 0, "no budget consumed");
        }

        // --- selection (ADR 0014 section 10.1) ---

        fn two_credentials_spec(
            rules: Vec<AgentRpRule>,
            selection: CredentialSelection,
        ) -> FixtureSpec {
            FixtureSpec {
                selection,
                // A is older than B.
                credentials: vec![
                    stored(0xA1, "example.com", 10),
                    stored(0xB2, "example.com", 20),
                ],
                dynamic_grant: true,
                ..FixtureSpec::new(rules, vec!["example.com"])
            }
        }

        fn id_a() -> Vec<u8> {
            vec![0xA1; 32]
        }

        fn id_b() -> Vec<u8> {
            vec![0xB2; 32]
        }

        #[test]
        fn pinned_credential_wins_over_allow_credentials() {
            let mut rule = allow_rule("example.com");
            rule.credential_selection = Some(CredentialSelection::Credential(cred_ref_of(&id_a())));
            let f = AuditTestFixture::from_spec(two_credentials_spec(
                vec![rule],
                CredentialSelection::Single,
            ));

            // allowCredentials names only B, but the rule pins A: denied, and B never signs.
            let mut only_b = f.make_req();
            only_b.allow_credentials = vec![b64u_encode(&id_b())];
            let err = f.make_handler().sign(&f.make_ctx(), &only_b).unwrap_err();
            assert_eq!(err.code, ErrorCode::Forbidden);
            assert_eq!(f.key_provider.sign_calls(), 0, "B must never sign");
            assert_eq!(
                f.policy_records(),
                vec![(
                    "policy.deny".to_string(),
                    Some("allow_credentials_mismatch".into())
                )]
            );

            // allowCredentials [A, B]: the pinned set is [A], so A signs.
            let mut both = f.make_req();
            both.allow_credentials = vec![b64u_encode(&id_b()), b64u_encode(&id_a())];
            let signed = signed_credential(f.make_handler().sign(&f.make_ctx(), &both));
            assert_eq!(signed, id_a());

            // No allowCredentials at all: still A.
            let signed = signed_credential(f.make_handler().sign(&f.make_ctx(), &f.make_req()));
            assert_eq!(signed, id_a());
        }

        #[test]
        fn allow_credentials_chooses_within_the_set_and_beats_single() {
            // Two candidates, selection `single`: an allowCredentials entry that leaves exactly one
            // permitted credential is used (step 3), and none at all is a conflict (step 4).
            let f = AuditTestFixture::from_spec(two_credentials_spec(
                vec![allow_rule("example.com")],
                CredentialSelection::Single,
            ));
            let mut only_b = f.make_req();
            only_b.allow_credentials = vec![b64u_encode(&id_b())];
            let signed = signed_credential(f.make_handler().sign(&f.make_ctx(), &only_b));
            assert_eq!(signed, id_b());

            let err = f
                .make_handler()
                .sign(&f.make_ctx(), &f.make_req())
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::Conflict);
            assert_eq!(f.key_provider.sign_calls(), 1, "the conflict signs nothing");
        }

        #[test]
        fn first_allow_credentials_entry_no_longer_wins_with_several_candidates() {
            // Both credentials are listed and the selection is `single`: the old "first
            // allowCredentials entry wins" behaviour is gone, so this is a conflict.
            let f = AuditTestFixture::from_spec(two_credentials_spec(
                vec![allow_rule("example.com")],
                CredentialSelection::Single,
            ));
            let mut both = f.make_req();
            both.allow_credentials = vec![b64u_encode(&id_b()), b64u_encode(&id_a())];
            let err = f.make_handler().sign(&f.make_ctx(), &both).unwrap_err();
            assert_eq!(err.code, ErrorCode::Conflict);
            assert_eq!(f.key_provider.sign_calls(), 0);
            assert_eq!(
                f.policy_records().last().unwrap().1.as_deref(),
                Some("credential_not_match")
            );
        }

        #[test]
        fn exact_rule_applies_profile_selection_newest_and_first_matching() {
            let f = AuditTestFixture::from_spec(two_credentials_spec(
                vec![allow_rule("example.com")],
                CredentialSelection::Newest,
            ));
            let signed = signed_credential(f.make_handler().sign(&f.make_ctx(), &f.make_req()));
            assert_eq!(signed, id_b(), "newest picks the credential created last");

            let f = AuditTestFixture::from_spec(two_credentials_spec(
                vec![allow_rule("example.com")],
                CredentialSelection::FirstMatching,
            ));
            let signed = signed_credential(f.make_handler().sign(&f.make_ctx(), &f.make_req()));
            assert_eq!(signed, id_a(), "first-matching is stable by credential id");
        }

        #[test]
        fn rule_selection_overrides_profile_selection() {
            let mut rule = allow_rule("example.com");
            rule.credential_selection = Some(CredentialSelection::FirstMatching);
            let f = AuditTestFixture::from_spec(two_credentials_spec(
                vec![rule],
                CredentialSelection::Newest,
            ));
            let signed = signed_credential(f.make_handler().sign(&f.make_ctx(), &f.make_req()));
            assert_eq!(signed, id_a());
        }

        #[test]
        fn wildcard_forces_single_even_when_the_profile_default_is_newest() {
            let f = AuditTestFixture::from_spec(two_credentials_spec(
                vec![allow_rule(ANY_RP_ID)],
                CredentialSelection::Newest,
            ));
            let err = f
                .make_handler()
                .sign(&f.make_ctx(), &f.make_req())
                .unwrap_err();
            assert_eq!(
                err.code,
                ErrorCode::Conflict,
                "a wildcard never picks an account"
            );
            assert_eq!(f.key_provider.sign_calls(), 0);

            // Control: the same profile with an exact rule does pick the newest credential.
            let f = AuditTestFixture::from_spec(two_credentials_spec(
                vec![allow_rule("example.com")],
                CredentialSelection::Newest,
            ));
            let signed = signed_credential(f.make_handler().sign(&f.make_ctx(), &f.make_req()));
            assert_eq!(signed, id_b());
        }

        #[test]
        fn wildcard_with_a_single_credential_signs_it() {
            let f = AuditTestFixture::from_spec(FixtureSpec {
                dynamic_grant: true,
                ..FixtureSpec::new(vec![allow_rule(ANY_RP_ID)], vec!["*"])
            });
            let signed = signed_credential(f.make_handler().sign(&f.make_ctx(), &f.make_req()));
            assert_eq!(signed, vec![1u8; 32]);
            let events = read_audit_events(&f.audit_dir);
            let allow = find_policy_events(&events)
                .into_iter()
                .find(|e| e["kind"] == "policy.allow")
                .unwrap();
            assert_eq!(allow["rp_id"], "example.com");
        }

        // --- pure selection functions ---

        fn cand(id: u8, created: i64) -> (Vec<u8>, passless_core::agent::CredentialRef, i64) {
            let id = vec![id; 32];
            let reference = cred_ref_of(&id);
            (id, reference, created)
        }

        #[test]
        fn narrow_candidates_pins_before_allow_credentials() {
            let candidates = vec![cand(1, 0), cand(2, 0), cand(3, 0)];
            let pin = CredentialSelection::Credential(cred_ref_of(&[1u8; 32]));

            let ids = |v: Vec<(Vec<u8>, _, i64)>| v.into_iter().map(|c| c.0[0]).collect::<Vec<_>>();

            assert_eq!(
                ids(SignHandler::narrow_candidates(
                    candidates.clone(),
                    &[],
                    &pin
                )),
                vec![1]
            );
            assert_eq!(
                ids(SignHandler::narrow_candidates(
                    candidates.clone(),
                    &[b64u_encode(&[2u8; 32])],
                    &pin
                )),
                Vec::<u8>::new(),
                "allowCredentials cannot widen a pin"
            );
            assert_eq!(
                ids(SignHandler::narrow_candidates(
                    candidates.clone(),
                    &[b64u_encode(&[2u8; 32]), b64u_encode(&[1u8; 32])],
                    &pin
                )),
                vec![1]
            );
            // Without a pin, allowCredentials narrows.
            assert_eq!(
                ids(SignHandler::narrow_candidates(
                    candidates.clone(),
                    &[b64u_encode(&[3u8; 32])],
                    &CredentialSelection::Single
                )),
                vec![3]
            );
            assert_eq!(
                ids(SignHandler::narrow_candidates(
                    candidates,
                    &[],
                    &CredentialSelection::Newest
                )),
                vec![1, 2, 3]
            );
        }

        #[test]
        fn select_credential_follows_the_selection_rules() {
            let one = vec![cand(9, 5)];
            // Exactly one candidate is used whatever the selection says.
            for selection in [
                CredentialSelection::Single,
                CredentialSelection::FirstMatching,
                CredentialSelection::Newest,
            ] {
                assert_eq!(
                    SignHandler::select_credential(one.clone(), &selection).unwrap(),
                    vec![9; 32]
                );
            }

            let several = vec![cand(3, 1), cand(1, 7), cand(2, 7)];
            assert_eq!(
                SignHandler::select_credential(several.clone(), &CredentialSelection::Single)
                    .unwrap_err()
                    .code,
                ErrorCode::Conflict
            );
            assert_eq!(
                SignHandler::select_credential(
                    several.clone(),
                    &CredentialSelection::FirstMatching
                )
                .unwrap(),
                vec![1; 32]
            );
            // Newest, ties broken by credential id.
            assert_eq!(
                SignHandler::select_credential(several, &CredentialSelection::Newest).unwrap(),
                vec![1; 32]
            );
            assert_eq!(
                SignHandler::select_credential(vec![], &CredentialSelection::Newest)
                    .unwrap_err()
                    .code,
                ErrorCode::NotFound
            );
        }

        // --- localhost (ADR 0014 section 6.1) ---

        fn localhost_spec(rules: Vec<AgentRpRule>, grant: Vec<&'static str>) -> FixtureSpec {
            FixtureSpec {
                credentials: vec![stored(7, "localhost", 0)],
                dynamic_grant: true,
                ..FixtureSpec::new(rules, grant)
            }
        }

        #[test]
        fn localhost_signs_through_an_exact_allow_rule() {
            let f = AuditTestFixture::from_spec(localhost_spec(
                vec![allow_rule("localhost")],
                vec!["localhost"],
            ));
            let signed = signed_credential(
                f.make_handler()
                    .sign(&f.make_ctx(), &f.make_localhost_req()),
            );
            assert_eq!(signed, vec![7; 32]);
            let events = read_audit_events(&f.audit_dir);
            let last = find_policy_events(&events).last().cloned().unwrap().clone();
            assert_eq!(last["kind"], "policy.allow");
            assert_eq!(last["rp_id"], "localhost");
        }

        #[test]
        fn localhost_also_accepts_an_https_origin() {
            let f = AuditTestFixture::from_spec(localhost_spec(
                vec![allow_rule("localhost")],
                vec!["localhost"],
            ));
            let mut req = f.make_localhost_req();
            req.origin = "https://localhost:8443".to_string();
            signed_credential(f.make_handler().sign(&f.make_ctx(), &req));
        }

        #[test]
        fn localhost_is_denied_through_a_wildcard_only_rule() {
            // Resolution: the grant names `localhost`, but only the wildcard rule exists, and the
            // wildcard never matches `localhost`.
            let f = AuditTestFixture::from_spec(localhost_spec(
                vec![allow_rule(ANY_RP_ID)],
                vec!["localhost"],
            ));
            let err = f
                .make_handler()
                .sign(&f.make_ctx(), &f.make_localhost_req())
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::Forbidden);
            assert_eq!(f.key_provider.sign_calls(), 0);
            assert_eq!(
                f.policy_records(),
                vec![("policy.deny".to_string(), Some("action_not_allowed".into()))]
            );
        }

        #[test]
        fn localhost_is_excluded_from_a_wildcard_grant_scope() {
            // The grant scope `*` does not cover `localhost` either (checked before resolution).
            let f = AuditTestFixture::from_spec(localhost_spec(
                vec![allow_rule(ANY_RP_ID), allow_rule("localhost")],
                vec!["*"],
            ));
            let err = f
                .make_handler()
                .sign(&f.make_ctx(), &f.make_localhost_req())
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::Forbidden);
            assert_eq!(f.key_provider.sign_calls(), 0);
            assert_eq!(
                f.policy_records(),
                vec![("policy.deny".to_string(), Some("rp_id_not_match".into()))]
            );
        }

        #[test]
        fn localhost_http_origin_is_rejected_for_another_rp() {
            let f = AuditTestFixture::default_allow();
            let mut req = f.make_req();
            req.origin = "http://localhost:8080".to_string();
            let err = f.make_handler().sign(&f.make_ctx(), &req).unwrap_err();
            assert_eq!(err.code, ErrorCode::OriginInvalid);
            assert_eq!(
                f.policy_records(),
                vec![("policy.deny".to_string(), Some("origin_invalid".into()))]
            );
        }

        #[test]
        fn cross_origin_request_is_denied_and_audited() {
            let f = AuditTestFixture::default_allow();
            let mut req = f.make_req();
            req.origin = "https://example.com".to_string();
            req.top_origin = Some("https://top.example".to_string());
            req.cross_origin = true;
            let err = f.make_handler().sign(&f.make_ctx(), &req).unwrap_err();
            assert_eq!(err.code, ErrorCode::Forbidden);
            assert_eq!(dom_exception_name(err.code), "NotAllowedError");

            let events = read_audit_events(&f.audit_dir);
            let policy_events = find_policy_events(&events);
            assert_eq!(policy_events.len(), 1, "{policy_events:?}");
            assert_eq!(policy_events[0]["kind"], "policy.deny");
            assert_eq!(policy_events[0]["reason"], "cross_origin_denied");
        }

        #[test]
        fn cross_origin_is_denied_even_without_a_top_origin() {
            let f = AuditTestFixture::default_allow();
            let mut req = f.make_req();
            req.cross_origin = true;
            let err = f.make_handler().sign(&f.make_ctx(), &req).unwrap_err();
            assert_eq!(err.code, ErrorCode::Forbidden);
        }

        #[test]
        fn allow_policy_permits_sign() {
            let f = AuditTestFixture::default_allow();
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let req = f.make_req();
            let result = handler.sign(&ctx, &req);
            assert!(result.is_ok());

            let events = read_audit_events(&f.audit_dir);
            let policy_events = find_policy_events(&events);
            assert!(!policy_events.is_empty());
            let last = policy_events.last().unwrap();
            assert_eq!(last["kind"], "policy.allow");
            assert_eq!(last["profile_id"], "test-profile");
            assert_eq!(last["action"], "authenticate");
            assert_eq!(last["rp_id"], "example.com");
        }

        #[test]
        fn deny_authorization_blocks_sign() {
            let f = AuditTestFixture::new(vec![deny_rule("example.com")], vec!["example.com"]);
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let req = f.make_req();
            let result = handler.sign(&ctx, &req);
            assert!(result.is_err());
        }

        #[test]
        fn mixed_policies_per_rp() {
            let f = AuditTestFixture::new(
                vec![allow_rule("example.com"), deny_rule("other.com")],
                vec!["example.com", "other.com"],
            );

            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let mut req_allowed = f.make_req();
            req_allowed.rp_id = "example.com".to_string();
            req_allowed.origin = "https://example.com".to_string();
            let result_allowed = handler.sign(&ctx, &req_allowed);
            assert!(result_allowed.is_ok());

            let handler2 = f.make_handler();
            let ctx2 = f.make_ctx();
            let mut req_denied = f.make_req();
            req_denied.rp_id = "other.com".to_string();
            req_denied.origin = "https://other.com".to_string();
            let result_denied = handler2.sign(&ctx2, &req_denied);
            assert!(result_denied.is_err());
        }

        // --- P5: check order, replay, budget, binding and revocation (ADR 0014 section 9) ---

        impl AuditTestFixture {
            /// Set the live budget. The reload changes the policy, so it revokes every session; the
            /// fixture approves a fresh grant and `make_ctx` binds new sessions at the new epoch.
            fn set_budget(&mut self, max_operations: u16) {
                let mut profile_config = Self::profile_config(&self.spec);
                profile_config.max_operations = max_operations;
                self.policy_runtime
                    .reload(&test_agent_config(profile_config))
                    .unwrap();
                self.grant_id =
                    Self::approve_grant(&self.policy_runtime, &self.profile_id, &self.spec);
            }

            fn req_with_challenge(&self, challenge: &[u8]) -> SignAssertionRequest {
                SignAssertionRequest {
                    challenge_b64u: b64u_encode(challenge),
                    ..self.make_req()
                }
            }

            fn register_handler(&self) -> RegisterHandler {
                RegisterHandler {
                    policy_runtime: self.policy_runtime.clone(),
                    credential_storage: self.storage.clone(),
                    audit_gate: self.audit_gate.clone(),
                    key_provider: self.key_provider.clone(),
                    security_config: self.security_config.clone(),
                    operation_lock: self.operation_lock.clone(),
                    escalation: crate::agent::escalation::test_support::idle_service(
                        self.audit_gate.clone(),
                    ),
                }
            }

            fn reasons(&self) -> Vec<String> {
                self.policy_records()
                    .into_iter()
                    .filter_map(|(_, reason)| reason)
                    .collect()
            }
        }

        fn signature_of(result: &Result<PrincipalResponse, ProtocolError>) -> String {
            match result.as_ref().expect("sign should succeed") {
                PrincipalResponse::SignAssertionResult(resp) => resp.signature_b64u.clone(),
                _ => panic!("expected SignAssertionResult"),
            }
        }

        fn two_rp_fixture() -> AuditTestFixture {
            let mut spec = FixtureSpec::new(
                vec![
                    rule("example.com", RuleAction::Allow, RuleAction::Allow),
                    allow_rule("other.example"),
                    deny_rule("denied.example"),
                ],
                vec!["example.com", "other.example", "denied.example"],
            );
            spec.dynamic_grant = true;
            AuditTestFixture::from_spec(spec)
        }

        #[test]
        fn rejected_requests_never_consume_budget() {
            let mut f = two_rp_fixture();
            f.set_budget(1);
            let handler = f.make_handler();
            let ctx = f.make_ctx();

            for i in 0..5u8 {
                // Origin mismatch.
                let mut req = f.req_with_challenge(&[1, i]);
                req.origin = "https://evil.test".to_string();
                assert_eq!(
                    handler.sign(&ctx, &req).unwrap_err().code,
                    ErrorCode::OriginInvalid
                );
                // A `deny` rule.
                let mut req = f.req_with_challenge(&[2, i]);
                req.rp_id = "denied.example".to_string();
                req.origin = "https://denied.example".to_string();
                assert_eq!(
                    handler.sign(&ctx, &req).unwrap_err().code,
                    ErrorCode::Forbidden
                );
                // An RP outside the session grant.
                let mut req = f.req_with_challenge(&[3, i]);
                req.rp_id = "evil.test".to_string();
                req.origin = "https://evil.test".to_string();
                assert!(handler.sign(&ctx, &req).is_err());
                // A malformed challenge.
                let mut req = f.make_req();
                req.challenge_b64u = "!!".to_string();
                assert_eq!(
                    handler.sign(&ctx, &req).unwrap_err().code,
                    ErrorCode::BadRequest
                );
            }
            assert_eq!(
                ctx.session.operations_used(),
                0,
                "no rejection claimed budget"
            );
            assert_eq!(f.key_provider.sign_calls(), 0);

            // The whole budget is still available to a legitimate request ...
            handler
                .sign(&ctx, &f.req_with_challenge(b"good"))
                .expect("budget intact");
            assert_eq!(ctx.session.operations_used(), 1);
            // ... and then it is used up.
            let err = handler
                .sign(&ctx, &f.req_with_challenge(b"next"))
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::BudgetExhausted);
            assert_eq!(f.reasons().last().unwrap(), "budget_exhausted");
            assert_eq!(f.key_provider.sign_calls(), 1);
        }

        #[test]
        fn budget_limit_is_read_from_the_live_policy() {
            let mut f = AuditTestFixture::default_allow();
            f.set_budget(1);
            let ctx = f.make_ctx();
            let handler = f.make_handler();
            handler.sign(&ctx, &f.req_with_challenge(b"a")).unwrap();
            assert_eq!(
                handler
                    .sign(&ctx, &f.req_with_challenge(b"b"))
                    .unwrap_err()
                    .code,
                ErrorCode::BudgetExhausted
            );
            assert_eq!(
                f.policy_runtime.max_operations(&f.profile_id),
                Some(1),
                "the context carries no copy of the budget"
            );
        }

        #[test]
        fn completed_duplicate_gets_the_original_result_and_is_never_signed_twice() {
            let f = AuditTestFixture::default_allow();
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let first = handler.sign(&ctx, &f.make_req());
            let second = handler.sign(&ctx, &f.make_req());
            assert_eq!(signature_of(&first), signature_of(&second));
            assert_eq!(
                f.key_provider.sign_calls(),
                1,
                "one signature for one replay key"
            );
            assert_eq!(
                ctx.session.operations_used(),
                1,
                "a duplicate claims no budget"
            );
            let allows = f
                .policy_records()
                .iter()
                .filter(|(kind, _)| kind == "policy.allow")
                .count();
            assert_eq!(allows, 1, "one reservation for one replay key");
        }

        #[test]
        fn in_flight_duplicate_joins_and_is_never_signed_twice() {
            let f = AuditTestFixture::default_allow();
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let req = f.make_req();
            let (reached_tx, reached_rx) = std::sync::mpsc::channel::<()>();
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let release_rx = Mutex::new(release_rx);

            std::thread::scope(|scope| {
                let original = scope.spawn(|| {
                    // Park the original between its audit reservation and key use.
                    let _hook =
                        super::super::super::session::test_hooks::set_before_key_use(move || {
                            reached_tx.send(()).unwrap();
                            release_rx.lock().unwrap().recv().unwrap();
                        });
                    handler.sign(&ctx, &req)
                });
                reached_rx.recv().unwrap();
                let (joined_tx, joined_rx) = std::sync::mpsc::channel::<()>();
                let duplicate = scope.spawn(|| {
                    // Proves the duplicate took the join path (not the completed cache).
                    let _join = super::super::super::session::test_hooks::set_on_join(move || {
                        joined_tx.send(()).unwrap();
                    });
                    handler.sign(&ctx, &req)
                });
                joined_rx
                    .recv_timeout(Duration::from_secs(10))
                    .expect("the duplicate joined the in-flight original");
                assert!(
                    !duplicate.is_finished(),
                    "the duplicate waits for the original"
                );
                release_tx.send(()).unwrap();
                let original = original.join().unwrap();
                let duplicate = duplicate.join().unwrap();
                assert_eq!(signature_of(&original), signature_of(&duplicate));
            });
            assert_eq!(f.key_provider.sign_calls(), 1);
            assert_eq!(ctx.session.operations_used(), 1);
            assert!(
                f.policy_records().contains(&(
                    "policy.replay_served".to_string(),
                    Some("replay_served".into())
                )),
                "a served duplicate is audited"
            );
        }

        #[test]
        fn a_detached_duplicate_does_not_affect_the_original() {
            let f = AuditTestFixture::default_allow();
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let req = f.make_req();
            let (reached_tx, reached_rx) = std::sync::mpsc::channel::<()>();
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let release_rx = Mutex::new(release_rx);
            std::thread::scope(|scope| {
                let original = scope.spawn(|| {
                    let _hook =
                        super::super::super::session::test_hooks::set_before_key_use(move || {
                            reached_tx.send(()).unwrap();
                            release_rx.lock().unwrap().recv().unwrap();
                        });
                    handler.sign(&ctx, &req)
                });
                reached_rx.recv().unwrap();
                // The duplicate's client goes away while it waits: it detaches at once. (The
                // first poll is the check before the replay key, which it passes.)
                let polls = std::sync::atomic::AtomicUsize::new(0);
                let detached = handler.sign_with(
                    &ctx,
                    &req,
                    Instant::now() + Duration::from_secs(30),
                    &|| polls.fetch_add(1, Ordering::AcqRel) > 0,
                );
                assert_eq!(detached.unwrap_err().code, ErrorCode::Aborted);
                // A duplicate already cancelled when it arrives stops before the replay key.
                let cancelled = handler.sign_with(
                    &ctx,
                    &req,
                    Instant::now() + Duration::from_secs(30),
                    &|| true,
                );
                assert_eq!(cancelled.unwrap_err().code, ErrorCode::Aborted);
                // A duplicate whose deadline passes detaches too.
                let late = handler.sign_with(&ctx, &req, Instant::now(), &|| false);
                assert_eq!(late.unwrap_err().code, ErrorCode::Timeout);
                release_tx.send(()).unwrap();
                original.join().unwrap().expect("the original completes");
            });
            assert_eq!(f.key_provider.sign_calls(), 1);
        }

        #[test]
        fn a_failure_consumes_the_key_and_is_returned_to_the_duplicate() {
            let f = AuditTestFixture::default_allow();
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let mut req = f.make_req();
            req.allow_credentials = vec![b64u_encode(&[9u8; 32])];
            let first = handler.sign(&ctx, &req).unwrap_err();
            let records_after_first = f.policy_records().len();
            let second = handler.sign(&ctx, &req).unwrap_err();
            assert_eq!(first, second, "the duplicate receives the same failure");
            // The duplicate is not re-evaluated: its only record is the served duplicate.
            let records = f.policy_records();
            assert_eq!(records.len(), records_after_first + 1);
            assert_eq!(records.last().unwrap().0, "policy.replay_served");
            // `allowCredentials` is not part of the replay key: the same action, RP, origin and
            // challenge without it is the same key, and gets the same failure without key use.
            let third = handler.sign(&ctx, &f.make_req()).unwrap_err();
            assert_eq!(third, first);
            assert_eq!(f.key_provider.sign_calls(), 0);
            // The failure ended before key use: the budget was given back (review M2).
            assert_eq!(ctx.session.operations_used(), 0);
        }

        #[test]
        fn same_challenge_with_another_rp_or_action_is_rejected_not_joined() {
            let f = two_rp_fixture();
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            handler.sign(&ctx, &f.make_req()).expect("first use");

            let mut other_rp = f.make_req();
            other_rp.rp_id = "other.example".to_string();
            other_rp.origin = "https://other.example".to_string();
            assert_eq!(
                handler.sign(&ctx, &other_rp).unwrap_err().code,
                ErrorCode::Replayed
            );
            assert_eq!(f.reasons().last().unwrap(), "challenge_reused");

            // A registration on the same bearer session with the same challenge.
            let register_ctx = RegisterContext::new(f.profile_id.clone(), ctx.session.clone());
            let register_req = RegisterCredentialRequest {
                origin: "https://example.com".to_string(),
                top_origin: None,
                rp_id: "example.com".to_string(),
                challenge_b64u: f.make_req().challenge_b64u,
                user_id_b64u: b64u_encode(b"user"),
                user_name: "user".to_string(),
                user_display_name: None,
                rp_name: None,
                exclude_credentials: vec![],
                pub_key_cred_params: vec![-7],
                user_verification: true,
                cross_origin: false,
                extensions: vec![],
                attestation: None,
                timeout_ms: None,
                authenticator_attachment: None,
            };
            assert_eq!(
                f.register_handler()
                    .register(&register_ctx, &register_req)
                    .unwrap_err()
                    .code,
                ErrorCode::Replayed
            );
            assert_eq!(f.key_provider.sign_calls(), 1);
            assert_eq!(ctx.session.operations_used(), 1);
        }

        #[test]
        fn principal_digest_mismatch_is_denied_and_audited() {
            let f = AuditTestFixture::default_allow();
            let mut ctx = f.make_ctx();
            ctx.session = AgentSession::new(super::super::super::session::SessionBinding {
                profile_id: f.profile_id.clone(),
                principal_digest: [9u8; 32],
                revocation_epoch: f.policy_runtime.revocation_epoch(),
                ttl: Duration::from_secs(600),
            });
            let err = f.make_handler().sign(&ctx, &f.make_req()).unwrap_err();
            assert_eq!(err.code, ErrorCode::Forbidden);
            assert_eq!(f.reasons(), vec!["principal_mismatch".to_string()]);
            assert_eq!(f.key_provider.sign_calls(), 0);
            assert_eq!(ctx.session.operations_used(), 0);
        }

        #[test]
        fn changed_reload_revokes_an_in_flight_operation_before_key_use() {
            let f = AuditTestFixture::default_allow();
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let runtime = f.policy_runtime.clone();
            let changed = test_agent_config(AuditTestFixture::profile_config(&FixtureSpec::new(
                vec![allow_rule("example.com"), allow_rule("other.example")],
                vec!["example.com"],
            )));
            let _hook = super::super::super::session::test_hooks::set_before_key_use(move || {
                assert!(runtime.reload(&changed).unwrap().changed);
            });
            let err = handler.sign(&ctx, &f.make_req()).unwrap_err();
            assert_eq!(err.code, ErrorCode::Unauthorized);
            assert_eq!(
                f.key_provider.sign_calls(),
                0,
                "no key use after the reload"
            );
            // The reservation is followed by an audited terminal record.
            assert_eq!(
                f.policy_records(),
                vec![
                    ("policy.allow".to_string(), None),
                    ("policy.deny".to_string(), Some("policy_revoked".into())),
                ]
            );
            // The bearer stays revoked.
            drop(_hook);
            let err = handler
                .sign(&ctx, &f.req_with_challenge(b"again"))
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::Unauthorized);
        }

        #[test]
        fn unchanged_reload_keeps_sessions_and_in_flight_operations() {
            let f = AuditTestFixture::default_allow();
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let runtime = f.policy_runtime.clone();
            let same = test_agent_config(AuditTestFixture::profile_config(&f.spec));
            let hook = super::super::super::session::test_hooks::set_before_key_use(move || {
                assert!(!runtime.reload(&same).unwrap().changed);
            });
            handler
                .sign(&ctx, &f.make_req())
                .expect("an unchanged reload revokes nothing");
            drop(hook);
            handler
                .sign(&ctx, &f.req_with_challenge(b"later"))
                .expect("the session survives an unchanged reload");
            assert_eq!(f.key_provider.sign_calls(), 2);
        }

        #[test]
        fn unsupported_extension_is_not_supported_and_claims_no_budget() {
            let f = AuditTestFixture::default_allow();
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let mut req = f.make_req();
            req.extensions = vec!["prf".to_string()];
            assert_eq!(
                handler.sign(&ctx, &req).unwrap_err().code,
                ErrorCode::NotSupported
            );
            assert_eq!(f.reasons(), vec!["unsupported_option".to_string()]);
            assert_eq!(ctx.session.operations_used(), 0);
            // The browser's `remoteDesktopClientOverride` is stripped by the transport's parse; named
            // as an RP extension it is not supported.
            req.extensions = vec!["remoteDesktopClientOverride".to_string()];
            assert_eq!(
                handler.sign(&ctx, &req).unwrap_err().code,
                ErrorCode::NotSupported
            );
            // `appid` is supported.
            req.extensions = vec!["appid".to_string()];
            handler.sign(&ctx, &req).expect("supported extensions");
            assert_eq!(
                dom_exception_name(ErrorCode::NotSupported),
                "NotSupportedError"
            );
        }

        #[test]
        fn expired_session_is_denied_before_anything_else() {
            let f = AuditTestFixture::default_allow();
            let mut ctx = f.make_ctx();
            ctx.session = AgentSession::new(super::super::super::session::SessionBinding {
                profile_id: f.profile_id.clone(),
                principal_digest: [0u8; 32],
                revocation_epoch: f.policy_runtime.revocation_epoch(),
                ttl: Duration::ZERO,
            });
            let err = f.make_handler().sign(&ctx, &f.make_req()).unwrap_err();
            assert_eq!(err.code, ErrorCode::Unauthorized);
            assert_eq!(f.reasons(), vec!["session_expired".to_string()]);
        }

        #[test]
        fn sign_path_follows_the_lock_order() {
            // Debug builds panic on any out-of-order acquisition (lock_order.rs). A successful
            // ceremony, a reload before key use and a revocation exercise every tracked lock of
            // the sign path; none may be left held.
            let f = AuditTestFixture::default_allow();
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            handler.sign(&ctx, &f.make_req()).unwrap();
            assert!(super::super::super::lock_order::held_levels().is_empty());
            let runtime = f.policy_runtime.clone();
            let changed = test_agent_config(AuditTestFixture::profile_config(&FixtureSpec::new(
                vec![deny_rule("example.com")],
                vec!["example.com"],
            )));
            let hook = super::super::super::session::test_hooks::set_before_key_use(move || {
                runtime.reload(&changed).unwrap();
            });
            assert!(handler.sign(&ctx, &f.req_with_challenge(b"x")).is_err());
            drop(hook);
            assert!(super::super::super::lock_order::held_levels().is_empty());
        }

        // --- P5 review: H1, M1, M2, L3 and negatives ---

        /// Signals that activation was reached, then waits for the release.
        type ActivationGate = (
            Mutex<std::sync::mpsc::Sender<()>>,
            Mutex<std::sync::mpsc::Receiver<()>>,
        );

        /// A lease activation that records calls and can be made to block or fail.
        struct TestActivation {
            calls: std::sync::atomic::AtomicUsize,
            fail: bool,
            gate: Option<ActivationGate>,
        }

        impl LeaseActivation for TestActivation {
            fn activate(&self) -> Result<(), String> {
                self.calls.fetch_add(1, Ordering::AcqRel);
                if let Some((reached, release)) = &self.gate {
                    reached.lock().unwrap().send(()).unwrap();
                    release.lock().unwrap().recv().unwrap();
                }
                if self.fail {
                    Err("lease gone".to_string())
                } else {
                    Ok(())
                }
            }
        }

        #[test]
        fn lease_activation_runs_after_the_operation_lock_is_released() {
            let f = AuditTestFixture::default_allow();
            let handler = f.make_handler();
            let (reached_tx, reached_rx) = std::sync::mpsc::channel::<()>();
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let activation = Arc::new(TestActivation {
                calls: std::sync::atomic::AtomicUsize::new(0),
                fail: false,
                gate: Some((Mutex::new(reached_tx), Mutex::new(release_rx))),
            });
            let mut ctx = f.make_ctx();
            ctx.lease_activation = Some(activation.clone());
            std::thread::scope(|scope| {
                let signer = scope.spawn(|| handler.sign(&ctx, &f.make_req()));
                // The slow browser-manager holder (the activation) is now blocking the ceremony.
                reached_rx.recv().unwrap();
                // A human CTAP operation gets the operation lock at once.
                let started = Instant::now();
                let human = crate::lock_operation(&f.operation_lock);
                assert!(started.elapsed() < Duration::from_secs(1));
                drop(human);
                assert!(!signer.is_finished(), "no assertion before activation");
                release_tx.send(()).unwrap();
                signer.join().unwrap().expect("signed after activation");
            });
            assert_eq!(activation.calls.load(Ordering::Acquire), 1);
        }

        #[test]
        fn failed_lease_activation_withholds_the_assertion() {
            let f = AuditTestFixture::default_allow();
            let handler = f.make_handler();
            let mut ctx = f.make_ctx();
            ctx.lease_activation = Some(Arc::new(TestActivation {
                calls: std::sync::atomic::AtomicUsize::new(0),
                fail: true,
                gate: None,
            }));
            let err = handler.sign(&ctx, &f.make_req()).unwrap_err();
            assert_eq!(err.code, ErrorCode::Internal);
            assert_eq!(f.reasons().last().unwrap(), "lease_activation_failed");
            // The key was used, so the operation counts; a duplicate gets the same failure.
            assert_eq!(ctx.session.operations_used(), 1);
            assert_eq!(handler.sign(&ctx, &f.make_req()).unwrap_err(), err);
        }

        #[test]
        fn sign_path_with_the_real_lease_activation_follows_the_lock_order() {
            // `BrowserLeaseActivation` takes the real (tracked) browser manager after the
            // operation lock is released. Here the lease does not exist, so activation fails
            // and the assertion is withheld; the lock-order checker must not fire.
            let f = AuditTestFixture::default_allow();
            let manager = Arc::new(Mutex::new(
                super::super::super::browser::BrowserProcessManager::new(f.clock.clone()),
            ));
            let mut ctx = f.make_ctx();
            ctx.lease_activation = Some(BrowserLeaseActivation::new(
                manager,
                passless_core::agent::BrowserLeaseId::new(),
                Duration::from_secs(60),
            ));
            let err = f.make_handler().sign(&ctx, &f.make_req()).unwrap_err();
            assert_eq!(err.code, ErrorCode::Internal);
            assert!(super::super::super::lock_order::held_levels().is_empty());
        }

        #[test]
        fn a_revocation_after_the_recheck_waits_for_key_use_and_then_holds() {
            let f = AuditTestFixture::default_allow();
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let (reached_tx, reached_rx) = std::sync::mpsc::channel::<()>();
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let reached_tx = Mutex::new(reached_tx);
            let release_rx = Mutex::new(release_rx);
            let hook: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                reached_tx.lock().unwrap().send(()).unwrap();
                release_rx.lock().unwrap().recv().unwrap();
            });
            f.key_provider.set_on_sign(Some(hook));
            std::thread::scope(|scope| {
                let signer = scope.spawn(|| handler.sign(&ctx, &f.make_req()));
                // The signer is inside key use, past its re-check.
                reached_rx.recv().unwrap();
                let session_revoke = scope.spawn(|| ctx.session.revoke());
                let epoch_bump = scope.spawn(|| f.policy_runtime.bump_revocation_epoch());
                std::thread::sleep(Duration::from_millis(200));
                assert!(!session_revoke.is_finished(), "revoke waits for key use");
                assert!(!epoch_bump.is_finished(), "an epoch bump waits for key use");
                release_tx.send(()).unwrap();
                signer
                    .join()
                    .unwrap()
                    .expect("the signature that was past its re-check");
                session_revoke.join().unwrap();
                epoch_bump.join().unwrap();
            });
            f.key_provider.set_on_sign(None);
            // Once revoke has returned, no later key use by this session.
            let err = handler
                .sign(&ctx, &f.req_with_challenge(b"after"))
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::Unauthorized);
            assert_eq!(f.key_provider.sign_calls(), 1);
        }

        #[test]
        fn failures_before_key_use_never_exhaust_the_budget() {
            let mut f = AuditTestFixture::default_allow();
            f.set_budget(2);
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            for i in 0..6u8 {
                let mut req = f.req_with_challenge(&[b'g', i]);
                req.allow_credentials = vec![b64u_encode(&[0xEE; 32])];
                assert_eq!(
                    handler.sign(&ctx, &req).unwrap_err().code,
                    ErrorCode::Forbidden
                );
            }
            assert_eq!(ctx.session.operations_used(), 0);
            handler
                .sign(&ctx, &f.req_with_challenge(b"ok1"))
                .expect("budget intact");
            handler
                .sign(&ctx, &f.req_with_challenge(b"ok2"))
                .expect("budget intact");
            assert_eq!(f.key_provider.sign_calls(), 2);
        }

        #[test]
        fn a_completed_duplicate_is_not_served_to_a_revoked_session() {
            let f = AuditTestFixture::default_allow();
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            handler.sign(&ctx, &f.make_req()).unwrap();
            ctx.session.revoke();
            let err = handler.sign(&ctx, &f.make_req()).unwrap_err();
            assert_eq!(err.code, ErrorCode::Unauthorized);
        }

        #[test]
        fn a_joined_duplicate_of_a_revoked_session_gets_no_signature() {
            let f = AuditTestFixture::default_allow();
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let req = f.make_req();
            let (reached_tx, reached_rx) = std::sync::mpsc::channel::<()>();
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let release_rx = Mutex::new(release_rx);
            std::thread::scope(|scope| {
                let original = scope.spawn(|| {
                    let _hook =
                        super::super::super::session::test_hooks::set_before_key_use(move || {
                            reached_tx.send(()).unwrap();
                            release_rx.lock().unwrap().recv().unwrap();
                        });
                    handler.sign(&ctx, &req)
                });
                reached_rx.recv().unwrap();
                let (joined_tx, joined_rx) = std::sync::mpsc::channel::<()>();
                let duplicate = scope.spawn(|| {
                    let _join = super::super::super::session::test_hooks::set_on_join(move || {
                        joined_tx.send(()).unwrap();
                    });
                    handler.sign(&ctx, &req)
                });
                joined_rx.recv().unwrap();
                ctx.session.revoke();
                release_tx.send(()).unwrap();
                assert_eq!(
                    original.join().unwrap().unwrap_err().code,
                    ErrorCode::Unauthorized
                );
                assert_eq!(
                    duplicate.join().unwrap().unwrap_err().code,
                    ErrorCode::Unauthorized
                );
            });
            assert_eq!(f.key_provider.sign_calls(), 0);
        }

        #[test]
        fn an_origin_spelled_differently_with_the_same_challenge_is_rejected() {
            let f = AuditTestFixture::default_allow();
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            handler.sign(&ctx, &f.make_req()).unwrap();
            let mut variant = f.make_req();
            variant.origin = "https://EXAMPLE.com".to_string();
            assert_eq!(
                handler.sign(&ctx, &variant).unwrap_err().code,
                ErrorCode::Replayed
            );
            assert_eq!(f.reasons().last().unwrap(), "challenge_reused");
            assert_eq!(f.key_provider.sign_calls(), 1);
        }

        // --- P7: escalation (ADR 0014 section 8) ---

        fn escalation_fixture() -> AuditTestFixture {
            let mut spec = FixtureSpec::new(vec![request_rule("example.com")], vec!["example.com"]);
            spec.escalation = true;
            AuditTestFixture::from_spec(spec)
        }

        type SignResult = Result<PrincipalResponse, ProtocolError>;

        /// Sign on a thread (the ceremony parks until the test decides the prompt).
        fn sign_on_thread(
            f: &AuditTestFixture,
            ctx: &SignContext,
            req: SignAssertionRequest,
        ) -> std::thread::JoinHandle<SignResult> {
            let handler = f.make_handler();
            let ctx = ctx.clone();
            std::thread::spawn(move || handler.sign(&ctx, &req))
        }

        fn kinds(f: &AuditTestFixture) -> Vec<String> {
            read_audit_events(&f.audit_dir)
                .iter()
                .filter_map(|e| e["kind"].as_str().map(str::to_string))
                .filter(|k| k.starts_with("escalation.") || k.starts_with("granted_rule."))
                .collect()
        }

        fn granted(f: &AuditTestFixture) -> usize {
            f.store
                .profile(&f.profile_id)
                .map_or(0, |grants| grants.rules().len())
        }

        #[test]
        fn approved_escalation_persists_the_grant_and_signs_once() {
            let f = escalation_fixture();
            let ctx = f.make_ctx();
            let ceremony = sign_on_thread(&f, &ctx, f.make_req());
            f.prompter.wait_shown(1);
            // The prompt carries only daemon-derived fields.
            let fields = f.prompter.last_fields();
            assert_eq!(fields.rp_id, "example.com");
            assert_eq!(fields.origin, "https://example.com");
            assert_eq!(fields.profile, "test-profile");
            f.prompter.decide(PromptEvent::Approved);
            ceremony.join().unwrap().expect("approved ceremony signs");
            assert_eq!(f.key_provider.sign_calls(), 1);
            assert_eq!(ctx.session.operations_used(), 1, "one budget claim");
            assert_eq!(granted(&f), 1);
            assert_eq!(
                kinds(&f),
                vec![
                    "escalation.requested",
                    "escalation.approved",
                    "granted_rule.add"
                ]
            );
            assert_eq!(f.policy_records(), vec![("policy.allow".to_string(), None)]);

            // The grant now upgrades `request` to `allow`: no further prompt.
            f.make_handler()
                .sign(&ctx, &f.req_with_challenge(b"second"))
                .expect("granted allow");
            assert_eq!(f.prompter.shown(), 1);
            assert_eq!(f.key_provider.sign_calls(), 2);
        }

        #[test]
        fn no_budget_is_claimed_unless_the_escalation_is_approved() {
            // Denied.
            let f = escalation_fixture();
            let ctx = f.make_ctx();
            let ceremony = sign_on_thread(&f, &ctx, f.make_req());
            f.prompter.wait_shown(1);
            f.prompter.decide(PromptEvent::Denied(
                crate::agent::audit_events::EscalationDenyCause::User,
            ));
            let err = ceremony.join().unwrap().unwrap_err();
            assert_eq!(err.code, ErrorCode::Forbidden);
            assert_eq!(ctx.session.operations_used(), 0);
            assert_eq!(f.key_provider.sign_calls(), 0);
            assert_eq!(granted(&f), 0);
            assert_eq!(f.reasons(), vec!["escalation_denied"]);

            // Timed out: the ceremony deadline passes while parked.
            let f = escalation_fixture();
            let ctx = f.make_ctx();
            let handler = f.make_handler();
            let err = handler
                .sign_with(
                    &ctx,
                    &f.make_req(),
                    Instant::now() + Duration::from_millis(300),
                    &|| false,
                )
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::Timeout);
            assert_eq!(ctx.session.operations_used(), 0);
            assert_eq!(f.reasons(), vec!["escalation_expired"]);
            assert!(kinds(&f).contains(&"escalation.expired".to_string()));

            // Aborted by the browser well before the deadline.
            let f = escalation_fixture();
            let ctx = f.make_ctx();
            let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let ceremony = {
                let handler = f.make_handler();
                let ctx = ctx.clone();
                let req = f.make_req();
                let cancel = cancel.clone();
                std::thread::spawn(move || {
                    handler.sign_with(
                        &ctx,
                        &req,
                        Instant::now() + Duration::from_secs(60),
                        &|| cancel.load(Ordering::Acquire),
                    )
                })
            };
            f.prompter.wait_shown(1);
            cancel.store(true, Ordering::Release);
            assert_eq!(
                ceremony.join().unwrap().unwrap_err().code,
                ErrorCode::Aborted
            );
            assert_eq!(ctx.session.operations_used(), 0);
            assert_eq!(f.prompter.withdrawn(), 1, "the prompt is withdrawn");
            // The replay key stays consumed with the abort's outcome.
            assert_eq!(
                f.make_handler().sign(&ctx, &f.make_req()).unwrap_err().code,
                ErrorCode::Aborted
            );
            assert_eq!(f.prompter.shown(), 1);
        }

        #[test]
        fn a_replay_duplicate_joins_the_pending_escalation() {
            let f = escalation_fixture();
            let ctx = f.make_ctx();
            let joined = Arc::new(std::sync::Barrier::new(2));
            let original = sign_on_thread(&f, &ctx, f.make_req());
            f.prompter.wait_shown(1);
            let duplicate = {
                let handler = f.make_handler();
                let ctx = ctx.clone();
                let req = f.make_req();
                let joined = joined.clone();
                std::thread::spawn(move || {
                    let _hook = super::super::super::session::test_hooks::set_on_join(move || {
                        joined.wait();
                    });
                    handler.sign(&ctx, &req)
                })
            };
            joined.wait();
            f.prompter.decide(PromptEvent::Approved);
            let first = original.join().unwrap().expect("original signs");
            let second = duplicate
                .join()
                .unwrap()
                .expect("duplicate gets the outcome");
            assert_eq!(signature_of(&Ok(first)), signature_of(&Ok(second)));
            assert_eq!(f.prompter.shown(), 1, "one prompt");
            assert_eq!(f.key_provider.sign_calls(), 1, "signed once");
            assert_eq!(ctx.session.operations_used(), 1);
            assert_eq!(
                kinds(&f)
                    .iter()
                    .filter(|k| *k == "escalation.requested")
                    .count(),
                1
            );
        }

        #[test]
        fn a_reload_cancels_the_waiter() {
            let f = escalation_fixture();
            let ctx = f.make_ctx();
            let ceremony = sign_on_thread(&f, &ctx, f.make_req());
            f.prompter.wait_shown(1);
            // What `handle_reload_policy` does for a changed reload.
            f.escalation.cancel_profile(&f.profile_id);
            let err = ceremony.join().unwrap().unwrap_err();
            assert_eq!(err.code, ErrorCode::Forbidden);
            assert_eq!(f.reasons(), vec!["policy_revoked"]);
            assert_eq!(f.prompter.withdrawn(), 1);
            assert_eq!(ctx.session.operations_used(), 0);
            assert_eq!(f.key_provider.sign_calls(), 0);
            assert!(kinds(&f).contains(&"escalation.revoked".to_string()));
            assert_eq!(granted(&f), 0);

            // A changed reload also invalidates the waiting session on its own.
            let mut f = escalation_fixture();
            let ctx = f.make_ctx();
            let ceremony = sign_on_thread(&f, &ctx, f.make_req());
            f.prompter.wait_shown(1);
            f.reload_rules(vec![
                request_rule("example.com"),
                allow_rule("other.example"),
            ]);
            let err = ceremony.join().unwrap().unwrap_err();
            assert_eq!(err.code, ErrorCode::Unauthorized);
            assert_eq!(f.reasons(), vec!["policy_revoked"]);
            assert_eq!(f.key_provider.sign_calls(), 0);
        }

        #[test]
        fn an_added_grant_bumps_only_the_grant_epoch() {
            let f = escalation_fixture();
            let ctx = f.make_ctx();
            let revocation = f.policy_runtime.revocation_epoch();
            let grant_epoch = f.policy_runtime.grant_epoch();
            let ceremony = sign_on_thread(&f, &ctx, f.make_req());
            f.prompter.approve(1);
            ceremony.join().unwrap().unwrap();
            assert_eq!(f.policy_runtime.grant_epoch(), grant_epoch + 1);
            assert_eq!(f.policy_runtime.revocation_epoch(), revocation);
            // Active sessions stay valid.
            assert!(
                ctx.session
                    .validity(f.policy_runtime.revocation_epoch(), Instant::now())
                    .is_ok()
            );
        }

        #[test]
        fn a_grant_is_inert_once_its_rule_is_removed() {
            let mut f = escalation_fixture();
            let ceremony = sign_on_thread(&f, &f.make_ctx(), f.make_req());
            f.prompter.approve(1);
            ceremony.join().unwrap().unwrap();
            assert_eq!(granted(&f), 1);

            // The rule is gone: the grant stays stored but permits nothing (ADR 0014 section
            // 6.2), and nothing is prompted.
            f.reload_rules(vec![]);
            let err = f
                .make_handler()
                .sign(&f.make_ctx(), &f.req_with_challenge(b"after removal"))
                .unwrap_err();
            assert_eq!(err.code, ErrorCode::Forbidden);
            assert_eq!(f.reasons().last().unwrap(), "action_not_allowed");
            f.reload_rules(vec![deny_rule("example.com")]);
            assert!(
                f.make_handler()
                    .sign(&f.make_ctx(), &f.req_with_challenge(b"after deny"))
                    .is_err()
            );
            assert_eq!(granted(&f), 1);
            assert_eq!(f.prompter.shown(), 1);
            assert_eq!(f.key_provider.sign_calls(), 1);

            // Restoring the `request` rule revives it without a prompt.
            f.reload_rules(vec![request_rule("example.com")]);
            f.make_handler()
                .sign(&f.make_ctx(), &f.req_with_challenge(b"restored"))
                .expect("the stored grant applies again");
            assert_eq!(f.prompter.shown(), 1);
        }

        #[test]
        fn automatic_interaction_mode_does_not_affect_escalation() {
            // `PASSLESS_INTERACTION_MODE=automatic` auto-approves the human path's prompts only;
            // an escalation still prompts and a deny is still a deny (ADR 0014 section 7, E2E-44).
            // SAFETY: only this test sets the variable; nothing else in the test binary reads it
            // concurrently (the human notification path is never exercised by unit tests).
            unsafe { std::env::set_var("PASSLESS_INTERACTION_MODE", "automatic") };
            let f = escalation_fixture();
            let ctx = f.make_ctx();
            let ceremony = sign_on_thread(&f, &ctx, f.make_req());
            f.prompter.wait_shown(1);
            f.prompter.decide(PromptEvent::Denied(
                crate::agent::audit_events::EscalationDenyCause::User,
            ));
            let result = ceremony.join().unwrap();
            unsafe { std::env::remove_var("PASSLESS_INTERACTION_MODE") };
            assert_eq!(result.unwrap_err().code, ErrorCode::Forbidden);
            assert_eq!(f.prompter.shown(), 1, "prompted, never auto-approved");
            assert_eq!(f.key_provider.sign_calls(), 0);
            assert_eq!(granted(&f), 0);
        }

        #[test]
        fn registration_grant_credentials_join_the_configured_pins() {
            // The profile pins the stored credential 1; credential B exists but is not pinned.
            // A registration grant for B adds it to the pinned set (ADR 0014 section 8.3).
            let f = escalation_fixture();
            let id_b = vec![0xB2u8; 32];
            get_write_counting_storage(&f.storage).add_cred(soft_fido2::Credential {
                id: id_b.clone(),
                rp: RelyingParty::new("example.com".into()),
                user: User::new(vec![9]),
                sign_count: 0,
                alg: -7,
                key: SoftwareCredentialKeyProvider.generate(-7).unwrap().key,
                created: 5,
                discoverable: true,
                backup_state: CredentialBackupState::NotEligible,
                extensions: soft_fido2::Extensions::default(),
            });
            let mut req = f.make_req();
            req.allow_credentials = vec![b64u_encode(&id_b)];

            // An escalation grant for the RP alone does not widen the pins.
            f.store
                .add(
                    &f.policy_runtime,
                    &f.profile_id,
                    crate::agent::granted_rules::GrantedRule::new(
                        "example.com",
                        crate::agent::granted_rules::GrantKind::Escalation,
                        "esc-1",
                        "https://example.com",
                        crate::agent::granted_rules::PermittingRule::Exact,
                        None,
                    ),
                    64,
                )
                .unwrap();
            assert_eq!(
                f.make_handler().sign(&f.make_ctx(), &req).unwrap_err().code,
                ErrorCode::Forbidden
            );
            assert_eq!(f.reasons(), vec!["allow_credentials_mismatch"]);

            f.store
                .add(
                    &f.policy_runtime,
                    &f.profile_id,
                    crate::agent::granted_rules::GrantedRule::new(
                        "example.com",
                        crate::agent::granted_rules::GrantKind::Registration,
                        "esc-2",
                        "https://example.com",
                        crate::agent::granted_rules::PermittingRule::Exact,
                        Some(cred_ref_of(&id_b)),
                    ),
                    64,
                )
                .unwrap();
            let mut req = f.req_with_challenge(b"pinned");
            req.allow_credentials = vec![b64u_encode(&id_b)];
            assert_eq!(
                signed_credential(f.make_handler().sign(&f.make_ctx(), &req)),
                id_b,
                "the registration grant's credential is in the pinned set"
            );
            assert_eq!(f.prompter.shown(), 0);
        }

        #[test]
        fn the_human_operation_lock_is_free_while_a_waiter_is_parked() {
            // LOCKING.md rule 3: a parked escalation waiter holds no lock, so the human CTAP path
            // (which takes the shared operation lock) runs while it waits. The debug lock-order
            // checks run on both threads.
            let f = escalation_fixture();
            let ctx = f.make_ctx();
            let ceremony = sign_on_thread(&f, &ctx, f.make_req());
            f.prompter.wait_shown(1);
            {
                let _human = lock_order::lock(&f.operation_lock, LockLevel::Operation);
                let _storage = lock_order::lock(&f.storage, LockLevel::Storage);
                assert!(!ceremony.is_finished());
            }
            assert!(lock_order::held_levels().is_empty());
            f.prompter.decide(PromptEvent::Approved);
            ceremony.join().unwrap().expect("signs after approval");
        }
    }

    mod registration_lease_tests {
        use super::*;
        use crate::agent::audit::test_support::read_audit_events;
        use crate::agent::transport::tests::{TestServer, create_body};
        use passless_core::agent::protocol::RegisterCredentialRequest;
        use soft_fido2::SoftwareCredentialKeyProvider;

        struct Rig {
            registry: Arc<SignContextRegistry>,
            handler: Arc<RegisterHandler>,
            ctx: RegisterContext,
            storage: Arc<Mutex<Box<dyn CredentialStorage>>>,
            audit_dir: PathBuf,
            _dirs: Vec<tempfile::TempDir>,
        }

        impl Rig {
            fn new() -> Self {
                let audit_tmp = tempfile::tempdir().unwrap();
                let audit_dir = audit_tmp.path().join("audit");
                std::fs::create_dir_all(&audit_dir).unwrap();
                std::fs::set_permissions(&audit_dir, std::fs::Permissions::from_mode(0o700))
                    .unwrap();
                let store_tmp = tempfile::tempdir().unwrap();

                let profile_config = sign_handler_tests::test_profile_config(
                    vec![sign_handler_tests::rule(
                        "example.com",
                        RuleAction::Deny,
                        RuleAction::Allow,
                    )],
                    None,
                    CredentialSelection::Single,
                );
                let clock = Arc::new(sign_handler_tests::MockClock::new());
                let policy_runtime = Arc::new(
                    PolicyRuntime::new(
                        &sign_handler_tests::test_agent_config(profile_config),
                        clock,
                        None,
                    )
                    .unwrap(),
                );
                let storage: Arc<Mutex<Box<dyn CredentialStorage>>> =
                    Arc::new(Mutex::new(Box::new(
                        crate::storage::LocalStorageAdapter::new(store_tmp.path().into()).unwrap(),
                    )));
                let audit_gate = Arc::new(AuditGate::open(&audit_dir).unwrap());
                let handler = Arc::new(RegisterHandler {
                    policy_runtime,
                    credential_storage: storage.clone(),
                    audit_gate: audit_gate.clone(),
                    key_provider: Arc::new(SoftwareCredentialKeyProvider),
                    security_config: SecurityConfig::default(),
                    operation_lock: Arc::new(Mutex::new(())),
                    escalation: crate::agent::escalation::test_support::idle_service(
                        audit_gate.clone(),
                    ),
                });
                let profile_id = ProfileId::new("test-profile").unwrap();
                let ctx = RegisterContext::new(profile_id.clone(), test_session(&profile_id));
                Self {
                    registry: Arc::new(SignContextRegistry::new()),
                    handler,
                    ctx,
                    storage,
                    audit_dir,
                    _dirs: vec![audit_tmp, store_tmp],
                }
            }

            /// Register a bearer, optionally bound to `lease`.
            /// A registration bearer with its own session (one bearer, one session).
            fn bearer(&self, lease: Option<&str>) -> String {
                let token = generate_bearer_token().unwrap();
                let ctx = RegisterContext::new(
                    self.ctx.profile_id.clone(),
                    test_session(&self.ctx.profile_id),
                );
                self.registry
                    .register_pending_registration(token.clone(), ctx, self.handler.clone())
                    .unwrap();
                if let Some(lease) = lease {
                    self.registry
                        .bind_registration_lease(&token, lease.to_string())
                        .unwrap();
                }
                token
            }

            fn credential_count(&self) -> usize {
                self.storage.lock().unwrap().count_credentials()
            }

            fn registration_body(&self, challenge: &str) -> Vec<u8> {
                serde_json::to_vec(&RegisterCredentialRequest {
                    extensions: Vec::new(),
                    attestation: None,
                    timeout_ms: None,
                    authenticator_attachment: None,
                    origin: "https://example.com".to_string(),
                    top_origin: None,
                    rp_id: "example.com".to_string(),
                    challenge_b64u: challenge.to_string(),
                    user_id_b64u: "dXNlcg".to_string(),
                    user_name: "testuser".to_string(),
                    user_display_name: None,
                    rp_name: None,
                    exclude_credentials: vec![],
                    pub_key_cred_params: vec![-7],
                    user_verification: false,
                    cross_origin: false,
                })
                .unwrap()
            }

            fn policy_denies(&self) -> Vec<serde_json::Value> {
                read_audit_events(&self.audit_dir)
                    .into_iter()
                    .filter(|e| e["kind"] == "policy.deny")
                    .collect()
            }
        }

        #[test]
        fn unbound_registration_bearer_is_unusable() {
            let rig = Rig::new();
            let token = rig.bearer(None);
            assert!(rig.registry.lookup_registration(&token).is_none());
            rig.registry
                .bind_registration_lease(&token, "lease-1".into())
                .unwrap();
            assert!(rig.registry.lookup_registration(&token).is_some());
            assert!(
                rig.registry
                    .bind_registration_lease(&token, "lease-2".into())
                    .is_err(),
                "a bearer binds to one lease only"
            );
        }

        #[test]
        fn revoke_by_lease_revokes_registration_bearers_only_for_that_lease() {
            let rig = Rig::new();
            let a = rig.bearer(Some("lease-a"));
            let b = rig.bearer(Some("lease-b"));

            assert_eq!(rig.registry.revoke_by_lease("lease-a"), 1);

            assert!(rig.registry.lookup_registration(&a).is_none());
            assert!(rig.registry.lookup_revoked_registration(&a).is_some());
            assert!(rig.registry.lookup_registration(&b).is_some());
            assert!(rig.registry.lookup_revoked_registration(&b).is_none());
        }

        #[test]
        fn revoke_by_lease_covers_sign_and_registration_bearers_of_one_token() {
            let rig = Rig::new();
            let token = rig.bearer(Some("lease-x"));
            let f = sign_handler_tests::TestFixture::new(true);
            // One bearer, one session: the sign context must share the registration's session.
            let mut ctx = f.make_ctx();
            assert!(
                rig.registry
                    .register_pending(token.clone(), ctx.clone(), Arc::new(f.make_handler()))
                    .is_err(),
                "a second session for one bearer is refused"
            );
            ctx.session = rig
                .registry
                .lookup_registration(&token)
                .unwrap()
                .context
                .session;
            rig.registry
                .register_pending(token.clone(), ctx.clone(), Arc::new(f.make_handler()))
                .unwrap();
            rig.registry.bind_lease(&token, "lease-x".into()).unwrap();

            assert_eq!(rig.registry.revoke_by_lease("lease-x"), 2);
            assert!(ctx.session.is_revoked());
            assert!(rig.registry.lookup_bound(&token).is_none());
            assert!(rig.registry.lookup_registration(&token).is_none());
        }

        #[test]
        fn registration_after_lease_revocation_is_refused_and_audited() {
            let rig = Rig::new();
            let server = TestServer::start(rig.registry.clone());
            let token = rig.bearer(Some("lease-1"));
            let mut client = server.connect();
            client.hello(&token);

            // While the lease is alive, registration works.
            client.request(1, "create", &create_body(b"challenge1"));
            let ok = client.result();
            assert_eq!(ok["ok"], true, "{ok:?}");
            assert_eq!(rig.credential_count(), 1);
            assert!(rig.policy_denies().is_empty());

            // The browser exits / the lease is revoked: the old bearer no longer registers.
            rig.registry.revoke_by_lease("lease-1");
            client.request(2, "create", &create_body(b"challenge2"));
            let refused = client.result();
            assert_eq!(refused["error"]["code"], "unauthorized", "{refused:?}");
            assert_eq!(rig.credential_count(), 1, "no credential may be created");

            let denies = rig.policy_denies();
            assert_eq!(denies.len(), 1, "{denies:?}");
            assert_eq!(denies[0]["action"], "register");
            assert_eq!(denies[0]["reason"], "bearer_revoked");
            assert_eq!(denies[0]["profile_id"], "test-profile");
            assert_eq!(denies[0]["rp_id"], "example.com");
        }

        #[test]
        fn request_in_flight_when_the_lease_is_revoked_creates_no_credential() {
            let rig = Rig::new();
            let token = rig.bearer(Some("lease-inflight"));
            // The request has passed authentication (the entry is in hand) ...
            let entry = rig.registry.lookup_registration(&token).unwrap();
            // ... when the browser exits.
            rig.registry.revoke_by_lease("lease-inflight");

            let req: RegisterCredentialRequest =
                serde_json::from_slice(&rig.registration_body("Y2hhbGxlbmdl")).unwrap();
            let err = entry.handler.register(&entry.context, &req).unwrap_err();

            assert_eq!(err.code, ErrorCode::Unauthorized);
            assert_eq!(rig.credential_count(), 0);
            let denies = rig.policy_denies();
            assert_eq!(denies.len(), 1, "{denies:?}");
            assert_eq!(denies[0]["reason"], "bearer_revoked");
        }

        #[test]
        fn unknown_registration_bearer_is_refused_without_audit() {
            let rig = Rig::new();
            let server = TestServer::start(rig.registry.clone());
            let token = generate_bearer_token().unwrap();
            let mut client = server.connect();
            let refused = client.hello_with(&token, true);
            assert_eq!(refused["code"], "unauthorized", "{refused:?}");
            assert!(client.closed());
            assert!(rig.policy_denies().is_empty());
        }

        #[test]
        fn refusals_of_a_revoked_bearer_are_audited_at_most_a_bounded_number_of_times() {
            let rig = Rig::new();
            let server = TestServer::start(rig.registry.clone());
            let token = rig.bearer(Some("lease-flood"));
            let mut client = server.connect();
            client.hello(&token);
            rig.registry.revoke_by_lease("lease-flood");

            let attempts = MAX_AUDITED_REFUSALS_PER_BEARER + 4;
            for i in 0..attempts {
                client.request(
                    i as u32 + 1,
                    "create",
                    &create_body(format!("challenge{i}").as_bytes()),
                );
                let refused = client.result();
                assert_eq!(refused["error"]["code"], "unauthorized", "{refused:?}");
            }
            assert_eq!(rig.policy_denies().len(), MAX_AUDITED_REFUSALS_PER_BEARER);
            assert_eq!(rig.credential_count(), 0);
        }

        #[test]
        fn revoked_registration_memory_is_bounded() {
            let rig = Rig::new();
            let mut first = None;
            for i in 0..(MAX_REVOKED_REGISTRATIONS + 8) {
                let token = rig.bearer(Some(&format!("lease-{i}")));
                rig.registry.revoke_registration(&token);
                first.get_or_insert(token);
            }
            let remembered = rig.registry.revoked_registrations.lock().unwrap();
            assert_eq!(remembered.entries.len(), MAX_REVOKED_REGISTRATIONS);
            let first = first.unwrap();
            assert!(!remembered.entries.contains_key(&first));
            drop(remembered);
            // The evicted bearer is gone from the live map as well, so it is still refused (as unknown).
            assert!(rig.registry.lookup_registration(&first).is_none());
        }
    }
}
