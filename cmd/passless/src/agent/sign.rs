use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use log::{debug, warn};
use sha2::{Digest, Sha256};

use passless_core::agent::config::{ANY_RP_ID, CredentialSelection};
use passless_core::agent::protocol::{
    ErrorCode, PrincipalResponse, ProtocolError, RecommendedAction, RegisterCredentialRequest,
    SignAssertionRequest, SignAssertionResponse,
};
use passless_core::agent::{AgentProfileConfig, CredentialRef, ProfileId};
use passless_core::config::SecurityConfig;

use super::audit::AuditGate;
use super::audit_events::{AuditAction, PolicyAllowBuilder, PolicyDenyBuilder, PolicyDenyReason};
use super::policy_engine::PolicyRuntime;
use super::register::{RegisterContext, RegisterHandler};

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

pub struct ParsedOrigin {
    pub host: String,
    pub port: Option<u16>,
}

pub fn parse_origin(origin: &str) -> Option<ParsedOrigin> {
    let rest = origin.strip_prefix("https://")?;
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
    if host_part.contains(':') {
        let (host, port_str) = host_part.rsplit_once(':').unwrap();
        if host.is_empty() {
            return None;
        }
        let port: u16 = port_str.parse().ok()?;
        Some(ParsedOrigin {
            host: host.to_ascii_lowercase(),
            port: Some(port),
        })
    } else {
        Some(ParsedOrigin {
            host: host_part.to_ascii_lowercase(),
            port: None,
        })
    }
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
    if cross_origin {
        return top_origin.and_then(parse_origin).is_some();
    }
    match top_origin {
        Some(top) => parse_origin(top).is_some_and(|parsed| {
            parse_origin(origin)
                .is_some_and(|frame| parsed.host == frame.host && parsed.port == frame.port)
        }),
        None => true,
    }
}

fn normalize_rp_id(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
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

#[derive(Debug, Clone)]
struct InFlightOutcome {
    status: &'static str,
    body: Vec<u8>,
}

#[derive(Debug)]
enum InFlightState {
    Pending,
    Resolved(InFlightOutcome),
}

#[derive(Debug)]
struct InFlightEntry {
    state: Mutex<InFlightState>,
    done: Condvar,
}

impl InFlightEntry {
    fn new() -> Self {
        Self {
            state: Mutex::new(InFlightState::Pending),
            done: Condvar::new(),
        }
    }

    fn resolve(&self, outcome: InFlightOutcome) {
        let mut s = match self.state.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        *s = InFlightState::Resolved(outcome);
        self.done.notify_all();
    }

    fn wait(&self, timeout: Duration) -> Option<InFlightOutcome> {
        let guard = match self.state.lock() {
            Ok(g) => g,
            Err(_) => return None,
        };
        let (guard, timed_out) = match self
            .done
            .wait_timeout_while(guard, timeout, |s| matches!(s, InFlightState::Pending))
        {
            Ok(pair) => pair,
            Err(_) => return None,
        };
        if timed_out.timed_out() {
            return None;
        }
        match &*guard {
            InFlightState::Resolved(o) => Some(o.clone()),
            InFlightState::Pending => None,
        }
    }
}

// Completed-outcome cache: some relying parties (e.g. Kanidm) submit the same
// WebAuthn request body more than once for a single user gesture. The first
// request is signed; an identical follow-up must receive the SAME outcome rather
// than a `replayed_operation` rejection, otherwise the user-facing ceremony fails.
//
// Safety: a cached outcome is returned without re-signing, so the sign counter is
// incremented exactly once and no new signature is produced. The real replay
// defence remains the relying party's one-time challenge. After the TTL elapses an
// identical body is rejected as `Replayed` as before.
const COMPLETED_OUTCOME_TTL: Duration = Duration::from_secs(120);
const MAX_COMPLETED_OUTCOMES: usize = 256;

struct CompletedOutcome {
    outcome: InFlightOutcome,
    at: Instant,
}

struct RequestBudgetInner {
    used: HashSet<[u8; 32]>,
    in_flight: HashMap<[u8; 32], Arc<InFlightEntry>>,
    completed: HashMap<[u8; 32], CompletedOutcome>,
}

#[derive(Clone)]
struct RequestBudget {
    inner: Arc<Mutex<RequestBudgetInner>>,
    max_requests: usize,
}

impl RequestBudget {
    fn claim(&self, body: &[u8]) -> RequestClaim {
        let hash = Sha256::digest(body);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&hash);

        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return RequestClaim::Unavailable,
        };

        if inner.used.contains(&digest) {
            if let Some(entry) = inner.in_flight.get(&digest) {
                return RequestClaim::WaitFor(entry.clone());
            }
            let now = Instant::now();
            if let Some(completed) = inner.completed.get(&digest)
                && now.duration_since(completed.at) <= COMPLETED_OUTCOME_TTL
            {
                return RequestClaim::Cached {
                    outcome: completed.outcome.clone(),
                };
            }
            return RequestClaim::Replayed;
        }

        if inner.used.len() >= self.max_requests {
            return RequestClaim::Exhausted;
        }

        inner.used.insert(digest);
        let entry = Arc::new(InFlightEntry::new());
        inner.in_flight.insert(digest, entry);
        RequestClaim::Claimed { digest }
    }

    fn resolve(&self, digest: [u8; 32], outcome: InFlightOutcome) {
        let entry = {
            let mut inner = match self.inner.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            let entry = inner.in_flight.remove(&digest);
            let now = Instant::now();
            inner
                .completed
                .retain(|_, completed| now.duration_since(completed.at) <= COMPLETED_OUTCOME_TTL);
            if inner.completed.len() >= MAX_COMPLETED_OUTCOMES
                && let Some(oldest) = inner
                    .completed
                    .iter()
                    .min_by_key(|(_, completed)| completed.at)
                    .map(|(digest, _)| *digest)
            {
                inner.completed.remove(&oldest);
            }
            inner.completed.insert(
                digest,
                CompletedOutcome {
                    outcome: outcome.clone(),
                    at: now,
                },
            );
            entry
        };
        if let Some(entry) = entry {
            entry.resolve(outcome);
        }
    }
}

struct InFlightGuard {
    budget: RequestBudget,
    digest: [u8; 32],
    resolved: bool,
}

impl InFlightGuard {
    fn new(budget: RequestBudget, digest: [u8; 32]) -> Self {
        Self {
            budget,
            digest,
            resolved: false,
        }
    }

    fn resolve(&mut self, outcome: InFlightOutcome) {
        self.budget.resolve(self.digest, outcome);
        self.resolved = true;
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if !self.resolved {
            self.budget.resolve(
                self.digest,
                InFlightOutcome {
                    status: "500 Internal Server Error",
                    body: b"{\"error\":\"internal_error\"}".to_vec(),
                },
            );
        }
    }
}

#[derive(Clone)]
pub struct LeaseEntry {
    pub context: SignContext,
    pub handler: Arc<SignHandler>,
    pub lease_id: Option<String>,
    request_budget: RequestBudget,
}

impl LeaseEntry {
    fn claim_request(&self, body: &[u8]) -> RequestClaim {
        self.request_budget.claim(body)
    }
}

pub struct SignContextRegistry {
    entries: Mutex<HashMap<String, LeaseEntry>>,
    registration_entries: Mutex<HashMap<String, RegistrationLeaseEntry>>,
    request_budgets: Mutex<HashMap<String, RequestBudget>>,
}

#[derive(Clone)]
pub struct RegistrationLeaseEntry {
    pub context: RegisterContext,
    pub handler: Arc<RegisterHandler>,
    request_budget: RequestBudget,
}

impl RegistrationLeaseEntry {
    fn claim_request(&self, body: &[u8]) -> RequestClaim {
        self.request_budget.claim(body)
    }
}

#[derive(Debug, Clone)]
enum RequestClaim {
    Claimed { digest: [u8; 32] },
    Replayed,
    Exhausted,
    Unavailable,
    WaitFor(Arc<InFlightEntry>),
    Cached { outcome: InFlightOutcome },
}

impl SignContextRegistry {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            registration_entries: Mutex::new(HashMap::new()),
            request_budgets: Mutex::new(HashMap::new()),
        }
    }

    fn request_budget(&self, token: &str, max_requests: usize) -> Result<RequestBudget, String> {
        let mut budgets = self
            .request_budgets
            .lock()
            .map_err(|_| "registry lock poisoned")?;
        if let Some(existing) = budgets.get(token) {
            if existing.max_requests != max_requests {
                return Err("operation budget mismatch".into());
            }
            return Ok(existing.clone());
        }
        let budget = RequestBudget {
            inner: Arc::new(Mutex::new(RequestBudgetInner {
                used: HashSet::new(),
                in_flight: HashMap::new(),
                completed: HashMap::new(),
            })),
            max_requests,
        };
        budgets.insert(token.to_string(), budget.clone());
        Ok(budget)
    }

    pub fn register_pending_registration(
        &self,
        token: String,
        context: RegisterContext,
        handler: Arc<RegisterHandler>,
    ) -> Result<(), String> {
        let max_requests = usize::from(context.profile_config.max_operations);
        let request_budget = self.request_budget(&token, max_requests)?;
        let mut map = self
            .registration_entries
            .lock()
            .map_err(|_| "registry lock poisoned")?;
        if map.contains_key(&token) {
            return Err("duplicate token".into());
        }
        map.insert(
            token,
            RegistrationLeaseEntry {
                context,
                handler,
                request_budget,
            },
        );
        Ok(())
    }

    pub fn lookup_registration(&self, token: &str) -> Option<RegistrationLeaseEntry> {
        let map = match self.registration_entries.lock() {
            Ok(m) => m,
            Err(_) => return None,
        };
        for (k, v) in map.iter() {
            if constant_time_eq(token.as_bytes(), k.as_bytes()) {
                return Some(v.clone());
            }
        }
        None
    }

    pub fn revoke_registration(&self, token: &str) -> bool {
        let removed = self
            .registration_entries
            .lock()
            .map(|mut map| map.remove(token).is_some())
            .unwrap_or(false);
        self.cleanup_request_budget(token);
        removed
    }

    pub fn register_pending(
        &self,
        token: String,
        context: SignContext,
        handler: Arc<SignHandler>,
    ) -> Result<(), String> {
        let max_requests = usize::from(context.profile_config.max_operations);
        let request_budget = self.request_budget(&token, max_requests)?;
        let mut map = self.entries.lock().map_err(|_| "registry lock poisoned")?;
        if map.contains_key(&token) {
            return Err("duplicate token".into());
        }
        map.insert(
            token,
            LeaseEntry {
                context,
                handler,
                lease_id: None,
                request_budget,
            },
        );
        Ok(())
    }

    fn cleanup_request_budget(&self, token: &str) {
        let sign_active = self
            .entries
            .lock()
            .map(|map| map.contains_key(token))
            .unwrap_or(true);
        let registration_active = self
            .registration_entries
            .lock()
            .map(|map| map.contains_key(token))
            .unwrap_or(true);
        if !sign_active
            && !registration_active
            && let Ok(mut budgets) = self.request_budgets.lock()
        {
            budgets.remove(token);
        }
    }

    pub fn bind_lease(&self, token: &str, lease_id: String) -> Result<(), String> {
        let mut map = self.entries.lock().map_err(|_| "registry lock poisoned")?;
        if !map.contains_key(token) {
            return Err("token not found".into());
        }
        if map.get(token).unwrap().lease_id.is_some() {
            return Err("already bound".into());
        }
        map.get_mut(token).unwrap().lease_id = Some(lease_id);
        Ok(())
    }

    pub fn lookup_bound(&self, token: &str) -> Option<LeaseEntry> {
        let map = match self.entries.lock() {
            Ok(m) => m,
            Err(_) => return None,
        };
        let mut found_key: Option<String> = None;
        for k in map.keys() {
            if constant_time_eq(token.as_bytes(), k.as_bytes()) {
                found_key = Some(k.clone());
            }
        }
        match found_key {
            Some(key) => {
                let entry = map.get(&key)?;
                entry.lease_id.is_some().then(|| entry.clone())
            }
            None => None,
        }
    }

    pub fn revoke(&self, token: &str) -> bool {
        let removed = self
            .entries
            .lock()
            .map(|mut map| map.remove(token).is_some())
            .unwrap_or(false);
        self.cleanup_request_budget(token);
        removed
    }

    pub fn revoke_by_lease(&self, lease_id: &str) -> usize {
        let mut map = match self.entries.lock() {
            Ok(m) => m,
            Err(_) => return 0,
        };
        let keys: Vec<String> = map
            .iter()
            .filter(|(_, e)| e.lease_id.as_deref() == Some(lease_id))
            .map(|(k, _)| k.clone())
            .collect();
        let count = keys.len();
        for k in &keys {
            map.remove(k);
        }
        drop(map);
        for key in keys {
            self.cleanup_request_budget(&key);
        }
        count
    }

    pub fn revoke_all(&self) {
        if let Ok(mut map) = self.entries.lock() {
            map.clear();
        }
        if let Ok(mut map) = self.registration_entries.lock() {
            map.clear();
        }
        if let Ok(mut budgets) = self.request_budgets.lock() {
            budgets.clear();
        }
    }

    pub fn len(&self) -> usize {
        self.entries.lock().map(|m| m.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn budget_snapshot_for_lease(&self, lease_id: &str) -> Option<(usize, usize)> {
        let budget = {
            let map = self.entries.lock().ok()?;
            let entry = map
                .values()
                .find(|entry| entry.lease_id.as_deref() == Some(lease_id))?;
            entry.request_budget.clone()
        };
        let used = budget.inner.lock().ok()?.used.len();
        Some((used, budget.max_requests))
    }

    #[cfg(test)]
    pub fn all_entries(&self) -> Vec<LeaseEntry> {
        let map = match self.entries.lock() {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };
        map.values().cloned().collect()
    }
}

impl Default for SignContextRegistry {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SignHttpServer {
    listener: Option<UnixListener>,
    socket_path: PathBuf,
    shutdown: Arc<AtomicBool>,
}

const MAX_HTTP_BODY_SIZE: usize = 16_384;
const MAX_HTTP_HEADER_SIZE: usize = 8192;
const MAX_CONNECTIONS: usize = 8;

impl SignHttpServer {
    pub fn bind(socket_path: PathBuf, shutdown: Arc<AtomicBool>) -> Result<Self, String> {
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create socket directory: {}", e))?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("set socket dir permissions: {}", e))?;
        }
        let _ = std::fs::remove_file(&socket_path);
        let listener =
            UnixListener::bind(&socket_path).map_err(|e| format!("bind failed: {}", e))?;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("set socket permissions: {}", e))?;
        Ok(Self {
            listener: Some(listener),
            socket_path,
            shutdown,
        })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }

    pub fn serve(mut self, registry: Arc<SignContextRegistry>) -> thread::JoinHandle<()> {
        let shutdown = self.shutdown.clone();
        let listener = self.listener.take().expect("listener already taken");
        let socket_path = self.socket_path.clone();
        thread::spawn(move || {
            listener.set_nonblocking(true).expect("set_nonblocking");
            let active_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            loop {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        let current = active_count.load(Ordering::Acquire);
                        if current >= MAX_CONNECTIONS {
                            continue;
                        }
                        active_count.fetch_add(1, Ordering::AcqRel);
                        let registry = registry.clone();
                        let count = active_count.clone();
                        thread::spawn(move || {
                            if let Err(e) = handle_http_connection(stream, &registry) {
                                debug!("sign http connection error: {}", e);
                            }
                            count.fetch_sub(1, Ordering::AcqRel);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(50));
                    }
                    Err(e) => {
                        warn!("sign http accept error: {}", e);
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }
            let _ = std::fs::remove_file(&socket_path);
        })
    }
}

impl Drop for SignHttpServer {
    fn drop(&mut self) {
        if self.listener.is_some() {
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }
}

fn send_http_response(stream: &mut UnixStream, status: &str, body: Option<&[u8]>) {
    let content_length = body.map(|b| b.len()).unwrap_or(0);
    let header = format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        status, content_length
    );
    let _ = stream.write_all(header.as_bytes());
    if let Some(body) = body {
        let _ = stream.write_all(body);
    }
}

fn send_http_error(stream: &mut UnixStream, status: &str, code: &str) {
    let body = format!("{{\"error\":\"{}\"}}", code);
    send_http_response(stream, status, Some(body.as_bytes()));
}

fn send_sign_response(stream: &mut UnixStream, status: &str, body: Option<&[u8]>) {
    let content_length = body.map(|b| b.len()).unwrap_or(0);
    let header = format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        status, content_length
    );
    let _ = stream.write_all(header.as_bytes());
    if let Some(body) = body {
        let _ = stream.write_all(body);
    }
}

fn send_sign_error(stream: &mut UnixStream, status: &str, code: &str) {
    let body = format!("{{\"error\":\"{}\"}}", code);
    send_sign_response(stream, status, Some(body.as_bytes()));
}

fn handle_http_connection(
    mut stream: UnixStream,
    registry: &SignContextRegistry,
) -> Result<(), String> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let mut buf = [0u8; MAX_HTTP_HEADER_SIZE + MAX_HTTP_BODY_SIZE];
    let mut total = 0;
    loop {
        let n = stream
            .read(&mut buf[total..])
            .map_err(|e| format!("read: {}", e))?;
        if n == 0 {
            return Err("connection closed before headers complete".into());
        }
        total += n;
        if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if total >= MAX_HTTP_HEADER_SIZE {
            send_http_error(&mut stream, "413 Payload Too Large", "request_too_large");
            return Ok(());
        }
    }
    let header_end = buf[..total]
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no header terminator")?;
    let header_str = std::str::from_utf8(&buf[..header_end]).map_err(|_| "invalid utf-8")?;
    let mut lines = header_str.split("\r\n");
    let request_line = lines.next().ok_or("no request line")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("no method")?;
    let path = parts.next().ok_or("no path")?;
    if method != "POST" || (path != "/sign" && path != "/register") {
        send_http_error(&mut stream, "404 Not Found", "not_found");
        return Ok(());
    }
    let mut auth_header = None;
    let mut content_type_header = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("authorization:") {
            auth_header = Some(
                line.split_once(':')
                    .map(|x| x.1)
                    .unwrap_or("")
                    .trim()
                    .to_string(),
            );
        } else if lower.starts_with("content-type:") {
            content_type_header = Some(
                line.split_once(':')
                    .map(|x| x.1)
                    .unwrap_or("")
                    .trim()
                    .to_string(),
            );
        }
    }
    let auth = match auth_header {
        Some(a) => a,
        None => {
            send_sign_error(&mut stream, "401 Unauthorized", "missing_authorization");
            return Ok(());
        }
    };
    let token = match auth.strip_prefix("Bearer ") {
        Some(t) => t,
        None => {
            send_sign_error(
                &mut stream,
                "401 Unauthorized",
                "invalid_authorization_scheme",
            );
            return Ok(());
        }
    };
    let is_register = path == "/register";
    let entry = match if is_register {
        None
    } else {
        registry.lookup_bound(token)
    } {
        Some(e) => e,
        None => {
            if is_register {
                let reg_entry = match registry.lookup_registration(token) {
                    Some(e) => e,
                    None => {
                        send_sign_error(&mut stream, "401 Unauthorized", "invalid_bearer");
                        return Ok(());
                    }
                };
                if let Some(ct) = content_type_header
                    && !ct.to_ascii_lowercase().starts_with("application/json")
                {
                    send_sign_error(
                        &mut stream,
                        "415 Unsupported Media Type",
                        "unsupported_content_type",
                    );
                    return Ok(());
                }
                let body_start = header_end + 4;
                let content_length: usize = header_str
                    .lines()
                    .find_map(|l| {
                        let lower = l.to_ascii_lowercase();
                        lower
                            .strip_prefix("content-length:")
                            .and_then(|v| v.trim().parse().ok())
                    })
                    .unwrap_or(0);
                if content_length > MAX_HTTP_BODY_SIZE {
                    send_sign_error(&mut stream, "413 Payload Too Large", "body_too_large");
                    return Ok(());
                }
                let mut body = Vec::new();
                body.extend_from_slice(&buf[body_start..total]);
                let remaining = content_length.saturating_sub(total - body_start);
                if remaining > 0 {
                    if remaining > MAX_HTTP_BODY_SIZE {
                        send_sign_error(&mut stream, "413 Payload Too Large", "body_too_large");
                        return Ok(());
                    }
                    let mut extra = vec![0u8; remaining];
                    stream
                        .read_exact(&mut extra)
                        .map_err(|e| format!("read body: {}", e))?;
                    body.extend_from_slice(&extra);
                }
                if body.len() > MAX_HTTP_BODY_SIZE {
                    send_sign_error(&mut stream, "413 Payload Too Large", "body_too_large");
                    return Ok(());
                }
                match reg_entry.claim_request(&body) {
                    RequestClaim::Claimed { digest } => {
                        let mut guard =
                            InFlightGuard::new(reg_entry.request_budget.clone(), digest);
                        let outcome = handle_register_body(&mut stream, &reg_entry, &body)?;
                        guard.resolve(outcome);
                    }
                    RequestClaim::WaitFor(in_flight) => {
                        match in_flight.wait(Duration::from_secs(30)) {
                            Some(outcome) => {
                                send_sign_response(
                                    &mut stream,
                                    outcome.status,
                                    Some(&outcome.body),
                                );
                            }
                            None => {
                                send_sign_error(
                                    &mut stream,
                                    "500 Internal Server Error",
                                    "operation_timeout",
                                );
                            }
                        }
                        return Ok(());
                    }
                    RequestClaim::Cached { outcome } => {
                        send_sign_response(&mut stream, outcome.status, Some(&outcome.body));
                        return Ok(());
                    }
                    RequestClaim::Replayed => {
                        send_sign_error(&mut stream, "409 Conflict", "replayed_operation");
                        return Ok(());
                    }
                    RequestClaim::Exhausted => {
                        send_sign_error(
                            &mut stream,
                            "429 Too Many Requests",
                            "operation_budget_exhausted",
                        );
                        return Ok(());
                    }
                    RequestClaim::Unavailable => {
                        send_sign_error(
                            &mut stream,
                            "500 Internal Server Error",
                            "operation_registry_unavailable",
                        );
                        return Ok(());
                    }
                }
                return Ok(());
            }
            send_sign_error(&mut stream, "401 Unauthorized", "invalid_bearer");
            return Ok(());
        }
    };
    if is_register {
        send_sign_error(
            &mut stream,
            "400 Bad Request",
            "sign_token_not_for_register",
        );
        return Ok(());
    }
    if let Some(ct) = content_type_header
        && !ct.to_ascii_lowercase().starts_with("application/json")
    {
        send_sign_error(
            &mut stream,
            "415 Unsupported Media Type",
            "unsupported_content_type",
        );
        return Ok(());
    }
    let body_start = header_end + 4;
    let content_length: usize = header_str
        .lines()
        .find_map(|l| {
            let lower = l.to_ascii_lowercase();
            lower
                .strip_prefix("content-length:")
                .and_then(|v| v.trim().parse().ok())
        })
        .unwrap_or(0);
    if content_length > MAX_HTTP_BODY_SIZE {
        send_sign_error(&mut stream, "413 Payload Too Large", "body_too_large");
        return Ok(());
    }
    let mut body = Vec::new();
    body.extend_from_slice(&buf[body_start..total]);
    let remaining = content_length.saturating_sub(total - body_start);
    if remaining > 0 {
        if remaining > MAX_HTTP_BODY_SIZE {
            send_sign_error(&mut stream, "413 Payload Too Large", "body_too_large");
            return Ok(());
        }
        let mut extra = vec![0u8; remaining];
        stream
            .read_exact(&mut extra)
            .map_err(|e| format!("read body: {}", e))?;
        body.extend_from_slice(&extra);
    }
    if body.len() > MAX_HTTP_BODY_SIZE {
        send_sign_error(&mut stream, "413 Payload Too Large", "body_too_large");
        return Ok(());
    }
    match entry.claim_request(&body) {
        RequestClaim::Claimed { digest } => {
            let mut guard = InFlightGuard::new(entry.request_budget.clone(), digest);
            let outcome = handle_sign_body(&mut stream, &entry, &body)?;
            guard.resolve(outcome);
        }
        RequestClaim::WaitFor(in_flight) => {
            match in_flight.wait(Duration::from_secs(30)) {
                Some(outcome) => {
                    send_sign_response(&mut stream, outcome.status, Some(&outcome.body));
                }
                None => {
                    send_sign_error(
                        &mut stream,
                        "500 Internal Server Error",
                        "operation_timeout",
                    );
                }
            }
            return Ok(());
        }
        RequestClaim::Cached { outcome } => {
            send_sign_response(&mut stream, outcome.status, Some(&outcome.body));
            return Ok(());
        }
        RequestClaim::Replayed => {
            send_sign_error(&mut stream, "409 Conflict", "replayed_operation");
            return Ok(());
        }
        RequestClaim::Exhausted => {
            send_sign_error(
                &mut stream,
                "429 Too Many Requests",
                "operation_budget_exhausted",
            );
            return Ok(());
        }
        RequestClaim::Unavailable => {
            send_sign_error(
                &mut stream,
                "500 Internal Server Error",
                "operation_registry_unavailable",
            );
            return Ok(());
        }
    }
    Ok(())
}

fn handle_sign_body(
    stream: &mut UnixStream,
    entry: &LeaseEntry,
    body: &[u8],
) -> Result<InFlightOutcome, String> {
    let req: SignAssertionRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(_) => {
            let outcome = InFlightOutcome {
                status: "400 Bad Request",
                body: b"{\"error\":\"invalid_json\"}".to_vec(),
            };
            send_sign_response(stream, outcome.status, Some(&outcome.body));
            return Ok(outcome);
        }
    };
    let outcome = match entry.handler.sign(&entry.context, &req) {
        Ok(resp) => {
            let resp_body =
                serde_json::to_vec(&resp).map_err(|e| format!("json serialize: {}", e))?;
            send_sign_response(stream, "200 OK", Some(&resp_body));
            InFlightOutcome {
                status: "200 OK",
                body: resp_body,
            }
        }
        Err(e) => {
            let (status, code) = error_status_code(e.code);
            let err_body = format!("{{\"error\":\"{}\"}}", code).into_bytes();
            send_sign_response(stream, status, Some(&err_body));
            InFlightOutcome {
                status,
                body: err_body,
            }
        }
    };
    Ok(outcome)
}

fn handle_register_body(
    stream: &mut UnixStream,
    reg_entry: &RegistrationLeaseEntry,
    body: &[u8],
) -> Result<InFlightOutcome, String> {
    let req: RegisterCredentialRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(_) => {
            let outcome = InFlightOutcome {
                status: "400 Bad Request",
                body: b"{\"error\":\"invalid_json\"}".to_vec(),
            };
            send_sign_response(stream, outcome.status, Some(&outcome.body));
            return Ok(outcome);
        }
    };
    let outcome = match reg_entry.handler.register(&reg_entry.context, &req) {
        Ok(resp) => {
            let resp_body =
                serde_json::to_vec(&resp).map_err(|e| format!("json serialize: {}", e))?;
            send_sign_response(stream, "200 OK", Some(&resp_body));
            InFlightOutcome {
                status: "200 OK",
                body: resp_body,
            }
        }
        Err(e) => {
            let (status, code) = error_status_code(e.code);
            let err_body = format!("{{\"error\":\"{}\"}}", code).into_bytes();
            send_sign_response(stream, status, Some(&err_body));
            InFlightOutcome {
                status,
                body: err_body,
            }
        }
    };
    Ok(outcome)
}

fn error_status_code(code: ErrorCode) -> (&'static str, &'static str) {
    match code {
        ErrorCode::BadRequest => ("400 Bad Request", "bad_request"),
        ErrorCode::Unauthorized => ("401 Unauthorized", "unauthorized"),
        ErrorCode::Forbidden => ("403 Forbidden", "forbidden"),
        ErrorCode::NotFound => ("404 Not Found", "not_found"),
        ErrorCode::Conflict => ("409 Conflict", "conflict"),
        ErrorCode::InteractionRequired => ("409 Conflict", "human_interaction_required"),
        _ => ("500 Internal Server Error", "internal_error"),
    }
}

#[derive(Clone)]
pub struct SignContext {
    pub profile_id: ProfileId,
    pub active_grant_id: passless_core::agent::GrantId,
    pub profile_config: AgentProfileConfig,
}

#[derive(Clone)]
pub struct SignHandler {
    pub credential_storage: Arc<Mutex<Box<dyn CredentialStorage>>>,
    pub policy_runtime: Arc<PolicyRuntime>,
    pub audit_gate: Arc<AuditGate>,
    pub security_config: SecurityConfig,
    pub key_provider: Arc<dyn CredentialKeyProvider + Send + Sync>,
    pub operation_lock: Arc<Mutex<()>>,
}

impl SignHandler {
    fn record_policy_deny(&self, ctx: &SignContext, rp_id: &str, reason: PolicyDenyReason) {
        let deny_event = PolicyDenyBuilder::new(
            ctx.profile_id.clone(),
            AuditAction::Authenticate,
            rp_id,
            reason,
        )
        .build();
        let _ = self.audit_gate.record(deny_event);
    }

    pub fn sign(
        &self,
        ctx: &SignContext,
        req: &SignAssertionRequest,
    ) -> Result<PrincipalResponse, ProtocolError> {
        let normalized_rp = normalize_rp_id(&req.rp_id);

        if !verify_origin_context(
            &req.origin,
            req.top_origin.as_deref(),
            req.cross_origin,
            &normalized_rp,
        ) {
            let deny_event = PolicyDenyBuilder::new(
                ctx.profile_id.clone(),
                AuditAction::Authenticate,
                &normalized_rp,
                PolicyDenyReason::OriginInvalid,
            )
            .build();
            let _ = self.audit_gate.record(deny_event);
            return Err(ProtocolError::new(
                ErrorCode::Forbidden,
                "origin not valid for RP",
                RecommendedAction::FixRequest,
            ));
        }

        let _op_lock = self.operation_lock.lock().map_err(|_| {
            ProtocolError::new(
                ErrorCode::Internal,
                "operation lock poisoned",
                RecommendedAction::Abort,
            )
        })?;

        let grant_snapshot = self
            .policy_runtime
            .resolve_grant_for_sign(&ctx.profile_id, &ctx.active_grant_id)
            .ok_or_else(|| {
                let deny_event = PolicyDenyBuilder::new(
                    ctx.profile_id.clone(),
                    AuditAction::Authenticate,
                    &normalized_rp,
                    PolicyDenyReason::GrantNotFound,
                )
                .build();
                let _ = self.audit_gate.record(deny_event);
                ProtocolError::new(
                    ErrorCode::Forbidden,
                    "active grant not valid",
                    RecommendedAction::FixRequest,
                )
            })?;

        if grant_snapshot.is_revoked {
            let deny_event = PolicyDenyBuilder::new(
                ctx.profile_id.clone(),
                AuditAction::Authenticate,
                &normalized_rp,
                PolicyDenyReason::GrantRevoked,
            )
            .build();
            let _ = self.audit_gate.record(deny_event);
            return Err(ProtocolError::new(
                ErrorCode::Forbidden,
                "grant revoked",
                RecommendedAction::FixRequest,
            ));
        }

        if grant_snapshot.state != super::grant::GrantState::Active {
            let deny_event = PolicyDenyBuilder::new(
                ctx.profile_id.clone(),
                AuditAction::Authenticate,
                &normalized_rp,
                PolicyDenyReason::GrantExpired,
            )
            .build();
            let _ = self.audit_gate.record(deny_event);
            return Err(ProtocolError::new(
                ErrorCode::Forbidden,
                "grant expired",
                RecommendedAction::FixRequest,
            ));
        }

        if !grant_snapshot.rp_ids.iter().any(|id| {
            let scope_rp = normalize_rp_id(id);
            scope_rp == normalized_rp || scope_rp == ANY_RP_ID
        }) {
            let deny_event = PolicyDenyBuilder::new(
                ctx.profile_id.clone(),
                AuditAction::Authenticate,
                &normalized_rp,
                PolicyDenyReason::RpIdNotMatch,
            )
            .build();
            let _ = self.audit_gate.record(deny_event);
            return Err(ProtocolError::new(
                ErrorCode::Forbidden,
                "RP ID not in active grant",
                RecommendedAction::FixRequest,
            ));
        }

        let ceremony_policy = ctx
            .profile_config
            .rule_for_rp(&normalized_rp)
            .map(|rule| rule.authenticate)
            .ok_or_else(|| {
                let deny_event = PolicyDenyBuilder::new(
                    ctx.profile_id.clone(),
                    AuditAction::Authenticate,
                    &normalized_rp,
                    PolicyDenyReason::ActionNotAllowed,
                )
                .build();
                let _ = self.audit_gate.record(deny_event);
                ProtocolError::new(
                    ErrorCode::Forbidden,
                    "RP policy does not allow signing",
                    RecommendedAction::FixRequest,
                )
            })?;

        match ceremony_policy.authorization {
            passless_core::agent::AgentAuthorization::Deny => {
                self.record_policy_deny(ctx, &normalized_rp, PolicyDenyReason::ActionNotAllowed);
                return Err(ProtocolError::new(
                    ErrorCode::Forbidden,
                    "RP policy denies signing",
                    RecommendedAction::FixRequest,
                ));
            }
            passless_core::agent::AgentAuthorization::Confirm => {
                self.record_policy_deny(ctx, &normalized_rp, PolicyDenyReason::ActionNotAllowed);
                return Err(ProtocolError::new(
                    ErrorCode::InteractionRequired,
                    "human confirmation is required by policy",
                    RecommendedAction::Retry,
                ));
            }
            passless_core::agent::AgentAuthorization::Allow => {}
        }

        let human_uv_required = ceremony_policy.user_verification
            == passless_core::agent::UserVerificationSource::Human
            && (req.user_verification
                || self.security_config.always_uv
                || ctx.profile_config.human_verification_prompt
                    == passless_core::agent::HumanVerificationPrompt::Always);
        if ceremony_policy.user_presence == passless_core::agent::UserPresenceSource::Human
            || human_uv_required
        {
            self.record_policy_deny(
                ctx,
                &normalized_rp,
                if human_uv_required {
                    PolicyDenyReason::UvRequired
                } else {
                    PolicyDenyReason::ActionNotAllowed
                },
            );
            return Err(ProtocolError::new(
                ErrorCode::InteractionRequired,
                "human WebAuthn verification is required by policy",
                RecommendedAction::Retry,
            ));
        }

        let up = ceremony_policy.user_presence == passless_core::agent::UserPresenceSource::Agent;
        let uv = ceremony_policy.user_verification
            == passless_core::agent::UserVerificationSource::Agent;
        if (req.user_verification || self.security_config.always_uv) && !uv {
            self.record_policy_deny(ctx, &normalized_rp, PolicyDenyReason::UvRequired);
            return Err(ProtocolError::new(
                ErrorCode::Forbidden,
                "user verification is required but the configured evidence source is none",
                RecommendedAction::FixRequest,
            ));
        }

        let mut storage = self.credential_storage.lock().map_err(|_| {
            ProtocolError::new(
                ErrorCode::Internal,
                "storage lock poisoned",
                RecommendedAction::Abort,
            )
        })?;

        let credential_scope = if grant_snapshot.credential_refs.is_empty() {
            let mut discovered = Vec::new();
            if let Ok(mut credential) = storage.read_first(crate::storage::CredentialFilter::None) {
                loop {
                    if credential.rp.id.eq_ignore_ascii_case(&normalized_rp) {
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
            grant_snapshot.credential_refs.clone()
        };

        let mut candidates = Vec::new();
        for credential_ref in &credential_scope {
            if let Ok(credential_id) =
                Self::resolve_credential_id(&mut storage, credential_ref, &normalized_rp)
            {
                let encoded_id = b64u_encode(&credential_id);
                if !req.allow_credentials.is_empty() && !req.allow_credentials.contains(&encoded_id)
                {
                    continue;
                }
                if let Ok(credential) = storage.read(&credential_id) {
                    if credential.extensions.cred_protect == Some(2)
                        && !uv
                        && req.allow_credentials.is_empty()
                    {
                        continue;
                    }
                    candidates.push((credential_id, credential_ref.clone(), credential.created));
                }
            }
        }

        if candidates.is_empty() && !req.allow_credentials.is_empty() {
            self.record_policy_deny(
                ctx,
                &normalized_rp,
                PolicyDenyReason::AllowCredentialsMismatch,
            );
            return Err(ProtocolError::new(
                ErrorCode::Forbidden,
                "allowCredentials does not contain a permitted credential",
                RecommendedAction::FixRequest,
            ));
        }

        let credential_selection = ctx
            .profile_config
            .credential_selection_for_rp(&normalized_rp);
        let cred_id =
            Self::select_credential(candidates, &req.allow_credentials, &credential_selection)
                .inspect_err(|_| {
                    self.record_policy_deny(
                        ctx,
                        &normalized_rp,
                        PolicyDenyReason::CredentialNotMatch,
                    );
                })?;

        let allow_event = PolicyAllowBuilder::new(
            ctx.profile_id.clone(),
            AuditAction::Authenticate,
            &normalized_rp,
        )
        .evidence_sources(
            &ceremony_policy.authorization.to_string(),
            &ceremony_policy.user_presence.to_string(),
            &ceremony_policy.user_verification.to_string(),
        )
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
            self.record_policy_deny(ctx, &normalized_rp, PolicyDenyReason::UvRequired);
            return Err(ProtocolError::new(
                ErrorCode::Forbidden,
                "credential protection policy requires user verification",
                RecommendedAction::FixRequest,
            ));
        }

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
                let deny_event = PolicyDenyBuilder::new(
                    ctx.profile_id.clone(),
                    AuditAction::Authenticate,
                    &normalized_rp,
                    PolicyDenyReason::CounterPersistenceFailure,
                )
                .build();
                let _ = self.audit_gate.record(deny_event);
                ProtocolError::new(
                    ErrorCode::Internal,
                    "failed to write updated credential",
                    RecommendedAction::Retry,
                )
            })?;
        }

        let backup_flags = cred.backup_state.flags();

        let authenticator_data =
            build_authenticator_data(&normalized_rp, up, uv, backup_flags, new_sign_count);

        let client_data_json = build_client_data_json(
            &req.origin,
            &req.challenge_b64u,
            req.cross_origin,
            req.top_origin.as_deref(),
        );
        let client_data_hash = Sha256::digest(&client_data_json);

        let sig_input = [&authenticator_data[..], &client_data_hash[..]].concat();
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

    fn select_credential(
        mut candidates: Vec<(Vec<u8>, CredentialRef, i64)>,
        allow_credentials: &[String],
        selection: &CredentialSelection,
    ) -> Result<Vec<u8>, ProtocolError> {
        if candidates.is_empty() {
            return Err(ProtocolError::new(
                ErrorCode::NotFound,
                "no permitted credential matches this WebAuthn request",
                RecommendedAction::FixRequest,
            ));
        }

        if !allow_credentials.is_empty() {
            for allowed in allow_credentials {
                if let Some(index) = candidates
                    .iter()
                    .position(|(id, _, _)| b64u_encode(id) == *allowed)
                {
                    return Ok(candidates.swap_remove(index).0);
                }
            }
        }

        match selection {
            CredentialSelection::Credential(reference) => candidates
                .into_iter()
                .find(|(_, candidate_ref, _)| candidate_ref == reference)
                .map(|(id, _, _)| id)
                .ok_or_else(|| {
                    ProtocolError::new(
                        ErrorCode::NotFound,
                        "configured credential does not match this WebAuthn request",
                        RecommendedAction::FixRequest,
                    )
                }),
            CredentialSelection::Single if candidates.len() != 1 => Err(ProtocolError::new(
                ErrorCode::Conflict,
                "multiple discoverable credentials match; configure credential_selection",
                RecommendedAction::FixRequest,
            )),
            CredentialSelection::Single => Ok(candidates.remove(0).0),
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
mod tests {
    use super::*;

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
        assert!(!verify_origin_structural(
            "http://example.com",
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
    fn test_cross_origin_requires_top_origin() {
        assert!(!verify_origin_context(
            "https://login.example.com",
            None,
            true,
            "example.com"
        ));
        assert!(verify_origin_context(
            "https://login.example.com",
            Some("https://portal.example.net"),
            true,
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
    fn test_parse_origin_invalid_scheme() {
        assert!(parse_origin("http://example.com").is_none());
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
    fn test_http_server_binds_unix_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("sock");
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = SignHttpServer::bind(sock_path.clone(), shutdown.clone()).unwrap();
        assert!(server.socket_path().exists());
        let meta = std::fs::metadata(server.socket_path()).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        drop(server);
        shutdown.store(true, Ordering::Release);
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
    fn test_registry_request_budget_is_shared_for_one_bearer() {
        let registry = SignContextRegistry::new();
        let token = generate_bearer_token().unwrap();
        let first = registry.request_budget(&token, 2).unwrap();
        let second = registry.request_budget(&token, 2).unwrap();

        assert!(matches!(
            first.claim(b"register-operation"),
            RequestClaim::Claimed { .. }
        ));
        assert!(matches!(
            second.claim(b"register-operation"),
            RequestClaim::WaitFor(_)
        ));
        assert!(matches!(
            second.claim(b"sign-operation"),
            RequestClaim::Claimed { .. }
        ));
        assert!(matches!(
            first.claim(b"third-operation"),
            RequestClaim::Exhausted
        ));
        assert!(registry.request_budget(&token, 3).is_err());
    }

    fn make_budget(max_requests: usize) -> RequestBudget {
        RequestBudget {
            inner: Arc::new(Mutex::new(RequestBudgetInner {
                used: HashSet::new(),
                in_flight: HashMap::new(),
                completed: HashMap::new(),
            })),
            max_requests,
        }
    }

    #[test]
    fn test_claim_duplicate_in_flight_returns_wait_for() {
        let budget = make_budget(5);
        let body = b"identical-request-body";
        let first = budget.claim(body);
        assert!(matches!(first, RequestClaim::Claimed { .. }));
        let second = budget.claim(body);
        assert!(matches!(second, RequestClaim::WaitFor(_)));

        let RequestClaim::Claimed { digest } = first else {
            panic!("expected Claimed");
        };
        budget.resolve(
            digest,
            InFlightOutcome {
                status: "200 OK",
                body: b"result".to_vec(),
            },
        );

        let third = budget.claim(body);
        assert!(matches!(third, RequestClaim::Cached { .. }));
    }

    #[test]
    fn test_completed_expired_returns_replayed() {
        let budget = make_budget(5);
        let body = b"expired-body";
        let RequestClaim::Claimed { digest } = budget.claim(body) else {
            panic!("expected Claimed");
        };
        budget.resolve(
            digest,
            InFlightOutcome {
                status: "200 OK",
                body: b"ok".to_vec(),
            },
        );
        {
            let mut inner = budget.inner.lock().unwrap();
            if let Some(completed) = inner.completed.get_mut(&digest) {
                completed.at = Instant::now() - COMPLETED_OUTCOME_TTL - Duration::from_secs(1);
            }
        }
        assert!(matches!(budget.claim(body), RequestClaim::Replayed));
    }

    #[test]
    fn test_claim_different_bodies_both_claimed() {
        let budget = make_budget(5);
        assert!(matches!(
            budget.claim(b"body-a"),
            RequestClaim::Claimed { .. }
        ));
        assert!(matches!(
            budget.claim(b"body-b"),
            RequestClaim::Claimed { .. }
        ));
    }

    #[test]
    fn test_claim_budget_exhausted() {
        let budget = make_budget(2);
        assert!(matches!(budget.claim(b"one"), RequestClaim::Claimed { .. }));
        assert!(matches!(budget.claim(b"two"), RequestClaim::Claimed { .. }));
        assert!(matches!(budget.claim(b"three"), RequestClaim::Exhausted));
    }

    #[test]
    fn test_in_flight_waiter_receives_resolved_outcome() {
        let budget = make_budget(5);
        let body = b"shared-body";
        let RequestClaim::Claimed { digest } = budget.claim(body) else {
            panic!("expected Claimed");
        };
        let RequestClaim::WaitFor(entry) = budget.claim(body) else {
            panic!("expected WaitFor");
        };

        let waiter = std::thread::spawn(move || entry.wait(Duration::from_secs(5)));
        std::thread::sleep(Duration::from_millis(50));
        budget.resolve(
            digest,
            InFlightOutcome {
                status: "403 Forbidden",
                body: b"{\"error\":\"forbidden\"}".to_vec(),
            },
        );
        let outcome = waiter.join().unwrap().expect("waiter should resolve");
        assert_eq!(outcome.status, "403 Forbidden");
        assert_eq!(outcome.body, b"{\"error\":\"forbidden\"}");
    }

    #[test]
    fn test_in_flight_waiter_timeout_returns_none() {
        let budget = make_budget(5);
        let body = b"timeout-body";
        assert!(matches!(budget.claim(body), RequestClaim::Claimed { .. }));
        let RequestClaim::WaitFor(entry) = budget.claim(body) else {
            panic!("expected WaitFor");
        };
        assert!(entry.wait(Duration::from_millis(50)).is_none());
    }

    #[test]
    fn test_in_flight_guard_drop_resolves_waiters() {
        let budget = make_budget(5);
        let body = b"guard-body";
        let RequestClaim::Claimed { digest } = budget.claim(body) else {
            panic!("expected Claimed");
        };
        let RequestClaim::WaitFor(entry) = budget.claim(body) else {
            panic!("expected WaitFor");
        };
        {
            let guard = InFlightGuard::new(budget.clone(), digest);
            drop(guard);
        }
        let outcome = entry
            .wait(Duration::from_secs(5))
            .expect("resolved by drop");
        assert_eq!(outcome.status, "500 Internal Server Error");
    }

    #[test]
    fn test_completed_duplicate_within_ttl_returns_cached() {
        let budget = make_budget(5);
        let body = b"cached-body";
        let RequestClaim::Claimed { digest } = budget.claim(body) else {
            panic!("expected Claimed");
        };
        budget.resolve(
            digest,
            InFlightOutcome {
                status: "200 OK",
                body: b"cached-result".to_vec(),
            },
        );
        let RequestClaim::Cached { outcome } = budget.claim(body) else {
            panic!("expected Cached");
        };
        assert_eq!(outcome.status, "200 OK");
        assert_eq!(outcome.body, b"cached-result");
    }

    #[test]
    fn test_completed_cache_does_not_consume_extra_budget() {
        let budget = make_budget(2);
        let body = b"budget-body";
        let RequestClaim::Claimed { digest } = budget.claim(body) else {
            panic!("expected Claimed");
        };
        budget.resolve(
            digest,
            InFlightOutcome {
                status: "200 OK",
                body: b"ok".to_vec(),
            },
        );
        assert!(matches!(budget.claim(body), RequestClaim::Cached { .. }));
        assert!(matches!(
            budget.claim(b"other"),
            RequestClaim::Claimed { .. }
        ));
        assert!(matches!(budget.claim(b"third"), RequestClaim::Exhausted));
    }

    #[test]
    fn test_completed_cache_bounded_size() {
        let budget = make_budget(MAX_COMPLETED_OUTCOMES + 8);
        for i in 0..MAX_COMPLETED_OUTCOMES + 4 {
            let body = format!("body-{}", i);
            let RequestClaim::Claimed { digest } = budget.claim(body.as_bytes()) else {
                panic!("expected Claimed");
            };
            budget.resolve(
                digest,
                InFlightOutcome {
                    status: "200 OK",
                    body: b"ok".to_vec(),
                },
            );
        }
        let used = budget.inner.lock().unwrap().completed.len();
        assert!(used <= MAX_COMPLETED_OUTCOMES);
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
    fn test_http_valid_bound_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("sock");
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = SignHttpServer::bind(sock_path.clone(), shutdown.clone()).unwrap();
        let registry = Arc::new(SignContextRegistry::new());
        let token = generate_bearer_token().unwrap();
        let f = sign_handler_tests::TestFixture::new(true);
        let handler = Arc::new(f.make_handler());
        let ctx = f.make_ctx();
        registry
            .register_pending(token.clone(), ctx, handler)
            .unwrap();
        registry.bind_lease(&token, "lease-rt".to_string()).unwrap();
        let handle = server.serve(registry);
        let body = serde_json::to_vec(&SignAssertionRequest {
            origin: "https://example.com".to_string(),
            top_origin: None,
            rp_id: "example.com".to_string(),
            challenge_b64u: "dGVzdA".to_string(),
            allow_credentials: vec![],
            user_verification: false,
            cross_origin: false,
        })
        .unwrap();
        let request = format!(
            "POST /sign HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            token,
            body.len()
        );
        let mut stream = UnixStream::connect(&sock_path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        stream.write_all(&body).unwrap();
        let mut resp_buf = vec![0u8; 8192];
        let n = stream.read(&mut resp_buf).unwrap();
        let resp_str = std::str::from_utf8(&resp_buf[..n]).unwrap();
        assert!(resp_str.contains("200 OK"));
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn test_http_unknown_bearer_401() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("sock");
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = SignHttpServer::bind(sock_path.clone(), shutdown.clone()).unwrap();
        let registry = Arc::new(SignContextRegistry::new());
        let handle = server.serve(registry);
        let body = b"{}";
        let request = format!(
            "POST /sign HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer unknown_token\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut stream = UnixStream::connect(&sock_path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
        let mut resp_buf = vec![0u8; 4096];
        let n = stream.read(&mut resp_buf).unwrap();
        let resp_str = std::str::from_utf8(&resp_buf[..n]).unwrap();
        assert!(resp_str.contains("401"));
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn test_http_unbound_bearer_401() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("sock");
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = SignHttpServer::bind(sock_path.clone(), shutdown.clone()).unwrap();
        let registry = Arc::new(SignContextRegistry::new());
        let token = generate_bearer_token().unwrap();
        let f = sign_handler_tests::TestFixture::new(true);
        let handler = Arc::new(f.make_handler());
        let ctx = f.make_ctx();
        registry
            .register_pending(token.clone(), ctx, handler)
            .unwrap();
        let handle = server.serve(registry);
        let body = b"{}";
        let request = format!(
            "POST /sign HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            token,
            body.len()
        );
        let mut stream = UnixStream::connect(&sock_path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
        let mut resp_buf = vec![0u8; 4096];
        let n = stream.read(&mut resp_buf).unwrap();
        let resp_str = std::str::from_utf8(&resp_buf[..n]).unwrap();
        assert!(resp_str.contains("401"));
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn test_http_revoked_bearer_401() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("sock");
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = SignHttpServer::bind(sock_path.clone(), shutdown.clone()).unwrap();
        let registry = Arc::new(SignContextRegistry::new());
        let token = generate_bearer_token().unwrap();
        let f = sign_handler_tests::TestFixture::new(true);
        let handler = Arc::new(f.make_handler());
        let ctx = f.make_ctx();
        registry
            .register_pending(token.clone(), ctx, handler)
            .unwrap();
        registry
            .bind_lease(&token, "lease-rev".to_string())
            .unwrap();
        registry.revoke(&token);
        let handle = server.serve(registry);
        let body = b"{}";
        let request = format!(
            "POST /sign HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            token,
            body.len()
        );
        let mut stream = UnixStream::connect(&sock_path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
        let mut resp_buf = vec![0u8; 4096];
        let n = stream.read(&mut resp_buf).unwrap();
        let resp_str = std::str::from_utf8(&resp_buf[..n]).unwrap();
        assert!(resp_str.contains("401"));
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn test_http_missing_bearer() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("sock");
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = SignHttpServer::bind(sock_path.clone(), shutdown.clone()).unwrap();
        let registry = Arc::new(SignContextRegistry::new());
        let handle = server.serve(registry);
        let body = b"{}";
        let request = format!(
            "POST /sign HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut stream = UnixStream::connect(&sock_path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
        let mut resp_buf = vec![0u8; 4096];
        let n = stream.read(&mut resp_buf).unwrap();
        let resp_str = std::str::from_utf8(&resp_buf[..n]).unwrap();
        assert!(resp_str.contains("401"));
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn test_http_wrong_method() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("sock");
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = SignHttpServer::bind(sock_path.clone(), shutdown.clone()).unwrap();
        let registry = Arc::new(SignContextRegistry::new());
        let token = generate_bearer_token().unwrap();
        let f = sign_handler_tests::TestFixture::new(true);
        let handler = Arc::new(f.make_handler());
        let ctx = f.make_ctx();
        registry
            .register_pending(token.clone(), ctx, handler)
            .unwrap();
        registry.bind_lease(&token, "lease-m".to_string()).unwrap();
        let handle = server.serve(registry);
        let request = format!(
            "GET /sign HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n\r\n",
            token
        );
        let mut stream = UnixStream::connect(&sock_path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut resp_buf = vec![0u8; 4096];
        let n = stream.read(&mut resp_buf).unwrap();
        let resp_str = std::str::from_utf8(&resp_buf[..n]).unwrap();
        assert!(resp_str.contains("404"));
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn test_http_wrong_path() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("sock");
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = SignHttpServer::bind(sock_path.clone(), shutdown.clone()).unwrap();
        let registry = Arc::new(SignContextRegistry::new());
        let token = generate_bearer_token().unwrap();
        let f = sign_handler_tests::TestFixture::new(true);
        let handler = Arc::new(f.make_handler());
        let ctx = f.make_ctx();
        registry
            .register_pending(token.clone(), ctx, handler)
            .unwrap();
        registry.bind_lease(&token, "lease-p".to_string()).unwrap();
        let handle = server.serve(registry);
        let request = format!(
            "POST /other HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Length: 0\r\n\r\n",
            token
        );
        let mut stream = UnixStream::connect(&sock_path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut resp_buf = vec![0u8; 4096];
        let n = stream.read(&mut resp_buf).unwrap();
        let resp_str = std::str::from_utf8(&resp_buf[..n]).unwrap();
        assert!(resp_str.contains("404"));
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn test_listener_loopback_only() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("sock");
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = SignHttpServer::bind(sock_path.clone(), shutdown.clone()).unwrap();
        assert!(server.socket_path().starts_with(dir.path()));
        shutdown.store(true, Ordering::Release);
    }

    #[test]
    fn test_shutdown_join() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("sock");
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = SignHttpServer::bind(sock_path, shutdown.clone()).unwrap();
        let registry = Arc::new(SignContextRegistry::new());
        let handle = server.serve(registry);
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn test_p256_sign_verify_through_provider() {
        let provider = soft_fido2::SoftwareCredentialKeyProvider;
        let generated = provider.generate(-7).unwrap();
        let message = b"test message for signing";
        let signature = provider.sign(&generated.key, -7, message).unwrap();
        assert!(!signature.is_empty());
    }

    #[test]
    fn test_http_options_returns_404() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("sock");
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = SignHttpServer::bind(sock_path.clone(), shutdown.clone()).unwrap();
        let registry = Arc::new(SignContextRegistry::new());
        let handle = server.serve(registry);
        let request = "OPTIONS /sign HTTP/1.1\r\nHost: localhost\r\nOrigin: https://evil.example.com\r\nAccess-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: Authorization\r\n\r\n";
        let mut stream = UnixStream::connect(&sock_path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut resp_buf = vec![0u8; 4096];
        let n = stream.read(&mut resp_buf).unwrap();
        let resp_str = std::str::from_utf8(&resp_buf[..n]).unwrap();
        assert!(resp_str.contains("404"));
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn test_http_post_error_no_cors_headers() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("sock");
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = SignHttpServer::bind(sock_path.clone(), shutdown.clone()).unwrap();
        let registry = Arc::new(SignContextRegistry::new());
        let handle = server.serve(registry);
        let body = b"{}";
        let request = format!(
            "POST /sign HTTP/1.1\r\nHost: localhost\r\nOrigin: https://attacker.example.com\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut stream = UnixStream::connect(&sock_path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
        let mut resp_buf = vec![0u8; 4096];
        let n = stream.read(&mut resp_buf).unwrap();
        let resp_str = std::str::from_utf8(&resp_buf[..n]).unwrap();
        assert!(resp_str.contains("401"));
        assert!(!resp_str.contains("Access-Control"));
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn test_http_success_no_cors_headers() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("sock");
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = SignHttpServer::bind(sock_path.clone(), shutdown.clone()).unwrap();
        let registry = Arc::new(SignContextRegistry::new());
        let token = generate_bearer_token().unwrap();
        let f = sign_handler_tests::TestFixture::new(true);
        let handler = Arc::new(f.make_handler());
        let ctx = f.make_ctx();
        registry
            .register_pending(token.clone(), ctx, handler)
            .unwrap();
        registry
            .bind_lease(&token, "lease-cors".to_string())
            .unwrap();
        let handle = server.serve(registry);
        let body = serde_json::to_vec(&SignAssertionRequest {
            origin: "https://example.com".to_string(),
            top_origin: None,
            rp_id: "example.com".to_string(),
            challenge_b64u: "dGVzdA".to_string(),
            allow_credentials: vec![],
            user_verification: false,
            cross_origin: false,
        })
        .unwrap();
        let request = format!(
            "POST /sign HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            token,
            body.len()
        );
        let mut stream = UnixStream::connect(&sock_path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        stream.write_all(&body).unwrap();
        let mut resp_buf = vec![0u8; 8192];
        let n = stream.read(&mut resp_buf).unwrap();
        let resp_str = std::str::from_utf8(&resp_buf[..n]).unwrap();
        assert!(resp_str.contains("200 OK"));
        assert!(!resp_str.contains("Access-Control"));
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn test_http_unbound_bearer_same_401_as_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("sock");
        let shutdown = Arc::new(AtomicBool::new(false));
        let server = SignHttpServer::bind(sock_path.clone(), shutdown.clone()).unwrap();
        let registry = Arc::new(SignContextRegistry::new());
        let token = generate_bearer_token().unwrap();
        let f = sign_handler_tests::TestFixture::new(true);
        let handler = Arc::new(f.make_handler());
        let ctx = f.make_ctx();
        registry
            .register_pending(token.clone(), ctx, handler)
            .unwrap();
        let handle = server.serve(registry);
        let body = b"{}";
        let request = format!(
            "POST /sign HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            token,
            body.len()
        );
        let mut stream = UnixStream::connect(&sock_path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
        let mut resp_buf = vec![0u8; 4096];
        let mut total = 0;
        loop {
            let n = stream.read(&mut resp_buf[total..]).unwrap();
            if n == 0 {
                break;
            }
            total += n;
            if resp_buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                let header_end = resp_buf[..total]
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .unwrap();
                let header_str = std::str::from_utf8(&resp_buf[..header_end]).unwrap();
                if let Some(cl) = header_str.lines().find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|v| v.trim().parse::<usize>().ok())
                }) {
                    let body_start = header_end + 4;
                    let body_len = total.saturating_sub(body_start);
                    if body_len >= cl {
                        break;
                    }
                } else {
                    break;
                }
            }
        }
        let resp_str = std::str::from_utf8(&resp_buf[..total]).unwrap();
        assert!(resp_str.contains("401"));
        assert!(resp_str.contains("invalid_bearer"));
        assert!(!resp_str.contains("unbound_bearer"));
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    pub(super) mod sign_handler_tests {
        use super::*;
        use crate::agent::audit::AuditGate;
        use crate::agent::browser;
        use crate::agent::grant::GrantRequestParams;
        use crate::agent::intent;
        use crate::agent::policy_engine::PolicyRuntime;
        use crate::storage::{CredentialFilter, CredentialStorage};
        use passless_core::agent::{
            AgentAuthorization, AgentCeremonyPolicy, AgentConfig, AgentMode, AgentProfileConfig,
            AgentRpRule, BrowserScope, DeviceIdentity, UserPresenceSource, UserVerificationSource,
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

        pub struct MockMonoClock {
            inner: Mutex<MockClockInner>,
        }
        impl MockMonoClock {
            pub fn new() -> Self {
                Self {
                    inner: Mutex::new(MockClockInner {
                        base: Instant::now(),
                        offset: Duration::ZERO,
                    }),
                }
            }
        }
        impl intent::MonotonicClock for MockMonoClock {
            fn now(&self) -> intent::MonotonicTime {
                let inner = self.inner.lock().unwrap();
                let elapsed = inner.offset;
                intent::MonotonicTime::from_millis(elapsed.as_millis() as u64)
            }
        }

        pub struct RecordingKeyProvider {
            inner: SoftwareCredentialKeyProvider,
            sign_count: AtomicUsize,
        }
        impl RecordingKeyProvider {
            pub fn new() -> Self {
                Self {
                    inner: SoftwareCredentialKeyProvider,
                    sign_count: AtomicUsize::new(0),
                }
            }
            fn sign_calls(&self) -> usize {
                self.sign_count.load(Ordering::Acquire)
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
                self.sign_count.fetch_add(1, Ordering::AcqRel);
                self.inner.sign(key, algorithm, data)
            }
        }

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
            fn writes(&self) -> u64 {
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
                let creds = self.creds.lock().unwrap();
                match filter {
                    CredentialFilter::ByRp(rp_id) => creds
                        .iter()
                        .find(|c| c.rp.id == rp_id)
                        .cloned()
                        .ok_or(soft_fido2::Error::Other),
                    CredentialFilter::None => {
                        creds.first().cloned().ok_or(soft_fido2::Error::Other)
                    }
                    CredentialFilter::ById(id) => creds
                        .iter()
                        .find(|c| c.id == id)
                        .cloned()
                        .ok_or(soft_fido2::Error::Other),
                    CredentialFilter::ByHash(_) => Err(soft_fido2::Error::Other),
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
            profile_config: AgentProfileConfig,
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

                let profile_config = AgentProfileConfig {
                    max_operations: 64,
                    max_concurrent_sessions: 1,
                    browser_scope: BrowserScope::Session,
                    credential_selection: passless_core::agent::config::CredentialSelection::Single,
                    human_verification_prompt:
                        passless_core::agent::config::HumanVerificationPrompt::Always,
                    mode: AgentMode::Isolated,
                    principal_user: String::new(),
                    rp_ids: vec!["example.com".to_string()],
                    require_uv: false,
                    credential_refs: Some(vec![cred_ref.clone()]),
                    max_grant_ttl: None,
                    max_session_ttl: None,
                    storage: None,
                    registration_allowed: false,
                    rules: vec![AgentRpRule {
                        credential_selection: None,
                        rp_id: "example.com".to_string(),
                        register: AgentCeremonyPolicy::deny(),
                        authenticate: AgentCeremonyPolicy {
                            authorization: AgentAuthorization::Allow,
                            user_presence: UserPresenceSource::Agent,
                            user_verification: UserVerificationSource::Agent,
                        },
                    }],
                    device: DeviceIdentity {
                        name: "test-device".to_string(),
                        phys: "test-phys".to_string(),
                        uniq: "test-uniq".to_string(),
                        vendor_id: 0x1234,
                        product_id: 0x5678,
                    },
                    start_url: None,
                    browser_command: None,
                    browser_user: None,
                    browser_runtime_root: None,
                    browser_cdp_expose: None,
                    browser_cdp_port: None,
                };

                let mut profiles = BTreeMap::new();
                profiles.insert("test-profile".to_string(), profile_config.clone());
                let agent_config = AgentConfig {
                    enabled: true,
                    profiles,
                    audit_path: Some(audit_path),
                    acknowledge_global_same_user: vec![],
                    acknowledge_same_user_registration: vec![],
                };

                let clock = Arc::new(MockClock::new());
                let mono_clock = Arc::new(MockMonoClock::new());

                let policy_runtime = Arc::new(
                    PolicyRuntime::new(&agent_config, clock.clone(), mono_clock.clone(), None)
                        .unwrap(),
                );

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

                let authority = intent::admin_authority();
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
                    profile_config,
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
                }
            }

            pub fn make_ctx(&self) -> SignContext {
                SignContext {
                    profile_id: self.profile_id.clone(),
                    active_grant_id: self.grant_id.clone(),
                    profile_config: self.profile_config.clone(),
                }
            }

            fn make_req(&self) -> SignAssertionRequest {
                SignAssertionRequest {
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

        fn get_write_counting_storage(
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
                .admin_approve_grant(&grant_request, &intent::admin_authority())
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

            let mut profile_config = f.profile_config.clone();
            profile_config.credential_refs = None;
            let ctx = SignContext {
                profile_id: f.profile_id.clone(),
                active_grant_id: dynamic_grant_id,
                profile_config,
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
                profile_id: f.profile_id.clone(),
                active_grant_id: fake_grant_id,
                profile_config: f.profile_config.clone(),
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
                profile_id: wrong_profile,
                active_grant_id: f.grant_id.clone(),
                profile_config: f.profile_config.clone(),
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
            for _ in 0..4 {
                let h = handler.clone();
                let c = ctx.clone();
                handles.push(std::thread::spawn(move || {
                    let req = SignAssertionRequest {
                        origin: "https://example.com".to_string(),
                        top_origin: None,
                        rp_id: "example.com".to_string(),
                        challenge_b64u: "dGVzdA".to_string(),
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
        use crate::agent::grant::GrantRequestParams;
        use crate::agent::intent;
        use crate::agent::policy_engine::PolicyRuntime;
        use crate::storage::CredentialStorage;

        use passless_core::agent::{
            AgentAuthorization, AgentCeremonyPolicy, AgentConfig, AgentMode, AgentProfileConfig,
            AgentRpRule, BrowserScope, DeviceIdentity, UserPresenceSource, UserVerificationSource,
        };
        use passless_core::config::SecurityConfig;

        use soft_fido2::{
            CredentialBackupState, CredentialKeyProvider, RelyingParty,
            SoftwareCredentialKeyProvider, User,
        };

        use std::collections::BTreeMap;
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
                    e.get("kind")
                        .and_then(|k| k.as_str())
                        .is_some_and(|k| k == "policy.allow" || k == "policy.deny")
                })
                .collect()
        }

        struct AuditTestFixture {
            profile_id: ProfileId,
            grant_id: passless_core::agent::GrantId,
            clock: Arc<MockClock>,
            policy_runtime: Arc<PolicyRuntime>,
            storage: Arc<Mutex<Box<dyn CredentialStorage>>>,
            key_provider: Arc<RecordingKeyProvider>,
            audit_gate: Arc<AuditGate>,
            operation_lock: Arc<Mutex<()>>,
            security_config: SecurityConfig,
            profile_config: AgentProfileConfig,
            audit_dir: std::path::PathBuf,
        }

        impl AuditTestFixture {
            fn new(rules: Vec<AgentRpRule>, grant_rp_ids: Vec<&str>) -> Self {
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

                let rp_id_strings: Vec<String> =
                    grant_rp_ids.iter().map(|s| s.to_string()).collect();

                let profile_config = AgentProfileConfig {
                    max_operations: 64,
                    max_concurrent_sessions: 1,
                    browser_scope: BrowserScope::Session,
                    credential_selection: passless_core::agent::config::CredentialSelection::Single,
                    human_verification_prompt:
                        passless_core::agent::config::HumanVerificationPrompt::Always,
                    mode: AgentMode::Isolated,
                    principal_user: String::new(),
                    rp_ids: rp_id_strings.clone(),
                    require_uv: false,
                    credential_refs: Some(vec![cred_ref.clone()]),
                    max_grant_ttl: None,
                    max_session_ttl: None,
                    storage: None,
                    registration_allowed: false,
                    rules,
                    device: DeviceIdentity {
                        name: "test-device".to_string(),
                        phys: "test-phys".to_string(),
                        uniq: "test-uniq".to_string(),
                        vendor_id: 0x1234,
                        product_id: 0x5678,
                    },
                    start_url: None,
                    browser_command: None,
                    browser_user: None,
                    browser_runtime_root: None,
                    browser_cdp_expose: None,
                    browser_cdp_port: None,
                };

                let mut profiles = BTreeMap::new();
                profiles.insert("test-profile".to_string(), profile_config.clone());
                let agent_config = AgentConfig {
                    enabled: true,
                    profiles,
                    audit_path: Some(audit_path.clone()),
                    acknowledge_global_same_user: vec![],
                    acknowledge_same_user_registration: vec![],
                };

                let clock = Arc::new(MockClock::new());
                let mono_clock = Arc::new(MockMonoClock::new());

                let policy_runtime = Arc::new(
                    PolicyRuntime::new(&agent_config, clock.clone(), mono_clock.clone(), None)
                        .unwrap(),
                );

                let session_id = passless_core::agent::PrincipalSessionId::new();
                let endpoint_id = passless_core::agent::EndpointId::new();

                let grant_req_id = policy_runtime
                    .admin_request_grant(GrantRequestParams {
                        profile_id: profile_id.clone(),
                        session_id: session_id.clone(),
                        endpoint_id: endpoint_id.clone(),
                        principal_digest: [0u8; 32],
                        rp_ids: grant_rp_ids.iter().map(|s| s.to_string()).collect(),
                        credentials: vec![cred_ref.clone()],
                        requested_ttl_secs: 300,
                    })
                    .unwrap();

                let authority = intent::admin_authority();
                let grant_id = policy_runtime
                    .admin_approve_grant(&grant_req_id, &authority)
                    .unwrap();

                let key_provider = Arc::new(RecordingKeyProvider::new());
                let operation_lock = Arc::new(Mutex::new(()));
                let security_config = SecurityConfig {
                    check_mlock: false,
                    disable_core_dumps: false,
                    constant_signature_counter: true,
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
                    profile_config,
                    audit_dir: audit_path,
                }
            }

            fn default_allow() -> Self {
                let rule = AgentRpRule {
                    credential_selection: None,
                    rp_id: "example.com".to_string(),
                    register: AgentCeremonyPolicy::deny(),
                    authenticate: AgentCeremonyPolicy {
                        authorization: AgentAuthorization::Allow,
                        user_presence: UserPresenceSource::Agent,
                        user_verification: UserVerificationSource::Agent,
                    },
                };
                Self::new(vec![rule], vec!["example.com"])
            }

            fn make_handler(&self) -> SignHandler {
                SignHandler {
                    credential_storage: self.storage.clone(),
                    policy_runtime: self.policy_runtime.clone(),
                    audit_gate: self.audit_gate.clone(),
                    security_config: self.security_config.clone(),
                    key_provider: self.key_provider.clone(),
                    operation_lock: self.operation_lock.clone(),
                }
            }

            fn make_ctx(&self) -> SignContext {
                SignContext {
                    profile_id: self.profile_id.clone(),
                    active_grant_id: self.grant_id.clone(),
                    profile_config: self.profile_config.clone(),
                }
            }

            fn make_req(&self) -> SignAssertionRequest {
                SignAssertionRequest {
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

        fn allow_rule(rp_id: &str) -> AgentRpRule {
            AgentRpRule {
                credential_selection: None,
                rp_id: rp_id.to_string(),
                register: AgentCeremonyPolicy::deny(),
                authenticate: AgentCeremonyPolicy {
                    authorization: AgentAuthorization::Allow,
                    user_presence: UserPresenceSource::Agent,
                    user_verification: UserVerificationSource::Agent,
                },
            }
        }

        fn confirm_rule(rp_id: &str) -> AgentRpRule {
            AgentRpRule {
                credential_selection: None,
                rp_id: rp_id.to_string(),
                register: AgentCeremonyPolicy::deny(),
                authenticate: AgentCeremonyPolicy {
                    authorization: AgentAuthorization::Confirm,
                    user_presence: UserPresenceSource::Human,
                    user_verification: UserVerificationSource::None,
                },
            }
        }

        fn deny_rule(rp_id: &str) -> AgentRpRule {
            AgentRpRule {
                credential_selection: None,
                rp_id: rp_id.to_string(),
                register: AgentCeremonyPolicy {
                    authorization: AgentAuthorization::Confirm,
                    user_presence: UserPresenceSource::Human,
                    user_verification: UserVerificationSource::None,
                },
                authenticate: AgentCeremonyPolicy::deny(),
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
            let rule = AgentRpRule {
                credential_selection: None,
                rp_id: "example.com".to_string(),
                register: AgentCeremonyPolicy::deny(),
                authenticate: AgentCeremonyPolicy {
                    authorization: AgentAuthorization::Allow,
                    user_presence: UserPresenceSource::Agent,
                    user_verification: UserVerificationSource::Agent,
                },
            };
            let mut f = AuditTestFixture::new(vec![rule], vec!["example.com"]);
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
        fn confirm_policy_blocks_autonomous_sign() {
            let f = AuditTestFixture::new(vec![confirm_rule("example.com")], vec!["example.com"]);
            let handler = f.make_handler();
            let ctx = f.make_ctx();
            let req = f.make_req();
            let result = handler.sign(&ctx, &req);
            assert!(result.is_err());
        }

        #[test]
        fn confirm_policy_deny_audit_event() {
            let f = AuditTestFixture::new(vec![confirm_rule("example.com")], vec!["example.com"]);
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
            assert_eq!(last["reason"], "action_not_allowed");
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
    }

    mod integration_tests {
        use super::sign_handler_tests::TestFixture;
        use super::*;

        use std::io::{Read, Write};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;

        fn http_request(sock_path: &Path, request: &str, body: &[u8]) -> String {
            let mut stream = UnixStream::connect(sock_path).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream.write_all(request.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
            let mut resp_buf = vec![0u8; 32768];
            let mut total = 0;
            loop {
                match stream.read(&mut resp_buf[total..]) {
                    Ok(0) => break,
                    Ok(n) => total += n,
                    Err(_) => break,
                }
            }
            String::from_utf8_lossy(&resp_buf[..total]).to_string()
        }

        fn http_body(resp: &str) -> &str {
            resp.split("\r\n\r\n").nth(1).unwrap_or("")
        }

        fn setup_bound(
            constant_counter: bool,
        ) -> (
            Arc<AtomicBool>,
            tempfile::TempDir,
            std::path::PathBuf,
            Arc<SignContextRegistry>,
            String,
            TestFixture,
            thread::JoinHandle<()>,
        ) {
            let dir = tempfile::tempdir().unwrap();
            let sock_path = dir.path().join("sock");
            let shutdown = Arc::new(AtomicBool::new(false));
            let server = SignHttpServer::bind(sock_path.clone(), shutdown.clone()).unwrap();
            let registry = Arc::new(SignContextRegistry::new());
            let token = generate_bearer_token().unwrap();
            let f = TestFixture::new(constant_counter);
            let handler = Arc::new(f.make_handler());
            let ctx = f.make_ctx();
            registry
                .register_pending(token.clone(), ctx, handler)
                .unwrap();
            registry
                .bind_lease(&token, "lease-integ".to_string())
                .unwrap();
            let handle = server.serve(registry.clone());
            (shutdown, dir, sock_path, registry, token, f, handle)
        }

        fn sign_request_body(
            origin: &str,
            rp_id: &str,
            challenge: &str,
            allow_credentials: Vec<String>,
            cross_origin: bool,
        ) -> Vec<u8> {
            serde_json::to_vec(&SignAssertionRequest {
                origin: origin.to_string(),
                top_origin: None,
                rp_id: rp_id.to_string(),
                challenge_b64u: challenge.to_string(),
                allow_credentials,
                user_verification: false,
                cross_origin,
            })
            .unwrap()
        }

        fn format_sign_request(token: &str, body: &[u8]) -> String {
            format!(
                "POST /sign HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                token,
                body.len()
            )
        }

        fn extract_counter(auth_data_b64u: &str) -> u32 {
            let auth_data = b64u_decode(auth_data_b64u).unwrap();
            assert!(auth_data.len() >= 37);
            u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]])
        }

        #[test]
        fn http_sign_full_response_structure() {
            let (shutdown, _dir, sock_path, _registry, token, _f, handle) = setup_bound(true);
            let body = sign_request_body(
                "https://example.com",
                "example.com",
                "dGVzdA",
                vec![],
                false,
            );
            let req = format_sign_request(&token, &body);
            let resp = http_request(&sock_path, &req, &body);
            assert!(resp.contains("200 OK"));
            let body_str = http_body(&resp);
            let parsed: serde_json::Value = serde_json::from_str(body_str).unwrap();
            let inner = parsed.get("sign_assertion_result").unwrap();
            assert!(inner.get("credential_id_b64u").is_some());
            assert!(inner.get("authenticator_data_b64u").is_some());
            assert!(inner.get("signature_b64u").is_some());
            assert!(inner.get("user_handle_b64u").is_some());
            assert!(inner.get("client_data_json_b64u").is_some());
            shutdown.store(true, Ordering::Release);
            handle.join().unwrap();
        }

        #[test]
        fn http_auth_preflight_then_sign() {
            let (shutdown, _dir, sock_path, _registry, token, _f, handle) = setup_bound(true);
            let body = sign_request_body(
                "https://example.com",
                "example.com",
                "dGVzdA",
                vec![],
                false,
            );
            let req = format_sign_request(&token, &body);
            let sign_resp = http_request(&sock_path, &req, &body);
            assert!(sign_resp.contains("200 OK"));
            assert!(!sign_resp.contains("Access-Control"));
            shutdown.store(true, Ordering::Release);
            handle.join().unwrap();
        }

        #[test]
        fn http_policy_deny_returns_403() {
            let (shutdown, _dir, sock_path, _registry, token, _f, handle) = setup_bound(true);
            let body = sign_request_body("https://other.com", "other.com", "dGVzdA", vec![], false);
            let req = format_sign_request(&token, &body);
            let resp = http_request(&sock_path, &req, &body);
            assert!(resp.contains("403"));
            let body_str = http_body(&resp);
            assert!(body_str.contains("forbidden"));
            shutdown.store(true, Ordering::Release);
            handle.join().unwrap();
        }

        #[test]
        fn http_grant_ttl_enforced() {
            let (shutdown, _dir, sock_path, _registry, token, f, handle) = setup_bound(true);
            f.clock.advance(Duration::from_secs(301));
            let body = sign_request_body(
                "https://example.com",
                "example.com",
                "dGVzdA",
                vec![],
                false,
            );
            let req = format_sign_request(&token, &body);
            let resp = http_request(&sock_path, &req, &body);
            assert!(resp.contains("403"));
            let body_str = http_body(&resp);
            assert!(body_str.contains("forbidden"));
            shutdown.store(true, Ordering::Release);
            handle.join().unwrap();
        }

        #[test]
        fn http_credential_ref_enforced() {
            let (shutdown, _dir, sock_path, _registry, token, _f, handle) = setup_bound(true);
            let body = sign_request_body(
                "https://example.com",
                "example.com",
                "dGVzdA",
                vec![],
                false,
            );
            let req = format_sign_request(&token, &body);
            let resp = http_request(&sock_path, &req, &body);
            assert!(resp.contains("200 OK"));
            let body_str = http_body(&resp);
            let parsed: serde_json::Value = serde_json::from_str(body_str).unwrap();
            let inner = parsed.get("sign_assertion_result").unwrap();
            let cred_id = inner.get("credential_id_b64u").unwrap().as_str().unwrap();
            let expected = b64u_encode(&[1u8; 32]);
            assert_eq!(cred_id, expected);
            shutdown.store(true, Ordering::Release);
            handle.join().unwrap();
        }

        #[test]
        fn http_counter_increment_monotonic() {
            let (shutdown, _dir, sock_path, _registry, token, _f, handle) = setup_bound(false);
            let body1 = sign_request_body(
                "https://example.com",
                "example.com",
                "dGVzdA",
                vec![],
                false,
            );
            let req1 = format_sign_request(&token, &body1);
            let resp1 = http_request(&sock_path, &req1, &body1);
            assert!(resp1.contains("200 OK"));
            let parsed1: serde_json::Value = serde_json::from_str(http_body(&resp1)).unwrap();
            let inner1 = parsed1.get("sign_assertion_result").unwrap();
            let auth1 = inner1
                .get("authenticator_data_b64u")
                .unwrap()
                .as_str()
                .unwrap();
            let counter1 = extract_counter(auth1);
            let body2 = sign_request_body(
                "https://example.com",
                "example.com",
                "Y2hhbA",
                vec![],
                false,
            );
            let req2 = format_sign_request(&token, &body2);
            let resp2 = http_request(&sock_path, &req2, &body2);
            assert!(resp2.contains("200 OK"));
            let parsed2: serde_json::Value = serde_json::from_str(http_body(&resp2)).unwrap();
            let inner2 = parsed2.get("sign_assertion_result").unwrap();
            let auth2 = inner2
                .get("authenticator_data_b64u")
                .unwrap()
                .as_str()
                .unwrap();
            let counter2 = extract_counter(auth2);
            assert_eq!(counter1, 1);
            assert_eq!(counter2, 2);
            shutdown.store(true, Ordering::Release);
            handle.join().unwrap();
        }

        #[test]
        fn http_content_type_validation() {
            let (shutdown, _dir, sock_path, _registry, token, _f, handle) = setup_bound(true);
            let body = b"{}";
            let req = format!(
                "POST /sign HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
                token,
                body.len()
            );
            let resp = http_request(&sock_path, &req, body);
            assert!(resp.contains("415"));
            let body_str = http_body(&resp);
            assert!(body_str.contains("unsupported_content_type"));
            shutdown.store(true, Ordering::Release);
            handle.join().unwrap();
        }

        #[test]
        fn http_origin_mismatch_denied() {
            let (shutdown, _dir, sock_path, _registry, token, _f, handle) = setup_bound(true);
            let body =
                sign_request_body("https://evil.com", "example.com", "dGVzdA", vec![], false);
            let req = format_sign_request(&token, &body);
            let resp = http_request(&sock_path, &req, &body);
            assert!(resp.contains("403"));
            let body_str = http_body(&resp);
            assert!(body_str.contains("forbidden"));
            shutdown.store(true, Ordering::Release);
            handle.join().unwrap();
        }

        #[test]
        fn http_wrong_rp_id_denied() {
            let (shutdown, _dir, sock_path, _registry, token, _f, handle) = setup_bound(true);
            let body = sign_request_body("https://other.com", "other.com", "dGVzdA", vec![], false);
            let req = format_sign_request(&token, &body);
            let resp = http_request(&sock_path, &req, &body);
            assert!(resp.contains("403"));
            let body_str = http_body(&resp);
            assert!(body_str.contains("forbidden"));
            shutdown.store(true, Ordering::Release);
            handle.join().unwrap();
        }

        #[test]
        fn http_unauthorized_credential_denied() {
            let (shutdown, _dir, sock_path, _registry, token, _f, handle) = setup_bound(true);
            let wrong_cred = b64u_encode(b"wrong_credential_id_bytes_1234567");
            let body = sign_request_body(
                "https://example.com",
                "example.com",
                "dGVzdA",
                vec![wrong_cred],
                false,
            );
            let req = format_sign_request(&token, &body);
            let resp = http_request(&sock_path, &req, &body);
            assert!(resp.contains("403"));
            let body_str = http_body(&resp);
            assert!(body_str.contains("forbidden"));
            shutdown.store(true, Ordering::Release);
            handle.join().unwrap();
        }

        #[test]
        fn http_duplicate_request_within_ttl_returns_cached_assertion() {
            let (shutdown, _dir, sock_path, _registry, token, _f, handle) = setup_bound(false);
            let body = sign_request_body(
                "https://example.com",
                "example.com",
                "dGVzdA",
                vec![],
                false,
            );
            let req = format_sign_request(&token, &body);
            let resp1 = http_request(&sock_path, &req, &body);
            assert!(resp1.contains("200 OK"));
            let parsed1: serde_json::Value = serde_json::from_str(http_body(&resp1)).unwrap();
            let auth1 = parsed1
                .get("sign_assertion_result")
                .unwrap()
                .get("authenticator_data_b64u")
                .unwrap()
                .as_str()
                .unwrap()
                .to_string();
            assert_eq!(extract_counter(&auth1), 1);

            // An identical request within the completed-outcome TTL returns the
            // same cached assertion instead of being re-signed. The counter is not
            // incremented again, so no new signature is produced (idempotent).
            let resp2 = http_request(&sock_path, &req, &body);
            assert!(resp2.contains("200 OK"));
            let parsed2: serde_json::Value = serde_json::from_str(http_body(&resp2)).unwrap();
            let auth2 = parsed2
                .get("sign_assertion_result")
                .unwrap()
                .get("authenticator_data_b64u")
                .unwrap()
                .as_str()
                .unwrap();
            assert_eq!(auth2, auth1);
            assert_eq!(extract_counter(auth2), 1);

            shutdown.store(true, Ordering::Release);
            handle.join().unwrap();
        }

        #[test]
        fn http_invalid_json_body() {
            let (shutdown, _dir, sock_path, _registry, token, _f, handle) = setup_bound(true);
            let body = b"{invalid json!!";
            let req = format_sign_request(&token, body);
            let resp = http_request(&sock_path, &req, body);
            assert!(resp.contains("400"));
            let body_str = http_body(&resp);
            assert!(body_str.contains("invalid_json"));
            shutdown.store(true, Ordering::Release);
            handle.join().unwrap();
        }

        #[test]
        fn http_body_too_large() {
            let (shutdown, _dir, sock_path, _registry, token, _f, handle) = setup_bound(true);
            let req = format!(
                "POST /sign HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: 99999\r\n\r\n",
                token
            );
            let resp = http_request(&sock_path, &req, b"");
            assert!(resp.contains("413"));
            let body_str = http_body(&resp);
            assert!(body_str.contains("body_too_large"));
            shutdown.store(true, Ordering::Release);
            handle.join().unwrap();
        }

        #[test]
        fn http_bearer_not_prefix_match() {
            let (shutdown, _dir, sock_path, _registry, token, _f, handle) = setup_bound(true);
            let prefix = &token[..10];
            let body = sign_request_body(
                "https://example.com",
                "example.com",
                "dGVzdA",
                vec![],
                false,
            );
            let req = format_sign_request(prefix, &body);
            let resp = http_request(&sock_path, &req, &body);
            assert!(resp.contains("401"));
            let body_str = http_body(&resp);
            assert!(body_str.contains("invalid_bearer"));
            shutdown.store(true, Ordering::Release);
            handle.join().unwrap();
        }

        #[test]
        fn http_wrong_auth_scheme() {
            let (shutdown, _dir, sock_path, _registry, token, _f, handle) = setup_bound(true);
            let body = sign_request_body(
                "https://example.com",
                "example.com",
                "dGVzdA",
                vec![],
                false,
            );
            let req = format!(
                "POST /sign HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                token,
                body.len()
            );
            let resp = http_request(&sock_path, &req, &body);
            assert!(resp.contains("401"));
            let body_str = http_body(&resp);
            assert!(body_str.contains("invalid_authorization_scheme"));
            shutdown.store(true, Ordering::Release);
            handle.join().unwrap();
        }

        #[test]
        fn http_cross_origin_theft_attempt() {
            let (shutdown, _dir, sock_path, _registry, token, _f, handle) = setup_bound(true);
            let body = sign_request_body(
                "https://attacker.com",
                "example.com",
                "dGVzdA",
                vec![],
                true,
            );
            let req = format_sign_request(&token, &body);
            let resp = http_request(&sock_path, &req, &body);
            assert!(resp.contains("403"));
            let body_str = http_body(&resp);
            assert!(body_str.contains("forbidden"));
            shutdown.store(true, Ordering::Release);
            handle.join().unwrap();
        }
    }
}
