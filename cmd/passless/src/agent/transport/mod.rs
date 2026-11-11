//! The daemon side of the agent sign transport (ADR 0014 sections 4.4 and 11, plan D2).
//!
//! The managed browser's extension worker keeps one `connectNative` port open to the `sign-proxy`
//! relay, which keeps one connection to this Unix socket. Both hops carry the same frames (see
//! [`frame`]): `hello`, `request`, `abort` and `keepalive` from the worker; `hello`, `result`,
//! `keepalive` and `error` from the daemon.
//!
//! Per connection:
//!
//! - one reader thread (this module's `serve_connection`) parses frames; a frame over 1 MiB, a
//!   payload that is not a JSON object, or an unknown `type` closes the connection;
//! - the first frame must be a valid `hello`: protocol version 2 and a known bearer. At most one
//!   connection per bearer is live; a newer hello supersedes the older connection;
//! - each admitted `request` runs on its own thread, bounded by the [`RequestLimiter`] caps
//!   (global, profile, this connection's [`ConnectionSlots`], session). A request over a cap is
//!   answered `busy` at once (plan R11);
//! - every request re-validates its bearer from scratch (sign registry for `get`, registration
//!   registry for `create`); the handlers re-check the session and its revocation epoch (V-M5);
//! - writes go through one write mutex (a leaf lock) with a 5 s timeout; a write that fails or
//!   times out closes the connection;
//! - a keepalive is written at most every [`KEEPALIVE_INTERVAL`];
//! - EOF, a read error or a write failure cancels every in-flight request of the connection (the
//!   `cancelled` closure of `sign_with` / `register_with` returns true) and no result is written.

pub(crate) mod frame;
mod readiness;
mod webauthn;

#[cfg(test)]
pub(crate) mod tests;

use std::collections::HashMap;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use log::{debug, warn};
use serde_json::{Map, Value, json};

use passless_core::agent::protocol::{ErrorCode, PrincipalResponse};

use super::audit_events::{TransportPeerRefusedBuilder, TransportVersionSkewBuilder};
use super::capacity::{
    BusyScope, ConnectionSlots, RequestLimiter, RequestPermit, decrement, try_increment,
};
use super::lock_order::{self, LockLevel};
use super::session::{MAX_CEREMONY_TIMEOUT, MIN_TRANSPORT_CEREMONY_TIMEOUT};
use super::sign::{BearerEntry, SignContextRegistry, constant_time_eq, dom_exception_name};

use self::frame::{FrameError, PROTOCOL_VERSION, WRITE_TIMEOUT, read_frame, write_frame};
use self::readiness::HelloState;
use self::webauthn::{Op, ParsedCeremony};

pub use self::readiness::{BearerReadiness, ReadinessRegistry};

/// Longest interval between two keepalives the daemon writes (the spec allows at most 20 s).
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
/// How long a new connection may take to say `hello`.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// A connection that sends nothing for this long is closed. The worker sends a keepalive every
/// 20 s whenever its port is open, so this only catches a peer that hung.
pub const IDLE_READ_TIMEOUT: Duration = Duration::from_secs(90);
/// The debug-build E2E hook that delays every successful result (E2E-20).
#[cfg(debug_assertions)]
pub const HOLD_RESULT_ENV: &str = "PASSLESS_E2E_HOLD_RESULT_MS";
/// The debug-build E2E hook that delays the start of every ceremony, before any policy check or
/// key use (E2E-17, E2E-19, E2E-22: an abort or a disconnect lands before key use).
#[cfg(debug_assertions)]
pub const HOLD_REQUEST_ENV: &str = "PASSLESS_E2E_HOLD_REQUEST_MS";
/// Longest version string kept from a hello.
const MAX_VERSION_LEN: usize = 64;
/// Longest bearer accepted in a hello (a bearer is 43 characters).
const MAX_BEARER_LEN: usize = 256;

/// The build version the daemon reports in its hello and compares the worker's and the relay's
/// against (plan V-L5).
pub fn build_version() -> String {
    frame::build_version_from(crate::build::PKG_VERSION, crate::build::SHORT_COMMIT)
}

/// The deadline of a ceremony carried by this transport, counted from when the request frame
/// arrived: Chromium's own clamp of the page timeout, `clamp(timeout, 3 min, 20 h)`, or 20 h when
/// the page set none (`AdjustTimeout()`; ADR 0014 section 8.1). Chromium gives up on the request
/// at that point, so a pending escalation is never cut short before the page itself would be
/// (E2E-20, E2E-21). It also bounds how long a duplicate waits for the original (section 9). An
/// escalation wait is further bounded by `agents.escalation_timeout` and the session TTL.
pub(crate) fn transport_ceremony_deadline(timeout_ms: Option<u64>, received: Instant) -> Instant {
    let timeout = timeout_ms
        .map(Duration::from_millis)
        .unwrap_or(MAX_CEREMONY_TIMEOUT)
        .clamp(MIN_TRANSPORT_CEREMONY_TIMEOUT, MAX_CEREMONY_TIMEOUT);
    received + timeout
}

/// Timings of the transport. Tests shorten them.
#[derive(Clone, Debug)]
pub struct TransportOptions {
    pub write_timeout: Duration,
    pub keepalive_interval: Duration,
    pub hello_timeout: Duration,
    pub idle_read_timeout: Duration,
    /// Debug builds only (`PASSLESS_E2E_HOLD_RESULT_MS`): delay every successful result. Keepalives
    /// keep flowing and an abort during the delay is honoured.
    pub hold_result: Option<Duration>,
    /// Debug builds only (`PASSLESS_E2E_HOLD_REQUEST_MS`): delay the start of every ceremony. An
    /// abort or a disconnect during the delay cancels the ceremony before key use.
    pub hold_request: Option<Duration>,
}

impl Default for TransportOptions {
    fn default() -> Self {
        Self {
            write_timeout: WRITE_TIMEOUT,
            keepalive_interval: KEEPALIVE_INTERVAL,
            hello_timeout: HELLO_TIMEOUT,
            idle_read_timeout: IDLE_READ_TIMEOUT,
            hold_result: None,
            hold_request: None,
        }
    }
}

impl TransportOptions {
    /// The defaults, plus the debug-build E2E hooks from the environment.
    pub fn from_env() -> Self {
        #[allow(unused_mut)]
        let mut options = Self::default();
        #[cfg(debug_assertions)]
        {
            options.hold_result = hold_result_from(std::env::var(HOLD_RESULT_ENV).ok().as_deref());
            options.hold_request =
                hold_result_from(std::env::var(HOLD_REQUEST_ENV).ok().as_deref());
        }
        options
    }
}

/// Parse the value of [`HOLD_RESULT_ENV`] or [`HOLD_REQUEST_ENV`] (milliseconds; zero or garbage
/// means no delay).
#[cfg(any(debug_assertions, test))]
fn hold_result_from(value: Option<&str>) -> Option<Duration> {
    value
        .and_then(|ms| ms.trim().parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map(Duration::from_millis)
}

/// The wire code of a ceremony error (`result.error.code`).
pub fn wire_error_code(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::BadRequest => "bad_request",
        ErrorCode::MalformedMessage => "invalid_json",
        ErrorCode::NotSupported => "not_supported",
        ErrorCode::Unauthorized => "unauthorized",
        ErrorCode::Forbidden => "forbidden",
        ErrorCode::OriginInvalid => "origin_invalid",
        ErrorCode::NotFound => "not_found",
        ErrorCode::Conflict => "conflict",
        ErrorCode::InvalidState => "invalid_state",
        ErrorCode::Replayed => "replayed_operation",
        ErrorCode::InteractionRequired => "human_interaction_required",
        ErrorCode::BudgetExhausted => "operation_budget_exhausted",
        ErrorCode::Busy => "busy",
        ErrorCode::Timeout => "operation_timeout",
        ErrorCode::Aborted => "aborted",
        _ => "internal_error",
    }
}

fn error_result(id: u32, code: ErrorCode) -> Value {
    json!({
        "type": "result",
        "id": id,
        "ok": false,
        "error": { "code": wire_error_code(code), "dom": dom_exception_name(code) },
    })
}

/// Reports the UID of a connection's peer (`SO_PEERCRED`); injectable for tests.
pub type PeerUidSource = Arc<dyn Fn(&UnixStream) -> Option<u32> + Send + Sync>;

/// The peer UID the kernel recorded when the peer connected.
pub fn peer_uid_from_socket(stream: &UnixStream) -> Option<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    (ret == 0).then_some(cred.uid)
}

/// The listening sockets of the sign transport: the daemon-UID socket, plus one socket per
/// browser UID that differs from the daemon's (`add_uid_socket`).
pub struct SignTransportServer {
    listeners: Vec<(UnixListener, PathBuf)>,
    socket_path: PathBuf,
    shutdown: Arc<AtomicBool>,
    peer_uid: PeerUidSource,
}

impl SignTransportServer {
    /// Bind `socket_path` (mode 0600, in a directory of mode 0700).
    pub fn bind(socket_path: PathBuf, shutdown: Arc<AtomicBool>) -> Result<Self, String> {
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create socket directory: {}", e))?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("set socket dir permissions: {}", e))?;
        }
        let listener = bind_socket(&socket_path)?;
        Ok(Self {
            listeners: vec![(listener, socket_path.clone())],
            socket_path,
            shutdown,
            peer_uid: Arc::new(peer_uid_from_socket),
        })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Test hook: report peer UIDs from `source` instead of `SO_PEERCRED`.
    #[cfg(test)]
    pub fn with_peer_uid_source(mut self, source: PeerUidSource) -> Self {
        self.peer_uid = source;
        self
    }

    /// Bind the socket a browser running as `uid` connects to: `<sign dir>/<uid>/sock`, in a
    /// directory owned by `uid` with mode 0700, the socket owned by `uid` with mode 0600. The sign
    /// directory becomes 0711 so that the browser user can traverse it without listing it. Needs
    /// the daemon to run as root (it chowns), and every ancestor of the sign directory to be
    /// traversable by `uid`; otherwise an error says why. Returns the socket path.
    pub fn add_uid_socket(&mut self, uid: u32, gid: u32) -> Result<PathBuf, String> {
        let sign_dir = self
            .socket_path
            .parent()
            .ok_or("the sign socket has no directory")?
            .to_path_buf();
        if unsafe { libc::geteuid() } != 0 {
            return Err(format!(
                "the daemon is not running as root, so it cannot give browser user {uid} its \
                 own sign socket; run the agent daemon as root (contrib/systemd/\
                 passless-agent.service) or set browser_user to the daemon's user"
            ));
        }
        std::fs::set_permissions(&sign_dir, std::fs::Permissions::from_mode(0o711))
            .map_err(|e| format!("set {} permissions: {e}", sign_dir.display()))?;
        if let Some(blocking) = untraversable_ancestor(&sign_dir, uid, gid) {
            return Err(format!(
                "browser user {uid} cannot traverse {} to reach its sign socket; make the \
                 runtime directory's parents searchable for that user",
                blocking.display()
            ));
        }
        // A directory left by an earlier run belongs to the browser user, who could have planted
        // a symlink in it: remove it (never following anything) and create a fresh one that stays
        // the daemon's until the socket in it is bound, chmodded and chowned; the directory is
        // handed to the browser user last (review H1).
        let name = uid.to_string();
        let uid_dir = sign_dir.join(&name);
        match std::fs::symlink_metadata(&uid_dir) {
            Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(&uid_dir)
                .map_err(|e| format!("remove stale {}: {e}", uid_dir.display()))?,
            Ok(_) => std::fs::remove_file(&uid_dir)
                .map_err(|e| format!("remove stale {}: {e}", uid_dir.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("inspect {}: {e}", uid_dir.display())),
        }
        let sign = crate::agent::safe_fs::Dir::open_path(&sign_dir)
            .map_err(|e| format!("open {}: {e}", sign_dir.display()))?;
        let pinned = sign
            .create_dir(&name, 0o700)
            .map_err(|e| format!("create {}: {e}", uid_dir.display()))?;
        let socket_path = uid_dir.join("sock");
        let listener = bind_socket(&socket_path)?;
        chown(&socket_path, uid, gid)?;
        pinned
            .chown(uid, gid)
            .map_err(|e| format!("chown {} to {uid}:{gid}: {e}", uid_dir.display()))?;
        self.listeners.push((listener, socket_path.clone()));
        Ok(socket_path)
    }

    /// Serve until shutdown. Connections beyond [`RequestLimiter::max_connections`] get
    /// `error{busy}` and are closed (plan R11). On shutdown every open connection is closed, which
    /// cancels its in-flight requests.
    pub fn serve(
        mut self,
        registry: Arc<SignContextRegistry>,
        limiter: Arc<RequestLimiter>,
        readiness: Arc<ReadinessRegistry>,
        options: TransportOptions,
    ) -> thread::JoinHandle<()> {
        let listeners = std::mem::take(&mut self.listeners);
        let shutdown = self.shutdown.clone();
        let shared = Arc::new(Shared {
            registry,
            limiter,
            readiness,
            options,
            daemon_version: build_version(),
            daemon_uid: unsafe { libc::geteuid() },
            peer_uid: self.peer_uid.clone(),
            connections: Mutex::new(HashMap::new()),
            next_connection: AtomicU64::new(1),
            open_connections: AtomicUsize::new(0),
        });
        thread::spawn(move || {
            for (listener, _) in &listeners {
                listener.set_nonblocking(true).expect("set_nonblocking");
            }
            while !shutdown.load(Ordering::Relaxed) {
                let mut idle = true;
                for (listener, _) in &listeners {
                    match listener.accept() {
                        Ok((stream, _addr)) => {
                            idle = false;
                            shared.admit(stream);
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(e) => warn!("sign transport accept error: {}", e),
                    }
                }
                if idle {
                    thread::sleep(Duration::from_millis(50));
                }
            }
            shared.close_all();
            for (_, path) in &listeners {
                let _ = std::fs::remove_file(path);
            }
        })
    }
}

impl Drop for SignTransportServer {
    fn drop(&mut self) {
        for (_, path) in &self.listeners {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn bind_socket(path: &Path) -> Result<UnixListener, String> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path).map_err(|e| format!("bind failed: {}", e))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("set socket permissions: {}", e))?;
    Ok(listener)
}

fn chown(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    std::os::unix::fs::lchown(path, Some(uid), Some(gid))
        .map_err(|e| format!("chown {} to {uid}:{gid}: {e}", path.display()))
}

/// The first directory of `dir` and its ancestors that `uid`/`gid` cannot traverse (search
/// permission), judged from the mode bits.
fn untraversable_ancestor(dir: &Path, uid: u32, gid: u32) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    for ancestor in dir.ancestors() {
        let Ok(meta) = std::fs::metadata(ancestor) else {
            return Some(ancestor.to_path_buf());
        };
        let mode = meta.mode();
        let searchable = if meta.uid() == uid {
            mode & 0o100 != 0
        } else if meta.gid() == gid {
            mode & 0o010 != 0
        } else {
            mode & 0o001 != 0
        };
        if !searchable {
            return Some(ancestor.to_path_buf());
        }
    }
    None
}

/// State shared by the accept loop and every connection.
struct Shared {
    registry: Arc<SignContextRegistry>,
    limiter: Arc<RequestLimiter>,
    readiness: Arc<ReadinessRegistry>,
    options: TransportOptions,
    daemon_version: String,
    /// The daemon's effective UID: the peer a bearer without a bound browser UID must have.
    daemon_uid: u32,
    peer_uid: PeerUidSource,
    /// Open connections by id (a leaf lock, `LockLevel::TransportConnection`).
    connections: Mutex<HashMap<u64, Arc<Connection>>>,
    next_connection: AtomicU64,
    open_connections: AtomicUsize,
}

impl Shared {
    fn admit(self: &Arc<Self>, stream: UnixStream) {
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_write_timeout(Some(self.options.write_timeout));
        if !try_increment(&self.open_connections, self.limiter.max_connections()) {
            self.limiter.note_overflow(BusyScope::Connections);
            reject_connection(stream, "busy");
            return;
        }
        let shared = self.clone();
        let spawned = thread::Builder::new()
            .name("agent-sign-conn".to_string())
            .spawn(move || {
                shared.serve_connection(stream);
                decrement(&shared.open_connections);
            });
        if let Err(e) = spawned {
            decrement(&self.open_connections);
            warn!("sign transport: failed to spawn a connection thread: {}", e);
        }
    }

    fn close_all(&self) {
        let open: Vec<Arc<Connection>> = self.lock_connections().values().cloned().collect();
        for connection in open {
            connection.close(None);
        }
    }

    fn lock_connections(&self) -> lock_order::Tracked<std::sync::MutexGuard<'_, ConnectionMap>> {
        lock_order::lock(&self.connections, LockLevel::TransportConnection)
    }

    /// The reader loop of one connection.
    fn serve_connection(self: &Arc<Self>, stream: UnixStream) {
        let (Ok(mut reader), Ok(writer)) = (stream.try_clone(), stream.try_clone()) else {
            return;
        };
        let peer_uid = (self.peer_uid)(&stream);
        // One absolute deadline from accept to a complete hello frame (a peer that trickles
        // bytes does not extend it); after the hello, the idle timeout applies per read.
        let hello_deadline = Instant::now() + self.options.hello_timeout;
        let id = self.next_connection.fetch_add(1, Ordering::Relaxed);
        let connection = Arc::new(Connection {
            id,
            writer: Mutex::new(writer),
            control: stream,
            closed: AtomicBool::new(false),
            in_flight: Mutex::new(HashMap::new()),
            slots: ConnectionSlots::new(),
        });
        self.lock_connections().insert(id, connection.clone());

        let mut peer: Option<Peer> = None;
        // Dropping the sender stops the keepalive writer.
        let mut keepalive_stop: Option<mpsc::Sender<()>> = None;
        loop {
            let read = if peer.is_none() {
                read_frame(&mut DeadlineReader {
                    stream: &mut reader,
                    deadline: hello_deadline,
                })
            } else {
                read_frame(&mut reader)
            };
            let frame = match read {
                Ok(frame) => frame,
                Err(FrameError::Eof) | Err(FrameError::Io(_)) => {
                    connection.close(None);
                    break;
                }
                Err(e) => {
                    debug!("sign transport: closing connection: {}", e);
                    connection.close(Some("bad_frame"));
                    break;
                }
            };
            let kind = frame.get("type").and_then(Value::as_str).unwrap_or("");
            let outcome = match (kind, peer.as_ref()) {
                ("hello", None) => match self.first_hello(&connection, &frame, peer_uid) {
                    Ok(authenticated) => {
                        peer = Some(authenticated);
                        let _ = reader.set_read_timeout(Some(self.options.idle_read_timeout));
                        keepalive_stop = Some(self.start_keepalive(&connection));
                        Ok(())
                    }
                    Err(code) => Err(code),
                },
                (_, None) => Err("unauthorized"),
                ("hello", Some(peer)) => self.repeated_hello(&connection, peer, &frame),
                ("request", Some(peer)) => self.request(&connection, peer, &frame),
                ("abort", Some(_)) => {
                    connection.abort(&frame);
                    Ok(())
                }
                ("keepalive", Some(_)) => Ok(()),
                _ => Err("bad_frame"),
            };
            if let Err(code) = outcome {
                connection.close(Some(code));
                break;
            }
            if connection.is_closed() {
                break;
            }
        }
        drop(keepalive_stop);
        self.lock_connections().remove(&id);
        if let Some(peer) = peer {
            self.readiness.on_disconnect(&peer.bearer, id);
        }
    }

    fn start_keepalive(&self, connection: &Arc<Connection>) -> mpsc::Sender<()> {
        let (stop, stopped) = mpsc::channel::<()>();
        let connection = connection.clone();
        let interval = self.options.keepalive_interval;
        let spawned = thread::Builder::new()
            .name("agent-sign-keepalive".to_string())
            .spawn(move || {
                while let Err(mpsc::RecvTimeoutError::Timeout) = stopped.recv_timeout(interval) {
                    if !connection.send(&json!({ "type": "keepalive" })) {
                        break;
                    }
                }
            });
        if let Err(e) = spawned {
            warn!(
                "sign transport: failed to spawn the keepalive writer: {}",
                e
            );
        }
        stop
    }

    /// Authenticate the first hello. On failure, the error code to send before closing.
    fn first_hello(
        &self,
        connection: &Arc<Connection>,
        frame: &Map<String, Value>,
        peer_uid: Option<u32>,
    ) -> Result<Peer, &'static str> {
        if frame.get("v").and_then(Value::as_u64) != Some(PROTOCOL_VERSION) {
            return Err("protocol_version");
        }
        let bearer = match frame.get("bearer") {
            Some(Value::String(bearer)) if !bearer.is_empty() && bearer.len() <= MAX_BEARER_LEN => {
                bearer.clone()
            }
            _ => return Err("bad_request"),
        };
        let state = hello_state(frame)?;
        let Some(entry) = self.registry.lookup_for_hello(&bearer) else {
            // A bearer revoked with its browser lease is refused like an unknown one, but the
            // attempt is audited (bounded per bearer).
            if let Some(revoked) = self.registry.lookup_revoked_sign(&bearer) {
                revoked.refuse(None);
            } else if let Some(revoked) = self.registry.lookup_revoked_registration(&bearer) {
                revoked.refuse(None);
            }
            return Err("unauthorized");
        };
        let epoch = entry.policy_runtime().revocation_epoch();
        if entry.session().validity(epoch, Instant::now()).is_err() {
            return Err("unauthorized");
        }
        // The relay must run as the lease's browser user (or as the daemon's user when the
        // browser shares it): a bearer copied out of the profile is useless to anyone else.
        let expected_uid = entry.session().browser_uid().unwrap_or(self.daemon_uid);
        if peer_uid != Some(expected_uid) {
            warn!(
                "sign transport: hello refused, peer uid {:?} is not the lease's browser uid {}",
                peer_uid, expected_uid
            );
            let event = TransportPeerRefusedBuilder::new(entry.profile_id().clone(), expected_uid)
                .peer_uid(peer_uid)
                .build();
            if let Err(e) = entry.audit_gate().record(event) {
                warn!("agent sign transport: peer refusal audit failed: {}", e);
            }
            return Err("unauthorized");
        }
        self.check_versions(&entry, &state);
        let (attached, incognito_allowed) = (state.attached, state.incognito_allowed);
        if let Some(superseded) = self.readiness.on_hello(&bearer, connection.id, state) {
            let previous = self.lock_connections().get(&superseded).cloned();
            if let Some(previous) = previous {
                previous.close(Some("superseded"));
            }
        }
        debug!(
            "sign transport: connection {} hello accepted (attached={}, incognito_allowed={})",
            connection.id, attached, incognito_allowed
        );
        connection.send(&json!({
            "type": "hello",
            "v": PROTOCOL_VERSION,
            "build_version": self.daemon_version,
        }));
        Ok(Peer { bearer })
    }

    /// A hello on an authenticated connection only updates the reported state; it may not change
    /// the bearer.
    fn repeated_hello(
        &self,
        connection: &Arc<Connection>,
        peer: &Peer,
        frame: &Map<String, Value>,
    ) -> Result<(), &'static str> {
        if frame.get("v").and_then(Value::as_u64) != Some(PROTOCOL_VERSION) {
            return Err("protocol_version");
        }
        let same_bearer = frame
            .get("bearer")
            .and_then(Value::as_str)
            .is_some_and(|bearer| constant_time_eq(bearer.as_bytes(), peer.bearer.as_bytes()));
        if !same_bearer {
            return Err("unauthorized");
        }
        let state = hello_state(frame)?;
        debug!(
            "sign transport: connection {} hello repeated (attached={}, incognito_allowed={})",
            connection.id, state.attached, state.incognito_allowed
        );
        // A connection that a newer one superseded changes nothing: it must not take the
        // bearer's readiness back from the live connection.
        if !self
            .readiness
            .on_repeated_hello(&peer.bearer, connection.id, state)
        {
            debug!(
                "sign transport: connection {} hello ignored (superseded)",
                connection.id
            );
        }
        Ok(())
    }

    /// A build or relay version that differs from the daemon's is logged and audited once per
    /// connection; it is not fatal (plan V-L5).
    fn check_versions(&self, entry: &BearerEntry, state: &HelloState) {
        let build_differs = state.build_version.as_deref() != Some(self.daemon_version.as_str());
        let relay_differs = state
            .relay_version
            .as_deref()
            .is_some_and(|relay| relay != self.daemon_version);
        if !build_differs && !relay_differs {
            return;
        }
        warn!(
            "agent sign transport version skew: daemon {}, extension {}, relay {}",
            self.daemon_version,
            state.build_version.as_deref().unwrap_or("unknown"),
            state.relay_version.as_deref().unwrap_or("unknown")
        );
        let event =
            TransportVersionSkewBuilder::new(entry.profile_id().clone(), &self.daemon_version)
                .reported(
                    state.build_version.as_deref(),
                    state.relay_version.as_deref(),
                )
                .build();
        if let Err(e) = entry.audit_gate().record(event) {
            warn!("agent sign transport: version skew audit failed: {}", e);
        }
    }

    /// Admit one `request` frame. Answers every admitted id exactly once; a frame without a
    /// usable id closes the connection.
    fn request(
        self: &Arc<Self>,
        connection: &Arc<Connection>,
        peer: &Peer,
        frame: &Map<String, Value>,
    ) -> Result<(), &'static str> {
        let received = Instant::now();
        let id = frame
            .get("id")
            .and_then(Value::as_u64)
            .and_then(|id| u32::try_from(id).ok())
            .ok_or("bad_frame")?;
        let reject = |code: ErrorCode| {
            debug!(
                "sign transport: connection {} request {} refused: {}",
                connection.id,
                id,
                wire_error_code(code)
            );
            connection.send(&error_result(id, code));
            Ok(())
        };
        let (Some(op), Some(body), Some(frame_origin), Some(frame_cross_origin)) = (
            frame.get("op").and_then(Value::as_str).and_then(Op::parse),
            frame.get("body").and_then(Value::as_str),
            frame.get("origin").and_then(Value::as_str),
            frame.get("cross_origin").and_then(Value::as_bool),
        ) else {
            return reject(ErrorCode::BadRequest);
        };
        // The worker never reuses a live id; a duplicate would get two results, so it is a
        // framing error that closes the connection.
        if connection.has_in_flight(id) {
            return Err("bad_frame");
        }

        // Re-validate the bearer from scratch on every request (plan V-M5).
        let entry = match op {
            Op::Get => match self.registry.lookup_bound(&peer.bearer) {
                Some(entry) => Some(BearerEntry::Sign(entry)),
                None => {
                    if let Some(revoked) = self.registry.lookup_revoked_sign(&peer.bearer) {
                        revoked.refuse(webauthn::refused_rp_id(op, body).as_deref());
                    }
                    None
                }
            },
            Op::Create => match self.registry.lookup_registration(&peer.bearer) {
                Some(entry) => Some(BearerEntry::Register(entry)),
                None => {
                    if let Some(revoked) = self.registry.lookup_revoked_registration(&peer.bearer) {
                        revoked.refuse(webauthn::refused_rp_id(op, body).as_deref());
                    }
                    None
                }
            },
        };
        let Some(entry) = entry else {
            return reject(ErrorCode::Unauthorized);
        };

        // The daemon's own parse is the only one used; the frame's copies must agree with it.
        let parsed = match webauthn::parse_request_details(op, body) {
            Ok(parsed) => parsed,
            Err(reason) => {
                debug!("sign transport: malformed request details: {}", reason);
                return reject(ErrorCode::BadRequest);
            }
        };
        if parsed.origin() != frame_origin || parsed.cross_origin() != frame_cross_origin {
            warn!("sign transport: request frame origin disagrees with the request details");
            return reject(ErrorCode::BadRequest);
        }

        // Capacity (plan R11): over any cap the request is answered `busy`, never dropped.
        let permit = match self.limiter.try_acquire(&connection.slots, entry.session()) {
            Ok(permit) => permit,
            Err(scope) => {
                self.limiter.note_overflow(scope);
                return reject(ErrorCode::Busy);
            }
        };

        let state = Arc::new(RequestState::default());
        connection.track(id, state.clone());
        debug!(
            "sign transport: connection {} request {} admitted ({:?})",
            connection.id, id, op
        );
        let deadline = transport_ceremony_deadline(parsed.timeout_ms(), received);
        let shared = self.clone();
        let worker_connection = connection.clone();
        let spawned = thread::Builder::new()
            .name("agent-sign-req".to_string())
            .spawn(move || {
                shared.hold_request(&state);
                let mut permit = permit;
                let outcome = run_ceremony(&entry, &parsed, deadline, &state, &mut permit);
                let held_aborted = outcome.is_ok() && shared.hold_result(&state);
                worker_connection.untrack(id);
                let result = match outcome {
                    Ok(_) if held_aborted => error_result(id, ErrorCode::Aborted),
                    Ok(response_json) => json!({
                        "type": "result",
                        "id": id,
                        "ok": true,
                        "body": response_json,
                    }),
                    Err(_) if state.aborted.load(Ordering::Acquire) => {
                        error_result(id, ErrorCode::Aborted)
                    }
                    Err(code) => error_result(id, code),
                };
                let written = worker_connection.send(&result);
                debug!(
                    "sign transport: connection {} request {} {}: {}",
                    worker_connection.id,
                    id,
                    if written {
                        "answered"
                    } else {
                        "not answered (connection closed)"
                    },
                    result
                        .get("error")
                        .and_then(|error| error.get("code"))
                        .and_then(Value::as_str)
                        .unwrap_or("ok")
                );
                drop(permit);
            });
        if let Err(e) = spawned {
            warn!("sign transport: failed to spawn a request thread: {}", e);
            connection.untrack(id);
            return reject(ErrorCode::Busy);
        }
        Ok(())
    }

    /// The E2E-17/19/22 hook: hold a request before its ceremony starts, until the hold elapses
    /// or the request is cancelled (the ceremony then stops before key use).
    fn hold_request(&self, state: &RequestState) {
        if let Some(hold) = self.options.hold_request {
            hold_until_cancelled(state, hold);
        }
    }

    /// The E2E-20 hook: hold a successful result. Returns whether the request was cancelled
    /// meanwhile (an abort is then answered `aborted`).
    fn hold_result(&self, state: &RequestState) -> bool {
        let Some(hold) = self.options.hold_result else {
            return false;
        };
        hold_until_cancelled(state, hold)
    }
}

/// Wait `hold` or until the request is cancelled; returns whether it was cancelled.
fn hold_until_cancelled(state: &RequestState, hold: Duration) -> bool {
    let until = Instant::now() + hold;
    loop {
        if state.cancelled.load(Ordering::Acquire) {
            return true;
        }
        let now = Instant::now();
        if now >= until {
            return false;
        }
        thread::sleep((until - now).min(Duration::from_millis(20)));
    }
}

/// Reads with every `read` bounded by what is left until `deadline`, so a whole frame, not each
/// read, must arrive before it.
struct DeadlineReader<'a> {
    stream: &'a mut UnixStream,
    deadline: Instant,
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
        }
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(buf)
    }
}

type ConnectionMap = HashMap<u64, Arc<Connection>>;

/// The authenticated end of a connection.
struct Peer {
    bearer: String,
}

/// The cancellation state of one in-flight request.
#[derive(Default)]
struct RequestState {
    /// The handler's `cancelled` closure returns this.
    cancelled: AtomicBool,
    /// The worker sent `abort` for this id.
    aborted: AtomicBool,
}

struct Connection {
    id: u64,
    /// Frames are written whole under this mutex (a leaf lock, `LockLevel::TransportWrite`).
    writer: Mutex<UnixStream>,
    /// Used to shut the socket down, which also unblocks the reader.
    control: UnixStream,
    /// Set under the write mutex; nothing is written once it is set.
    closed: AtomicBool,
    /// In-flight requests by wire id (a leaf lock, `LockLevel::TransportConnection`).
    in_flight: Mutex<HashMap<u32, Arc<RequestState>>>,
    slots: Arc<ConnectionSlots>,
}

impl Connection {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Write one frame. A failed or timed-out write closes the connection. Returns whether the
    /// frame was written.
    fn send(&self, frame: &Value) -> bool {
        let Ok(payload) = serde_json::to_vec(frame) else {
            return false;
        };
        let mut writer = lock_order::lock(&self.writer, LockLevel::TransportWrite);
        if self.closed.load(Ordering::Acquire) {
            return false;
        }
        if let Err(e) = write_frame(&mut *writer, &payload) {
            debug!(
                "sign transport: write failed, closing the connection: {}",
                e
            );
            self.closed.store(true, Ordering::Release);
            drop(writer);
            self.after_close();
            return false;
        }
        true
    }

    /// Close the connection, first sending `error{code}` when given. Cancels every in-flight
    /// request; none of them writes a result afterwards.
    fn close(&self, code: Option<&str>) {
        let mut writer = lock_order::lock(&self.writer, LockLevel::TransportWrite);
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(code) = code {
            let _ = write_frame(
                &mut *writer,
                json!({ "type": "error", "code": code })
                    .to_string()
                    .as_bytes(),
            );
        }
        drop(writer);
        self.after_close();
    }

    fn after_close(&self) {
        let _ = self.control.shutdown(std::net::Shutdown::Both);
        let in_flight: Vec<Arc<RequestState>> = self.lock_in_flight().values().cloned().collect();
        debug!(
            "sign transport: connection {} closed; cancelling {} in-flight request(s)",
            self.id,
            in_flight.len()
        );
        for state in in_flight {
            state.cancelled.store(true, Ordering::Release);
        }
    }

    fn lock_in_flight(
        &self,
    ) -> lock_order::Tracked<std::sync::MutexGuard<'_, HashMap<u32, Arc<RequestState>>>> {
        lock_order::lock(&self.in_flight, LockLevel::TransportConnection)
    }

    fn has_in_flight(&self, id: u32) -> bool {
        self.lock_in_flight().contains_key(&id)
    }

    fn track(&self, id: u32, state: Arc<RequestState>) {
        self.lock_in_flight().insert(id, state);
        // A close that raced the insert has already cancelled everything else.
        if self.is_closed() {
            self.after_close();
        }
    }

    fn untrack(&self, id: u32) {
        self.lock_in_flight().remove(&id);
    }

    /// `abort{id}`: cancel that request. Its result (normally `aborted`) still follows.
    fn abort(&self, frame: &Map<String, Value>) {
        let Some(id) = frame
            .get("id")
            .and_then(Value::as_u64)
            .and_then(|id| u32::try_from(id).ok())
        else {
            return;
        };
        let state = self.lock_in_flight().get(&id).cloned();
        debug!(
            "sign transport: connection {} abort for request {} ({})",
            self.id,
            id,
            if state.is_some() {
                "in flight"
            } else {
                "not in flight"
            }
        );
        if let Some(state) = state {
            state.aborted.store(true, Ordering::Release);
            state.cancelled.store(true, Ordering::Release);
        }
    }
}

/// Run the ceremony and build its `responseJson`.
/// `permit` is suspended while the ceremony is parked on an escalation and resumed afterwards
/// (plan P7 gap 2), so parked ceremonies do not hold the request caps.
fn run_ceremony(
    entry: &BearerEntry,
    parsed: &ParsedCeremony,
    deadline: Instant,
    state: &RequestState,
    permit: &mut RequestPermit,
) -> Result<String, ErrorCode> {
    let cancelled = || state.cancelled.load(Ordering::Acquire);
    match (entry, parsed) {
        (BearerEntry::Sign(entry), ParsedCeremony::Get(request)) => {
            match entry
                .handler
                .sign_parked(&entry.context, request, deadline, &cancelled, permit)
                .map_err(|e| e.code)?
            {
                PrincipalResponse::SignAssertionResult(response) => {
                    Ok(webauthn::assertion_response_json(&response))
                }
                _ => Err(ErrorCode::Internal),
            }
        }
        (
            BearerEntry::Register(entry),
            ParsedCeremony::Create {
                request,
                cred_props,
            },
        ) => {
            let response = entry
                .handler
                .register_parked(&entry.context, request, deadline, &cancelled, permit)
                .map_err(|e| e.code)?;
            webauthn::attestation_response_json(&response, *cred_props).map_err(|reason| {
                warn!(
                    "sign transport: cannot build the registration response: {}",
                    reason
                );
                ErrorCode::Internal
            })
        }
        _ => Err(ErrorCode::Internal),
    }
}

/// What a hello reports, with the version strings bounded.
fn hello_state(frame: &Map<String, Value>) -> Result<HelloState, &'static str> {
    let flag = |name: &str| match frame.get(name) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err("bad_request"),
    };
    Ok(HelloState {
        attached: flag("attached")?,
        incognito_allowed: flag("incognito_allowed")?,
        build_version: reported_version(frame.get("build_version")),
        relay_version: reported_version(frame.get("relay_version")),
    })
}

/// A reported version string, kept only when it is short printable ASCII.
fn reported_version(value: Option<&Value>) -> Option<String> {
    let version = value?.as_str()?;
    (!version.is_empty()
        && version.len() <= MAX_VERSION_LEN
        && version.bytes().all(|b| b.is_ascii_graphic()))
    .then(|| version.to_string())
}

/// Answer a connection the daemon will not serve, then close it.
fn reject_connection(stream: UnixStream, code: &str) {
    let mut stream = stream;
    let _ = write_frame(
        &mut stream,
        json!({ "type": "error", "code": code })
            .to_string()
            .as_bytes(),
    );
    let _ = stream.shutdown(std::net::Shutdown::Both);
}
