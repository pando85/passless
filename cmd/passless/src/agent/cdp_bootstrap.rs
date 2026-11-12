use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_CONNECTIONS: usize = 16;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_BACKOFF: Duration = Duration::from_millis(20);

#[derive(Debug)]
pub enum BootstrapError {
    Bind(std::io::Error),
    Configure(std::io::Error),
    Thread(std::io::Error),
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bind(e) => write!(f, "failed to bind CDP bootstrap listener: {e}"),
            Self::Configure(e) => write!(f, "failed to configure CDP bootstrap listener: {e}"),
            Self::Thread(e) => write!(f, "failed to start CDP bootstrap thread: {e}"),
        }
    }
}

impl std::error::Error for BootstrapError {}

/// Why the bootstrap could not hand out an endpoint: the full text (for the wrapper's stderr) and,
/// when the caller knows it, the class; otherwise the class is derived from the text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnsureError {
    pub class: Option<&'static str>,
    pub message: String,
}

impl EnsureError {
    pub fn new(class: &'static str, message: impl Into<String>) -> Self {
        Self {
            class: Some(class),
            message: message.into(),
        }
    }

    /// The class and its fixed, secret-free hint.
    fn classify(&self) -> (&'static str, &'static str) {
        match self.class {
            Some(class) => (class, hint_for(class)),
            None => classify_ensure_error(&self.message),
        }
    }
}

impl From<String> for EnsureError {
    fn from(message: String) -> Self {
        Self {
            class: None,
            message,
        }
    }
}

/// The path prefix of the error endpoint a failed discovery points Playwright at.
const UNAVAILABLE_PATH: &str = "/passless/unavailable/";

/// Small loopback-only HTTP discovery endpoint used by Playwright's CDP connector.
///
/// This is deliberately *not* a CDP proxy. `/json/version` authenticates the caller,
/// lazily asks the Passless agent to ensure the managed browser exists, and returns the
/// browser's real websocket endpoint. All CDP traffic subsequently flows directly from
/// Playwright to Chromium, which is why this integration is only valid for Passless'
/// explicitly trusted `browser_cdp_expose = "port"` mode.
///
/// When no browser can be ensured, `/json/version` answers with a `webSocketDebuggerUrl` on this
/// listener, `/passless/unavailable/<class>`, and that path answers every authenticated request,
/// the WebSocket upgrade included, with `503` and a one-line explanation. Playwright puts the body
/// of a failed WebSocket handshake into its error, but not that of a failed `/json/version`, so
/// this is how the MCP client learns why ("passless daemon unavailable, ..."). No WebSocket is
/// ever accepted here.
pub struct CdpBootstrap {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl CdpBootstrap {
    pub fn start<F>(token: String, ensure_browser: F) -> Result<Self, BootstrapError>
    where
        F: Fn() -> Result<String, EnsureError> + Send + Sync + 'static,
    {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .map_err(BootstrapError::Bind)?;
        listener
            .set_nonblocking(true)
            .map_err(BootstrapError::Configure)?;
        let addr = listener.local_addr().map_err(BootstrapError::Configure)?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_thread = shutdown.clone();
        let ensure_browser = Arc::new(ensure_browser);
        let active = Arc::new(AtomicUsize::new(0));

        let join = thread::Builder::new()
            .name("passless-cdp-bootstrap".to_string())
            .spawn(move || {
                while !shutdown_thread.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _peer)) => {
                            if active.load(Ordering::Acquire) >= MAX_CONNECTIONS {
                                let _ = reject_busy(stream);
                                continue;
                            }
                            active.fetch_add(1, Ordering::AcqRel);
                            let active_worker = active.clone();
                            let token_worker = token.clone();
                            let ensure_worker = ensure_browser.clone();
                            if let Err(e) = thread::Builder::new()
                                .name("passless-cdp-bootstrap-request".to_string())
                                .spawn(move || {
                                    let _guard = ConnectionGuard(active_worker);
                                    if let Err(e) = handle_connection(
                                        stream,
                                        &token_worker,
                                        ensure_worker.as_ref(),
                                    ) {
                                        log::debug!("CDP bootstrap request failed: {e}");
                                    }
                                })
                            {
                                active.fetch_sub(1, Ordering::AcqRel);
                                report_to_wrapper_stderr(&format!(
                                    "failed to spawn CDP bootstrap request worker: {e}"
                                ));
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(ACCEPT_BACKOFF);
                        }
                        Err(e) => {
                            log::warn!("CDP bootstrap listener failed: {e}");
                            thread::sleep(ACCEPT_BACKOFF);
                        }
                    }
                }
            })
            .map_err(BootstrapError::Thread)?;

        Ok(Self {
            addr,
            shutdown,
            join: Some(join),
        })
    }

    pub fn endpoint(&self) -> String {
        format!("http://{}", self.addr)
    }

    #[cfg(test)]
    fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        // Wake the nonblocking accept loop so shutdown is prompt even if its polling
        // interval changes in the future.
        let _ = TcpStream::connect(self.addr);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for CdpBootstrap {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct ConnectionGuard(Arc<AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn handle_connection<F>(
    mut stream: TcpStream,
    token: &str,
    ensure_browser: &F,
) -> Result<(), std::io::Error>
where
    F: Fn() -> Result<String, EnsureError> + ?Sized,
{
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    let request = match read_request(&mut stream) {
        Ok(request) => request,
        Err(RequestError::TooLarge) => {
            return write_json(
                &mut stream,
                431,
                "Request Header Fields Too Large",
                r#"{"error":"request headers too large"}"#,
                &[],
            );
        }
        Err(RequestError::Invalid) => {
            return write_json(
                &mut stream,
                400,
                "Bad Request",
                r#"{"error":"invalid request"}"#,
                &[],
            );
        }
        Err(RequestError::Io(e)) => return Err(e),
    };

    if request.method != "GET" {
        return write_json(
            &mut stream,
            405,
            "Method Not Allowed",
            r#"{"error":"method not allowed"}"#,
            &[("Allow", "GET")],
        );
    }

    match request.path.as_str() {
        "/healthz" => write_json(&mut stream, 200, "OK", r#"{"status":"ok"}"#, &[]),
        "/json/version" | "/json/version/" => {
            if !authorized(&request, token) {
                return unauthorized(&mut stream);
            }

            match ensure_browser() {
                Ok(ws_endpoint) if valid_loopback_ws_endpoint(&ws_endpoint) => {
                    let body = serde_json::json!({
                        "Browser": "Passless managed Chromium",
                        "Protocol-Version": "1.3",
                        "webSocketDebuggerUrl": ws_endpoint,
                    })
                    .to_string();
                    write_json(&mut stream, 200, "OK", &body, &[])
                }
                Ok(_) => {
                    report_to_wrapper_stderr(
                        "agent returned a non-loopback or invalid CDP websocket endpoint",
                    );
                    write_json(
                        &mut stream,
                        503,
                        "Service Unavailable",
                        r#"{"error":"managed browser endpoint unavailable"}"#,
                        &[],
                    )
                }
                Err(e) => {
                    // The answer carries the failure's class and a fixed hint, never the
                    // daemon's message: that may hold paths or policy details. The wrapper's
                    // stderr gets the full text (the `agent` client subcommands run before
                    // logging is initialised, so a `log::` call would be dropped there); the
                    // daemon's own log has the refusal or the launch error from its side.
                    let (class, _hint) = e.classify();
                    report_to_wrapper_stderr(&bootstrap_failure_message(class, &e.message));
                    let local = stream.local_addr()?;
                    let body = serde_json::json!({
                        "Browser": "Passless managed browser (unavailable)",
                        "Protocol-Version": "1.3",
                        "webSocketDebuggerUrl": format!("ws://{local}{UNAVAILABLE_PATH}{class}"),
                    })
                    .to_string();
                    write_json(&mut stream, 200, "OK", &body, &[])
                }
            }
        }
        path if path.starts_with(UNAVAILABLE_PATH) => {
            if !authorized(&request, token) {
                return unauthorized(&mut stream);
            }
            let named = &path[UNAVAILABLE_PATH.len()..];
            match KNOWN_CLASSES.iter().find(|class| **class == named) {
                Some(class) => write_text(
                    &mut stream,
                    503,
                    "Service Unavailable",
                    &unavailable_text(class),
                ),
                None => write_json(
                    &mut stream,
                    404,
                    "Not Found",
                    r#"{"error":"not found"}"#,
                    &[],
                ),
            }
        }
        _ => write_json(
            &mut stream,
            404,
            "Not Found",
            r#"{"error":"not found"}"#,
            &[],
        ),
    }
}

/// The line the wrapper prints when a discovery request could not be served.
fn bootstrap_failure_message(class: &str, error: &str) -> String {
    format!("failed to ensure managed browser for CDP bootstrap ({class}): {error}")
}

/// Tell the wrapper's user, on stderr. The `agent` client subcommands (`agent mcp playwright`)
/// run before `logging::init`, so a `log::warn!` there goes nowhere; stdout is the MCP stdio
/// channel and must stay clean, so this writes to stderr only. The record is also sent to the
/// `log` facade for the case where a logger is installed.
fn report_to_wrapper_stderr(message: &str) {
    log::warn!("{message}");
    let _ = writeln!(std::io::stderr().lock(), "passless: {message}");
}

/// Every class a failed discovery can name (the error endpoint serves only these).
const KNOWN_CLASSES: &[&str] = &[
    "daemon_unreachable",
    "session_lost",
    "session_ended",
    "runtime_root_invalid",
    "launch_failed",
    "refused",
    "unavailable",
];

/// The fixed, secret-free hint of a class: what happened and where to look.
fn hint_for(class: &str) -> &'static str {
    match class {
        "daemon_unreachable" => {
            "passless daemon unavailable, retrying on the next browser tool call: the daemon is \
             not running (stopped or restarting), or runs without agents; this MCP server stays \
             up. If it does not come back, check `systemctl --user status passless` and \
             `passless doctor --agents`"
        }
        "session_lost" => {
            "the principal session of this MCP server ended while the daemon still answers; \
             retry in a few seconds (a restarting daemon gets a new session on the next call)"
        }
        "session_ended" => {
            "the daemon ended the principal session of this MCP server (revoked, expired, its \
             grants revoked or its profile disabled); the server exits: restart it in your MCP \
             client"
        }
        "runtime_root_invalid" => {
            "the browser runtime root could not be used: see the passless daemon's log \
             (journalctl --user -u passless) for the directory and the reason"
        }
        "launch_failed" => {
            "the daemon could not start the browser: see the passless daemon's log \
             (journalctl --user -u passless) and run `passless doctor --agents`"
        }
        _ => "see the passless daemon's log (journalctl --user -u passless)",
    }
}

/// The body of the error endpoint: one line that the MCP client shows in the tool's error.
fn unavailable_text(class: &str) -> String {
    format!(
        "passless: managed browser unavailable ({class}): {}\n",
        hint_for(class)
    )
}

/// The class of a failed `EnsureBrowser` and its hint, from the error text the agent client
/// produced. The class is one of [`KNOWN_CLASSES`].
fn classify_ensure_error(error: &str) -> (&'static str, &'static str) {
    let has = |needle: &str| error.contains(needle);
    let class = if has("no agent socket") || has("daemon is not running") {
        "daemon_unreachable"
    } else if has("invalid runtime root") {
        "runtime_root_invalid"
    } else if has("failed to launch browser") {
        "launch_failed"
    } else if has("denied")
        || has("not allowed")
        || has("refused")
        || has("requires browser_cdp_expose")
    {
        "refused"
    } else {
        "unavailable"
    };
    (class, hint_for(class))
}

/// Whether `request` carries the bootstrap's bearer.
fn authorized(request: &HttpRequest, token: &str) -> bool {
    let Some(auth) = request.header("authorization") else {
        return false;
    };
    let expected = format!("Bearer {token}");
    constant_time_eq(auth.as_bytes(), expected.as_bytes())
}

fn reject_busy(mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    write_json(
        &mut stream,
        503,
        "Service Unavailable",
        r#"{"error":"bootstrap busy"}"#,
        &[("Retry-After", "1")],
    )
}

fn unauthorized(stream: &mut TcpStream) -> std::io::Result<()> {
    write_json(
        stream,
        401,
        "Unauthorized",
        r#"{"error":"unauthorized"}"#,
        &[("WWW-Authenticate", "Bearer")],
    )
}

fn write_json(
    stream: &mut TcpStream,
    code: u16,
    reason: &str,
    body: &str,
    extra_headers: &[(&str, &str)],
) -> std::io::Result<()> {
    write_response(
        stream,
        code,
        reason,
        "application/json; charset=utf-8",
        body,
        extra_headers,
    )
}

fn write_text(stream: &mut TcpStream, code: u16, reason: &str, body: &str) -> std::io::Result<()> {
    write_response(stream, code, reason, "text/plain; charset=utf-8", body, &[])
}

fn write_response(
    stream: &mut TcpStream,
    code: u16,
    reason: &str,
    content_type: &str,
    body: &str,
    extra_headers: &[(&str, &str)],
) -> std::io::Result<()> {
    let mut response = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in extra_headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("\r\n");
    response.push_str(body);
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

enum RequestError {
    Io(std::io::Error),
    Invalid,
    TooLarge,
}

fn read_request(stream: &mut TcpStream) -> Result<HttpRequest, RequestError> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if buf.len() >= MAX_REQUEST_BYTES {
            return Err(RequestError::TooLarge);
        }
        let remaining = MAX_REQUEST_BYTES - buf.len();
        let read_len = remaining.min(chunk.len());
        let n = stream
            .read(&mut chunk[..read_len])
            .map_err(RequestError::Io)?;
        if n == 0 {
            return Err(RequestError::Invalid);
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }

    let raw = std::str::from_utf8(&buf).map_err(|_| RequestError::Invalid)?;
    let head_end = raw.find("\r\n\r\n").ok_or(RequestError::Invalid)?;
    let mut lines = raw[..head_end].split("\r\n");
    let request_line = lines.next().ok_or(RequestError::Invalid)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or(RequestError::Invalid)?;
    let target = parts.next().ok_or(RequestError::Invalid)?;
    let version = parts.next().ok_or(RequestError::Invalid)?;
    if parts.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(RequestError::Invalid);
    }
    if method.len() > 16 || !target.starts_with('/') || target.contains('\0') {
        return Err(RequestError::Invalid);
    }
    let path = target.split_once('?').map_or(target, |(path, _)| path);

    let mut headers = Vec::new();
    for line in lines {
        if line.starts_with(' ') || line.starts_with('\t') {
            // Obsolete folded headers are intentionally rejected to avoid ambiguous parsing.
            return Err(RequestError::Invalid);
        }
        let (name, value) = line.split_once(':').ok_or(RequestError::Invalid)?;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(RequestError::Invalid);
        }
        let value = value.trim();
        if value.bytes().any(|b| b < 0x20 && b != b'\t') {
            return Err(RequestError::Invalid);
        }
        headers.push((name.to_ascii_lowercase(), value.to_string()));
    }

    Ok(HttpRequest {
        method: method.to_string(),
        path: path.to_string(),
        headers,
    })
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let max = a.len().max(b.len());
    let mut diff = a.len() ^ b.len();
    for i in 0..max {
        let left = a.get(i).copied().unwrap_or(0);
        let right = b.get(i).copied().unwrap_or(0);
        diff |= usize::from(left ^ right);
    }
    diff == 0
}

/// The daemon hands out only `ws://127.0.0.1:<port>/devtools/browser/<id>`, after verifying that
/// the listener there is the managed browser's (ADR 0014 section 4.3). Anything else, such as an
/// `[::1]` endpoint, is not relayed.
fn valid_loopback_ws_endpoint(endpoint: &str) -> bool {
    let Some(rest) = endpoint.strip_prefix("ws://") else {
        return false;
    };
    let Some((authority, path)) = rest.split_once('/') else {
        return false;
    };
    if !path.starts_with("devtools/browser/") || path.len() <= "devtools/browser/".len() {
        return false;
    }
    authority
        .strip_prefix("127.0.0.1:")
        .is_some_and(|port| port.parse::<u16>().is_ok_and(|port| port != 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn request(addr: SocketAddr, raw: &str) -> String {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.write_all(raw.as_bytes()).unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut out = String::new();
        stream.read_to_string(&mut out).unwrap();
        out
    }

    #[test]
    fn health_does_not_start_browser() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_cb = calls.clone();
        let server = CdpBootstrap::start("secret".into(), move || {
            calls_cb.fetch_add(1, Ordering::SeqCst);
            Ok("ws://127.0.0.1:9222/devtools/browser/test".into())
        })
        .unwrap();

        let response = request(
            server.addr(),
            "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        );
        assert!(response.starts_with("HTTP/1.1 200"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn discovery_requires_auth_before_side_effects() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_cb = calls.clone();
        let server = CdpBootstrap::start("secret".into(), move || {
            calls_cb.fetch_add(1, Ordering::SeqCst);
            Ok("ws://127.0.0.1:9222/devtools/browser/test".into())
        })
        .unwrap();

        let response = request(
            server.addr(),
            "GET /json/version HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        );
        assert!(response.starts_with("HTTP/1.1 401"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn authenticated_discovery_returns_actual_websocket() {
        let server = CdpBootstrap::start("secret".into(), || {
            Ok("ws://127.0.0.1:43871/devtools/browser/uuid".into())
        })
        .unwrap();

        let response = request(
            server.addr(),
            "GET /json/version/ HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer secret\r\n\r\n",
        );
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(
            response
                .contains(r#""webSocketDebuggerUrl":"ws://127.0.0.1:43871/devtools/browser/uuid""#)
        );
    }

    #[test]
    fn rejects_non_loopback_endpoint() {
        let server = CdpBootstrap::start("secret".into(), || {
            Ok("ws://10.0.0.4:9222/devtools/browser/uuid".into())
        })
        .unwrap();

        let response = request(
            server.addr(),
            "GET /json/version HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer secret\r\n\r\n",
        );
        assert!(response.starts_with("HTTP/1.1 503"));
    }

    /// Only the `127.0.0.1` endpoint the daemon verified is relayed: an `[::1]` or `localhost`
    /// one (where a browser that lost its `127.0.0.1` bind would listen) is not.
    #[test]
    fn relays_only_ipv4_loopback_endpoints() {
        assert!(valid_loopback_ws_endpoint(
            "ws://127.0.0.1:43871/devtools/browser/uuid"
        ));
        for bad in [
            "ws://[::1]:9333/devtools/browser/uuid",
            "ws://localhost:9333/devtools/browser/uuid",
            "ws://127.0.0.1:0/devtools/browser/uuid",
            "ws://127.0.0.1:9333/devtools/page/uuid",
            "ws://127.0.0.1:9333/devtools/browser/",
        ] {
            assert!(!valid_loopback_ws_endpoint(bad), "{bad}");
        }
    }

    /// The `webSocketDebuggerUrl` of a failed discovery, and the answer at it.
    fn failed_discovery(server: &CdpBootstrap) -> (String, String) {
        let response = request(
            server.addr(),
            "GET /json/version/ HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer secret\r\n\r\n",
        );
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        let body = response.split("\r\n\r\n").nth(1).unwrap().to_string();
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let ws = json["webSocketDebuggerUrl"].as_str().unwrap().to_string();
        let path = ws
            .strip_prefix(&format!("ws://{}", server.addr()))
            .unwrap_or_else(|| panic!("the error endpoint is on the bootstrap: {ws}"));
        // What Playwright's WebSocket handshake gets there (it sends the bearer header again).
        let answer = request(
            server.addr(),
            &format!(
                "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer secret\r\n\
                 Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
                 Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
            ),
        );
        (body, answer)
    }

    /// A failed launch points Playwright at the error endpoint, whose `503` body (which Playwright
    /// shows) names the class and a fixed hint, and never echoes the daemon's message.
    #[test]
    fn a_failed_launch_names_the_class_and_leaks_nothing() {
        let server = CdpBootstrap::start("secret".into(), || {
            Err(EnsureError::from(
                "protocol error: failed to launch browser: invalid runtime root: \
                 /run/user/1000/passless/browser: No such file or directory"
                    .to_string(),
            ))
        })
        .unwrap();
        let (discovery, answer) = failed_discovery(&server);
        assert!(
            discovery.contains("/passless/unavailable/runtime_root_invalid"),
            "{discovery}"
        );
        assert!(answer.starts_with("HTTP/1.1 503"), "{answer}");
        assert!(!answer.contains("101 Switching"), "{answer}");
        let text = answer.split("\r\n\r\n").nth(1).unwrap();
        assert!(
            text.starts_with("passless: managed browser unavailable (runtime_root_invalid): "),
            "{text}"
        );
        assert!(text.contains("daemon's log"), "{text}");
        for leak in [&discovery, &answer] {
            assert!(!leak.contains("/run/user"), "{leak}");
            assert!(!leak.contains("secret"), "{leak}");
        }
    }

    /// A daemon that is down (the wrapper outside a session says so with a class) reads as such
    /// in the MCP client: "passless daemon unavailable, retrying".
    #[test]
    fn a_down_daemon_reads_as_unavailable_and_retrying() {
        let server = CdpBootstrap::start("secret".into(), || {
            Err(EnsureError::new(
                "daemon_unreachable",
                "the passless daemon is not running",
            ))
        })
        .unwrap();
        let (_, answer) = failed_discovery(&server);
        assert!(answer.starts_with("HTTP/1.1 503"), "{answer}");
        assert!(
            answer.contains("passless daemon unavailable, retrying"),
            "{answer}"
        );
    }

    /// The error endpoint needs the bearer too, and serves only the known classes.
    #[test]
    fn the_error_endpoint_is_authenticated_and_closed() {
        let server = CdpBootstrap::start("secret".into(), || {
            Ok("ws://127.0.0.1:9222/devtools/browser/test".into())
        })
        .unwrap();
        let anonymous = request(
            server.addr(),
            "GET /passless/unavailable/daemon_unreachable HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        );
        assert!(anonymous.starts_with("HTTP/1.1 401"), "{anonymous}");
        let unknown = request(
            server.addr(),
            "GET /passless/unavailable/whatever HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer secret\r\n\r\n",
        );
        assert!(unknown.starts_with("HTTP/1.1 404"), "{unknown}");
        for class in KNOWN_CLASSES {
            assert!(!hint_for(class).is_empty());
            assert!(!unavailable_text(class).contains('\r'));
        }
    }

    #[test]
    fn ensure_errors_are_classified() {
        let class = |e: &str| classify_ensure_error(e).0;
        assert_eq!(
            class("the passless daemon is not running: no agent socket at /x"),
            "daemon_unreachable"
        );
        assert_eq!(
            class("protocol error: failed to launch browser: invalid runtime root: /x: nope"),
            "runtime_root_invalid"
        );
        assert_eq!(
            class("protocol error: failed to launch browser: failed to spawn browser: x"),
            "launch_failed"
        );
        assert_eq!(class("policy denied"), "refused");
        assert_eq!(
            class(
                "protocol error: Playwright browser discovery requires browser_cdp_expose = \
                 'port' (trusted agents only); in pipe mode run `passless agent browser`"
            ),
            "refused"
        );
        assert_eq!(class("something else"), "unavailable");
    }

    /// The line written to the wrapper's stderr keeps the daemon's full refusal text, which the
    /// 503 body deliberately does not carry.
    #[test]
    fn the_wrapper_stderr_line_carries_the_documented_refusal() {
        let refusal = "protocol error: Playwright browser discovery requires browser_cdp_expose = \
                       'port' (trusted agents only); in pipe mode run `passless agent browser` \
                       and drive the browser with `passless agent browser-control`";
        let (class, _hint) = classify_ensure_error(refusal);
        let line = bootstrap_failure_message(class, refusal);
        assert!(
            line.contains("requires browser_cdp_expose = 'port'"),
            "{line}"
        );
        assert!(
            line.contains("in pipe mode run `passless agent browser`"),
            "{line}"
        );
        assert!(line.contains("(refused)"), "{line}");
    }

    #[test]
    fn constant_time_comparison_handles_different_lengths() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
