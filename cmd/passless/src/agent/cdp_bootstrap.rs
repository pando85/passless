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

/// Small loopback-only HTTP discovery endpoint used by Playwright's CDP connector.
///
/// This is deliberately *not* a CDP proxy. `/json/version` authenticates the caller,
/// lazily asks the Passless agent to ensure the managed browser exists, and returns the
/// browser's real websocket endpoint. All CDP traffic subsequently flows directly from
/// Playwright to Chromium, which is why this integration is only valid for Passless'
/// explicitly trusted `browser_cdp_expose = "port"` mode.
pub struct CdpBootstrap {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl CdpBootstrap {
    pub fn start<F>(token: String, ensure_browser: F) -> Result<Self, BootstrapError>
    where
        F: Fn() -> Result<String, String> + Send + Sync + 'static,
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
                                log::warn!("failed to spawn CDP bootstrap request worker: {e}");
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
    F: Fn() -> Result<String, String> + ?Sized,
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
            let Some(auth) = request.header("authorization") else {
                return unauthorized(&mut stream);
            };
            let expected = format!("Bearer {token}");
            if !constant_time_eq(auth.as_bytes(), expected.as_bytes()) {
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
                    log::error!("agent returned a non-loopback or invalid CDP websocket endpoint");
                    write_json(
                        &mut stream,
                        503,
                        "Service Unavailable",
                        r#"{"error":"managed browser endpoint unavailable"}"#,
                        &[],
                    )
                }
                Err(e) => {
                    // Keep detailed daemon/profile information out of the HTTP response. It may
                    // contain paths or policy details; the wrapper's stderr is the right channel.
                    log::warn!("failed to ensure managed browser for CDP bootstrap: {e}");
                    write_json(
                        &mut stream,
                        503,
                        "Service Unavailable",
                        r#"{"error":"managed browser unavailable"}"#,
                        &[],
                    )
                }
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
    let mut response = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n",
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

    if let Some(port) = authority.strip_prefix("127.0.0.1:") {
        return port.parse::<u16>().is_ok_and(|port| port != 0);
    }
    if let Some(port) = authority.strip_prefix("localhost:") {
        return port.parse::<u16>().is_ok_and(|port| port != 0);
    }
    if let Some(port) = authority.strip_prefix("[::1]:") {
        return port.parse::<u16>().is_ok_and(|port| port != 0);
    }
    false
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
        assert!(response.contains(
            r#"\"webSocketDebuggerUrl\":\"ws://127.0.0.1:43871/devtools/browser/uuid\""#
        ));
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

    #[test]
    fn constant_time_comparison_handles_different_lengths() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
