use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct NativeRequest {
    path: String,
    bearer: String,
    #[allow(dead_code)]
    socket_path: String,
    body: String,
}

#[derive(Serialize)]
struct NativeResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// The WebAuthn DOMException name the daemon chose for this error (ADR 0014 section 11).
    #[serde(skip_serializing_if = "Option::is_none")]
    dom: Option<String>,
}

/// The DOMException names the daemon may report; anything else is dropped (the extension then
/// uses `NotAllowedError`).
const DOM_EXCEPTION_NAMES: &[&str] = &[
    "NotAllowedError",
    "NotSupportedError",
    "InvalidStateError",
    "SecurityError",
    "AbortError",
];

fn read_native_message() -> Option<NativeRequest> {
    let mut len_buf = [0u8; 4];
    std::io::stdin().read_exact(&mut len_buf).ok()?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 1024 * 1024 {
        return None;
    }
    let mut msg_buf = vec![0u8; len];
    std::io::stdin().read_exact(&mut msg_buf).ok()?;
    serde_json::from_slice(&msg_buf).ok()
}

fn write_native_response(resp: &NativeResponse) {
    let json = serde_json::to_vec(resp).unwrap_or_default();
    let len = (json.len() as u32).to_le_bytes();
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(&len);
    let _ = stdout.write_all(&json);
    let _ = stdout.flush();
}

/// Ceremony timeout assumed when the request carries none (the daemon's default).
const DEFAULT_CEREMONY_TIMEOUT: Duration = Duration::from_secs(120);
/// The daemon's longest ceremony timeout (Chromium's upper clamp, 20 h).
const MAX_CEREMONY_TIMEOUT: Duration = Duration::from_secs(20 * 3600);
/// Added to the ceremony timeout so the daemon's own deadline answer arrives first.
const READ_TIMEOUT_MARGIN: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for the daemon's answer to `body`: its `timeout_ms` (or the default) plus a
/// margin, never more than the ceremony maximum.
fn read_timeout_for(body: &str) -> Duration {
    let timeout = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("timeout_ms").and_then(|t| t.as_u64()))
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_CEREMONY_TIMEOUT);
    timeout
        .saturating_add(READ_TIMEOUT_MARGIN)
        .min(MAX_CEREMONY_TIMEOUT)
}

fn forward_to_sign_server(req: &NativeRequest) -> NativeResponse {
    let socket_path =
        std::env::var("PASSLESS_SIGN_SOCKET").unwrap_or_else(|_| req.socket_path.clone());

    let mut stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            return NativeResponse {
                dom: None,
                body: None,
                error: Some(format!("connect: {}", e)),
            };
        }
    };

    // The daemon may hold the request until the ceremony's own deadline (a joined duplicate, a
    // pending escalation), so the read timeout follows the request's `timeout_ms`.
    let _ = stream.set_read_timeout(Some(read_timeout_for(&req.body)));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));

    let http_req = format!(
        "POST {} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        req.path,
        req.bearer,
        req.body.len(),
        req.body
    );

    if stream.write_all(http_req.as_bytes()).is_err() {
        return NativeResponse {
            body: None,
            error: Some("write".to_string()),
            dom: None,
        };
    }

    let mut resp_buf = vec![0u8; 65536];
    let mut total = 0;
    loop {
        match stream.read(&mut resp_buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if total >= resp_buf.len() {
                    break;
                }
                if let Some(pos) = resp_buf[..total].windows(4).position(|w| w == b"\r\n\r\n") {
                    let header_end = pos + 4;
                    let header_str = match std::str::from_utf8(&resp_buf[..pos]) {
                        Ok(s) => s,
                        Err(_) => {
                            return NativeResponse {
                                body: None,
                                error: Some("invalid_utf8".to_string()),
                                dom: None,
                            };
                        }
                    };
                    let content_length: usize = header_str
                        .lines()
                        .find_map(|l| {
                            let lower = l.to_ascii_lowercase();
                            lower
                                .strip_prefix("content-length:")
                                .and_then(|v| v.trim().parse().ok())
                        })
                        .unwrap_or(0);
                    let body_start = header_end;
                    let body_received = total.saturating_sub(body_start);
                    if body_received >= content_length {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }

    let resp_str = match std::str::from_utf8(&resp_buf[..total]) {
        Ok(s) => s,
        Err(_) => {
            return NativeResponse {
                body: None,
                error: Some("invalid_response".to_string()),
                dom: None,
            };
        }
    };

    let body = resp_str
        .find("\r\n\r\n")
        .map(|pos| &resp_str[pos + 4..])
        .unwrap_or("");

    let status_ok = resp_str.starts_with("HTTP/1.1 200");
    if status_ok {
        NativeResponse {
            body: Some(body.to_string()),
            error: None,
            dom: None,
        }
    } else {
        let parsed = serde_json::from_str::<serde_json::Value>(body).ok();
        let error = parsed
            .as_ref()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
            .unwrap_or_else(|| "request_denied".to_string());
        let dom = parsed
            .as_ref()
            .and_then(|v| v.get("dom").and_then(|d| d.as_str()))
            .filter(|name| DOM_EXCEPTION_NAMES.contains(name))
            .map(String::from);
        NativeResponse {
            body: None,
            error: Some(error),
            dom,
        }
    }
}

fn main() {
    while let Some(req) = read_native_message() {
        let resp = forward_to_sign_server(&req);
        write_native_response(&resp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_timeout_follows_the_request_timeout_with_a_margin() {
        assert_eq!(
            read_timeout_for(r#"{"timeout_ms":60000}"#),
            Duration::from_secs(65)
        );
        assert_eq!(read_timeout_for("{}"), Duration::from_secs(125));
        assert_eq!(read_timeout_for("not json"), Duration::from_secs(125));
        assert_eq!(
            read_timeout_for(r#"{"timeout_ms":18446744073709551615}"#),
            MAX_CEREMONY_TIMEOUT
        );
        assert!(read_timeout_for(r#"{"timeout_ms":1000}"#) > Duration::from_secs(5));
    }

    #[test]
    fn a_slow_daemon_answer_within_the_timeout_is_received() {
        // A join waits for the original: the proxy must not give up after a fixed 10 s.
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            std::thread::sleep(Duration::from_millis(300));
            let body = r#"{"ok":true}"#;
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
        });
        let req = NativeRequest {
            path: "/sign".to_string(),
            bearer: "b".to_string(),
            socket_path: sock.to_string_lossy().into_owned(),
            body: r#"{"timeout_ms":2000}"#.to_string(),
        };
        let resp = forward_to_sign_server(&req);
        server.join().unwrap();
        assert_eq!(resp.body.as_deref(), Some(r#"{"ok":true}"#));
    }
}
