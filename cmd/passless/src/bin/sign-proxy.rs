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
}

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

fn forward_to_sign_server(req: &NativeRequest) -> NativeResponse {
    let socket_path =
        std::env::var("PASSLESS_SIGN_SOCKET").unwrap_or_else(|_| req.socket_path.clone());

    let mut stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            return NativeResponse {
                body: None,
                error: Some(format!("connect: {}", e)),
            };
        }
    };

    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

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
        }
    } else {
        let error = serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
            .unwrap_or_else(|| "request_denied".to_string());
        NativeResponse {
            body: None,
            error: Some(error),
        }
    }
}

fn main() {
    while let Some(req) = read_native_message() {
        let resp = forward_to_sign_server(&req);
        write_native_response(&resp);
    }
}
