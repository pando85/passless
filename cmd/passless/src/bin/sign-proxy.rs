//! `sign-proxy`: the native-messaging host of the managed browser's agent extension (ADR 0014
//! section 4.4, plan D2).
//!
//! It relays frames between the extension worker's `connectNative` port (stdin and stdout) and one
//! connection to the daemon's sign socket. Both sides use the same framing: a 4-byte
//! little-endian length and a JSON object, at most 1 MiB, checked before allocation.
//!
//! - The connection is opened when the first frame, the worker's `hello`, arrives. The socket is
//!   `PASSLESS_SIGN_SOCKET` if set, else the hello's `socket` field.
//! - Every `hello` is forwarded with `relay_version` added (plan V-L5).
//! - The relay tracks the ids of forwarded requests until their `result` comes back. If the daemon
//!   connection drops, it answers each tracked id with
//!   `result{ok:false, error{code:"transport", dom:"NotAllowedError"}}` and exits.
//! - When stdin ends (the browser closed the port) it exits; closing the socket makes the daemon
//!   cancel every request of this connection.
//! - Socket writes time out after 5 s, which also ends the relay.
//!
//! `sign-proxy --version` prints the build version.

#[path = "../agent/transport/frame.rs"]
#[allow(dead_code)]
mod frame;

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use serde_json::{Map, Value, json};

use shadow_rs::shadow;

use frame::{FrameError, WRITE_TIMEOUT, encode_frame, read_frame_bytes};

shadow!(build);

/// The relay's build version, in the daemon's format.
fn relay_version() -> String {
    frame::build_version_from(build::PKG_VERSION, build::SHORT_COMMIT)
}

/// Why the relay stopped.
#[derive(Debug, PartialEq, Eq)]
enum RelayEnd {
    /// stdin ended or broke: the browser closed the port.
    InputClosed,
    /// The daemon connection ended, failed or timed out; tracked requests were failed.
    DaemonLost,
    /// The browser sent a frame over the cap or one that is not a JSON object.
    BadFrame,
    /// The first frame was not a `hello`.
    NoHello,
    /// The daemon socket could not be reached.
    ConnectFailed,
}

/// State shared by the two relay threads.
struct Relay<W: Write> {
    output: Mutex<W>,
    in_flight: Mutex<BTreeSet<u32>>,
    /// Set once the relay is ending; nothing more is written to the browser.
    finished: AtomicBool,
}

impl<W: Write> Relay<W> {
    fn write_output(&self, payload: &[u8]) -> bool {
        let Some(frame) = encode_frame(payload) else {
            return false;
        };
        let mut output = self.output.lock().unwrap_or_else(|e| e.into_inner());
        output
            .write_all(&frame)
            .and_then(|()| output.flush())
            .is_ok()
    }

    /// Answer every request still waiting for the daemon with a transport error.
    fn fail_in_flight(&self) {
        let ids: Vec<u32> =
            std::mem::take(&mut *self.in_flight.lock().unwrap_or_else(|e| e.into_inner()))
                .into_iter()
                .collect();
        for id in ids {
            let result = json!({
                "type": "result",
                "id": id,
                "ok": false,
                "error": { "code": "transport", "dom": "NotAllowedError" },
            });
            if !self.write_output(result.to_string().as_bytes()) {
                break;
            }
        }
    }
}

/// Relay between `input`/`output` (the browser) and the daemon until either side ends.
fn run<R, W>(
    input: R,
    output: W,
    socket_override: Option<PathBuf>,
    relay_version: String,
    write_timeout: Duration,
) -> RelayEnd
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    let relay = Arc::new(Relay {
        output: Mutex::new(output),
        in_flight: Mutex::new(BTreeSet::new()),
        finished: AtomicBool::new(false),
    });
    let (end_tx, end_rx) = mpsc::channel::<RelayEnd>();
    let (socket_tx, socket_rx) = mpsc::channel::<UnixStream>();
    {
        let relay = relay.clone();
        thread::spawn(move || {
            let end = browser_to_daemon(
                input,
                &relay,
                socket_override,
                &relay_version,
                write_timeout,
                &end_tx,
                &socket_tx,
            );
            let _ = end_tx.send(end);
        });
    }
    let end = end_rx.recv().unwrap_or(RelayEnd::InputClosed);
    relay.finished.store(true, Ordering::Release);
    // Closing the socket makes the daemon cancel every request of this connection.
    if let Ok(socket) = socket_rx.try_recv() {
        let _ = socket.shutdown(std::net::Shutdown::Both);
    }
    end
}

/// The browser-to-daemon direction. Connects on the first frame and starts the other direction.
fn browser_to_daemon<R: Read, W: Write + Send + 'static>(
    mut input: R,
    relay: &Arc<Relay<W>>,
    socket_override: Option<PathBuf>,
    relay_version: &str,
    write_timeout: Duration,
    end_tx: &mpsc::Sender<RelayEnd>,
    socket_tx: &mpsc::Sender<UnixStream>,
) -> RelayEnd {
    let mut socket: Option<UnixStream> = None;
    loop {
        let payload = match read_frame_bytes(&mut input) {
            Ok(payload) => payload,
            Err(FrameError::TooLarge(_)) => return RelayEnd::BadFrame,
            Err(_) => return RelayEnd::InputClosed,
        };
        let Ok(Value::Object(mut frame)) = serde_json::from_slice::<Value>(&payload) else {
            return RelayEnd::BadFrame;
        };
        let kind = frame
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if kind == "hello" {
            frame.insert(
                "relay_version".into(),
                Value::String(relay_version.to_string()),
            );
        }
        let stream = match socket.as_mut() {
            Some(stream) => stream,
            None => {
                if kind != "hello" {
                    return RelayEnd::NoHello;
                }
                let Some(path) = socket_override
                    .clone()
                    .or_else(|| hello_socket(&frame).map(PathBuf::from))
                else {
                    return RelayEnd::ConnectFailed;
                };
                let Ok(stream) = UnixStream::connect(&path) else {
                    return RelayEnd::ConnectFailed;
                };
                let _ = stream.set_write_timeout(Some(write_timeout));
                let (Ok(reader), Ok(control)) = (stream.try_clone(), stream.try_clone()) else {
                    return RelayEnd::ConnectFailed;
                };
                let _ = socket_tx.send(control);
                let relay = relay.clone();
                let end_tx = end_tx.clone();
                thread::spawn(move || {
                    let _ = end_tx.send(daemon_to_browser(reader, &relay));
                });
                socket.insert(stream)
            }
        };
        if kind == "request"
            && let Some(id) = frame
                .get("id")
                .and_then(Value::as_u64)
                .and_then(|id| u32::try_from(id).ok())
        {
            relay
                .in_flight
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(id);
        }
        let Ok(payload) = serde_json::to_vec(&Value::Object(frame)) else {
            return RelayEnd::BadFrame;
        };
        let Some(bytes) = encode_frame(&payload) else {
            return RelayEnd::BadFrame;
        };
        if stream.write_all(&bytes).is_err() {
            relay.fail_in_flight();
            return RelayEnd::DaemonLost;
        }
    }
}

/// The daemon-to-browser direction: forward frames, retire answered ids, and fail the rest when
/// the daemon goes away.
fn daemon_to_browser<W: Write>(mut socket: UnixStream, relay: &Relay<W>) -> RelayEnd {
    while let Ok(payload) = read_frame_bytes(&mut socket) {
        let Ok(Value::Object(frame)) = serde_json::from_slice::<Value>(&payload) else {
            break;
        };
        if frame.get("type").and_then(Value::as_str) == Some("result")
            && let Some(id) = frame
                .get("id")
                .and_then(Value::as_u64)
                .and_then(|id| u32::try_from(id).ok())
        {
            relay
                .in_flight
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&id);
        }
        if relay.finished.load(Ordering::Acquire) {
            return RelayEnd::InputClosed;
        }
        if !relay.write_output(&payload) {
            return RelayEnd::InputClosed;
        }
    }
    if !relay.finished.load(Ordering::Acquire) {
        relay.fail_in_flight();
    }
    RelayEnd::DaemonLost
}

fn hello_socket(frame: &Map<String, Value>) -> Option<&str> {
    frame
        .get("socket")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("{}", relay_version());
        return;
    }
    let socket_override = std::env::var_os("PASSLESS_SIGN_SOCKET").map(PathBuf::from);
    let end = run(
        std::io::stdin(),
        std::io::stdout(),
        socket_override,
        relay_version(),
        WRITE_TIMEOUT,
    );
    std::process::exit(if end == RelayEnd::InputClosed { 0 } else { 1 });
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::net::UnixListener;
    use std::time::Instant;

    use frame::{MAX_FRAME_LEN, read_frame, write_frame};

    /// A relay running against a test daemon socket, with the browser's ends of stdin/stdout.
    struct Rig {
        browser_in: UnixStream,
        browser_out: UnixStream,
        listener: UnixListener,
        sock: PathBuf,
        end: mpsc::Receiver<RelayEnd>,
        _dir: tempfile::TempDir,
    }

    fn rig(write_timeout: Duration) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let (browser_in, relay_in) = UnixStream::pair().unwrap();
        let (relay_out, browser_out) = UnixStream::pair().unwrap();
        browser_out
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        browser_in
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let (tx, end) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(run(
                relay_in,
                relay_out,
                None,
                "9.9.9+relay".to_string(),
                write_timeout,
            ));
        });
        Rig {
            browser_in,
            browser_out,
            listener,
            sock,
            end,
            _dir: dir,
        }
    }

    impl Rig {
        fn send(&mut self, frame: Value) {
            write_frame(&mut self.browser_in, frame.to_string().as_bytes()).unwrap();
        }

        fn hello(&mut self) {
            let sock = self.sock.to_string_lossy().into_owned();
            self.send(json!({"type": "hello", "v": 2, "bearer": "b", "socket": sock}));
        }

        fn accept(&self) -> UnixStream {
            let (daemon, _) = self.listener.accept().unwrap();
            daemon
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            daemon
        }

        fn end(&self) -> RelayEnd {
            self.end.recv_timeout(Duration::from_secs(10)).unwrap()
        }
    }

    #[test]
    fn hello_gets_the_relay_version_and_frames_pass_both_ways() {
        let mut rig = rig(WRITE_TIMEOUT);
        rig.hello();
        let mut daemon = rig.accept();
        let hello = read_frame(&mut daemon).unwrap();
        assert_eq!(hello["type"], "hello");
        assert_eq!(hello["relay_version"], "9.9.9+relay");
        assert_eq!(hello["bearer"], "b");

        rig.send(json!({"type": "request", "id": 3, "op": "get", "body": "{}"}));
        let request = read_frame(&mut daemon).unwrap();
        assert_eq!(request["id"], 3);
        write_frame(
            &mut daemon,
            json!({"type": "result", "id": 3, "ok": true, "body": "x"})
                .to_string()
                .as_bytes(),
        )
        .unwrap();
        let result = read_frame(&mut rig.browser_out).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["body"], "x");
    }

    #[test]
    fn the_hello_socket_is_used_and_an_unreachable_one_ends_the_relay() {
        let mut rig = rig(WRITE_TIMEOUT);
        rig.send(json!({"type": "hello", "v": 2, "bearer": "b", "socket": "/nonexistent/sock"}));
        assert_eq!(rig.end(), RelayEnd::ConnectFailed);
    }

    #[test]
    fn a_frame_before_hello_ends_the_relay() {
        let mut rig = rig(WRITE_TIMEOUT);
        rig.send(json!({"type": "keepalive"}));
        assert_eq!(rig.end(), RelayEnd::NoHello);
    }

    #[test]
    fn an_oversize_frame_length_ends_the_relay_without_reading_it() {
        let mut rig = rig(WRITE_TIMEOUT);
        // Only the length is sent: the relay must stop on the length alone.
        rig.browser_in
            .write_all(&((MAX_FRAME_LEN as u32) + 1).to_le_bytes())
            .unwrap();
        assert_eq!(rig.end(), RelayEnd::BadFrame);
    }

    #[test]
    fn an_oversize_daemon_frame_drops_the_connection_and_fails_tracked_requests() {
        let mut rig = rig(WRITE_TIMEOUT);
        rig.hello();
        let mut daemon = rig.accept();
        read_frame(&mut daemon).unwrap();
        rig.send(json!({"type": "request", "id": 9, "op": "get", "body": "{}"}));
        read_frame(&mut daemon).unwrap();
        daemon
            .write_all(&((MAX_FRAME_LEN as u32) + 1).to_le_bytes())
            .unwrap();
        let result = read_frame(&mut rig.browser_out).unwrap();
        assert_eq!(result["id"], 9);
        assert_eq!(result["error"]["code"], "transport");
        assert_eq!(rig.end(), RelayEnd::DaemonLost);
    }

    #[test]
    fn daemon_loss_fails_every_tracked_request_once_and_ends_the_relay() {
        let mut rig = rig(WRITE_TIMEOUT);
        rig.hello();
        let mut daemon = rig.accept();
        read_frame(&mut daemon).unwrap();
        for id in [7, 8] {
            rig.send(json!({"type": "request", "id": id, "op": "get", "body": "{}"}));
            read_frame(&mut daemon).unwrap();
        }
        // Request 8 is answered; request 7 is still in flight when the daemon goes away.
        write_frame(
            &mut daemon,
            json!({"type": "result", "id": 8, "ok": true, "body": "x"})
                .to_string()
                .as_bytes(),
        )
        .unwrap();
        let answered = read_frame(&mut rig.browser_out).unwrap();
        assert_eq!(answered["id"], 8);
        drop(daemon);

        let failed = read_frame(&mut rig.browser_out).unwrap();
        assert_eq!(
            Value::Object(failed),
            json!({
                "type": "result",
                "id": 7,
                "ok": false,
                "error": {"code": "transport", "dom": "NotAllowedError"},
            })
        );
        assert_eq!(rig.end(), RelayEnd::DaemonLost);
        rig.browser_out
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        assert!(
            read_frame(&mut rig.browser_out).is_err(),
            "nothing more is written"
        );
    }

    #[test]
    fn stdin_eof_ends_the_relay_and_closes_the_daemon_connection() {
        let mut rig = rig(WRITE_TIMEOUT);
        rig.hello();
        let mut daemon = rig.accept();
        read_frame(&mut daemon).unwrap();
        rig.browser_in.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(rig.end(), RelayEnd::InputClosed);
        assert!(matches!(read_frame(&mut daemon), Err(FrameError::Eof)));
    }

    #[test]
    fn a_daemon_that_stops_reading_times_the_write_out() {
        let mut rig = rig(Duration::from_millis(200));
        rig.hello();
        let mut daemon = rig.accept();
        read_frame(&mut daemon).unwrap();
        // The daemon never reads again: the socket buffer fills and a write times out.
        let started = Instant::now();
        let body = "x".repeat(512 * 1024);
        let mut id = 1;
        let end = loop {
            if let Ok(end) = rig.end.try_recv() {
                break end;
            }
            assert!(started.elapsed() < Duration::from_secs(10), "no timeout");
            let frame = json!({"type": "request", "id": id, "op": "get", "body": body});
            if write_frame(&mut rig.browser_in, frame.to_string().as_bytes()).is_err() {
                break rig.end();
            }
            id += 1;
        };
        assert_eq!(end, RelayEnd::DaemonLost);
        // The requests the daemon never answered are failed.
        let failed = read_frame(&mut rig.browser_out).unwrap();
        assert_eq!(failed["error"]["code"], "transport");
        drop(daemon);
    }

    #[test]
    fn relay_version_has_the_daemon_format() {
        let version = relay_version();
        assert!(version.starts_with(build::PKG_VERSION));
        assert_eq!(
            frame::build_version_from("1.2.3", ""),
            "1.2.3",
            "no commit, version only"
        );
        assert_eq!(frame::build_version_from("1.2.3", "abc"), "1.2.3+abc");
    }
}
