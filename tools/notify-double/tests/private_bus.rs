//! Hermetic integration tests: a private, minimal `dbus-daemon` plus the real binary.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Error, Read};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures_lite::StreamExt;
use serde_json::Value as Json;
use tokio::time::{sleep, timeout};
use zbus::connection::Builder;
use zbus::{Connection, Proxy, Variant};

const NAME: &str = "org.freedesktop.Notifications";
const PATH: &str = "/org/freedesktop/Notifications";

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Scratch directory base; falls back to `/tmp` so unix socket paths stay short.
fn temp_base() -> PathBuf {
    let base = std::env::temp_dir();
    if base.as_os_str().len() > 40 {
        PathBuf::from("/tmp")
    } else {
        base
    }
}

/// A fresh, empty scratch directory removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir = temp_base().join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A child in its own process group that dies with the test process and is
/// killed (whole group) and reaped on drop, including during a panic unwind.
struct Proc(Child);

impl Proc {
    fn spawn(cmd: &mut Command) -> std::io::Result<Self> {
        // SAFETY: the closure only calls the async-signal-safe `prctl`.
        unsafe {
            cmd.pre_exec(|| {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong) != 0 {
                    return Err(Error::last_os_error());
                }
                Ok(())
            });
        }
        cmd.process_group(0).spawn().map(Self)
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        // The group id equals the leader's pid (`process_group(0)`).
        unsafe {
            libc::kill(-(self.0.id() as i32), libc::SIGKILL);
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct PrivateBus {
    // Field order matters: the daemon is killed before its directory is removed.
    _daemon: Proc,
    _dir: TempDir,
    address: String,
}

impl PrivateBus {
    /// Starts a private bus with no service activation. Returns `None` only
    /// when `dbus-daemon` is missing and `NOTIFY_DOUBLE_ALLOW_SKIP=1`.
    fn start() -> Option<Self> {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = TempDir::new(&format!("nd-bus-{}-{n}", std::process::id()));
        let sock = dir.0.join("bus.sock");
        let conf = dir.0.join("bus.conf");
        fs::write(
            &conf,
            format!(
                "<busconfig>\n\
                 <type>session</type>\n\
                 <listen>unix:path={}</listen>\n\
                 <auth>EXTERNAL</auth>\n\
                 <policy context=\"default\">\n\
                 <allow send_destination=\"*\" eavesdrop=\"true\"/>\n\
                 <allow eavesdrop=\"true\"/>\n\
                 <allow own=\"*\"/>\n\
                 <allow user=\"*\"/>\n\
                 </policy>\n\
                 </busconfig>\n",
                sock.display()
            ),
        )
        .unwrap();
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut cmd = Command::new("dbus-daemon");
        cmd.arg(format!("--config-file={}", conf.display()))
            .args(["--nofork", "--print-address=1"])
            .env_clear()
            .env("PATH", path)
            .env("HOME", &dir.0)
            .env("XDG_DATA_HOME", dir.0.join("data"))
            .env("XDG_DATA_DIRS", dir.0.join("share"))
            .env("XDG_RUNTIME_DIR", &dir.0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped());
        let mut daemon = match Proc::spawn(&mut cmd) {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if std::env::var("NOTIFY_DOUBLE_ALLOW_SKIP").as_deref() == Ok("1") {
                    eprintln!("SKIP: dbus-daemon not found on PATH");
                    return None;
                }
                panic!(
                    "dbus-daemon not found on PATH; install it or set NOTIFY_DOUBLE_ALLOW_SKIP=1"
                );
            }
            Err(e) => panic!("cannot run dbus-daemon: {e}"),
        };
        let mut address = String::new();
        let stdout = daemon.0.stdout.take().expect("piped stdout");
        BufReader::new(stdout)
            .read_line(&mut address)
            .expect("read dbus-daemon address");
        let address = address.trim().to_string();
        assert!(
            !address.is_empty(),
            "dbus-daemon did not print an address (exited: {:?})",
            daemon.0.try_wait()
        );
        Some(Self {
            _daemon: daemon,
            _dir: dir,
            address,
        })
    }
}

struct Server {
    // Field order matters: the child is killed before its directory is removed.
    child: Proc,
    dir: TempDir,
    unique_name: String,
}

impl Server {
    async fn start(bus: &PrivateBus, tag: &str, script: &str) -> Self {
        let dir = TempDir::new(&format!("nd-{}-{tag}", std::process::id()));
        let ready = dir.0.join("ready");
        let mut child = Proc::spawn(
            Command::new(env!("CARGO_BIN_EXE_notify-double"))
                .arg("--log")
                .arg(dir.0.join("log.jsonl"))
                .arg("--ready-file")
                .arg(&ready)
                .env("DBUS_SESSION_BUS_ADDRESS", &bus.address)
                .env("NOTIFY_DOUBLE_SCRIPT", script)
                .stdin(Stdio::null()),
        )
        .expect("spawn notify-double");
        let mut unique_name = None;
        for _ in 0..100 {
            if let Ok(s) = fs::read_to_string(&ready) {
                unique_name = Some(s.trim().to_string());
                break;
            }
            if let Some(status) = child.0.try_wait().unwrap() {
                panic!("notify-double exited early: {status}");
            }
            sleep(Duration::from_millis(50)).await;
        }
        let unique_name = unique_name.expect("ready file not created");
        assert!(
            unique_name.starts_with(':'),
            "unexpected name {unique_name}"
        );
        Self {
            child,
            dir,
            unique_name,
        }
    }

    fn log(&self) -> Vec<Json> {
        read_log(&self.dir.0.join("log.jsonl"))
    }

    fn events(&self, name: &str) -> Vec<Json> {
        self.log()
            .into_iter()
            .filter(|r| r["event"] == name)
            .collect()
    }
}

fn read_log(path: &Path) -> Vec<Json> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).expect("log line is JSON"))
        .collect()
}

async fn client(bus: &PrivateBus) -> Connection {
    Builder::address(bus.address.as_str())
        .build()
        .await
        .unwrap()
}

async fn notify(conn: &Connection, summary: &str) -> u32 {
    let mut hints: HashMap<&str, Variant<'_>> = HashMap::new();
    hints.insert("urgency", Variant::U8(2));
    hints.insert("category", Variant::from("x.test"));
    let reply = conn
        .call_method(
            Some(NAME),
            PATH,
            Some(NAME),
            "Notify",
            &(
                "client",
                0u32,
                "",
                summary,
                "body",
                vec!["approve", "Approve", "deny", "Deny"],
                hints,
                5000i32,
            ),
        )
        .await
        .unwrap();
    reply.body().deserialize().unwrap()
}

async fn next_signal(
    stream: &mut zbus::proxy::SignalStream<'_>,
    wait_ms: u64,
) -> Option<zbus::Message> {
    timeout(Duration::from_millis(wait_ms), stream.next())
        .await
        .ok()
        .flatten()
}

#[tokio::test]
async fn approve_after_delay_emits_signals_and_logs() {
    let Some(bus) = PrivateBus::start() else {
        return;
    };
    let mut server = Server::start(&bus, "approve", "approve:50").await;
    let conn = client(&bus).await;
    let proxy = Proxy::new(&conn, NAME, PATH, NAME).await.unwrap();
    let mut invoked = proxy.receive_signal("ActionInvoked").await.unwrap();
    let mut closed = proxy.receive_signal("NotificationClosed").await.unwrap();

    let id = notify(&conn, "hello").await;
    assert_eq!(id, 1);

    let msg = next_signal(&mut invoked, 3000)
        .await
        .expect("ActionInvoked");
    let (sid, key): (u32, String) = msg.body().deserialize().unwrap();
    assert_eq!((sid, key.as_str()), (1, "approve"));
    assert_eq!(
        msg.header().sender().map(|s| s.to_string()).as_deref(),
        Some(server.unique_name.as_str())
    );
    let msg = next_signal(&mut closed, 3000)
        .await
        .expect("NotificationClosed");
    let (sid, reason): (u32, u32) = msg.body().deserialize().unwrap();
    assert_eq!((sid, reason), (1, 2));

    let log = server.log();
    let events: Vec<&str> = log.iter().map(|r| r["event"].as_str().unwrap()).collect();
    assert_eq!(events, ["Notify", "ActionInvoked", "NotificationClosed"]);
    let n = &log[0];
    assert_eq!(n["summary"], "hello");
    assert_eq!(n["id"], 1);
    assert_eq!(n["step"], "approve:50");
    assert_eq!(n["expire_timeout"], 5000);
    assert_eq!(n["actions"][0], "approve");
    assert_eq!(n["hints"]["urgency"], 2);
    assert_eq!(n["hints"]["category"], "x.test");
    assert!(n["sender"].as_str().unwrap().starts_with(':'));
    assert_eq!(log[1]["action"], "approve");
    assert_eq!(log[1]["delay_ms"], 50);
    assert_eq!(log[2]["origin"], "script");
    let seqs: Vec<u64> = log.iter().map(|r| r["seq"].as_u64().unwrap()).collect();
    assert_eq!(seqs, [1, 2, 3]);
    assert!(log.iter().all(|r| r["ts_ms"].is_number()));

    // SIGTERM exits cleanly.
    unsafe {
        libc::kill(server.child.0.id() as i32, libc::SIGTERM);
    }
    let status = server.child.0.wait().unwrap();
    assert!(status.success(), "exit status {status}");
}

#[tokio::test]
async fn ignore_emits_nothing() {
    let Some(bus) = PrivateBus::start() else {
        return;
    };
    let server = Server::start(&bus, "ignore", "ignore").await;
    let conn = client(&bus).await;
    let proxy = Proxy::new(&conn, NAME, PATH, NAME).await.unwrap();
    let mut invoked = proxy.receive_signal("ActionInvoked").await.unwrap();
    let mut closed = proxy.receive_signal("NotificationClosed").await.unwrap();

    assert_eq!(notify(&conn, "a").await, 1);
    assert_eq!(notify(&conn, "b").await, 2);
    assert!(next_signal(&mut invoked, 400).await.is_none());
    assert!(next_signal(&mut closed, 10).await.is_none());

    let log = server.log();
    assert_eq!(log.len(), 2);
    assert!(log.iter().all(|r| r["event"] == "Notify"));
    assert_eq!(log[0]["step"], "ignore");
}

#[tokio::test]
async fn nth_step_then_last_repeats() {
    let Some(bus) = PrivateBus::start() else {
        return;
    };
    let server = Server::start(&bus, "nth", "deny,approve").await;
    let conn = client(&bus).await;
    let proxy = Proxy::new(&conn, NAME, PATH, NAME).await.unwrap();
    let mut invoked = proxy.receive_signal("ActionInvoked").await.unwrap();

    let mut keys = Vec::new();
    for i in 0..3 {
        notify(&conn, &format!("n{i}")).await;
        let msg = next_signal(&mut invoked, 3000).await.expect("signal");
        let (_, key): (u32, String) = msg.body().deserialize().unwrap();
        keys.push(key);
    }
    assert_eq!(keys, ["deny", "approve", "approve"]);
    let steps: Vec<String> = server
        .events("Notify")
        .iter()
        .map(|r| r["step"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(steps, ["deny", "approve", "approve"]);
}

#[tokio::test]
async fn close_notification_cancels_pending_step() {
    let Some(bus) = PrivateBus::start() else {
        return;
    };
    let server = Server::start(&bus, "close", "approve:400").await;
    let conn = client(&bus).await;
    let proxy = Proxy::new(&conn, NAME, PATH, NAME).await.unwrap();
    let mut invoked = proxy.receive_signal("ActionInvoked").await.unwrap();
    let mut closed = proxy.receive_signal("NotificationClosed").await.unwrap();

    let id = notify(&conn, "x").await;
    conn.call_method(Some(NAME), PATH, Some(NAME), "CloseNotification", &(id,))
        .await
        .unwrap();
    let msg = next_signal(&mut closed, 3000).await.expect("closed signal");
    let (sid, reason): (u32, u32) = msg.body().deserialize().unwrap();
    assert_eq!((sid, reason), (id, 3));
    assert!(next_signal(&mut invoked, 800).await.is_none());

    let log = server.log();
    let events: Vec<&str> = log.iter().map(|r| r["event"].as_str().unwrap()).collect();
    assert_eq!(
        events,
        [
            "Notify",
            "CloseNotification",
            "Cancelled",
            "NotificationClosed"
        ]
    );
    assert_eq!(log[2]["reason"], "CloseNotification");
    assert_eq!(log[3]["origin"], "CloseNotification");
}

#[tokio::test]
async fn name_already_taken_fails_loudly() {
    let Some(bus) = PrivateBus::start() else {
        return;
    };
    let _first = Server::start(&bus, "first", "ignore").await;
    let dir = TempDir::new(&format!("nd-{}-second", std::process::id()));
    let mut second = Proc::spawn(
        Command::new(env!("CARGO_BIN_EXE_notify-double"))
            .arg("--log")
            .arg(dir.0.join("log.jsonl"))
            .env("DBUS_SESSION_BUS_ADDRESS", &bus.address)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped()),
    )
    .unwrap();
    let status = second.0.wait().unwrap();
    let mut stderr = String::new();
    second
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(!status.success());
    assert!(!stderr.is_empty());
}

#[tokio::test]
async fn bus_is_private_and_minimal() {
    let Some(bus) = PrivateBus::start() else {
        return;
    };
    let conn = client(&bus).await;
    let call = |method: &'static str| {
        let conn = conn.clone();
        async move {
            let reply = conn
                .call_method(
                    Some("org.freedesktop.DBus"),
                    "/org/freedesktop/DBus",
                    Some("org.freedesktop.DBus"),
                    method,
                    &(),
                )
                .await
                .unwrap();
            reply.body().deserialize::<Vec<String>>().unwrap()
        }
    };
    let names = call("ListNames").await;
    assert!(
        names
            .iter()
            .all(|n| n == "org.freedesktop.DBus" || n.starts_with(":1.")),
        "unexpected names on private bus: {names:?}"
    );
    assert!(names.iter().any(|n| n == "org.freedesktop.DBus"));
    let activatable = call("ListActivatableNames").await;
    assert!(
        activatable.iter().all(|n| n == "org.freedesktop.DBus"),
        "activatable names on private bus: {activatable:?}"
    );
}
