//! The escalation prompt child as the daemon starts it: the `passless` binary re-executed with the
//! hidden first argument, with an empty environment except `DBUS_SESSION_BUS_ADDRESS`, against
//! `tools/notify-double` on a private, minimal `dbus-daemon` (never the real session bus).
#![cfg(feature = "agent")]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use notify_double::server::{Config, NotificationDouble};
use notify_double::{Emulation, LogWriter, OBJECT_PATH, Script, WELL_KNOWN_NAME};
use serde_json::{Value as Json, json};

const HIDDEN_ARG: &str = "__agent-escalation-prompt";

struct PrivateBus {
    // Field order matters: the daemon is killed before its directory is removed.
    daemon: Child,
    dir: tempfile::TempDir,
    address: String,
}

impl PrivateBus {
    fn start() -> Self {
        let base = if std::env::temp_dir().as_os_str().len() > 40 {
            PathBuf::from("/tmp")
        } else {
            std::env::temp_dir()
        };
        let dir = tempfile::Builder::new()
            .prefix("passless-bus-")
            .tempdir_in(base)
            .unwrap();
        let sock = dir.path().join("bus.sock");
        let conf = dir.path().join("bus.conf");
        fs::write(
            &conf,
            format!(
                "<busconfig>\n<type>session</type>\n<listen>unix:path={}</listen>\n\
                 <auth>EXTERNAL</auth>\n<policy context=\"default\">\n\
                 <allow send_destination=\"*\" eavesdrop=\"true\"/>\n\
                 <allow eavesdrop=\"true\"/>\n<allow own=\"*\"/>\n<allow user=\"*\"/>\n\
                 </policy>\n</busconfig>\n",
                sock.display()
            ),
        )
        .unwrap();
        let mut command = Command::new("dbus-daemon");
        command
            .arg(format!("--config-file={}", conf.display()))
            .args(["--nofork", "--print-address=1"])
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", dir.path())
            .env("XDG_RUNTIME_DIR", dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .process_group(0);
        // SAFETY: the closure only calls the async-signal-safe `prctl`.
        unsafe {
            command.pre_exec(|| {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut daemon = command.spawn().expect("dbus-daemon");
        let mut address = String::new();
        let read = BufReader::new(daemon.stdout.take().unwrap()).read_line(&mut address);
        let bus = Self {
            daemon,
            dir,
            address: address.trim().to_string(),
        };
        read.unwrap();
        assert!(!bus.address.is_empty());
        bus
    }
}

impl Drop for PrivateBus {
    fn drop(&mut self) {
        // SAFETY: the process group id equals the leader's pid (`process_group(0)`).
        unsafe {
            libc::kill(-(self.daemon.id() as i32), libc::SIGKILL);
        }
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
    }
}

fn log_events(path: &PathBuf) -> Vec<Json> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn reexecuted_binary_runs_the_prompt_child_with_only_the_bus_address() {
    let bus = PrivateBus::start();
    let log = bus.dir.path().join("notify.jsonl");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let _server = runtime.block_on(async {
        zbus::connection::Builder::address(bus.address.as_str())
            .name(WELL_KNOWN_NAME)
            .serve_at(
                OBJECT_PATH,
                NotificationDouble::new(
                    Config {
                        script: Script::parse_list("ignore").unwrap(),
                        capabilities: vec!["actions".to_string(), "body".to_string()],
                        server_name: "notify-double".to_string(),
                        emulation: Emulation::Spec,
                    },
                    Arc::new(LogWriter::open(&log).unwrap()),
                ),
            )
            .build()
            .await
            .unwrap()
    });

    // No HOME, no config: the child must not parse arguments or load anything.
    let mut child = Command::new(env!("CARGO_BIN_EXE_passless"))
        .arg(HIDDEN_ARG)
        .env_clear()
        .env("DBUS_SESSION_BUS_ADDRESS", &bus.address)
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let request = json!({
        "v": 1,
        "summary": "Passless: agent sign-in request",
        "body": "Site: example.com (any page under this site)",
        "actions": [["allow_always", "Allow always"], ["deny", "Deny"]],
        "min_review_delay_ms": 1000,
    });
    writeln!(stdin, "{request}").unwrap();

    let stdout = BufReader::new(child.stdout.take().unwrap());
    let (lines, received) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in stdout.lines().map_while(Result::ok) {
            let _ = lines.send(line);
        }
    });
    let line = received
        .recv_timeout(Duration::from_secs(10))
        .unwrap_or_else(|_| {
            let _ = child.kill();
            panic!("the prompt child reported nothing")
        });
    let shown: Json = serde_json::from_str(&line).unwrap();
    assert_eq!(shown["event"], "shown", "{line}");
    assert_eq!(shown["server"], "notify-double");

    writeln!(stdin, "{}", json!({"withdraw": true})).unwrap();
    drop(stdin);
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "child did not exit"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(status.success(), "{status}");

    let events = log_events(&log);
    let notify = events.iter().find(|e| e["event"] == "Notify").unwrap();
    assert_eq!(notify["summary"], "Passless: agent sign-in request");
    assert_eq!(notify["expire_timeout"], 0);
    assert_eq!(notify["id"], shown["id"]);
    assert!(
        events
            .iter()
            .any(|e| e["event"] == "CloseNotification" && e["id"] == shown["id"]),
        "{events:?}"
    );
}

#[test]
fn reexecuted_binary_without_a_bus_reports_bus_unavailable() {
    let output = Command::new(env!("CARGO_BIN_EXE_passless"))
        .arg(HIDDEN_ARG)
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let line = String::from_utf8(output.stdout).unwrap();
    let event: Json = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(event, json!({"event": "error", "kind": "bus_unavailable"}));
}
