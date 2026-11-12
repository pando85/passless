//! Validation-only probe of the escalation prompt child (ADR 0014 section 8.2).
//!
//! It runs the production prompt child protocol (`agent/escalation_prompt.rs`) against the
//! session bus in `DBUS_SESSION_BUS_ADDRESS` and prints one JSON line:
//! `{"decision":"approved"|"denied"|"timeout"|"error","error_kind":…,"latency_class":…}`.
//! A dismissal is a deny, like in the daemon. After `--timeout` seconds without a decision the
//! prompt is withdrawn (`CloseNotification`) and the decision is `timeout`.

#[path = "../agent/escalation_prompt.rs"]
#[allow(dead_code, unused_imports)]
mod escalation_prompt;

use std::io::{BufRead, BufReader, Write};
use std::process;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;
use serde::Serialize;

use escalation_prompt::{
    ACTION_ALLOW_ALWAYS, ChildEvent, ControlMessage, InProcessChild, PromptFields, PromptRequest,
    PromptVerb, render_prompt,
};

/// How long the probe waits for the child to close a withdrawn notification.
const WITHDRAW_GRACE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum LatencyClass {
    Fast,
    Normal,
    Slow,
}

impl LatencyClass {
    fn from_ms(ms: u64) -> Self {
        if ms < 1000 {
            Self::Fast
        } else if ms <= 5000 {
            Self::Normal
        } else {
            Self::Slow
        }
    }
}

#[derive(Debug, Serialize)]
struct ProbeOutput {
    decision: String,
    error_kind: Option<String>,
    latency_class: LatencyClass,
}

#[derive(Parser, Debug)]
#[command(
    name = "agent-prompt-probe",
    about = "Validation-only escalation prompt probe"
)]
struct Args {
    /// Seconds to wait for a decision before withdrawing the prompt.
    #[arg(long, default_value_t = 60)]
    timeout: u64,

    /// Milliseconds after which "Allow always" is accepted.
    #[arg(long, default_value_t = escalation_prompt::DEFAULT_MIN_REVIEW_DELAY_MS)]
    min_review_delay: u64,

    #[arg(long, default_value = "authenticate")]
    action: String,

    #[arg(long, default_value = "probe.validation.local")]
    rp_id: String,
}

fn finish(decision: &str, error_kind: Option<&str>, start: Instant) -> ! {
    let output = ProbeOutput {
        decision: decision.to_string(),
        error_kind: error_kind.map(str::to_string),
        latency_class: LatencyClass::from_ms(start.elapsed().as_millis() as u64),
    };
    println!(
        "{}",
        serde_json::to_string(&output).expect("probe output serializes")
    );
    process::exit(if decision == "error" { 1 } else { 0 });
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .format_timestamp(None)
        .init();
    let args = Args::parse();
    let start = Instant::now();

    let verb = match args.action.as_str() {
        "register" => PromptVerb::Register,
        "authenticate" => PromptVerb::Authenticate,
        other => {
            eprintln!("invalid action: {other}");
            finish("error", Some("internal_error"), start);
        }
    };
    let fields = PromptFields {
        profile: "validation-probe".to_string(),
        mode: "isolated".to_string(),
        principal_user: "validation".to_string(),
        verb,
        rp_id: args.rp_id.clone(),
        origin: format!("https://{}", args.rp_id),
    };
    let (summary, body) = match render_prompt(&fields) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("cannot render the prompt: {e}");
            finish("error", Some("internal_error"), start);
        }
    };
    let request = PromptRequest::new(summary, body, args.min_review_delay);

    let address = std::env::var("DBUS_SESSION_BUS_ADDRESS").ok();
    let mut child = match InProcessChild::spawn(address) {
        Ok(child) => child,
        Err(e) => {
            eprintln!("cannot start the prompt: {e}");
            finish("error", Some("internal_error"), start);
        }
    };
    let mut stdin = child.stdin.take().expect("child stdin");
    let mut line = serde_json::to_vec(&request).expect("request serializes");
    line.push(b'\n');
    if stdin.write_all(&line).is_err() {
        finish("error", Some("internal_error"), start);
    }

    let (sender, events) = mpsc::channel();
    let stdout = child.stdout.take().expect("child stdout");
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if let Ok(event) = serde_json::from_str::<ChildEvent>(&line)
                && sender.send(event).is_err()
            {
                break;
            }
        }
    });

    let deadline = start + Duration::from_secs(args.timeout);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match events.recv_timeout(remaining) {
            Ok(ChildEvent::Shown { .. }) => {}
            Ok(ChildEvent::Decision { action }) if action == ACTION_ALLOW_ALWAYS => {
                finish("approved", None, start)
            }
            Ok(ChildEvent::Decision { .. }) | Ok(ChildEvent::Closed { .. }) => {
                finish("denied", None, start)
            }
            Ok(ChildEvent::ServerLost) => finish("error", Some("server_lost"), start),
            Ok(ChildEvent::Error { kind }) => finish("error", Some(kind.as_str()), start),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let mut withdraw = serde_json::to_vec(&ControlMessage { withdraw: true })
                    .expect("control message serializes");
                withdraw.push(b'\n');
                let _ = stdin.write_all(&withdraw);
                drop(stdin);
                if let Some(thread) = child.thread.take() {
                    let (done, finished) = mpsc::channel();
                    thread::spawn(move || {
                        let _ = thread.join();
                        let _ = done.send(());
                    });
                    let _ = finished.recv_timeout(WITHDRAW_GRACE);
                }
                finish("timeout", None, start);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                finish("error", Some("internal_error"), start)
            }
        }
    }
}
