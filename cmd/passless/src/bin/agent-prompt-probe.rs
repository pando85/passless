//! Validation-only probe of the escalation prompt child (ADR 0014 section 8.2).
//!
//! It runs the production prompt child protocol (`agent/escalation_prompt.rs`) against the
//! session bus in `DBUS_SESSION_BUS_ADDRESS` and prints one JSON line:
//! `{"decision":"approved"|"denied"|"timeout"|"error","error_kind":…,"latency_class":…}`.
//! `approved` is the prompt's own approving action: "Allow always" for `--action authenticate`,
//! "Register once" for `--action register` (protocol version 2). A dismissal is a deny, like in
//! the daemon. After `--timeout` seconds without a decision the
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
    ChildEvent, ControlMessage, InProcessChild, PromptFields, PromptRequest, PromptRule,
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

    /// Milliseconds after which the approving action is accepted.
    #[arg(long, default_value_t = escalation_prompt::DEFAULT_MIN_REVIEW_DELAY_MS)]
    min_review_delay: u64,

    #[arg(long, default_value = "authenticate")]
    action: String,

    #[arg(long, default_value = "probe.validation.local")]
    rp_id: String,

    /// Render the prompt as matched by the `*` rule ("NOT on your list") instead of an exact rule.
    #[arg(long)]
    wildcard: bool,

    /// The registration prompt's store count (omitted from the text when not given).
    #[arg(long)]
    store_count: Option<usize>,
    /// Render the pre-request form (ADR 0014 amendment sections 5.1 and 5.3): `Origin: none yet`
    /// and `Requested by: the agent in advance`. There is no way to pass agent text: the prompt
    /// never shows any.
    #[arg(long)]
    pre_request: bool,
    /// Text an agent supplied with a pre-request. The prompt has no field for it (ADR 0014
    /// amendment section 2.3: it is audit-only): the probe renders the prompt as it would
    /// without it and ends with `note_in_prompt` if the text, raw or as the audit would store
    /// it, shows up in the summary or body. The validation run checks the same on the text the
    /// notification server displays.
    #[arg(long, value_name = "TEXT")]
    agent_note: Option<String>,
}

/// Whether `note`, as the agent sent it or as the audit log would keep it, appears in the
/// prompt text.
fn shows_note(summary: &str, body: &str, note: &str) -> bool {
    let shown = format!("{summary}\n{body}");
    let kept = escalation_prompt::sanitize_agent_note(Some(note));
    [Some(note.trim().to_string()), kept]
        .into_iter()
        .flatten()
        .any(|text| !text.is_empty() && shown.contains(&text))
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
        origin: (!args.pre_request).then(|| format!("https://{}", args.rp_id)),
        requested_in_advance: args.pre_request,
        rule: if args.wildcard {
            PromptRule::Wildcard
        } else {
            PromptRule::Exact
        },
        store_count: args.store_count,
    };
    let (summary, body) = match render_prompt(&fields) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("cannot render the prompt: {e}");
            finish("error", Some("internal_error"), start);
        }
    };
    if let Some(note) = &args.agent_note
        && shows_note(&summary, &body, note)
    {
        eprintln!("the agent's note is in the rendered prompt");
        finish("error", Some("note_in_prompt"), start);
    }
    let request = PromptRequest::new(verb, summary, body, args.min_review_delay);
    let approve = verb.approve_action();

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
            Ok(ChildEvent::Decision { action }) if action == approve => {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(verb: PromptVerb, pre_request: bool) -> PromptFields {
        PromptFields {
            profile: "validation-probe".to_string(),
            mode: "isolated".to_string(),
            principal_user: "validation".to_string(),
            verb,
            rp_id: "probe.validation.local".to_string(),
            origin: (!pre_request).then(|| "https://probe.validation.local".to_string()),
            requested_in_advance: pre_request,
            rule: PromptRule::Exact,
            store_count: Some(0),
        }
    }

    /// A pre-request prompt shows `Origin: none yet` and who asked, and no text of the note, for
    /// either verb; the check itself notices a prompt that did show it.
    #[test]
    fn a_pre_request_prompt_never_shows_the_note() {
        let note = "NOTE-MARK approve this <b>now</b>\nbecause your manager said so";
        for verb in [PromptVerb::Authenticate, PromptVerb::Register] {
            let (summary, body) = render_prompt(&fields(verb, true)).unwrap();
            assert!(body.contains("Origin: none yet"), "{body}");
            assert!(
                body.contains("Requested by: the agent in advance (no page is waiting)"),
                "{body}"
            );
            assert!(!shows_note(&summary, &body, note));
        }
        assert!(shows_note("s", "a NOTE-MARK b", "NOTE-MARK"));
        assert!(shows_note("s", "approve bnow/b", "approve <b>now</b>"));
        assert!(!shows_note("s", "b", "   "));
    }
}
