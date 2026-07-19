#[path = "../agent/prompt.rs"]
#[allow(dead_code, unused_imports, unused_variables)]
mod prompt;

use std::process;

use clap::Parser;
use serde::Serialize;

use passless_core::agent::ProfileId;

use prompt::{DesktopPromptHandle, PromptAction, PromptHandle, PromptMode, PromptRequest};

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
    about = "Validation-only production prompt probe"
)]
struct Args {
    #[arg(long, default_value_t = 60)]
    timeout: u64,

    #[arg(long, default_value_t = 1000)]
    min_review_delay: u64,

    #[arg(long, default_value = "authenticate")]
    action: String,

    #[arg(long, default_value = "probe.validation.local")]
    rp_id: String,
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .format_timestamp(None)
        .init();

    let args = Args::parse();

    let action = match args.action.as_str() {
        "register" => PromptAction::Register,
        "authenticate" => PromptAction::Authenticate,
        other => {
            let output = ProbeOutput {
                decision: "error".to_string(),
                error_kind: Some("internal_error".to_string()),
                latency_class: LatencyClass::Fast,
            };
            eprintln!("invalid action: {other}");
            println!("{}", serde_json::to_string(&output).unwrap());
            process::exit(1);
        }
    };

    let profile_id = match ProfileId::new("validation-probe") {
        Ok(id) => id,
        Err(e) => {
            let output = ProbeOutput {
                decision: "error".to_string(),
                error_kind: Some("internal_error".to_string()),
                latency_class: LatencyClass::Fast,
            };
            eprintln!("failed to construct profile id: {e}");
            println!("{}", serde_json::to_string(&output).unwrap());
            process::exit(1);
        }
    };

    let request = match PromptRequest::builder()
        .profile_id(profile_id)
        .mode(PromptMode::Isolated)
        .action(action)
        .rp_id(&args.rp_id)
        .grant_ttl_secs(300)
        .session_ttl_secs(3600)
        .untrusted_reason("validation probe")
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            let output = ProbeOutput {
                decision: "error".to_string(),
                error_kind: Some("internal_error".to_string()),
                latency_class: LatencyClass::Fast,
            };
            eprintln!("failed to build prompt request: {e}");
            println!("{}", serde_json::to_string(&output).unwrap());
            process::exit(1);
        }
    };

    let handle = DesktopPromptHandle::new(args.timeout, args.min_review_delay);

    let result = handle.prompt(&request);

    let latency_class = LatencyClass::from_ms(result.latency_ms);
    let error_kind = result.error_kind.map(|k| format!("{k}"));

    let output = ProbeOutput {
        decision: format!("{}", result.decision),
        error_kind,
        latency_class,
    };

    println!("{}", serde_json::to_string(&output).unwrap());
}
