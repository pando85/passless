//! `passless doctor --agents`: host checks for the agent browser path. See
//! [`crate::agent::doctor_agents`].

use passless_core::agent::protocol::DoctorResponse;
use passless_core::{AppConfig, Args, Error, OutputFormat, Result};

use crate::agent::doctor_agents;

use super::config_check;

/// Run the checks and print them. Exits 1 when a check fails, after printing.
pub fn dispatch(args: &mut Args, agents: bool, output: OutputFormat) -> Result<()> {
    if !agents {
        return Err(Error::Other(
            "nothing to check: pass --agents to check the agent browser path".to_string(),
        ));
    }
    let config = AppConfig::load(args)?;
    let mut checks = doctor_agents::config_checks(config_check::check(&config));
    checks.extend(doctor_agents::run(&config.agents));
    let report = DoctorResponse {
        healthy: checks.iter().all(|check| check.passed),
        checks,
    };
    match output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "version": "1",
                "status": if report.healthy { "ok" } else { "unhealthy" },
                "data": report,
            }))
            .map_err(|e| Error::Other(e.to_string()))?
        ),
        OutputFormat::Plain => {
            println!(
                "status: {}",
                if report.healthy {
                    "healthy"
                } else {
                    "unhealthy"
                }
            );
            for check in &report.checks {
                let mark = check.mark();
                println!("  [{mark}] {}: {}", check.name, check.message);
            }
        }
    }
    if !report.healthy {
        std::process::exit(1);
    }
    Ok(())
}
