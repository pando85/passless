//! `passless config check`: validate the configuration offline, as the daemon would at startup.
//! `passless doctor --agents` runs the same check.
//!
//! The parsing and the rules are the daemon's own ([`AppConfig::load`], [`AppConfig::check_startup`],
//! [`AgentConfig::deprecation_warnings`]); this module only adds what the daemon discovers later by
//! failing (the audit directory) and prints the result.

use passless_core::{AppConfig, Args, Error, Result};

use std::path::PathBuf;

/// What a valid configuration still tells the operator.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Checked {
    pub warnings: Vec<String>,
    pub notes: Vec<String>,
}

/// Run the daemon's configuration checks on a loaded configuration.
pub fn check(config: &AppConfig) -> Result<Checked> {
    #[allow(unused_mut)]
    let mut checked = Checked::default();
    config.check_startup()?;
    #[cfg(feature = "agent")]
    {
        if config.agents.enabled {
            // The daemon logs these while validating the profiles.
            checked
                .warnings
                .extend(config.agents.deprecation_warnings());
            // `AuditGate::open` creates only the last component of the path.
            if let Some(audit) = &config.agents.audit_path {
                crate::agent::audit::AuditGate::check_dir(audit).map_err(|e| {
                    Error::Config(format!("agents.audit_path {}: {e}", audit.display()))
                })?;
            }
        } else if !config.agents.profiles.is_empty() {
            checked.notes.push(
                "agents.enabled is false: the agent profiles are not validated (the daemon does not either)"
                    .to_owned(),
            );
        }
    }
    Ok(checked)
}

/// `passless config check [--config-path PATH]`.
pub fn dispatch(args: &mut Args, config_path: Option<PathBuf>) -> Result<()> {
    if let Some(path) = config_path {
        args.config_path = Some(path);
    }
    // The daemon quietly uses the defaults for a file that is not there; a check of a file named
    // on purpose must not.
    if let Some(path) = args.config_path.as_ref().filter(|path| !path.exists()) {
        return Err(Error::Config(format!(
            "configuration file {} does not exist",
            path.display()
        )));
    }
    match AppConfig::config_file_path(args) {
        Some(path) => println!("Checking {}", path.display()),
        None => println!("No configuration file found: checking the defaults"),
    }
    let config = AppConfig::load(args)?;
    let checked = check(&config)?;
    for note in &checked.notes {
        println!("note: {note}");
    }
    for warning in &checked.warnings {
        println!("warning: {warning}");
    }
    match checked.warnings.len() {
        0 => println!("ok: the configuration is valid"),
        1 => println!("ok: the configuration is valid, with 1 warning"),
        n => println!("ok: the configuration is valid, with {n} warnings"),
    }
    Ok(())
}

#[cfg(all(test, feature = "agent"))]
mod tests;
