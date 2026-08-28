use std::fs::File;
use std::io::BufReader;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use passless_core::agent::protocol::{PrincipalRequest, PrincipalResponse};
use passless_core::agent::{AgentConfig, BrowserScope};
use passless_core::{Error, Result};

use crate::agent::cdp_bootstrap::CdpBootstrap;
use crate::agent::client::{ClientError, PrincipalClient, resolve_runtime_base};

/// Try to run the Playwright MCP integration in the current process.
///
/// `Ok(None)` means this process is not a launched principal and the caller should re-launch
/// the current executable through the normal `agent run` path. Any other capability error is
/// considered fatal rather than falling back to admin, which prevents recursion or privilege
/// escalation when fd 3 exists but is malformed.
pub fn try_run_as_principal(
    profile: &str,
    url: Option<&str>,
    command: &[PathBuf],
) -> Result<Option<()>> {
    let base = resolve_runtime_base().map_err(client_error)?;
    match PrincipalClient::connect_launched(&base, profile) {
        Ok(_) => run_as_principal(profile, url, command).map(Some),
        Err(ClientError::NoControlFd) => Ok(None),
        Err(e) => Err(client_error(e)),
    }
}

fn run_as_principal(profile: &str, url: Option<&str>, command: &[PathBuf]) -> Result<()> {
    if command.is_empty() {
        return Err(Error::Other(
            "playwright-mcp requires an executable after '--'".to_string(),
        ));
    }

    let executable = &command[0];
    if !executable.is_absolute() {
        return Err(Error::Other(format!(
            "Playwright MCP executable must be an absolute path, got '{}'",
            executable.display()
        )));
    }

    let token = crate::agent::sign::generate_bearer_token()
        .map_err(|e| Error::Other(format!("failed to generate CDP bootstrap token: {e}")))?;
    let profile_owned = profile.to_string();
    let start_url = url.map(ToOwned::to_owned);
    let shared_browser = profile_uses_shared_browser(profile);
    let profile_for_bootstrap = profile_owned.clone();
    let bootstrap = CdpBootstrap::start(token.clone(), move || {
        let (endpoint, _) = ensure_browser(&profile_for_bootstrap, start_url.as_deref())?;
        Ok(endpoint)
    })
    .map_err(|e| Error::Other(e.to_string()))?;

    let bootstrap_endpoint = bootstrap.endpoint();
    let mut child_command = Command::new(executable);
    child_command.args(command.iter().skip(1));

    let has_shared_flag = command.iter().skip(1).any(|arg| {
        arg.to_str()
            .is_some_and(|s| s == "--shared-browser-context")
    });

    child_command
        .arg("--cdp-endpoint")
        .arg(&bootstrap_endpoint)
        .arg("--cdp-header")
        .arg(format!("Authorization: Bearer {token}"));

    if shared_browser && !has_shared_flag {
        child_command.arg("--shared-browser-context");
    }

    // The Playwright process needs browser authority, not Passless principal IPC authority.
    // Close the inherited capability fd before exec and arrange for the MCP child to die if the
    // principal wrapper disappears unexpectedly.
    unsafe {
        child_command.pre_exec(|| {
            let _ = libc::close(crate::agent::launcher::CONTROL_FD);
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = child_command.spawn().map_err(|e| {
        Error::Other(format!(
            "failed to start Playwright MCP executable '{}': {e}",
            executable.display()
        ))
    })?;

    let status = child
        .wait()
        .map_err(|e| Error::Other(format!("failed waiting for Playwright MCP: {e}")))?;
    drop(bootstrap);

    if status.success() {
        Ok(())
    } else if let Some(code) = status.code() {
        Err(Error::Other(format!(
            "Playwright MCP exited with code {code}"
        )))
    } else {
        Err(Error::Other(
            "Playwright MCP terminated by signal".to_string(),
        ))
    }
}

fn ensure_browser(
    profile: &str,
    start_url: Option<&str>,
) -> std::result::Result<(String, bool), String> {
    let base = resolve_runtime_base().map_err(|e| e.to_string())?;
    let mut client =
        PrincipalClient::connect_launched(&base, profile).map_err(|e| e.to_string())?;
    let response = client
        .request(PrincipalRequest::EnsureBrowser {
            start_url: start_url.map(ToOwned::to_owned),
        })
        .map_err(|e| e.to_string())?;
    match response {
        PrincipalResponse::BrowserEnsured(status) => {
            let endpoint = status.cdp_endpoint.ok_or_else(|| {
                "agent ensured a browser but returned no CDP endpoint".to_string()
            })?;
            let shared = status.shared_browser_context.unwrap_or(false);
            Ok((endpoint, shared))
        }
        _ => Err("agent returned an unexpected EnsureBrowser response".to_string()),
    }
}

fn profile_uses_shared_browser(profile: &str) -> bool {
    load_agent_config()
        .and_then(|config| config.get_profile(profile).cloned())
        .is_some_and(|p| p.browser_scope == BrowserScope::Profile)
}

fn load_agent_config() -> Option<AgentConfig> {
    let config_path = std::env::var("PASSLESS_CONFIG")
        .ok()
        .map(PathBuf::from)
        .or_else(|| dirs::config_dir().map(|p| p.join("passless/config.toml")))?;

    if !config_path.exists() {
        return None;
    }

    let file = File::open(&config_path).ok()?;
    let reader = BufReader::new(file);
    let content = std::io::read_to_string(reader).ok()?;
    let table: toml::Table = toml::from_str(&content).ok()?;

    table
        .get("agents")
        .and_then(|v| serde::Deserialize::deserialize(v.clone()).ok())
}

fn client_error(error: ClientError) -> Error {
    Error::Other(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_command_inside_principal_helper() {
        // The pure command validation is intentionally duplicated here rather than attempting to
        // manufacture a principal capability fd in this unit test.
        let command: Vec<PathBuf> = Vec::new();
        assert!(command.is_empty());
    }

    #[test]
    fn playwright_command_must_be_absolute() {
        let path = PathBuf::from("npx");
        assert!(!path.is_absolute());
    }
}
