use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use passless_core::agent::protocol::{
    ErrorCode, PrincipalRequest, PrincipalResponse, ProtocolError, RecommendedAction,
};
use passless_core::agent::{AgentConfig, BrowserScope};
use passless_core::{Error, Result};

use crate::agent::cdp_bootstrap::CdpBootstrap;
use crate::agent::client::{ClientError, PrincipalClient, resolve_runtime_base};

use super::mcp_relay::{AccessCall, AccessTool, ToolResult};

/// How often the adapters check that the browser they were given is still there.
const WATCH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

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
        Ok(_) => run_as_principal(profile, url, command, false).map(Some),
        Err(ClientError::NoControlFd) => Ok(None),
        Err(e) => Err(client_error(e)),
    }
}

pub(super) fn run_as_principal(
    profile: &str,
    url: Option<&str>,
    command: &[PathBuf],
    with_access_tool: bool,
) -> Result<()> {
    let executable = check_command(command)?;
    let token = bootstrap_token()?;
    let profile_for_bootstrap = profile.to_string();
    let start_url = url.map(ToOwned::to_owned);
    let bootstrap = CdpBootstrap::start(token.clone(), move || {
        let (endpoint, _) = ensure_browser(&profile_for_bootstrap, start_url.as_deref(), false)?;
        Ok(endpoint)
    })
    .map_err(|e| Error::Other(e.to_string()))?;

    let child_command = server_command(profile, command, &bootstrap.endpoint(), &token, true);
    // This process is the principal session: with the opt-in flag it relays the client's stdio and
    // asks the daemon itself (the capability never reaches the server, which has none).
    let tool: Option<Arc<dyn AccessTool>> = with_access_tool.then(|| {
        Arc::new(SessionTool {
            profile: profile.to_string(),
        }) as Arc<dyn AccessTool>
    });
    let result = supervise_watching(
        child_command,
        "Playwright MCP",
        executable,
        &mut || true,
        tool,
    );
    drop(bootstrap);
    result
}

/// `passless_request_access` through the principal session this process runs in.
struct SessionTool {
    profile: String,
}

impl AccessTool for SessionTool {
    fn call(&self, call: AccessCall) -> ToolResult {
        let failed = |message: String| {
            ProtocolError::new(ErrorCode::Internal, message, RecommendedAction::Retry)
        };
        let base = resolve_runtime_base().map_err(|e| failed(e.to_string()))?;
        let mut client = PrincipalClient::connect_launched(&base, &self.profile)
            .map_err(|e| failed(e.to_string()))?;
        match client.request(PrincipalRequest::RequestAccess {
            rp_id: call.rp_id,
            action: call.action,
            note: call.note,
            wait_ms: Some(call.wait_ms),
        }) {
            Ok(PrincipalResponse::AccessRequest(status)) => Ok(status),
            Ok(_) => Err(failed(
                "agent returned an unexpected RequestAccess response".to_string(),
            )),
            Err(ClientError::Protocol(error)) => Err(error),
            Err(e) => Err(failed(e.to_string())),
        }
    }
}

/// The Playwright MCP command line must be an absolute executable and its arguments.
pub(super) fn check_command(command: &[PathBuf]) -> Result<&std::path::Path> {
    let Some(executable) = command.first() else {
        return Err(Error::Other(
            "playwright-mcp requires an executable after '--'".to_string(),
        ));
    };
    if !executable.is_absolute() {
        return Err(Error::Other(format!(
            "Playwright MCP executable must be an absolute path, got '{}'",
            executable.display()
        )));
    }
    Ok(executable)
}

/// A fresh bearer for the discovery bootstrap: it lives as long as the process that serves the
/// bootstrap and is only ever given to that process's Playwright MCP child.
pub(super) fn bootstrap_token() -> Result<String> {
    crate::agent::sign::generate_bearer_token()
        .map_err(|e| Error::Other(format!("failed to generate CDP bootstrap token: {e}")))
}

/// The Playwright MCP server pointed at the bootstrap `endpoint` (see [`playwright_command`]),
/// with `--shared-browser-context` for a profile whose sessions share one browser. The
/// Playwright process needs browser authority, not Passless principal IPC authority: inside a
/// session the capability descriptor is closed before exec. Either way the server dies with the
/// process that supervises it.
pub(super) fn server_command(
    profile: &str,
    command: &[PathBuf],
    endpoint: &str,
    token: &str,
    in_session: bool,
) -> Command {
    let has_shared_flag = command.iter().skip(1).any(|arg| {
        arg.to_str()
            .is_some_and(|s| s == "--shared-browser-context")
    });
    let mut child_command = playwright_command(
        command,
        endpoint,
        token,
        profile_uses_shared_browser(profile) && !has_shared_flag,
    );
    if in_session {
        super::agent_browser::spawn_without_capability(&mut child_command);
    } else {
        super::agent_browser::spawn_bound_to_wrapper(&mut child_command);
    }
    child_command
}

/// The `@playwright/mcp` command: the user's arguments, the bootstrap as `--cdp-endpoint`, and the
/// bootstrap's bearer through `PLAYWRIGHT_MCP_CDP_HEADERS`, never as an argument: argv is readable
/// by every local user through `/proc/<pid>/cmdline`, the environment only by the process's owner.
/// The directory of the executable (npx) goes first in the child's `PATH`, so that a node that
/// lives next to it (nvm, fnm, a prefix install) is found.
fn playwright_command(
    command: &[PathBuf],
    endpoint: &str,
    token: &str,
    add_shared_flag: bool,
) -> Command {
    let mut child = Command::new(&command[0]);
    child.args(command.iter().skip(1));
    child.arg("--cdp-endpoint").arg(endpoint);
    child.env(
        "PLAYWRIGHT_MCP_CDP_HEADERS",
        format!("Authorization: Bearer {token}"),
    );
    if add_shared_flag {
        child.arg("--shared-browser-context");
    }
    super::agent_browser::prepend_path_dir(&mut child, command[0].parent());
    child
}

/// Run an MCP server child to completion (its exit status is ours), polling `browser_alive`
/// every couple of seconds: when it reports the browser gone, the child is stopped and an error
/// returned, so that an MCP client restarts the adapter and gets a fresh endpoint. With `tool`
/// the server's stdio goes through the access-tool relay ([`super::mcp_relay`]).
pub(super) fn supervise_watching(
    mut child_command: Command,
    label: &str,
    executable: &std::path::Path,
    browser_alive: &mut dyn FnMut() -> bool,
    tool: Option<Arc<dyn AccessTool>>,
) -> Result<()> {
    let spawned = match tool {
        Some(tool) => super::mcp_relay::spawn_relayed(&mut child_command, tool)
            .map(|(child, handle)| (child, Some(handle))),
        None => child_command.spawn().map(|child| (child, None)),
    };
    let (mut child, relay) = spawned.map_err(|e| {
        Error::Other(format!(
            "failed to start {label} executable '{}': {e}",
            executable.display()
        ))
    })?;

    let mut last_check = std::time::Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(e) => return Err(Error::Other(format!("failed waiting for {label}: {e}"))),
        }
        if last_check.elapsed() >= WATCH_INTERVAL {
            last_check = std::time::Instant::now();
            if !browser_alive() {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::Other(format!(
                    "the managed browser is gone (it was closed, or its owning session ended); \
                     stopped {label}: your MCP client restarts it with a fresh endpoint"
                )));
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };

    // The server's last output still reaches the client.
    if let Some(relay) = relay {
        relay.finish();
    }
    exit_result(label, status)
}

/// The child's exit status is ours.
pub(super) fn exit_result(label: &str, status: std::process::ExitStatus) -> Result<()> {
    if status.success() {
        Ok(())
    } else if let Some(code) = status.code() {
        Err(Error::Other(format!("{label} exited with code {code}")))
    } else {
        Err(Error::Other(format!("{label} terminated by signal")))
    }
}

fn ensure_browser(
    profile: &str,
    start_url: Option<&str>,
    headed: bool,
) -> std::result::Result<(String, bool), String> {
    let base = resolve_runtime_base().map_err(|e| e.to_string())?;
    let mut client =
        PrincipalClient::connect_launched(&base, profile).map_err(|e| e.to_string())?;
    let response = client
        .request(PrincipalRequest::EnsureBrowser {
            headed,
            start_url: start_url.map(ToOwned::to_owned),
            // The bootstrap hands out an endpoint, which a pipe-mode browser has none of: the
            // daemon refuses before it starts a browser nobody could reach.
            direct_cdp: true,
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

/// The names of the profiles in the agent configuration (`PASSLESS_CONFIG` or the default file);
/// empty when it cannot be read.
pub(super) fn configured_profile_names() -> Vec<String> {
    load_agent_config()
        .map(|config| config.profiles.keys().cloned().collect())
        .unwrap_or_default()
}

pub(super) fn load_agent_config() -> Option<AgentConfig> {
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
    fn the_command_must_be_an_absolute_executable() {
        assert!(check_command(&[]).is_err());
        let err = check_command(&[PathBuf::from("npx")])
            .unwrap_err()
            .to_string();
        assert!(err.contains("absolute"), "{err}");
        assert_eq!(
            check_command(&[PathBuf::from("/usr/bin/npx"), PathBuf::from("--yes")]).unwrap(),
            std::path::Path::new("/usr/bin/npx")
        );
    }

    #[test]
    fn the_bearer_never_appears_in_the_childs_argv() {
        let token = "s3cr3t-bearer-token-value";
        let command = vec![
            PathBuf::from("/opt/node/bin/npx"),
            PathBuf::from("--yes"),
            PathBuf::from("@playwright/mcp"),
        ];
        let child = playwright_command(&command, "http://127.0.0.1:4242", token, true);
        let argv: Vec<String> = child
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(
            argv.iter()
                .all(|a| !a.contains(token) && !a.contains("Bearer")),
            "{argv:?}"
        );
        assert!(!argv.iter().any(|a| a == "--cdp-header"), "{argv:?}");
        assert_eq!(
            argv,
            [
                "--yes",
                "@playwright/mcp",
                "--cdp-endpoint",
                "http://127.0.0.1:4242",
                "--shared-browser-context"
            ]
        );
        let env: std::collections::HashMap<_, _> = child
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert_eq!(
            env["PLAYWRIGHT_MCP_CDP_HEADERS"].as_deref(),
            Some("Authorization: Bearer s3cr3t-bearer-token-value")
        );
        // npx's directory leads the child's PATH.
        assert!(
            env["PATH"].as_deref().unwrap().starts_with("/opt/node/bin"),
            "{env:?}"
        );
    }

    #[test]
    fn a_vanished_browser_stops_the_server_with_an_actionable_error() {
        let mut sleeper = Command::new("/bin/sleep");
        sleeper.arg("30");
        let started = std::time::Instant::now();
        let err = supervise_watching(
            sleeper,
            "test MCP",
            std::path::Path::new("/bin/sleep"),
            &mut || false,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("browser is gone"), "{err}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "the child was stopped"
        );
        // A browser that stays up lets the child finish on its own.
        let mut quick = Command::new("/bin/true");
        quick.arg("x");
        supervise_watching(
            quick,
            "test MCP",
            std::path::Path::new("/bin/true"),
            &mut || true,
            None,
        )
        .unwrap();
    }
}
