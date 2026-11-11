//! `passless agent browser` and `passless agent mcp` (ADR 0014 D4, the agent-browser "easy
//! path"): ensure the managed browser of the calling principal and hand its CDP endpoint to a
//! tool, directly or through an MCP stdio adapter.
//!
//! These commands need a principal session (the capability descriptor `agent run` passes). Run
//! from a plain shell, they start one for the profile and re-run themselves in it, with the same
//! standard streams, so `passless agent browser --profile p` works from a terminal.

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use passless_core::agent::protocol::{BrowserStatusResponse, PrincipalRequest, PrincipalResponse};
use passless_core::{Error, McpAdapter, McpAdapterKind, McpConfigTarget, OutputFormat, Result};

use serde::Serialize;

use crate::agent::client::{ClientError, PrincipalClient, resolve_runtime_base};

/// How long `--wait` waits for the browser to be intercepting.
const WAIT_TIMEOUT: Duration = Duration::from_secs(60);
const WAIT_POLL: Duration = Duration::from_millis(250);

/// The default npm packages the adapters run.
const PLAYWRIGHT_PACKAGE: &str = "@playwright/mcp";
const CHROME_DEVTOOLS_PACKAGE: &str = "chrome-devtools-mcp";

#[derive(Serialize)]
struct BrowserOutput<'a> {
    /// The CDP HTTP endpoint (`http://127.0.0.1:<port>`): what `connectOverCDP`, browser-use
    /// `cdp_url`, `agent-browser --cdp` and `--browserUrl` take.
    endpoint: &'a str,
    /// The browser's `ws://` endpoint.
    ws_endpoint: &'a str,
    profile: &'a str,
    status: &'a str,
    shared_browser_context: bool,
    interception: &'a str,
    incognito_allowed: bool,
}

/// `http://127.0.0.1:<port>` from the browser's `ws://127.0.0.1:<port>/devtools/browser/<id>`.
/// `None` unless it is a loopback websocket URL.
pub fn http_endpoint(ws_endpoint: &str) -> Option<String> {
    let url = url::Url::parse(ws_endpoint).ok()?;
    if url.scheme() != "ws" {
        return None;
    }
    let host = url.host_str()?;
    if host != "127.0.0.1" && host != "localhost" && host != "[::1]" {
        return None;
    }
    Some(format!("http://{host}:{}", url.port()?))
}

fn principal_client(profile: &str) -> std::result::Result<PrincipalClient, ClientError> {
    let base = resolve_runtime_base()?;
    PrincipalClient::connect_launched(&base, profile)
}

/// Whether this process holds a principal session's capability descriptor.
fn in_principal_session(profile: &str) -> Result<bool> {
    match principal_client(profile) {
        Ok(_) => Ok(true),
        Err(ClientError::NoControlFd) => Ok(false),
        Err(e) => Err(Error::Other(e.to_string())),
    }
}

fn ensure(profile: &str, url: Option<&str>, headed: bool) -> Result<BrowserStatusResponse> {
    let mut client = principal_client(profile).map_err(|e| Error::Other(e.to_string()))?;
    match client
        .request(PrincipalRequest::EnsureBrowser {
            start_url: url.map(ToOwned::to_owned),
            headed,
        })
        .map_err(|e| Error::Other(e.to_string()))?
    {
        PrincipalResponse::BrowserEnsured(status) => Ok(status),
        _ => Err(Error::Other(
            "the agent returned an unexpected EnsureBrowser response".into(),
        )),
    }
}

fn is_intercepting(status: &BrowserStatusResponse) -> bool {
    status.interception.as_deref() == Some("attached") && status.incognito_allowed == Some(true)
}

/// Block until the profile's browser is attached and allowed in incognito (the `hello` gate of
/// plan D6 layer 1), or fail after [`WAIT_TIMEOUT`].
fn wait_intercepting(profile: &str, first: BrowserStatusResponse) -> Result<BrowserStatusResponse> {
    let deadline = Instant::now() + WAIT_TIMEOUT;
    let mut status = first;
    loop {
        if is_intercepting(&status) {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(Error::Other(format!(
                "the managed browser is not intercepting after {} s (interception: {}, \
                 incognito allowed: {:?}); see `passless doctor --agents`",
                WAIT_TIMEOUT.as_secs(),
                status.interception.as_deref().unwrap_or("unknown"),
                status.incognito_allowed
            )));
        }
        std::thread::sleep(WAIT_POLL);
        let mut client = principal_client(profile).map_err(|e| Error::Other(e.to_string()))?;
        status = match client
            .request(PrincipalRequest::BrowserStatus)
            .map_err(|e| Error::Other(e.to_string()))?
        {
            PrincipalResponse::BrowserStatus(status) => status,
            _ => return Err(Error::Other("unexpected BrowserStatus response".into())),
        };
    }
}

/// What `agent browser` prints.
pub struct BrowserFlags {
    pub json: bool,
    pub env: bool,
    pub wait: bool,
    pub headed: bool,
    pub url: Option<String>,
}

/// The text printed for the endpoint: the bare URL, `PASSLESS_CDP_URL=<url>`, or the JSON
/// envelope.
fn render_browser(
    profile: &str,
    status: &BrowserStatusResponse,
    flags: &BrowserFlags,
) -> Result<String> {
    let ws = status
        .cdp_endpoint
        .as_deref()
        .ok_or_else(|| Error::Other("the agent returned no CDP endpoint".into()))?;
    let endpoint = http_endpoint(ws).ok_or_else(|| {
        Error::Other("the agent returned a CDP endpoint that is not a loopback ws:// URL".into())
    })?;
    Ok(if flags.json {
        serde_json::to_string(&serde_json::json!({
            "version": "1",
            "status": "ok",
            "data": BrowserOutput {
                endpoint: &endpoint,
                ws_endpoint: ws,
                profile,
                status: &status.status,
                shared_browser_context: status.shared_browser_context.unwrap_or(false),
                interception: status.interception.as_deref().unwrap_or("unknown"),
                incognito_allowed: status.incognito_allowed.unwrap_or(false),
            },
        }))
        .map_err(|e| Error::Other(e.to_string()))?
    } else if flags.env {
        format!("PASSLESS_CDP_URL={endpoint}")
    } else {
        endpoint
    })
}

/// `passless agent browser`.
pub fn dispatch_browser(
    profile: Option<&str>,
    output: OutputFormat,
    flags: &BrowserFlags,
) -> Result<()> {
    let profile = profile
        .ok_or_else(|| Error::Other("--profile is required for `agent browser`".to_string()))?;
    if !in_principal_session(profile)? {
        let mut args = vec![
            "agent".to_string(),
            "browser".to_string(),
            "--profile".to_string(),
            profile.to_string(),
        ];
        for (on, flag) in [
            (flags.json, "--json"),
            (flags.env, "--env"),
            (flags.wait, "--wait"),
            (flags.headed, "--headed"),
        ] {
            if on {
                args.push(flag.to_string());
            }
        }
        if let Some(url) = &flags.url {
            args.extend(["--url".to_string(), url.clone()]);
        }
        return relaunch(output, profile, args);
    }
    let mut status = ensure(profile, flags.url.as_deref(), flags.headed)?;
    if flags.wait {
        status = wait_intercepting(profile, status)?;
    }
    println!("{}", render_browser(profile, &status, flags)?);
    Ok(())
}

/// Re-run this executable with `args` in a new principal session of `profile`, standard streams
/// shared, quietly.
fn relaunch(output: OutputFormat, profile: &str, args: Vec<String>) -> Result<()> {
    let exe = std::env::current_exe()
        .map_err(|e| Error::Other(format!("failed to resolve the passless executable: {e}")))?;
    let mut command = vec![exe];
    command.extend(args.into_iter().map(PathBuf::from));
    super::agent::run_in_principal_session(output, profile, &command, true)
}

fn resolve_npx(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        if !path.is_absolute() {
            return Err(Error::Other(format!(
                "--npx must be an absolute path, got '{}'",
                path.display()
            )));
        }
        return Ok(path.to_path_buf());
    }
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join("npx"))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| {
            Error::Other(
                "npx was not found in PATH: install Node.js (it ships npx) or pass --npx <path>"
                    .to_string(),
            )
        })
}

/// The npx command line of an adapter: `npx --yes <package> <args...>`. `--yes` because the
/// MCP client owns stdin, so npx cannot ask before installing the package.
fn npx_command(npx: &Path, package: &str, args: &[String]) -> Vec<PathBuf> {
    let mut command = vec![
        npx.to_path_buf(),
        PathBuf::from("--yes"),
        PathBuf::from(package),
    ];
    command.extend(args.iter().map(PathBuf::from));
    command
}

/// The MCP clients' server name, and the arguments `passless` is started with.
fn entry_parts(profile: &str, adapter: McpAdapterKind) -> (&'static str, Vec<String>) {
    let (name, adapter_name) = match adapter {
        McpAdapterKind::Playwright => ("passless-playwright", "playwright"),
        McpAdapterKind::ChromeDevtools => ("passless-chrome-devtools", "chrome-devtools"),
    };
    (
        name,
        ["agent", "mcp", adapter_name, "--profile", profile]
            .map(String::from)
            .to_vec(),
    )
}

/// The configuration a client reads, with one passless MCP server entry (formats checked against
/// each client's documentation, P10b):
///
/// - Claude Code: `.mcp.json`, `mcpServers.<name> {type, command, args}`; the same entry without
///   the wrapper is what `claude mcp add-json <name> '<entry>'` takes;
/// - opencode: `opencode.json`, `mcp.servers.<name> {type: "local", command: [..]}` (the layout
///   its current documentation shows);
/// - Cursor: `.cursor/mcp.json`, `mcpServers.<name> {type, command, args}`;
/// - VS Code: `.vscode/mcp.json`, `servers.<name> {type, command, args}`.
pub fn render_client_config(
    target: McpConfigTarget,
    profile: &str,
    adapter: McpAdapterKind,
) -> serde_json::Value {
    use serde_json::json;
    let (name, args) = entry_parts(profile, adapter);
    let stdio = json!({ "type": "stdio", "command": "passless", "args": args });
    match target {
        McpConfigTarget::ClaudeCode | McpConfigTarget::Cursor => {
            json!({ "mcpServers": { name: stdio } })
        }
        McpConfigTarget::Vscode => json!({ "servers": { name: stdio } }),
        McpConfigTarget::Opencode => {
            let mut command = vec!["passless".to_string()];
            command.extend(args);
            json!({
                "$schema": "https://opencode.ai/config.json",
                "mcp": { "servers": { name: { "type": "local", "command": command } } }
            })
        }
    }
}

/// `passless agent mcp --print-config <client>`.
fn print_config(
    profile: Option<&str>,
    target: McpConfigTarget,
    adapter: McpAdapterKind,
) -> Result<()> {
    let profile = profile.ok_or_else(|| {
        Error::Other("--profile is required to print an MCP server entry".to_string())
    })?;
    let config = render_client_config(target, profile, adapter);
    println!(
        "{}",
        serde_json::to_string_pretty(&config).map_err(|e| Error::Other(e.to_string()))?
    );
    if target == McpConfigTarget::ClaudeCode {
        let (name, _) = entry_parts(profile, adapter);
        let entry = &config["mcpServers"][name];
        eprintln!(
            "# or, without editing .mcp.json:\n# claude mcp add-json {name} --scope project '{entry}'"
        );
    }
    Ok(())
}

/// `passless agent mcp ...`.
pub fn dispatch_mcp(
    profile: Option<&str>,
    output: OutputFormat,
    print: Option<McpConfigTarget>,
    server: McpAdapterKind,
    adapter: Option<&McpAdapter>,
) -> Result<()> {
    if let Some(target) = print {
        return print_config(profile, target, server);
    }
    let Some(adapter) = adapter else {
        return Err(Error::Other(
            "choose an adapter (`agent mcp playwright` or `agent mcp chrome-devtools`) or pass \
             --print-config <claude-code|opencode|cursor|vscode>"
                .to_string(),
        ));
    };
    let profile =
        profile.ok_or_else(|| Error::Other("--profile is required for `agent mcp`".to_string()))?;
    let (kind, package, npx, url, extra) = match adapter {
        McpAdapter::Playwright {
            package,
            npx,
            url,
            extra,
        } => (McpAdapterKind::Playwright, package, npx, url, extra),
        McpAdapter::ChromeDevtools {
            package,
            npx,
            url,
            extra,
        } => (McpAdapterKind::ChromeDevtools, package, npx, url, extra),
    };
    let adapter_name = entry_parts(profile, kind).1[2].clone();
    if !in_principal_session(profile)? {
        // Resolve npx here: the principal session runs with the daemon's environment, whose PATH
        // need not have it.
        let npx = resolve_npx(npx.as_deref())?;
        let mut args = vec![
            "agent".to_string(),
            "mcp".to_string(),
            adapter_name,
            "--profile".to_string(),
            profile.to_string(),
            "--npx".to_string(),
            npx.display().to_string(),
        ];
        if let Some(package) = package {
            args.extend(["--package".to_string(), package.clone()]);
        }
        if let Some(url) = url {
            args.extend(["--url".to_string(), url.clone()]);
        }
        if !extra.is_empty() {
            args.push("--".to_string());
            args.extend(extra.iter().cloned());
        }
        return relaunch(output, profile, args);
    }
    let npx = resolve_npx(npx.as_deref())?;
    match kind {
        McpAdapterKind::Playwright => {
            let package = package.as_deref().unwrap_or(PLAYWRIGHT_PACKAGE);
            let command = npx_command(&npx, package, extra);
            super::playwright_mcp::run_as_principal(profile, url.as_deref(), &command)
        }
        McpAdapterKind::ChromeDevtools => {
            run_chrome_devtools(profile, url.as_deref(), &npx, package.as_deref(), extra)
        }
    }
}

/// `npx chrome-devtools-mcp --browserUrl <endpoint>`. The browser is ensured before the server
/// starts: puppeteer fetches `<browserUrl>/json/version` at the root of the URL and cannot send
/// the bootstrap's bearer header (or keep a token in the URL path), so the lazy, authenticated
/// discovery endpoint `agent mcp playwright` uses is not possible here, and an unauthenticated
/// one would let any local process start the browser.
fn run_chrome_devtools(
    profile: &str,
    url: Option<&str>,
    npx: &Path,
    package: Option<&str>,
    extra: &[String],
) -> Result<()> {
    let status = wait_intercepting(profile, ensure(profile, url, false)?)?;
    let ws = status
        .cdp_endpoint
        .as_deref()
        .ok_or_else(|| Error::Other("the agent returned no CDP endpoint".into()))?;
    let endpoint = http_endpoint(ws)
        .ok_or_else(|| Error::Other("the agent returned a non-loopback CDP endpoint".into()))?;
    let mut args = vec!["--browserUrl".to_string(), endpoint];
    args.extend(extra.iter().cloned());
    let command = npx_command(npx, package.unwrap_or(CHROME_DEVTOOLS_PACKAGE), &args);
    let mut child = Command::new(&command[0]);
    child.args(&command[1..]);
    spawn_without_capability(&mut child);
    super::playwright_mcp::supervise(child, "chrome-devtools-mcp", &command[0])
}

/// The MCP server needs browser authority, not the principal capability: close the descriptor
/// before exec and tie the child's life to this wrapper's.
pub(super) fn spawn_without_capability(command: &mut Command) {
    // SAFETY: the closure only calls async-signal-safe `close` and `prctl`.
    unsafe {
        command.pre_exec(|| {
            let _ = libc::close(crate::agent::launcher::CONTROL_FD);
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(interception: &str, incognito: bool) -> BrowserStatusResponse {
        BrowserStatusResponse {
            running: true,
            status: "active".into(),
            cdp_endpoint: Some(
                "ws://127.0.0.1:43871/devtools/browser/00000000-0000-0000-0000-000000000000".into(),
            ),
            shared_browser_context: Some(true),
            interception: Some(interception.into()),
            incognito_allowed: Some(incognito),
        }
    }

    #[test]
    fn the_http_endpoint_is_the_loopback_origin_of_the_websocket_endpoint() {
        assert_eq!(
            http_endpoint("ws://127.0.0.1:43871/devtools/browser/abc").as_deref(),
            Some("http://127.0.0.1:43871")
        );
        for bad in [
            "ws://evil.example:9222/devtools/browser/abc",
            "wss://127.0.0.1:9222/devtools/browser/abc",
            "http://127.0.0.1:9222",
            "ws://127.0.0.1/devtools/browser/abc",
            "not a url",
        ] {
            assert_eq!(http_endpoint(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_output_is_a_bare_url_an_env_line_or_a_json_envelope() {
        let flags = |json, env| BrowserFlags {
            json,
            env,
            wait: false,
            headed: false,
            url: None,
        };
        let status = status("attached", true);
        assert_eq!(
            render_browser("p", &status, &flags(false, false)).unwrap(),
            "http://127.0.0.1:43871"
        );
        assert_eq!(
            render_browser("p", &status, &flags(false, true)).unwrap(),
            "PASSLESS_CDP_URL=http://127.0.0.1:43871"
        );
        let json: serde_json::Value =
            serde_json::from_str(&render_browser("p", &status, &flags(true, false)).unwrap())
                .unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["data"]["endpoint"], "http://127.0.0.1:43871");
        assert_eq!(json["data"]["profile"], "p");
        assert_eq!(json["data"]["interception"], "attached");
        assert_eq!(json["data"]["incognito_allowed"], true);
        let mut none = status.clone();
        none.cdp_endpoint = None;
        assert!(render_browser("p", &none, &flags(false, false)).is_err());
    }

    #[test]
    fn only_an_attached_incognito_allowed_browser_is_intercepting() {
        assert!(is_intercepting(&status("attached", true)));
        assert!(!is_intercepting(&status("attached", false)));
        assert!(!is_intercepting(&status("degraded", true)));
        assert!(!is_intercepting(&status("pending", true)));
    }

    #[test]
    fn the_npx_command_installs_without_asking_and_keeps_extra_arguments() {
        let command = npx_command(
            Path::new("/usr/bin/npx"),
            "@playwright/mcp@0.0.85",
            &["--isolated".to_string()],
        );
        let command: Vec<_> = command
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            command,
            [
                "/usr/bin/npx",
                "--yes",
                "@playwright/mcp@0.0.85",
                "--isolated"
            ]
        );
        assert!(resolve_npx(Some(Path::new("npx"))).is_err());
        assert_eq!(
            resolve_npx(Some(Path::new("/opt/node/bin/npx"))).unwrap(),
            PathBuf::from("/opt/node/bin/npx")
        );
    }

    #[test]
    fn client_configs_follow_each_clients_format() {
        use McpAdapterKind::{ChromeDevtools, Playwright};
        let args = ["agent", "mcp", "playwright", "--profile", "coding"];

        // Claude Code `.mcp.json`: `mcpServers`, stdio command and args.
        let claude = render_client_config(McpConfigTarget::ClaudeCode, "coding", Playwright);
        let entry = &claude["mcpServers"]["passless-playwright"];
        assert_eq!(entry["type"], "stdio");
        assert_eq!(entry["command"], "passless");
        assert_eq!(entry["args"], serde_json::json!(args));

        // Cursor `.cursor/mcp.json`: the same shape.
        let cursor = render_client_config(McpConfigTarget::Cursor, "coding", Playwright);
        assert_eq!(cursor, claude);

        // VS Code `.vscode/mcp.json`: `servers`, not `mcpServers`.
        let vscode = render_client_config(McpConfigTarget::Vscode, "coding", Playwright);
        assert!(vscode.get("mcpServers").is_none());
        assert_eq!(vscode["servers"]["passless-playwright"]["type"], "stdio");
        assert_eq!(
            vscode["servers"]["passless-playwright"]["args"],
            serde_json::json!(args)
        );

        // opencode `opencode.json`: `mcp.servers.<name>` with a local command array.
        let opencode = render_client_config(McpConfigTarget::Opencode, "coding", Playwright);
        let entry = &opencode["mcp"]["servers"]["passless-playwright"];
        assert_eq!(entry["type"], "local");
        assert_eq!(
            entry["command"],
            serde_json::json!([
                "passless",
                "agent",
                "mcp",
                "playwright",
                "--profile",
                "coding"
            ])
        );
        assert_eq!(opencode["$schema"], "https://opencode.ai/config.json");

        let devtools = render_client_config(McpConfigTarget::ClaudeCode, "coding", ChromeDevtools);
        assert_eq!(
            devtools["mcpServers"]["passless-chrome-devtools"]["args"][2],
            "chrome-devtools"
        );
    }
}
