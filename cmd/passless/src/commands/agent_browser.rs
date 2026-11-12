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
    /// `cdp_url`, `agent-browser --cdp` and `--browserUrl` take. `null` in pipe mode.
    endpoint: Option<&'a str>,
    /// The browser's `ws://` endpoint. `null` in pipe mode.
    ws_endpoint: Option<&'a str>,
    /// `port` or `pipe`. In pipe mode CDP only goes through `browser-control`.
    cdp_exposure: &'a str,
    /// The command that drives a pipe-mode browser; `null` in port mode.
    control_command: Option<String>,
    profile: &'a str,
    status: &'a str,
    shared_browser_context: bool,
    interception: &'a str,
    incognito_allowed: bool,
}

/// `http://127.0.0.1:<port>` from the browser's `ws://127.0.0.1:<port>/devtools/browser/<id>`.
/// `None` unless it is a `ws://127.0.0.1` URL: the only endpoint the daemon hands out, once it
/// verified that the listener is the managed browser's (an `[::1]` one never is).
pub fn http_endpoint(ws_endpoint: &str) -> Option<String> {
    let url = url::Url::parse(ws_endpoint).ok()?;
    if url.scheme() != "ws" {
        return None;
    }
    let host = url.host_str()?;
    if host != "127.0.0.1" {
        return None;
    }
    Some(format!("http://{host}:{}", url.port()?))
}

fn principal_client(profile: &str) -> std::result::Result<PrincipalClient, ClientError> {
    let base = resolve_runtime_base()?;
    PrincipalClient::connect_launched(&base, profile)
}

/// The profile a command applies to: `--profile`, else the only configured profile, else (inside
/// a principal session) the one profile whose daemon socket accepts this session. Several
/// candidates and no way to tell is an error that names them.
fn resolve_profile(explicit: Option<&str>) -> Result<String> {
    if let Some(profile) = explicit {
        return Ok(profile.to_string());
    }
    let names = super::playwright_mcp::configured_profile_names();
    choose_profile(&names, &|name: &str| {
        principal_client(name).is_ok_and(|mut client| {
            matches!(
                client.request(PrincipalRequest::Ping),
                Ok(PrincipalResponse::Pong)
            )
        })
    })
}

/// The pure part of [`resolve_profile`]: `accepts(name)` says whether this process is a session
/// of that profile (only asked when there is more than one).
fn choose_profile(names: &[String], accepts: &dyn Fn(&str) -> bool) -> Result<String> {
    match names {
        [] => Err(Error::Other(
            "no agent profile is configured (or the configuration cannot be read: see \
             PASSLESS_CONFIG); pass --profile <name>"
                .to_string(),
        )),
        [only] => Ok(only.clone()),
        several => {
            let mine: Vec<&String> = several.iter().filter(|name| accepts(name)).collect();
            match mine.as_slice() {
                [one] => Ok((*one).clone()),
                _ => Err(Error::Other(format!(
                    "several agent profiles are configured ({}) and this is not a session of \
                     exactly one of them; pass --profile <name>",
                    several.join(", ")
                ))),
            }
        }
    }
}

/// Whether this process holds a principal session's capability descriptor.
fn in_principal_session(profile: &str) -> Result<bool> {
    match principal_client(profile) {
        Ok(_) => Ok(true),
        Err(ClientError::NoControlFd) => Ok(false),
        Err(e) => Err(Error::Other(e.to_string())),
    }
}

fn ensure_once(
    profile: &str,
    url: Option<&str>,
    headed: bool,
    direct_cdp: bool,
) -> std::result::Result<BrowserStatusResponse, ClientError> {
    let mut client = principal_client(profile)?;
    match client.request(PrincipalRequest::EnsureBrowser {
        start_url: url.map(ToOwned::to_owned),
        headed,
        direct_cdp,
    })? {
        PrincipalResponse::BrowserEnsured(status) => Ok(status),
        _ => Err(ClientError::Io(std::io::Error::other(
            "the agent returned an unexpected EnsureBrowser response",
        ))),
    }
}

fn ensure(profile: &str, url: Option<&str>, headed: bool) -> Result<BrowserStatusResponse> {
    ensure_once(profile, url, headed, false).map_err(|e| Error::Other(e.to_string()))
}

/// [`ensure`] that keeps asking while the daemon answers `Conflict`: a degraded lease (its worker
/// is re-attaching) refuses to hand out its endpoint until the worker is back, for up to the
/// daemon's grace period, then the browser is replaced. `direct_cdp` says that the caller can only
/// use an endpoint, which a pipe-mode profile refuses before it starts a browser.
fn ensure_waiting(
    profile: &str,
    url: Option<&str>,
    headed: bool,
    direct_cdp: bool,
    timeout: Duration,
) -> Result<BrowserStatusResponse> {
    let deadline = Instant::now() + timeout;
    loop {
        match ensure_once(profile, url, headed, direct_cdp) {
            Ok(status) => return Ok(status),
            Err(ClientError::Protocol(e))
                if e.code == passless_core::agent::protocol::ErrorCode::Conflict
                    && Instant::now() < deadline =>
            {
                log::debug!("EnsureBrowser: {}; retrying", e.message);
                std::thread::sleep(WAIT_POLL);
            }
            Err(e) => return Err(Error::Other(e.to_string())),
        }
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

/// Whether the daemon ensured a pipe-mode browser: CDP only through `browser-control`.
fn is_pipe_mode(status: &BrowserStatusResponse) -> bool {
    status.cdp_exposure.as_deref() == Some("pipe")
}

/// The command that drives a pipe-mode browser of `profile`.
fn control_command(profile: &str) -> String {
    format!("passless agent browser-control --profile {profile} --request '<CDP JSON>'")
}

/// What `agent browser` prints for a pipe-mode browser: how to drive it (the daemon holds the CDP
/// pipes, so there is no endpoint), or the JSON envelope with `endpoint` null. `--env` has no
/// endpoint to put into a variable and is an error.
fn render_pipe_browser(
    profile: &str,
    status: &BrowserStatusResponse,
    flags: &BrowserFlags,
) -> Result<String> {
    if flags.env {
        return Err(Error::Other(format!(
            "profile '{profile}' uses browser_cdp_expose = \"pipe\": the browser is running, but \
             it has no CDP endpoint to export. Drive it with `{}`; tools that need an endpoint \
             (Playwright, chrome-devtools-mcp) need browser_cdp_expose = \"port\"",
            control_command(profile)
        )));
    }
    if flags.json {
        return serde_json::to_string(&serde_json::json!({
            "version": "1",
            "status": "ok",
            "data": BrowserOutput {
                endpoint: None,
                ws_endpoint: None,
                cdp_exposure: "pipe",
                control_command: Some(control_command(profile)),
                profile,
                status: &status.status,
                shared_browser_context: status.shared_browser_context.unwrap_or(false),
                interception: status.interception.as_deref().unwrap_or("unknown"),
                incognito_allowed: status.incognito_allowed.unwrap_or(false),
            },
        }))
        .map_err(|e| Error::Other(e.to_string()));
    }
    Ok(format!(
        "pipe mode: the browser is running ({}, interception: {}) and has no CDP endpoint; drive it \
         with `{}`",
        status.status,
        status.interception.as_deref().unwrap_or("unknown"),
        control_command(profile)
    ))
}

/// The text printed for the endpoint: the bare URL, `PASSLESS_CDP_URL=<url>`, or the JSON
/// envelope. A pipe-mode browser has no endpoint ([`render_pipe_browser`]).
fn render_browser(
    profile: &str,
    status: &BrowserStatusResponse,
    flags: &BrowserFlags,
) -> Result<String> {
    if is_pipe_mode(status) {
        return render_pipe_browser(profile, status, flags);
    }
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
                endpoint: Some(&endpoint),
                ws_endpoint: Some(ws),
                cdp_exposure: "port",
                control_command: None,
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
pub fn dispatch_browser(profile: Option<&str>, flags: &BrowserFlags) -> Result<()> {
    let profile = &resolve_profile(profile)?;
    if !in_principal_session(profile)? {
        // Not relaunched in a session of its own like the MCP adapters: the browser belongs to the
        // principal session and is closed when it ends, so a browser started here would die as
        // soon as this command printed its endpoint.
        return Err(Error::Other(format!(
            "`agent browser` must run inside a principal session of profile '{profile}' (the \
             browser belongs to that session and is closed when it ends): start your agent with \
             `passless agent run --profile {profile} -- <command>` and call this from it, or use \
             `passless agent mcp playwright|chrome-devtools`, which keep a session of their own"
        )));
    }
    let mut status = if flags.wait {
        ensure_waiting(
            profile,
            flags.url.as_deref(),
            flags.headed,
            false,
            WAIT_TIMEOUT,
        )?
    } else {
        ensure(profile, flags.url.as_deref(), flags.headed)?
    };
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

/// `npx` must be an executable regular file that nobody but its owner can write: the adapter runs
/// it with the principal's browser authority.
fn check_npx(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path)
        .map_err(|e| Error::Other(format!("npx '{}' is not usable: {e}", path.display())))?;
    if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
        return Err(Error::Other(format!(
            "npx '{}' is not an executable regular file",
            path.display()
        )));
    }
    if meta.permissions().mode() & 0o022 != 0 {
        return Err(Error::Other(format!(
            "npx '{}' is writable by group or others (mode {:o}); refusing to run it with browser \
             authority: fix its permissions or pass another --npx",
            path.display(),
            meta.permissions().mode() & 0o7777
        )));
    }
    Ok(())
}

fn resolve_npx(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        if !path.is_absolute() {
            return Err(Error::Other(format!(
                "--npx must be an absolute path, got '{}'",
                path.display()
            )));
        }
        check_npx(path)?;
        return Ok(path.to_path_buf());
    }
    let found = std::env::var_os("PATH")
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
        })?;
    check_npx(&found)?;
    Ok(found)
}

/// Put `dir` first in `command`'s `PATH` (the current `PATH` otherwise unchanged): `npx` starts
/// `node` by name, and a node installed next to it (nvm, fnm, a prefix) is not on the daemon's
/// `PATH`, which a principal session inherits.
pub(super) fn prepend_path_dir(command: &mut Command, dir: Option<&Path>) {
    let Some(dir) = dir.filter(|dir| dir.is_absolute()) else {
        return;
    };
    let mut paths = vec![dir.to_path_buf()];
    if let Some(existing) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&existing));
    }
    if let Ok(joined) = std::env::join_paths(paths) {
        command.env("PATH", joined);
    }
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
    command: &str,
) -> serde_json::Value {
    use serde_json::json;
    let (name, args) = entry_parts(profile, adapter);
    let stdio = json!({ "type": "stdio", "command": command, "args": args });
    match target {
        McpConfigTarget::ClaudeCode | McpConfigTarget::Cursor => {
            json!({ "mcpServers": { name: stdio } })
        }
        McpConfigTarget::Vscode => json!({ "servers": { name: stdio } }),
        McpConfigTarget::Opencode => {
            let mut argv = vec![command.to_string()];
            argv.extend(args);
            json!({
                "$schema": "https://opencode.ai/config.json",
                "mcp": { "servers": { name: { "type": "local", "command": argv } } }
            })
        }
    }
}

/// The command a printed MCP entry runs: the absolute, canonical path of this executable, so the
/// entry works from a client whose `PATH` does not include where passless was installed (a
/// `cargo install` goes to `~/.cargo/bin`, which GUI clients often lack). Falls back to the bare
/// name `passless` (found through the client's `PATH`) when the path is unknown, no longer exists
/// (a replaced binary reads as `... (deleted)`), is not valid UTF-8 or holds a quote that would
/// break the shell one-liner printed next to it.
pub(super) fn mcp_entry_command(current_exe: std::io::Result<PathBuf>) -> String {
    current_exe
        .and_then(std::fs::canonicalize)
        .ok()
        .and_then(|path| path.to_str().map(str::to_owned))
        .filter(|path| Path::new(path).is_absolute() && !path.contains(['\'', '"']))
        .unwrap_or_else(|| "passless".to_string())
}

/// `passless agent mcp --print-config <client>`.
fn print_config(
    profile: Option<&str>,
    target: McpConfigTarget,
    adapter: McpAdapterKind,
) -> Result<()> {
    // The entry names its profile explicitly, so it keeps working when more are added later.
    let profile = &resolve_profile(profile)?;
    let command = mcp_entry_command(std::env::current_exe());
    let config = render_client_config(target, profile, adapter, &command);
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
    if let Some(McpAdapter::Install {
        client,
        project,
        yes,
        skill,
        passless_path,
        ..
    }) = adapter
    {
        return super::agent_mcp_install::run(
            profile,
            &super::agent_mcp_install::InstallRequest {
                client: *client,
                project: project.as_deref(),
                yes: *yes,
                skill: *skill,
                passless_path: passless_path.as_deref(),
            },
        );
    }
    let Some(adapter) = adapter else {
        return Err(Error::Other(
            "choose an adapter (`agent mcp playwright` or `agent mcp chrome-devtools`) or pass \
             --print-config <claude-code|opencode|cursor|vscode>"
                .to_string(),
        ));
    };
    let profile = &resolve_profile(profile)?;
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
        McpAdapter::Install { .. } => unreachable!("handled above"),
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
    let status = wait_intercepting(
        profile,
        ensure_waiting(profile, url, false, true, WAIT_TIMEOUT)?,
    )?;
    let ws = status
        .cdp_endpoint
        .as_deref()
        .ok_or_else(|| Error::Other("the agent returned no CDP endpoint".into()))?;
    let endpoint = http_endpoint(ws)
        .ok_or_else(|| Error::Other("the agent returned a non-loopback CDP endpoint".into()))?;
    let args = chrome_devtools_args(&endpoint, extra);
    let command = npx_command(npx, package.unwrap_or(CHROME_DEVTOOLS_PACKAGE), &args);
    let mut child = Command::new(&command[0]);
    child.args(&command[1..]);
    prepend_path_dir(&mut child, command[0].parent());
    spawn_without_capability(&mut child);
    // The server is bound to this browser's websocket: when the browser is gone (closed, or its
    // owning session ended) the server would only fail every call, so it exits and the MCP
    // client restarts it, which ensures a browser again and passes the new URL.
    let addr = endpoint_addr(&endpoint);
    let mut misses = 0;
    super::playwright_mcp::supervise_watching(
        child,
        "chrome-devtools-mcp",
        &command[0],
        &mut || {
            let Some(addr) = addr else { return true };
            misses = if endpoint_alive(&addr) { 0 } else { misses + 1 };
            misses < 2
        },
    )
}

/// `--browserUrl <endpoint>`, telemetry off (Google collects usage statistics by default; an
/// MCP server started on a principal's behalf should not report), then the user's arguments,
/// which can still override it.
fn chrome_devtools_args(endpoint: &str, extra: &[String]) -> Vec<String> {
    let mut args = vec![
        "--browserUrl".to_string(),
        endpoint.to_string(),
        "--no-usage-statistics".to_string(),
    ];
    args.extend(extra.iter().cloned());
    args
}

fn endpoint_addr(endpoint: &str) -> Option<std::net::SocketAddr> {
    use std::net::ToSocketAddrs;
    let url = url::Url::parse(endpoint).ok()?;
    (url.host_str()?, url.port()?)
        .to_socket_addrs()
        .ok()?
        .next()
}

/// Whether something still accepts connections at the browser's debugging port.
fn endpoint_alive(addr: &std::net::SocketAddr) -> bool {
    std::net::TcpStream::connect_timeout(addr, Duration::from_secs(1)).is_ok()
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
            cdp_exposure: Some("port".into()),
        }
    }

    fn pipe_status() -> BrowserStatusResponse {
        BrowserStatusResponse {
            cdp_endpoint: None,
            cdp_exposure: Some("pipe".into()),
            ..status("attached", true)
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
            "ws://[::1]:9333/devtools/browser/abc",
            "ws://localhost:9333/devtools/browser/abc",
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
        assert_eq!(json["data"]["cdp_exposure"], "port");
        assert!(json["data"]["control_command"].is_null());
        let mut none = status.clone();
        none.cdp_endpoint = None;
        assert!(render_browser("p", &none, &flags(false, false)).is_err());
    }

    #[test]
    fn a_pipe_mode_browser_prints_how_to_drive_it_instead_of_an_endpoint() {
        let flags = |json, env| BrowserFlags {
            json,
            env,
            wait: false,
            headed: false,
            url: None,
        };
        let status = pipe_status();
        assert!(is_pipe_mode(&status));
        assert!(!is_pipe_mode(&self::status("attached", true)));

        let plain = render_browser("coding", &status, &flags(false, false)).unwrap();
        assert!(plain.contains("no CDP endpoint"), "{plain}");
        assert!(
            plain.contains("passless agent browser-control --profile coding"),
            "{plain}"
        );
        assert!(!plain.contains("http://"), "{plain}");

        let json: serde_json::Value =
            serde_json::from_str(&render_browser("coding", &status, &flags(true, false)).unwrap())
                .unwrap();
        assert_eq!(json["status"], "ok");
        assert!(json["data"]["endpoint"].is_null());
        assert!(json["data"]["ws_endpoint"].is_null());
        assert_eq!(json["data"]["cdp_exposure"], "pipe");
        assert!(
            json["data"]["control_command"]
                .as_str()
                .unwrap()
                .contains("browser-control --profile coding")
        );
        assert_eq!(json["data"]["interception"], "attached");

        // `--env` has nothing to export.
        let err = render_browser("coding", &status, &flags(false, true))
            .unwrap_err()
            .to_string();
        assert!(err.contains("no CDP endpoint to export"), "{err}");
        assert!(err.contains("browser-control"), "{err}");
    }

    #[test]
    fn only_an_attached_incognito_allowed_browser_is_intercepting() {
        assert!(is_intercepting(&status("attached", true)));
        assert!(!is_intercepting(&status("attached", false)));
        assert!(!is_intercepting(&status("degraded", true)));
        assert!(!is_intercepting(&status("pending", true)));
    }

    #[test]
    fn npx_must_be_an_executable_regular_file_nobody_else_can_write() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let npx = dir.path().join("npx");
        std::fs::write(&npx, "#!/bin/sh\n").unwrap();
        let mode = |m| std::fs::set_permissions(&npx, std::fs::Permissions::from_mode(m)).unwrap();
        mode(0o755);
        assert_eq!(resolve_npx(Some(&npx)).unwrap(), npx);
        for writable in [0o775, 0o757, 0o777] {
            mode(writable);
            let err = resolve_npx(Some(&npx)).unwrap_err().to_string();
            assert!(
                err.contains("writable by group or others"),
                "{writable:o}: {err}"
            );
        }
        mode(0o644);
        let err = resolve_npx(Some(&npx)).unwrap_err().to_string();
        assert!(err.contains("not an executable regular file"), "{err}");
        // A directory, and a missing file.
        assert!(resolve_npx(Some(dir.path())).is_err());
        assert!(resolve_npx(Some(&dir.path().join("absent"))).is_err());
        // A symlink to a good file is fine; the file's mode counts.
        mode(0o755);
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&npx, &link).unwrap();
        assert!(resolve_npx(Some(&link)).is_ok());
    }

    #[test]
    fn the_adapters_path_gets_npxs_directory_first() {
        let mut command = Command::new("/opt/node/bin/npx");
        prepend_path_dir(&mut command, Path::new("/opt/node/bin/npx").parent());
        let path = command
            .get_envs()
            .find(|(k, _)| *k == "PATH")
            .and_then(|(_, v)| v)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(path.starts_with("/opt/node/bin:"), "{path}");
        // A relative directory is ignored.
        let mut command = Command::new("npx");
        prepend_path_dir(&mut command, Some(Path::new("bin")));
        assert_eq!(command.get_envs().count(), 0);
    }

    #[test]
    fn chrome_devtools_runs_with_telemetry_off_and_user_arguments_last() {
        assert_eq!(
            chrome_devtools_args("http://127.0.0.1:9", &["--slim".into()]),
            [
                "--browserUrl",
                "http://127.0.0.1:9",
                "--no-usage-statistics",
                "--slim"
            ]
        );
    }

    #[test]
    fn the_browser_watch_sees_a_closed_port() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        assert!(endpoint_alive(&endpoint_addr(&endpoint).unwrap()));
        drop(listener);
        // Another test may take the freed port at once; a port nobody listens on exists soon.
        let dead = (0..20).any(|_| {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = probe.local_addr().unwrap();
            drop(probe);
            !endpoint_alive(&addr)
        });
        assert!(dead, "a closed port is reported as gone");
        assert_eq!(endpoint_addr("not a url"), None);
    }

    #[test]
    fn the_profile_defaults_to_the_only_one_or_the_session_s_own() {
        let one = vec!["coding".to_string()];
        assert_eq!(choose_profile(&one, &|_| false).unwrap(), "coding");
        let two = vec!["coding".to_string(), "review".to_string()];
        // Several profiles: the session's own is the one that accepts it.
        assert_eq!(choose_profile(&two, &|n| n == "review").unwrap(), "review");
        // Ambiguous (a plain shell, or accepted by both): an error naming the candidates.
        for accepts in [false, true] {
            let err = choose_profile(&two, &|_| accepts).unwrap_err().to_string();
            assert!(
                err.contains("coding, review") && err.contains("--profile"),
                "{err}"
            );
        }
        let err = choose_profile(&[], &|_| true).unwrap_err().to_string();
        assert!(err.contains("no agent profile"), "{err}");
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
    }

    #[test]
    fn client_configs_follow_each_clients_format() {
        use McpAdapterKind::{ChromeDevtools, Playwright};
        let args = ["agent", "mcp", "playwright", "--profile", "coding"];

        // Claude Code `.mcp.json`: `mcpServers`, stdio command and args.
        let claude = render_client_config(
            McpConfigTarget::ClaudeCode,
            "coding",
            Playwright,
            "passless",
        );
        let entry = &claude["mcpServers"]["passless-playwright"];
        assert_eq!(entry["type"], "stdio");
        assert_eq!(entry["command"], "passless");
        assert_eq!(entry["args"], serde_json::json!(args));

        // Cursor `.cursor/mcp.json`: the same shape.
        let cursor =
            render_client_config(McpConfigTarget::Cursor, "coding", Playwright, "passless");
        assert_eq!(cursor, claude);

        // VS Code `.vscode/mcp.json`: `servers`, not `mcpServers`.
        let vscode =
            render_client_config(McpConfigTarget::Vscode, "coding", Playwright, "passless");
        assert!(vscode.get("mcpServers").is_none());
        assert_eq!(vscode["servers"]["passless-playwright"]["type"], "stdio");
        assert_eq!(
            vscode["servers"]["passless-playwright"]["args"],
            serde_json::json!(args)
        );

        // opencode `opencode.json`: `mcp.servers.<name>` with a local command array.
        let opencode =
            render_client_config(McpConfigTarget::Opencode, "coding", Playwright, "passless");
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

        let devtools = render_client_config(
            McpConfigTarget::ClaudeCode,
            "coding",
            ChromeDevtools,
            "passless",
        );
        assert_eq!(
            devtools["mcpServers"]["passless-chrome-devtools"]["args"][2],
            "chrome-devtools"
        );
    }

    /// The printed entry names this executable by its absolute, canonical path.
    #[test]
    fn the_printed_entry_runs_the_absolute_path_of_this_executable() {
        use McpAdapterKind::Playwright;
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real-passless");
        std::fs::write(&real, b"").unwrap();
        let link = tmp.path().join("link-passless");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let canonical = std::fs::canonicalize(&real).unwrap();
        let canonical = canonical.to_str().unwrap();

        // A symlink resolves to the file; the entry carries it in every client's format.
        let command = mcp_entry_command(Ok(link));
        assert_eq!(command, canonical);
        let claude =
            render_client_config(McpConfigTarget::ClaudeCode, "coding", Playwright, &command);
        assert_eq!(
            claude["mcpServers"]["passless-playwright"]["command"],
            canonical
        );
        let opencode =
            render_client_config(McpConfigTarget::Opencode, "coding", Playwright, &command);
        assert_eq!(
            opencode["mcp"]["servers"]["passless-playwright"]["command"][0],
            canonical
        );

        // Unknown, vanished (a replaced binary) or shell-hostile paths fall back to the name.
        assert_eq!(
            mcp_entry_command(Err(std::io::Error::other("no /proc"))),
            "passless"
        );
        assert_eq!(
            mcp_entry_command(Ok(tmp.path().join("gone (deleted)"))),
            "passless"
        );
        let quoted = tmp.path().join("it's");
        std::fs::write(&quoted, b"").unwrap();
        assert_eq!(mcp_entry_command(Ok(quoted)), "passless");
        assert_eq!(mcp_entry_command(Ok(PathBuf::from("relative"))), "passless");
        // The running test binary resolves to an absolute path.
        assert!(Path::new(&mcp_entry_command(std::env::current_exe())).is_absolute());
    }
}
