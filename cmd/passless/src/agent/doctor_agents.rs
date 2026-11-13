//! `passless doctor --agents`: host checks for the agent browser path (ADR 0014 section 4.2 and
//! plan D4).
//!
//! It inspects the host and the configuration; it starts no browser, needs no running daemon for
//! the host checks and changes nothing outside a scratch directory it removes again. When agents
//! are configured enabled it also pings the daemon's admin socket (`agent_subsystem`) and fails
//! if the daemon is not serving them. Per profile: the browser binary
//! (supported and trusted for the profile's deployment) and the containment case of the browser's
//! user. Once: the interception extension and native messaging host manifest render and verify,
//! the notification bus answers, the state directory is private and the automatic-interaction
//! guard (R19). The daemon-side checks stay in `passless agent-admin profile check`.

use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use passless_core::agent::protocol::{AdminRequest, AdminResponse, DoctorCheck, ProtocolError};
use passless_core::agent::{AgentConfig, AgentProfileConfig};
use passless_core::{McpAdapterKind, McpInstallClient};

use super::browser::{self, ExtensionSelfCheck};
use super::browser_select::{self, BrowserLaunch};
use super::client::{AdminClient, ClientError, resolve_runtime_base};
use super::containment::{self, ContainmentCase, ContainmentPolicy, ContainmentReport};
use super::launcher::HardenedChildSetup;
use super::mcp_clients::{self, Kind, Roots, Scope, Target};
use super::prompt;

fn check(name: impl Into<String>, passed: bool, message: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        name: name.into(),
        passed,
        message: message.into(),
    }
}

/// The major version in a `--version` line such as `Chromium 156.0.8078.79 Arch Linux` or
/// `Google Chrome for Testing 155.0.8059.12`.
pub fn major_version(version_line: &str) -> Option<u64> {
    version_line.split_whitespace().find_map(|word| {
        word.split('.')
            .next()
            .and_then(|n| n.parse().ok())
            .filter(|_| word.contains('.'))
    })
}

/// The browser a profile would launch, or why none can be.
pub fn browser_binary_check(
    profile: &str,
    launch: Result<BrowserLaunch, String>,
    minimum_chrome_major: Option<u64>,
) -> DoctorCheck {
    let name = format!("{profile}: browser_binary");
    match launch {
        Err(why) => check(name, false, why),
        Ok(launch) => {
            let info = &launch.info;
            if !info.kind.is_supported() {
                return check(
                    name,
                    true,
                    format!(
                        "warning: {} is {}, which passless has not probed (Chromium and Chrome \
                         for Testing are supported)",
                        launch.executable.display(),
                        info.kind.label()
                    ),
                );
            }
            if let (Some(minimum), Some(found)) =
                (minimum_chrome_major, major_version(&info.version))
                && found < minimum
            {
                return check(
                    name,
                    false,
                    format!(
                        "{} is {} ({}), older than the Chrome {minimum} the interception \
                         extension needs (chrome.webAuthenticationProxy); install a newer one",
                        info.path.display(),
                        info.kind.label(),
                        info.version
                    ),
                );
            }
            check(
                name,
                true,
                format!(
                    "{} {} at {} (from {})",
                    info.kind.label(),
                    info.version,
                    info.path.display(),
                    launch.source.label()
                ),
            )
        }
    }
}

/// The extension and the native messaging host manifest, rendered into `scratch` and verified.
pub fn extension_checks(
    scratch: &Path,
    sign_proxy: Option<PathBuf>,
) -> (DoctorCheck, DoctorCheck, Option<u64>) {
    let Some(sign_proxy) = sign_proxy else {
        return (
            check("extension", false, "cannot locate the passless executable"),
            check(
                "native_host_manifest",
                false,
                "cannot locate the sign-proxy relay: the executable path is unknown",
            ),
            None,
        );
    };
    let relay_ok = fs::metadata(&sign_proxy)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0);
    let relay = if relay_ok {
        check(
            "native_host_manifest",
            true,
            format!(
                "the relay {} is installed; each launch writes the host manifest \
                 (rs.passless.sign_proxy) into the browser's own profile, never into ~/.config",
                sign_proxy.display()
            ),
        )
    } else {
        check(
            "native_host_manifest",
            false,
            format!(
                "the sign-proxy relay is missing or not executable at {}: reinstall passless so \
                 that sign-proxy sits next to the passless executable; without it the browser \
                 cannot reach the daemon and no launch is allowed",
                sign_proxy.display()
            ),
        )
    };
    match browser::extension_self_check(scratch, &sign_proxy) {
        Ok(ExtensionSelfCheck {
            id,
            minimum_chrome_major,
        }) => (
            check(
                "extension",
                true,
                format!(
                    "the interception extension renders and verifies (id {id}, needs Chrome {})",
                    minimum_chrome_major.map_or("?".to_string(), |m| m.to_string())
                ),
            ),
            relay,
            minimum_chrome_major,
        ),
        Err(why) => (check("extension", false, why), relay, None),
    }
}

fn dir_is_writable(dir: &Path) -> bool {
    nix::unistd::access(
        dir,
        nix::unistd::AccessFlags::W_OK | nix::unistd::AccessFlags::X_OK,
    )
    .is_ok()
}

/// The agent state directory (granted rules): present, a directory the daemon user owns, mode
/// 0700. A missing directory is created by the daemon at start, so it passes when its parent is
/// writable.
pub fn state_dir_check(dir: Option<&Path>, euid: u32) -> DoctorCheck {
    let Some(dir) = dir else {
        return check(
            "state_dir",
            false,
            "no agents.state_dir and no home directory to derive it from; set agents.state_dir",
        );
    };
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return check(
                    "state_dir",
                    false,
                    format!("{} is not a directory (or is a symlink)", dir.display()),
                );
            }
            let mode = meta.mode() & 0o7777;
            if meta.uid() != euid {
                return check(
                    "state_dir",
                    false,
                    format!(
                        "{} is owned by uid {}, not by the daemon user (uid {euid})",
                        dir.display(),
                        meta.uid()
                    ),
                );
            }
            if mode & 0o077 != 0 {
                return check(
                    "state_dir",
                    false,
                    format!(
                        "{} has mode {mode:o}: it holds the granted-rules store, so it must be \
                         0700 (chmod 700 {})",
                        dir.display(),
                        dir.display()
                    ),
                );
            }
            check(
                "state_dir",
                true,
                format!("{} is private (mode {mode:o})", dir.display()),
            )
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let parent = dir.ancestors().skip(1).find(|p| p.exists());
            match parent.map(|p| (p, fs::metadata(p))) {
                Some((p, Ok(meta))) if meta.is_dir() && dir_is_writable(p) => check(
                    "state_dir",
                    true,
                    format!(
                        "{} does not exist yet; the daemon creates it (0700)",
                        dir.display()
                    ),
                ),
                Some((p, _)) => check(
                    "state_dir",
                    false,
                    format!(
                        "{} does not exist and its nearest parent {} is not a directory this \
                         user can write to, so the daemon cannot create it",
                        dir.display(),
                        p.display()
                    ),
                ),
                None => check(
                    "state_dir",
                    false,
                    format!("{} cannot be created", dir.display()),
                ),
            }
        }
        Err(e) => check(
            "state_dir",
            false,
            format!("cannot inspect {}: {e}", dir.display()),
        ),
    }
}

/// R19: `PASSLESS_INTERACTION_MODE=automatic` with a same-user profile that has `allow` or
/// `request` rules.
pub fn interaction_mode_check(config: &AgentConfig, automatic: bool) -> DoctorCheck {
    match config.validate_human_path_interaction(automatic) {
        Ok(()) => check(
            "interaction_mode",
            true,
            if automatic {
                "PASSLESS_INTERACTION_MODE=automatic, acknowledged by \
                 agents.allow_automatic_human_path or no same-user profile exposed"
                    .to_string()
            } else {
                "the human authenticator's prompts are not auto-approved".to_string()
            },
        ),
        Err(e) => check("interaction_mode", false, e.to_string()),
    }
}

/// The result of the daemon's own configuration validation (`passless config check`) as checks:
/// a configuration the daemon would refuse to start with is a FAIL, a deprecation or an advisory
/// (a key without effect, a stale acknowledgement) is a warning.
pub fn config_checks(
    checked: passless_core::Result<crate::commands::config_check::Checked>,
) -> Vec<DoctorCheck> {
    match checked {
        Err(e) => vec![check(
            "config",
            false,
            format!(
                "the daemon would refuse to start: {}. Fix the configuration and run \
                 `passless config check` before restarting passless",
                e.format_cli()
            ),
        )],
        Ok(checked) => {
            let mut checks = vec![check("config", true, "the configuration validates")];
            checks.extend(
                checked
                    .warnings
                    .into_iter()
                    .map(|warning| check("config: warning", true, format!("warning: {warning}"))),
            );
            checks
        }
    }
}

/// The profile `agent mcp install` is suggested with: the only profile that exposes a CDP port.
fn suggested_profile(config: &AgentConfig) -> String {
    let ports: Vec<&String> = config
        .profiles
        .iter()
        .filter(|(_, profile)| {
            profile.browser_cdp_expose == Some(passless_core::agent::config::CdpExposeMode::Port)
        })
        .map(|(name, _)| name)
        .collect();
    match ports.as_slice() {
        [only] => (*only).clone(),
        _ => "<profile>".to_string(),
    }
}

fn scope_name(scope: &Scope) -> &'static str {
    match scope {
        Scope::User => "user",
        Scope::Project(_) => "project",
    }
}

fn adapter_package(adapter: McpAdapterKind) -> &'static str {
    match adapter {
        McpAdapterKind::Playwright => "@playwright/mcp",
        McpAdapterKind::ChromeDevtools => "chrome-devtools-mcp",
    }
}

/// MCP clients whose browser MCP server starts a browser of its own: passkeys in it reach the
/// human's authenticator and the agent policy never applies. A WARNING, not a failure: the
/// configuration is valid, it just bypasses Passless. Entries that run through
/// `passless agent mcp ...` are reported ok.
pub fn mcp_client_checks(config: &AgentConfig, roots: &Roots) -> Vec<DoctorCheck> {
    let targets = mcp_clients::doctor_targets(roots);
    let profile = suggested_profile(config);
    let mut checks = Vec::new();
    for target in &targets {
        checks.extend(mcp_target_checks(config, target, &profile, roots));
    }
    let no_entries = checks.is_empty();
    checks.extend(mcp_shadow_checks(roots, &profile));
    if no_entries {
        checks.push(check(
            "mcp_clients",
            true,
            format!(
                "no Playwright or chrome-devtools MCP entry in {} opencode / Claude Code \
                 configuration file(s) (user scope and the current directory)",
                targets.len()
            ),
        ));
    }
    checks
}

/// Whether a Claude Code local-scope project key is the working directory.
fn is_cwd(project: &str, roots: &Roots) -> bool {
    roots.cwd.as_deref().is_some_and(|cwd| {
        Path::new(project) == cwd
            || fs::canonicalize(cwd).is_ok_and(|real| real == Path::new(project))
    })
}

fn mcp_target_checks(
    config: &AgentConfig,
    target: &Target,
    profile: &str,
    roots: &Roots,
) -> Vec<DoctorCheck> {
    let client = mcp_clients::client_name(target.client);
    let path = target.path.display();
    let Ok(text) = fs::read_to_string(&target.path) else {
        return vec![check(
            format!("mcp_client: {client}/{}", scope_name(&target.scope)),
            true,
            format!("warning: cannot read {path}; its MCP entries were not checked"),
        )];
    };
    let root = match mcp_clients::parse_config(&text) {
        Ok((root, _)) => root,
        Err(e) => {
            return vec![check(
                format!("mcp_client: {client}/{}", scope_name(&target.scope)),
                true,
                format!("warning: {path} is {e}; its MCP entries were not checked"),
            )];
        }
    };
    let fix = if target.installable {
        format!(
            "Fix: {} (leave out --yes to preview the diff)",
            mcp_clients::install_command(target, profile)
        )
    } else {
        format!(
            "Fix: edit it by hand (`passless agent mcp --print-config {client}` prints the entry; \
             docs/agents/migration.md)"
        )
    };
    mcp_clients::find_entries(target.client, &root)
        .into_iter()
        .map(|found| {
            // A local-scope entry (`claude mcp add` without --scope) lives in the user-level file,
            // under the project it belongs to, and only applies in that project.
            let local = found.entry.local_project().map(|project| {
                format!(
                    " (local scope of project {project}, {})",
                    if is_cwd(project, roots) {
                        "which is the current directory: it applies here"
                    } else {
                        "not the current directory"
                    }
                )
            });
            let name = match found.entry.local_project() {
                Some(project) => {
                    format!("mcp_client: {client}/local[{project}]/{}", found.entry.name)
                }
                None => format!(
                    "mcp_client: {client}/{}/{}",
                    scope_name(&target.scope),
                    found.entry.name
                ),
            };
            let entry = &format!("'{}'{}", found.entry.name, local.unwrap_or_default());
            match found.kind {
                Kind::Plain(launch) => check(
                    name,
                    true,
                    format!(
                        "warning: {path}: entry {entry} starts its own browser ({} via {}): \
                         passkeys from this MCP reach your human authenticator, not the agent \
                         policy. {fix}",
                        adapter_package(launch.adapter),
                        launch.runner.label()
                    ),
                ),
                Kind::Unsupported { adapter, why } => check(
                    name,
                    true,
                    format!(
                        "warning: {path}: entry {entry} starts its own {} browser ({why}): \
                         passkeys from this MCP reach your human authenticator, not the agent \
                         policy. Fix: edit it by hand (docs/agents/migration.md)",
                        adapter_package(adapter)
                    ),
                ),
                Kind::Wrapped { profile, .. } => {
                    let problem = profile.as_deref().and_then(|p| match config.profiles.get(p) {
                        None => Some(format!("profile '{p}' is not configured")),
                        Some(cfg)
                            if cfg.browser_cdp_expose
                                != Some(passless_core::agent::config::CdpExposeMode::Port) =>
                        {
                            Some(format!(
                                "profile '{p}' is not browser_cdp_expose = \"port\", which the adapters need"
                            ))
                        }
                        Some(_) => None,
                    });
                    match problem {
                        Some(problem) => check(
                            name,
                            true,
                            format!("warning: {path}: entry {entry} runs through Passless, but {problem}"),
                        ),
                        None => check(
                            name,
                            true,
                            format!(
                                "{path}: entry {entry} runs through Passless{}",
                                profile
                                    .as_deref()
                                    .map(|p| format!(" (profile {p})"))
                                    .unwrap_or_default()
                            ),
                        ),
                    }
                }
                Kind::Other => unreachable!("find_entries drops other servers"),
            }
        })
        .collect()
}

/// A plain `playwright` server that overrides the user-level Passless one: Claude Code lets a
/// local-scope entry beat a project `.mcp.json` entry, which beats a user-scope one of the same
/// name; opencode merges a project `opencode.json` over the global one. The agent's tools then
/// start a browser of their own and the Passless entry is never used. A warning, not a failure.
fn mcp_shadow_checks(roots: &Roots, profile: &str) -> Vec<DoctorCheck> {
    use mcp_clients::{Shadow, ShadowScope, shell_word};

    let message = |shadow: &Shadow| {
        let (verb, what) = if shadow.certain {
            ("overrides", "")
        } else {
            (
                "may override",
                " (the precedence here is not certain: check which file your client reads)",
            )
        };
        let place = match shadow.scope {
            ShadowScope::Local => format!(
                "the local-scope entry of this project in {} ({})",
                shadow.file.display(),
                shadow.what
            ),
            ShadowScope::Project => format!("{} ({})", shadow.file.display(), shadow.what),
        };
        let mut entry = shadow.user_entry.clone();
        if let Some(map) = entry.as_object_mut() {
            map.entry("type").or_insert_with(|| "stdio".into());
        }
        let json = shell_word(&serde_json::to_string(&entry).unwrap_or_default());
        let fixes = match (shadow.client, shadow.scope) {
            (McpInstallClient::ClaudeCode, ShadowScope::Project) => format!(
                "Fix, one of: remove `playwright` from {file} (your own repo); override it for \
                 you only: `claude mcp add-json playwright --scope local {json}` (a shared repo \
                 you cannot change); or `passless agent mcp install --client claude-code \
                 --project . --profile {profile} --yes` (rewrites {file}; it writes your passless \
                 path and profile into the repo's file). Restart the Claude Code session \
                 afterwards (docs/agents/browser-tools.md)",
                file = shadow.file.display()
            ),
            (McpInstallClient::ClaudeCode, ShadowScope::Local) => format!(
                "Fix, one of: `claude mcp remove playwright --scope local` in this project; \
                 `claude mcp add-json playwright --scope local {json}` (replaces it); or \
                 `passless agent mcp install --client claude-code --user --profile {profile} \
                 --yes` (rewrites the local-scope entries too). Restart the Claude Code session \
                 afterwards (docs/agents/browser-tools.md)"
            ),
            (McpInstallClient::Opencode, _) => format!(
                "Fix, one of: remove `playwright` from {file}; or `passless agent mcp install \
                 --client opencode --project . --profile {profile} --yes`. Restart opencode \
                 afterwards (docs/agents/browser-tools.md)",
                file = shadow.file.display()
            ),
        };
        format!(
            "warning: {user} runs `playwright` through Passless, but {place} {verb} it{what}: \
             the agent gets a plain Playwright browser, not the managed one. {fixes}",
            user = shadow.user_file.display()
        )
    };
    mcp_clients::find_shadows(roots)
        .iter()
        .map(|shadow| {
            check(
                format!(
                    "mcp_shadow: {}/{}/playwright",
                    mcp_clients::client_name(shadow.client),
                    match shadow.scope {
                        ShadowScope::Local => "local",
                        ShadowScope::Project => "project",
                    }
                ),
                true,
                message(shadow),
            )
        })
        .collect()
}

/// The containment case of a profile's browser user (D6 layer 3).
pub fn containment_check(profile: &str, report: &ContainmentReport) -> DoctorCheck {
    let name = format!("{profile}: containment");
    let bwrap = match &report.bwrap {
        Ok(path) => format!("bwrap {}", path.display()),
        Err(why) => format!("no bwrap ({why})"),
    };
    let hidraw = match report.hidraw_accessible {
        Some(true) => "the browser user can open a hidraw node",
        Some(false) => "the browser user cannot open any hidraw node",
        None => "hidraw access could not be evaluated for the browser user from here",
    };
    let message = format!("{}: {bwrap}; {hidraw}", report.case);
    match report.case {
        ContainmentCase::Refused => check(
            name,
            false,
            format!(
                "{message}. Launches are refused: install bubblewrap (bwrap) and allow \
                 unprivileged user namespaces, or run the browser as a user that cannot open any \
                 hidraw device (browser_user)"
            ),
        ),
        _ => check(name, true, message),
    }
}

/// A profile's fixed `browser_cdp_port` (ADR 0014 section 4.3): a warning when another process
/// holds it on `127.0.0.1` now, as launches are then refused. A managed browser of passless
/// holding it (`managed`) is fine.
pub fn cdp_port_check(
    profile: &str,
    port: u16,
    holder: Option<&super::cdp_owner::PortHolder>,
    managed: bool,
) -> DoctorCheck {
    let name = format!("{profile}: browser_cdp_port");
    match holder {
        None => check(name, true, format!("{port} is free on 127.0.0.1")),
        Some(holder) if managed => check(
            name,
            true,
            format!(
                "{port} is held by a passless managed browser ({})",
                holder.description
            ),
        ),
        Some(holder) => check(
            name,
            true,
            format!(
                "warning: browser_cdp_port {port} on 127.0.0.1 is in use by {}; launches of \
                 this profile are refused while it is. Remove browser_cdp_port to use an \
                 ephemeral port (recommended), or choose a free one",
                holder.description
            ),
        ),
    }
}

/// The informational line for a profile that sets a fixed `browser_cdp_port`: no supported
/// integration needs one. Always passing, so it never makes the report unhealthy, and separate
/// from the occupied-port warning of [`cdp_port_check`].
pub fn cdp_port_hint_check(profile: &str, port: u16) -> DoctorCheck {
    check(
        format!("{profile}: fixed browser_cdp_port"),
        true,
        format!(
            "note: browser_cdp_port = {port} is not needed by any supported integration (the MCP \
             wrappers and `passless agent browser --env` find the endpoint themselves); leave it \
             unset so the browser picks an ephemeral port that cannot collide with other browsers"
        ),
    )
}

/// The checks for a profile's fixed `browser_cdp_port`, none when it sets none (or 0): the
/// informational hint, and in port mode the occupied-port check.
fn fixed_port_checks(profile_name: &str, profile: &AgentProfileConfig) -> Vec<DoctorCheck> {
    let Some(port) = profile.browser_cdp_port.filter(|port| *port > 0) else {
        return Vec::new();
    };
    let mut checks = Vec::new();
    if profile.browser_cdp_expose == Some(passless_core::agent::config::CdpExposeMode::Port) {
        let holder = super::cdp_owner::port_holder(port);
        let managed = holder
            .as_ref()
            .and_then(|h| h.pid)
            .is_some_and(|pid| is_managed_browser(pid, port));
        checks.push(cdp_port_check(profile_name, port, holder.as_ref(), managed));
    }
    checks.push(cdp_port_hint_check(profile_name, port));
    checks
}

/// Whether `pid` is a passless managed browser listening on `port`: started with that
/// `--remote-debugging-port` and a lease profile (`.../lease-<id>/profile`) as its user data dir.
fn is_managed_browser(pid: u32, port: u16) -> bool {
    let Ok(cmdline) = fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    let args: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
    let port_flag = format!("--remote-debugging-port={port}");
    args.contains(&port_flag.as_bytes())
        && args.iter().any(|a| {
            a.strip_prefix(b"--user-data-dir=".as_slice())
                .map(|dir| Path::new(std::ffi::OsStr::from_bytes(dir)))
                .is_some_and(|dir| {
                    dir.file_name().is_some_and(|n| n == "profile")
                        && dir
                            .parent()
                            .and_then(Path::file_name)
                            .and_then(|n| n.to_str())
                            .is_some_and(|n| n.starts_with("lease-"))
                })
        })
}

/// The notification server on the escalation bus (ADR 0014 section 8.2): the bus the daemon's
/// prompt child would use answers, and a server owns `org.freedesktop.Notifications` with the
/// `actions` capability (or is notify-osd 1.0, whose fallback dialogs have distinct buttons). Only
/// profiles with a `request` rule make it a failure.
pub fn notification_bus_check(config: &AgentConfig, euid: u32) -> DoctorCheck {
    let needs_prompt = config.profiles.values().any(|profile| {
        profile.rules.iter().any(|rule| {
            rule.authenticate == passless_core::agent::RuleAction::Request
                || rule.register == passless_core::agent::RuleAction::Request
        })
    });
    let own_bus = prompt::inherited_session_bus_address();
    let plan = prompt::plan_prompt_child(
        euid,
        config.notify_user.as_deref(),
        own_bus.as_deref(),
        &prompt::SystemUsers,
        &prompt::FsSockets,
    );
    let (passed_when_down, unavailable_prefix) = if needs_prompt {
        (false, "")
    } else {
        (true, "warning: ")
    };
    let plan = match plan {
        Ok(plan) => plan,
        Err(why) => {
            return check(
                "notification_bus",
                passed_when_down,
                format!(
                    "{unavailable_prefix}no usable session bus for escalation prompts: {why}; \
                     `request` rules are denied (escalation_unavailable) until it is fixed"
                ),
            );
        }
    };
    match probe_notification_server(&plan.bus_address) {
        Ok(server) => check(
            "notification_bus",
            true,
            format!("{} on {}", server, plan.bus_address),
        ),
        Err(why) => check(
            "notification_bus",
            passed_when_down,
            format!(
                "{unavailable_prefix}{why} (bus {}); `request` rules are denied until a \
                 notification server with action support runs there",
                plan.bus_address
            ),
        ),
    }
}

/// Connect to `address` and classify the notification server with the prompt child's capability
/// gate (`escalation_prompt::server_support`).
pub(crate) fn probe_notification_server(address: &str) -> Result<String, String> {
    use super::escalation_prompt::{ServerSupport, server_support};
    use zbus::connection::Builder;

    let address = address.to_string();
    let work = async move {
        let conn = Builder::address(address.as_str())
            .build()
            .await
            .map_err(|e| format!("cannot connect to the bus: {e}"))?;
        let owner: String = conn
            .call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                "GetNameOwner",
                &"org.freedesktop.Notifications",
            )
            .await
            .map_err(|_| "nothing owns org.freedesktop.Notifications".to_string())?
            .body()
            .deserialize()
            .map_err(|e| format!("bad GetNameOwner reply: {e}"))?;
        let capabilities: Vec<String> = conn
            .call_method(
                Some(owner.as_str()),
                "/org/freedesktop/Notifications",
                Some("org.freedesktop.Notifications"),
                "GetCapabilities",
                &(),
            )
            .await
            .map_err(|e| format!("GetCapabilities failed: {e}"))?
            .body()
            .deserialize()
            .map_err(|e| format!("bad GetCapabilities reply: {e}"))?;
        let (name, _vendor, version, _spec): (String, String, String, String) = conn
            .call_method(
                Some(owner.as_str()),
                "/org/freedesktop/Notifications",
                Some("org.freedesktop.Notifications"),
                "GetServerInformation",
                &(),
            )
            .await
            .map_err(|e| format!("GetServerInformation failed: {e}"))?
            .body()
            .deserialize()
            .map_err(|e| format!("bad GetServerInformation reply: {e}"))?;
        match server_support(&name, &version, &capabilities) {
            Ok(ServerSupport::Actions) => Ok(format!(
                "notification server {name} {version} supports actions"
            )),
            Ok(ServerSupport::FallbackDialog) => Ok(format!(
                "notification server {name} {version} has no `actions` capability; escalation \
                 prompts use its fallback dialogs (Allow always or Register once, and Deny, as buttons)"
            )),
            Err(why) => Err(format!("{why} ({name} {version})")),
        }
    };
    // Bounded: a stuck bus must not hang the doctor.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(zbus::block_on(work));
    });
    rx.recv_timeout(Duration::from_secs(8))
        .unwrap_or_else(|_| Err("the bus did not answer within 8 s".to_string()))
}

/// Ask the daemon's admin socket below `base` for a `Ping`, bounded in time: a daemon that
/// accepts and never answers must not hang the doctor.
pub fn probe_agent_subsystem(base: &Path) -> Result<(), ClientError> {
    let base = base.to_path_buf();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = AdminClient::connect(&base).and_then(|mut client| {
            match client.request(AdminRequest::Ping)? {
                AdminResponse::Pong => Ok(()),
                _ => Err(ClientError::Protocol(ProtocolError::malformed(
                    "unexpected reply to ping",
                ))),
            }
        });
        let _ = tx.send(result);
    });
    rx.recv_timeout(AGENT_PROBE_TIMEOUT)
        .unwrap_or(Err(ClientError::Timeout))
}

/// How long [`probe_agent_subsystem`] waits for the daemon.
const AGENT_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// The daemon side of an enabled agent configuration: its admin socket is there and answers. A
/// daemon that runs without agents (the subsystem failed to start, `agents.enabled` was edited
/// after the start) or does not run at all has no such socket, and every `agent-admin` and
/// `agent` command fails with "no agent socket"; the host checks above can all pass meanwhile.
/// A socket that exists but cannot be opened by this user (a root daemon) is not a failure of the
/// daemon, so that case is only a warning.
pub fn agent_subsystem_check(probe: Result<(), ClientError>) -> DoctorCheck {
    let name = "agent_subsystem";
    match probe {
        Ok(()) => check(
            name,
            true,
            "the daemon's agent subsystem answers on its admin socket",
        ),
        Err(ClientError::DaemonNotRunning { socket }) => check(
            name,
            false,
            format!(
                "agents are enabled, but nothing answers on the admin socket {}: the daemon is \
                 not running, or it runs without agents. Restart it (`systemctl --user restart \
                 passless`) and read its log for \"Agent subsystem failed to start\"; it cannot \
                 serve any agent request until then",
                socket.display()
            ),
        ),
        Err(ClientError::Timeout) => check(
            name,
            false,
            format!(
                "the daemon's admin socket accepted a connection but did not answer within {} s",
                AGENT_PROBE_TIMEOUT.as_secs()
            ),
        ),
        Err(ClientError::Io(e)) if e.kind() == std::io::ErrorKind::PermissionDenied => check(
            name,
            true,
            format!(
                "warning: this user cannot open the daemon's admin socket ({e}); run the doctor \
                 as the daemon's user to check that the agent subsystem answers"
            ),
        ),
        Err(other) => check(
            name,
            false,
            format!("the daemon's agent subsystem does not answer: {other}"),
        ),
    }
}

/// A fresh private directory under the temporary directory, removed on drop.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn create() -> std::io::Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let path =
            std::env::temp_dir().join(format!("passless-doctor-{}-{nanos}", std::process::id()));
        // `create` fails if the name exists (a planted symlink included), so nothing is reused.
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The profile's browser user: UID and GID.
struct BrowserIdentity {
    uid: u32,
    gid: u32,
}

fn browser_identity(profile: &AgentProfileConfig, daemon: (u32, u32)) -> BrowserIdentity {
    let port =
        profile.browser_cdp_expose == Some(passless_core::agent::config::CdpExposeMode::Port);
    let by_name = |name: &str| {
        nix::unistd::User::from_name(name)
            .ok()
            .flatten()
            .map(|user| (user.uid.as_raw(), user.gid.as_raw()))
    };
    // The runtime's rule: the browser user when set, else (trusted port mode) the principal,
    // else the daemon.
    let chosen = profile
        .browser_user
        .as_deref()
        .and_then(by_name)
        .or_else(|| port.then(|| by_name(&profile.principal_user)).flatten());
    let (uid, gid) = chosen.unwrap_or(daemon);
    BrowserIdentity { uid, gid }
}

/// All the `--agents` checks for `config`, in order: the global ones, then each profile's.
/// `human` locates the human credential store for the pin checks of same-user profiles.
pub fn run(
    config: &AgentConfig,
    human: Option<&super::doctor_pins::HumanStore>,
) -> Vec<DoctorCheck> {
    // SAFETY: no preconditions.
    let (euid, egid) = unsafe { (libc::geteuid(), libc::getegid()) };
    let mut checks = Vec::new();

    if config.profiles.is_empty() {
        checks.push(check(
            "agents",
            false,
            "no agent profiles are configured ([agents.profiles.<name>])",
        ));
    }

    // Agents enabled and profiles configured: the daemon must be serving them. The host checks
    // below need no daemon, but a daemon without its agent subsystem is not a healthy setup.
    if config.enabled && !config.profiles.is_empty() {
        checks.push(match resolve_runtime_base() {
            Ok(base) => agent_subsystem_check(probe_agent_subsystem(&base)),
            Err(e) => check("agent_subsystem", false, e.to_string()),
        });
    }

    // Extension and host manifest, rendered into a scratch directory that is removed again.
    let (extension, native_host, minimum_chrome) = match ScratchDir::create() {
        Ok(dir) => extension_checks(dir.path(), browser::installed_sign_proxy_path()),
        Err(e) => (
            check(
                "extension",
                false,
                format!("cannot create a scratch directory: {e}"),
            ),
            check(
                "native_host_manifest",
                false,
                "skipped: no scratch directory",
            ),
            None,
        ),
    };

    for (name, profile) in &config.profiles {
        let identity = browser_identity(profile, (euid, egid));
        let principal_uid = nix::unistd::User::from_name(&profile.principal_user)
            .ok()
            .flatten()
            .map_or(euid, |user| user.uid.as_raw());
        let home = browser_select::home_dir_of_uid(identity.uid);
        let launch = browser_select::resolve_launch(
            profile.browser_command.as_deref(),
            config.browser_path.as_deref(),
            home.as_deref(),
            principal_uid != euid,
            false,
            &browser_select::run_version,
        )
        .map_err(|e| e.to_string());
        checks.push(browser_binary_check(name, launch, minimum_chrome));
        let setup = HardenedChildSetup {
            target_uid: identity.uid,
            target_gid: identity.gid,
            daemon_uid: euid,
            daemon_gid: egid,
            rlimit_nofile: 8192,
            rlimit_nproc: 4096,
            rlimit_core: 0,
            rlimit_as: libc::RLIM_INFINITY,
            bind_parent_death: true,
        };
        // The same-UID port-mode browser skips the privilege drop, as the launcher does.
        let trusted_same_user = identity.uid == euid && identity.gid == egid;
        let report = containment::assess(&ContainmentPolicy::Auto, &setup, trusted_same_user);
        checks.push(containment_check(name, &report));
        checks.extend(fixed_port_checks(name, profile));
    }

    checks.push(extension);
    checks.push(native_host);
    checks.push(notification_bus_check(config, euid));
    checks.push(state_dir_check(
        config.effective_state_dir(euid).as_deref(),
        euid,
    ));
    // Granted rules no rule can reach any more, and stores of profiles that are gone.
    checks.extend(super::doctor_grants::run(config, euid, human));
    checks.push(interaction_mode_check(
        config,
        std::env::var("PASSLESS_INTERACTION_MODE")
            .is_ok_and(|mode| mode.eq_ignore_ascii_case("automatic")),
    ));
    // MCP clients that start a browser of their own bypass the agent policy.
    checks.extend(mcp_client_checks(config, &Roots::from_process()));
    checks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::browser_select::{BrowserInfo, BrowserKind, Source};

    fn launch(kind: BrowserKind, version: &str) -> BrowserLaunch {
        BrowserLaunch {
            executable: PathBuf::from("/opt/b/chrome"),
            extra_args: vec!["--headless=new".into()],
            info: BrowserInfo {
                path: PathBuf::from("/opt/b/chrome"),
                kind,
                version: version.into(),
            },
            source: Source::PlaywrightChromium,
        }
    }

    #[test]
    fn versions_parse_to_a_major() {
        assert_eq!(
            major_version("Chromium 156.0.8078.79 Arch Linux"),
            Some(156)
        );
        assert_eq!(
            major_version("Google Chrome for Testing 155.0.8059.12 "),
            Some(155)
        );
        assert_eq!(major_version("Chromium"), None);
        assert_eq!(major_version(""), None);
    }

    #[test]
    fn the_browser_check_reports_kind_version_and_source_and_the_extension_minimum() {
        let ok = browser_binary_check(
            "coding",
            Ok(launch(
                BrowserKind::ChromeForTesting,
                "Google Chrome for Testing 155.0.8059.12",
            )),
            Some(116),
        );
        assert!(ok.passed, "{ok:?}");
        assert_eq!(ok.name, "coding: browser_binary");
        assert!(ok.message.contains("Chrome for Testing"), "{ok:?}");
        assert!(ok.message.contains("Playwright Chromium"), "{ok:?}");

        let old = browser_binary_check(
            "coding",
            Ok(launch(BrowserKind::Chromium, "Chromium 110.0.1.2")),
            Some(116),
        );
        assert!(!old.passed, "{old:?}");
        assert!(old.message.contains("older than the Chrome 116"), "{old:?}");

        let none = browser_binary_check("coding", Err("no supported browser found".into()), None);
        assert!(!none.passed);

        let unknown = browser_binary_check(
            "coding",
            Ok(launch(BrowserKind::Unknown, "Brave Browser 1.90")),
            Some(116),
        );
        assert!(
            unknown.passed && unknown.message.starts_with("warning:"),
            "{unknown:?}"
        );
    }

    /// Waits until nothing listens on `port` any more, and returns the last holder seen.
    ///
    /// Dropping a `TcpListener` does not free the port while a forked child still has a copy of the
    /// descriptor: the unit tests share one process with tests that spawn children, and a child
    /// forked just before the drop keeps the socket listening until its `exec` closes it
    /// (`CLOEXEC`). That is a window of a few milliseconds, longer on a loaded runner. A forked
    /// child may also show up as the holder instead of this process, or vanish between the table
    /// read and the descriptor scan, so only the free state is asserted against, after this wait.
    fn wait_until_free(port: u16) -> Option<crate::agent::cdp_owner::PortHolder> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let holder = crate::agent::cdp_owner::port_holder(port);
            if holder.is_none() || std::time::Instant::now() >= deadline {
                return holder;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// A fixed CDP port held by another process is a warning that names the holder and the fix;
    /// a free one, or one held by a managed browser, is fine.
    #[test]
    fn the_cdp_port_check_warns_about_a_held_fixed_port() {
        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = held.local_addr().unwrap().port();
        let holder = crate::agent::cdp_owner::port_holder(port).expect("held");
        assert!(!is_managed_browser(std::process::id(), port));
        let warn = cdp_port_check("coding", port, Some(&holder), false);
        assert!(
            warn.passed && warn.message.starts_with("warning:"),
            "{warn:?}"
        );
        // The holder is this process, or a child forked while the listener was open, or only its
        // UID when the descriptor table could not be read: never nobody.
        assert!(
            warn.message.contains(&holder.description)
                && (holder.description.contains("pid ")
                    || holder.description.starts_with("a process of uid ")),
            "{warn:?}"
        );
        assert!(
            warn.message
                .contains(&format!("browser_cdp_port {port} on 127.0.0.1")),
            "{warn:?}"
        );
        assert!(warn.message.contains("Remove browser_cdp_port"), "{warn:?}");
        let ours = cdp_port_check("coding", port, Some(&holder), true);
        assert!(!ours.message.starts_with("warning:"), "{ours:?}");
        drop(held);
        let free = cdp_port_check("coding", port, wait_until_free(port).as_ref(), false);
        assert!(free.passed && free.message.contains("is free"), "{free:?}");
    }

    /// A fixed port gets one informational line; it passes (so it cannot make the status
    /// unhealthy) and is not the warning.
    #[test]
    fn the_cdp_port_hint_is_informational_and_never_unhealthy() {
        let hint = cdp_port_hint_check("coding", 9222);
        assert_eq!(hint.name, "coding: fixed browser_cdp_port");
        assert!(hint.passed, "{hint:?}");
        assert!(hint.message.starts_with("note:"), "{hint:?}");
        assert!(!hint.message.starts_with("warning:"), "{hint:?}");
        assert!(hint.message.contains("9222"), "{hint:?}");
        assert!(hint.message.contains("agent browser --env"), "{hint:?}");
        assert!(hint.message.contains("leave it unset"), "{hint:?}");
        // The held-port warning stays a distinct line.
        let free = cdp_port_check("coding", 9222, None, false);
        assert!(!free.message.contains("unset"), "{free:?}");
    }

    fn profile_with(port: Option<u16>) -> AgentProfileConfig {
        let port = port
            .map(|port| format!("browser_cdp_port = {port}\n"))
            .unwrap_or_default();
        toml::from_str(&format!(
            "mode = \"same-user\"\nprincipal_user = \"agent\"\nbrowser_cdp_expose = \"port\"\n{port}"
        ))
        .unwrap()
    }

    /// The hint is there when a port is set, absent when it is not, and the report's status
    /// (every check passes) is the same either way.
    #[test]
    fn the_cdp_port_hint_appears_only_for_a_fixed_port_and_keeps_the_status() {
        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = held.local_addr().unwrap().port();
        let hinted = |checks: &[DoctorCheck]| {
            checks
                .iter()
                .filter(|c| c.name == "coding: fixed browser_cdp_port")
                .count()
        };
        let healthy = |checks: &[DoctorCheck]| checks.iter().all(|c| c.passed);

        let unset = fixed_port_checks("coding", &profile_with(None));
        assert!(unset.is_empty(), "{unset:?}");
        assert!(healthy(&unset));
        let zero = fixed_port_checks("coding", &profile_with(Some(0)));
        assert!(zero.is_empty(), "{zero:?}");

        // A port another process holds: the warning and, separately, the hint. Both pass.
        let set = fixed_port_checks("coding", &profile_with(Some(port)));
        assert_eq!(hinted(&set), 1, "{set:?}");
        assert_eq!(set.len(), 2, "{set:?}");
        assert!(
            set.iter().any(|c| c.message.starts_with("warning:")),
            "{set:?}"
        );
        assert!(healthy(&set), "{set:?}");
        let hint = set.iter().find(|c| c.message.starts_with("note:")).unwrap();
        assert!(!hint.message.starts_with("warning:"), "{hint:?}");

        // A free port: the plain check plus the hint, no warning.
        drop(held);
        assert!(wait_until_free(port).is_none(), "port {port} stayed held");
        let free = fixed_port_checks("coding", &profile_with(Some(port)));
        assert_eq!(hinted(&free), 1, "{free:?}");
        assert!(
            free.iter().all(|c| !c.message.starts_with("warning:")),
            "{free:?}"
        );
        assert!(healthy(&free), "{free:?}");
    }

    #[test]
    fn the_containment_check_fails_only_when_launches_are_refused() {
        let report = |case, accessible| ContainmentReport {
            case,
            bwrap: Err("not installed".into()),
            hidraw_accessible: accessible,
        };
        let refused = containment_check("p", &report(ContainmentCase::Refused, Some(true)));
        assert!(!refused.passed, "{refused:?}");
        assert!(
            refused.message.contains("Launches are refused"),
            "{refused:?}"
        );
        for case in [
            ContainmentCase::RequiredInPlace,
            ContainmentCase::DefenceInDepth,
            ContainmentCase::NotRequired,
        ] {
            let ok = containment_check("p", &report(case, Some(false)));
            assert!(ok.passed, "{ok:?}");
            assert!(ok.message.starts_with(case.as_str()), "{ok:?}");
        }
    }

    #[test]
    fn the_state_dir_check_wants_a_private_directory_the_daemon_owns() {
        let tmp = tempfile::tempdir().unwrap();
        let euid = unsafe { libc::geteuid() };
        let dir = tmp.path().join("state");
        // Missing: passes when the daemon can create it.
        let missing = state_dir_check(Some(&dir), euid);
        assert!(missing.passed, "{missing:?}");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let open = state_dir_check(Some(&dir), euid);
        assert!(!open.passed, "{open:?}");
        assert!(open.message.contains("chmod 700"), "{open:?}");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(state_dir_check(Some(&dir), euid).passed);
        // Another owner is refused (as if the daemon ran as someone else).
        assert!(!state_dir_check(Some(&dir), euid.wrapping_add(1)).passed);
        // A file or a symlink in the way.
        let file = tmp.path().join("file");
        fs::write(&file, "x").unwrap();
        assert!(!state_dir_check(Some(&file), euid).passed);
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert!(!state_dir_check(Some(&link), euid).passed);
        assert!(!state_dir_check(None, euid).passed);
    }

    #[test]
    fn the_agent_subsystem_check_fails_when_the_admin_socket_is_absent_or_silent() {
        let ok = agent_subsystem_check(Ok(()));
        assert!(ok.passed, "{ok:?}");
        assert_eq!(ok.name, "agent_subsystem");

        let absent = agent_subsystem_check(Err(ClientError::DaemonNotRunning {
            socket: PathBuf::from("/run/user/1000/agent/admin/admin.sock"),
        }));
        assert!(!absent.passed, "{absent:?}");
        assert!(
            absent.message.contains("Agent subsystem failed to start"),
            "{absent:?}"
        );
        assert!(absent.message.contains("admin.sock"), "{absent:?}");

        let silent = agent_subsystem_check(Err(ClientError::Timeout));
        assert!(!silent.passed, "{silent:?}");
        assert!(silent.message.contains("did not answer"), "{silent:?}");

        let other = agent_subsystem_check(Err(ClientError::UnsafePath {
            detail: "mode is 755".into(),
        }));
        assert!(!other.passed, "{other:?}");

        // A root daemon's socket this user cannot open is not the daemon's failure.
        let denied = agent_subsystem_check(Err(ClientError::Io(std::io::Error::from(
            std::io::ErrorKind::PermissionDenied,
        ))));
        assert!(
            denied.passed && denied.message.starts_with("warning:"),
            "{denied:?}"
        );
    }

    struct PongHandler;

    impl crate::agent::ipc::AdminHandler for PongHandler {
        fn handle_admin(
            &self,
            _request: &AdminRequest,
            _cred: &passless_core::agent::PeerCred,
            _ctx: &crate::agent::ipc::AdminRequestContext,
        ) -> Result<AdminResponse, ProtocolError> {
            Ok(AdminResponse::Pong)
        }
    }

    /// The probe against a daemon-less directory (the defect: doctor said healthy) and against a
    /// real admin socket of a live server.
    #[test]
    fn the_probe_tells_a_missing_daemon_from_a_serving_one() {
        use std::collections::BTreeMap;
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;

        use crate::agent::ipc::{IpcServer, RuntimeDir};

        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("agent");
        let missing = agent_subsystem_check(probe_agent_subsystem(&base));
        assert!(!missing.passed, "{missing:?}");

        // SAFETY: no preconditions.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let runtime_dir = RuntimeDir::create(&base, uid, gid, &BTreeMap::new()).unwrap();
        let server = Arc::new(
            IpcServer::bind(
                runtime_dir,
                BTreeMap::new(),
                Arc::new(AtomicBool::new(false)),
                PathBuf::from("/proc"),
            )
            .unwrap(),
        );
        let serving = Arc::clone(&server);
        let handle = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while std::time::Instant::now() < deadline {
                match serving.accept_admin_connection() {
                    Ok(Some(fd)) => {
                        let _ = serving.handle_one_admin(fd, &PongHandler);
                        return;
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                    Err(_) => return,
                }
            }
        });
        let alive = agent_subsystem_check(probe_agent_subsystem(&base));
        assert!(alive.passed, "{alive:?}");
        handle.join().unwrap();

        // A listener that accepts into the backlog and never answers: reported, not hung.
        let silent = agent_subsystem_check(probe_agent_subsystem(&base));
        assert!(!silent.passed, "{silent:?}");
        assert!(silent.message.contains("did not answer"), "{silent:?}");
    }

    fn mcp_roots(cwd: &Path, claude: Option<&Path>) -> Roots {
        Roots {
            home: Some(cwd.join("no-home")),
            claude_config_dir: claude.map(Path::to_path_buf),
            cwd: Some(cwd.to_path_buf()),
            ..Roots::default()
        }
    }

    fn port_config() -> AgentConfig {
        toml::from_str(
            r#"
            enabled = true
            [profiles.agent]
            mode = "same-user"
            principal_user = "agent"
            browser_cdp_expose = "port"
            "#,
        )
        .unwrap()
    }

    #[test]
    fn a_plain_playwright_mcp_is_a_warning_with_the_exact_fix() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(".mcp.json"),
            r#"{"mcpServers": {"playwright": {"command": "pnpm", "args": ["dlx", "@playwright/mcp@0.0.83", "--isolated"]}, "other": {"command": "bash", "args": ["x.sh"]}}}"#,
        )
        .unwrap();
        let checks = mcp_client_checks(&port_config(), &mcp_roots(dir.path(), None));
        assert_eq!(checks.len(), 1, "{checks:?}");
        let check = &checks[0];
        assert!(check.passed, "a warning is not a failure: {check:?}");
        assert!(check.message.starts_with("warning:"), "{check:?}");
        assert!(
            check.message.contains(
                "passkeys from this MCP reach your human authenticator, not the agent policy"
            ),
            "{check:?}"
        );
        assert!(check.message.contains("pnpm dlx"), "{check:?}");
        let fix = format!(
            "passless agent mcp install --client claude-code --project {} --profile agent --yes",
            dir.path().display()
        );
        assert!(check.message.contains(&fix), "{check:?}");
    }

    #[test]
    fn opencode_and_the_claude_config_dir_are_scanned_too() {
        let dir = tempfile::tempdir().unwrap();
        let claude = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("opencode.json"),
            r#"{"mcp": {"servers": {"pw": {"type": "local", "command": ["/usr/bin/npx", "-y", "@playwright/mcp@latest"]}}}}"#,
        )
        .unwrap();
        fs::write(
            claude.path().join(".claude.json"),
            r#"{"mcpServers": {"devtools": {"command": "npx", "args": ["-y", "chrome-devtools-mcp@latest"]}}}"#,
        )
        .unwrap();
        let checks = mcp_client_checks(&port_config(), &mcp_roots(dir.path(), Some(claude.path())));
        assert_eq!(checks.len(), 2, "{checks:?}");
        let by_name = |name: &str| checks.iter().find(|c| c.name.contains(name)).unwrap();
        assert!(
            by_name("claude-code/user/devtools")
                .message
                .contains("chrome-devtools-mcp")
        );
        assert!(
            by_name("claude-code/user/devtools")
                .message
                .contains("--client claude-code --user --profile agent --yes")
        );
        assert!(
            by_name("opencode/project/pw")
                .message
                .contains("@playwright/mcp via npx")
        );
    }

    #[test]
    fn wrapped_entries_are_ok_and_a_missing_profile_is_a_warning() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(".mcp.json"),
            r#"{"mcpServers": {
                "playwright": {"command": "/usr/bin/passless", "args": ["agent", "mcp", "playwright", "--profile", "agent"]},
                "devtools": {"command": "/usr/bin/passless", "args": ["agent", "mcp", "chrome-devtools", "--profile", "gone"]}
            }}"#,
        )
        .unwrap();
        let checks = mcp_client_checks(&port_config(), &mcp_roots(dir.path(), None));
        let ok = checks
            .iter()
            .find(|c| c.name.ends_with("/playwright"))
            .unwrap();
        assert!(ok.passed && !ok.message.starts_with("warning:"), "{ok:?}");
        assert!(
            ok.message.contains("runs through Passless (profile agent)"),
            "{ok:?}"
        );
        let gone = checks
            .iter()
            .find(|c| c.name.ends_with("/devtools"))
            .unwrap();
        assert!(
            gone.passed
                && gone.message.starts_with("warning:")
                && gone.message.contains("'gone' is not configured"),
            "{gone:?}"
        );
    }

    #[test]
    fn without_browser_entries_one_ok_check_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let checks = mcp_client_checks(&port_config(), &mcp_roots(dir.path(), None));
        assert_eq!(checks.len(), 1);
        assert!(
            checks[0].passed
                && checks[0].name == "mcp_clients"
                && !checks[0].message.starts_with("warning:")
        );
        // An unparseable file is reported, not fatal.
        fs::write(dir.path().join(".mcp.json"), "{ nope").unwrap();
        let checks = mcp_client_checks(&port_config(), &mcp_roots(dir.path(), None));
        assert!(
            checks[0].passed && checks[0].message.starts_with("warning:"),
            "{checks:?}"
        );
    }

    #[test]
    fn the_fix_names_a_placeholder_when_the_profile_is_ambiguous() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(".mcp.json"),
            r#"{"mcpServers": {"pw": {"command": "npx", "args": ["@playwright/mcp"]}}}"#,
        )
        .unwrap();
        let two: AgentConfig = toml::from_str(
            r#"
            enabled = true
            [profiles.a]
            mode = "same-user"
            principal_user = "agent"
            browser_cdp_expose = "port"
            [profiles.b]
            mode = "same-user"
            principal_user = "agent"
            browser_cdp_expose = "port"
            "#,
        )
        .unwrap();
        let checks = mcp_client_checks(&two, &mcp_roots(dir.path(), None));
        assert!(
            checks[0].message.contains("--profile <profile> --yes"),
            "{checks:?}"
        );
    }

    #[test]
    fn the_interaction_mode_check_flags_the_automatic_human_path() {
        let toml = |extra: &str| -> AgentConfig {
            toml::from_str(&format!(
                r#"
                enabled = true
                {extra}
                [profiles.p]
                mode = "same-user"
                principal_user = "agent"
                [[profiles.p.rules]]
                rp_id = "example.com"
                authenticate = "allow"
                register = "deny"
                "#
            ))
            .unwrap()
        };
        let config = toml("");
        assert!(interaction_mode_check(&config, false).passed);
        let flagged = interaction_mode_check(&config, true);
        assert!(!flagged.passed, "{flagged:?}");
        assert!(
            flagged.message.contains("allow_automatic_human_path"),
            "{flagged:?}"
        );
        assert!(interaction_mode_check(&toml("allow_automatic_human_path = true"), true).passed);
    }

    #[test]
    fn the_extension_and_host_manifest_render_and_a_missing_relay_fails() {
        let scratch = tempfile::tempdir().unwrap();
        let relay = scratch.path().join("sign-proxy");
        fs::write(&relay, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&relay, fs::Permissions::from_mode(0o755)).unwrap();
        let work = scratch.path().join("work");
        fs::create_dir(&work).unwrap();
        fs::set_permissions(&work, fs::Permissions::from_mode(0o700)).unwrap();
        let (extension, native_host, minimum) = extension_checks(&work, Some(relay.clone()));
        assert!(extension.passed, "{extension:?}");
        assert!(
            extension.message.contains(browser::AGENT_EXTENSION_ID),
            "{extension:?}"
        );
        assert!(native_host.passed, "{native_host:?}");
        assert_eq!(minimum, Some(116));

        let work = scratch.path().join("work2");
        fs::create_dir(&work).unwrap();
        fs::set_permissions(&work, fs::Permissions::from_mode(0o700)).unwrap();
        let (_, native_host, _) = extension_checks(&work, Some(scratch.path().join("absent")));
        assert!(!native_host.passed, "{native_host:?}");
        assert!(
            native_host.message.contains("reinstall passless"),
            "{native_host:?}"
        );
        let (extension, native_host, _) = extension_checks(&work, None);
        assert!(!extension.passed && !native_host.passed);
    }

    #[test]
    fn the_notification_bus_check_reports_a_dead_bus_as_a_warning_without_request_rules() {
        // SAFETY: geteuid has no preconditions.
        let euid = unsafe { libc::geteuid() };
        let mut config = AgentConfig::default();
        // No bus can be planned for a root daemon without notify_user, nor reached at a bogus
        // address; either way nothing here may panic or hang, and with no request rule it only
        // warns.
        let result = probe_notification_server("unix:path=/nonexistent/passless-doctor-bus");
        assert!(result.is_err());
        config.notify_user = None;
        let check = notification_bus_check(&config, euid);
        assert_eq!(check.name, "notification_bus");
        if !check.passed {
            panic!("no request rule: must not fail: {check:?}");
        }
    }

    #[test]
    fn a_plain_local_scope_entry_is_reported_with_its_project() {
        // `claude mcp add playwright ...` without --scope: `projects.<path>.mcpServers`, in the
        // user-level file. `install --user` rewrites it; the doctor says whether it applies here.
        let dir = tempfile::tempdir().unwrap();
        let claude = dir.path().join("claude");
        fs::create_dir_all(&claude).unwrap();
        let here = dir.path().to_string_lossy().into_owned();
        fs::write(
            claude.join(".claude.json"),
            format!(
                r#"{{"projects": {{
                    "{here}": {{"mcpServers": {{"playwright": {{"type": "stdio", "command": "npx", "args": ["@playwright/mcp@latest"]}}}}}},
                    "/elsewhere": {{"mcpServers": {{"playwright": {{"type": "stdio", "command": "npx", "args": ["@playwright/mcp@latest"]}}}}}}
                }}}}"#
            ),
        )
        .unwrap();
        let checks = mcp_client_checks(&port_config(), &mcp_roots(dir.path(), Some(&claude)));
        assert_eq!(checks.len(), 2, "{checks:?}");
        let here_check = checks
            .iter()
            .find(|c| c.name == format!("mcp_client: claude-code/local[{here}]/playwright"))
            .unwrap();
        assert!(here_check.passed && here_check.message.starts_with("warning: "));
        assert!(
            here_check.message.contains("applies here"),
            "{here_check:?}"
        );
        assert!(
            here_check
                .message
                .contains("passless agent mcp install --client claude-code --user"),
            "{here_check:?}"
        );
        let other = checks
            .iter()
            .find(|c| c.name.contains("/elsewhere"))
            .unwrap();
        assert!(
            other.message.contains("not the current directory"),
            "{other:?}"
        );
    }

    const USER_PASSLESS: &str = r#"{"mcpServers": {"playwright": {"type": "stdio", "command": "/usr/bin/passless", "args": ["agent", "mcp", "playwright", "--profile", "agent"]}}}"#;

    #[test]
    fn a_plain_project_entry_that_shadows_the_user_level_passless_one_is_a_warning() {
        let dir = tempfile::tempdir().unwrap();
        let claude = dir.path().join("claude");
        fs::create_dir_all(&claude).unwrap();
        fs::write(claude.join(".claude.json"), USER_PASSLESS).unwrap();
        fs::write(
            dir.path().join(".mcp.json"),
            r#"{"mcpServers": {"playwright": {"command": "npx", "args": ["@playwright/mcp@latest", "--headless"]}}}"#,
        )
        .unwrap();
        let checks = mcp_client_checks(&port_config(), &mcp_roots(dir.path(), Some(&claude)));
        let shadow = checks
            .iter()
            .find(|c| c.name == "mcp_shadow: claude-code/project/playwright")
            .unwrap_or_else(|| panic!("{checks:?}"));
        assert!(shadow.passed, "a warning, not a failure");
        let message = &shadow.message;
        assert!(message.starts_with("warning: "), "{message}");
        assert!(
            message.contains("overrides it") && !message.contains("may override"),
            "{message}"
        );
        // The three fixes.
        assert!(message.contains("remove `playwright` from"), "{message}");
        assert!(
            message.contains("claude mcp add-json playwright --scope local '{"),
            "{message}"
        );
        assert!(
            message.contains("\"command\":\"/usr/bin/passless\""),
            "{message}"
        );
        assert!(
            message.contains(
                "passless agent mcp install --client claude-code --project . --profile agent --yes"
            ),
            "{message}"
        );
        // The same repo seen from another account (no Passless entry there): nothing to warn about.
        let other = dir.path().join("claude-other");
        fs::create_dir_all(&other).unwrap();
        fs::write(other.join(".claude.json"), "{}").unwrap();
        let checks = mcp_client_checks(&port_config(), &mcp_roots(dir.path(), Some(&other)));
        assert!(
            !checks.iter().any(|c| c.name.starts_with("mcp_shadow")),
            "{checks:?}"
        );
    }

    #[test]
    fn a_local_entry_shadows_with_its_own_fixes_and_a_project_opencode_json_only_softly() {
        let dir = tempfile::tempdir().unwrap();
        let claude = dir.path().join("claude");
        fs::create_dir_all(&claude).unwrap();
        let here = dir.path().to_string_lossy().into_owned();
        fs::write(
            claude.join(".claude.json"),
            format!(
                r#"{{"mcpServers": {{"playwright": {{"command": "/usr/bin/passless", "args": ["agent", "mcp", "playwright", "--profile", "agent"]}}}},
                    "projects": {{"{here}": {{"mcpServers": {{"playwright": {{"command": "npx", "args": ["@playwright/mcp"]}}}}}}}}}}"#
            ),
        )
        .unwrap();
        let checks = mcp_client_checks(&port_config(), &mcp_roots(dir.path(), Some(&claude)));
        let local = checks
            .iter()
            .find(|c| c.name == "mcp_shadow: claude-code/local/playwright")
            .unwrap();
        assert!(
            local
                .message
                .contains("claude mcp remove playwright --scope local"),
            "{local:?}"
        );

        // opencode: a project file is merged over the global one; only a soft warning.
        let home = dir.path().join("home");
        fs::create_dir_all(home.join(".config/opencode")).unwrap();
        fs::write(
            home.join(".config/opencode/opencode.json"),
            r#"{"mcp": {"servers": {"playwright": {"type": "local", "command": ["/usr/bin/passless", "agent", "mcp", "playwright", "--profile", "agent"]}}}}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("opencode.json"),
            r#"{"mcp": {"playwright": {"type": "local", "command": ["npx", "@playwright/mcp"]}}}"#,
        )
        .unwrap();
        let roots = Roots {
            home: Some(home),
            cwd: Some(dir.path().to_path_buf()),
            ..Roots::default()
        };
        let checks = mcp_client_checks(&port_config(), &roots);
        let soft = checks
            .iter()
            .find(|c| c.name == "mcp_shadow: opencode/project/playwright")
            .unwrap();
        assert!(soft.message.contains("may override it"), "{soft:?}");
    }
}
