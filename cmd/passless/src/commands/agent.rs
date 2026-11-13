use std::path::{Path, PathBuf};

use passless_core::agent::protocol::{
    AUTHORITY_SCOPE_DISCOVERED, AUTHORITY_SCOPE_PINNED, AccessRequestState, AccessRequestStatus,
    AuthorityCredentialScope, AuthorityRisk, GrantAction, PrincipalCredentialSummary,
    PrincipalRequest, PrincipalResponse,
};
use passless_core::{
    AgentCommand, AgentCredentialAction, CredentialRef, Error, OutputFormat, ProfileId, Result,
};

use serde::Serialize;

use crate::agent::client::resolve_runtime_base;
use crate::agent::client::{AdminClient, ClientError, PrincipalClient};

use passless_core::agent::protocol::{AdminRequest, AdminResponse};

const ENVELOPE_VERSION: &str = "1";

#[derive(Serialize)]
struct Envelope<T: Serialize> {
    version: &'static str,
    status: &'static str,
    data: T,
}

fn output_json<T: Serialize>(data: &T) -> Result<()> {
    let envelope = Envelope {
        version: ENVELOPE_VERSION,
        status: "ok",
        data,
    };
    println!(
        "{}",
        serde_json::to_string(&envelope).map_err(|e| Error::Other(e.to_string()))?
    );
    Ok(())
}

fn client_error_to_result(e: ClientError) -> Error {
    Error::Other(e.to_string())
}

fn parse_profile_id(s: &str) -> Result<ProfileId> {
    ProfileId::new(s).map_err(|e| Error::Other(e.to_string()))
}

fn parse_credential_ref(s: &str) -> Result<CredentialRef> {
    CredentialRef::from_hex(s).map_err(|e| Error::Other(e.to_string()))
}

fn connect_principal(profile: &str) -> Result<PrincipalClient> {
    let base = resolve_runtime_base().map_err(client_error_to_result)?;
    PrincipalClient::connect_launched(&base, profile).map_err(client_error_to_result)
}

fn connect_admin() -> Result<AdminClient> {
    let base = resolve_runtime_base().map_err(client_error_to_result)?;
    AdminClient::connect(&base).map_err(client_error_to_result)
}

pub fn dispatch(profile: Option<&str>, output: OutputFormat, action: &AgentCommand) -> Result<()> {
    match action {
        AgentCommand::PlaywrightMcp {
            profile: playwright_profile,
            url: playwright_url,
            command,
        } => dispatch_playwright_mcp(
            output,
            playwright_profile,
            playwright_url.as_deref(),
            command,
        ),
        AgentCommand::Run {
            profile: run_profile,
            command,
        } => dispatch_run(output, run_profile, command),
        AgentCommand::McpSessionBroker {
            profile: broker_profile,
            url,
        } => super::mcp_session::serve_broker(broker_profile, url.as_deref()),
        AgentCommand::Browser {
            json,
            env,
            wait,
            headed,
            url,
        } => super::agent_browser::dispatch_browser(
            profile,
            &super::agent_browser::BrowserFlags {
                json: *json,
                env: *env,
                wait: *wait,
                headed: *headed,
                url: url.clone(),
            },
        ),
        AgentCommand::Mcp {
            print_config,
            server,
            with_access_tool,
            adapter,
        } => super::agent_browser::dispatch_mcp(
            profile,
            output,
            *print_config,
            *server,
            *with_access_tool,
            adapter.as_ref(),
        ),
        AgentCommand::RequestAccess {
            rp_id,
            register,
            note,
            wait,
            json,
            fresh_session,
        } => dispatch_request_access(
            profile,
            output,
            &AccessArgs {
                rp_id,
                register: *register,
                note: note.as_deref(),
                wait: *wait,
                json: *json,
                fresh_session: *fresh_session,
            },
        ),
        _ => {
            let profile = profile.ok_or_else(|| {
                Error::Other("--profile is required for principal commands".to_string())
            })?;
            match action {
                AgentCommand::Doctor => dispatch_doctor(output, profile),
                AgentCommand::Capabilities => dispatch_capabilities(output, profile),
                AgentCommand::Instructions => dispatch_instructions(output, profile),
                AgentCommand::Credential { action } => dispatch_credential(output, profile, action),
                AgentCommand::BrowserStatus => dispatch_browser_status(output, profile),
                AgentCommand::BrowserControl {
                    request,
                    request_file,
                    timeout_ms,
                } => dispatch_browser_control(output, profile, request, request_file, *timeout_ms),
                AgentCommand::PlaywrightMcp { .. }
                | AgentCommand::Run { .. }
                | AgentCommand::McpSessionBroker { .. }
                | AgentCommand::Browser { .. }
                | AgentCommand::Mcp { .. }
                | AgentCommand::RequestAccess { .. } => unreachable!(),
            }
        }
    }
}

/// The arguments of `passless agent request-access`.
struct AccessArgs<'a> {
    rp_id: &'a str,
    register: bool,
    note: Option<&'a str>,
    wait: u32,
    json: bool,
    /// This command was re-run by itself in a fresh principal session, which ends with it.
    fresh_session: bool,
}

/// `passless agent request-access <rp_id>` (ADR 0014 amendment section 2.3): ask the human for
/// access before navigating. Inside a principal session it uses that session. Outside one it runs
/// itself in a fresh principal session (like the MCP adapters), for `authenticate` only: a
/// `register` approval is bound to the session that owns the browser, so a fresh one could never
/// use it.
fn dispatch_request_access(
    profile: Option<&str>,
    output: OutputFormat,
    args: &AccessArgs,
) -> Result<()> {
    let profile = profile
        .ok_or_else(|| Error::Other("--profile is required for principal commands".to_string()))?;
    let base = resolve_runtime_base().map_err(client_error_to_result)?;
    match PrincipalClient::connect_launched(&base, profile) {
        Ok(mut client) => {
            let status = request_access(&mut client, args)?;
            print_access_status(&status, args.json, args.fresh_session)
        }
        Err(ClientError::NoControlFd) => {
            if args.register {
                return Err(Error::Other(
                    "--register must run inside the principal session that owns the browser: its \
                     one-use approval is bound to that session, and a fresh session started for \
                     this command could never use it. Start the agent with `passless agent run \
                     --profile <profile> -- <command>` and call this from there, or use the \
                     `passless_request_access` MCP tool of `passless agent mcp playwright \
                     --with-access-tool`"
                        .to_string(),
                ));
            }
            let exe = std::env::current_exe()
                .map_err(|e| Error::Other(format!("failed to resolve passless executable: {e}")))?;
            let command: Vec<PathBuf> = request_access_argv(&exe, profile, args)
                .into_iter()
                .map(PathBuf::from)
                .collect();
            run_in_principal_session(output, profile, &command, true)
        }
        Err(e) => Err(client_error_to_result(e)),
    }
}

/// The command a fresh principal session runs for `request-access` (the executable, then the
/// arguments that reproduce this call).
fn request_access_argv(exe: &Path, profile: &str, args: &AccessArgs) -> Vec<String> {
    let mut argv = vec![
        exe.to_string_lossy().into_owned(),
        "agent".to_string(),
        "--profile".to_string(),
        profile.to_string(),
        "request-access".to_string(),
        args.rp_id.to_string(),
        "--wait".to_string(),
        args.wait.to_string(),
    ];
    if args.register {
        argv.push("--register".to_string());
    }
    if let Some(note) = args.note {
        argv.extend(["--note".to_string(), note.to_string()]);
    }
    if args.json {
        argv.push("--json".to_string());
    }
    argv.push("--fresh-session".to_string());
    argv
}

fn request_access(client: &mut PrincipalClient, args: &AccessArgs) -> Result<AccessRequestStatus> {
    let response = client
        .request(PrincipalRequest::RequestAccess {
            rp_id: args.rp_id.to_string(),
            action: if args.register {
                GrantAction::Register
            } else {
                GrantAction::Authenticate
            },
            note: args.note.map(str::to_string),
            wait_ms: Some(u64::from(args.wait) * 1000),
        })
        .map_err(client_error_to_result)?;
    match response {
        PrincipalResponse::AccessRequest(status) => Ok(status),
        _ => Err(Error::Other("unexpected response".to_string())),
    }
}

/// `--json`: the status object as-is (the MCP tool's result is the same object); otherwise a few
/// lines for a person or a shell agent.
fn print_access_status(
    status: &AccessRequestStatus,
    json: bool,
    fresh_session: bool,
) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string(status).map_err(|e| Error::Other(e.to_string()))?
        );
    } else {
        print!("{}", format_access_status(status, fresh_session));
    }
    Ok(())
}

fn format_access_status(status: &AccessRequestStatus, fresh_session: bool) -> String {
    let mut out = format!(
        "state: {}\nrp_id: {}\naction: {}\n",
        status.state.as_str(),
        status.rp_id,
        match status.action {
            GrantAction::Register => "register",
            GrantAction::Authenticate => "authenticate",
        }
    );
    if let Some(secs) = status.expires_in_secs {
        out.push_str(&format!("expires_in_secs: {secs}\n"));
    }
    if let Some(secs) = status.retry_after_secs {
        out.push_str(&format!("retry_after_secs: {secs}\n"));
    }
    out.push_str(&format!("message: {}\n", status.message));
    if status.state == AccessRequestState::Pending {
        out.push_str(if fresh_session {
            "This command's own principal session ended with it, which withdrew the request. \
             Run the command inside your agent's principal session (`passless agent run`) to keep \
             a request pending and poll it, or use a longer --wait.\n"
        } else {
            "Run the same command again later, with the same arguments, to see the decision.\n"
        });
    }
    out
}

fn dispatch_playwright_mcp(
    output: OutputFormat,
    profile: &str,
    url: Option<&str>,
    command: &[PathBuf],
) -> Result<()> {
    match super::playwright_mcp::try_run_as_principal(profile, url, command)? {
        Some(()) => Ok(()),
        None => {
            let current_exe = std::env::current_exe()
                .map_err(|e| Error::Other(format!("failed to resolve passless executable: {e}")))?;
            let mut wrapper_command = vec![
                current_exe,
                PathBuf::from("agent"),
                PathBuf::from("playwright-mcp"),
                PathBuf::from("--profile"),
                PathBuf::from(profile),
            ];
            if let Some(url) = url {
                wrapper_command.push(PathBuf::from("--url"));
                wrapper_command.push(PathBuf::from(url));
            }
            wrapper_command.push(PathBuf::from("--"));
            wrapper_command.extend(command.iter().cloned());
            dispatch_run(output, profile, &wrapper_command)
        }
    }
}

fn dispatch_doctor(output: OutputFormat, profile: &str) -> Result<()> {
    let mut client = connect_principal(profile)?;
    let resp = client
        .request(passless_core::agent::PrincipalRequest::Doctor)
        .map_err(client_error_to_result)?;
    match resp {
        passless_core::agent::PrincipalResponse::Doctor(doc) => match output {
            OutputFormat::Json => output_json(&doc),
            OutputFormat::Plain => {
                let status = if doc.healthy { "healthy" } else { "unhealthy" };
                println!("status: {}", status);
                for check in &doc.checks {
                    let mark = check.mark();
                    println!("  [{}] {}: {}", mark, check.name, check.message);
                }
                Ok(())
            }
        },
        _ => Err(Error::Other("unexpected response".to_string())),
    }
}

fn authority_risk_message(risk: AuthorityRisk) -> (&'static str, &'static str, &'static str) {
    match risk {
        AuthorityRisk::HumanIdentity => (
            "high",
            "human_identity",
            "same-user exercises the human credential/RP identity; application actions are unconstrained after login",
        ),
        AuthorityRisk::GlobalRpScope => (
            "critical",
            "global_rp_scope",
            "global RP scope '*' permits authentication to any valid RP with a matching credential",
        ),
        AuthorityRisk::AutonomousAuthentication => (
            "high",
            "autonomous_authentication",
            "at least one RP rule permits authentication without ceremony-time human approval",
        ),
        AuthorityRisk::HumanBackendRegistration => (
            "high",
            "human_backend_registration",
            "registration can mutate the human credential backend",
        ),
        AuthorityRisk::DirectCdpPort => (
            "high",
            "direct_cdp_port",
            "loopback CDP port grants direct full managed-browser authority",
        ),
        AuthorityRisk::AmbiguousCredentialSelection => (
            "medium",
            "ambiguous_credential_selection",
            "profile may choose among multiple eligible credentials without requiring a single candidate",
        ),
    }
}

/// The plain `agent capabilities` lines for where the profile's credentials come from: one for
/// the exact rules and one for the `*` rule (ADR 0014 amendment section 2.1).
fn credential_scope_lines(scope: &AuthorityCredentialScope) -> Vec<String> {
    let exact = match scope.exact_rules.as_str() {
        AUTHORITY_SCOPE_PINNED => format!(
            "pinned: the profile's credential_refs ({} configured), plus credentials registered \
             at the RP",
            scope.configured_reference_count
        ),
        AUTHORITY_SCOPE_DISCOVERED => "discovered: every credential of the RP".to_string(),
        other => other.to_string(),
    };
    let wildcard = match scope.wildcard.as_deref() {
        None => "none: the profile has no `*` rule".to_string(),
        Some(AUTHORITY_SCOPE_DISCOVERED) => {
            "discovered: every credential of the RP, or only the credentials registered at \
             that RP once there are any; credential_refs never apply"
                .to_string()
        }
        Some(other) => other.to_string(),
    };
    vec![
        format!("credential_scope_exact_rules: {exact}"),
        format!("credential_scope_wildcard: {wildcard}"),
    ]
}

fn dispatch_capabilities(output: OutputFormat, profile: &str) -> Result<()> {
    let mut client = connect_principal(profile)?;
    let resp = client
        .request(passless_core::agent::PrincipalRequest::Authority)
        .map_err(client_error_to_result)?;
    match resp {
        passless_core::agent::PrincipalResponse::Authority(authority) => match output {
            OutputFormat::Json => output_json(&authority),
            OutputFormat::Plain => {
                println!("profile: {}", authority.profile_id);
                println!("mode: {}", authority.mode);
                println!(
                    "credential_namespace: {}",
                    authority.identity.credential_namespace
                );
                println!("rp_identity: {}", authority.identity.rp_identity);
                println!("acts_as_human: {}", authority.identity.acts_as_human);
                println!("policy_generation: {}", authority.policy_generation);
                println!("credential_selection: {}", authority.credentials.selection);
                for line in credential_scope_lines(&authority.credentials) {
                    println!("{line}");
                }
                println!(
                    "max_session_ttl_secs: {}",
                    authority.session.max_session_ttl_secs
                );
                println!(
                    "principal_remaining_ttl_secs: {}",
                    authority.session.principal_remaining_ttl_secs
                );
                println!("max_operations: {}", authority.session.max_operations);
                if let Some(used) = authority.session.operations_used {
                    println!("operations_used: {}", used);
                }
                if let Some(remaining) = authority.session.operations_remaining {
                    println!("operations_remaining: {}", remaining);
                }
                println!("browser_active: {}", authority.browser.active);
                println!("cdp_exposure: {}", authority.browser.cdp_exposure);
                println!(
                    "full_session_authority: {}",
                    authority.browser.full_session_authority
                );
                println!("rp_rules:");
                for rule in &authority.rp_rules {
                    println!(
                        "  - {}: authenticate={} up={} uv={}; register={} up={} uv={}{}",
                        rule.rp_id,
                        rule.authenticate.authorization,
                        rule.authenticate.user_presence,
                        rule.authenticate.user_verification,
                        rule.register.authorization,
                        rule.register.user_presence,
                        rule.register.user_verification,
                        if rule.wildcard { " [wildcard]" } else { "" },
                    );
                }
                if !authority.risk_flags.is_empty() {
                    println!("risk_flags:");
                    for risk in authority.risk_flags {
                        let (severity, code, message) = authority_risk_message(risk);
                        println!("  - {}: {}: {}", severity, code, message);
                    }
                }
                Ok(())
            }
        },
        _ => Err(Error::Other("unexpected response".to_string())),
    }
}

fn dispatch_instructions(output: OutputFormat, profile: &str) -> Result<()> {
    let mut client = connect_principal(profile)?;
    let resp = client
        .request(passless_core::agent::PrincipalRequest::Instructions)
        .map_err(client_error_to_result)?;
    match resp {
        passless_core::agent::PrincipalResponse::Instructions(instr) => match output {
            OutputFormat::Json => output_json(&instr),
            OutputFormat::Plain => {
                println!("profile: {}", instr.profile_id);
                println!("mode: {}", instr.mode);
                println!("{}", instr.instructions);
                Ok(())
            }
        },
        _ => Err(Error::Other("unexpected response".to_string())),
    }
}

fn dispatch_credential(
    output: OutputFormat,
    profile: &str,
    action: &AgentCredentialAction,
) -> Result<()> {
    match action {
        AgentCredentialAction::List => {
            let mut client = connect_principal(profile)?;
            let req = passless_core::agent::PrincipalRequest::ListCredentials {
                profile_id: parse_profile_id(profile)?,
            };
            let resp = client.request(req).map_err(client_error_to_result)?;
            match resp {
                passless_core::agent::PrincipalResponse::CredentialList(list) => match output {
                    OutputFormat::Json => output_json(&list),
                    OutputFormat::Plain => {
                        println!("total: {}", list.total);
                        for cred in &list.credentials {
                            print_principal_cred(cred);
                        }
                        Ok(())
                    }
                },
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
        AgentCredentialAction::Show { credential_ref } => {
            let mut client = connect_principal(profile)?;
            let _cred_ref = parse_credential_ref(credential_ref)?;
            let req = passless_core::agent::PrincipalRequest::ListCredentials {
                profile_id: parse_profile_id(profile)?,
            };
            let resp = client.request(req).map_err(client_error_to_result)?;
            match resp {
                passless_core::agent::PrincipalResponse::CredentialList(list) => {
                    let found = list
                        .credentials
                        .iter()
                        .find(|c| c.credential_ref.to_hex() == *credential_ref);
                    match found {
                        Some(cred) => match output {
                            OutputFormat::Json => output_json(cred),
                            OutputFormat::Plain => {
                                print_principal_cred(cred);
                                Ok(())
                            }
                        },
                        None => Err(Error::Other(format!(
                            "credential {} not found",
                            credential_ref
                        ))),
                    }
                }
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
    }
}

fn print_principal_cred(cred: &PrincipalCredentialSummary) {
    println!("credential_ref: {}", cred.credential_ref);
    println!("rp_id: {}", cred.rp_id);
    println!("user_name: {}", cred.user_name);
    println!("display_name: {}", cred.display_name);
    println!();
}

fn dispatch_browser_status(output: OutputFormat, profile: &str) -> Result<()> {
    let mut client = connect_principal(profile)?;
    let resp = client
        .request(passless_core::agent::PrincipalRequest::BrowserStatus)
        .map_err(client_error_to_result)?;
    match resp {
        passless_core::agent::PrincipalResponse::BrowserStatus(status) => match output {
            OutputFormat::Json => output_json(&status),
            OutputFormat::Plain => {
                println!("running: {}", if status.running { "true" } else { "false" });
                println!("status: {}", status.status);
                if let Some(endpoint) = &status.cdp_endpoint {
                    println!("cdp_endpoint: {}", endpoint);
                }
                if let Some(interception) = &status.interception {
                    println!("interception: {}", interception);
                }
                if let Some(incognito_allowed) = status.incognito_allowed {
                    println!("incognito_allowed: {}", incognito_allowed);
                }
                Ok(())
            }
        },
        _ => Err(Error::Other("unexpected response".to_string())),
    }
}

fn dispatch_browser_control(
    output: OutputFormat,
    profile: &str,
    request: &Option<String>,
    request_file: &Option<PathBuf>,
    timeout_ms: u32,
) -> Result<()> {
    let request_json = match (request, request_file) {
        (Some(json), None) => json.clone(),
        (None, Some(path)) => read_cdp_request_file(path)?,
        (None, None) => {
            return Err(Error::Other(
                "either --request or --request-file is required".to_string(),
            ));
        }
        (Some(_), Some(_)) => {
            return Err(Error::Other(
                "--request and --request-file are mutually exclusive".to_string(),
            ));
        }
    };

    let mut client = connect_principal(profile)?;
    let req = passless_core::agent::PrincipalRequest::BrowserControl {
        request_json,
        timeout_ms,
    };
    let resp = client.request(req).map_err(client_error_to_result)?;
    match resp {
        passless_core::agent::PrincipalResponse::BrowserControl { messages } => match output {
            OutputFormat::Json => {
                #[derive(Serialize)]
                struct BrowserControlOutput {
                    messages: Vec<String>,
                }
                output_json(&BrowserControlOutput { messages })
            }
            OutputFormat::Plain => {
                eprintln!(
                    "WARNING: CDP output may contain session state (cookies, DOM, network data)."
                );
                eprintln!("Do not mix with credential/admin output.");
                for msg in &messages {
                    println!("{}", msg);
                }
                Ok(())
            }
        },
        _ => Err(Error::Other("unexpected response".to_string())),
    }
}

fn read_cdp_request_file(path: &Path) -> Result<String> {
    use std::os::unix::fs::PermissionsExt;

    let meta = std::fs::symlink_metadata(path).map_err(|e| {
        Error::Other(format!(
            "cannot stat request file '{}': {}",
            path.display(),
            e
        ))
    })?;

    if meta.file_type().is_symlink() {
        return Err(Error::Other(format!(
            "request file '{}' is a symlink (not allowed)",
            path.display()
        )));
    }

    if !meta.is_file() {
        return Err(Error::Other(format!(
            "request file '{}' is not a regular file",
            path.display()
        )));
    }

    if meta.len() > 8 * 1024 {
        return Err(Error::Other(format!(
            "request file '{}' exceeds 8KiB ({} bytes)",
            path.display(),
            meta.len()
        )));
    }

    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(Error::Other(format!(
            "request file '{}' must not be group/world writable (mode {:o})",
            path.display(),
            mode
        )));
    }

    let content = std::fs::read_to_string(path).map_err(|e| {
        Error::Other(format!(
            "cannot read request file '{}': {}",
            path.display(),
            e
        ))
    })?;

    if content.is_empty() {
        return Err(Error::Other("request file is empty".to_string()));
    }

    Ok(content)
}

fn dispatch_run(output: OutputFormat, profile: &str, command: &[PathBuf]) -> Result<()> {
    run_in_principal_session(output, profile, command, false)
}

/// Start `command` in a new principal session of `profile` (or exec it directly when this
/// process already is one) and wait for it. `quiet` suppresses the session notice on stderr.
pub(super) fn run_in_principal_session(
    output: OutputFormat,
    profile: &str,
    command: &[PathBuf],
    quiet: bool,
) -> Result<()> {
    let control_fd = crate::agent::launcher::CONTROL_FD;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(control_fd, &mut stat) } == 0
        && (stat.st_mode & libc::S_IFMT) == libc::S_IFSOCK
    {
        return exec_command_directly(command);
    }

    let mut client = connect_admin()?;
    let argv: Vec<String> = command
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

    use std::os::unix::io::AsRawFd;
    let stdin_fd = std::io::stdin().as_raw_fd();
    let stdout_fd = std::io::stdout().as_raw_fd();
    let stderr_fd = std::io::stderr().as_raw_fd();

    let profile_id = parse_profile_id(profile)?;

    let resp = client
        .launch_principal_with_stdio(&profile_id, argv, stdin_fd, stdout_fd, stderr_fd)
        .map_err(client_error_to_result)?;

    match resp {
        AdminResponse::PrincipalLaunched(launched) => {
            let session_id = launched.session_id.clone();

            if quiet {
            } else if output == OutputFormat::Json {
                eprintln!(
                    "{}",
                    serde_json::to_string(&Envelope {
                        version: ENVELOPE_VERSION,
                        status: "ok",
                        data: &launched,
                    })
                    .map_err(|e| Error::Other(e.to_string()))?
                );
            } else {
                eprintln!("session_id: {}", launched.session_id);
                eprintln!("pid: {}", launched.pid);
                eprintln!("profile_id: {}", launched.profile_id);
            }

            let terminate_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let terminate_flag_clone = terminate_flag.clone();

            ctrlc::set_handler({
                let flag = terminate_flag_clone.clone();
                move || {
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            })
            .map_err(|e| Error::Other(format!("failed to set Ctrl+C handler: {}", e)))?;

            signal_hook::flag::register(libc::SIGTERM, terminate_flag_clone)
                .map_err(|e| Error::Other(format!("failed to register SIGTERM handler: {}", e)))?;

            let mut exit_code: Option<i32> = None;
            let mut signal: Option<i32> = None;

            loop {
                if terminate_flag.load(std::sync::atomic::Ordering::SeqCst) {
                    if let Ok(mut client) = connect_admin() {
                        let _ = client.request(AdminRequest::RevokeSession {
                            session_id: session_id.clone(),
                        });
                    }
                    break;
                }

                let mut wait_client = match connect_admin() {
                    Ok(c) => c,
                    Err(_) => break,
                };

                match wait_client.wait_principal(&session_id, 1000) {
                    Ok(AdminResponse::PrincipalWait(wait_resp)) => {
                        if !wait_resp.running {
                            exit_code = wait_resp.exit_code;
                            signal = wait_resp.signal;
                            break;
                        }
                    }
                    Ok(_) => break,
                    Err(ClientError::Io(ref e))
                        if e.kind() == std::io::ErrorKind::ConnectionReset
                            || e.kind() == std::io::ErrorKind::UnexpectedEof
                            || e.kind() == std::io::ErrorKind::BrokenPipe =>
                    {
                        break;
                    }
                    Err(e) => {
                        return Err(client_error_to_result(e));
                    }
                }
            }

            if let Some(sig) = signal {
                Err(Error::Other(format!("child killed by signal {}", sig)))
            } else if let Some(code) = exit_code {
                if code == 0 {
                    Ok(())
                } else {
                    Err(Error::Other(format!("child exited with code {}", code)))
                }
            } else {
                Err(Error::Other("terminated by signal".to_string()))
            }
        }
        _ => Err(Error::Other("unexpected response".to_string())),
    }
}

fn exec_command_directly(command: &[PathBuf]) -> Result<()> {
    use std::os::unix::process::CommandExt;

    if command.is_empty() {
        return Err(Error::Other("no command to execute".to_string()));
    }

    let err = std::process::Command::new(&command[0])
        .args(&command[1..])
        .exec();

    Err(Error::Other(format!("failed to exec command: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(exact: &str, wildcard: Option<&str>, count: u32) -> AuthorityCredentialScope {
        AuthorityCredentialScope {
            exact_rules: exact.to_string(),
            wildcard: wildcard.map(str::to_string),
            configured_reference_count: count,
            selection: "single".to_string(),
        }
    }

    #[test]
    fn capabilities_say_pins_cover_the_exact_rules_and_the_wildcard_discovers() {
        let lines = credential_scope_lines(&scope(
            AUTHORITY_SCOPE_PINNED,
            Some(AUTHORITY_SCOPE_DISCOVERED),
            19,
        ));
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("credential_scope_exact_rules: pinned"));
        assert!(
            lines[0].contains("credential_refs (19 configured)"),
            "{lines:?}"
        );
        assert!(lines[1].starts_with("credential_scope_wildcard: discovered"));
        assert!(
            lines[1].contains("credential_refs never apply"),
            "{lines:?}"
        );
    }

    #[test]
    fn capabilities_say_so_when_there_is_no_wildcard_or_no_pin() {
        let lines = credential_scope_lines(&scope(AUTHORITY_SCOPE_DISCOVERED, None, 0));
        assert_eq!(
            lines[0],
            "credential_scope_exact_rules: discovered: every credential of the RP"
        );
        assert_eq!(
            lines[1],
            "credential_scope_wildcard: none: the profile has no `*` rule"
        );
    }

    fn status(state: AccessRequestState) -> AccessRequestStatus {
        AccessRequestStatus {
            state,
            rp_id: "example.org".into(),
            action: GrantAction::Authenticate,
            expires_in_secs: None,
            retry_after_secs: Some(60),
            message: "Ask again later.".into(),
        }
    }

    #[test]
    fn request_access_text_lists_the_state_and_says_what_to_do_when_pending() {
        let text = format_access_status(&status(AccessRequestState::Cooldown), false);
        assert_eq!(
            text,
            "state: cooldown\nrp_id: example.org\naction: authenticate\nretry_after_secs: 60\n\
             message: Ask again later.\n"
        );
        let pending = format_access_status(&status(AccessRequestState::Pending), false);
        assert!(pending.contains("same command again"), "{pending}");
        // Run in a session of its own, a pending request cannot be polled: it was withdrawn.
        let fresh = format_access_status(&status(AccessRequestState::Pending), true);
        assert!(fresh.contains("withdrew the request"), "{fresh}");
        assert!(!fresh.contains("same command again"), "{fresh}");
    }

    #[test]
    fn request_access_json_is_the_status_object_without_an_envelope() {
        let json = serde_json::to_value(status(AccessRequestState::Approved)).unwrap();
        assert_eq!(json["state"], "approved");
        assert_eq!(json["rp_id"], "example.org");
        assert!(json.get("version").is_none() && json.get("data").is_none());
        // Every key of the object is present, null when it does not apply.
        assert!(json["expires_in_secs"].is_null());
    }

    #[test]
    fn a_fresh_session_reruns_the_same_request() {
        let args = AccessArgs {
            rp_id: "example.org",
            register: false,
            note: Some("why --register"),
            wait: 45,
            json: true,
            fresh_session: false,
        };
        assert_eq!(
            request_access_argv(Path::new("/usr/bin/passless"), "coding", &args),
            [
                "/usr/bin/passless",
                "agent",
                "--profile",
                "coding",
                "request-access",
                "example.org",
                "--wait",
                "45",
                "--note",
                "why --register",
                "--json",
                "--fresh-session"
            ]
        );
    }

    #[test]
    fn json_envelope_has_no_secrets() {
        let instructions = passless_core::agent::PrincipalInstructions {
            profile_id: "test".into(),
            mode: "isolated".into(),
            instructions: "Use WebAuthn API for authentication".into(),
        };
        let envelope = Envelope {
            version: ENVELOPE_VERSION,
            status: "ok",
            data: &instructions,
        };
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(json.contains(r#""version":"1"#));
        assert!(json.contains(r#""status":"ok"#));
        assert!(!json.contains("secret"));
        assert!(!json.contains("private_key"));
        assert!(!json.contains("password"));
    }

    #[test]
    fn authority_risk_messages_are_stable() {
        let (severity, code, _) = authority_risk_message(AuthorityRisk::GlobalRpScope);
        assert_eq!(severity, "critical");
        assert_eq!(code, "global_rp_scope");
    }

    #[test]
    fn json_envelope_credential_list_no_secrets() {
        let cred = PrincipalCredentialSummary {
            credential_ref: CredentialRef::from_hex(
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            )
            .unwrap(),
            rp_id: "example.com".into(),
            user_name: "alice".into(),
            display_name: "Alice".into(),
        };
        let list = passless_core::agent::PrincipalCredentialList {
            credentials: vec![cred],
            total: 1,
        };
        let envelope = Envelope {
            version: ENVELOPE_VERSION,
            status: "ok",
            data: &list,
        };
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(!json.contains("private_key"));
        assert!(!json.contains("secret_key"));
        assert!(!json.contains("sign_count"));
        assert!(json.contains("credential_ref"));
        assert!(json.contains("rp_id"));
    }

    #[test]
    fn json_envelope_doctor_response_no_secrets() {
        let doc = passless_core::agent::DoctorResponse {
            healthy: true,
            checks: vec![passless_core::agent::DoctorCheck {
                name: "socket".into(),
                passed: true,
                message: "ok".into(),
            }],
        };
        let envelope = Envelope {
            version: ENVELOPE_VERSION,
            status: "ok",
            data: &doc,
        };
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(!json.contains("capability_proof"));
        assert!(!json.contains("secret"));
    }

    #[test]
    fn admin_request_type_cannot_be_principal_request() {
        fn accepts_admin(_: AdminRequest) {}
        fn accepts_principal(_: passless_core::agent::PrincipalRequest) {}

        accepts_admin(AdminRequest::Ping);
        accepts_principal(passless_core::agent::PrincipalRequest::Ping);
    }

    #[test]
    fn profile_id_parse_rejects_empty() {
        assert!(parse_profile_id("").is_err());
    }

    #[test]
    fn profile_id_parse_rejects_path_separator() {
        assert!(parse_profile_id("foo/bar").is_err());
    }

    #[test]
    fn credential_ref_parse_rejects_short_hex() {
        assert!(parse_credential_ref("abcd").is_err());
    }

    #[test]
    fn credential_ref_parse_rejects_non_hex() {
        assert!(parse_credential_ref("zzzz").is_err());
    }

    #[test]
    fn exec_command_directly_rejects_empty_command() {
        let result = exec_command_directly(&[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no command"));
    }

    #[test]
    fn exec_command_directly_rejects_nonexistent_binary() {
        let result = exec_command_directly(&[PathBuf::from("/nonexistent/binary")]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("failed to exec"));
    }

    #[test]
    fn control_fd_socket_detection() {
        let control_fd = crate::agent::launcher::CONTROL_FD;
        let mut fds = [0i32; 2];
        let ret = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        assert_eq!(ret, 0, "socketpair failed");

        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        let stat_ret = unsafe { libc::fstat(fds[0], &mut stat) };
        assert_eq!(stat_ret, 0);
        assert_eq!(
            (stat.st_mode & libc::S_IFMT),
            libc::S_IFSOCK,
            "socketpair fd should be detected as socket"
        );

        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }

        let invalid_fd = 9999;
        let stat_ret = unsafe { libc::fstat(invalid_fd, &mut stat) };
        assert_ne!(stat_ret, 0, "fstat on invalid fd should fail");

        let _ = control_fd;
    }
}
