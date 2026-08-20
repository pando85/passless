use std::path::{Path, PathBuf};
use std::time::Duration;

use passless_core::agent::protocol::{
    AuthorityRisk, DelegationState, IntentAction, IntentState, PrincipalCredentialSummary,
};
use passless_core::{
    AgentCommand, AgentCredentialAction, AgentDelegationAction, AgentIntentAction,
    AgentIntentActionType, CredentialRef, Error, OutputFormat, PendingRequestId, ProfileId, Result,
};

use serde::Serialize;

use crate::agent::client::resolve_runtime_base;
use crate::agent::client::{AdminClient, ClientError, PrincipalClient, WaitTarget, wait_with_poll};

use passless_core::agent::protocol::AdminResponse;

#[cfg(test)]
use passless_core::agent::protocol::AdminRequest;

const ENVELOPE_VERSION: &str = "1";

#[derive(Serialize)]
struct Envelope<T: Serialize> {
    version: &'static str,
    status: &'static str,
    data: T,
}

#[derive(Serialize)]
struct ErrorEnvelope {
    version: &'static str,
    status: &'static str,
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: String,
    message: String,
    recommended_action: String,
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

fn output_error(code: &str, message: &str, action: &str) -> Result<()> {
    let envelope = ErrorEnvelope {
        version: ENVELOPE_VERSION,
        status: "error",
        error: ErrorDetail {
            code: code.to_string(),
            message: message.to_string(),
            recommended_action: action.to_string(),
        },
    };
    eprintln!(
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

fn parse_pending_request_id(s: &str) -> Result<PendingRequestId> {
    s.parse::<PendingRequestId>()
        .map_err(|e| Error::Other(e.to_string()))
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
        _ => {
            let profile = profile.ok_or_else(|| {
                Error::Other("--profile is required for principal commands".to_string())
            })?;
            match action {
                AgentCommand::Doctor => dispatch_doctor(output, profile),
                AgentCommand::Capabilities => dispatch_capabilities(output, profile),
                AgentCommand::Instructions => dispatch_instructions(output, profile),
                AgentCommand::Intent { action } => dispatch_intent(output, profile, action),
                AgentCommand::Delegation { action } => dispatch_delegation(output, profile, action),
                AgentCommand::Credential { action } => dispatch_credential(output, profile, action),
                AgentCommand::BrowserStatus => dispatch_browser_status(output, profile),
                AgentCommand::EndpointStatus => dispatch_endpoint_status(output, profile),
                AgentCommand::BrowserControl {
                    request,
                    request_file,
                    timeout_ms,
                } => dispatch_browser_control(output, profile, request, request_file, *timeout_ms),
                AgentCommand::PlaywrightMcp { .. } | AgentCommand::Run { .. } => unreachable!(),
            }
        }
    }
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
                    let mark = if check.passed { "ok" } else { "FAIL" };
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
                println!(
                    "dynamic_credential_scope: {}",
                    authority.credentials.dynamic_per_rp
                );
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

fn dispatch_intent(output: OutputFormat, profile: &str, action: &AgentIntentAction) -> Result<()> {
    match action {
        AgentIntentAction::Create {
            action: intent_type,
            rp,
            credential,
            reason,
        } => {
            let mut client = connect_principal(profile)?;
            let action = match intent_type {
                AgentIntentActionType::Register => IntentAction::Register,
                AgentIntentActionType::Authenticate => IntentAction::Authenticate,
            };
            let cred_ref = credential
                .as_deref()
                .map(parse_credential_ref)
                .transpose()?;
            let req = passless_core::agent::PrincipalRequest::CreateIntent {
                profile_id: parse_profile_id(profile)?,
                action,
                rp_id: rp.clone(),
                credential_ref: cred_ref,
                reason: reason.clone(),
                grant_ttl_secs: None,
                session_ttl_secs: None,
            };
            let resp = client.request(req).map_err(client_error_to_result)?;
            match resp {
                passless_core::agent::PrincipalResponse::IntentCreated { request_id } => {
                    #[derive(Serialize)]
                    struct IntentCreated {
                        request_id: String,
                    }
                    match output {
                        OutputFormat::Json => output_json(&IntentCreated {
                            request_id: request_id.to_string(),
                        }),
                        OutputFormat::Plain => {
                            println!("request_id: {}", request_id);
                            Ok(())
                        }
                    }
                }
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
        AgentIntentAction::Show { request_id } => {
            let mut client = connect_principal(profile)?;
            let req = passless_core::agent::PrincipalRequest::ShowIntent {
                request_id: parse_pending_request_id(request_id)?,
            };
            let resp = client.request(req).map_err(client_error_to_result)?;
            match resp {
                passless_core::agent::PrincipalResponse::IntentStatus { request_id, state } => {
                    #[derive(Serialize)]
                    struct IntentStatusOut {
                        request_id: String,
                        state: String,
                    }
                    match output {
                        OutputFormat::Json => output_json(&IntentStatusOut {
                            request_id: request_id.to_string(),
                            state: state.to_string(),
                        }),
                        OutputFormat::Plain => {
                            println!("request_id: {}", request_id);
                            println!("state: {}", state);
                            Ok(())
                        }
                    }
                }
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
        AgentIntentAction::Wait {
            request_id,
            timeout,
            poll_interval,
        } => {
            let mut client = connect_principal(profile)?;
            let req_id = parse_pending_request_id(request_id)?;
            let timeout_dur = timeout.map(Duration::from_secs);
            let poll_dur = poll_interval.map(Duration::from_millis);

            let result = wait_with_poll(
                WaitTarget::Intent,
                &req_id,
                timeout_dur,
                poll_dur,
                || -> std::result::Result<bool, ClientError> {
                    let show_req = passless_core::agent::PrincipalRequest::ShowIntent {
                        request_id: req_id.clone(),
                    };
                    let resp = client.request(show_req)?;
                    match resp {
                        passless_core::agent::PrincipalResponse::IntentStatus { state, .. } => {
                            Ok(is_terminal_intent(state))
                        }
                        _ => Ok(false),
                    }
                },
            );

            match result {
                Ok(()) => {
                    let show_req = passless_core::agent::PrincipalRequest::ShowIntent {
                        request_id: req_id.clone(),
                    };
                    let resp = client.request(show_req).map_err(client_error_to_result)?;
                    match resp {
                        passless_core::agent::PrincipalResponse::IntentStatus {
                            request_id,
                            state,
                        } => {
                            #[derive(Serialize)]
                            struct IntentWaitOut {
                                request_id: String,
                                state: String,
                            }
                            match output {
                                OutputFormat::Json => output_json(&IntentWaitOut {
                                    request_id: request_id.to_string(),
                                    state: state.to_string(),
                                }),
                                OutputFormat::Plain => {
                                    println!("request_id: {}", request_id);
                                    println!("state: {}", state);
                                    Ok(())
                                }
                            }
                        }
                        _ => Err(Error::Other("unexpected response".to_string())),
                    }
                }
                Err(ClientError::Timeout) => {
                    let _ = output_error("timeout", "wait timed out", "retry");
                    Err(Error::Other("wait timed out".to_string()))
                }
                Err(e) => Err(client_error_to_result(e)),
            }
        }
        AgentIntentAction::Cancel { request_id } => {
            let mut client = connect_principal(profile)?;
            let req = passless_core::agent::PrincipalRequest::CancelIntent {
                request_id: parse_pending_request_id(request_id)?,
            };
            let resp = client.request(req).map_err(client_error_to_result)?;
            match resp {
                passless_core::agent::PrincipalResponse::IntentCancelled => {
                    #[derive(Serialize)]
                    struct CancelledOut {
                        cancelled: bool,
                    }
                    match output {
                        OutputFormat::Json => output_json(&CancelledOut { cancelled: true }),
                        OutputFormat::Plain => {
                            println!("cancelled: true");
                            Ok(())
                        }
                    }
                }
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
    }
}

fn is_terminal_intent(state: IntentState) -> bool {
    matches!(
        state,
        IntentState::Approved | IntentState::Denied | IntentState::Cancelled | IntentState::Expired
    )
}

fn is_terminal_delegation(state: DelegationState) -> bool {
    matches!(
        state,
        DelegationState::Approved
            | DelegationState::Denied
            | DelegationState::Cancelled
            | DelegationState::Expired
            | DelegationState::Revoked
    )
}

fn dispatch_delegation(
    output: OutputFormat,
    profile: &str,
    action: &AgentDelegationAction,
) -> Result<()> {
    match action {
        AgentDelegationAction::Request {
            rp,
            credential,
            session_ttl,
            reason,
        } => {
            let mut client = connect_admin()?;
            let req = passless_core::agent::AdminRequest::RequestDelegation {
                profile_id: parse_profile_id(profile)?,
                rp_id: rp.clone(),
                credential_ref: parse_credential_ref(credential)?,
                max_session_ttl: *session_ttl,
                reason: reason.clone(),
            };
            let resp = client.request(req).map_err(client_error_to_result)?;
            match resp {
                passless_core::agent::AdminResponse::DelegationRequested { request_id } => {
                    #[derive(Serialize)]
                    struct DelegationRequestedOut {
                        request_id: String,
                    }
                    match output {
                        OutputFormat::Json => output_json(&DelegationRequestedOut {
                            request_id: request_id.to_string(),
                        }),
                        OutputFormat::Plain => {
                            println!("request_id: {}", request_id);
                            Ok(())
                        }
                    }
                }
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
        AgentDelegationAction::Show { request_id } => {
            let mut client = connect_principal(profile)?;
            let req = passless_core::agent::PrincipalRequest::ShowDelegation {
                request_id: parse_pending_request_id(request_id)?,
            };
            let resp = client.request(req).map_err(client_error_to_result)?;
            match resp {
                passless_core::agent::PrincipalResponse::DelegationStatus { request_id, state } => {
                    #[derive(Serialize)]
                    struct DelegationStatusOut {
                        request_id: String,
                        state: String,
                    }
                    match output {
                        OutputFormat::Json => output_json(&DelegationStatusOut {
                            request_id: request_id.to_string(),
                            state: state.to_string(),
                        }),
                        OutputFormat::Plain => {
                            println!("request_id: {}", request_id);
                            println!("state: {}", state);
                            Ok(())
                        }
                    }
                }
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
        AgentDelegationAction::Wait {
            request_id,
            timeout,
            poll_interval,
        } => {
            let mut client = connect_principal(profile)?;
            let req_id = parse_pending_request_id(request_id)?;
            let timeout_dur = timeout.map(Duration::from_secs);
            let poll_dur = poll_interval.map(Duration::from_millis);

            let result = wait_with_poll(
                WaitTarget::Delegation,
                &req_id,
                timeout_dur,
                poll_dur,
                || -> std::result::Result<bool, ClientError> {
                    let show_req = passless_core::agent::PrincipalRequest::ShowDelegation {
                        request_id: req_id.clone(),
                    };
                    let resp = client.request(show_req)?;
                    match resp {
                        passless_core::agent::PrincipalResponse::DelegationStatus {
                            state, ..
                        } => Ok(is_terminal_delegation(state)),
                        _ => Ok(false),
                    }
                },
            );

            match result {
                Ok(()) => {
                    let show_req = passless_core::agent::PrincipalRequest::ShowDelegation {
                        request_id: req_id.clone(),
                    };
                    let resp = client.request(show_req).map_err(client_error_to_result)?;
                    match resp {
                        passless_core::agent::PrincipalResponse::DelegationStatus {
                            request_id,
                            state,
                        } => {
                            #[derive(Serialize)]
                            struct DelegationWaitOut {
                                request_id: String,
                                state: String,
                            }
                            match output {
                                OutputFormat::Json => output_json(&DelegationWaitOut {
                                    request_id: request_id.to_string(),
                                    state: state.to_string(),
                                }),
                                OutputFormat::Plain => {
                                    println!("request_id: {}", request_id);
                                    println!("state: {}", state);
                                    Ok(())
                                }
                            }
                        }
                        _ => Err(Error::Other("unexpected response".to_string())),
                    }
                }
                Err(ClientError::Timeout) => {
                    let _ = output_error("timeout", "wait timed out", "retry");
                    Err(Error::Other("wait timed out".to_string()))
                }
                Err(e) => Err(client_error_to_result(e)),
            }
        }
        AgentDelegationAction::Cancel { request_id } => {
            let mut client = connect_principal(profile)?;
            let req = passless_core::agent::PrincipalRequest::CancelDelegation {
                request_id: parse_pending_request_id(request_id)?,
            };
            let resp = client.request(req).map_err(client_error_to_result)?;
            match resp {
                passless_core::agent::PrincipalResponse::DelegationCancelled => {
                    #[derive(Serialize)]
                    struct CancelledOut {
                        cancelled: bool,
                    }
                    match output {
                        OutputFormat::Json => output_json(&CancelledOut { cancelled: true }),
                        OutputFormat::Plain => {
                            println!("cancelled: true");
                            Ok(())
                        }
                    }
                }
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
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
                Ok(())
            }
        },
        _ => Err(Error::Other("unexpected response".to_string())),
    }
}

fn dispatch_endpoint_status(output: OutputFormat, profile: &str) -> Result<()> {
    let mut client = connect_principal(profile)?;
    let resp = client
        .request(passless_core::agent::PrincipalRequest::EndpointStatus)
        .map_err(client_error_to_result)?;
    match resp {
        passless_core::agent::PrincipalResponse::EndpointStatus(status) => match output {
            OutputFormat::Json => output_json(&status),
            OutputFormat::Plain => {
                println!("endpoint_id: {}", status.endpoint_id);
                println!("status: {}", status.status);
                println!(
                    "connected: {}",
                    if status.connected { "true" } else { "false" }
                );
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

            if output == OutputFormat::Json {
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

            let ctrlc_profile = profile.to_string();
            let ctrlc_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let ctrlc_flag_clone = ctrlc_flag.clone();

            ctrlc::set_handler(move || {
                if ctrlc_flag_clone.load(std::sync::atomic::Ordering::SeqCst) {
                    std::process::exit(130);
                }
                ctrlc_flag_clone.store(true, std::sync::atomic::Ordering::SeqCst);

                match connect_admin() {
                    Ok(mut terminate_client) => {
                        if let Ok(pid) = parse_profile_id(&ctrlc_profile) {
                            let _ = terminate_client.terminate_principal(&pid);
                        }
                    }
                    Err(_) => {
                        std::process::exit(130);
                    }
                }
            })
            .map_err(|e| Error::Other(format!("failed to set Ctrl+C handler: {}", e)))?;

            let mut exit_code: Option<i32> = None;
            let mut signal: Option<i32> = None;

            loop {
                if ctrlc_flag.load(std::sync::atomic::Ordering::SeqCst) {
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
                Ok(())
            }
        }
        _ => Err(Error::Other("unexpected response".to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_envelope_has_no_secrets() {
        let caps = passless_core::agent::PrincipalCapabilities {
            profile_id: "test".into(),
            mode: "isolated".into(),
            allowed_rp_ids: vec!["example.com".into()],
            registration_allowed: true,
        };
        let envelope = Envelope {
            version: ENVELOPE_VERSION,
            status: "ok",
            data: &caps,
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
    fn error_envelope_has_code_message_action() {
        let err = ErrorEnvelope {
            version: ENVELOPE_VERSION,
            status: "error",
            error: ErrorDetail {
                code: "not_found".into(),
                message: "credential not found".into(),
                recommended_action: "fix_request".into(),
            },
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains(r#""code":"not_found"#));
        assert!(json.contains(r#""message":"credential not found"#));
        assert!(json.contains(r#""recommended_action":"fix_request"#));
        assert!(!json.contains("data"));
    }

    #[test]
    fn error_envelope_no_raw_internal_details() {
        let err = ErrorEnvelope {
            version: ENVELOPE_VERSION,
            status: "error",
            error: ErrorDetail {
                code: "internal".into(),
                message: "something went wrong".into(),
                recommended_action: "retry".into(),
            },
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(!json.contains("stack_trace"));
        assert!(!json.contains("backtrace"));
        assert!(!json.contains("source_file"));
    }

    #[test]
    fn capabilities_plain_output_no_debug() {
        let caps = passless_core::agent::PrincipalCapabilities {
            profile_id: "test".into(),
            mode: "isolated".into(),
            allowed_rp_ids: vec!["example.com".into()],
            registration_allowed: true,
        };
        let plain = format!(
            "profile: {}\nmode: {}\nregistration_allowed: {}\nallowed_rp_ids:\n  - {}",
            caps.profile_id, caps.mode, caps.registration_allowed, caps.allowed_rp_ids[0]
        );
        assert!(!plain.contains("PrincipalCapabilities"));
        assert!(!plain.contains("{"));
    }

    #[test]
    fn terminal_intent_states() {
        assert!(!is_terminal_intent(IntentState::Pending));
        assert!(is_terminal_intent(IntentState::Approved));
        assert!(is_terminal_intent(IntentState::Denied));
        assert!(is_terminal_intent(IntentState::Cancelled));
        assert!(is_terminal_intent(IntentState::Expired));
    }

    #[test]
    fn terminal_delegation_states() {
        assert!(!is_terminal_delegation(DelegationState::Pending));
        assert!(is_terminal_delegation(DelegationState::Approved));
        assert!(is_terminal_delegation(DelegationState::Denied));
        assert!(is_terminal_delegation(DelegationState::Cancelled));
        assert!(is_terminal_delegation(DelegationState::Expired));
        assert!(is_terminal_delegation(DelegationState::Revoked));
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
    fn pending_request_id_parse_rejects_non_hex() {
        assert!(parse_pending_request_id("not-hex").is_err());
    }
}
