use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use passless_core::{
    AdminAuditAction, AdminAuditExportFormat, AdminBrowserAction, AdminCredentialAction,
    AdminDelegationAction, AdminPolicyAction, AdminProfileAction, AdminSessionAction,
    AgentAdminAction, AgentSkillScope, AgentSkillTarget, CredentialRef, Error, GrantId,
    OutputFormat, ProfileId, Result,
};

use passless_core::agent::PrincipalSessionId;
use passless_core::agent::protocol::{AdminRequest, AuditExportFormat};

use serde::Serialize;

use crate::agent::client::{AdminClient, resolve_runtime_base};

const ENVELOPE_VERSION: &str = "1";

const SKILL_NAME: &str = "passless-agent";
const SKILL_CONTENT: &str = include_str!("../../assets/skills/passless-agent/SKILL.md");

// Pi skill paths per official docs:
// https://raw.githubusercontent.com/badlogic/pi-mono/main/packages/coding-agent/docs/skills.md
// Global: ~/.pi/agent/skills/  Project: .pi/skills/
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentKind {
    Opencode,
    Claude,
    Pi,
}

impl AgentKind {
    const ALL: [Self; 3] = [Self::Opencode, Self::Claude, Self::Pi];

    fn name(self) -> &'static str {
        match self {
            Self::Opencode => "OpenCode",
            Self::Claude => "Claude Code",
            Self::Pi => "Pi",
        }
    }

    fn command(self) -> &'static str {
        match self {
            Self::Opencode => "opencode",
            Self::Claude => "claude",
            Self::Pi => "pi",
        }
    }

    fn user_config_path(self, home: &Path) -> PathBuf {
        match self {
            Self::Opencode => home.join(".config/opencode"),
            Self::Claude => home.join(".claude"),
            Self::Pi => home.join(".pi/agent"),
        }
    }

    fn skill_path(self, scope: AgentSkillScope, home: &Path, project: &Path) -> PathBuf {
        let root = match (self, scope) {
            (Self::Opencode, AgentSkillScope::User) => home.join(".config/opencode/skills"),
            (Self::Claude, AgentSkillScope::User) => home.join(".claude/skills"),
            (Self::Opencode, AgentSkillScope::Project) => project.join(".opencode/skills"),
            (Self::Claude, AgentSkillScope::Project) => project.join(".claude/skills"),
            (Self::Pi, AgentSkillScope::User) => home.join(".pi/agent/skills"),
            (Self::Pi, AgentSkillScope::Project) => project.join(".pi/skills"),
        };
        root.join(SKILL_NAME).join("SKILL.md")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallStatus {
    Installed,
    Current,
}

pub fn install(target: AgentSkillTarget, scope: AgentSkillScope, force: bool) -> Result<()> {
    let current_dir = env::current_dir()?;
    let project = project_root(&current_dir);
    let home = dirs::home_dir().ok_or_else(|| {
        Error::Other("Could not determine the home directory for skill installation".to_string())
    })?;
    let agents = selected_agents(target, &home, &project)?;

    for agent in agents {
        let path = agent.skill_path(scope, &home, &project);
        let trusted_root = match scope {
            AgentSkillScope::User => &home,
            AgentSkillScope::Project => &project,
        };
        match install_skill(&path, trusted_root, force)? {
            InstallStatus::Installed => {
                println!(
                    "Installed Passless skill for {} at {}",
                    agent.name(),
                    path.display()
                );
            }
            InstallStatus::Current => {
                println!(
                    "Passless skill for {} is already current at {}",
                    agent.name(),
                    path.display()
                );
            }
        }
    }

    Ok(())
}

#[derive(Serialize)]
struct AdminEnvelope<T: Serialize> {
    version: &'static str,
    status: &'static str,
    data: T,
}

fn admin_output_json<T: Serialize>(data: &T) -> Result<()> {
    let envelope = AdminEnvelope {
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

fn connect_admin_client() -> Result<AdminClient> {
    let base = resolve_runtime_base().map_err(|e| Error::Other(e.to_string()))?;
    AdminClient::connect(&base).map_err(|e| Error::Other(e.to_string()))
}

fn parse_profile_id(s: &str) -> Result<ProfileId> {
    ProfileId::new(s).map_err(|e| Error::Other(e.to_string()))
}

fn parse_credential_ref(s: &str) -> Result<CredentialRef> {
    CredentialRef::from_hex(s).map_err(|e| Error::Other(e.to_string()))
}

fn parse_grant_id(s: &str) -> Result<GrantId> {
    s.parse::<GrantId>()
        .map_err(|e| Error::Other(e.to_string()))
}

fn parse_session_id(s: &str) -> Result<PrincipalSessionId> {
    s.parse::<PrincipalSessionId>()
        .map_err(|e| Error::Other(e.to_string()))
}

pub fn dispatch_admin(output: OutputFormat, action: &AgentAdminAction) -> Result<()> {
    match action {
        AgentAdminAction::Install {
            target,
            scope,
            force,
        } => install(*target, *scope, *force),
        AgentAdminAction::Profile { action } => dispatch_profile(output, action),
        AgentAdminAction::Policy { action } => dispatch_policy(output, action),
        AgentAdminAction::Credential { action } => dispatch_admin_credential(output, action),
        AgentAdminAction::Delegation { action } => dispatch_admin_delegation(output, action),
        AgentAdminAction::Session { action } => dispatch_admin_session(output, action),
        AgentAdminAction::Browser { action } => dispatch_browser(output, action),
        AgentAdminAction::Audit { action } => dispatch_audit(output, action),
        AgentAdminAction::Shutdown { confirm } => dispatch_shutdown(output, *confirm),
    }
}

fn dispatch_profile(output: OutputFormat, action: &AdminProfileAction) -> Result<()> {
    let mut client = connect_admin_client()?;
    match action {
        AdminProfileAction::Check { profile } => {
            let req = AdminRequest::ProfileCheck {
                profile_id: parse_profile_id(profile)?,
            };
            let resp = client
                .request(req)
                .map_err(|e| Error::Other(e.to_string()))?;
            match resp {
                passless_core::agent::AdminResponse::ProfileCheck(report) => match output {
                    OutputFormat::Json => admin_output_json(&report),
                    OutputFormat::Plain => {
                        println!("profile_id: {}", report.profile_id);
                        println!("enabled: {}", report.enabled);
                        println!("mode: {}", report.mode);
                        println!("endpoint_state: {}", report.endpoint_state);
                        if let Some(ref lease) = report.browser_lease_state {
                            println!("browser_lease_state: {}", lease);
                        }
                        println!("policy_generation: {}", report.policy_generation);
                        println!("audit_gate_healthy: {}", report.audit_gate_healthy);
                        for check in &report.checks {
                            let mark = if check.passed { "ok" } else { "FAIL" };
                            println!("  [{}] {}: {}", mark, check.name, check.message);
                        }
                        Ok(())
                    }
                },
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
        AdminProfileAction::Show { profile } => {
            let req = AdminRequest::ShowProfile {
                profile_id: parse_profile_id(profile)?,
            };
            let resp = client
                .request(req)
                .map_err(|e| Error::Other(e.to_string()))?;
            match resp {
                passless_core::agent::AdminResponse::ProfileInfo(info) => match output {
                    OutputFormat::Json => admin_output_json(&info),
                    OutputFormat::Plain => {
                        println!("profile_id: {}", info.profile_id);
                        println!("enabled: {}", info.enabled);
                        println!("mode: {}", info.mode);
                        println!("policy_generation: {}", info.policy_generation);
                        println!("active_grants: {}", info.active_grants);
                        println!("active_sessions: {}", info.active_sessions);
                        println!("pending_intents: {}", info.pending_intents);
                        Ok(())
                    }
                },
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
        AdminProfileAction::List => {
            let resp = client
                .request(AdminRequest::ListProfiles)
                .map_err(|e| Error::Other(e.to_string()))?;
            match resp {
                passless_core::agent::AdminResponse::ProfileList(list) => match output {
                    OutputFormat::Json => admin_output_json(&list),
                    OutputFormat::Plain => {
                        println!("total: {}", list.total);
                        for p in &list.profiles {
                            println!(
                                "  {} (enabled={}, mode={})",
                                p.profile_id, p.enabled, p.mode
                            );
                        }
                        Ok(())
                    }
                },
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
        AdminProfileAction::Enable { profile } => {
            let req = AdminRequest::EnableProfile {
                profile_id: parse_profile_id(profile)?,
            };
            let resp = client
                .request(req)
                .map_err(|e| Error::Other(e.to_string()))?;
            match resp {
                passless_core::agent::AdminResponse::ProfileEnabled => {
                    #[derive(Serialize)]
                    struct EnabledOut {
                        profile_id: String,
                        enabled: bool,
                    }
                    match output {
                        OutputFormat::Json => admin_output_json(&EnabledOut {
                            profile_id: profile.clone(),
                            enabled: true,
                        }),
                        OutputFormat::Plain => {
                            println!("profile: {}", profile);
                            println!("enabled: true");
                            Ok(())
                        }
                    }
                }
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
        AdminProfileAction::Disable { profile } => {
            let req = AdminRequest::DisableProfile {
                profile_id: parse_profile_id(profile)?,
            };
            let resp = client
                .request(req)
                .map_err(|e| Error::Other(e.to_string()))?;
            match resp {
                passless_core::agent::AdminResponse::ProfileDisabled => {
                    #[derive(Serialize)]
                    struct DisabledOut {
                        profile_id: String,
                        enabled: bool,
                    }
                    match output {
                        OutputFormat::Json => admin_output_json(&DisabledOut {
                            profile_id: profile.clone(),
                            enabled: false,
                        }),
                        OutputFormat::Plain => {
                            println!("profile: {}", profile);
                            println!("enabled: false");
                            Ok(())
                        }
                    }
                }
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
    }
}

fn dispatch_policy(output: OutputFormat, action: &AdminPolicyAction) -> Result<()> {
    let mut client = connect_admin_client()?;
    match action {
        AdminPolicyAction::Check { profile } => {
            let req = AdminRequest::ShowPolicy {
                profile_id: parse_profile_id(profile)?,
            };
            let resp = client
                .request(req)
                .map_err(|e| Error::Other(e.to_string()))?;
            match resp {
                passless_core::agent::AdminResponse::PolicyInfo(info) => {
                    #[derive(Serialize)]
                    struct PolicyCheckOut {
                        profile_id: String,
                        valid: bool,
                        policy_generation: u64,
                    }
                    match output {
                        OutputFormat::Json => admin_output_json(&PolicyCheckOut {
                            profile_id: info.profile_id,
                            valid: true,
                            policy_generation: info.policy_generation,
                        }),
                        OutputFormat::Plain => {
                            println!("profile: {}", info.profile_id);
                            println!("valid: true");
                            println!("generation: {}", info.policy_generation);
                            Ok(())
                        }
                    }
                }
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
        AdminPolicyAction::Reload { profile } => {
            let req = AdminRequest::ReloadPolicy {
                profile_id: parse_profile_id(profile)?,
            };
            let resp = client
                .request(req)
                .map_err(|e| Error::Other(e.to_string()))?;
            match resp {
                passless_core::agent::AdminResponse::PolicyRecompiled => {
                    #[derive(Serialize)]
                    struct RecompiledOut {
                        profile_id: String,
                        recompiled: bool,
                    }
                    match output {
                        OutputFormat::Json => admin_output_json(&RecompiledOut {
                            profile_id: profile.clone(),
                            recompiled: true,
                        }),
                        OutputFormat::Plain => {
                            println!("profile: {}", profile);
                            println!("recompiled: true");
                            Ok(())
                        }
                    }
                }
                passless_core::agent::AdminResponse::PolicyReloaded => {
                    #[derive(Serialize)]
                    struct ReloadedOut {
                        profile_id: String,
                        reloaded: bool,
                    }
                    match output {
                        OutputFormat::Json => admin_output_json(&ReloadedOut {
                            profile_id: profile.clone(),
                            reloaded: true,
                        }),
                        OutputFormat::Plain => {
                            println!("profile: {}", profile);
                            println!("reloaded: true");
                            Ok(())
                        }
                    }
                }
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
        AdminPolicyAction::Show { profile } => {
            let req = AdminRequest::ShowPolicy {
                profile_id: parse_profile_id(profile)?,
            };
            let resp = client
                .request(req)
                .map_err(|e| Error::Other(e.to_string()))?;
            match resp {
                passless_core::agent::AdminResponse::PolicyInfo(info) => match output {
                    OutputFormat::Json => admin_output_json(&info),
                    OutputFormat::Plain => {
                        println!("profile_id: {}", info.profile_id);
                        println!("policy_generation: {}", info.policy_generation);
                        println!("digest: {}", info.digest);
                        Ok(())
                    }
                },
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
    }
}

fn dispatch_admin_credential(output: OutputFormat, action: &AdminCredentialAction) -> Result<()> {
    let mut client = connect_admin_client()?;
    match action {
        AdminCredentialAction::List { rp_id } => {
            let req = AdminRequest::ListCredentials {
                rp_id: rp_id.clone(),
            };
            let resp = client
                .request(req)
                .map_err(|e| Error::Other(e.to_string()))?;
            match resp {
                passless_core::agent::AdminResponse::CredentialList(list) => match output {
                    OutputFormat::Json => admin_output_json(&list),
                    OutputFormat::Plain => {
                        println!("total: {}", list.total);
                        for c in &list.credentials {
                            println!("  {} rp={} user={}", c.credential_ref, c.rp_id, c.user_name);
                        }
                        Ok(())
                    }
                },
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
        AdminCredentialAction::Show { credential_ref } => {
            let req = AdminRequest::ShowCredential {
                credential_ref: parse_credential_ref(credential_ref)?,
            };
            let resp = client
                .request(req)
                .map_err(|e| Error::Other(e.to_string()))?;
            match resp {
                passless_core::agent::AdminResponse::CredentialInfo(info) => match output {
                    OutputFormat::Json => admin_output_json(&info),
                    OutputFormat::Plain => {
                        println!("credential_ref: {}", info.credential_ref);
                        println!("rp_id: {}", info.rp_id);
                        println!("user_name: {}", info.user_name);
                        println!("display_name: {}", info.display_name);
                        Ok(())
                    }
                },
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
        AdminCredentialAction::Revoke {
            credential_ref,
            confirm,
        } => {
            if !confirm {
                return Err(Error::Other(
                    "destructive action requires --confirm flag".to_string(),
                ));
            }
            let req = AdminRequest::RevokeCredential {
                credential_ref: parse_credential_ref(credential_ref)?,
            };
            let resp = client
                .request(req)
                .map_err(|e| Error::Other(e.to_string()))?;
            match resp {
                passless_core::agent::AdminResponse::CredentialRevoked => {
                    #[derive(Serialize)]
                    struct RevokedOut {
                        credential_ref: String,
                        revoked: bool,
                    }
                    match output {
                        OutputFormat::Json => admin_output_json(&RevokedOut {
                            credential_ref: credential_ref.clone(),
                            revoked: true,
                        }),
                        OutputFormat::Plain => {
                            println!("credential_ref: {}", credential_ref);
                            println!("revoked: true");
                            Ok(())
                        }
                    }
                }
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
        AdminCredentialAction::Delete {
            credential_ref,
            confirm,
        } => {
            if !confirm {
                return Err(Error::Other(
                    "destructive action requires --confirm flag".to_string(),
                ));
            }
            let req = AdminRequest::DeleteCredential {
                credential_ref: parse_credential_ref(credential_ref)?,
            };
            let resp = client
                .request(req)
                .map_err(|e| Error::Other(e.to_string()))?;
            match resp {
                passless_core::agent::AdminResponse::Deleted => {
                    #[derive(Serialize)]
                    struct DeletedOut {
                        credential_ref: String,
                        deleted: bool,
                    }
                    match output {
                        OutputFormat::Json => admin_output_json(&DeletedOut {
                            credential_ref: credential_ref.clone(),
                            deleted: true,
                        }),
                        OutputFormat::Plain => {
                            println!("credential_ref: {}", credential_ref);
                            println!("deleted: true");
                            Ok(())
                        }
                    }
                }
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
    }
}

fn dispatch_admin_delegation(output: OutputFormat, action: &AdminDelegationAction) -> Result<()> {
    let mut client = connect_admin_client()?;
    match action {
        AdminDelegationAction::Show { grant_id } => {
            let req = AdminRequest::ShowDelegation {
                grant_id: parse_grant_id(grant_id)?,
            };
            let resp = client
                .request(req)
                .map_err(|e| Error::Other(e.to_string()))?;
            match resp {
                passless_core::agent::AdminResponse::DelegationInfo(info) => match output {
                    OutputFormat::Json => admin_output_json(&info),
                    OutputFormat::Plain => {
                        println!("grant_id: {}", info.grant_id);
                        println!("profile_id: {}", info.profile_id);
                        println!("rp_id: {}", info.rp_id);
                        println!("credential_ref: {}", info.credential_ref);
                        println!("state: {}", info.state);
                        println!("created_at: {}", info.created_at);
                        println!("expires_at: {}", info.expires_at);
                        Ok(())
                    }
                },
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
        AdminDelegationAction::List { profile } => {
            let profile_id = profile.as_deref().map(parse_profile_id).transpose()?;
            let req = AdminRequest::ListDelegations { profile_id };
            let resp = client
                .request(req)
                .map_err(|e| Error::Other(e.to_string()))?;
            match resp {
                passless_core::agent::AdminResponse::DelegationList(list) => match output {
                    OutputFormat::Json => admin_output_json(&list),
                    OutputFormat::Plain => {
                        println!("total: {}", list.total);
                        for g in &list.grants {
                            println!(
                                "  {} profile={} rp={} state={}",
                                g.grant_id, g.profile_id, g.rp_id, g.state
                            );
                        }
                        Ok(())
                    }
                },
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
        AdminDelegationAction::Revoke { grant_id, confirm } => {
            if !confirm {
                return Err(Error::Other(
                    "destructive action requires --confirm flag".to_string(),
                ));
            }
            let req = AdminRequest::RevokeDelegation {
                grant_id: parse_grant_id(grant_id)?,
            };
            let resp = client
                .request(req)
                .map_err(|e| Error::Other(e.to_string()))?;
            match resp {
                passless_core::agent::AdminResponse::DelegationRevoked => {
                    #[derive(Serialize)]
                    struct RevokedOut {
                        grant_id: String,
                        revoked: bool,
                    }
                    match output {
                        OutputFormat::Json => admin_output_json(&RevokedOut {
                            grant_id: grant_id.clone(),
                            revoked: true,
                        }),
                        OutputFormat::Plain => {
                            println!("grant_id: {}", grant_id);
                            println!("revoked: true");
                            Ok(())
                        }
                    }
                }
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
        AdminDelegationAction::RequestRegistration {
            profile,
            rp,
            session_ttl,
            reason,
        } => {
            let req = AdminRequest::RequestRegistration {
                profile_id: parse_profile_id(profile)?,
                rp_id: rp.clone(),
                max_session_ttl: *session_ttl,
                reason: reason.clone(),
            };
            let resp = client
                .request(req)
                .map_err(|e| Error::Other(e.to_string()))?;
            match resp {
                passless_core::agent::AdminResponse::RegistrationGranted {
                    registration_grant_id,
                } => {
                    #[derive(Serialize)]
                    struct RegistrationGrantedOut {
                        registration_grant_id: String,
                        rp_id: String,
                        session_ttl: u64,
                    }
                    let out = RegistrationGrantedOut {
                        registration_grant_id: registration_grant_id.to_string(),
                        rp_id: rp.clone(),
                        session_ttl: *session_ttl,
                    };
                    match output {
                        OutputFormat::Json => admin_output_json(&out),
                        OutputFormat::Plain => {
                            println!("registration_grant_id: {}", out.registration_grant_id);
                            println!("rp_id: {}", out.rp_id);
                            println!("session_ttl: {}", out.session_ttl);
                            Ok(())
                        }
                    }
                }
                _ => Err(Error::Other(
                    "unexpected response for registration request".to_string(),
                )),
            }
        }
    }
}

fn dispatch_admin_session(output: OutputFormat, action: &AdminSessionAction) -> Result<()> {
    let mut client = connect_admin_client()?;
    match action {
        AdminSessionAction::Show { session_id } => {
            let req = AdminRequest::ShowSession {
                session_id: parse_session_id(session_id)?,
            };
            let resp = client
                .request(req)
                .map_err(|e| Error::Other(e.to_string()))?;
            match resp {
                passless_core::agent::AdminResponse::SessionInfo(info) => match output {
                    OutputFormat::Json => admin_output_json(&info),
                    OutputFormat::Plain => {
                        println!("session_id: {}", info.session_id);
                        println!("profile_id: {}", info.profile_id);
                        println!("pid: {}", info.pid);
                        println!("created_at: {}", info.created_at);
                        println!("expires_at: {}", info.expires_at);
                        Ok(())
                    }
                },
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
        AdminSessionAction::List { profile } => {
            let profile_id = profile.as_deref().map(parse_profile_id).transpose()?;
            let req = AdminRequest::ListSessions { profile_id };
            let resp = client
                .request(req)
                .map_err(|e| Error::Other(e.to_string()))?;
            match resp {
                passless_core::agent::AdminResponse::SessionList(list) => match output {
                    OutputFormat::Json => admin_output_json(&list),
                    OutputFormat::Plain => {
                        println!("total: {}", list.total);
                        for s in &list.sessions {
                            println!("  {} profile={} pid={}", s.session_id, s.profile_id, s.pid);
                        }
                        Ok(())
                    }
                },
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
        AdminSessionAction::Revoke {
            session_id,
            confirm,
        } => {
            if !confirm {
                return Err(Error::Other(
                    "destructive action requires --confirm flag".to_string(),
                ));
            }
            let req = AdminRequest::RevokeSession {
                session_id: parse_session_id(session_id)?,
            };
            let resp = client
                .request(req)
                .map_err(|e| Error::Other(e.to_string()))?;
            match resp {
                passless_core::agent::AdminResponse::SessionRevoked => {
                    #[derive(Serialize)]
                    struct RevokedOut {
                        session_id: String,
                        revoked: bool,
                    }
                    match output {
                        OutputFormat::Json => admin_output_json(&RevokedOut {
                            session_id: session_id.clone(),
                            revoked: true,
                        }),
                        OutputFormat::Plain => {
                            println!("session_id: {}", session_id);
                            println!("revoked: true");
                            Ok(())
                        }
                    }
                }
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
    }
}

fn dispatch_browser(output: OutputFormat, action: &AdminBrowserAction) -> Result<()> {
    let mut client = connect_admin_client()?;
    match action {
        AdminBrowserAction::Launch { profile, url } => {
            let profile_id = parse_profile_id(profile)?;
            let req = AdminRequest::LaunchBrowser {
                profile_id,
                start_url: url.clone(),
            };
            let resp = client
                .request(req)
                .map_err(|e| Error::Other(e.to_string()))?;
            match resp {
                passless_core::agent::AdminResponse::BrowserLaunched(info) => match output {
                    OutputFormat::Json => admin_output_json(&info),
                    OutputFormat::Plain => {
                        println!("lease_id: {}", info.lease_id);
                        println!("profile_id: {}", info.profile_id);
                        println!("pid: {}", info.pid);
                        if let Some(ref url) = info.start_url {
                            println!("start_url: {}", url);
                        }
                        Ok(())
                    }
                },
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
    }
}

fn dispatch_audit(output: OutputFormat, action: &AdminAuditAction) -> Result<()> {
    let mut client = connect_admin_client()?;
    match action {
        AdminAuditAction::Status => {
            let resp = client
                .request(AdminRequest::AuditStatus)
                .map_err(|e| Error::Other(e.to_string()))?;
            match resp {
                passless_core::agent::AdminResponse::AuditStatus(status) => match output {
                    OutputFormat::Json => admin_output_json(&status),
                    OutputFormat::Plain => {
                        println!("enabled: {}", status.enabled);
                        println!("entry_count: {}", status.entry_count);
                        println!(
                            "latest_entry_at: {}",
                            status
                                .latest_entry_at
                                .map_or("none".to_string(), |v| v.to_string())
                        );
                        Ok(())
                    }
                },
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
        AdminAuditAction::Verify => {
            let resp = client
                .request(AdminRequest::AuditVerify)
                .map_err(|e| Error::Other(e.to_string()))?;
            match resp {
                passless_core::agent::AdminResponse::AuditVerified(verified) => match output {
                    OutputFormat::Json => admin_output_json(&verified),
                    OutputFormat::Plain => {
                        println!("verified: {}", verified.verified);
                        println!("entries_checked: {}", verified.entries_checked);
                        println!("integrity_ok: {}", verified.integrity_ok);
                        Ok(())
                    }
                },
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
        AdminAuditAction::Export { format } => {
            let fmt = match format {
                AdminAuditExportFormat::Json => AuditExportFormat::Json,
                AdminAuditExportFormat::Csv => AuditExportFormat::Csv,
            };
            let resp = client
                .request(AdminRequest::AuditExport { format: fmt })
                .map_err(|e| Error::Other(e.to_string()))?;
            match resp {
                passless_core::agent::AdminResponse::AuditExported(exported) => match output {
                    OutputFormat::Json => admin_output_json(&exported),
                    OutputFormat::Plain => {
                        println!("entry_count: {}", exported.entry_count);
                        println!("format: {}", exported.format);
                        println!("path: {}", exported.path);
                        Ok(())
                    }
                },
                _ => Err(Error::Other("unexpected response".to_string())),
            }
        }
    }
}

fn dispatch_shutdown(output: OutputFormat, confirm: bool) -> Result<()> {
    if !confirm {
        return Err(Error::Other("shutdown requires --confirm flag".to_string()));
    }
    let mut client = connect_admin_client()?;
    let resp = client
        .request(AdminRequest::Shutdown)
        .map_err(|e| Error::Other(e.to_string()))?;
    match resp {
        passless_core::agent::AdminResponse::ShutdownAccepted => {
            #[derive(Serialize)]
            struct ShutdownOut {
                shutdown_initiated: bool,
            }
            match output {
                OutputFormat::Json => admin_output_json(&ShutdownOut {
                    shutdown_initiated: true,
                }),
                OutputFormat::Plain => {
                    println!("shutdown_initiated: true");
                    Ok(())
                }
            }
        }
        _ => Err(Error::Other("unexpected response".to_string())),
    }
}

fn selected_agents(
    target: AgentSkillTarget,
    home: &Path,
    project: &Path,
) -> Result<Vec<AgentKind>> {
    let explicit = match target {
        AgentSkillTarget::Auto => None,
        AgentSkillTarget::Opencode => Some(AgentKind::Opencode),
        AgentSkillTarget::Claude => Some(AgentKind::Claude),
        AgentSkillTarget::Pi => Some(AgentKind::Pi),
    };
    if let Some(agent) = explicit {
        return Ok(vec![agent]);
    }

    let agents: Vec<_> = AgentKind::ALL
        .into_iter()
        .filter(|agent| agent_is_detected(*agent, home, project))
        .collect();
    if agents.is_empty() {
        return Err(Error::Other(
            "No supported coding agent was detected. Specify one of: opencode, claude, pi"
                .to_string(),
        ));
    }
    Ok(agents)
}

fn agent_is_detected(agent: AgentKind, home: &Path, project: &Path) -> bool {
    agent.user_config_path(home).is_dir()
        || match agent {
            AgentKind::Opencode => project.join(".opencode").is_dir(),
            AgentKind::Claude => project.join(".claude").is_dir(),
            AgentKind::Pi => project.join(".pi").is_dir(),
        }
        || command_exists(agent.command())
}

fn command_exists(command: &str) -> bool {
    env::var_os("PATH").is_some_and(|path| {
        env::split_paths(&path).any(|directory| {
            let candidate = directory.join(command);
            fs::metadata(candidate).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
    })
}

fn project_root(current_dir: &Path) -> PathBuf {
    current_dir
        .ancestors()
        .find(|path| path.join(".git").exists())
        .unwrap_or(current_dir)
        .to_path_buf()
}

fn install_skill(path: &Path, trusted_root: &Path, force: bool) -> Result<InstallStatus> {
    let skill_dir = path.parent().ok_or_else(|| {
        Error::Other(format!(
            "Invalid skill installation path: {}",
            path.display()
        ))
    })?;
    reject_symlink_components(trusted_root, skill_dir)?;

    if let Ok(metadata) = fs::symlink_metadata(skill_dir) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(Error::Other(format!(
                "Refusing to install through non-directory skill path: {}",
                skill_dir.display()
            )));
        }
    } else {
        fs::create_dir_all(skill_dir).map_err(|error| {
            Error::Other(format!(
                "Failed to create skill directory {}: {}",
                skill_dir.display(),
                error
            ))
        })?;
        fs::set_permissions(skill_dir, fs::Permissions::from_mode(0o755))?;
    }
    reject_symlink_components(trusted_root, skill_dir)?;

    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Error::Other(format!(
                "Refusing to replace non-regular skill file: {}",
                path.display()
            )));
        }
        if fs::read(path)? == SKILL_CONTENT.as_bytes() {
            return Ok(InstallStatus::Current);
        }
        if !force {
            return Err(Error::Other(format!(
                "A different skill already exists at {}. Re-run with --force to replace it",
                path.display()
            )));
        }
    }

    let (temp_path, mut temp) = create_temp_file(skill_dir)?;

    let write_result = (|| -> std::io::Result<()> {
        temp.write_all(SKILL_CONTENT.as_bytes())?;
        temp.sync_all()?;
        drop(temp);

        if force {
            fs::rename(&temp_path, path)?;
        } else {
            fs::hard_link(&temp_path, path)?;
            fs::remove_file(&temp_path)?;
        }
        File::open(skill_dir)?.sync_all()
    })();

    if let Err(error) = write_result {
        let _ = fs::remove_file(&temp_path);
        if error.kind() == std::io::ErrorKind::AlreadyExists && !force {
            if fs::read(path).is_ok_and(|content| content == SKILL_CONTENT.as_bytes()) {
                return Ok(InstallStatus::Current);
            }
            return Err(Error::Other(format!(
                "A different skill was concurrently installed at {}",
                path.display()
            )));
        }
        return Err(Error::Other(format!(
            "Failed to install skill at {}: {}",
            path.display(),
            error
        )));
    }

    Ok(InstallStatus::Installed)
}

fn reject_symlink_components(trusted_root: &Path, path: &Path) -> Result<()> {
    let relative = path.strip_prefix(trusted_root).map_err(|_| {
        Error::Other(format!(
            "Skill path {} is outside trusted root {}",
            path.display(),
            trusted_root.display()
        ))
    })?;
    let mut current = trusted_root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(Error::Other(format!(
                    "Refusing to install through symlinked path component: {}",
                    current.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn create_temp_file(skill_dir: &Path) -> Result<(PathBuf, File)> {
    for _ in 0..16 {
        let temp_path = skill_dir.join(format!(
            ".SKILL.md.{}.{:016x}.tmp",
            std::process::id(),
            rand::random::<u64>()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&temp_path)
        {
            Ok(file) => return Ok((temp_path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(Error::Other(format!(
                    "Failed to create temporary skill file {}: {}",
                    temp_path.display(),
                    error
                )));
            }
        }
    }
    Err(Error::Other(format!(
        "Failed to allocate a temporary skill file in {}",
        skill_dir.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::symlink;

    use tempfile::tempdir;

    #[test]
    fn skill_paths_match_agent_conventions() {
        let home = Path::new("/home/test");
        let project = Path::new("/work/project");

        assert_eq!(
            AgentKind::Opencode.skill_path(AgentSkillScope::User, home, project),
            Path::new("/home/test/.config/opencode/skills/passless-agent/SKILL.md")
        );
        assert_eq!(
            AgentKind::Claude.skill_path(AgentSkillScope::User, home, project),
            Path::new("/home/test/.claude/skills/passless-agent/SKILL.md")
        );
        assert_eq!(
            AgentKind::Opencode.skill_path(AgentSkillScope::Project, home, project),
            Path::new("/work/project/.opencode/skills/passless-agent/SKILL.md")
        );
        assert_eq!(
            AgentKind::Claude.skill_path(AgentSkillScope::Project, home, project),
            Path::new("/work/project/.claude/skills/passless-agent/SKILL.md")
        );
    }

    #[test]
    fn pi_skill_paths_match_official_conventions() {
        let home = Path::new("/home/test");
        let project = Path::new("/work/project");

        assert_eq!(
            AgentKind::Pi.skill_path(AgentSkillScope::User, home, project),
            Path::new("/home/test/.pi/agent/skills/passless-agent/SKILL.md")
        );
        assert_eq!(
            AgentKind::Pi.skill_path(AgentSkillScope::Project, home, project),
            Path::new("/work/project/.pi/skills/passless-agent/SKILL.md")
        );
    }

    #[test]
    fn user_config_paths_match_known_conventions() {
        let home = Path::new("/home/test");

        assert_eq!(
            AgentKind::Opencode.user_config_path(home),
            Path::new("/home/test/.config/opencode")
        );
        assert_eq!(
            AgentKind::Claude.user_config_path(home),
            Path::new("/home/test/.claude")
        );
        assert_eq!(
            AgentKind::Pi.user_config_path(home),
            Path::new("/home/test/.pi/agent")
        );
    }

    #[test]
    fn all_target_scope_combinations_produce_unique_paths() {
        let home = Path::new("/home/test");
        let project = Path::new("/work/project");
        let mut paths = Vec::new();
        for agent in AgentKind::ALL {
            for scope in [AgentSkillScope::User, AgentSkillScope::Project] {
                let p = agent.skill_path(scope, home, project);
                assert!(!paths.contains(&p), "duplicate path: {}", p.display());
                paths.push(p);
            }
        }
        assert_eq!(paths.len(), 6);
    }

    #[test]
    fn explicit_selection_does_not_require_detection() {
        let dir = tempdir().unwrap();
        let selected = selected_agents(AgentSkillTarget::Claude, dir.path(), dir.path()).unwrap();
        assert_eq!(selected, vec![AgentKind::Claude]);
    }

    #[test]
    fn explicit_opencode_does_not_require_detection() {
        let dir = tempdir().unwrap();
        let selected = selected_agents(AgentSkillTarget::Opencode, dir.path(), dir.path()).unwrap();
        assert_eq!(selected, vec![AgentKind::Opencode]);
    }

    #[test]
    fn explicit_pi_does_not_require_detection() {
        let dir = tempdir().unwrap();
        let selected = selected_agents(AgentSkillTarget::Pi, dir.path(), dir.path()).unwrap();
        assert_eq!(selected, vec![AgentKind::Pi]);
    }

    #[test]
    fn auto_selects_configured_agents() {
        let home = tempdir().unwrap();
        let project = tempdir().unwrap();
        fs::create_dir_all(home.path().join(".config/opencode")).unwrap();
        fs::create_dir_all(home.path().join(".claude")).unwrap();

        let selected =
            selected_agents(AgentSkillTarget::Auto, home.path(), project.path()).unwrap();
        assert!(selected.contains(&AgentKind::Opencode));
        assert!(selected.contains(&AgentKind::Claude));
    }

    #[test]
    fn auto_detects_via_project_directory() {
        let home = tempdir().unwrap();
        let project = tempdir().unwrap();
        fs::create_dir_all(project.path().join(".opencode")).unwrap();

        let selected =
            selected_agents(AgentSkillTarget::Auto, home.path(), project.path()).unwrap();
        assert!(selected.contains(&AgentKind::Opencode));
    }

    #[test]
    fn auto_detects_pi_via_user_config() {
        let home = tempdir().unwrap();
        let project = tempdir().unwrap();
        fs::create_dir_all(home.path().join(".pi/agent")).unwrap();

        let selected =
            selected_agents(AgentSkillTarget::Auto, home.path(), project.path()).unwrap();
        assert!(selected.contains(&AgentKind::Pi));
    }

    #[test]
    fn auto_detects_pi_via_project_directory() {
        let home = tempdir().unwrap();
        let project = tempdir().unwrap();
        fs::create_dir_all(project.path().join(".pi")).unwrap();

        let selected =
            selected_agents(AgentSkillTarget::Auto, home.path(), project.path()).unwrap();
        assert!(selected.contains(&AgentKind::Pi));
    }

    #[test]
    fn auto_detects_via_path_command() {
        let home = tempdir().unwrap();
        let project = tempdir().unwrap();
        let bin_dir = tempdir().unwrap();

        let fake_opencode = bin_dir.path().join("opencode");
        fs::write(&fake_opencode, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&fake_opencode, fs::Permissions::from_mode(0o755)).unwrap();

        let old_path = env::var("PATH").ok();
        unsafe { env::set_var("PATH", bin_dir.path()) };
        let selected =
            selected_agents(AgentSkillTarget::Auto, home.path(), project.path()).unwrap();
        if let Some(old) = old_path {
            unsafe { env::set_var("PATH", old) };
        }
        assert!(selected.contains(&AgentKind::Opencode));
    }

    #[test]
    fn auto_fails_when_no_agent_detected() {
        let home = tempdir().unwrap();
        let project = tempdir().unwrap();

        let old_path = env::var("PATH").ok();
        unsafe { env::set_var("PATH", tempdir().unwrap().path()) };
        let result = selected_agents(AgentSkillTarget::Auto, home.path(), project.path());
        if let Some(old) = old_path {
            unsafe { env::set_var("PATH", old) };
        }
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("No supported coding agent")
        );
    }

    #[test]
    fn install_is_idempotent_and_requires_force_for_changes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("skills/passless-agent/SKILL.md");

        assert_eq!(
            install_skill(&path, dir.path(), false).unwrap(),
            InstallStatus::Installed
        );
        assert_eq!(
            install_skill(&path, dir.path(), false).unwrap(),
            InstallStatus::Current
        );

        fs::write(&path, "custom skill").unwrap();
        assert!(install_skill(&path, dir.path(), false).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "custom skill");

        assert_eq!(
            install_skill(&path, dir.path(), true).unwrap(),
            InstallStatus::Installed
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), SKILL_CONTENT);
    }

    #[test]
    fn installed_skill_bytes_match_bundled_asset() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("skills/passless-agent/SKILL.md");
        install_skill(&path, dir.path(), false).unwrap();
        assert_eq!(fs::read(&path).unwrap(), SKILL_CONTENT.as_bytes());
    }

    #[test]
    fn install_creates_parent_directories_with_correct_mode() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a/b/c/passless-agent/SKILL.md");
        install_skill(&path, dir.path(), false).unwrap();

        let skill_dir = path.parent().unwrap();
        let mode = fs::metadata(skill_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }

    #[test]
    fn install_temp_file_is_cleaned_up() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("skills/passless-agent/SKILL.md");
        install_skill(&path, dir.path(), false).unwrap();

        let skill_dir = path.parent().unwrap();
        let leftover: Vec<_> = fs::read_dir(skill_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".SKILL.md."))
            .collect();
        assert!(leftover.is_empty(), "temporary file was not cleaned up");
    }

    #[test]
    fn install_rejects_symlink_target() {
        let dir = tempdir().unwrap();
        let skill_dir = dir.path().join("skills/passless-agent");
        fs::create_dir_all(&skill_dir).unwrap();
        let outside = dir.path().join("outside");
        fs::write(&outside, "do not replace").unwrap();
        let path = skill_dir.join("SKILL.md");
        symlink(&outside, &path).unwrap();

        assert!(install_skill(&path, dir.path(), true).is_err());
        assert_eq!(fs::read_to_string(outside).unwrap(), "do not replace");
    }

    #[test]
    fn install_rejects_symlinked_directory_component() {
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        symlink(outside.path(), dir.path().join("skills")).unwrap();
        let path = dir.path().join("skills/passless-agent/SKILL.md");

        assert!(install_skill(&path, dir.path(), false).is_err());
        assert!(!outside.path().join("passless-agent/SKILL.md").exists());
    }

    #[test]
    fn install_rejects_non_directory_skill_parent() {
        let dir = tempdir().unwrap();
        let blocker = dir.path().join("skills");
        fs::write(&blocker, "not a directory").unwrap();
        let path = dir.path().join("skills/passless-agent/SKILL.md");

        assert!(install_skill(&path, dir.path(), false).is_err());
    }

    #[test]
    fn install_rejects_symlinked_skill_parent() {
        let dir = tempdir().unwrap();
        let real_dir = tempdir().unwrap();
        symlink(real_dir.path(), dir.path().join("skills")).unwrap();
        let path = dir.path().join("skills/passless-agent/SKILL.md");

        assert!(install_skill(&path, dir.path(), false).is_err());
    }

    #[test]
    fn concurrent_install_race_detected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("skills/passless-agent/SKILL.md");
        let skill_dir = path.parent().unwrap();
        fs::create_dir_all(skill_dir).unwrap();

        fs::write(&path, "different content").unwrap();

        let result = install_skill(&path, dir.path(), false);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("different skill") || err_msg.contains("concurrently"),
            "unexpected error: {}",
            err_msg
        );
    }

    #[test]
    fn force_overwrites_different_content() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("skills/passless-agent/SKILL.md");
        let skill_dir = path.parent().unwrap();
        fs::create_dir_all(skill_dir).unwrap();

        fs::write(&path, "stale content").unwrap();
        assert_eq!(
            install_skill(&path, dir.path(), true).unwrap(),
            InstallStatus::Installed
        );
        assert_eq!(fs::read(&path).unwrap(), SKILL_CONTENT.as_bytes());
    }

    #[test]
    fn project_root_uses_git_worktree() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join(".git")).unwrap();
        let nested = dir.path().join("a/b");
        fs::create_dir_all(&nested).unwrap();

        assert_eq!(project_root(&nested), dir.path());
    }

    #[test]
    fn project_root_falls_back_to_current_dir() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("no/git/here");
        fs::create_dir_all(&nested).unwrap();

        assert_eq!(project_root(&nested), nested);
    }

    #[test]
    fn project_root_handles_git_worktree_file() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join(".git"), "gitdir: /somewhere").unwrap();
        let nested = dir.path().join("sub");
        fs::create_dir(&nested).unwrap();

        assert_eq!(project_root(&nested), dir.path());
    }

    #[test]
    fn reject_symlink_components_walks_each_segment() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join("real")).unwrap();
        symlink(dir.path().join("real"), dir.path().join("link")).unwrap();

        assert!(reject_symlink_components(dir.path(), &dir.path().join("link/sub")).is_err());
    }

    #[test]
    fn reject_symlink_components_accepts_clean_path() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("a/b/c")).unwrap();

        assert!(reject_symlink_components(dir.path(), &dir.path().join("a/b/c")).is_ok());
    }

    #[test]
    fn reject_symlink_components_rejects_escape() {
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();

        let result = reject_symlink_components(dir.path(), outside.path());
        assert!(result.is_err());
    }

    #[test]
    fn command_exists_finds_executable() {
        let bin_dir = tempdir().unwrap();
        let fake = bin_dir.path().join("test-cmd-exists");
        fs::write(&fake, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();

        let old_path = env::var("PATH").ok();
        unsafe { env::set_var("PATH", bin_dir.path()) };
        assert!(command_exists("test-cmd-exists"));
        if let Some(old) = old_path {
            unsafe { env::set_var("PATH", old) };
        }
    }

    #[test]
    fn command_exists_rejects_non_executable() {
        let bin_dir = tempdir().unwrap();
        let fake = bin_dir.path().join("test-cmd-noexec");
        fs::write(&fake, "not executable").unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o644)).unwrap();

        let old_path = env::var("PATH").ok();
        unsafe { env::set_var("PATH", bin_dir.path()) };
        assert!(!command_exists("test-cmd-noexec"));
        if let Some(old) = old_path {
            unsafe { env::set_var("PATH", old) };
        }
    }

    #[test]
    fn create_temp_file_produces_unique_names() {
        let dir = tempdir().unwrap();
        let (_, f1) = create_temp_file(dir.path()).unwrap();
        let (_, f2) = create_temp_file(dir.path()).unwrap();
        drop(f1);
        drop(f2);

        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn profile_check_request_uses_profile_check_variant() {
        use passless_core::agent::ProfileId;
        use passless_core::agent::protocol::AdminRequest;

        let profile_id = ProfileId::new("test-profile").unwrap();
        let req = AdminRequest::ProfileCheck {
            profile_id: profile_id.clone(),
        };

        match req {
            AdminRequest::ProfileCheck { profile_id: pid } => {
                assert_eq!(pid, profile_id);
            }
            _ => panic!("expected ProfileCheck variant"),
        }
    }

    #[test]
    fn profile_diagnostic_report_serializes_to_json() {
        use passless_core::agent::ProfileDiagnosticReport;
        use passless_core::agent::protocol::{DoctorCheck, EndpointDiagnosticState};

        let report = ProfileDiagnosticReport {
            profile_id: "test".into(),
            enabled: true,
            mode: "Isolated".into(),
            endpoint_state: EndpointDiagnosticState::Ready,
            browser_lease_state: None,
            policy_generation: 42,
            audit_gate_healthy: true,
            pin_storage_available: true,
            pin_set: true,
            checks: vec![DoctorCheck {
                name: "enabled".into(),
                passed: true,
                message: "profile is enabled".into(),
            }],
        };

        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains(r#""profile_id":"test""#));
        assert!(json.contains(r#""enabled":true"#));
        assert!(json.contains(r#""policy_generation":42"#));
        assert!(json.contains(r#""audit_gate_healthy":true"#));
    }
}
