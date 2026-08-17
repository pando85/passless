#!/usr/bin/env python3
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one match, found {count}: {old[:100]!r}")
    p.write_text(text.replace(old, new, 1))


# Protocol: a minor-versioned, principal-scoped idempotent browser lifecycle operation.
replace_once(
    "passless-core/src/agent/protocol.rs",
    "pub const CURRENT_VERSION: ProtocolVersion = ProtocolVersion { major: 1, minor: 1 };",
    "pub const CURRENT_VERSION: ProtocolVersion = ProtocolVersion { major: 1, minor: 2 };",
)
replace_once(
    "passless-core/src/agent/protocol.rs",
    "const MAX_CDP_TIMEOUT_MS: u32 = 30_000;\n",
    "const MAX_CDP_TIMEOUT_MS: u32 = 30_000;\nconst MAX_START_URL_LEN: usize = 2048;\n",
)
replace_once(
    "passless-core/src/agent/protocol.rs",
    "    BrowserStatus,\n    EndpointStatus,\n    BrowserControl {",
    "    BrowserStatus,\n    EnsureBrowser {\n        #[serde(skip_serializing_if = \"Option::is_none\")]\n        start_url: Option<String>,\n    },\n    EndpointStatus,\n    BrowserControl {",
)
replace_once(
    "passless-core/src/agent/protocol.rs",
    "    BrowserStatus(BrowserStatusResponse),\n    EndpointStatus(EndpointStatusResponse),",
    "    BrowserStatus(BrowserStatusResponse),\n    BrowserEnsured(BrowserStatusResponse),\n    EndpointStatus(EndpointStatusResponse),",
)
replace_once(
    "passless-core/src/agent/protocol.rs",
    "            Self::ListCredentials { .. } => {}\n            Self::BrowserControl {",
    "            Self::ListCredentials { .. } => {}\n            Self::EnsureBrowser { start_url } => {\n                if let Some(url) = start_url {\n                    check_str(url, \"start_url\", MAX_START_URL_LEN, &mut errors);\n                }\n            }\n            Self::BrowserControl {",
)

# Runtime: compile the focused child module and route only fully verified principal requests to it.
replace_once(
    "cmd/passless/src/agent/runtime.rs",
    "#[cfg(feature = \"agent\")]\nuse passless_uhid::RawUhidDevice;\n\nconst SHUTDOWN_TIMEOUT",
    "#[cfg(feature = \"agent\")]\nuse passless_uhid::RawUhidDevice;\n\nmod browser_ensure;\n\nconst SHUTDOWN_TIMEOUT",
)
replace_once(
    "cmd/passless/src/agent/runtime.rs",
    "            PrincipalRequest::BrowserStatus => self.handle_browser_status(&profile_id, profile),\n            PrincipalRequest::EndpointStatus => {",
    "            PrincipalRequest::BrowserStatus => self.handle_browser_status(&profile_id, profile),\n            PrincipalRequest::EnsureBrowser { start_url } => self.handle_ensure_browser(\n                &profile_id,\n                &managed.session_id,\n                &managed.process_digest,\n                start_url.as_deref(),\n                profile,\n            ),\n            PrincipalRequest::EndpointStatus => {",
)

# Fix the helper to import the ID from passless-core rather than the browser module's private import.
replace_once(
    "cmd/passless/src/agent/runtime/browser_ensure.rs",
    "use passless_core::agent::{PrincipalSessionId, ProfileId};\n\nuse super::{ActiveBrowserLease, AgentRuntime, ProfileRuntime};\nuse crate::agent::browser::{BrowserConfig, BrowserLeaseId, LeaseState};",
    "use passless_core::agent::{BrowserLeaseId, PrincipalSessionId, ProfileId};\n\nuse super::{ActiveBrowserLease, AgentRuntime, ProfileRuntime};\nuse crate::agent::browser::{BrowserConfig, LeaseState};",
)

# CLI: expose one self-relaunching command. The admin side is used only to create the normal
# principal session; browser lifecycle inside that session is principal IPC only.
replace_once(
    "passless-core/src/config.rs",
    "    /// Launch a detached principal session\n    Run {",
    "    /// Run Playwright MCP with lazy access to the profile's trusted CDP browser\n    PlaywrightMcp {\n        /// Profile to bind the Playwright session to\n        #[arg(long, value_name = \"PROFILE\")]\n        profile: String,\n        /// Absolute Playwright MCP executable and arguments\n        #[arg(last = true, required = true)]\n        command: Vec<std::path::PathBuf>,\n    },\n    /// Launch a detached principal session\n    Run {",
)
replace_once(
    "cmd/passless/src/commands/agent.rs",
    "    match action {\n        AgentCommand::Run {\n            profile: run_profile,\n            command,\n        } => dispatch_run(output, run_profile, command),",
    "    match action {\n        AgentCommand::PlaywrightMcp {\n            profile: playwright_profile,\n            command,\n        } => dispatch_playwright_mcp(output, playwright_profile, command),\n        AgentCommand::Run {\n            profile: run_profile,\n            command,\n        } => dispatch_run(output, run_profile, command),",
)
replace_once(
    "cmd/passless/src/commands/agent.rs",
    "                AgentCommand::Run { .. } => unreachable!(),",
    "                AgentCommand::PlaywrightMcp { .. } | AgentCommand::Run { .. } => unreachable!(),",
)
replace_once(
    "cmd/passless/src/commands/agent.rs",
    "fn dispatch_doctor(output: OutputFormat, profile: &str) -> Result<()> {",
    "fn dispatch_playwright_mcp(\n    output: OutputFormat,\n    profile: &str,\n    command: &[PathBuf],\n) -> Result<()> {\n    match super::playwright_mcp::try_run_as_principal(profile, command)? {\n        Some(()) => Ok(()),\n        None => {\n            let current_exe = std::env::current_exe().map_err(|e| {\n                Error::Other(format!(\"failed to resolve passless executable: {e}\"))\n            })?;\n            let mut wrapper_command = vec![\n                current_exe,\n                PathBuf::from(\"agent\"),\n                PathBuf::from(\"playwright-mcp\"),\n                PathBuf::from(\"--profile\"),\n                PathBuf::from(profile),\n                PathBuf::from(\"--\"),\n            ];\n            wrapper_command.extend(command.iter().cloned());\n            dispatch_run(output, profile, &wrapper_command)\n        }\n    }\n}\n\nfn dispatch_doctor(output: OutputFormat, profile: &str) -> Result<()> {",
)

print("Playwright MCP source integration applied successfully")
