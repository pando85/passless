use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::Duration;

use passless_config_doc::ConfigDoc;
use serde::{Deserialize, Serialize};

use super::ids::{CredentialRef, ProfileId};
use super::resolve::{GrantSource, MatchedRule, resolve_rules};
use crate::error::{Error, Result};

const MAX_DURATION_SECS: u64 = 86_400 * 365;
const MIN_DURATION_SECS: u64 = 1;

pub const ANY_RP_ID: &str = "*";
/// The one single-label RP ID that is valid, for exact rules only (plan R15).
pub const LOCALHOST_RP_ID: &str = "localhost";
/// The most RP IDs one browser session grant can cover (see `AgentProfileConfig::rule_rp_ids`).
pub const MAX_GRANT_RP_IDS: usize = 32;

const DEFAULT_MAX_OPERATIONS: u16 = 64;
const MAX_OPERATIONS: u16 = 4096;
const DEFAULT_MAX_CONCURRENT_SESSIONS: u16 = MAX_CONCURRENT_SESSIONS;
const MAX_CONCURRENT_SESSIONS: u16 = 64;

fn default_max_operations() -> u16 {
    DEFAULT_MAX_OPERATIONS
}

fn default_max_concurrent_sessions() -> u16 {
    DEFAULT_MAX_CONCURRENT_SESSIONS
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CredentialSelection {
    #[default]
    Single,
    FirstMatching,
    Newest,
    Credential(CredentialRef),
}

impl fmt::Display for CredentialSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Single => f.write_str("single"),
            Self::FirstMatching => f.write_str("first-matching"),
            Self::Newest => f.write_str("newest"),
            Self::Credential(reference) => write!(f, "credential:{reference}"),
        }
    }
}

impl Serialize for CredentialSelection {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let value = match self {
            Self::Single => "single".to_string(),
            Self::FirstMatching => "first-matching".to_string(),
            Self::Newest => "newest".to_string(),
            Self::Credential(reference) => format!("credential:{reference}"),
        };
        serializer.serialize_str(&value)
    }
}

impl<'de> Deserialize<'de> for CredentialSelection {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "single" => Ok(Self::Single),
            "first-matching" | "first_matching" => Ok(Self::FirstMatching),
            "newest" => Ok(Self::Newest),
            _ => value
                .strip_prefix("credential:")
                .ok_or_else(|| serde::de::Error::custom(
                    "credential_selection must be single, first-matching, newest, or credential:<ref>",
                ))
                .and_then(|reference| {
                    CredentialRef::from_hex(reference)
                        .map(Self::Credential)
                        .map_err(serde::de::Error::custom)
                }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentMode {
    #[serde(rename = "same-user", alias = "same_user")]
    SameUser,
    #[serde(rename = "isolated")]
    Isolated,
}

impl fmt::Display for AgentMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentMode::SameUser => write!(f, "same-user"),
            AgentMode::Isolated => write!(f, "isolated"),
        }
    }
}

impl std::str::FromStr for AgentMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "same-user" | "same_user" => Ok(AgentMode::SameUser),
            "isolated" => Ok(AgentMode::Isolated),
            _ => Err(format!(
                "Invalid agent mode '{}'. Must be: same-user, isolated",
                s
            )),
        }
    }
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CdpExposeMode {
    #[default]
    Pipe,
    Port,
}

impl fmt::Display for CdpExposeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pipe => f.write_str("pipe"),
            Self::Port => f.write_str("port"),
        }
    }
}

impl std::str::FromStr for CdpExposeMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "pipe" => Ok(CdpExposeMode::Pipe),
            "port" => Ok(CdpExposeMode::Port),
            _ => Err(format!(
                "Invalid CDP expose mode '{}'. Must be: pipe, port",
                s
            )),
        }
    }
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserScope {
    #[default]
    Session,
    Profile,
}

impl fmt::Display for BrowserScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session => f.write_str("session"),
            Self::Profile => f.write_str("profile"),
        }
    }
}

impl std::str::FromStr for BrowserScope {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "session" => Ok(BrowserScope::Session),
            "profile" => Ok(BrowserScope::Profile),
            _ => Err(format!(
                "Invalid browser scope '{}'. Must be: session, profile",
                s
            )),
        }
    }
}

/// What a rule does for one action (ADR 0014 section 6.1).
///
/// * `deny`: reject before credential enumeration or key access; never prompts.
/// * `allow`: authorize autonomously. UP and UV come from validated agent-session evidence; rules
///   carry no evidence fields.
/// * `request`: not authorized yet; the ceremony raises an escalation (P7). Until the escalation
///   service lands, a `request` decision denies with `escalation_unavailable`.
///
/// A missing action denies.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    #[default]
    Deny,
    Allow,
    Request,
}

impl RuleAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Allow => "allow",
            Self::Request => "request",
        }
    }
}

impl fmt::Display for RuleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The two ceremonies a rule governs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyAction {
    Authenticate,
    Register,
}

impl PolicyAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authenticate => "authenticate",
            Self::Register => "register",
        }
    }
}

impl fmt::Display for PolicyAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ConfigDoc)]
#[serde(deny_unknown_fields)]
pub struct AgentRpRule {
    pub rp_id: String,
    #[serde(default)]
    pub register: RuleAction,
    #[serde(default)]
    pub authenticate: RuleAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_selection: Option<CredentialSelection>,
}

impl AgentRpRule {
    pub fn action(&self, action: PolicyAction) -> RuleAction {
        match action {
            PolicyAction::Authenticate => self.authenticate,
            PolicyAction::Register => self.register,
        }
    }

    pub fn is_wildcard(&self) -> bool {
        normalize_rp_id(&self.rp_id) == ANY_RP_ID
    }
}

/// Deprecated config vocabulary found while parsing a profile (ADR 0014 section 6.4, plan R8).
///
/// Legacy rule vocabulary is mapped at parse time and each mapping is recorded in `warnings`;
/// removed profile keys are recorded in `removed_keys`, and rule values that cannot be mapped safely
/// in `errors`. The latter two fail `AgentProfileConfig::validate` with a migration message, which
/// runs only when `agents.enabled = true`: parsing never fails on legacy vocabulary, so a bad legacy
/// rule cannot break the human authenticator's config load (invariant 23). The unmappable action is
/// parsed as `deny`. Nothing here is serialized.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct LegacyConfigUse {
    pub warnings: Vec<String>,
    pub removed_keys: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum LegacyAuthorization {
    Deny,
    Confirm,
    Allow,
}

#[derive(Deserialize, PartialEq, Eq, Clone, Copy)]
enum LegacyEvidence {
    #[serde(rename = "human")]
    Human,
    #[serde(rename = "agent", alias = "policy")]
    Agent,
    #[serde(rename = "none")]
    None,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyCeremonyFields {
    authorization: LegacyAuthorization,
    user_presence: LegacyEvidence,
    user_verification: LegacyEvidence,
}

/// A rule action as written in a config file: the new words, or the legacy aliases and evidence
/// tables that are still accepted for one minor release.
#[derive(Deserialize)]
#[serde(untagged)]
enum RuleActionRepr {
    Word(String),
    Legacy(LegacyCeremonyFields),
    /// Anything else (a number, an array, a table with unknown evidence values): reported by
    /// `validate`, never at parse time.
    Other(toml::Value),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentRpRuleRepr {
    rp_id: String,
    #[serde(default)]
    register: Option<RuleActionRepr>,
    #[serde(default)]
    authenticate: Option<RuleActionRepr>,
    #[serde(default)]
    credential_selection: Option<CredentialSelection>,
}

/// The legacy-to-new mapping of ADR 0014 section 6.4. Returns the new action and, for a legacy
/// spelling, the deprecation warning. Anything that cannot be mapped safely is an error.
fn map_rule_action(
    repr: Option<RuleActionRepr>,
    rp_id: &str,
    field: &str,
) -> std::result::Result<(RuleAction, Option<String>), String> {
    let Some(repr) = repr else {
        return Ok((RuleAction::Deny, None));
    };
    let deprecated = |what: String, new: RuleAction| {
        Some(format!(
            "rule '{rp_id}': {what} is deprecated and was mapped to `{field} = \"{new}\"`; \
             update the config (legacy rule vocabulary is removed in the release after next)"
        ))
    };
    match repr {
        RuleActionRepr::Word(word) => match word.as_str() {
            "deny" => Ok((RuleAction::Deny, None)),
            "allow" => Ok((RuleAction::Allow, None)),
            "request" => Ok((RuleAction::Request, None)),
            "autonomous" => Ok((
                RuleAction::Allow,
                deprecated(format!("`{field} = \"autonomous\"`"), RuleAction::Allow),
            )),
            "supervised" => Ok((
                RuleAction::Request,
                deprecated(format!("`{field} = \"supervised\"`"), RuleAction::Request),
            )),
            other => Err(format!(
                "rule '{rp_id}': unknown `{field}` value '{other}'; expected \"deny\", \"allow\" or \"request\""
            )),
        },
        RuleActionRepr::Other(value) => Err(format!(
            "rule '{rp_id}': `{field}` has an unrecognized value ({value}); expected \"deny\", \"allow\" or \"request\""
        )),
        RuleActionRepr::Legacy(fields) => {
            let table = || format!("the `{field}` evidence table");
            match (
                fields.authorization,
                fields.user_presence,
                fields.user_verification,
            ) {
                (LegacyAuthorization::Deny, LegacyEvidence::None, LegacyEvidence::None) => {
                    Ok((RuleAction::Deny, deprecated(table(), RuleAction::Deny)))
                }
                (LegacyAuthorization::Deny, _, _) => Err(format!(
                    "rule '{rp_id}': `{field}` is a legacy `deny` evidence table with UP or UV evidence, \
                     which cannot be mapped safely; write `{field} = \"deny\"`"
                )),
                (LegacyAuthorization::Confirm, _, _) => Ok((
                    RuleAction::Request,
                    deprecated(table(), RuleAction::Request),
                )),
                (LegacyAuthorization::Allow, LegacyEvidence::Agent, LegacyEvidence::Agent) => {
                    Ok((RuleAction::Allow, deprecated(table(), RuleAction::Allow)))
                }
                (LegacyAuthorization::Allow, up, uv) => {
                    let describe = |source: LegacyEvidence| match source {
                        LegacyEvidence::Human => "human",
                        LegacyEvidence::Agent => "agent",
                        LegacyEvidence::None => "none",
                    };
                    Err(format!(
                        "rule '{rp_id}': `{field}` is a legacy `allow` table with user_presence = {}, user_verification = {}, \
                         which cannot be mapped safely: agent rules carry no evidence fields and `allow` always uses \
                         agent evidence (ADR 0014 sections 6.4 and 7). Use `{field} = \"allow\"` for autonomous use \
                         or `{field} = \"request\"` to require human approval",
                        describe(up),
                        describe(uv),
                    ))
                }
            }
        }
    }
}

fn convert_rule(repr: AgentRpRuleRepr, legacy: &mut LegacyConfigUse) -> AgentRpRule {
    let mut action = |value: Option<RuleActionRepr>, field: &str| match map_rule_action(
        value,
        &repr.rp_id,
        field,
    ) {
        Ok((action, warning)) => {
            legacy.warnings.extend(warning);
            action
        }
        Err(message) => {
            legacy.errors.push(message);
            RuleAction::Deny
        }
    };
    let register = action(repr.register, "register");
    let authenticate = action(repr.authenticate, "authenticate");
    AgentRpRule {
        rp_id: repr.rp_id,
        register,
        authenticate,
        credential_selection: repr.credential_selection,
    }
}

fn default_gpg_backend() -> String {
    "gnupg-bin".to_string()
}

fn default_git_enabled() -> bool {
    true
}

#[cfg(feature = "tpm")]
fn default_tcti() -> String {
    "device:/dev/tpmrm0".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum AgentStorageConfig {
    Local {
        path: PathBuf,
        pin_path: PathBuf,
    },
    Pass {
        store_path: PathBuf,
        path: String,
        #[serde(default = "default_gpg_backend")]
        gpg_backend: String,
        pin_path: PathBuf,
        /// Synchronize this isolated agent's pass store (independent of [pass]).
        #[serde(default = "default_git_enabled")]
        git_sync: bool,
        /// Push this isolated agent's Git commits (independent of [pass]).
        #[serde(default = "default_git_enabled")]
        git_auto_push: bool,
    },
    #[cfg(feature = "tpm")]
    Tpm {
        path: PathBuf,
        #[serde(default = "default_tcti")]
        tcti: String,
        pin_path: PathBuf,
        #[serde(default)]
        portable: bool,
    },
}

impl AgentStorageConfig {
    pub fn credential_state_path(&self) -> PathBuf {
        match self {
            Self::Local { path, .. } => crate::config::BackendConfig::canonicalize_path(path),
            Self::Pass {
                store_path, path, ..
            } => crate::config::BackendConfig::canonicalize_path(&store_path.join(path)),
            #[cfg(feature = "tpm")]
            Self::Tpm { path, .. } => crate::config::BackendConfig::canonicalize_path(path),
        }
    }

    pub fn pin_state_path(&self) -> PathBuf {
        match self {
            Self::Local { pin_path, .. } => {
                crate::config::BackendConfig::canonicalize_path(pin_path)
            }
            Self::Pass {
                store_path,
                pin_path,
                ..
            } => crate::config::BackendConfig::canonicalize_path(&store_path.join(pin_path)),
            #[cfg(feature = "tpm")]
            Self::Tpm { pin_path, .. } => crate::config::BackendConfig::canonicalize_path(pin_path),
        }
    }

    pub fn to_backend_config(&self) -> crate::config::BackendConfig {
        match self {
            Self::Local { path, .. } => crate::config::BackendConfig::Local {
                path: path.display().to_string(),
            },
            Self::Pass {
                store_path,
                path,
                gpg_backend,
                ..
            } => crate::config::BackendConfig::Pass {
                store_path: store_path.display().to_string(),
                path: path.clone(),
                gpg_backend: gpg_backend.clone(),
            },
            #[cfg(feature = "tpm")]
            Self::Tpm {
                path,
                tcti,
                portable,
                ..
            } => crate::config::BackendConfig::Tpm {
                path: path.display().to_string(),
                tcti: tcti.clone(),
                portable: *portable,
            },
        }
    }

    pub fn all_paths(&self) -> Vec<(String, PathBuf)> {
        vec![
            ("credential".to_string(), self.credential_state_path()),
            ("pin".to_string(), self.pin_state_path()),
        ]
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Pass {
                store_path,
                path,
                pin_path,
                ..
            } => {
                if pin_path.is_absolute() {
                    return Err(Error::Config(format!(
                        "pass pin_path must be a relative subpath within the password store, got absolute path: {}",
                        pin_path.display()
                    )));
                }
                for component in pin_path.components() {
                    match component {
                        std::path::Component::ParentDir => {
                            return Err(Error::Config(format!(
                                "pass pin_path must not contain path traversal ('..'): {}",
                                pin_path.display()
                            )));
                        }
                        std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                            return Err(Error::Config(format!(
                                "pass pin_path must be a relative subpath: {}",
                                pin_path.display()
                            )));
                        }
                        _ => {}
                    }
                }
                let cred_canon =
                    crate::config::BackendConfig::canonicalize_path(&store_path.join(path));
                let pin_canon =
                    crate::config::BackendConfig::canonicalize_path(&store_path.join(pin_path));
                if cred_canon.starts_with(&pin_canon) || pin_canon.starts_with(&cred_canon) {
                    return Err(Error::Config(format!(
                        "pass pin_path '{}' overlaps with credential path '{}'",
                        pin_path.display(),
                        path
                    )));
                }
            }
            Self::Local { .. } => {}
            #[cfg(feature = "tpm")]
            Self::Tpm { .. } => {}
        }
        Ok(())
    }
}

impl fmt::Display for AgentStorageConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local { .. } => write!(f, "local"),
            Self::Pass { .. } => write!(f, "pass"),
            #[cfg(feature = "tpm")]
            Self::Tpm { .. } => write!(f, "tpm"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BoundedDuration {
    secs: u64,
}

impl BoundedDuration {
    pub const MIN_SECS: u64 = MIN_DURATION_SECS;
    pub const MAX_SECS: u64 = MAX_DURATION_SECS;

    pub fn new(secs: u64) -> Result<Self> {
        if secs < MIN_DURATION_SECS {
            return Err(Error::Config(format!(
                "duration must be at least {} seconds, got {}",
                MIN_DURATION_SECS, secs
            )));
        }
        if secs > MAX_DURATION_SECS {
            return Err(Error::Config(format!(
                "duration must be at most {} seconds, got {}",
                MAX_DURATION_SECS, secs
            )));
        }
        Ok(Self { secs })
    }

    pub fn as_secs(&self) -> u64 {
        self.secs
    }

    pub fn as_duration(&self) -> Duration {
        Duration::from_secs(self.secs)
    }
}

impl Serialize for BoundedDuration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.secs.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BoundedDuration {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        BoundedDuration::new(secs).map_err(serde::de::Error::custom)
    }
}

/// Legacy per-profile UHID identity.
///
/// Agents have no UHID or hidraw device of their own (ADR 0014 section 5): the isolated route was
/// removed, so a `[agents.profiles.<id>.device]` table is parsed only so that old configs keep
/// loading. Its contents are ignored and a deprecation warning is logged by
/// `AgentProfileConfig::validate`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceIdentity {}

#[derive(Debug, Clone, Serialize, Deserialize, ConfigDoc)]
#[serde(from = "AgentProfileConfigRepr")]
pub struct AgentProfileConfig {
    pub mode: AgentMode,
    pub principal_user: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_refs: Option<Vec<CredentialRef>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_grant_ttl: Option<BoundedDuration>,
    #[serde(
        default,
        alias = "session_ttl",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_session_ttl: Option<BoundedDuration>,
    #[serde(default = "default_max_operations")]
    pub max_operations: u16,
    /// Maximum number of live principal runtime sessions allowed for this profile.
    /// A value of 0 means unlimited and is only valid when browser_scope is "profile".
    #[serde(default = "default_max_concurrent_sessions")]
    pub max_concurrent_sessions: u16,
    #[serde(default)]
    pub browser_scope: BrowserScope,
    /// Profile default selection; a rule may override it, and the wildcard rule is always `single`.
    #[serde(default)]
    pub credential_selection: CredentialSelection,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<AgentStorageConfig>,

    #[serde(default)]
    pub rules: Vec<AgentRpRule>,

    /// Deprecated and ignored: agents no longer use a UHID device.
    #[serde(default, skip_serializing)]
    pub device: Option<DeviceIdentity>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_command: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_runtime_root: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_cdp_expose: Option<CdpExposeMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_cdp_port: Option<u16>,

    /// Deprecated vocabulary seen while parsing (not part of the config schema).
    #[serde(default, skip_serializing)]
    pub legacy: LegacyConfigUse,
}

/// The profile as written in a config file. It carries the removed profile keys so that a config
/// that still uses them fails with a migration message instead of "unknown field", and the rules
/// in their legacy spelling (ADR 0014 section 6.4).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentProfileConfigRepr {
    mode: AgentMode,
    principal_user: String,
    #[serde(default)]
    credential_refs: Option<Vec<CredentialRef>>,
    #[serde(default)]
    max_grant_ttl: Option<BoundedDuration>,
    #[serde(default, alias = "session_ttl")]
    max_session_ttl: Option<BoundedDuration>,
    #[serde(default = "default_max_operations")]
    max_operations: u16,
    #[serde(default = "default_max_concurrent_sessions")]
    max_concurrent_sessions: u16,
    #[serde(default)]
    browser_scope: BrowserScope,
    #[serde(default)]
    credential_selection: CredentialSelection,
    #[serde(default)]
    storage: Option<AgentStorageConfig>,
    #[serde(default)]
    rules: Vec<AgentRpRuleRepr>,
    #[serde(default)]
    device: Option<DeviceIdentity>,
    #[serde(default)]
    start_url: Option<String>,
    #[serde(default)]
    browser_command: Option<Vec<String>>,
    #[serde(default)]
    browser_user: Option<String>,
    #[serde(default)]
    browser_runtime_root: Option<PathBuf>,
    #[serde(default)]
    browser_cdp_expose: Option<CdpExposeMode>,
    #[serde(default)]
    browser_cdp_port: Option<u16>,

    // Removed profile keys (ADR 0014 section 6.4): detected only to produce a migration message.
    #[serde(default)]
    rp_ids: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    require_uv: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    registration_allowed: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    human_verification_prompt: Option<serde::de::IgnoredAny>,
}

impl From<AgentProfileConfigRepr> for AgentProfileConfig {
    fn from(repr: AgentProfileConfigRepr) -> Self {
        let mut legacy = LegacyConfigUse::default();
        for (key, present) in [
            ("rp_ids", repr.rp_ids.is_some()),
            ("require_uv", repr.require_uv.is_some()),
            ("registration_allowed", repr.registration_allowed.is_some()),
            (
                "human_verification_prompt",
                repr.human_verification_prompt.is_some(),
            ),
        ] {
            if present {
                legacy.removed_keys.push(key.to_string());
            }
        }

        let mut rules = Vec::with_capacity(repr.rules.len());
        for rule in repr.rules {
            rules.push(convert_rule(rule, &mut legacy));
        }

        Self {
            mode: repr.mode,
            principal_user: repr.principal_user,
            credential_refs: repr.credential_refs,
            max_grant_ttl: repr.max_grant_ttl,
            max_session_ttl: repr.max_session_ttl,
            max_operations: repr.max_operations,
            max_concurrent_sessions: repr.max_concurrent_sessions,
            browser_scope: repr.browser_scope,
            credential_selection: repr.credential_selection,
            storage: repr.storage,
            rules,
            device: repr.device,
            start_url: repr.start_url,
            browser_command: repr.browser_command,
            browser_user: repr.browser_user,
            browser_runtime_root: repr.browser_runtime_root,
            browser_cdp_expose: repr.browser_cdp_expose,
            browser_cdp_port: repr.browser_cdp_port,
            legacy,
        }
    }
}

impl AgentProfileConfig {
    /// The coarse RP scope of a browser session and its grant (at most [`MAX_GRANT_RP_IDS`]).
    ///
    /// A denied RP must still reach the daemon so that the deny is resolved and audited there, and
    /// a profile whose rules are all `deny` still has a scope (B4), so `deny` rules are included.
    /// With a wildcard rule the scope collapses to `*` (plus `localhost` when an exact `localhost`
    /// rule exists, since `*` never matches it); resolution stays the authority. Without a wildcard
    /// `validate` enforces the limit, so the grant request cannot fail at runtime.
    pub fn rule_rp_ids(&self) -> Vec<String> {
        if self.rules.iter().any(|rule| rule.is_wildcard()) {
            let mut scope = vec![ANY_RP_ID.to_string()];
            if self
                .rules
                .iter()
                .any(|rule| normalize_rp_id(&rule.rp_id) == LOCALHOST_RP_ID)
            {
                scope.push(LOCALHOST_RP_ID.to_string());
            }
            return scope;
        }
        self.rules.iter().map(|rule| rule.rp_id.clone()).collect()
    }

    /// RP IDs of every rule that is not `deny` for both actions (including the wildcard).
    pub fn allowed_rp_ids(&self) -> Vec<String> {
        self.rules
            .iter()
            .filter(|rule| {
                rule.register != RuleAction::Deny || rule.authenticate != RuleAction::Deny
            })
            .map(|rule| rule.rp_id.clone())
            .collect()
    }

    /// Resolve `(action, rp_id)` against this configuration alone, with no granted rules
    /// (ADR 0014 section 6.2). Runtime ceremonies resolve through `PolicyRuntime::resolve`, which
    /// also consults the granted-rules store.
    pub fn resolve(&self, action: PolicyAction, rp_id: &str) -> MatchedRule {
        resolve_rules(
            &self.rules,
            &self.credential_selection,
            action,
            rp_id,
            |_| false,
        )
    }

    /// Like [`Self::resolve`], upgrading a `request` through `grants`.
    pub fn resolve_with(
        &self,
        profile_id: &ProfileId,
        action: PolicyAction,
        rp_id: &str,
        grants: &dyn GrantSource,
    ) -> MatchedRule {
        resolve_rules(
            &self.rules,
            &self.credential_selection,
            action,
            rp_id,
            |rp_id| grants.is_granted(profile_id, rp_id),
        )
    }

    pub fn credential_selection_for_rp(&self, rp_id: &str) -> CredentialSelection {
        self.resolve(PolicyAction::Authenticate, rp_id).selection
    }

    pub fn allows_registration(&self) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.register != RuleAction::Deny)
    }

    pub fn allows_authentication(&self) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.authenticate != RuleAction::Deny)
    }

    /// Deprecation warnings for legacy keys and vocabulary that are still accepted.
    pub fn deprecation_warnings(&self, profile_id: &ProfileId) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.device.is_some() {
            warnings.push(format!(
                "agent profile '{}': the [device] table is deprecated and ignored: agents have no \
                 UHID device (ADR 0014 section 5); remove it",
                profile_id
            ));
        }
        for warning in &self.legacy.warnings {
            warnings.push(format!("agent profile '{}': {}", profile_id, warning));
        }
        warnings
    }

    pub fn validate(&self, profile_id: &ProfileId) -> Result<()> {
        if !self.legacy.errors.is_empty() {
            return Err(Error::Config(format!(
                "agent profile '{}': {}",
                profile_id,
                self.legacy.errors.join("; ")
            )));
        }
        if !self.legacy.removed_keys.is_empty() {
            return Err(Error::Config(format!(
                "agent profile '{}': the profile keys {} were removed (ADR 0014 section 6.4). \
                 Replace `rp_ids`, `registration_allowed` and `require_uv` with explicit \
                 [[agents.profiles.{}.rules]] entries (rp_id, authenticate = \"allow\" | \"request\" | \"deny\", \
                 register = \"allow\" | \"request\" | \"deny\"), and delete `human_verification_prompt`: \
                 agent ceremonies never prompt for human UP or UV",
                profile_id,
                self.legacy
                    .removed_keys
                    .iter()
                    .map(|key| format!("`{key}`"))
                    .collect::<Vec<_>>()
                    .join(", "),
                profile_id,
            )));
        }
        for warning in self.deprecation_warnings(profile_id) {
            log::warn!("{}", warning);
        }
        if self.principal_user.is_empty() {
            return Err(Error::Config(format!(
                "agent profile '{}': principal_user must not be empty",
                profile_id
            )));
        }
        if self.max_operations == 0 || self.max_operations > MAX_OPERATIONS {
            return Err(Error::Config(format!(
                "agent profile '{}': max_operations must be between 1 and {}",
                profile_id, MAX_OPERATIONS
            )));
        }
        if self.browser_scope == BrowserScope::Session {
            if self.max_concurrent_sessions == 0
                || self.max_concurrent_sessions > MAX_CONCURRENT_SESSIONS
            {
                return Err(Error::Config(format!(
                    "agent profile '{}': max_concurrent_sessions must be between 1 and {} for session browser scope",
                    profile_id, MAX_CONCURRENT_SESSIONS
                )));
            }
            if self.max_concurrent_sessions > 1
                && self.browser_cdp_expose == Some(CdpExposeMode::Port)
                && self.browser_cdp_port.unwrap_or(0) != 0
            {
                return Err(Error::Config(format!(
                    "agent profile '{}': browser_cdp_port must be 0 (or omitted) when max_concurrent_sessions > 1 in port mode with session browser scope",
                    profile_id
                )));
            }
        }
        if self.browser_scope == BrowserScope::Profile
            && self.max_concurrent_sessions > MAX_CONCURRENT_SESSIONS
        {
            return Err(Error::Config(format!(
                "agent profile '{}': max_concurrent_sessions must be 0 (unlimited) or between 1 and {} for profile browser scope",
                profile_id, MAX_CONCURRENT_SESSIONS
            )));
        }
        if let CredentialSelection::Credential(reference) = &self.credential_selection
            && self
                .credential_refs
                .as_ref()
                .is_some_and(|refs| !refs.contains(reference))
        {
            return Err(Error::Config(format!(
                "agent profile '{}': credential_selection reference must be included in credential_refs",
                profile_id
            )));
        }

        let mut normalized_rules = std::collections::BTreeSet::new();
        for rule in &self.rules {
            validate_agent_rp_rule_id(&rule.rp_id)?;
            let normalized = rule.rp_id.trim().to_ascii_lowercase();
            if !normalized_rules.insert(normalized) {
                return Err(Error::Config(format!(
                    "agent profile '{}': duplicate RP rule for '{}'",
                    profile_id, rule.rp_id,
                )));
            }
            if rule.register == RuleAction::Request && rule.authenticate == RuleAction::Deny {
                return Err(Error::Config(format!(
                    "agent profile '{}': rule '{}' has register = \"request\" with authenticate = \"deny\": \
                     a registration escalation persists authenticate = allow for the new credential \
                     (ADR 0014 section 8.3); set authenticate to \"allow\" or \"request\", or register to \"deny\"",
                    profile_id, rule.rp_id,
                )));
            }
            if let Some(CredentialSelection::Credential(reference)) = &rule.credential_selection
                && self
                    .credential_refs
                    .as_ref()
                    .is_some_and(|refs| !refs.contains(reference))
            {
                return Err(Error::Config(format!(
                    "agent profile '{}': credential_selection reference for RP '{}' must be included in credential_refs",
                    profile_id, rule.rp_id,
                )));
            }
        }

        if self.rule_rp_ids().len() > MAX_GRANT_RP_IDS {
            return Err(Error::Config(format!(
                "agent profile '{}': {} RP rules exceed the limit of {} (every rule's RP is in the \
                 browser session grant scope); remove rules, or use a `*` rule (same-user only), \
                 which collapses the scope",
                profile_id,
                self.rules.len(),
                MAX_GRANT_RP_IDS,
            )));
        }

        if let Some(wildcard_rule) = self.rules.iter().find(|rule| rule.is_wildcard()) {
            if self.mode != AgentMode::SameUser {
                return Err(Error::Config(format!(
                    "agent profile '{}': wildcard RP scope '*' is only supported in same-user mode",
                    profile_id
                )));
            }
            if self.credential_refs.is_some() {
                return Err(Error::Config(format!(
                    "agent profile '{}': wildcard RP scope '*' requires credential_refs to be omitted for dynamic credential discovery",
                    profile_id
                )));
            }
            if wildcard_rule.register != RuleAction::Deny {
                return Err(Error::Config(format!(
                    "agent profile '{}': wildcard RP scope '*' must have register = \"deny\" (a wildcard never permits or requests registration)",
                    profile_id
                )));
            }
            if wildcard_rule
                .credential_selection
                .as_ref()
                .is_some_and(|selection| *selection != CredentialSelection::Single)
            {
                return Err(Error::Config(format!(
                    "agent profile '{}': wildcard RP scope '*' always selects with `single`; \
                     a wildcard never chooses between several accounts (ADR 0014 section 6.3)",
                    profile_id
                )));
            }
        }

        if let Some(ref cmd) = self.browser_command {
            if cmd.is_empty() {
                return Err(Error::Config(format!(
                    "agent profile '{}': browser_command must not be empty",
                    profile_id
                )));
            }
            for (i, arg) in cmd.iter().enumerate() {
                if arg.contains('\0') {
                    return Err(Error::Config(format!(
                        "agent profile '{}': browser_command[{}] must not contain NUL bytes",
                        profile_id, i,
                    )));
                }
            }
        }

        match self.mode {
            AgentMode::SameUser => {
                if self.storage.is_some() {
                    return Err(Error::Config(format!(
                        "agent profile '{}': same-user mode uses the human backend and must not specify storage",
                        profile_id
                    )));
                }
            }
            AgentMode::Isolated => {
                if self.storage.is_none() {
                    return Err(Error::Config(format!(
                        "agent profile '{}': isolated mode requires storage backend configuration",
                        profile_id
                    )));
                }
                if let Some(ref storage) = self.storage {
                    storage.validate()?;
                }
                if self.browser_user.is_some() {
                    return Err(Error::Config(format!(
                        "agent profile '{}': isolated mode must not specify browser_user",
                        profile_id
                    )));
                }
                if self.browser_runtime_root.is_some() {
                    return Err(Error::Config(format!(
                        "agent profile '{}': isolated mode must not specify browser_runtime_root",
                        profile_id
                    )));
                }
            }
        }

        if let Some(ref url) = self.start_url {
            if url.is_empty() {
                return Err(Error::Config(format!(
                    "agent profile '{}': start_url must not be empty",
                    profile_id
                )));
            }
            if !url.starts_with("https://") && !url.starts_with("http://") {
                return Err(Error::Config(format!(
                    "agent profile '{}': start_url must use http or https scheme, got '{}'",
                    profile_id, url
                )));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, ConfigDoc)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub profiles: BTreeMap<String, AgentProfileConfig>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_path: Option<PathBuf>,

    /// Profile IDs for which the operator explicitly accepts same-user catch-all RP authority.
    #[serde(default)]
    pub acknowledge_global_same_user: Vec<String>,

    /// Profile IDs for which the operator explicitly accepts writes to the human credential backend.
    #[serde(default)]
    pub acknowledge_same_user_registration: Vec<String>,

    /// Concurrency caps of the agent ceremony server (plan R11). Read when the daemon starts.
    #[serde(default)]
    pub limits: AgentRequestLimits,
}

/// Default global cap on concurrent agent ceremony requests.
pub const DEFAULT_MAX_CONCURRENT_REQUESTS: u16 = 32;
/// Default cap on concurrent requests of one profile (all its sessions).
pub const DEFAULT_MAX_REQUESTS_PER_PROFILE: u16 = 16;
/// Default cap on concurrent requests carried by one connection.
pub const DEFAULT_MAX_REQUESTS_PER_CONNECTION: u16 = 8;
/// Default cap on concurrent requests of one bearer session.
pub const DEFAULT_MAX_REQUESTS_PER_SESSION: u16 = 8;
/// Upper bound for every request cap.
pub const MAX_REQUEST_LIMIT: u16 = 1024;

fn default_max_concurrent_requests() -> u16 {
    DEFAULT_MAX_CONCURRENT_REQUESTS
}

fn default_max_requests_per_profile() -> u16 {
    DEFAULT_MAX_REQUESTS_PER_PROFILE
}

fn default_max_requests_per_connection() -> u16 {
    DEFAULT_MAX_REQUESTS_PER_CONNECTION
}

fn default_max_requests_per_session() -> u16 {
    DEFAULT_MAX_REQUESTS_PER_SESSION
}

/// Concurrency caps of the agent ceremony server. A request over any cap is answered with an
/// explicit `busy` error instead of being dropped (plan R11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ConfigDoc)]
#[serde(deny_unknown_fields)]
pub struct AgentRequestLimits {
    /// Concurrent ceremony requests across all sessions and connections.
    #[serde(default = "default_max_concurrent_requests")]
    pub max_concurrent_requests: u16,
    /// Concurrent ceremony requests of one profile, so that one profile cannot exhaust the global
    /// cap.
    #[serde(default = "default_max_requests_per_profile")]
    pub max_requests_per_profile: u16,
    /// Concurrent ceremony requests carried by one connection.
    #[serde(default = "default_max_requests_per_connection")]
    pub max_requests_per_connection: u16,
    /// Concurrent ceremony requests of one bearer session (one managed browser).
    #[serde(default = "default_max_requests_per_session")]
    pub max_requests_per_session: u16,
}

impl Default for AgentRequestLimits {
    fn default() -> Self {
        Self {
            max_concurrent_requests: DEFAULT_MAX_CONCURRENT_REQUESTS,
            max_requests_per_profile: DEFAULT_MAX_REQUESTS_PER_PROFILE,
            max_requests_per_connection: DEFAULT_MAX_REQUESTS_PER_CONNECTION,
            max_requests_per_session: DEFAULT_MAX_REQUESTS_PER_SESSION,
        }
    }
}

impl AgentRequestLimits {
    pub fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("max_concurrent_requests", self.max_concurrent_requests),
            ("max_requests_per_profile", self.max_requests_per_profile),
            (
                "max_requests_per_connection",
                self.max_requests_per_connection,
            ),
            ("max_requests_per_session", self.max_requests_per_session),
        ] {
            if value == 0 || value > MAX_REQUEST_LIMIT {
                return Err(Error::Config(format!(
                    "agents.limits.{} must be between 1 and {}",
                    name, MAX_REQUEST_LIMIT
                )));
            }
        }
        Ok(())
    }
}

impl AgentConfig {
    /// Parse the `[agents]` table of a Passless TOML configuration. A missing table is the default
    /// (disabled) configuration. Validation is separate ([`Self::validate`]).
    pub fn from_toml_str(content: &str, source: &str) -> Result<Self> {
        let table = toml::from_str::<toml::Table>(content).map_err(|e| {
            Error::Config(format!(
                "failed to parse config file {} as TOML: {}",
                source, e
            ))
        })?;
        match table.get("agents") {
            Some(agents_value) => {
                Deserialize::deserialize(agents_value.clone()).map_err(|e: toml::de::Error| {
                    Error::Config(format!(
                        "failed to parse [agents] section in {}: {}",
                        source, e
                    ))
                })
            }
            None => Ok(Self::default()),
        }
    }

    /// Read and parse the `[agents]` table of the configuration file at `path`.
    pub fn from_config_file(path: &std::path::Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            Error::Config(format!(
                "failed to read config file {}: {}",
                path.display(),
                e
            ))
        })?;
        Self::from_toml_str(&content, &path.display().to_string())
    }

    /// Why `next` cannot replace `self` in a running daemon, if it cannot.
    ///
    /// A policy reload applies rules, selection, acknowledgements, budgets and TTLs. It cannot add
    /// or remove profiles or change what was bound when the daemon started (backends, users, modes,
    /// browser scope, session concurrency, audit location, request caps); those need a restart.
    pub fn reload_incompatibility(&self, next: &AgentConfig) -> Option<String> {
        if self.enabled != next.enabled {
            return Some("agents.enabled changed".to_string());
        }
        if self.audit_path != next.audit_path {
            return Some("agents.audit_path changed".to_string());
        }
        if self.limits != next.limits {
            return Some("agents.limits changed".to_string());
        }
        if !self.profiles.keys().eq(next.profiles.keys()) {
            return Some("the set of agent profiles changed".to_string());
        }
        for (name, current) in &self.profiles {
            let Some(candidate) = next.profiles.get(name) else {
                return Some(format!("agent profile '{}' was removed", name));
            };
            let storage = |p: &AgentProfileConfig| p.storage.as_ref().map(|s| format!("{:?}", s));
            let changed = if current.mode != candidate.mode {
                Some("mode")
            } else if current.principal_user != candidate.principal_user {
                Some("principal_user")
            } else if current.browser_user != candidate.browser_user {
                Some("browser_user")
            } else if storage(current) != storage(candidate) {
                Some("storage")
            } else if current.browser_scope != candidate.browser_scope {
                Some("browser_scope")
            } else if current.max_concurrent_sessions != candidate.max_concurrent_sessions {
                Some("max_concurrent_sessions")
            } else {
                None
            };
            if let Some(field) = changed {
                return Some(format!("agent profile '{}': {} changed", name, field));
            }
        }
        None
    }

    pub fn validate(&self, human_state_path: Option<&std::path::Path>) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        self.limits.validate()?;

        if self.audit_path.is_none() {
            return Err(Error::Config(
                "agents.enabled = true requires agents.audit_path".to_string(),
            ));
        }

        for acknowledged in self
            .acknowledge_global_same_user
            .iter()
            .chain(self.acknowledge_same_user_registration.iter())
        {
            if !self.profiles.contains_key(acknowledged) {
                return Err(Error::Config(format!(
                    "agents dangerous-profile acknowledgement references unknown profile '{}'",
                    acknowledged,
                )));
            }
        }

        let mut validated_profiles: Vec<(ProfileId, &AgentProfileConfig)> = Vec::new();

        for (name, profile) in &self.profiles {
            let pid = ProfileId::new(name.as_str())
                .map_err(|e| Error::Config(format!("invalid profile id '{}': {}", name, e)))?;
            profile.validate(&pid)?;

            let global_same_user = profile.mode == AgentMode::SameUser
                && profile.rules.iter().any(|rule| rule.is_wildcard());
            if global_same_user
                && !self
                    .acknowledge_global_same_user
                    .iter()
                    .any(|ack| ack == name)
            {
                return Err(Error::Config(format!(
                    "agent profile '{}': global same-user authentication requires explicit operator acknowledgement; add '{}' to agents.acknowledge_global_same_user",
                    name, name,
                )));
            }

            let human_backend_registration =
                profile.mode == AgentMode::SameUser && profile.allows_registration();
            if human_backend_registration
                && !self
                    .acknowledge_same_user_registration
                    .iter()
                    .any(|ack| ack == name)
            {
                return Err(Error::Config(format!(
                    "agent profile '{}': same-user registration mutates the human credential backend and requires explicit operator acknowledgement; add '{}' to agents.acknowledge_same_user_registration",
                    name, name,
                )));
            }

            validated_profiles.push((pid, profile));
        }

        let mut all_roots: Vec<(String, PathBuf)> = Vec::new();

        if let Some(ref audit) = self.audit_path {
            all_roots.push((
                "audit_path".to_string(),
                crate::config::BackendConfig::canonicalize_path(audit),
            ));
        }

        for (pid, profile) in &validated_profiles {
            if let Some(ref storage) = profile.storage {
                for (suffix, path) in storage.all_paths() {
                    all_roots.push((format!("{}.storage.{}", pid, suffix), path));
                }
            }
        }

        for (i, (name_a, path_a)) in all_roots.iter().enumerate() {
            for (name_b, path_b) in all_roots.iter().skip(i + 1) {
                if path_a.starts_with(path_b) || path_b.starts_with(path_a) {
                    return Err(Error::Config(format!(
                        "agent roots {} ({}) and {} ({}) overlap",
                        name_a,
                        path_a.display(),
                        name_b,
                        path_b.display(),
                    )));
                }
            }
        }

        if let Some(human_path) = human_state_path {
            let canonical_human = crate::config::BackendConfig::canonicalize_path(human_path);
            for (name, agent_root) in &all_roots {
                if agent_root.starts_with(&canonical_human)
                    || canonical_human.starts_with(agent_root)
                {
                    return Err(Error::Config(format!(
                        "agent {} ({}) overlaps with human backend state ({})",
                        name,
                        agent_root.display(),
                        canonical_human.display(),
                    )));
                }
            }
        }

        Ok(())
    }

    /// Deprecation warnings of every profile (legacy rule vocabulary, `[device]` tables). Logged
    /// once per load by `validate` and reported by `passless agent doctor`.
    pub fn deprecation_warnings(&self) -> Vec<String> {
        self.profiles
            .iter()
            .filter_map(|(name, profile)| {
                ProfileId::new(name.as_str())
                    .ok()
                    .map(|id| profile.deprecation_warnings(&id))
            })
            .flatten()
            .collect()
    }

    pub fn get_profile(&self, name: &str) -> Option<&AgentProfileConfig> {
        self.profiles.get(name)
    }

    pub fn profiles_for_rp_id(&self, rp_id: &str) -> Vec<(&String, &AgentProfileConfig)> {
        let Ok(normalized) = validate_rp_id(rp_id) else {
            return Vec::new();
        };
        self.profiles
            .iter()
            .filter(|(_, profile)| {
                profile.rules.iter().any(|rule| {
                    let rule_rp = normalize_rp_id(&rule.rp_id);
                    rule_rp == normalized || (rule_rp == ANY_RP_ID && normalized != LOCALHOST_RP_ID)
                })
            })
            .collect()
    }
}

fn normalize_rp_id(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

fn is_ipv4(s: &str) -> bool {
    s.parse::<Ipv4Addr>().is_ok()
}

fn is_ipv6(s: &str) -> bool {
    let stripped = s.strip_prefix('[').and_then(|r| r.strip_suffix(']'));
    let candidate = stripped.unwrap_or(s);
    candidate.parse::<Ipv6Addr>().is_ok()
}

fn is_ip_address(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok() || is_ipv4(s) || is_ipv6(s)
}

fn is_valid_dns_name(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    if labels.is_empty() {
        return false;
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
    }
    true
}

fn is_public_suffix(domain: &str) -> bool {
    use psl::Psl;
    psl::List.domain(domain.as_bytes()).is_none()
}

pub fn validate_agent_rp_rule_id(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed == ANY_RP_ID {
        return Ok(ANY_RP_ID.to_string());
    }
    validate_rp_id(trimmed)
}

pub fn validate_rp_id(raw: &str) -> Result<String> {
    let trimmed = raw.trim();

    if trimmed.is_empty() {
        return Err(Error::Config("RP ID must not be empty".to_string()));
    }

    if trimmed.contains("://") {
        return Err(Error::Config(format!(
            "RP ID must not contain a scheme: '{}'",
            trimmed
        )));
    }

    if trimmed.contains('/') {
        return Err(Error::Config(format!(
            "RP ID must not contain a path: '{}'",
            trimmed
        )));
    }

    if let Some(colon_pos) = trimmed.rfind(':') {
        let after_colon = &trimmed[colon_pos + 1..];
        if !after_colon.is_empty() && after_colon.chars().all(|c| c.is_ascii_digit()) {
            return Err(Error::Config(format!(
                "RP ID must not contain a port: '{}'",
                trimmed
            )));
        }
    }

    if trimmed.starts_with("*.") || trimmed.starts_with('*') {
        return Err(Error::Config(format!(
            "RP ID must not be a wildcard: '{}'",
            trimmed
        )));
    }

    if trimmed.ends_with('.') {
        return Err(Error::Config(format!(
            "RP ID must not have a trailing dot: '{}'",
            trimmed
        )));
    }

    let normalized = normalize_rp_id(trimmed);

    if is_ip_address(&normalized) {
        return Err(Error::Config(format!(
            "RP ID must not be an IP address: '{}'",
            normalized
        )));
    }

    if !is_valid_dns_name(&normalized) {
        return Err(Error::Config(format!(
            "RP ID is not a valid DNS name: '{}'",
            normalized
        )));
    }

    // `localhost` is the one exception to the public-suffix rule (ADR 0014 section 6.1, plan R15):
    // valid for exact rules only (resolution never matches it through the wildcard). Subdomains of
    // `localhost` are never valid.
    if normalized == LOCALHOST_RP_ID {
        return Ok(normalized);
    }
    if normalized.ends_with(".localhost") {
        return Err(Error::Config(format!(
            "RP ID must not be a subdomain of localhost: '{}'",
            normalized
        )));
    }

    if !normalized.contains('.') {
        return Err(Error::Config(format!(
            "RP ID must have at least two labels: '{}'",
            normalized
        )));
    }

    if is_public_suffix(&normalized) {
        return Err(Error::Config(format!(
            "RP ID must not be a public suffix: '{}'",
            normalized
        )));
    }

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::super::resolve::RuleIdentity;
    use super::*;

    #[test]
    fn test_rp_id_valid() {
        assert_eq!(validate_rp_id("example.com").unwrap(), "example.com");
        assert_eq!(
            validate_rp_id("sub.example.com").unwrap(),
            "sub.example.com"
        );
        assert_eq!(validate_rp_id("EXAMPLE.COM").unwrap(), "example.com");
    }

    #[test]
    fn test_rp_id_reject_scheme() {
        assert!(validate_rp_id("https://example.com").is_err());
        assert!(validate_rp_id("http://example.com").is_err());
    }

    #[test]
    fn test_rp_id_reject_port() {
        assert!(validate_rp_id("example.com:443").is_err());
        assert!(validate_rp_id("example.com:8080").is_err());
    }

    #[test]
    fn test_rp_id_reject_path() {
        assert!(validate_rp_id("example.com/path").is_err());
        assert!(validate_rp_id("example.com/a/b").is_err());
    }

    #[test]
    fn test_rp_id_reject_wildcard() {
        assert!(validate_rp_id("*.example.com").is_err());
        assert!(validate_rp_id("*").is_err());
    }

    #[test]
    fn test_agent_rp_rule_accepts_only_global_wildcard() {
        assert_eq!(validate_agent_rp_rule_id(" * ").unwrap(), ANY_RP_ID);
        assert!(validate_agent_rp_rule_id("*.example.com").is_err());
    }

    #[test]
    fn test_rp_id_reject_trailing_dot() {
        assert!(validate_rp_id("example.com.").is_err());
    }

    #[test]
    fn test_rp_id_reject_ipv4() {
        assert!(validate_rp_id("192.168.1.1").is_err());
        assert!(validate_rp_id("127.0.0.1").is_err());
    }

    #[test]
    fn test_rp_id_reject_ipv6() {
        assert!(validate_rp_id("::1").is_err());
        assert!(validate_rp_id("[::1]").is_err());
        assert!(validate_rp_id("2001:db8::1").is_err());
    }

    #[test]
    fn test_rp_id_reject_empty() {
        assert!(validate_rp_id("").is_err());
        assert!(validate_rp_id("  ").is_err());
    }

    #[test]
    fn test_rp_id_reject_single_label() {
        assert!(validate_rp_id("com").is_err());
        assert!(validate_rp_id("intranet").is_err());
    }

    #[test]
    fn test_rp_id_reject_public_suffix() {
        assert!(validate_rp_id("com").is_err());
        assert!(validate_rp_id("co.uk").is_err());
        assert!(validate_rp_id("github.io").is_err());
    }

    #[test]
    fn test_rp_id_reject_invalid_dns() {
        assert!(validate_rp_id("-example.com").is_err());
        assert!(validate_rp_id("example-.com").is_err());
        assert!(validate_rp_id("exam ple.com").is_err());
    }

    #[test]
    fn test_bounded_duration_valid() {
        let d = BoundedDuration::new(60).unwrap();
        assert_eq!(d.as_secs(), 60);
        assert_eq!(d.as_duration(), Duration::from_secs(60));
    }

    #[test]
    fn test_bounded_duration_zero_rejected() {
        assert!(BoundedDuration::new(0).is_err());
    }

    #[test]
    fn test_bounded_duration_too_large() {
        assert!(BoundedDuration::new(MAX_DURATION_SECS + 1).is_err());
    }

    #[test]
    fn test_bounded_duration_boundary() {
        assert!(BoundedDuration::new(MIN_DURATION_SECS).is_ok());
        assert!(BoundedDuration::new(MAX_DURATION_SECS).is_ok());
    }

    #[test]
    fn test_bounded_duration_serde_roundtrip() {
        let d = BoundedDuration::new(120).unwrap();
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, "120");
        let d2: BoundedDuration = serde_json::from_str(&json).unwrap();
        assert_eq!(d, d2);
    }

    #[test]
    fn test_bounded_duration_serde_rejects_zero() {
        let result: std::result::Result<BoundedDuration, _> = serde_json::from_str("0");
        assert!(result.is_err());
    }

    #[test]
    fn test_agent_mode_serde_isolated() {
        let mode = AgentMode::Isolated;
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(json, "\"isolated\"");
        let mode2: AgentMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, mode2);
    }

    #[test]
    fn test_agent_mode_from_str() {
        assert_eq!(
            "isolated".parse::<AgentMode>().unwrap(),
            AgentMode::Isolated
        );
        assert!("delegated".parse::<AgentMode>().is_err());
        assert!("invalid".parse::<AgentMode>().is_err());
    }

    #[test]
    fn test_agent_mode_serde_same_user() {
        let mode = AgentMode::SameUser;
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(json, "\"same-user\"");
        assert_eq!(serde_json::from_str::<AgentMode>(&json).unwrap(), mode);
        assert_eq!("same_user".parse::<AgentMode>().unwrap(), mode);
    }

    #[test]
    fn test_same_user_profile_rejects_storage() {
        let mut profile = make_isolated_profile();
        profile.mode = AgentMode::SameUser;
        assert!(
            profile
                .validate(&ProfileId::new("same-user").unwrap())
                .is_err()
        );
    }

    #[test]
    fn test_agent_config_default_disabled() {
        let config = AgentConfig::default();
        assert!(!config.enabled);
        assert!(config.profiles.is_empty());
    }

    #[test]
    fn test_agent_config_validate_disabled_skips_checks() {
        let config = AgentConfig::default();
        assert!(config.validate(None).is_ok());
    }

    fn rule(rp_id: &str, authenticate: RuleAction, register: RuleAction) -> AgentRpRule {
        AgentRpRule {
            rp_id: rp_id.to_string(),
            register,
            authenticate,
            credential_selection: None,
        }
    }

    fn make_isolated_profile() -> AgentProfileConfig {
        AgentProfileConfig {
            max_operations: 64,
            max_concurrent_sessions: 1,
            browser_scope: BrowserScope::Session,
            credential_selection: CredentialSelection::Single,
            mode: AgentMode::Isolated,
            principal_user: "test-user".to_string(),
            credential_refs: None,
            max_grant_ttl: None,
            max_session_ttl: None,
            storage: Some(AgentStorageConfig::Local {
                path: PathBuf::from("/tmp/test-agent/creds"),
                pin_path: PathBuf::from("/tmp/test-agent/pin"),
            }),
            rules: vec![rule("example.com", RuleAction::Allow, RuleAction::Deny)],
            legacy: Default::default(),
            device: None,
            start_url: None,
            browser_command: None,
            browser_user: None,
            browser_runtime_root: None,
            browser_cdp_expose: None,
            browser_cdp_port: None,
        }
    }

    fn same_user_profile(rules: Vec<AgentRpRule>) -> AgentProfileConfig {
        let mut profile = make_isolated_profile();
        profile.mode = AgentMode::SameUser;
        profile.storage = None;
        profile.rules = rules;
        profile
    }

    fn pid(name: &str) -> ProfileId {
        ProfileId::new(name).unwrap()
    }

    fn parse_profile(body: &str) -> std::result::Result<AgentProfileConfig, toml::de::Error> {
        toml::from_str(&format!(
            "mode = \"same-user\"\nprincipal_user = \"alice\"\n{body}"
        ))
    }

    fn agent_config(
        profile: AgentProfileConfig,
        acknowledge_global: bool,
        acknowledge_registration: bool,
    ) -> AgentConfig {
        let mut profiles = BTreeMap::new();
        profiles.insert("coding".to_string(), profile);
        AgentConfig {
            limits: Default::default(),
            enabled: true,
            profiles,
            audit_path: Some(PathBuf::from("/tmp/passless-agent-audit-p4")),
            acknowledge_global_same_user: if acknowledge_global {
                vec!["coding".to_string()]
            } else {
                vec![]
            },
            acknowledge_same_user_registration: if acknowledge_registration {
                vec!["coding".to_string()]
            } else {
                vec![]
            },
        }
    }

    // B6 regression: an isolated profile no longer needs (or can collide on) a `[device]` identity.
    #[test]
    fn test_isolated_profile_valid_without_device() {
        let profile = make_isolated_profile();
        assert!(profile.device.is_none());
        let pid = ProfileId::new("test").unwrap();
        profile.validate(&pid).unwrap();
        assert!(profile.deprecation_warnings(&pid).is_empty());
    }

    #[test]
    fn test_legacy_device_key_warns_and_is_ignored() {
        let input = r#"
mode = "isolated"
principal_user = "agent"

[storage.local]
path = "/tmp/legacy-device/credentials"
pin_path = "/tmp/legacy-device/pin"

[device]
name = "legacy"
phys = "legacy-phys"
uniq = "legacy-uniq"
vendor_id = 4660
product_id = 22136
"#;
        let profile: AgentProfileConfig = toml::from_str(input).unwrap();
        let pid = ProfileId::new("legacy").unwrap();
        let warnings = profile.deprecation_warnings(&pid);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("[device]") && warnings[0].contains("ignored"));
        profile.validate(&pid).unwrap();
        // The legacy identity is never written back out.
        let rendered = toml::to_string(&profile).unwrap();
        assert!(!rendered.contains("legacy-phys"), "{rendered}");
    }

    #[test]
    fn test_identical_legacy_devices_do_not_collide_across_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let mut profiles = BTreeMap::new();
        for name in ["a", "b"] {
            let mut profile = make_isolated_profile();
            profile.storage = Some(AgentStorageConfig::Local {
                path: dir.path().join(name).join("creds"),
                pin_path: dir.path().join(name).join("pin"),
            });
            // The same legacy identity on two profiles used to be a config error.
            profile.device = Some(DeviceIdentity::default());
            profiles.insert(name.to_string(), profile);
        }
        let config = AgentConfig {
            limits: Default::default(),
            enabled: true,
            profiles,
            audit_path: Some(dir.path().join("audit")),
            acknowledge_global_same_user: vec![],
            acknowledge_same_user_registration: vec![],
        };
        config.validate(None).unwrap();
    }

    #[test]
    fn test_profile_isolated_requires_storage() {
        let mut profile = make_isolated_profile();
        profile.storage = None;
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("storage"));
    }

    #[test]
    fn test_profile_isolated_valid() {
        let profile = make_isolated_profile();
        let pid = ProfileId::new("test").unwrap();
        assert!(profile.validate(&pid).is_ok());
    }

    #[test]
    fn test_config_deny_unknown_fields() {
        let toml_str = r#"
enabled = true
unknown_field = "bad"
"#;
        let result: std::result::Result<AgentConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_profile_deny_unknown_fields() {
        let toml_str = r#"
enabled = true

[profiles.test]
mode = "isolated"
principal_user = "u"
extra_field = "bad"

[profiles.test.device]
name = "n"
phys = "p"
uniq = "u"
vendor_id = 1
product_id = 2

[profiles.test.storage.local]
path = "/tmp/c"
pin_path = "/tmp/p"
"#;
        let result: std::result::Result<AgentConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_profiles_for_rp_id_matches_explicit_rules() {
        let toml_str = r#"
enabled = true

[profiles.release-bot]
mode = "isolated"
principal_user = "passless-release"

[[profiles.release-bot.rules]]
rp_id = "github.com"
register = "deny"
authenticate = "allow"

[profiles.release-bot.device]
name = "passless-agent-release"
phys = "release-phys"
uniq = "release-uniq"
vendor_id = 4660
product_id = 22137

[profiles.release-bot.storage.local]
path = "/var/lib/passless-agent/release/credentials"
pin_path = "/var/lib/passless-agent/release/pin"
"#;
        let config: AgentConfig = toml::from_str(toml_str).unwrap();

        let matches = config.profiles_for_rp_id("GITHUB.COM");

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, "release-bot");
    }

    #[test]
    fn test_config_no_agents_section_backward_compatible() {
        let toml_str = r#"
backend_type = "local"
verbose = false
"#;
        let result: std::result::Result<AgentConfig, _> = toml::from_str("");
        assert!(result.is_ok());
        let config = result.unwrap();
        assert!(!config.enabled);
        let _ = toml_str;
    }

    #[test]
    fn test_config_overlapping_roots_rejected() {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "a".to_string(),
            AgentProfileConfig {
                max_operations: 64,
                max_concurrent_sessions: 1,
                browser_scope: BrowserScope::Session,
                credential_selection: CredentialSelection::Single,
                mode: AgentMode::Isolated,
                principal_user: "u1".to_string(),
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: PathBuf::from("/tmp/agent/data"),
                    pin_path: PathBuf::from("/tmp/agent/data/sub"),
                }),
                rules: vec![],
                legacy: Default::default(),
                device: None,
                start_url: None,
                browser_command: None,
                browser_user: None,
                browser_runtime_root: None,
                browser_cdp_expose: None,
                browser_cdp_port: None,
            },
        );
        let config = AgentConfig {
            limits: Default::default(),
            enabled: true,
            profiles,
            audit_path: Some(PathBuf::from("/tmp/agent-audit-roots")),
            acknowledge_global_same_user: vec![],
            acknowledge_same_user_registration: vec![],
        };
        let err = config.validate(None).unwrap_err();
        assert!(err.to_string().contains("overlap"));
    }

    #[test]
    fn test_config_agent_root_overlaps_human_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let human_path = dir.path().join("human");
        std::fs::create_dir_all(&human_path).unwrap();

        let mut profiles = BTreeMap::new();
        profiles.insert(
            "a".to_string(),
            AgentProfileConfig {
                max_operations: 64,
                max_concurrent_sessions: 1,
                browser_scope: BrowserScope::Session,
                credential_selection: CredentialSelection::Single,
                mode: AgentMode::Isolated,
                principal_user: "u1".to_string(),
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: human_path.join("creds"),
                    pin_path: dir.path().join("pin"),
                }),
                rules: vec![],
                legacy: Default::default(),
                device: None,
                start_url: None,
                browser_command: None,
                browser_user: None,
                browser_runtime_root: None,
                browser_cdp_expose: None,
                browser_cdp_port: None,
            },
        );
        let config = AgentConfig {
            limits: Default::default(),
            enabled: true,
            profiles,
            audit_path: Some(dir.path().join("audit")),
            acknowledge_global_same_user: vec![],
            acknowledge_same_user_registration: vec![],
        };
        let err = config.validate(Some(human_path.as_path())).unwrap_err();
        assert!(err.to_string().contains("overlaps with human"));
    }

    #[test]
    fn test_config_unknown_mode_rejected() {
        let toml_str = r#"
enabled = true

[profiles.test]
mode = "delegated"
principal_user = "u"

[profiles.test.device]
name = "n"
phys = "p"
uniq = "u"
vendor_id = 1
product_id = 2
"#;
        let result: std::result::Result<AgentConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_credential_ref_not_raw_id() {
        use super::super::ids::CredentialRef;
        let _cred_ref = CredentialRef::with_default_domain(b"test-credential");
        assert_eq!(_cred_ref.as_bytes().len(), 32);
    }

    #[test]
    fn test_enabled_requires_audit_path() {
        let config = AgentConfig {
            limits: Default::default(),
            enabled: true,
            profiles: BTreeMap::new(),
            audit_path: None,
            acknowledge_global_same_user: vec![],
            acknowledge_same_user_registration: vec![],
        };
        let err = config.validate(None).unwrap_err();
        assert!(err.to_string().contains("audit_path"));
    }

    #[test]
    fn test_disabled_does_not_require_audit_path() {
        let config = AgentConfig {
            limits: Default::default(),
            enabled: false,
            profiles: BTreeMap::new(),
            audit_path: None,
            acknowledge_global_same_user: vec![],
            acknowledge_same_user_registration: vec![],
        };
        assert!(config.validate(None).is_ok());
    }

    #[test]
    fn test_path_overlap_labels_include_profile_id() {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "myprofile".to_string(),
            AgentProfileConfig {
                max_operations: 64,
                max_concurrent_sessions: 1,
                browser_scope: BrowserScope::Session,
                credential_selection: CredentialSelection::Single,
                mode: AgentMode::Isolated,
                principal_user: "u1".to_string(),
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: PathBuf::from("/tmp/overlap/data"),
                    pin_path: PathBuf::from("/tmp/overlap/data/sub"),
                }),
                rules: vec![],
                legacy: Default::default(),
                device: None,
                start_url: None,
                browser_command: None,
                browser_user: None,
                browser_runtime_root: None,
                browser_cdp_expose: None,
                browser_cdp_port: None,
            },
        );
        let config = AgentConfig {
            limits: Default::default(),
            enabled: true,
            profiles,
            audit_path: Some(PathBuf::from("/tmp/overlap-audit")),
            acknowledge_global_same_user: vec![],
            acknowledge_same_user_registration: vec![],
        };
        let err = config.validate(None).unwrap_err();
        assert!(err.to_string().contains("myprofile.storage.credential"));
        assert!(err.to_string().contains("myprofile.storage.pin"));
    }

    #[test]
    fn test_btreemap_profiles_deterministic_order() {
        let mut profiles = BTreeMap::new();
        for name in ["zeta", "alpha", "mu", "beta"] {
            profiles.insert(
                name.to_string(),
                AgentProfileConfig {
                    max_operations: 64,
                    max_concurrent_sessions: 1,
                    browser_scope: BrowserScope::Session,
                    credential_selection: CredentialSelection::Single,
                    mode: AgentMode::Isolated,
                    principal_user: format!("u-{}", name),
                    credential_refs: None,
                    max_grant_ttl: None,
                    max_session_ttl: None,
                    storage: Some(AgentStorageConfig::Local {
                        path: PathBuf::from(format!("/tmp/{}", name)),
                        pin_path: PathBuf::from(format!("/tmp/{}-pin", name)),
                    }),
                    rules: vec![],
                    legacy: Default::default(),
                    device: None,
                    start_url: None,
                    browser_command: None,
                    browser_user: None,
                    browser_runtime_root: None,
                    browser_cdp_expose: None,
                    browser_cdp_port: None,
                },
            );
        }
        let keys: Vec<String> = profiles.keys().cloned().collect();
        assert_eq!(keys, vec!["alpha", "beta", "mu", "zeta"]);
    }

    #[test]
    fn test_credential_ref_serde_hex_roundtrip() {
        let cred_ref = CredentialRef::with_default_domain(b"test-credential");
        let json = serde_json::to_string(&cred_ref).unwrap();
        assert_eq!(json.len(), 66);
        assert!(json.starts_with('"'));
        assert!(json.ends_with('"'));
        let hex_str = &json[1..65];
        assert!(hex_str.chars().all(|c| c.is_ascii_hexdigit()));
        let parsed: CredentialRef = serde_json::from_str(&json).unwrap();
        assert_eq!(cred_ref, parsed);
    }

    #[test]
    fn test_credential_ref_serde_rejects_short_hex() {
        let json = r#""abcdef01""#;
        let result: std::result::Result<CredentialRef, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_credential_ref_serde_rejects_non_hex() {
        let json = format!(r#""{}""#, "g".repeat(64));
        let result: std::result::Result<CredentialRef, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_malformed_agents_section_fails_load() {
        use clap::Parser;
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            r#"
backend_type = "local"

[agents]
enabled = "not_a_bool"
"#,
        )
        .unwrap();

        let mut args =
            crate::config::Args::try_parse_from(["passless", "-c", config_path.to_str().unwrap()])
                .unwrap();
        let result = crate::config::AppConfig::load(&mut args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("[agents]"));
    }

    #[test]
    fn test_no_agents_section_backward_compatible() {
        use clap::Parser;
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            r#"
backend_type = "local"
"#,
        )
        .unwrap();

        let mut args =
            crate::config::Args::try_parse_from(["passless", "-c", config_path.to_str().unwrap()])
                .unwrap();
        let result = crate::config::AppConfig::load(&mut args);
        assert!(result.is_ok());
    }

    #[test]
    fn test_malformed_toml_fails_load() {
        use clap::Parser;
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "this is not valid toml {{{").unwrap();

        let mut args =
            crate::config::Args::try_parse_from(["passless", "-c", config_path.to_str().unwrap()])
                .unwrap();
        let result = crate::config::AppConfig::load(&mut args);
        assert!(result.is_err());
    }

    #[test]
    fn test_symlink_overlap_between_credential_store_and_pin_store() {
        let dir = tempfile::tempdir().unwrap();
        let real_dir = dir.path().join("real");
        std::fs::create_dir(&real_dir).unwrap();
        let symlink_dir = dir.path().join("link");
        std::os::unix::fs::symlink(&real_dir, &symlink_dir).unwrap();

        let mut profiles = BTreeMap::new();
        profiles.insert(
            "a".to_string(),
            AgentProfileConfig {
                max_operations: 64,
                max_concurrent_sessions: 1,
                browser_scope: BrowserScope::Session,
                credential_selection: CredentialSelection::Single,
                mode: AgentMode::Isolated,
                principal_user: "u1".to_string(),
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: real_dir.clone(),
                    pin_path: symlink_dir.clone(),
                }),
                rules: vec![],
                legacy: Default::default(),
                device: None,
                start_url: None,
                browser_command: None,
                browser_user: None,
                browser_runtime_root: None,
                browser_cdp_expose: None,
                browser_cdp_port: None,
            },
        );
        let config = AgentConfig {
            limits: Default::default(),
            enabled: true,
            profiles,
            audit_path: Some(dir.path().join("audit")),
            acknowledge_global_same_user: vec![],
            acknowledge_same_user_registration: vec![],
        };
        let err = config.validate(None).unwrap_err();
        assert!(err.to_string().contains("overlap"));
    }

    #[test]
    fn test_symlink_replacement_credential_store_via_audit_path() {
        let dir = tempfile::tempdir().unwrap();
        let real_audit = dir.path().join("audit_real");
        std::fs::create_dir(&real_audit).unwrap();
        let audit_link = dir.path().join("audit_link");
        std::os::unix::fs::symlink(&real_audit, &audit_link).unwrap();

        let cred_store = dir.path().join("creds");
        std::fs::create_dir(&cred_store).unwrap();
        let cred_link = dir.path().join("creds_link");
        std::os::unix::fs::symlink(&cred_store, &cred_link).unwrap();

        let nested = real_audit.join("sub");
        std::fs::create_dir(&nested).unwrap();

        let mut profiles = BTreeMap::new();
        profiles.insert(
            "a".to_string(),
            AgentProfileConfig {
                max_operations: 64,
                max_concurrent_sessions: 1,
                browser_scope: BrowserScope::Session,
                credential_selection: CredentialSelection::Single,
                mode: AgentMode::Isolated,
                principal_user: "u1".to_string(),
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: nested.clone(),
                    pin_path: dir.path().join("pin"),
                }),
                rules: vec![],
                legacy: Default::default(),
                device: None,
                start_url: None,
                browser_command: None,
                browser_user: None,
                browser_runtime_root: None,
                browser_cdp_expose: None,
                browser_cdp_port: None,
            },
        );
        let config = AgentConfig {
            limits: Default::default(),
            enabled: true,
            profiles,
            audit_path: Some(audit_link),
            acknowledge_global_same_user: vec![],
            acknowledge_same_user_registration: vec![],
        };
        let err = config.validate(None).unwrap_err();
        assert!(err.to_string().contains("overlap"));
    }

    #[test]
    fn test_symlink_overlap_with_human_state_path() {
        let dir = tempfile::tempdir().unwrap();
        let human_real = dir.path().join("human_real");
        std::fs::create_dir(&human_real).unwrap();
        let human_link = dir.path().join("human_link");
        std::os::unix::fs::symlink(&human_real, &human_link).unwrap();

        let mut profiles = BTreeMap::new();
        profiles.insert(
            "a".to_string(),
            AgentProfileConfig {
                max_operations: 64,
                max_concurrent_sessions: 1,
                browser_scope: BrowserScope::Session,
                credential_selection: CredentialSelection::Single,
                mode: AgentMode::Isolated,
                principal_user: "u1".to_string(),
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: human_real.join("creds"),
                    pin_path: dir.path().join("pin"),
                }),
                rules: vec![],
                legacy: Default::default(),
                device: None,
                start_url: None,
                browser_command: None,
                browser_user: None,
                browser_runtime_root: None,
                browser_cdp_expose: None,
                browser_cdp_port: None,
            },
        );
        let config = AgentConfig {
            limits: Default::default(),
            enabled: true,
            profiles,
            audit_path: Some(dir.path().join("audit")),
            acknowledge_global_same_user: vec![],
            acknowledge_same_user_registration: vec![],
        };
        let err = config.validate(Some(human_link.as_path())).unwrap_err();
        assert!(err.to_string().contains("overlaps with human"));
    }

    #[test]
    fn test_migration_old_credential_store_field_rejected() {
        let toml_str = r#"
enabled = true

[profiles.bot]
mode = "isolated"
principal_user = "u"
credential_store = "/tmp/creds"
pin_store = "/tmp/pin"

[profiles.bot.device]
name = "n"
phys = "p"
uniq = "u"
vendor_id = 1
product_id = 2
"#;
        let result: std::result::Result<AgentConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("credential_store") || err.contains("unknown field"),
            "expected migration error about old field, got: {}",
            err
        );
    }

    #[test]
    fn test_migration_old_pin_store_field_rejected() {
        let toml_str = r#"
enabled = true

[profiles.bot]
mode = "isolated"
principal_user = "u"
pin_store = "/tmp/pin"

[profiles.bot.storage.local]
path = "/tmp/creds"
pin_path = "/tmp/pin2"

[profiles.bot.device]
name = "n"
phys = "p"
uniq = "u"
vendor_id = 1
product_id = 2
"#;
        let result: std::result::Result<AgentConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("pin_store"));
    }

    #[test]
    fn test_snapshot_toml_local_storage_roundtrip() {
        let toml_str = r#"
enabled = true

[profiles.bot]
mode = "isolated"
principal_user = "bot-user"

[profiles.bot.device]
name = "agent-bot"
phys = "bot-phys"
uniq = "bot-uniq"
vendor_id = 4660
product_id = 22137

[profiles.bot.storage.local]
path = "/var/lib/passless-agent/bot/credentials"
pin_path = "/var/lib/passless-agent/bot/pin"
"#;
        let config: AgentConfig = toml::from_str(toml_str).unwrap();
        let profile = config.profiles.get("bot").unwrap();
        assert_eq!(profile.mode, AgentMode::Isolated);
        match &profile.storage {
            Some(AgentStorageConfig::Local { path, pin_path }) => {
                assert_eq!(
                    path,
                    &PathBuf::from("/var/lib/passless-agent/bot/credentials")
                );
                assert_eq!(pin_path, &PathBuf::from("/var/lib/passless-agent/bot/pin"));
            }
            other => panic!("expected Local storage, got: {:?}", other),
        }
    }

    #[test]
    fn test_snapshot_toml_pass_storage_roundtrip() {
        let toml_str = r#"
enabled = true

[profiles.ci]
mode = "isolated"
principal_user = "ci-user"

[profiles.ci.device]
name = "agent-ci"
phys = "ci-phys"
uniq = "ci-uniq"
vendor_id = 4660
product_id = 22138

[profiles.ci.storage.pass]
store_path = "/home/user/.password-store"
path = "fido2/ci"
gpg_backend = "gpgme"
pin_path = "pin"
git_sync = true
git_auto_push = false
"#;
        let config: AgentConfig = toml::from_str(toml_str).unwrap();
        let profile = config.profiles.get("ci").unwrap();
        match &profile.storage {
            Some(AgentStorageConfig::Pass {
                store_path,
                path,
                gpg_backend,
                pin_path,
                git_sync,
                git_auto_push,
            }) => {
                assert_eq!(store_path, &PathBuf::from("/home/user/.password-store"));
                assert_eq!(path, "fido2/ci");
                assert_eq!(gpg_backend, "gpgme");
                assert_eq!(pin_path, &PathBuf::from("pin"));
                assert!(*git_sync);
                assert!(!*git_auto_push);
            }
            other => panic!("expected Pass storage, got: {:?}", other),
        }
        let serialized = toml::to_string(&config).unwrap();
        let decoded: AgentConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(serialized, toml::to_string(&decoded).unwrap());
    }

    #[test]
    fn test_snapshot_toml_pass_storage_default_gpg_backend() {
        let toml_str = r#"
enabled = true

[profiles.ci]
mode = "isolated"
principal_user = "ci-user"

[profiles.ci.device]
name = "agent-ci"
phys = "ci-phys"
uniq = "ci-uniq"
vendor_id = 4660
product_id = 22138

[profiles.ci.storage.pass]
store_path = "/home/user/.password-store"
path = "fido2"
pin_path = "pin"
"#;
        let config: AgentConfig = toml::from_str(toml_str).unwrap();
        let profile = config.profiles.get("ci").unwrap();
        match &profile.storage {
            Some(AgentStorageConfig::Pass {
                gpg_backend,
                git_sync,
                git_auto_push,
                ..
            }) => {
                assert_eq!(gpg_backend, "gnupg-bin");
                assert!(*git_sync);
                assert!(*git_auto_push);
            }
            other => panic!("expected Pass storage, got: {:?}", other),
        }
    }

    #[cfg(feature = "tpm")]
    #[test]
    fn test_snapshot_toml_tpm_storage_roundtrip() {
        let toml_str = r#"
enabled = true

[profiles.secure]
mode = "isolated"
principal_user = "secure-user"

[profiles.secure.device]
name = "agent-secure"
phys = "secure-phys"
uniq = "secure-uniq"
vendor_id = 4660
product_id = 22139

[profiles.secure.storage.tpm]
path = "/var/lib/passless-agent/secure/tpm"
tcti = "swtpm:path=/tmp/swtpm-sock"
pin_path = "/var/lib/passless-agent/secure/pin"
"#;
        let config: AgentConfig = toml::from_str(toml_str).unwrap();
        let profile = config.profiles.get("secure").unwrap();
        match &profile.storage {
            Some(AgentStorageConfig::Tpm {
                path,
                tcti,
                pin_path,
                portable,
            }) => {
                assert_eq!(path, &PathBuf::from("/var/lib/passless-agent/secure/tpm"));
                assert_eq!(tcti, "swtpm:path=/tmp/swtpm-sock");
                assert_eq!(
                    pin_path,
                    &PathBuf::from("/var/lib/passless-agent/secure/pin")
                );
                assert!(!portable);
            }
            other => panic!("expected Tpm storage, got: {:?}", other),
        }
    }

    #[cfg(feature = "tpm")]
    #[test]
    fn test_snapshot_toml_tpm_storage_default_tcti() {
        let toml_str = r#"
enabled = true

[profiles.secure]
mode = "isolated"
principal_user = "secure-user"

[profiles.secure.device]
name = "agent-secure"
phys = "secure-phys"
uniq = "secure-uniq"
vendor_id = 4660
product_id = 22139

[profiles.secure.storage.tpm]
path = "/var/lib/passless-agent/secure/tpm"
pin_path = "/var/lib/passless-agent/secure/pin"
"#;
        let config: AgentConfig = toml::from_str(toml_str).unwrap();
        let profile = config.profiles.get("secure").unwrap();
        match &profile.storage {
            Some(AgentStorageConfig::Tpm { tcti, .. }) => {
                assert_eq!(tcti, "device:/dev/tpmrm0");
            }
            other => panic!("expected Tpm storage, got: {:?}", other),
        }
    }

    #[test]
    fn test_storage_backend_config_conversion_local() {
        let storage = AgentStorageConfig::Local {
            path: PathBuf::from("/tmp/creds"),
            pin_path: PathBuf::from("/tmp/pin"),
        };
        let backend = storage.to_backend_config();
        match backend {
            crate::config::BackendConfig::Local { path } => {
                assert_eq!(path, "/tmp/creds");
            }
            _ => panic!("expected Local backend"),
        }
    }

    #[test]
    fn test_storage_backend_config_conversion_pass() {
        let storage = AgentStorageConfig::Pass {
            store_path: PathBuf::from("/home/user/.password-store"),
            path: "fido2".to_string(),
            gpg_backend: "gnupg-bin".to_string(),
            pin_path: PathBuf::from("pin"),
            git_sync: true,
            git_auto_push: true,
        };
        let backend = storage.to_backend_config();
        match backend {
            crate::config::BackendConfig::Pass {
                store_path,
                path,
                gpg_backend,
            } => {
                assert_eq!(store_path, "/home/user/.password-store");
                assert_eq!(path, "fido2");
                assert_eq!(gpg_backend, "gnupg-bin");
            }
            _ => panic!("expected Pass backend"),
        }
    }

    #[test]
    fn test_storage_all_paths_returns_two_entries() {
        let storage = AgentStorageConfig::Local {
            path: PathBuf::from("/tmp/creds"),
            pin_path: PathBuf::from("/tmp/pin"),
        };
        let paths = storage.all_paths();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0].0, "credential");
        assert_eq!(paths[1].0, "pin");
    }

    #[test]
    fn test_storage_pin_paths_never_shared_across_profiles() {
        let mut profiles = BTreeMap::new();
        let shared_pin = PathBuf::from("/tmp/shared-pin");
        profiles.insert(
            "a".to_string(),
            AgentProfileConfig {
                max_operations: 64,
                max_concurrent_sessions: 1,
                browser_scope: BrowserScope::Session,
                credential_selection: CredentialSelection::Single,
                mode: AgentMode::Isolated,
                principal_user: "u1".to_string(),
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: PathBuf::from("/tmp/a/creds"),
                    pin_path: shared_pin.clone(),
                }),
                rules: vec![],
                legacy: Default::default(),
                device: None,
                start_url: None,
                browser_command: None,
                browser_user: None,
                browser_runtime_root: None,
                browser_cdp_expose: None,
                browser_cdp_port: None,
            },
        );
        profiles.insert(
            "b".to_string(),
            AgentProfileConfig {
                max_operations: 64,
                max_concurrent_sessions: 1,
                browser_scope: BrowserScope::Session,
                credential_selection: CredentialSelection::Single,
                mode: AgentMode::Isolated,
                principal_user: "u2".to_string(),
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: PathBuf::from("/tmp/b/creds"),
                    pin_path: shared_pin,
                }),
                rules: vec![],
                legacy: Default::default(),
                device: None,
                start_url: None,
                browser_command: None,
                browser_user: None,
                browser_runtime_root: None,
                browser_cdp_expose: None,
                browser_cdp_port: None,
            },
        );
        let config = AgentConfig {
            limits: Default::default(),
            enabled: true,
            profiles,
            audit_path: Some(PathBuf::from("/tmp/audit")),
            acknowledge_global_same_user: vec![],
            acknowledge_same_user_registration: vec![],
        };
        let err = config.validate(None).unwrap_err();
        assert!(err.to_string().contains("overlap"));
    }

    #[test]
    fn test_storage_display() {
        let local = AgentStorageConfig::Local {
            path: PathBuf::from("/tmp/c"),
            pin_path: PathBuf::from("/tmp/p"),
        };
        assert_eq!(format!("{}", local), "local");
        let pass = AgentStorageConfig::Pass {
            store_path: PathBuf::from("/tmp/s"),
            path: "fido2".to_string(),
            gpg_backend: "gnupg-bin".to_string(),
            pin_path: PathBuf::from("pin"),
            git_sync: true,
            git_auto_push: true,
        };
        assert_eq!(format!("{}", pass), "pass");
    }

    #[test]
    fn test_storage_serde_rejects_unknown_variant() {
        let json = r#"{"unknown": {"path": "/tmp/c", "pin_path": "/tmp/p"}}"#;
        let result: std::result::Result<AgentStorageConfig, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_storage_serde_rejects_missing_pin_path() {
        let json = r#"{"local": {"path": "/tmp/c"}}"#;
        let result: std::result::Result<AgentStorageConfig, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_storage_cross_profile_credential_overlap_rejected() {
        let mut profiles = BTreeMap::new();
        let shared_cred = PathBuf::from("/tmp/shared-creds");
        profiles.insert(
            "a".to_string(),
            AgentProfileConfig {
                max_operations: 64,
                max_concurrent_sessions: 1,
                browser_scope: BrowserScope::Session,
                credential_selection: CredentialSelection::Single,
                mode: AgentMode::Isolated,
                principal_user: "u1".to_string(),
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: shared_cred.clone(),
                    pin_path: PathBuf::from("/tmp/a/pin"),
                }),
                rules: vec![],
                legacy: Default::default(),
                device: None,
                start_url: None,
                browser_command: None,
                browser_user: None,
                browser_runtime_root: None,
                browser_cdp_expose: None,
                browser_cdp_port: None,
            },
        );
        profiles.insert(
            "b".to_string(),
            AgentProfileConfig {
                max_operations: 64,
                max_concurrent_sessions: 1,
                browser_scope: BrowserScope::Session,
                credential_selection: CredentialSelection::Single,
                mode: AgentMode::Isolated,
                principal_user: "u2".to_string(),
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: shared_cred,
                    pin_path: PathBuf::from("/tmp/b/pin"),
                }),
                rules: vec![],
                legacy: Default::default(),
                device: None,
                start_url: None,
                browser_command: None,
                browser_user: None,
                browser_runtime_root: None,
                browser_cdp_expose: None,
                browser_cdp_port: None,
            },
        );
        let config = AgentConfig {
            limits: Default::default(),
            enabled: true,
            profiles,
            audit_path: Some(PathBuf::from("/tmp/audit")),
            acknowledge_global_same_user: vec![],
            acknowledge_same_user_registration: vec![],
        };
        let err = config.validate(None).unwrap_err();
        assert!(err.to_string().contains("overlap"));
    }

    #[test]
    fn test_storage_audit_overlap_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("audit");
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "a".to_string(),
            AgentProfileConfig {
                max_operations: 64,
                max_concurrent_sessions: 1,
                browser_scope: BrowserScope::Session,
                credential_selection: CredentialSelection::Single,
                mode: AgentMode::Isolated,
                principal_user: "u1".to_string(),
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: dir.path().join("creds"),
                    pin_path: audit.clone(),
                }),
                rules: vec![],
                legacy: Default::default(),
                device: None,
                start_url: None,
                browser_command: None,
                browser_user: None,
                browser_runtime_root: None,
                browser_cdp_expose: None,
                browser_cdp_port: None,
            },
        );
        let config = AgentConfig {
            limits: Default::default(),
            enabled: true,
            profiles,
            audit_path: Some(audit),
            acknowledge_global_same_user: vec![],
            acknowledge_same_user_registration: vec![],
        };
        let err = config.validate(None).unwrap_err();
        assert!(err.to_string().contains("overlap"));
    }

    #[test]
    fn test_storage_pass_credential_path_derives_from_store_and_subpath() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir_all(&store).unwrap();
        let storage = AgentStorageConfig::Pass {
            store_path: store.clone(),
            path: "fido2".to_string(),
            gpg_backend: "gnupg-bin".to_string(),
            pin_path: PathBuf::from("pin"),
            git_sync: true,
            git_auto_push: true,
        };
        let cred_path = storage.credential_state_path();
        let expected = crate::config::BackendConfig::canonicalize_path(&store.join("fido2"));
        assert_eq!(cred_path, expected);
    }

    #[test]
    fn test_storage_pin_path_is_independent() {
        let storage = AgentStorageConfig::Local {
            path: PathBuf::from("/tmp/creds"),
            pin_path: PathBuf::from("/tmp/pin"),
        };
        let cred = storage.credential_state_path();
        let pin = storage.pin_state_path();
        assert_ne!(cred, pin);
    }

    #[test]
    fn test_isolated_mode_rejects_browser_user() {
        let mut profile = make_isolated_profile();
        profile.browser_user = Some("browser-user".to_string());
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("browser_user"));
    }

    #[test]
    fn test_isolated_mode_rejects_browser_runtime_root() {
        let mut profile = make_isolated_profile();
        profile.browser_runtime_root = Some(PathBuf::from("/var/run/browser"));
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("browser_runtime_root"));
    }

    #[cfg(feature = "tpm")]
    #[test]
    fn test_storage_backend_config_conversion_tpm_portable_true() {
        let storage = AgentStorageConfig::Tpm {
            path: PathBuf::from("/tmp/tpm-creds"),
            tcti: "swtpm:host=127.0.0.1,port=2321".to_string(),
            pin_path: PathBuf::from("/tmp/tpm-pin"),
            portable: true,
        };
        let backend = storage.to_backend_config();
        match backend {
            crate::config::BackendConfig::Tpm {
                path,
                tcti,
                portable,
            } => {
                assert_eq!(path, "/tmp/tpm-creds");
                assert_eq!(tcti, "swtpm:host=127.0.0.1,port=2321");
                assert!(portable);
            }
            _ => panic!("expected Tpm backend"),
        }
    }

    #[cfg(feature = "tpm")]
    #[test]
    fn test_storage_backend_config_conversion_tpm_portable_false() {
        let storage = AgentStorageConfig::Tpm {
            path: PathBuf::from("/tmp/tpm-creds"),
            tcti: "device:/dev/tpmrm0".to_string(),
            pin_path: PathBuf::from("/tmp/tpm-pin"),
            portable: false,
        };
        let backend = storage.to_backend_config();
        match backend {
            crate::config::BackendConfig::Tpm {
                path,
                tcti,
                portable,
            } => {
                assert_eq!(path, "/tmp/tpm-creds");
                assert_eq!(tcti, "device:/dev/tpmrm0");
                assert!(!portable);
            }
            _ => panic!("expected Tpm backend"),
        }
    }

    #[cfg(feature = "tpm")]
    #[test]
    fn test_snapshot_toml_tpm_storage_portable_true() {
        let toml_str = r#"
enabled = true

[profiles.secure]
mode = "isolated"
principal_user = "secure-user"

[profiles.secure.device]
name = "agent-secure"
phys = "secure-phys"
uniq = "secure-uniq"
vendor_id = 4660
product_id = 22139

[profiles.secure.storage.tpm]
path = "/var/lib/passless-agent/secure/tpm"
tcti = "swtpm:path=/tmp/swtpm-sock"
pin_path = "/var/lib/passless-agent/secure/pin"
portable = true
"#;
        let config: AgentConfig = toml::from_str(toml_str).unwrap();
        let profile = config.profiles.get("secure").unwrap();
        match &profile.storage {
            Some(AgentStorageConfig::Tpm {
                path,
                tcti,
                pin_path,
                portable,
            }) => {
                assert_eq!(path, &PathBuf::from("/var/lib/passless-agent/secure/tpm"));
                assert_eq!(tcti, "swtpm:path=/tmp/swtpm-sock");
                assert_eq!(
                    pin_path,
                    &PathBuf::from("/var/lib/passless-agent/secure/pin")
                );
                assert!(*portable);
            }
            other => panic!("expected Tpm storage, got: {:?}", other),
        }
    }

    #[test]
    fn global_same_user_requires_operator_acknowledgement() {
        let raw = r#"
enabled = true
audit_path = "/tmp/passless-agent-audit"

[profiles.coding]
mode = "same-user"
principal_user = "alice"

[[profiles.coding.rules]]
rp_id = "*"
authenticate = "allow"
register = "deny"
"#;
        let cfg: AgentConfig = toml::from_str(raw).unwrap();
        let err = cfg.validate(None).unwrap_err().to_string();
        assert!(err.contains("acknowledge_global_same_user"));
    }

    #[test]
    fn global_same_user_accepts_operator_acknowledgement() {
        let raw = r#"
enabled = true
audit_path = "/tmp/passless-agent-audit"
acknowledge_global_same_user = ["coding"]

[profiles.coding]
mode = "same-user"
principal_user = "alice"

[[profiles.coding.rules]]
rp_id = "*"
authenticate = "allow"
register = "deny"
"#;
        let cfg: AgentConfig = toml::from_str(raw).unwrap();
        cfg.validate(None).unwrap();
    }

    #[test]
    fn same_user_registration_requires_operator_acknowledgement() {
        let raw = r#"
enabled = true
audit_path = "/tmp/passless-agent-audit"

[profiles.coding]
mode = "same-user"
principal_user = "alice"

[[profiles.coding.rules]]
rp_id = "example.com"
authenticate = "allow"
register = "request"
"#;
        let cfg: AgentConfig = toml::from_str(raw).unwrap();
        let err = cfg.validate(None).unwrap_err().to_string();
        assert!(err.contains("acknowledge_same_user_registration"));
    }

    #[test]
    fn dangerous_acknowledgement_rejects_unknown_profile() {
        let raw = r#"
enabled = true
audit_path = "/tmp/passless-agent-audit"
acknowledge_global_same_user = ["missing"]
"#;
        let cfg: AgentConfig = toml::from_str(raw).unwrap();
        let err = cfg.validate(None).unwrap_err().to_string();
        assert!(err.contains("unknown profile 'missing'"));
    }

    #[test]
    fn credential_selection_for_rp_uses_exact_rule_override() {
        let mut profile = make_isolated_profile();
        profile.credential_selection = CredentialSelection::Single;
        profile.rules = vec![AgentRpRule {
            rp_id: "github.com".to_string(),
            register: RuleAction::Deny,
            authenticate: RuleAction::Allow,
            credential_selection: Some(CredentialSelection::Newest),
        }];
        assert_eq!(
            profile.credential_selection_for_rp("github.com"),
            CredentialSelection::Newest
        );
    }

    #[test]
    fn credential_selection_for_rp_falls_back_to_profile_default() {
        let mut profile = make_isolated_profile();
        profile.credential_selection = CredentialSelection::Newest;
        profile.rules = vec![AgentRpRule {
            rp_id: "github.com".to_string(),
            register: RuleAction::Deny,
            authenticate: RuleAction::Allow,
            credential_selection: None,
        }];
        assert_eq!(
            profile.credential_selection_for_rp("github.com"),
            CredentialSelection::Newest
        );
    }

    #[test]
    fn rule_credential_ref_must_be_in_credential_refs() {
        let cred_ref = CredentialRef::with_default_domain(b"test-cred");
        let mut profile = make_isolated_profile();
        profile.credential_refs = Some(vec![cred_ref.clone()]);
        profile.rules = vec![AgentRpRule {
            rp_id: "github.com".to_string(),
            register: RuleAction::Deny,
            authenticate: RuleAction::Allow,
            credential_selection: Some(CredentialSelection::Credential(cred_ref)),
        }];
        assert!(profile.validate(&ProfileId::new("test").unwrap()).is_ok());
    }

    #[test]
    fn rule_credential_ref_rejected_when_not_in_credential_refs() {
        let cred_ref = CredentialRef::with_default_domain(b"test-cred");
        let other_ref = CredentialRef::with_default_domain(b"other-cred");
        let mut profile = make_isolated_profile();
        profile.credential_refs = Some(vec![cred_ref]);
        profile.rules = vec![AgentRpRule {
            rp_id: "github.com".to_string(),
            register: RuleAction::Deny,
            authenticate: RuleAction::Allow,
            credential_selection: Some(CredentialSelection::Credential(other_ref)),
        }];
        let err = profile
            .validate(&ProfileId::new("test").unwrap())
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("must be included in credential_refs")
        );
    }

    #[test]
    fn wildcard_rule_cannot_use_credential_ref() {
        let cred_ref = CredentialRef::with_default_domain(b"test-cred");
        let mut profile = make_isolated_profile();
        profile.mode = AgentMode::SameUser;
        profile.rules = vec![AgentRpRule {
            rp_id: "*".to_string(),
            register: RuleAction::Deny,
            authenticate: RuleAction::Allow,
            credential_selection: Some(CredentialSelection::Credential(cred_ref)),
        }];
        let err = profile
            .validate(&ProfileId::new("test").unwrap())
            .unwrap_err();
        assert!(err.to_string().contains("always selects with `single`"));
    }

    #[test]
    fn browser_scope_session_rejects_max_zero() {
        let mut profile = make_isolated_profile();
        profile.browser_scope = BrowserScope::Session;
        profile.max_concurrent_sessions = 0;
        let err = profile
            .validate(&ProfileId::new("test").unwrap())
            .unwrap_err();
        assert!(err.to_string().contains("max_concurrent_sessions"));
    }

    #[test]
    fn browser_scope_session_rejects_max_above_limit() {
        let mut profile = make_isolated_profile();
        profile.browser_scope = BrowserScope::Session;
        profile.max_concurrent_sessions = 65;
        let err = profile
            .validate(&ProfileId::new("test").unwrap())
            .unwrap_err();
        assert!(err.to_string().contains("max_concurrent_sessions"));
    }

    #[test]
    fn browser_scope_session_accepts_max_one() {
        let mut profile = make_isolated_profile();
        profile.browser_scope = BrowserScope::Session;
        profile.max_concurrent_sessions = 1;
        assert!(profile.validate(&ProfileId::new("test").unwrap()).is_ok());
    }

    #[test]
    fn browser_scope_session_accepts_max_64() {
        let mut profile = make_isolated_profile();
        profile.browser_scope = BrowserScope::Session;
        profile.max_concurrent_sessions = 64;
        assert!(profile.validate(&ProfileId::new("test").unwrap()).is_ok());
    }

    #[test]
    fn browser_scope_session_rejects_fixed_port_with_max_gt_1() {
        let mut profile = make_isolated_profile();
        profile.browser_scope = BrowserScope::Session;
        profile.max_concurrent_sessions = 2;
        profile.browser_cdp_expose = Some(CdpExposeMode::Port);
        profile.browser_cdp_port = Some(9222);
        let err = profile
            .validate(&ProfileId::new("test").unwrap())
            .unwrap_err();
        assert!(err.to_string().contains("browser_cdp_port"));
    }

    #[test]
    fn browser_scope_session_accepts_fixed_port_with_max_1() {
        let mut profile = make_isolated_profile();
        profile.browser_scope = BrowserScope::Session;
        profile.max_concurrent_sessions = 1;
        profile.browser_cdp_expose = Some(CdpExposeMode::Port);
        profile.browser_cdp_port = Some(9222);
        assert!(profile.validate(&ProfileId::new("test").unwrap()).is_ok());
    }

    #[test]
    fn browser_scope_session_accepts_ephemeral_port_with_max_gt_1() {
        let mut profile = make_isolated_profile();
        profile.browser_scope = BrowserScope::Session;
        profile.max_concurrent_sessions = 4;
        profile.browser_cdp_expose = Some(CdpExposeMode::Port);
        profile.browser_cdp_port = Some(0);
        assert!(profile.validate(&ProfileId::new("test").unwrap()).is_ok());
    }

    #[test]
    fn browser_scope_profile_accepts_max_zero() {
        let mut profile = make_isolated_profile();
        profile.browser_scope = BrowserScope::Profile;
        profile.max_concurrent_sessions = 0;
        assert!(profile.validate(&ProfileId::new("test").unwrap()).is_ok());
    }

    #[test]
    fn browser_scope_profile_accepts_max_two() {
        let mut profile = make_isolated_profile();
        profile.browser_scope = BrowserScope::Profile;
        profile.max_concurrent_sessions = 2;
        assert!(profile.validate(&ProfileId::new("test").unwrap()).is_ok());
    }

    #[test]
    fn browser_scope_profile_accepts_fixed_port_with_max_gt_1() {
        let mut profile = make_isolated_profile();
        profile.browser_scope = BrowserScope::Profile;
        profile.max_concurrent_sessions = 4;
        profile.browser_cdp_expose = Some(CdpExposeMode::Port);
        profile.browser_cdp_port = Some(9222);
        assert!(profile.validate(&ProfileId::new("test").unwrap()).is_ok());
    }

    #[test]
    fn browser_scope_profile_accepts_fixed_port_with_max_zero() {
        let mut profile = make_isolated_profile();
        profile.browser_scope = BrowserScope::Profile;
        profile.max_concurrent_sessions = 0;
        profile.browser_cdp_expose = Some(CdpExposeMode::Port);
        profile.browser_cdp_port = Some(9222);
        assert!(profile.validate(&ProfileId::new("test").unwrap()).is_ok());
    }

    #[test]
    fn browser_scope_profile_rejects_max_above_limit() {
        let mut profile = make_isolated_profile();
        profile.browser_scope = BrowserScope::Profile;
        profile.max_concurrent_sessions = 65;
        let err = profile
            .validate(&ProfileId::new("test").unwrap())
            .unwrap_err();
        assert!(err.to_string().contains("max_concurrent_sessions"));
    }

    #[test]
    fn browser_scope_serde_roundtrip() {
        let session: BrowserScope = serde_json::from_str("\"session\"").unwrap();
        assert_eq!(session, BrowserScope::Session);
        let profile: BrowserScope = serde_json::from_str("\"profile\"").unwrap();
        assert_eq!(profile, BrowserScope::Profile);
        let default: BrowserScope = serde_json::from_str("null").unwrap_or_default();
        assert_eq!(default, BrowserScope::Session);
    }

    // ---- P4: rule schema, legacy mapping, validation and resolution ----

    #[test]
    fn rule_action_defaults_to_deny_and_roundtrips_lowercase() {
        assert_eq!(RuleAction::default(), RuleAction::Deny);
        for (action, text) in [
            (RuleAction::Deny, "\"deny\""),
            (RuleAction::Allow, "\"allow\""),
            (RuleAction::Request, "\"request\""),
        ] {
            assert_eq!(serde_json::to_string(&action).unwrap(), text);
            assert_eq!(serde_json::from_str::<RuleAction>(text).unwrap(), action);
            assert_eq!(action.to_string(), text.trim_matches('"'));
        }
        assert!(serde_json::from_str::<RuleAction>("\"autonomous\"").is_err());
    }

    #[test]
    fn missing_rule_action_denies() {
        let profile = parse_profile("[[rules]]\nrp_id = \"example.com\"\n").unwrap();
        assert_eq!(profile.rules[0].authenticate, RuleAction::Deny);
        assert_eq!(profile.rules[0].register, RuleAction::Deny);
        assert!(profile.legacy.warnings.is_empty());

        let profile =
            parse_profile("[[rules]]\nrp_id = \"example.com\"\nauthenticate = \"allow\"\n")
                .unwrap();
        assert_eq!(profile.rules[0].authenticate, RuleAction::Allow);
        assert_eq!(profile.rules[0].register, RuleAction::Deny);

        // A profile without any rule resolves everything to deny.
        let profile = parse_profile("").unwrap();
        assert!(profile.rules.is_empty());
        assert_eq!(
            profile
                .resolve(PolicyAction::Authenticate, "example.com")
                .action,
            RuleAction::Deny
        );
    }

    #[test]
    fn rule_rejects_unknown_fields() {
        let err = parse_profile(
            "[[rules]]\nrp_id = \"example.com\"\nauthenticate = \"allow\"\nuser_presence = \"agent\"\n",
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("user_presence") || err.contains("unknown field"),
            "{err}"
        );
    }

    fn evidence_table(authorization: &str, up: &str, uv: &str) -> String {
        format!(
            "{{ authorization = \"{authorization}\", user_presence = \"{up}\", user_verification = \"{uv}\" }}"
        )
    }

    enum Expect {
        /// Parses to this action; `true` when exactly one deprecation warning is recorded.
        Mapped(RuleAction, bool),
        /// Fails to parse with a message containing this text.
        Rejected(&'static str),
    }

    fn legacy_mapping_rows() -> Vec<(String, Expect)> {
        use Expect::{Mapped, Rejected};
        const UNSAFE: &str = "cannot be mapped safely";
        let table = |a: &str, up: &str, uv: &str| evidence_table(a, up, uv);
        let mut rows: Vec<(String, Expect)> = vec![
            // The new vocabulary: no warning.
            ("\"deny\"".into(), Mapped(RuleAction::Deny, false)),
            ("\"allow\"".into(), Mapped(RuleAction::Allow, false)),
            ("\"request\"".into(), Mapped(RuleAction::Request, false)),
            // Presets.
            ("\"autonomous\"".into(), Mapped(RuleAction::Allow, true)),
            ("\"supervised\"".into(), Mapped(RuleAction::Request, true)),
            ("\"maybe\"".into(), Rejected("unknown")),
            // deny: only with no evidence.
            (
                table("deny", "none", "none"),
                Mapped(RuleAction::Deny, true),
            ),
            (table("deny", "agent", "none"), Rejected(UNSAFE)),
            (table("deny", "none", "agent"), Rejected(UNSAFE)),
            (table("deny", "human", "human"), Rejected(UNSAFE)),
            (table("deny", "policy", "policy"), Rejected(UNSAFE)),
            // confirm: anything maps to request.
            (
                table("confirm", "human", "human"),
                Mapped(RuleAction::Request, true),
            ),
            (
                table("confirm", "agent", "agent"),
                Mapped(RuleAction::Request, true),
            ),
            (
                table("confirm", "none", "none"),
                Mapped(RuleAction::Request, true),
            ),
            (
                table("confirm", "human", "none"),
                Mapped(RuleAction::Request, true),
            ),
            // allow: only agent (or its `policy` alias) evidence maps.
            (
                table("allow", "agent", "agent"),
                Mapped(RuleAction::Allow, true),
            ),
            (
                table("allow", "policy", "policy"),
                Mapped(RuleAction::Allow, true),
            ),
            (
                table("allow", "policy", "agent"),
                Mapped(RuleAction::Allow, true),
            ),
        ];
        // Every other allow combination (human or none evidence) is a parse error.
        for up in ["human", "agent", "none"] {
            for uv in ["human", "agent", "none"] {
                if up == "agent" && uv == "agent" {
                    continue;
                }
                rows.push((table("allow", up, uv), Rejected(UNSAFE)));
            }
        }
        rows
    }

    #[test]
    fn legacy_mapping_table_maps_every_row() {
        for field in ["authenticate", "register"] {
            for (value, expect) in legacy_mapping_rows() {
                let body = format!("[[rules]]\nrp_id = \"example.com\"\n{field} = {value}\n");
                let parsed = parse_profile(&body);
                match expect {
                    Expect::Mapped(action, warns) => {
                        let profile = parsed
                            .unwrap_or_else(|err| panic!("`{field} = {value}` must parse: {err}"));
                        let rule = &profile.rules[0];
                        let (mapped, other) = match field {
                            "authenticate" => (rule.authenticate, rule.register),
                            _ => (rule.register, rule.authenticate),
                        };
                        assert_eq!(mapped, action, "`{field} = {value}`");
                        assert_eq!(other, RuleAction::Deny, "the other action stays deny");
                        if warns {
                            assert_eq!(
                                profile.legacy.warnings.len(),
                                1,
                                "`{field} = {value}`: {:?}",
                                profile.legacy.warnings
                            );
                            let warning = &profile.legacy.warnings[0];
                            assert!(warning.contains(field), "{warning}");
                            assert!(warning.contains("example.com"), "{warning}");
                            assert!(
                                warning.contains(&format!("`{field} = \"{action}\"`")),
                                "warning names the replacement: {warning}"
                            );
                            let reported = profile.deprecation_warnings(&pid("coding"));
                            assert_eq!(reported.len(), 1);
                            assert!(reported[0].contains("coding"), "{}", reported[0]);
                        } else {
                            assert!(
                                profile.legacy.warnings.is_empty(),
                                "`{field} = {value}` is the new vocabulary: {:?}",
                                profile.legacy.warnings
                            );
                            assert!(profile.deprecation_warnings(&pid("coding")).is_empty());
                        }
                        assert!(profile.legacy.removed_keys.is_empty());
                    }
                    Expect::Rejected(needle) => {
                        // Parsing never fails on legacy vocabulary (invariant 23): the unmappable
                        // action parses as `deny` and `validate` reports the problem.
                        let profile = parsed.unwrap_or_else(|e| {
                            panic!("`{field} = {value}` must parse leniently: {e}")
                        });
                        let rule = &profile.rules[0];
                        assert_eq!(
                            if field == "authenticate" {
                                rule.authenticate
                            } else {
                                rule.register
                            },
                            RuleAction::Deny
                        );
                        let err = profile
                            .validate(&pid("coding"))
                            .err()
                            .unwrap_or_else(|| panic!("`{field} = {value}` must fail validate"))
                            .to_string();
                        assert!(err.contains(needle), "`{field} = {value}`: {err}");
                        assert!(err.contains(field), "error names the field: {err}");
                        assert!(err.contains("example.com"), "error names the rule: {err}");
                        if needle == "cannot be mapped safely" {
                            // Actionable: it says what to write instead.
                            assert!(
                                err.contains(&format!("{field} = \"")),
                                "error suggests a replacement: {err}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn legacy_allow_with_human_or_no_evidence_names_the_evidence() {
        let human = parse_profile(&format!(
            "[[rules]]\nrp_id = \"example.com\"\nauthenticate = {}\n",
            evidence_table("allow", "human", "human")
        ))
        .unwrap()
        .validate(&pid("coding"))
        .unwrap_err()
        .to_string();
        assert!(human.contains("cannot be mapped safely"), "{human}");
        assert!(human.contains("user_presence = human"), "{human}");

        let none = parse_profile(&format!(
            "[[rules]]\nrp_id = \"example.com\"\nregister = {}\n",
            evidence_table("allow", "none", "none")
        ))
        .unwrap()
        .validate(&pid("coding"))
        .unwrap_err()
        .to_string();
        assert!(none.contains("cannot be mapped safely"), "{none}");
        assert!(none.contains("user_presence = none"), "{none}");
    }

    #[test]
    fn invalid_legacy_rule_does_not_break_load_when_agents_disabled() {
        use clap::Parser;
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let local = dir.path().join("store");
        std::fs::write(
            &config_path,
            format!(
                r#"
backend_type = "local"

[local]
path = "{}"

[agents]
enabled = false

[agents.profiles.coding]
mode = "same-user"
principal_user = "alice"

[[agents.profiles.coding.rules]]
rp_id = "example.com"
authenticate = {{ authorization = "allow", user_presence = "none", user_verification = "none" }}
register = "maybe"
"#,
                local.display()
            ),
        )
        .unwrap();
        let mut args =
            crate::config::Args::try_parse_from(["passless", "-c", config_path.to_str().unwrap()])
                .unwrap();
        let config = crate::config::AppConfig::load(&mut args)
            .expect("an invalid legacy rule must not break the human config load");
        // The human authenticator config is usable, and agents stay disabled and unvalidated.
        assert_eq!(config.backend_type, "local");
        assert!(config.backend().is_ok());
        assert!(!config.agents.enabled);
        config.validate().expect("validate skips disabled agents");

        // Enabled, the same config fails validation with an actionable message.
        let mut enabled = config.agents.clone();
        enabled.enabled = true;
        enabled.audit_path = Some(dir.path().join("audit"));
        let err = enabled.validate(None).unwrap_err().to_string();
        assert!(err.contains("coding"), "{err}");
        assert!(err.contains("cannot be mapped safely"), "{err}");
        assert!(err.contains("unknown `register` value 'maybe'"), "{err}");
    }

    #[test]
    fn wrongly_typed_legacy_action_is_reported_by_validate_not_parse() {
        let profile = parse_profile("[[rules]]\nrp_id = \"example.com\"\nauthenticate = 7\n")
            .expect("parses leniently");
        assert_eq!(profile.rules[0].authenticate, RuleAction::Deny);
        let err = profile.validate(&pid("coding")).unwrap_err().to_string();
        assert!(err.contains("unrecognized value"), "{err}");
    }

    #[test]
    fn grant_scope_is_capped_without_wildcard_and_collapses_with_one() {
        let denies = |n: usize| -> Vec<AgentRpRule> {
            (0..n)
                .map(|i| {
                    rule(
                        &format!("deny{i}.example.com"),
                        RuleAction::Deny,
                        RuleAction::Deny,
                    )
                })
                .collect()
        };

        // Exactly at the limit: valid, and every rule's RP is in the scope.
        let at_limit = same_user_profile(denies(MAX_GRANT_RP_IDS));
        at_limit.validate(&pid("coding")).unwrap();
        assert_eq!(at_limit.rule_rp_ids().len(), MAX_GRANT_RP_IDS);

        // One over, no wildcard: rejected at config validation with a clear message, never at runtime.
        let over = same_user_profile(denies(MAX_GRANT_RP_IDS + 1));
        let err = over.validate(&pid("coding")).unwrap_err().to_string();
        assert!(err.contains("exceed the limit of 32"), "{err}");
        assert!(err.contains("coding"), "{err}");

        // A wildcard collapses the scope: `*` allow plus many exact denies is valid and the scope is `*`.
        let mut rules = denies(MAX_GRANT_RP_IDS + 20);
        rules.push(rule("*", RuleAction::Allow, RuleAction::Deny));
        let wildcard = same_user_profile(rules.clone());
        wildcard.validate(&pid("coding")).unwrap();
        assert_eq!(wildcard.rule_rp_ids(), vec!["*".to_string()]);

        // `localhost` is never matched by `*`, so an exact localhost rule stays in the scope.
        rules.push(rule("localhost", RuleAction::Allow, RuleAction::Deny));
        let with_localhost = same_user_profile(rules);
        with_localhost.validate(&pid("coding")).unwrap();
        assert_eq!(
            with_localhost.rule_rp_ids(),
            vec!["*".to_string(), "localhost".to_string()]
        );
    }

    #[test]
    fn legacy_rule_with_both_fields_records_one_warning_per_field() {
        let profile = parse_profile(
            "[[rules]]\nrp_id = \"example.com\"\nauthenticate = \"autonomous\"\nregister = \"supervised\"\n",
        )
        .unwrap();
        assert_eq!(profile.rules[0].authenticate, RuleAction::Allow);
        assert_eq!(profile.rules[0].register, RuleAction::Request);
        assert_eq!(profile.legacy.warnings.len(), 2);
    }

    #[test]
    fn config_deprecation_warnings_aggregate_across_profiles() {
        let raw = r#"
enabled = true
audit_path = "/tmp/passless-agent-audit-p4"

[profiles.alpha]
mode = "same-user"
principal_user = "alice"

[[profiles.alpha.rules]]
rp_id = "a.example.com"
authenticate = "autonomous"
register = "supervised"

[profiles.beta]
mode = "same-user"
principal_user = "alice"

[[profiles.beta.rules]]
rp_id = "b.example.com"
authenticate = { authorization = "confirm", user_presence = "human", user_verification = "human" }

[profiles.gamma]
mode = "same-user"
principal_user = "alice"

[profiles.gamma.device]
name = "legacy"

[[profiles.gamma.rules]]
rp_id = "c.example.com"
authenticate = "allow"
register = "deny"

[profiles.clean]
mode = "same-user"
principal_user = "alice"

[[profiles.clean.rules]]
rp_id = "d.example.com"
authenticate = "request"
"#;
        let cfg: AgentConfig = toml::from_str(raw).unwrap();
        let warnings = cfg.deprecation_warnings();
        let count = |profile: &str| {
            warnings
                .iter()
                .filter(|w| w.contains(&format!("agent profile '{profile}'")))
                .count()
        };
        assert_eq!(count("alpha"), 2, "{warnings:?}");
        assert_eq!(count("beta"), 1, "{warnings:?}");
        assert_eq!(count("gamma"), 1, "device table only: {warnings:?}");
        assert_eq!(count("clean"), 0, "{warnings:?}");
        assert_eq!(warnings.len(), 4, "{warnings:?}");
    }

    #[test]
    fn config_without_legacy_vocabulary_has_no_warnings() {
        let raw = r#"
enabled = true
audit_path = "/tmp/passless-agent-audit-p4"
acknowledge_global_same_user = ["coding"]

[profiles.coding]
mode = "same-user"
principal_user = "alice"

[[profiles.coding.rules]]
rp_id = "github.com"
authenticate = "allow"
register = "deny"

[[profiles.coding.rules]]
rp_id = "*"
authenticate = "request"
register = "deny"
"#;
        let cfg: AgentConfig = toml::from_str(raw).unwrap();
        assert!(cfg.deprecation_warnings().is_empty());
        cfg.validate(None).unwrap();
    }

    #[test]
    fn removed_profile_keys_parse_but_fail_validation_with_migration_message() {
        for (key, value) in [
            ("rp_ids", "[\"example.com\"]"),
            ("require_uv", "true"),
            ("registration_allowed", "true"),
            ("human_verification_prompt", "\"always\""),
        ] {
            let profile = parse_profile(&format!("{key} = {value}\n")).unwrap();
            assert_eq!(profile.legacy.removed_keys, vec![key.to_string()]);

            let err = profile
                .validate(&pid("legacy-bot"))
                .unwrap_err()
                .to_string();
            assert!(err.contains("legacy-bot"), "{err}");
            assert!(err.contains(&format!("`{key}`")), "{err}");
            assert!(
                err.contains("[[agents.profiles.legacy-bot.rules]]"),
                "{err}"
            );

            // The same failure surfaces through the whole-config validation.
            let cfg = agent_config(profile, false, false);
            let err = cfg.validate(None).unwrap_err().to_string();
            assert!(
                err.contains("coding") && err.contains(&format!("`{key}`")),
                "{err}"
            );
        }
    }

    #[test]
    fn removed_profile_keys_are_all_reported_together() {
        let profile = parse_profile(
            "rp_ids = [\"example.com\"]\nrequire_uv = true\nregistration_allowed = false\nhuman_verification_prompt = \"never\"\n",
        )
        .unwrap();
        assert_eq!(profile.legacy.removed_keys.len(), 4);
        let err = profile.validate(&pid("bot")).unwrap_err().to_string();
        for key in [
            "rp_ids",
            "require_uv",
            "registration_allowed",
            "human_verification_prompt",
        ] {
            assert!(err.contains(&format!("`{key}`")), "{err}");
        }
    }

    #[test]
    fn unknown_profile_keys_are_still_rejected() {
        assert!(parse_profile("extra_field = \"bad\"\n").is_err());
    }

    #[test]
    fn rules_toml_roundtrip_uses_new_vocabulary() {
        let profile = parse_profile(
            r#"
[[rules]]
rp_id = "example.com"
authenticate = "allow"
register = "request"
credential_selection = "newest"

[[rules]]
rp_id = "other.example.com"
authenticate = "request"
"#,
        )
        .unwrap();
        assert_eq!(profile.rules.len(), 2);
        assert!(profile.legacy.warnings.is_empty());
        let rendered = toml::to_string(&profile).unwrap();
        assert!(rendered.contains("authenticate = \"allow\""), "{rendered}");
        assert!(rendered.contains("register = \"request\""), "{rendered}");
        let reparsed: AgentProfileConfig = toml::from_str(&rendered).unwrap();
        assert_eq!(reparsed.rules, profile.rules);
        assert!(reparsed.legacy.warnings.is_empty());
    }

    #[test]
    fn explicit_rules_report_allowed_rps_and_registration() {
        let mut profile = make_isolated_profile();
        profile.rules = vec![
            rule("example.com", RuleAction::Request, RuleAction::Allow),
            rule("denied.example.com", RuleAction::Deny, RuleAction::Deny),
        ];
        profile.validate(&pid("test")).unwrap();
        assert_eq!(profile.allowed_rp_ids(), vec!["example.com"]);
        assert!(profile.allows_registration());
        assert!(profile.allows_authentication());

        profile.rules = vec![rule("example.com", RuleAction::Deny, RuleAction::Deny)];
        assert!(profile.allowed_rp_ids().is_empty());
        assert!(!profile.allows_registration());
        assert!(!profile.allows_authentication());
    }

    #[test]
    fn duplicate_rp_rule_rejected_case_insensitively() {
        let mut profile = make_isolated_profile();
        profile.rules = vec![
            rule("example.com", RuleAction::Allow, RuleAction::Deny),
            rule("Example.COM", RuleAction::Request, RuleAction::Deny),
        ];
        let err = profile.validate(&pid("test")).unwrap_err();
        assert!(err.to_string().contains("duplicate RP rule"));
    }

    // ---- validation: wildcard ----

    #[test]
    fn wildcard_requires_same_user_mode() {
        let mut profile = make_isolated_profile();
        profile.rules = vec![rule("*", RuleAction::Allow, RuleAction::Deny)];
        let err = profile.validate(&pid("test")).unwrap_err();
        assert!(err.to_string().contains("only supported in same-user mode"));

        let profile = same_user_profile(vec![rule("*", RuleAction::Allow, RuleAction::Deny)]);
        profile.validate(&pid("test")).unwrap();
    }

    #[test]
    fn wildcard_requires_global_same_user_acknowledgement() {
        // Allow, request and even deny/deny wildcard rules need the acknowledgement.
        for authenticate in [RuleAction::Allow, RuleAction::Request, RuleAction::Deny] {
            let profile = same_user_profile(vec![rule("*", authenticate, RuleAction::Deny)]);
            let err = agent_config(profile.clone(), false, false)
                .validate(None)
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("acknowledge_global_same_user"),
                "authenticate = {authenticate}: {err}"
            );
            agent_config(profile, true, false).validate(None).unwrap();
        }
    }

    #[test]
    fn wildcard_requires_register_deny_including_request() {
        for register in [RuleAction::Allow, RuleAction::Request] {
            let profile = same_user_profile(vec![rule("*", RuleAction::Allow, register)]);
            let err = profile.validate(&pid("test")).unwrap_err().to_string();
            assert!(
                err.contains("register = \"deny\""),
                "register = {register}: {err}"
            );
            // The acknowledgements do not lift the restriction.
            let err = agent_config(profile, true, true)
                .validate(None)
                .unwrap_err()
                .to_string();
            assert!(err.contains("register = \"deny\""), "{err}");
        }
    }

    #[test]
    fn wildcard_selection_is_forced_to_single() {
        let cred_ref = CredentialRef::with_default_domain(b"wild");
        for rejected in [
            CredentialSelection::FirstMatching,
            CredentialSelection::Newest,
            CredentialSelection::Credential(cred_ref),
        ] {
            let mut wildcard = rule("*", RuleAction::Allow, RuleAction::Deny);
            wildcard.credential_selection = Some(rejected.clone());
            let err = same_user_profile(vec![wildcard])
                .validate(&pid("test"))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("always selects with `single`"),
                "{rejected:?}: {err}"
            );
        }

        for accepted in [None, Some(CredentialSelection::Single)] {
            let mut wildcard = rule("*", RuleAction::Allow, RuleAction::Deny);
            wildcard.credential_selection = accepted.clone();
            same_user_profile(vec![wildcard])
                .validate(&pid("test"))
                .unwrap_or_else(|err| panic!("{accepted:?} must validate: {err}"));
        }
    }

    #[test]
    fn wildcard_forbids_credential_refs() {
        let mut profile = same_user_profile(vec![rule("*", RuleAction::Allow, RuleAction::Deny)]);
        profile.credential_refs = Some(vec![CredentialRef::with_default_domain(b"restricted")]);
        let err = profile.validate(&pid("test")).unwrap_err().to_string();
        assert!(err.contains("credential_refs to be omitted"), "{err}");
    }

    // ---- validation: register = request ----

    #[test]
    fn register_request_accepted_on_exact_rp_with_authenticate_allow_or_request() {
        for authenticate in [RuleAction::Allow, RuleAction::Request] {
            let mut isolated = make_isolated_profile();
            isolated.rules = vec![rule("example.com", authenticate, RuleAction::Request)];
            isolated
                .validate(&pid("test"))
                .unwrap_or_else(|err| panic!("isolated, authenticate = {authenticate}: {err}"));

            let same_user =
                same_user_profile(vec![rule("example.com", authenticate, RuleAction::Request)]);
            agent_config(same_user, false, true)
                .validate(None)
                .unwrap_or_else(|err| panic!("same-user, authenticate = {authenticate}: {err}"));
        }
    }

    #[test]
    fn register_request_rejected_with_authenticate_deny() {
        let mut profile = make_isolated_profile();
        profile.rules = vec![rule("example.com", RuleAction::Deny, RuleAction::Request)];
        let err = profile.validate(&pid("test")).unwrap_err().to_string();
        assert!(
            err.contains("register = \"request\" with authenticate = \"deny\""),
            "{err}"
        );
        assert!(err.contains("example.com"), "{err}");
    }

    #[test]
    fn register_request_rejected_on_wildcard() {
        let profile = same_user_profile(vec![rule("*", RuleAction::Request, RuleAction::Request)]);
        let err = profile.validate(&pid("test")).unwrap_err().to_string();
        assert!(err.contains("register = \"deny\""), "{err}");
    }

    #[test]
    fn same_user_register_request_requires_registration_acknowledgement() {
        let profile = same_user_profile(vec![rule(
            "example.com",
            RuleAction::Allow,
            RuleAction::Request,
        )]);
        let err = agent_config(profile.clone(), false, false)
            .validate(None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("acknowledge_same_user_registration"), "{err}");
        agent_config(profile, false, true).validate(None).unwrap();
    }

    #[test]
    fn same_user_register_allow_requires_registration_acknowledgement() {
        let profile = same_user_profile(vec![rule(
            "example.com",
            RuleAction::Allow,
            RuleAction::Allow,
        )]);
        let err = agent_config(profile.clone(), false, false)
            .validate(None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("acknowledge_same_user_registration"), "{err}");
        agent_config(profile, false, true).validate(None).unwrap();
    }

    #[test]
    fn same_user_authenticate_only_needs_no_registration_acknowledgement() {
        let profile = same_user_profile(vec![rule(
            "example.com",
            RuleAction::Request,
            RuleAction::Deny,
        )]);
        agent_config(profile, false, false).validate(None).unwrap();
    }

    // ---- localhost ----

    #[test]
    fn localhost_is_a_valid_exact_rp_id_only() {
        assert_eq!(validate_rp_id("localhost").unwrap(), LOCALHOST_RP_ID);
        assert_eq!(validate_rp_id("LOCALHOST").unwrap(), "localhost");
        assert_eq!(validate_rp_id(" LocalHost ").unwrap(), "localhost");
        assert!(validate_rp_id("foo.localhost").is_err());
        assert!(validate_rp_id("a.b.localhost").is_err());
        assert!(validate_rp_id("*.localhost").is_err());
        assert!(validate_rp_id("localhost:8443").is_err());
        assert!(validate_rp_id("http://localhost").is_err());

        assert_eq!(validate_agent_rp_rule_id("localhost").unwrap(), "localhost");
        assert!(validate_agent_rp_rule_id("foo.localhost").is_err());
        assert!(validate_agent_rp_rule_id("*.localhost").is_err());
    }

    #[test]
    fn exact_localhost_rule_validates() {
        let mut profile = make_isolated_profile();
        profile.rules = vec![rule("localhost", RuleAction::Allow, RuleAction::Deny)];
        profile.validate(&pid("test")).unwrap();

        let profile = same_user_profile(vec![rule(
            "LocalHost",
            RuleAction::Request,
            RuleAction::Deny,
        )]);
        agent_config(profile, false, false).validate(None).unwrap();

        let mut bad = make_isolated_profile();
        bad.rules = vec![rule("foo.localhost", RuleAction::Allow, RuleAction::Deny)];
        assert!(bad.validate(&pid("test")).is_err());
    }

    #[test]
    fn wildcard_does_not_resolve_localhost_but_exact_rule_does() {
        let wildcard_only = same_user_profile(vec![rule("*", RuleAction::Allow, RuleAction::Deny)]);
        for rp_id in ["localhost", "LOCALHOST"] {
            let matched = wildcard_only.resolve(PolicyAction::Authenticate, rp_id);
            assert_eq!(matched.action, RuleAction::Deny, "{rp_id}");
            assert_eq!(matched.rule, RuleIdentity::None, "{rp_id}");
            assert_eq!(matched.audit_rule(), None);
        }
        // The same wildcard still governs an ordinary RP.
        let matched = wildcard_only.resolve(PolicyAction::Authenticate, "github.com");
        assert_eq!(matched.action, RuleAction::Allow);
        assert_eq!(matched.rule, RuleIdentity::Wildcard);

        let with_exact = same_user_profile(vec![
            rule("*", RuleAction::Allow, RuleAction::Deny),
            rule("localhost", RuleAction::Allow, RuleAction::Deny),
        ]);
        let matched = with_exact.resolve(PolicyAction::Authenticate, "localhost");
        assert_eq!(matched.action, RuleAction::Allow);
        assert_eq!(matched.rule, RuleIdentity::Exact("localhost".to_string()));
        assert_eq!(matched.audit_rule(), Some("localhost"));
    }

    #[test]
    fn profiles_for_rp_id_never_matches_localhost_through_wildcard() {
        let profile = same_user_profile(vec![rule("*", RuleAction::Allow, RuleAction::Deny)]);
        let cfg = agent_config(profile, true, false);
        assert_eq!(cfg.profiles_for_rp_id("github.com").len(), 1);
        assert!(cfg.profiles_for_rp_id("localhost").is_empty());

        let exact = same_user_profile(vec![rule("localhost", RuleAction::Allow, RuleAction::Deny)]);
        let cfg = agent_config(exact, false, false);
        assert_eq!(cfg.profiles_for_rp_id("localhost").len(), 1);
    }

    // ---- B4 ----

    // B4 regression: a profile whose rules are all `deny` authorizes nothing and still loads.
    #[test]
    fn all_deny_profile_loads_b4() {
        let same_user = same_user_profile(vec![
            rule("example.com", RuleAction::Deny, RuleAction::Deny),
            rule("other.example.com", RuleAction::Deny, RuleAction::Deny),
        ]);
        let cfg = agent_config(same_user, false, false);
        cfg.validate(None).unwrap();
        let profile = cfg.get_profile("coding").unwrap();
        assert!(profile.allowed_rp_ids().is_empty());
        assert_eq!(
            profile
                .resolve(PolicyAction::Authenticate, "example.com")
                .action,
            RuleAction::Deny
        );

        let dir = tempfile::tempdir().unwrap();
        let mut isolated = make_isolated_profile();
        isolated.storage = Some(AgentStorageConfig::Local {
            path: dir.path().join("creds"),
            pin_path: dir.path().join("pin"),
        });
        isolated.rules = vec![rule("example.com", RuleAction::Deny, RuleAction::Deny)];
        let mut cfg = agent_config(isolated, false, false);
        cfg.audit_path = Some(dir.path().join("audit"));
        cfg.validate(None).unwrap();

        // No rules at all loads too.
        let mut empty = make_isolated_profile();
        empty.storage = cfg.profiles["coding"].storage.clone();
        empty.rules = vec![];
        let mut cfg = agent_config(empty, false, false);
        cfg.audit_path = Some(dir.path().join("audit"));
        cfg.validate(None).unwrap();
    }

    // ---- credential selection ----

    #[test]
    fn credential_selection_for_rp_wildcard_is_always_single() {
        let mut profile = same_user_profile(vec![rule("*", RuleAction::Allow, RuleAction::Deny)]);
        profile.credential_selection = CredentialSelection::Newest;
        assert_eq!(
            profile.credential_selection_for_rp("any-rp.com"),
            CredentialSelection::Single,
            "the wildcard ignores the profile default"
        );

        // Validation rejects an override on the wildcard; resolution still forces `single`
        // for a rule that bypassed validation.
        let mut bypassed = rule("*", RuleAction::Allow, RuleAction::Deny);
        bypassed.credential_selection = Some(CredentialSelection::FirstMatching);
        let mut profile = same_user_profile(vec![bypassed]);
        profile.credential_selection = CredentialSelection::Newest;
        assert_eq!(
            profile.credential_selection_for_rp("any-rp.com"),
            CredentialSelection::Single
        );
    }

    #[test]
    fn credential_selection_for_rp_exact_beats_wildcard_and_default() {
        let mut exact = rule("github.com", RuleAction::Allow, RuleAction::Deny);
        exact.credential_selection = Some(CredentialSelection::Newest);
        let mut profile = same_user_profile(vec![
            rule("*", RuleAction::Allow, RuleAction::Deny),
            exact,
            rule("gitlab.com", RuleAction::Allow, RuleAction::Deny),
        ]);
        profile.credential_selection = CredentialSelection::FirstMatching;
        // Exact override.
        assert_eq!(
            profile.credential_selection_for_rp("github.com"),
            CredentialSelection::Newest
        );
        // Exact rule without an override uses the profile default.
        assert_eq!(
            profile.credential_selection_for_rp("gitlab.com"),
            CredentialSelection::FirstMatching
        );
        // Wildcard match.
        assert_eq!(
            profile.credential_selection_for_rp("other.com"),
            CredentialSelection::Single
        );
    }

    #[test]
    fn credential_selection_for_rp_unmatched_rp_uses_profile_default() {
        let mut profile = make_isolated_profile();
        profile.credential_selection = CredentialSelection::Newest;
        assert_eq!(
            profile.credential_selection_for_rp("unlisted.example.com"),
            CredentialSelection::Newest
        );
    }
}
