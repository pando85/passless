use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use passless_config_doc::ConfigDoc;
use serde::{Deserialize, Serialize};

use super::ids::{CredentialRef, ProfileId};
use crate::error::{Error, Result};

const MAX_DURATION_SECS: u64 = 86_400 * 365;
const MIN_DURATION_SECS: u64 = 1;

const UHID_NAME_MAX: usize = 128;
const UHID_PHYS_MAX: usize = 64;
const UHID_UNIQ_MAX: usize = 64;

const DEVICE_NAME_MAX: usize = UHID_NAME_MAX - 1;
const DEVICE_PHYS_MAX: usize = UHID_PHYS_MAX - 1;
const DEVICE_UNIQ_MAX: usize = UHID_UNIQ_MAX - 1;

const HUMAN_DEVICE_NAME: &str = "virtual-fido";
const HUMAN_DEVICE_PHYS: &str = "virtual-fido-001";
const HUMAN_VENDOR_ID: u16 = 0x15d9;
const HUMAN_PRODUCT_ID: u16 = 0x0a37;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentMode {
    #[serde(rename = "isolated")]
    Isolated,
    #[serde(rename = "delegated-session")]
    DelegatedSession,
}

impl fmt::Display for AgentMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentMode::Isolated => write!(f, "isolated"),
            AgentMode::DelegatedSession => write!(f, "delegated-session"),
        }
    }
}

impl std::str::FromStr for AgentMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "isolated" => Ok(AgentMode::Isolated),
            "delegated-session" => Ok(AgentMode::DelegatedSession),
            _ => Err(format!(
                "Invalid agent mode '{}'. Must be: isolated, delegated-session",
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentAuthorization {
    Deny,
    Confirm,
    Allow,
}

impl fmt::Display for AgentAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deny => f.write_str("deny"),
            Self::Confirm => f.write_str("confirm"),
            Self::Allow => f.write_str("allow"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserPresenceSource {
    Human,
    Policy,
    None,
}

impl fmt::Display for UserPresenceSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Human => f.write_str("human"),
            Self::Policy => f.write_str("policy"),
            Self::None => f.write_str("none"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserVerificationSource {
    Human,
    Policy,
    None,
}

impl fmt::Display for UserVerificationSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Human => f.write_str("human"),
            Self::Policy => f.write_str("policy"),
            Self::None => f.write_str("none"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ConfigDoc)]
#[serde(deny_unknown_fields)]
pub struct AgentCeremonyPolicy {
    pub authorization: AgentAuthorization,
    pub user_presence: UserPresenceSource,
    pub user_verification: UserVerificationSource,
}

impl AgentCeremonyPolicy {
    pub fn validate(&self, profile_id: &ProfileId, rp_id: &str, action: &str) -> Result<()> {
        if self.authorization == AgentAuthorization::Deny
            && (self.user_presence != UserPresenceSource::None
                || self.user_verification != UserVerificationSource::None)
        {
            return Err(Error::Config(format!(
                "agent profile '{}': {} policy for '{}' must use no UP or UV evidence when authorization is deny",
                profile_id, action, rp_id,
            )));
        }
        if self.authorization == AgentAuthorization::Allow
            && self.user_presence == UserPresenceSource::Human
        {
            return Err(Error::Config(format!(
                "agent profile '{}': {} policy for '{}' cannot require human UP when authorization is allow",
                profile_id, action, rp_id,
            )));
        }
        Ok(())
    }

    pub fn legacy_confirm(require_uv: bool) -> Self {
        Self {
            authorization: AgentAuthorization::Confirm,
            user_presence: UserPresenceSource::Human,
            user_verification: if require_uv {
                UserVerificationSource::Human
            } else {
                UserVerificationSource::None
            },
        }
    }

    pub fn deny() -> Self {
        Self {
            authorization: AgentAuthorization::Deny,
            user_presence: UserPresenceSource::None,
            user_verification: UserVerificationSource::None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ConfigDoc)]
#[serde(deny_unknown_fields)]
pub struct AgentRpRule {
    pub rp_id: String,
    pub register: AgentCeremonyPolicy,
    pub authenticate: AgentCeremonyPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DelegatedRegistrationStorage {
    Human,
}

impl fmt::Display for DelegatedRegistrationStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Human => f.write_str("human"),
        }
    }
}

fn default_gpg_backend() -> String {
    "gnupg-bin".to_string()
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

#[derive(Debug, Clone, Serialize, Deserialize, ConfigDoc)]
#[serde(deny_unknown_fields)]
pub struct DeviceIdentity {
    pub name: String,
    pub phys: String,
    pub uniq: String,
    pub vendor_id: u16,
    pub product_id: u16,
}

impl DeviceIdentity {
    pub fn validate(&self, profile_id: &ProfileId) -> Result<()> {
        validate_device_field(&self.name, "name", DEVICE_NAME_MAX, profile_id)?;
        validate_device_field(&self.phys, "phys", DEVICE_PHYS_MAX, profile_id)?;
        validate_device_field(&self.uniq, "uniq", DEVICE_UNIQ_MAX, profile_id)?;

        if self.name == HUMAN_DEVICE_NAME
            && self.phys == HUMAN_DEVICE_PHYS
            && self.vendor_id == HUMAN_VENDOR_ID
            && self.product_id == HUMAN_PRODUCT_ID
        {
            return Err(Error::Config(format!(
                "agent profile '{}': device identity collides with the human authenticator \
                 (virtual-fido / 0x{:04x}:0x{:04x})",
                profile_id, HUMAN_VENDOR_ID, HUMAN_PRODUCT_ID,
            )));
        }

        Ok(())
    }
}

fn validate_device_field(
    value: &str,
    field: &'static str,
    max: usize,
    profile_id: &ProfileId,
) -> Result<()> {
    if value.contains('\0') {
        return Err(Error::Config(format!(
            "agent profile '{}': device.{} must not contain NUL bytes",
            profile_id, field,
        )));
    }
    if value.len() > max {
        return Err(Error::Config(format!(
            "agent profile '{}': device.{} exceeds maximum length of {} bytes (got {}); \
             limit reserves 1 byte for NUL terminator",
            profile_id,
            field,
            max,
            value.len(),
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, ConfigDoc)]
#[serde(deny_unknown_fields)]
pub struct AgentProfileConfig {
    pub mode: AgentMode,
    pub principal_user: String,
    #[serde(default)]
    pub rp_ids: Vec<String>,
    #[serde(default)]
    pub require_uv: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_refs: Option<Vec<CredentialRef>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_grant_ttl: Option<BoundedDuration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_session_ttl: Option<BoundedDuration>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<AgentStorageConfig>,
    #[serde(default)]
    pub registration_allowed: bool,

    #[serde(default)]
    pub rules: Vec<AgentRpRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_registration_storage: Option<DelegatedRegistrationStorage>,

    pub device: DeviceIdentity,

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
}

impl AgentProfileConfig {
    pub fn effective_rules(&self) -> Vec<AgentRpRule> {
        if !self.rules.is_empty() {
            return self.rules.clone();
        }

        self.rp_ids
            .iter()
            .map(|rp_id| AgentRpRule {
                rp_id: rp_id.clone(),
                register: if self.registration_allowed && self.mode == AgentMode::Isolated {
                    AgentCeremonyPolicy::legacy_confirm(self.require_uv)
                } else {
                    AgentCeremonyPolicy::deny()
                },
                authenticate: AgentCeremonyPolicy::legacy_confirm(self.require_uv),
            })
            .collect()
    }

    pub fn allowed_rp_ids(&self) -> Vec<String> {
        self.effective_rules()
            .into_iter()
            .filter(|rule| {
                rule.register.authorization != AgentAuthorization::Deny
                    || rule.authenticate.authorization != AgentAuthorization::Deny
            })
            .map(|rule| rule.rp_id)
            .collect()
    }

    pub fn rule_for_rp(&self, rp_id: &str) -> Option<AgentRpRule> {
        let normalized = rp_id.trim().to_ascii_lowercase();
        self.effective_rules()
            .into_iter()
            .find(|rule| rule.rp_id.trim().to_ascii_lowercase() == normalized)
    }

    pub fn allows_registration(&self) -> bool {
        self.effective_rules()
            .iter()
            .any(|rule| rule.register.authorization != AgentAuthorization::Deny)
    }

    pub fn allows_authentication(&self) -> bool {
        self.effective_rules()
            .iter()
            .any(|rule| rule.authenticate.authorization != AgentAuthorization::Deny)
    }

    pub fn requires_human_uv(&self) -> bool {
        self.effective_rules().iter().any(|rule| {
            rule.register.user_verification == UserVerificationSource::Human
                || rule.authenticate.user_verification == UserVerificationSource::Human
        })
    }

    pub fn validate(&self, profile_id: &ProfileId) -> Result<()> {
        if self.principal_user.is_empty() {
            return Err(Error::Config(format!(
                "agent profile '{}': principal_user must not be empty",
                profile_id
            )));
        }

        if !self.rules.is_empty()
            && (!self.rp_ids.is_empty() || self.registration_allowed || self.require_uv)
        {
            return Err(Error::Config(format!(
                "agent profile '{}': explicit rules cannot be combined with legacy rp_ids, registration_allowed, or require_uv",
                profile_id,
            )));
        }

        let effective_rules = self.effective_rules();
        let mut normalized_rules = std::collections::BTreeSet::new();
        for rule in &effective_rules {
            validate_rp_id(&rule.rp_id)?;
            let normalized = rule.rp_id.trim().to_ascii_lowercase();
            if !normalized_rules.insert(normalized) {
                return Err(Error::Config(format!(
                    "agent profile '{}': duplicate RP rule for '{}'",
                    profile_id, rule.rp_id,
                )));
            }
            rule.register
                .validate(profile_id, &rule.rp_id, "registration")?;
            rule.authenticate
                .validate(profile_id, &rule.rp_id, "authentication")?;
        }

        self.device.validate(profile_id)?;

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
            AgentMode::DelegatedSession => {
                if self.rules.is_empty() && !self.require_uv {
                    return Err(Error::Config(format!(
                        "agent profile '{}': delegated-session requires require_uv = true",
                        profile_id
                    )));
                }
                if self.storage.is_some() {
                    return Err(Error::Config(format!(
                        "agent profile '{}': delegated-session must not specify isolated \
                         backend storage fields",
                        profile_id
                    )));
                }
                if self.allows_registration() && self.delegated_registration_storage.is_none() {
                    return Err(Error::Config(format!(
                        "agent profile '{}': delegated registration requires delegated_registration_storage",
                        profile_id,
                    )));
                }
                if self.allows_authentication() {
                    let refs = self.credential_refs.as_ref().ok_or_else(|| {
                        Error::Config(format!(
                            "agent profile '{}': delegated authentication requires credential_refs",
                            profile_id
                        ))
                    })?;
                    if refs.is_empty() {
                        return Err(Error::Config(format!(
                            "agent profile '{}': credential_refs must not be empty",
                            profile_id
                        )));
                    }
                }
                if self.max_grant_ttl.is_none() {
                    return Err(Error::Config(format!(
                        "agent profile '{}': delegated-session requires max_grant_ttl",
                        profile_id
                    )));
                }
                if self.max_session_ttl.is_none() {
                    return Err(Error::Config(format!(
                        "agent profile '{}': delegated-session requires max_session_ttl",
                        profile_id
                    )));
                }
                if self.browser_command.is_none() {
                    return Err(Error::Config(format!(
                        "agent profile '{}': delegated-session requires browser_command",
                        profile_id
                    )));
                }

                let cdp_port_mode = self.browser_cdp_expose == Some(CdpExposeMode::Port);

                if let Some(ref browser_user) = self.browser_user {
                    if browser_user.is_empty() {
                        return Err(Error::Config(format!(
                            "agent profile '{}': browser_user must not be empty",
                            profile_id
                        )));
                    }
                    if browser_user.contains('\0') {
                        return Err(Error::Config(format!(
                            "agent profile '{}': browser_user must not contain NUL bytes",
                            profile_id
                        )));
                    }
                    if !cdp_port_mode && *browser_user == self.principal_user {
                        return Err(Error::Config(format!(
                            "agent profile '{}': browser_user must differ from principal_user \
                             (unless browser_cdp_expose = \"port\")",
                            profile_id
                        )));
                    }
                } else if !cdp_port_mode {
                    return Err(Error::Config(format!(
                        "agent profile '{}': delegated-session requires browser_user \
                         (or set browser_cdp_expose = \"port\" to use principal_user)",
                        profile_id
                    )));
                }

                let browser_runtime_root = self.browser_runtime_root.as_ref().ok_or_else(|| {
                    Error::Config(format!(
                        "agent profile '{}': delegated-session requires browser_runtime_root",
                        profile_id
                    ))
                })?;
                validate_browser_runtime_root(browser_runtime_root, profile_id)?;

                if let Some(ref url) = self.start_url {
                    validate_start_url(url, &self.allowed_rp_ids(), profile_id)?;
                }
            }
            AgentMode::Isolated => {
                if self.delegated_registration_storage.is_some() {
                    return Err(Error::Config(format!(
                        "agent profile '{}': isolated mode must not specify delegated_registration_storage",
                        profile_id,
                    )));
                }
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

        if let Some(ref url) = self.start_url
            && url.is_empty()
        {
            return Err(Error::Config(format!(
                "agent profile '{}': start_url must not be empty",
                profile_id
            )));
        }

        Ok(())
    }
}

fn validate_browser_runtime_root(path: &Path, profile_id: &ProfileId) -> Result<()> {
    let path_str = path.to_string_lossy();
    if path_str.contains('\0') {
        return Err(Error::Config(format!(
            "agent profile '{}': browser_runtime_root must not contain NUL bytes",
            profile_id
        )));
    }
    if !path.is_absolute() {
        return Err(Error::Config(format!(
            "agent profile '{}': browser_runtime_root must be an absolute path",
            profile_id
        )));
    }
    if path_str.len() > 4096 {
        return Err(Error::Config(format!(
            "agent profile '{}': browser_runtime_root path too long",
            profile_id
        )));
    }
    Ok(())
}

fn validate_start_url(raw_url: &str, rp_ids: &[String], profile_id: &ProfileId) -> Result<()> {
    let rest = raw_url.strip_prefix("https://").ok_or_else(|| {
        Error::Config(format!(
            "agent profile '{}': start_url must use HTTPS scheme",
            profile_id,
        ))
    })?;

    let host = rest
        .split('/')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");

    if host.is_empty() {
        return Err(Error::Config(format!(
            "agent profile '{}': start_url must have a valid host",
            profile_id,
        )));
    }

    let host_normalized = host.to_ascii_lowercase();

    if !is_valid_dns_name(&host_normalized) && !is_ip_address(&host_normalized) {
        return Err(Error::Config(format!(
            "agent profile '{}': start_url host '{}' is not a valid hostname",
            profile_id, host,
        )));
    }

    let matching: Vec<&str> = rp_ids
        .iter()
        .filter(|rp_id| {
            let rp = rp_id.trim().to_ascii_lowercase();
            host_normalized == rp || host_normalized.ends_with(&format!(".{}", rp))
        })
        .map(|s| s.as_str())
        .collect();

    if matching.len() != 1 {
        return Err(Error::Config(format!(
            "agent profile '{}': start_url host '{}' must match exactly one allowed RP ID, matched {:?}",
            profile_id, host, matching,
        )));
    }

    Ok(())
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
}

impl AgentConfig {
    pub fn validate(&self, human_state_path: Option<&std::path::Path>) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        if self.audit_path.is_none() {
            return Err(Error::Config(
                "agents.enabled = true requires agents.audit_path".to_string(),
            ));
        }

        let mut validated_profiles: Vec<(ProfileId, &AgentProfileConfig)> = Vec::new();

        for (name, profile) in &self.profiles {
            let pid = ProfileId::new(name.as_str())
                .map_err(|e| Error::Config(format!("invalid profile id '{}': {}", name, e)))?;
            profile.validate(&pid)?;
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

        let mut device_keys: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (pid, profile) in &validated_profiles {
            let key = format!(
                "{}:{}:{}:{}:{}",
                profile.device.name,
                profile.device.phys,
                profile.device.uniq,
                profile.device.vendor_id,
                profile.device.product_id,
            );
            if !device_keys.insert(key) {
                return Err(Error::Config(format!(
                    "agent profile '{}': device identity collides with another profile",
                    pid
                )));
            }
        }

        Ok(())
    }

    pub fn get_profile(&self, name: &str) -> Option<&AgentProfileConfig> {
        self.profiles.get(name)
    }

    pub fn profiles_for_rp_id(&self, rp_id: &str) -> Vec<(&String, &AgentProfileConfig)> {
        let normalized = normalize_rp_id(rp_id);
        self.profiles
            .iter()
            .filter(|(_, profile)| {
                profile
                    .effective_rules()
                    .iter()
                    .any(|rule| normalize_rp_id(&rule.rp_id) == normalized)
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
        assert!(validate_rp_id("localhost").is_err());
        assert!(validate_rp_id("com").is_err());
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
    fn test_agent_mode_serde_delegated_session() {
        let mode = AgentMode::DelegatedSession;
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(json, "\"delegated-session\"");
        let mode2: AgentMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, mode2);
    }

    #[test]
    fn test_agent_mode_from_str() {
        assert_eq!(
            "isolated".parse::<AgentMode>().unwrap(),
            AgentMode::Isolated
        );
        assert_eq!(
            "delegated-session".parse::<AgentMode>().unwrap(),
            AgentMode::DelegatedSession
        );
        assert!("delegated".parse::<AgentMode>().is_err());
        assert!("invalid".parse::<AgentMode>().is_err());
    }

    #[test]
    fn test_agent_mode_rejects_bare_delegated() {
        let result: std::result::Result<AgentMode, _> = serde_json::from_str("\"delegated\"");
        assert!(result.is_err());
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

    fn make_delegated_profile() -> AgentProfileConfig {
        AgentProfileConfig {
            mode: AgentMode::DelegatedSession,
            principal_user: "test-user".to_string(),
            rp_ids: vec!["example.com".to_string()],
            require_uv: true,
            credential_refs: Some(vec![CredentialRef::with_default_domain(b"user-github")]),
            max_grant_ttl: Some(BoundedDuration::new(120).unwrap()),
            max_session_ttl: Some(BoundedDuration::new(900).unwrap()),
            storage: None,
            registration_allowed: false,
            rules: vec![],
            delegated_registration_storage: None,
            device: DeviceIdentity {
                name: "passless-agent-test".to_string(),
                phys: "test-phys".to_string(),
                uniq: "test-uniq-001".to_string(),
                vendor_id: 0x1234,
                product_id: 0x5678,
            },
            start_url: None,
            browser_command: Some(vec!["firefox".to_string()]),
            browser_user: Some("browser-user".to_string()),
            browser_runtime_root: Some(PathBuf::from("/var/run/passless-browser")),
            browser_cdp_expose: None,
            browser_cdp_port: None,
        }
    }

    fn make_isolated_profile() -> AgentProfileConfig {
        AgentProfileConfig {
            mode: AgentMode::Isolated,
            principal_user: "test-user".to_string(),
            rp_ids: vec!["example.com".to_string()],
            require_uv: true,
            credential_refs: None,
            max_grant_ttl: None,
            max_session_ttl: None,
            storage: Some(AgentStorageConfig::Local {
                path: PathBuf::from("/tmp/test-agent/creds"),
                pin_path: PathBuf::from("/tmp/test-agent/pin"),
            }),
            registration_allowed: true,
            rules: vec![],
            delegated_registration_storage: None,
            device: DeviceIdentity {
                name: "passless-agent-iso".to_string(),
                phys: "iso-phys".to_string(),
                uniq: "iso-uniq-001".to_string(),
                vendor_id: 0x1234,
                product_id: 0x5679,
            },
            start_url: None,
            browser_command: None,
            browser_user: None,
            browser_runtime_root: None,
            browser_cdp_expose: None,
            browser_cdp_port: None,
        }
    }

    #[test]
    fn test_profile_delegated_session_requires_uv() {
        let mut profile = make_delegated_profile();
        profile.require_uv = false;
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("require_uv"));
    }

    #[test]
    fn test_profile_delegated_session_requires_credential_refs() {
        let mut profile = make_delegated_profile();
        profile.credential_refs = None;
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("credential_refs"));
    }

    #[test]
    fn test_profile_delegated_session_requires_grant_ttl() {
        let mut profile = make_delegated_profile();
        profile.max_grant_ttl = None;
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("max_grant_ttl"));
    }

    #[test]
    fn test_profile_delegated_session_requires_session_ttl() {
        let mut profile = make_delegated_profile();
        profile.max_session_ttl = None;
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("max_session_ttl"));
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
    fn test_profile_delegated_valid() {
        let profile = make_delegated_profile();
        let pid = ProfileId::new("test").unwrap();
        assert!(profile.validate(&pid).is_ok());
    }

    #[test]
    fn test_profile_isolated_valid() {
        let profile = make_isolated_profile();
        let pid = ProfileId::new("test").unwrap();
        assert!(profile.validate(&pid).is_ok());
    }

    fn policy(
        authorization: AgentAuthorization,
        user_presence: UserPresenceSource,
        user_verification: UserVerificationSource,
    ) -> AgentCeremonyPolicy {
        AgentCeremonyPolicy {
            authorization,
            user_presence,
            user_verification,
        }
    }

    #[test]
    fn test_explicit_policy_allow_validates() {
        let mut profile = make_isolated_profile();
        profile.rp_ids.clear();
        profile.registration_allowed = false;
        profile.require_uv = false;
        profile.rules = vec![AgentRpRule {
            rp_id: "example.com".to_string(),
            register: policy(
                AgentAuthorization::Allow,
                UserPresenceSource::Policy,
                UserVerificationSource::Policy,
            ),
            authenticate: policy(
                AgentAuthorization::Confirm,
                UserPresenceSource::Human,
                UserVerificationSource::Human,
            ),
        }];

        assert!(profile.validate(&ProfileId::new("test").unwrap()).is_ok());
        assert_eq!(profile.allowed_rp_ids(), vec!["example.com"]);
        assert!(profile.allows_registration());
        assert!(profile.requires_human_uv());
    }

    #[test]
    fn test_explicit_policy_rejects_legacy_fields() {
        let mut profile = make_isolated_profile();
        profile.rules = vec![AgentRpRule {
            rp_id: "example.com".to_string(),
            register: AgentCeremonyPolicy::deny(),
            authenticate: AgentCeremonyPolicy::deny(),
        }];
        let err = profile
            .validate(&ProfileId::new("test").unwrap())
            .unwrap_err();
        assert!(err.to_string().contains("cannot be combined"));
    }

    #[test]
    fn test_allow_rejects_human_up() {
        let err = policy(
            AgentAuthorization::Allow,
            UserPresenceSource::Human,
            UserVerificationSource::None,
        )
        .validate(
            &ProfileId::new("test").unwrap(),
            "example.com",
            "authentication",
        )
        .unwrap_err();
        assert!(err.to_string().contains("cannot require human UP"));
    }

    #[test]
    fn test_deny_rejects_evidence() {
        let err = policy(
            AgentAuthorization::Deny,
            UserPresenceSource::Policy,
            UserVerificationSource::None,
        )
        .validate(
            &ProfileId::new("test").unwrap(),
            "example.com",
            "registration",
        )
        .unwrap_err();
        assert!(err.to_string().contains("must use no UP or UV evidence"));
    }

    #[test]
    fn test_duplicate_explicit_rp_rule_rejected() {
        let mut profile = make_isolated_profile();
        profile.rp_ids.clear();
        profile.registration_allowed = false;
        profile.require_uv = false;
        let rule = AgentRpRule {
            rp_id: "example.com".to_string(),
            register: AgentCeremonyPolicy::deny(),
            authenticate: policy(
                AgentAuthorization::Allow,
                UserPresenceSource::Policy,
                UserVerificationSource::None,
            ),
        };
        profile.rules = vec![rule.clone(), rule];
        let err = profile
            .validate(&ProfileId::new("test").unwrap())
            .unwrap_err();
        assert!(err.to_string().contains("duplicate RP rule"));
    }

    #[test]
    fn test_delegated_registration_requires_explicit_storage_target() {
        let mut profile = make_delegated_profile();
        profile.rp_ids.clear();
        profile.registration_allowed = false;
        profile.require_uv = false;
        profile.rules = vec![AgentRpRule {
            rp_id: "example.com".to_string(),
            register: policy(
                AgentAuthorization::Allow,
                UserPresenceSource::Policy,
                UserVerificationSource::Policy,
            ),
            authenticate: AgentCeremonyPolicy::deny(),
        }];
        profile.credential_refs = None;

        let profile_id = ProfileId::new("test").unwrap();
        let err = profile.validate(&profile_id).unwrap_err();
        assert!(err.to_string().contains("delegated_registration_storage"));

        profile.delegated_registration_storage = Some(DelegatedRegistrationStorage::Human);
        assert!(profile.validate(&profile_id).is_ok());
    }

    #[test]
    fn test_explicit_rules_toml_roundtrip() {
        let input = r#"
mode = "isolated"
principal_user = "agent"

[[rules]]
rp_id = "example.com"
register = { authorization = "deny", user_presence = "none", user_verification = "none" }
authenticate = { authorization = "allow", user_presence = "policy", user_verification = "policy" }

[storage.local]
path = "/tmp/rules/credentials"
pin_path = "/tmp/rules/pin"

[device]
name = "rules"
phys = "rules-phys"
uniq = "rules-uniq"
vendor_id = 4660
product_id = 22136
"#;
        let profile: AgentProfileConfig = toml::from_str(input).unwrap();
        assert_eq!(profile.rules.len(), 1);
        assert_eq!(
            profile.rules[0].authenticate.authorization,
            AgentAuthorization::Allow
        );
        assert!(profile.validate(&ProfileId::new("rules").unwrap()).is_ok());
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
rp_ids = ["example.com"]
require_uv = true
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
    fn test_config_toml_delegated_session_roundtrip() {
        let toml_str = r#"
enabled = true
audit_path = "/var/lib/passless/audit"

[profiles.opencode]
mode = "delegated-session"
principal_user = "passless-opencode"
rp_ids = ["github.com"]
require_uv = true
credential_refs = ["9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"]
max_grant_ttl = 120
max_session_ttl = 900
browser_command = ["firefox", "--kiosk"]
start_url = "https://github.com/dashboard"
browser_user = "passless-browser"
browser_runtime_root = "/var/run/passless-browser"

[profiles.opencode.device]
name = "passless-agent-opencode"
phys = "opencode-phys"
uniq = "opencode-uniq"
vendor_id = 4660
product_id = 22136
"#;
        let config: AgentConfig = toml::from_str(toml_str).unwrap();
        assert!(config.enabled);
        assert_eq!(config.profiles.len(), 1);
        let profile = config.profiles.get("opencode").unwrap();
        assert_eq!(profile.mode, AgentMode::DelegatedSession);
        assert_eq!(profile.principal_user, "passless-opencode");
        assert!(profile.require_uv);
        assert_eq!(profile.browser_user.as_deref(), Some("passless-browser"));
        assert_eq!(
            profile
                .browser_runtime_root
                .as_ref()
                .map(|p| p.display().to_string()),
            Some("/var/run/passless-browser".to_string())
        );
    }

    #[test]
    fn test_config_toml_isolated_roundtrip() {
        let toml_str = r#"
enabled = true

[profiles.release-bot]
mode = "isolated"
principal_user = "passless-release"
rp_ids = ["github.com"]
require_uv = true
registration_allowed = true

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
        let profile = config.profiles.get("release-bot").unwrap();
        assert_eq!(profile.mode, AgentMode::Isolated);
        assert!(profile.registration_allowed);
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
register = { authorization = "deny", user_presence = "none", user_verification = "none" }
authenticate = { authorization = "allow", user_presence = "policy", user_verification = "policy" }

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
    fn test_config_device_identity_collision() {
        let mut profiles = BTreeMap::new();
        let device = DeviceIdentity {
            name: "same".to_string(),
            phys: "same".to_string(),
            uniq: "same".to_string(),
            vendor_id: 1,
            product_id: 2,
        };
        profiles.insert(
            "a".to_string(),
            AgentProfileConfig {
                mode: AgentMode::Isolated,
                principal_user: "u1".to_string(),
                rp_ids: vec!["a.com".to_string()],
                require_uv: true,
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: PathBuf::from("/tmp/a/creds"),
                    pin_path: PathBuf::from("/tmp/a/pin"),
                }),
                registration_allowed: false,
                rules: vec![],
                delegated_registration_storage: None,
                device: device.clone(),
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
                mode: AgentMode::Isolated,
                principal_user: "u2".to_string(),
                rp_ids: vec!["b.com".to_string()],
                require_uv: true,
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: PathBuf::from("/tmp/b/creds"),
                    pin_path: PathBuf::from("/tmp/b/pin"),
                }),
                registration_allowed: false,
                rules: vec![],
                delegated_registration_storage: None,
                device,
                start_url: None,
                browser_command: None,
                browser_user: None,
                browser_runtime_root: None,
                browser_cdp_expose: None,
                browser_cdp_port: None,
            },
        );
        let config = AgentConfig {
            enabled: true,
            profiles,
            audit_path: Some(PathBuf::from("/tmp/agent-audit")),
        };
        let err = config.validate(None).unwrap_err();
        assert!(err.to_string().contains("collides"));
    }

    #[test]
    fn test_config_overlapping_roots_rejected() {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "a".to_string(),
            AgentProfileConfig {
                mode: AgentMode::Isolated,
                principal_user: "u1".to_string(),
                rp_ids: vec!["a.com".to_string()],
                require_uv: true,
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: PathBuf::from("/tmp/agent/data"),
                    pin_path: PathBuf::from("/tmp/agent/data/sub"),
                }),
                registration_allowed: false,
                rules: vec![],
                delegated_registration_storage: None,
                device: DeviceIdentity {
                    name: "a".to_string(),
                    phys: "a".to_string(),
                    uniq: "a".to_string(),
                    vendor_id: 1,
                    product_id: 1,
                },
                start_url: None,
                browser_command: None,
                browser_user: None,
                browser_runtime_root: None,
                browser_cdp_expose: None,
                browser_cdp_port: None,
            },
        );
        let config = AgentConfig {
            enabled: true,
            profiles,
            audit_path: Some(PathBuf::from("/tmp/agent-audit-roots")),
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
                mode: AgentMode::Isolated,
                principal_user: "u1".to_string(),
                rp_ids: vec!["a.com".to_string()],
                require_uv: true,
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: human_path.join("creds"),
                    pin_path: dir.path().join("pin"),
                }),
                registration_allowed: false,
                rules: vec![],
                delegated_registration_storage: None,
                device: DeviceIdentity {
                    name: "a".to_string(),
                    phys: "a".to_string(),
                    uniq: "a".to_string(),
                    vendor_id: 1,
                    product_id: 1,
                },
                start_url: None,
                browser_command: None,
                browser_user: None,
                browser_runtime_root: None,
                browser_cdp_expose: None,
                browser_cdp_port: None,
            },
        );
        let config = AgentConfig {
            enabled: true,
            profiles,
            audit_path: Some(dir.path().join("audit")),
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
rp_ids = ["example.com"]
require_uv = true

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
    fn test_profile_principal_user_required() {
        let mut profile = make_delegated_profile();
        profile.principal_user = String::new();
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("principal_user"));
    }

    #[test]
    fn test_device_identity_nul_in_name_rejected() {
        let mut profile = make_isolated_profile();
        profile.device.name = "te\0st".to_string();
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("NUL"));
    }

    #[test]
    fn test_device_identity_nul_in_phys_rejected() {
        let mut profile = make_isolated_profile();
        profile.device.phys = "ph\0ys".to_string();
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("NUL"));
    }

    #[test]
    fn test_device_identity_nul_in_uniq_rejected() {
        let mut profile = make_isolated_profile();
        profile.device.uniq = "un\0iq".to_string();
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("NUL"));
    }

    #[test]
    fn test_device_identity_name_too_long_rejected() {
        let mut profile = make_isolated_profile();
        profile.device.name = "a".repeat(DEVICE_NAME_MAX + 1);
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("NUL terminator"));
    }

    #[test]
    fn test_device_identity_phys_too_long_rejected() {
        let mut profile = make_isolated_profile();
        profile.device.phys = "a".repeat(DEVICE_PHYS_MAX + 1);
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("NUL terminator"));
    }

    #[test]
    fn test_device_identity_uniq_too_long_rejected() {
        let mut profile = make_isolated_profile();
        profile.device.uniq = "a".repeat(DEVICE_UNIQ_MAX + 1);
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("NUL terminator"));
    }

    #[test]
    fn test_device_identity_name_at_nul_boundary_rejected() {
        let mut profile = make_isolated_profile();
        profile.device.name = "a".repeat(UHID_NAME_MAX);
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("NUL terminator"));
    }

    #[test]
    fn test_device_identity_phys_at_nul_boundary_rejected() {
        let mut profile = make_isolated_profile();
        profile.device.phys = "a".repeat(UHID_PHYS_MAX);
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("NUL terminator"));
    }

    #[test]
    fn test_device_identity_uniq_at_nul_boundary_rejected() {
        let mut profile = make_isolated_profile();
        profile.device.uniq = "a".repeat(UHID_UNIQ_MAX);
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("NUL terminator"));
    }

    #[test]
    fn test_device_identity_name_at_max_accepted() {
        let mut profile = make_isolated_profile();
        profile.device.name = "a".repeat(DEVICE_NAME_MAX);
        let pid = ProfileId::new("test").unwrap();
        assert!(profile.validate(&pid).is_ok());
    }

    #[test]
    fn test_device_identity_phys_at_max_accepted() {
        let mut profile = make_isolated_profile();
        profile.device.phys = "a".repeat(DEVICE_PHYS_MAX);
        let pid = ProfileId::new("test").unwrap();
        assert!(profile.validate(&pid).is_ok());
    }

    #[test]
    fn test_device_identity_uniq_at_max_accepted() {
        let mut profile = make_isolated_profile();
        profile.device.uniq = "a".repeat(DEVICE_UNIQ_MAX);
        let pid = ProfileId::new("test").unwrap();
        assert!(profile.validate(&pid).is_ok());
    }

    #[test]
    fn test_device_identity_human_collision_rejected() {
        let mut profile = make_isolated_profile();
        profile.device.name = "virtual-fido".to_string();
        profile.device.phys = "virtual-fido-001".to_string();
        profile.device.vendor_id = 0x15d9;
        profile.device.product_id = 0x0a37;
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("human authenticator"));
    }

    #[test]
    fn test_device_identity_partial_human_match_allowed() {
        let mut profile = make_isolated_profile();
        profile.device.name = "virtual-fido".to_string();
        profile.device.phys = "virtual-fido-001".to_string();
        profile.device.vendor_id = 0x1234;
        profile.device.product_id = 0x5678;
        let pid = ProfileId::new("test").unwrap();
        assert!(profile.validate(&pid).is_ok());
    }

    #[test]
    fn test_browser_command_empty_rejected() {
        let mut profile = make_delegated_profile();
        profile.browser_command = Some(vec![]);
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("browser_command"));
    }

    #[test]
    fn test_browser_command_nul_in_arg_rejected() {
        let mut profile = make_delegated_profile();
        profile.browser_command = Some(vec!["firefox\0--flag".to_string()]);
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("NUL"));
    }

    #[test]
    fn test_delegated_session_requires_browser_command() {
        let mut profile = make_delegated_profile();
        profile.browser_command = None;
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("browser_command"));
    }

    #[test]
    fn test_delegated_session_start_url_https_required() {
        let mut profile = make_delegated_profile();
        profile.start_url = Some("http://example.com/dashboard".to_string());
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("HTTPS"));
    }

    #[test]
    fn test_delegated_session_start_url_must_match_rp_id() {
        let mut profile = make_delegated_profile();
        profile.rp_ids = vec!["example.com".to_string()];
        profile.start_url = Some("https://other.com/dashboard".to_string());
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("exactly one"));
    }

    #[test]
    fn test_delegated_session_start_url_must_match_exactly_one_rp_id() {
        let mut profile = make_delegated_profile();
        profile.rp_ids = vec!["example.com".to_string(), "example.org".to_string()];
        profile.start_url = Some("https://other.com/dashboard".to_string());
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("exactly one"));
    }

    #[test]
    fn test_delegated_session_start_url_valid_subdomain() {
        let mut profile = make_delegated_profile();
        profile.rp_ids = vec!["example.com".to_string()];
        profile.start_url = Some("https://app.example.com/dashboard".to_string());
        profile.browser_command = Some(vec!["firefox".to_string()]);
        let pid = ProfileId::new("test").unwrap();
        assert!(profile.validate(&pid).is_ok());
    }

    #[test]
    fn test_delegated_session_start_url_exact_host_match() {
        let mut profile = make_delegated_profile();
        profile.rp_ids = vec!["example.com".to_string()];
        profile.start_url = Some("https://example.com/dashboard".to_string());
        profile.browser_command = Some(vec!["firefox".to_string()]);
        let pid = ProfileId::new("test").unwrap();
        assert!(profile.validate(&pid).is_ok());
    }

    #[test]
    fn test_enabled_requires_audit_path() {
        let config = AgentConfig {
            enabled: true,
            profiles: BTreeMap::new(),
            audit_path: None,
        };
        let err = config.validate(None).unwrap_err();
        assert!(err.to_string().contains("audit_path"));
    }

    #[test]
    fn test_disabled_does_not_require_audit_path() {
        let config = AgentConfig {
            enabled: false,
            profiles: BTreeMap::new(),
            audit_path: None,
        };
        assert!(config.validate(None).is_ok());
    }

    #[test]
    fn test_path_overlap_labels_include_profile_id() {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "myprofile".to_string(),
            AgentProfileConfig {
                mode: AgentMode::Isolated,
                principal_user: "u1".to_string(),
                rp_ids: vec!["a.com".to_string()],
                require_uv: true,
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: PathBuf::from("/tmp/overlap/data"),
                    pin_path: PathBuf::from("/tmp/overlap/data/sub"),
                }),
                registration_allowed: false,
                rules: vec![],
                delegated_registration_storage: None,
                device: DeviceIdentity {
                    name: "overlap-test".to_string(),
                    phys: "p".to_string(),
                    uniq: "u".to_string(),
                    vendor_id: 1,
                    product_id: 1,
                },
                start_url: None,
                browser_command: None,
                browser_user: None,
                browser_runtime_root: None,
                browser_cdp_expose: None,
                browser_cdp_port: None,
            },
        );
        let config = AgentConfig {
            enabled: true,
            profiles,
            audit_path: Some(PathBuf::from("/tmp/overlap-audit")),
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
                    mode: AgentMode::Isolated,
                    principal_user: format!("u-{}", name),
                    rp_ids: vec!["a.com".to_string()],
                    require_uv: true,
                    credential_refs: None,
                    max_grant_ttl: None,
                    max_session_ttl: None,
                    storage: Some(AgentStorageConfig::Local {
                        path: PathBuf::from(format!("/tmp/{}", name)),
                        pin_path: PathBuf::from(format!("/tmp/{}-pin", name)),
                    }),
                    registration_allowed: false,
                    rules: vec![],
                    delegated_registration_storage: None,
                    device: DeviceIdentity {
                        name: format!("dev-{}", name),
                        phys: format!("phys-{}", name),
                        uniq: format!("uniq-{}", name),
                        vendor_id: 1,
                        product_id: 1,
                    },
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
                mode: AgentMode::Isolated,
                principal_user: "u1".to_string(),
                rp_ids: vec!["a.com".to_string()],
                require_uv: true,
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: real_dir.clone(),
                    pin_path: symlink_dir.clone(),
                }),
                registration_allowed: false,
                rules: vec![],
                delegated_registration_storage: None,
                device: DeviceIdentity {
                    name: "a".to_string(),
                    phys: "a".to_string(),
                    uniq: "a".to_string(),
                    vendor_id: 1,
                    product_id: 1,
                },
                start_url: None,
                browser_command: None,
                browser_user: None,
                browser_runtime_root: None,
                browser_cdp_expose: None,
                browser_cdp_port: None,
            },
        );
        let config = AgentConfig {
            enabled: true,
            profiles,
            audit_path: Some(dir.path().join("audit")),
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
                mode: AgentMode::Isolated,
                principal_user: "u1".to_string(),
                rp_ids: vec!["a.com".to_string()],
                require_uv: true,
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: nested.clone(),
                    pin_path: dir.path().join("pin"),
                }),
                registration_allowed: false,
                rules: vec![],
                delegated_registration_storage: None,
                device: DeviceIdentity {
                    name: "a".to_string(),
                    phys: "a".to_string(),
                    uniq: "a".to_string(),
                    vendor_id: 1,
                    product_id: 1,
                },
                start_url: None,
                browser_command: None,
                browser_user: None,
                browser_runtime_root: None,
                browser_cdp_expose: None,
                browser_cdp_port: None,
            },
        );
        let config = AgentConfig {
            enabled: true,
            profiles,
            audit_path: Some(audit_link),
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
                mode: AgentMode::Isolated,
                principal_user: "u1".to_string(),
                rp_ids: vec!["a.com".to_string()],
                require_uv: true,
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: human_real.join("creds"),
                    pin_path: dir.path().join("pin"),
                }),
                registration_allowed: false,
                rules: vec![],
                delegated_registration_storage: None,
                device: DeviceIdentity {
                    name: "a".to_string(),
                    phys: "a".to_string(),
                    uniq: "a".to_string(),
                    vendor_id: 1,
                    product_id: 1,
                },
                start_url: None,
                browser_command: None,
                browser_user: None,
                browser_runtime_root: None,
                browser_cdp_expose: None,
                browser_cdp_port: None,
            },
        );
        let config = AgentConfig {
            enabled: true,
            profiles,
            audit_path: Some(dir.path().join("audit")),
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
rp_ids = ["example.com"]
require_uv = true
credential_store = "/tmp/creds"
pin_store = "/tmp/pin"
registration_allowed = true

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
rp_ids = ["example.com"]
require_uv = true
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
    fn test_delegated_session_rejects_storage_local() {
        let toml_str = r#"
enabled = true
audit_path = "/tmp/audit"

[profiles.bot]
mode = "delegated-session"
principal_user = "u"
rp_ids = ["example.com"]
require_uv = true
credential_refs = ["9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"]
max_grant_ttl = 120
max_session_ttl = 900
browser_command = ["firefox"]

[profiles.bot.device]
name = "n"
phys = "p"
uniq = "u"
vendor_id = 1
product_id = 2

[profiles.bot.storage.local]
path = "/tmp/creds"
pin_path = "/tmp/pin"
"#;
        let config: AgentConfig = toml::from_str(toml_str).unwrap();
        let pid = ProfileId::new("bot").unwrap();
        let err = config.profiles["bot"].validate(&pid).unwrap_err();
        assert!(err.to_string().contains("delegated-session"));
        assert!(err.to_string().contains("storage"));
    }

    #[test]
    fn test_snapshot_toml_local_storage_roundtrip() {
        let toml_str = r#"
enabled = true

[profiles.bot]
mode = "isolated"
principal_user = "bot-user"
rp_ids = ["example.com"]
require_uv = true
registration_allowed = true

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
rp_ids = ["ci.example.com"]
require_uv = true
registration_allowed = false

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
"#;
        let config: AgentConfig = toml::from_str(toml_str).unwrap();
        let profile = config.profiles.get("ci").unwrap();
        match &profile.storage {
            Some(AgentStorageConfig::Pass {
                store_path,
                path,
                gpg_backend,
                pin_path,
            }) => {
                assert_eq!(store_path, &PathBuf::from("/home/user/.password-store"));
                assert_eq!(path, "fido2/ci");
                assert_eq!(gpg_backend, "gpgme");
                assert_eq!(pin_path, &PathBuf::from("pin"));
            }
            other => panic!("expected Pass storage, got: {:?}", other),
        }
    }

    #[test]
    fn test_snapshot_toml_pass_storage_default_gpg_backend() {
        let toml_str = r#"
enabled = true

[profiles.ci]
mode = "isolated"
principal_user = "ci-user"
rp_ids = ["ci.example.com"]
require_uv = true

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
            Some(AgentStorageConfig::Pass { gpg_backend, .. }) => {
                assert_eq!(gpg_backend, "gnupg-bin");
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
rp_ids = ["secure.example.com"]
require_uv = true

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
rp_ids = ["secure.example.com"]
require_uv = true

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
                mode: AgentMode::Isolated,
                principal_user: "u1".to_string(),
                rp_ids: vec!["a.com".to_string()],
                require_uv: true,
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: PathBuf::from("/tmp/a/creds"),
                    pin_path: shared_pin.clone(),
                }),
                registration_allowed: false,
                rules: vec![],
                delegated_registration_storage: None,
                device: DeviceIdentity {
                    name: "a".to_string(),
                    phys: "a".to_string(),
                    uniq: "a".to_string(),
                    vendor_id: 1,
                    product_id: 1,
                },
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
                mode: AgentMode::Isolated,
                principal_user: "u2".to_string(),
                rp_ids: vec!["b.com".to_string()],
                require_uv: true,
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: PathBuf::from("/tmp/b/creds"),
                    pin_path: shared_pin,
                }),
                registration_allowed: false,
                rules: vec![],
                delegated_registration_storage: None,
                device: DeviceIdentity {
                    name: "b".to_string(),
                    phys: "b".to_string(),
                    uniq: "b".to_string(),
                    vendor_id: 2,
                    product_id: 2,
                },
                start_url: None,
                browser_command: None,
                browser_user: None,
                browser_runtime_root: None,
                browser_cdp_expose: None,
                browser_cdp_port: None,
            },
        );
        let config = AgentConfig {
            enabled: true,
            profiles,
            audit_path: Some(PathBuf::from("/tmp/audit")),
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
                mode: AgentMode::Isolated,
                principal_user: "u1".to_string(),
                rp_ids: vec!["a.com".to_string()],
                require_uv: true,
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: shared_cred.clone(),
                    pin_path: PathBuf::from("/tmp/a/pin"),
                }),
                registration_allowed: false,
                rules: vec![],
                delegated_registration_storage: None,
                device: DeviceIdentity {
                    name: "a".to_string(),
                    phys: "a".to_string(),
                    uniq: "a".to_string(),
                    vendor_id: 1,
                    product_id: 1,
                },
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
                mode: AgentMode::Isolated,
                principal_user: "u2".to_string(),
                rp_ids: vec!["b.com".to_string()],
                require_uv: true,
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: shared_cred,
                    pin_path: PathBuf::from("/tmp/b/pin"),
                }),
                registration_allowed: false,
                rules: vec![],
                delegated_registration_storage: None,
                device: DeviceIdentity {
                    name: "b".to_string(),
                    phys: "b".to_string(),
                    uniq: "b".to_string(),
                    vendor_id: 2,
                    product_id: 2,
                },
                start_url: None,
                browser_command: None,
                browser_user: None,
                browser_runtime_root: None,
                browser_cdp_expose: None,
                browser_cdp_port: None,
            },
        );
        let config = AgentConfig {
            enabled: true,
            profiles,
            audit_path: Some(PathBuf::from("/tmp/audit")),
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
                mode: AgentMode::Isolated,
                principal_user: "u1".to_string(),
                rp_ids: vec!["a.com".to_string()],
                require_uv: true,
                credential_refs: None,
                max_grant_ttl: None,
                max_session_ttl: None,
                storage: Some(AgentStorageConfig::Local {
                    path: dir.path().join("creds"),
                    pin_path: audit.clone(),
                }),
                registration_allowed: false,
                rules: vec![],
                delegated_registration_storage: None,
                device: DeviceIdentity {
                    name: "a".to_string(),
                    phys: "a".to_string(),
                    uniq: "a".to_string(),
                    vendor_id: 1,
                    product_id: 1,
                },
                start_url: None,
                browser_command: None,
                browser_user: None,
                browser_runtime_root: None,
                browser_cdp_expose: None,
                browser_cdp_port: None,
            },
        );
        let config = AgentConfig {
            enabled: true,
            profiles,
            audit_path: Some(audit),
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
    fn test_delegated_session_requires_browser_user() {
        let mut profile = make_delegated_profile();
        profile.browser_user = None;
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("browser_user"));
    }

    #[test]
    fn test_delegated_session_browser_user_must_not_be_empty() {
        let mut profile = make_delegated_profile();
        profile.browser_user = Some(String::new());
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("browser_user"));
    }

    #[test]
    fn test_delegated_session_browser_user_must_not_contain_nul() {
        let mut profile = make_delegated_profile();
        profile.browser_user = Some("browser\0user".to_string());
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("NUL"));
    }

    #[test]
    fn test_delegated_session_browser_user_must_differ_from_principal() {
        let mut profile = make_delegated_profile();
        profile.browser_user = Some("test-user".to_string());
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("differ"));
    }

    #[test]
    fn test_delegated_session_requires_browser_runtime_root() {
        let mut profile = make_delegated_profile();
        profile.browser_runtime_root = None;
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("browser_runtime_root"));
    }

    #[test]
    fn test_delegated_session_browser_runtime_root_must_be_absolute() {
        let mut profile = make_delegated_profile();
        profile.browser_runtime_root = Some(PathBuf::from("relative/path"));
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("absolute"));
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
rp_ids = ["secure.example.com"]
require_uv = true

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
    fn test_port_mode_allows_same_browser_and_principal_user() {
        let mut profile = make_delegated_profile();
        profile.browser_cdp_expose = Some(CdpExposeMode::Port);
        profile.browser_user = Some(profile.principal_user.clone());
        let pid = ProfileId::new("test").unwrap();
        assert!(profile.validate(&pid).is_ok());
    }

    #[test]
    fn test_port_mode_allows_browser_user_omitted() {
        let mut profile = make_delegated_profile();
        profile.browser_cdp_expose = Some(CdpExposeMode::Port);
        profile.browser_user = None;
        let pid = ProfileId::new("test").unwrap();
        assert!(profile.validate(&pid).is_ok());
    }

    #[test]
    fn test_pipe_mode_rejects_same_browser_and_principal_user() {
        let mut profile = make_delegated_profile();
        profile.browser_cdp_expose = Some(CdpExposeMode::Pipe);
        profile.browser_user = Some(profile.principal_user.clone());
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("browser_user must differ"));
    }

    #[test]
    fn test_pipe_mode_default_rejects_same_browser_and_principal_user() {
        let mut profile = make_delegated_profile();
        profile.browser_cdp_expose = None;
        profile.browser_user = Some(profile.principal_user.clone());
        let pid = ProfileId::new("test").unwrap();
        let err = profile.validate(&pid).unwrap_err();
        assert!(err.to_string().contains("browser_user must differ"));
    }
}
