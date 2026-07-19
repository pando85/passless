//! Application configuration using clap-serde-derive
//!
//! This module provides a unified configuration approach where settings can come from:
//! 1. CLI arguments (highest priority)
//! 2. Configuration file (medium priority)
//! 3. Default values (lowest priority)

use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};

use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use clap_serde_derive::ClapSerde;
use libc::{PR_SET_DUMPABLE, prctl};
use libc::{mlock, munlock};
use log::debug;
use nix::sys::resource::{Resource, setrlimit};
use passless_config_doc::ConfigDoc;
use serde::{Deserialize, Serialize};

#[cfg(feature = "agent")]
use crate::agent::AgentConfig;

use crate::error::Error;

/// Compute default local storage path
pub fn local_path() -> String {
    dirs::data_dir()
        .expect("Could not determine data directory: $XDG_DATA_HOME or $HOME/.local/share")
        .join("passless/local")
        .to_string_lossy()
        .into_owned()
}

/// Local backend configuration
#[derive(ClapSerde, Debug, Clone, Serialize, Deserialize, ConfigDoc)]
#[group(id = "local-backend-config")]
pub struct LocalBackendConfig {
    /// Path to local storage directory
    #[arg(
        long = "local-path",
        env = "PASSLESS_LOCAL_PATH",
        id = "local-path",
        value_name = "PATH"
    )]
    #[serde(default)]
    #[default(local_path())]
    pub path: String,
}

/// Compute default password-store path
pub fn pass_store_path() -> String {
    dirs::home_dir()
        .expect("Could not determine home directory: $HOME")
        .join(".password-store")
        .to_string_lossy()
        .into_owned()
}
/// Pass (password-store) backend configuration
#[derive(ClapSerde, Debug, Clone, Serialize, Deserialize, ConfigDoc)]
#[group(id = "pass-backend-config")]
pub struct PassBackendConfig {
    /// Path to password store directory
    #[arg(
        long = "pass-store-path",
        env = "PASSLESS_PASS_STORE_PATH",
        id = "pass-store-path",
        value_name = "PATH"
    )]
    #[serde(default)]
    #[default(pass_store_path())]
    pub store_path: String,

    /// Relative path within password store for FIDO2 entries
    #[arg(
        long = "pass-path",
        env = "PASSLESS_PASS_PATH",
        id = "pass-path",
        value_name = "PATH"
    )]
    #[serde(default)]
    #[default("fido2".to_string())]
    pub path: String,

    /// GPG backend: "gpgme" or "gnupg-bin"
    #[arg(
        long = "pass-gpg-backend",
        env = "PASSLESS_PASS_GPG_BACKEND",
        value_name = "BACKEND"
    )]
    #[serde(default)]
    #[default("gnupg-bin".to_string())]
    pub gpg_backend: String,
}

/// Compute default TPM storage path
pub fn tpm_path() -> String {
    dirs::data_dir()
        .expect("Could not determine data directory: $XDG_DATA_HOME or $HOME/.local/share")
        .join("passless/tpm")
        .to_string_lossy()
        .into_owned()
}

/// TPM backend configuration
#[cfg(feature = "tpm")]
#[derive(ClapSerde, Debug, Clone, Serialize, Deserialize, ConfigDoc)]
#[group(id = "tpm-backend-config")]
pub struct TpmBackendConfig {
    /// Path to TPM storage directory
    #[arg(
        long = "tpm-path",
        env = "PASSLESS_TPM_PATH",
        id = "tpm-path",
        value_name = "PATH"
    )]
    #[serde(default)]
    #[default(tpm_path())]
    pub path: String,

    /// TPM TCTI (TPM Command Transmission Interface) configuration
    #[arg(long = "tpm-tcti", env = "PASSLESS_TPM_TCTI", value_name = "TCTI")]
    #[serde(default)]
    #[default("device:/dev/tpmrm0".to_string())]
    pub tcti: String,
}

/// Security configuration
#[derive(ClapSerde, Debug, Clone, Serialize, Deserialize, ConfigDoc)]
#[group(id = "security")]
pub struct SecurityConfig {
    /// Check if mlock is available to prevent credentials from being swapped to disk
    #[arg(long = "check-mlock", env = "PASSLESS_CHECK_MLOCK")]
    #[serde(default)]
    #[default(true)]
    pub check_mlock: bool,

    /// Disable core dumps to prevent credential leakage
    #[arg(long = "disable-core-dumps", env = "PASSLESS_DISABLE_CORE_DUMPS")]
    #[serde(default)]
    #[default(true)]
    pub disable_core_dumps: bool,

    /// Enable constant signature counter to help RPs detect cloned authenticators
    #[arg(
        long = "constant-signature-counter",
        env = "PASSLESS_CONSTANT_SIGNATURE_COUNTER",
        action = ArgAction::Set,
        require_equals = true,
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    #[serde(default)]
    pub constant_signature_counter: bool,

    /// Always require user verification for all operations
    /// - When PIN is set + pin.enforcement="required": requires PIN
    /// - When PIN is set + pin.enforcement="optional": depends on context
    /// - When PIN is set + pin.enforcement="never": uses notification fallback
    /// - When PIN not set: uses notification
    #[arg(
        long = "always-uv",
        env = "PASSLESS_ALWAYS_UV",
        action = ArgAction::Set,
        require_equals = true,
        num_args = 0..=1,
        default_value = "true",
        default_missing_value = "true"
    )]
    #[serde(default)]
    #[default(true)]
    pub always_uv: bool,

    /// Show user verification notification during registration
    #[arg(
        long = "user-verification-registration",
        env = "PASSLESS_USER_VERIFICATION_REGISTRATION"
    )]
    #[serde(default)]
    #[default(true)]
    pub user_verification_registration: bool,

    /// Show user verification notification during authentication
    #[arg(
        long = "user-verification-authentication",
        env = "PASSLESS_USER_VERIFICATION_AUTHENTICATION"
    )]
    #[serde(default)]
    #[default(true)]
    pub user_verification_authentication: bool,

    /// Notification timeout in seconds (0 = no timeout)
    #[arg(
        long = "notification-timeout",
        env = "PASSLESS_NOTIFICATION_TIMEOUT",
        value_name = "SECONDS"
    )]
    #[serde(default)]
    #[default(30)]
    pub notification_timeout: u32,
}

/// PIN enforcement policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PinEnforcement {
    /// Never require PIN, always use notification fallback (backward compatible)
    Never,
    /// Use PIN only when always_uv=true or client requests UV
    #[default]
    Optional,
    /// Always require PIN when set (most secure)
    Required,
}

impl std::str::FromStr for PinEnforcement {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "never" => Ok(PinEnforcement::Never),
            "optional" => Ok(PinEnforcement::Optional),
            "required" => Ok(PinEnforcement::Required),
            _ => Err(format!(
                "Invalid PIN enforcement '{}'. Must be: never, optional, or required",
                s
            )),
        }
    }
}

impl std::fmt::Display for PinEnforcement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinEnforcement::Never => write!(f, "never"),
            PinEnforcement::Optional => write!(f, "optional"),
            PinEnforcement::Required => write!(f, "required"),
        }
    }
}

/// PIN configuration
#[derive(ClapSerde, Debug, Clone, Serialize, Deserialize, ConfigDoc)]
#[group(id = "pin")]
pub struct PinConfig {
    /// PIN enforcement policy when PIN is set:
    /// - "never": Always use notification fallback (backward compatible, convenience)
    /// - "optional": Use PIN only when always_uv=true or client requests UV
    /// - "required": Always require PIN when set (most secure)
    #[arg(
        long = "pin-enforcement",
        env = "PASSLESS_PIN_ENFORCEMENT",
        value_name = "POLICY"
    )]
    #[serde(default)]
    #[default(PinEnforcement::Optional)]
    pub enforcement: PinEnforcement,

    /// Minimum PIN length in characters (CTAP spec: 4-63)
    #[arg(
        long = "pin-min-length",
        env = "PASSLESS_PIN_MIN_LENGTH",
        value_name = "LENGTH"
    )]
    #[serde(default)]
    #[default(4)]
    pub min_length: u8,

    /// Maximum PIN retry attempts before lockout (CTAP spec: 8)
    #[arg(
        long = "pin-max-retries",
        env = "PASSLESS_PIN_MAX_RETRIES",
        value_name = "RETRIES"
    )]
    #[serde(default)]
    #[default(8)]
    pub max_retries: u8,

    /// Maximum user verification retry attempts before UV is blocked (default: 8)
    ///
    /// This controls how many consecutive UV failures are allowed before UV is blocked.
    /// Use `passless client pin uv-reset` to restore the retry counter after authentication.
    /// Higher values improve usability but may reduce security against brute-force attacks.
    #[arg(
        long = "pin-max-uv-retries",
        env = "PASSLESS_PIN_MAX_UV_RETRIES",
        value_name = "RETRIES"
    )]
    #[serde(default)]
    #[default(8)]
    pub max_uv_retries: u8,

    /// Auto-lock timeout in seconds after max failed attempts (0 = disabled)
    /// After lockout, authenticator must be reset to use PIN again
    #[arg(
        long = "pin-auto-lock-timeout",
        env = "PASSLESS_PIN_AUTO_LOCK_TIMEOUT",
        value_name = "SECONDS"
    )]
    #[serde(default)]
    #[default(0)]
    pub auto_lock_timeout: u32,
}

impl PinConfig {
    /// Validate PIN configuration values
    pub fn validate(&self) -> crate::error::Result<()> {
        if self.min_length < 4 || self.min_length > 63 {
            return Err(crate::error::Error::Config(format!(
                "pin.min_length must be between 4 and 63, got {}",
                self.min_length
            )));
        }
        if self.max_retries == 0 {
            return Err(crate::error::Error::Config(
                "pin.max_retries must be greater than 0".to_string(),
            ));
        }
        if self.max_uv_retries == 0 {
            return Err(crate::error::Error::Config(
                "pin.max_uv_retries must be greater than 0".to_string(),
            ));
        }
        Ok(())
    }
}

impl SecurityConfig {
    /// Apply security hardening measures
    pub fn apply_hardening(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.disable_core_dumps {
            self.disable_core_dumps_impl()?;
        }
        if self.check_mlock {
            self.probe_mlock_capability()?;
        }
        Ok(())
    }

    /// Disable core dumps to prevent credential leakage
    fn disable_core_dumps_impl(&self) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Disabling core dumps to prevent credential leakage");
        setrlimit(Resource::RLIMIT_CORE, 0, 0)?;
        let r = unsafe { prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if r != 0 {
            log::warn!("prctl(PR_SET_DUMPABLE) failed: {}", r);
        }
        Ok(())
    }

    /// Probe mlock capability by testing with a small allocation
    fn probe_mlock_capability(&self) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Check mlock capability");

        let test_size = 4096;
        let test_buffer = vec![0u8; test_size];
        let ptr = test_buffer.as_ptr() as *const libc::c_void;

        let lock_result = unsafe { mlock(ptr, test_size) };

        if lock_result == 0 {
            unsafe { munlock(ptr, test_size) };
            log::debug!("MLOCK is enabled - sensitive data will not be swapped to disk");
        } else {
            log::warn!(
                "mlock capability probe failed - memory locking may not be available.\n\
                 Hint: grant CAP_IPC_LOCK to the binary with: 'sudo setcap cap_ipc_lock=+ep $(which passless)'"
            );
        }
        Ok(())
    }
}

/// Main application configuration
/// Note: Cannot derive Clone/Debug because it has #[clap_serde] fields
#[derive(ClapSerde, Serialize, Deserialize, Debug, ConfigDoc)]
pub struct AppConfig {
    /// Storage backend type: pass, tpm (experimental), or local (for testing)
    #[arg(short = 't', long = "backend-type", env = "PASSLESS_BACKEND_TYPE")]
    #[serde(default)]
    #[default("pass".to_string())]
    pub backend_type: String,

    /// Enable verbose logging
    // workaround for allowing `-v` syntax instead of `-v=true`
    #[arg(
        short,
        long,
        env = "PASSLESS_VERBOSE",
        action = ArgAction::Set,
        require_equals = true,
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    #[default(true)]
    #[serde(default)]
    pub verbose: bool,

    /// Pass backend configuration
    #[clap_serde]
    #[serde(default)]
    #[command(flatten)]
    pub pass: PassBackendConfig,

    /// TPM backend configuration
    #[cfg(feature = "tpm")]
    #[clap_serde]
    #[serde(default)]
    #[command(flatten)]
    pub tpm: TpmBackendConfig,

    /// Local backend configuration
    #[clap_serde]
    #[serde(default)]
    #[command(flatten)]
    pub local: LocalBackendConfig,

    /// Security hardening configuration
    #[clap_serde]
    #[serde(default)]
    #[command(flatten)]
    pub security: SecurityConfig,

    /// PIN configuration
    #[clap_serde]
    #[serde(default)]
    #[command(flatten)]
    pub pin: PinConfig,

    /// Agent configuration (only available with the `agent` feature)
    #[cfg(feature = "agent")]
    #[arg(skip)]
    pub agents: AgentConfig,
}

/// Backend-specific configuration
#[derive(Debug, Clone)]
pub enum BackendConfig {
    Local {
        path: String,
    },
    Pass {
        store_path: String,
        path: String,
        gpg_backend: String,
    },
    #[cfg(feature = "tpm")]
    Tpm {
        path: String,
        tcti: String,
    },
}

impl BackendConfig {
    /// Canonicalize a path, resolving symlinks for existing parents.
    ///
    /// If the full path does not exist, canonicalize the longest existing
    /// prefix and append the remaining components lexically.
    pub fn canonicalize_path(path: &Path) -> PathBuf {
        match fs::canonicalize(path) {
            Ok(p) => p,
            Err(_) => {
                let mut current = path.to_path_buf();
                let mut suffix = Vec::new();
                loop {
                    match fs::canonicalize(&current) {
                        Ok(base) => {
                            let mut result = base;
                            for component in suffix.iter().rev() {
                                result.push(component);
                            }
                            return result;
                        }
                        Err(_) => {
                            if let Some(file_name) = current.file_name() {
                                suffix.push(file_name.to_os_string());
                                current = current
                                    .parent()
                                    .map(|p| p.to_path_buf())
                                    .unwrap_or_default();
                            } else {
                                return path.to_path_buf();
                            }
                        }
                    }
                }
            }
        }
    }

    /// Return the canonical state path for this backend.
    ///
    /// This is used as the identity for the instance lock: two daemons with the
    /// same canonical state path will contend for the same lock.
    pub fn state_path(&self) -> PathBuf {
        match self {
            BackendConfig::Local { path } => Self::canonicalize_path(Path::new(path)),
            BackendConfig::Pass {
                store_path, path, ..
            } => Self::canonicalize_path(&Path::new(store_path).join(path)),
            #[cfg(feature = "tpm")]
            BackendConfig::Tpm { path, .. } => Self::canonicalize_path(Path::new(path)),
        }
    }

    /// Return a human-readable display string for the backend state path.
    pub fn state_display(&self) -> String {
        match self {
            BackendConfig::Local { path } => path.clone(),
            BackendConfig::Pass {
                store_path, path, ..
            } => {
                format!("{}/{}", store_path, path)
            }
            #[cfg(feature = "tpm")]
            BackendConfig::Tpm { path, .. } => path.clone(),
        }
    }

    /// Validate backend configuration for security and correctness.
    ///
    /// This checks that paths are well-formed and don't escape their intended roots.
    pub fn validate(&self) -> crate::error::Result<()> {
        match self {
            BackendConfig::Local { path } => {
                let p = Path::new(path);
                if !p.is_absolute() && !p.starts_with("~") {
                    debug!("Local backend path is relative: {}, canonicalizing", path);
                }
                Ok(())
            }
            BackendConfig::Pass {
                store_path, path, ..
            } => {
                let p = Path::new(path);
                if p.is_absolute() {
                    return Err(Error::Config(format!(
                        "Pass backend 'path' must be relative, got absolute path: {}",
                        path
                    )));
                }
                if path.contains("..") {
                    return Err(Error::Config(format!(
                        "Pass backend 'path' must not contain '..': {}",
                        path
                    )));
                }
                // Verify the combined path doesn't escape the store
                let combined = Path::new(store_path).join(path);
                let canonical_store = Self::canonicalize_path(Path::new(store_path));
                let canonical_combined = Self::canonicalize_path(&combined);
                if !canonical_combined.starts_with(&canonical_store) {
                    return Err(Error::Config(format!(
                        "Pass backend 'path' escapes store_path: {} not beneath {}",
                        canonical_combined.display(),
                        canonical_store.display()
                    )));
                }
                Ok(())
            }
            #[cfg(feature = "tpm")]
            BackendConfig::Tpm { path, .. } => {
                let p = Path::new(path);
                if !p.is_absolute() && !p.starts_with("~") {
                    debug!("TPM backend path is relative: {}, canonicalizing", path);
                }
                Ok(())
            }
        }
    }
}

impl AppConfig {
    /// Load configuration with precedence: CLI > config file > defaults
    pub fn load(args: &mut Args) -> crate::error::Result<Self> {
        let default_config_path = dirs::config_dir().map(|p| p.join("passless/config.toml"));

        let config_file_path = args
            .config_path
            .as_ref()
            .or(default_config_path.as_ref())
            .filter(|p| p.exists());

        if let Some(path) = config_file_path
            && let Ok(f) = File::open(path)
        {
            log::info!("Loading configuration from: {}", path.display());
            let content = std::io::read_to_string(BufReader::new(f)).unwrap_or_default();

            #[cfg(feature = "agent")]
            let agent_config = {
                match toml::from_str::<toml::Table>(&content) {
                    Ok(table) => match table.get("agents") {
                        Some(agents_value) => serde::Deserialize::deserialize(agents_value.clone())
                            .map_err(|e| {
                                Error::Config(format!(
                                    "failed to parse [agents] section in {}: {}",
                                    path.display(),
                                    e
                                ))
                            })?,
                        None => AgentConfig::default(),
                    },
                    Err(e) => {
                        return Err(Error::Config(format!(
                            "failed to parse config file {} as TOML: {}",
                            path.display(),
                            e
                        )));
                    }
                }
            };

            match toml::from_str::<<AppConfig as ClapSerde>::Opt>(&content) {
                Ok(file_config) => {
                    #[allow(unused_mut)]
                    let mut config = AppConfig::from(file_config).merge(&mut args.config);
                    #[cfg(feature = "agent")]
                    {
                        config.agents = agent_config;
                    }
                    return Ok(config);
                }
                Err(e) => {
                    return Err(Error::Config(format!(
                        "failed to parse config file {}: {}",
                        path.display(),
                        e
                    )));
                }
            }
        }

        #[allow(unused_mut)]
        let mut config = AppConfig::from(&mut args.config);
        #[cfg(feature = "agent")]
        {
            config.agents = AgentConfig::default();
        }
        Ok(config)
    }

    /// Get the backend configuration based on the backend_type
    pub fn backend(&self) -> crate::error::Result<BackendConfig> {
        match self.backend_type.as_str() {
            "local" => Ok(BackendConfig::Local {
                path: self.local.path.clone(),
            }),
            "pass" => Ok(BackendConfig::Pass {
                store_path: self.pass.store_path.clone(),
                path: self.pass.path.clone(),
                gpg_backend: self.pass.gpg_backend.clone(),
            }),
            #[cfg(feature = "tpm")]
            "tpm" => Ok(BackendConfig::Tpm {
                path: self.tpm.path.clone(),
                tcti: self.tpm.tcti.clone(),
            }),
            _ => Err(crate::error::Error::Config(format!(
                "Invalid backend_type '{}'. Must be one of: local, pass, tpm",
                self.backend_type
            ))),
        }
    }

    /// Apply security hardening measures
    pub fn apply_security_hardening(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.security.apply_hardening()
    }

    /// Get security configuration
    pub fn security_config(&self) -> SecurityConfig {
        self.security.clone()
    }

    /// Get PIN configuration
    pub fn pin_config(&self) -> PinConfig {
        self.pin.clone()
    }

    /// Validate the configuration
    pub fn validate(&self) -> crate::error::Result<()> {
        self.pin.validate()?;
        #[cfg(feature = "agent")]
        {
            let human_path = self.backend().ok().map(|b| b.state_path());
            self.agents.validate(human_path.as_deref())?;
        }
        Ok(())
    }
}

/// CLI arguments structure
#[derive(Parser)]
#[command(author, version, about)]
pub struct Args {
    /// Path to configuration file (TOML format)
    #[arg(short, long, env = "PASSLESS_CONFIG")]
    pub config_path: Option<PathBuf>,

    /// Application configuration (can come from CLI or config file)
    #[command(flatten)]
    pub config: <AppConfig as ClapSerde>::Opt,

    /// Subcommands
    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// Output format for client commands
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable plain text output
    Plain,
    /// JSON output for programmatic consumption
    Json,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "plain" => Ok(OutputFormat::Plain),
            "json" => Ok(OutputFormat::Json),
            _ => Err(format!(
                "Invalid output format '{}'. Must be 'plain' or 'json'",
                s
            )),
        }
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Plain => write!(f, "plain"),
            OutputFormat::Json => write!(f, "json"),
        }
    }
}

/// Subcommands for passless
#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Configuration management commands
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// FIDO2 client commands for managing authenticators
    ///
    /// These commands require a running authenticator. For testing:
    /// 1. Start authenticator: PASSLESS_E2E_AUTO_ACCEPT_UV=1 cargo run -- --backend-type local
    /// 2. Run client commands in another terminal with the same environment variable
    Client {
        /// Select device by index (0-based) or name. Use 'devices' subcommand to list available devices.
        #[arg(short = 'D', long = "device", value_name = "INDEX|NAME", global = true)]
        device: Option<String>,

        /// Output format: plain (default) or json
        #[arg(
            short = 'o',
            long = "output",
            value_name = "FORMAT",
            default_value = "plain",
            global = true
        )]
        output: OutputFormat,

        #[command(subcommand)]
        action: ClientAction,
    },
    /// Agent administration commands
    #[cfg(feature = "agent")]
    AgentAdmin {
        /// Output format: json (default) or plain
        #[arg(
            short = 'o',
            long = "output",
            value_name = "FORMAT",
            default_value = "json",
            global = true
        )]
        output: OutputFormat,

        #[command(subcommand)]
        action: AgentAdminAction,
    },
    /// Agent principal and session commands
    #[cfg(feature = "agent")]
    Agent {
        /// Profile to use for principal commands
        #[arg(long, value_name = "PROFILE", global = true)]
        profile: Option<String>,

        /// Output format: json (default) or plain
        #[arg(
            short = 'o',
            long = "output",
            value_name = "FORMAT",
            default_value = "json",
            global = true
        )]
        output: OutputFormat,

        #[command(subcommand)]
        action: crate::AgentCommand,
    },
}

/// Configuration actions
#[derive(Subcommand, Debug, Clone)]
pub enum ConfigAction {
    /// Print the default configuration in TOML format
    Print,
}

/// Agent administration actions
#[cfg(feature = "agent")]
#[derive(Subcommand, Debug, Clone)]
pub enum AgentAdminAction {
    /// Install the Passless skill for a supported coding agent
    Install {
        /// Agent to install for; auto installs to every detected agent
        #[arg(value_enum, default_value_t = AgentSkillTarget::Auto)]
        target: AgentSkillTarget,

        /// Install for the current user or the current Git worktree
        #[arg(long, value_enum, default_value_t = AgentSkillScope::User)]
        scope: AgentSkillScope,

        /// Replace a different existing file at the skill target
        #[arg(long)]
        force: bool,
    },
    /// Profile management
    Profile {
        #[command(subcommand)]
        action: AdminProfileAction,
    },
    /// Policy management
    Policy {
        #[command(subcommand)]
        action: AdminPolicyAction,
    },
    /// Credential management
    Credential {
        #[command(subcommand)]
        action: AdminCredentialAction,
    },
    /// Delegation management
    Delegation {
        #[command(subcommand)]
        action: AdminDelegationAction,
    },
    /// Session management
    Session {
        #[command(subcommand)]
        action: AdminSessionAction,
    },
    /// Audit log management
    Audit {
        #[command(subcommand)]
        action: AdminAuditAction,
    },
    /// Shut down the running daemon
    #[command(hide = true)]
    Shutdown {
        /// Confirm the shutdown
        #[arg(long)]
        confirm: bool,
    },
}

/// Admin profile actions
#[cfg(feature = "agent")]
#[derive(Subcommand, Debug, Clone)]
pub enum AdminProfileAction {
    /// Check if a profile exists and is valid
    Check {
        /// Profile identifier
        #[arg(value_name = "PROFILE")]
        profile: String,
    },
    /// Show profile details
    Show {
        /// Profile identifier
        #[arg(value_name = "PROFILE")]
        profile: String,
    },
    /// List all configured profiles
    List,
    /// Enable a profile
    Enable {
        /// Profile identifier
        #[arg(value_name = "PROFILE")]
        profile: String,
    },
    /// Disable a profile
    Disable {
        /// Profile identifier
        #[arg(value_name = "PROFILE")]
        profile: String,
    },
}

/// Admin policy actions
#[cfg(feature = "agent")]
#[derive(Subcommand, Debug, Clone)]
pub enum AdminPolicyAction {
    /// Check policy validity for a profile
    Check {
        /// Profile identifier
        #[arg(value_name = "PROFILE")]
        profile: String,
    },
    /// Reload policy for a profile
    Reload {
        /// Profile identifier
        #[arg(value_name = "PROFILE")]
        profile: String,
    },
    /// Show current policy for a profile
    Show {
        /// Profile identifier
        #[arg(value_name = "PROFILE")]
        profile: String,
    },
}

/// Admin credential actions
#[cfg(feature = "agent")]
#[derive(Subcommand, Debug, Clone)]
pub enum AdminCredentialAction {
    /// List credentials
    List {
        /// Filter by relying party ID
        #[arg(short = 'd', long = "domain", value_name = "DOMAIN")]
        rp_id: Option<String>,
    },
    /// Show credential details
    Show {
        /// Credential reference (hex)
        #[arg(value_name = "CREDENTIAL_REF")]
        credential_ref: String,
    },
    /// Revoke a credential
    Revoke {
        /// Credential reference (hex)
        #[arg(value_name = "CREDENTIAL_REF")]
        credential_ref: String,
        /// Confirm the revocation
        #[arg(long)]
        confirm: bool,
    },
    /// Delete a credential
    Delete {
        /// Credential reference (hex)
        #[arg(value_name = "CREDENTIAL_REF")]
        credential_ref: String,
        /// Confirm the deletion
        #[arg(long)]
        confirm: bool,
    },
}

/// Admin delegation actions
#[cfg(feature = "agent")]
#[derive(Subcommand, Debug, Clone)]
pub enum AdminDelegationAction {
    /// Show delegation details
    Show {
        /// Grant identifier (hex)
        #[arg(value_name = "GRANT_ID")]
        grant_id: String,
    },
    /// List all delegations
    List {
        /// Filter by profile
        #[arg(long, value_name = "PROFILE")]
        profile: Option<String>,
    },
    /// Revoke a delegation
    Revoke {
        /// Grant identifier (hex)
        #[arg(value_name = "GRANT_ID")]
        grant_id: String,
        /// Confirm the revocation
        #[arg(long)]
        confirm: bool,
    },
}

/// Admin session actions
#[cfg(feature = "agent")]
#[derive(Subcommand, Debug, Clone)]
pub enum AdminSessionAction {
    /// Show session details
    Show {
        /// Session identifier (hex)
        #[arg(value_name = "SESSION_ID")]
        session_id: String,
    },
    /// List all sessions
    List {
        /// Filter by profile
        #[arg(long, value_name = "PROFILE")]
        profile: Option<String>,
    },
    /// Revoke a session
    Revoke {
        /// Session identifier (hex)
        #[arg(value_name = "SESSION_ID")]
        session_id: String,
        /// Confirm the revocation
        #[arg(long)]
        confirm: bool,
    },
}

/// Admin audit actions
#[cfg(feature = "agent")]
#[derive(Subcommand, Debug, Clone)]
pub enum AdminAuditAction {
    /// Show audit subsystem status
    Status,
    /// Verify audit log integrity
    Verify,
    /// Export audit log entries
    Export {
        /// Export format
        #[arg(long, value_enum, default_value_t = AdminAuditExportFormat::Json)]
        format: AdminAuditExportFormat,
    },
}

/// Audit export format for CLI
#[cfg(feature = "agent")]
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminAuditExportFormat {
    Json,
    Csv,
}

/// Supported coding-agent skill targets
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentSkillTarget {
    Auto,
    Opencode,
    Claude,
    Pi,
}

/// Skill installation scope
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentSkillScope {
    User,
    Project,
}

/// Client actions for FIDO2 authenticator management
#[derive(Subcommand, Debug, Clone)]
pub enum ClientAction {
    /// List all available FIDO2 authenticators/devices
    Devices,
    /// Get authenticator information (capabilities, AAGUID, versions, etc.)
    Info,
    /// Reset the authenticator (WARNING: deletes ALL credentials)
    Reset {
        /// Confirmation flag that must be provided twice for safety
        #[arg(long = "yes-i-really-want-to-reset-my-device", action = ArgAction::Count)]
        confirm: u8,
    },
    /// List all credentials on the authenticator
    List {
        /// Filter by relying party ID (domain)
        #[arg(short = 'd', long = "domain", value_name = "DOMAIN")]
        rp_id: Option<String>,
    },
    /// Show detailed information about a specific credential
    Show {
        /// Credential ID in hexadecimal format
        #[arg(value_name = "CREDENTIAL_ID")]
        credential_id: String,
    },
    /// Delete a specific credential by ID
    Delete {
        /// Credential ID in hexadecimal format
        #[arg(value_name = "CREDENTIAL_ID")]
        credential_id: String,
    },
    /// Rename a credential (update user name and/or display name)
    Rename {
        /// Credential ID in hexadecimal format
        #[arg(value_name = "CREDENTIAL_ID")]
        credential_id: String,
        /// New user name (login identifier)
        #[arg(short = 'u', long = "user-name", value_name = "NAME")]
        user_name: Option<String>,
        /// New display name (friendly name)
        #[arg(short = 'n', long = "display-name", value_name = "NAME")]
        display_name: Option<String>,
    },
    /// PIN management commands
    Pin {
        #[command(subcommand)]
        action: PinAction,
    },
}

/// PIN management actions
#[derive(Subcommand, Debug, Clone)]
pub enum PinAction {
    /// Set a new PIN (authenticator must not have a PIN set)
    Set {
        /// The new PIN (minimum 4 characters)
        #[arg(value_name = "PIN")]
        pin: String,
    },
    /// Change the existing PIN
    Change {
        /// The current PIN
        #[arg(value_name = "OLD_PIN")]
        old_pin: String,
        /// The new PIN (minimum 4 characters)
        #[arg(value_name = "NEW_PIN")]
        new_pin: String,
    },
    /// Reset built-in user verification retries without deleting credentials
    UvReset,
}

/// Agent principal and session commands
#[cfg(feature = "agent")]
#[derive(Subcommand, Debug, Clone)]
pub enum AgentCommand {
    /// Run health diagnostics
    Doctor,
    /// Show principal capabilities
    Capabilities,
    /// Show principal instructions
    Instructions,
    /// Intent management
    Intent {
        #[command(subcommand)]
        action: AgentIntentAction,
    },
    /// Delegation management
    Delegation {
        #[command(subcommand)]
        action: AgentDelegationAction,
    },
    /// Credential queries
    Credential {
        #[command(subcommand)]
        action: AgentCredentialAction,
    },
    /// Show browser bridge status
    BrowserStatus,
    /// Show endpoint status
    EndpointStatus,
    /// Send a CDP command to the managed browser session
    ///
    /// WARNING: This is the full browser-session authority interface.
    /// CDP commands can access cookies, DOM, network state, and session data.
    /// Output may contain CDP response data — do not mix with credential/admin output.
    BrowserControl {
        /// CDP request as JSON (e.g. '{"id":1,"method":"Page.navigate","params":{"url":"https://example.com"}}')
        #[arg(long, value_name = "JSON", conflicts_with = "request_file")]
        request: Option<String>,
        /// Path to file containing CDP request JSON (owner/symlink/size checked)
        #[arg(long, value_name = "PATH", conflicts_with = "request")]
        request_file: Option<std::path::PathBuf>,
        /// Timeout in milliseconds (default: 5000, max: 30000)
        #[arg(long, value_name = "MS", default_value = "5000")]
        timeout_ms: u32,
    },
    /// Launch a detached principal session
    Run {
        /// Profile to launch
        #[arg(long, value_name = "PROFILE")]
        profile: String,
        /// Absolute command path and arguments
        #[arg(last = true, required = true)]
        command: Vec<std::path::PathBuf>,
    },
}

/// Agent intent actions
#[cfg(feature = "agent")]
#[derive(Subcommand, Debug, Clone)]
pub enum AgentIntentAction {
    /// Create a new intent
    Create {
        /// Action type
        #[arg(value_enum)]
        action: AgentIntentActionType,
        /// Relying party ID
        #[arg(long, value_name = "RP_ID")]
        rp: String,
        /// Credential reference (hex)
        #[arg(long, value_name = "CREDENTIAL_REF")]
        credential: Option<String>,
        /// Reason for the intent
        #[arg(long, value_name = "REASON")]
        reason: Option<String>,
    },
    /// Show intent status
    Show {
        /// Request identifier (hex)
        #[arg(value_name = "REQUEST_ID")]
        request_id: String,
    },
    /// Wait for intent to reach terminal state
    Wait {
        /// Request identifier (hex)
        #[arg(value_name = "REQUEST_ID")]
        request_id: String,
        /// Timeout in seconds
        #[arg(long, value_name = "SECONDS")]
        timeout: Option<u64>,
        /// Poll interval in milliseconds
        #[arg(long, value_name = "MS")]
        poll_interval: Option<u64>,
    },
    /// Cancel a pending intent
    Cancel {
        /// Request identifier (hex)
        #[arg(value_name = "REQUEST_ID")]
        request_id: String,
    },
}

/// Intent action type for CLI
#[cfg(feature = "agent")]
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentIntentActionType {
    Register,
    Authenticate,
}

/// Agent delegation actions
#[cfg(feature = "agent")]
#[derive(Subcommand, Debug, Clone)]
pub enum AgentDelegationAction {
    /// Request a new delegation
    Request {
        /// Relying party ID
        #[arg(long, value_name = "RP_ID")]
        rp: String,
        /// Credential reference (hex)
        #[arg(long, value_name = "CREDENTIAL_REF")]
        credential: String,
        /// Session TTL in seconds
        #[arg(long, value_name = "SECONDS")]
        session_ttl: u64,
        /// Reason for the delegation
        #[arg(long, value_name = "REASON")]
        reason: Option<String>,
    },
    /// Show delegation status
    Show {
        /// Request identifier (hex)
        #[arg(value_name = "REQUEST_ID")]
        request_id: String,
    },
    /// Wait for delegation to reach terminal state
    Wait {
        /// Request identifier (hex)
        #[arg(value_name = "REQUEST_ID")]
        request_id: String,
        /// Timeout in seconds
        #[arg(long, value_name = "SECONDS")]
        timeout: Option<u64>,
        /// Poll interval in milliseconds
        #[arg(long, value_name = "MS")]
        poll_interval: Option<u64>,
    },
    /// Cancel a pending delegation
    Cancel {
        /// Request identifier (hex)
        #[arg(value_name = "REQUEST_ID")]
        request_id: String,
    },
}

/// Agent credential actions
#[cfg(feature = "agent")]
#[derive(Subcommand, Debug, Clone)]
pub enum AgentCredentialAction {
    /// List credentials for the profile
    List,
    /// Show credential details
    Show {
        /// Credential reference (hex)
        #[arg(value_name = "CREDENTIAL_REF")]
        credential_ref: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "agent")]
    #[test]
    fn test_agent_admin_install_defaults() {
        let args = Args::try_parse_from(["passless", "agent-admin", "install"]).unwrap();
        assert!(matches!(
            args.command,
            Some(Commands::AgentAdmin {
                action: AgentAdminAction::Install {
                    target: AgentSkillTarget::Auto,
                    scope: AgentSkillScope::User,
                    force: false,
                },
                ..
            })
        ));
    }

    #[cfg(feature = "agent")]
    #[test]
    fn test_agent_admin_install_explicit_options() {
        let args = Args::try_parse_from([
            "passless",
            "agent-admin",
            "install",
            "claude",
            "--scope",
            "project",
            "--force",
        ])
        .unwrap();
        assert!(matches!(
            args.command,
            Some(Commands::AgentAdmin {
                action: AgentAdminAction::Install {
                    target: AgentSkillTarget::Claude,
                    scope: AgentSkillScope::Project,
                    force: true,
                },
                ..
            })
        ));
    }

    #[test]
    fn test_pin_config_default_max_uv_retries() {
        let config = PinConfig {
            enforcement: PinEnforcement::Optional,
            min_length: 4,
            max_retries: 8,
            max_uv_retries: 8,
            auto_lock_timeout: 0,
        };
        assert_eq!(config.max_uv_retries, 8);
    }

    #[test]
    fn test_pin_config_validate_success() {
        let config = PinConfig {
            enforcement: PinEnforcement::Optional,
            min_length: 4,
            max_retries: 8,
            max_uv_retries: 8,
            auto_lock_timeout: 0,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_pin_config_validate_zero_max_uv_retries() {
        let config = PinConfig {
            enforcement: PinEnforcement::Optional,
            min_length: 4,
            max_retries: 8,
            max_uv_retries: 0,
            auto_lock_timeout: 0,
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("max_uv_retries"));
    }

    #[test]
    fn test_pin_config_validate_zero_max_retries() {
        let config = PinConfig {
            enforcement: PinEnforcement::Optional,
            min_length: 4,
            max_retries: 0,
            max_uv_retries: 8,
            auto_lock_timeout: 0,
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("max_retries"));
    }

    #[test]
    fn test_pin_config_validate_invalid_min_length() {
        let config = PinConfig {
            enforcement: PinEnforcement::Optional,
            min_length: 3,
            max_retries: 8,
            max_uv_retries: 8,
            auto_lock_timeout: 0,
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("min_length"));
    }

    #[test]
    fn test_canonicalize_path_existing() {
        let dir = std::env::temp_dir();
        let canonical = BackendConfig::canonicalize_path(&dir);
        assert!(canonical.is_absolute());
        assert!(canonical.exists());
    }

    #[test]
    fn test_canonicalize_path_nonexistent() {
        let base = std::env::temp_dir();
        let nonexistent = base.join("passless_test_nonexistent_dir_12345/sub");
        let canonical = BackendConfig::canonicalize_path(&nonexistent);
        assert!(canonical.is_absolute());
        assert!(canonical.starts_with(BackendConfig::canonicalize_path(&base)));
    }

    #[test]
    fn test_canonicalize_path_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let canonical_real = BackendConfig::canonicalize_path(&real);
        let canonical_link = BackendConfig::canonicalize_path(&link);
        assert_eq!(canonical_real, canonical_link);
    }

    #[test]
    fn test_local_state_path_relative_and_absolute() {
        let dir = tempfile::tempdir_in(".").unwrap();
        let abs_path = std::fs::canonicalize(dir.path()).unwrap();
        let rel_path = dir.path().to_path_buf();

        let backend_abs = BackendConfig::Local {
            path: abs_path.display().to_string(),
        };
        let backend_rel = BackendConfig::Local {
            path: rel_path.display().to_string(),
        };
        assert_eq!(backend_abs.state_path(), backend_rel.state_path());
    }

    #[test]
    fn test_pass_state_path_different_subpaths() {
        let store = "/tmp/passless_test_store";
        let backend_a = BackendConfig::Pass {
            store_path: store.to_string(),
            path: "fido2".to_string(),
            gpg_backend: "gnupg-bin".to_string(),
        };
        let backend_b = BackendConfig::Pass {
            store_path: store.to_string(),
            path: "fido2-other".to_string(),
            gpg_backend: "gnupg-bin".to_string(),
        };
        assert_ne!(backend_a.state_path(), backend_b.state_path());
    }

    #[test]
    fn test_different_local_paths_produce_different_identities() {
        let backend_a = BackendConfig::Local {
            path: "/tmp/passless_a".to_string(),
        };
        let backend_b = BackendConfig::Local {
            path: "/tmp/passless_b".to_string(),
        };
        assert_ne!(backend_a.state_path(), backend_b.state_path());
    }

    #[cfg(feature = "agent")]
    #[test]
    fn test_agent_admin_profile_list() {
        let args = Args::try_parse_from(["passless", "agent-admin", "profile", "list"]).unwrap();
        assert!(matches!(
            args.command,
            Some(Commands::AgentAdmin {
                action: AgentAdminAction::Profile {
                    action: AdminProfileAction::List,
                },
                ..
            })
        ));
    }

    #[cfg(feature = "agent")]
    #[test]
    fn test_agent_admin_credential_delete_without_confirm() {
        let args = Args::try_parse_from([
            "passless",
            "agent-admin",
            "credential",
            "delete",
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        ])
        .unwrap();
        assert!(matches!(
            args.command,
            Some(Commands::AgentAdmin {
                action: AgentAdminAction::Credential {
                    action: AdminCredentialAction::Delete { confirm: false, .. },
                },
                ..
            })
        ));
    }

    #[cfg(feature = "agent")]
    #[test]
    fn test_agent_admin_credential_delete_with_confirm() {
        let args = Args::try_parse_from([
            "passless",
            "agent-admin",
            "credential",
            "delete",
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "--confirm",
        ])
        .unwrap();
        assert!(matches!(
            args.command,
            Some(Commands::AgentAdmin {
                action: AgentAdminAction::Credential {
                    action: AdminCredentialAction::Delete { confirm: true, .. },
                },
                ..
            })
        ));
    }

    #[cfg(feature = "agent")]
    #[test]
    fn test_agent_admin_shutdown_hidden() {
        let args =
            Args::try_parse_from(["passless", "agent-admin", "shutdown", "--confirm"]).unwrap();
        assert!(matches!(
            args.command,
            Some(Commands::AgentAdmin {
                action: AgentAdminAction::Shutdown { confirm: true },
                ..
            })
        ));
    }

    #[cfg(feature = "agent")]
    #[test]
    fn test_agent_admin_output_default_json() {
        let args = Args::try_parse_from(["passless", "agent-admin", "profile", "list"]).unwrap();
        match args.command {
            Some(Commands::AgentAdmin { output, .. }) => {
                assert_eq!(output, OutputFormat::Json);
            }
            _ => panic!("expected AgentAdmin command"),
        }
    }

    #[cfg(feature = "agent")]
    #[test]
    fn test_agent_admin_output_plain() {
        let args = Args::try_parse_from([
            "passless",
            "agent-admin",
            "--output",
            "plain",
            "profile",
            "list",
        ])
        .unwrap();
        match args.command {
            Some(Commands::AgentAdmin { output, .. }) => {
                assert_eq!(output, OutputFormat::Plain);
            }
            _ => panic!("expected AgentAdmin command"),
        }
    }

    #[cfg(feature = "agent")]
    #[test]
    fn test_agent_doctor_parses() {
        let args = Args::try_parse_from(["passless", "agent", "doctor"]).unwrap();
        assert!(matches!(
            args.command,
            Some(Commands::Agent {
                action: AgentCommand::Doctor,
                ..
            })
        ));
    }

    #[cfg(feature = "agent")]
    #[test]
    fn test_agent_run_with_command() {
        let args = Args::try_parse_from([
            "passless",
            "agent",
            "run",
            "--profile",
            "myprofile",
            "--",
            "/usr/bin/test",
            "arg1",
        ])
        .unwrap();
        match args.command {
            Some(Commands::Agent {
                action: AgentCommand::Run { profile, command },
                ..
            }) => {
                assert_eq!(profile, "myprofile");
                assert_eq!(command.len(), 2);
            }
            _ => panic!("expected Agent Run command"),
        }
    }

    #[cfg(feature = "agent")]
    #[test]
    fn test_agent_intent_create_parses() {
        let args = Args::try_parse_from([
            "passless",
            "agent",
            "intent",
            "create",
            "register",
            "--rp",
            "example.com",
        ])
        .unwrap();
        assert!(matches!(
            args.command,
            Some(Commands::Agent {
                action: AgentCommand::Intent {
                    action: AgentIntentAction::Create {
                        action: AgentIntentActionType::Register,
                        ..
                    },
                },
                ..
            })
        ));
    }

    #[cfg(feature = "agent")]
    #[test]
    fn test_agent_output_default_json() {
        let args = Args::try_parse_from(["passless", "agent", "doctor"]).unwrap();
        match args.command {
            Some(Commands::Agent { output, .. }) => {
                assert_eq!(output, OutputFormat::Json);
            }
            _ => panic!("expected Agent command"),
        }
    }

    #[cfg(feature = "agent")]
    #[test]
    fn test_shell_completions_contain_agent_commands() {
        use clap::CommandFactory;

        let cmd = Args::command();
        let mut buf = Vec::new();
        clap_complete::generate(
            clap_complete::Shell::Bash,
            &mut cmd.clone(),
            "passless",
            &mut buf,
        );
        let completion = String::from_utf8(buf).unwrap();

        for expected in [
            "agent-admin",
            "agent",
            "install",
            "browser-control",
            "intent",
            "delegation",
            "doctor",
            "capabilities",
            "instructions",
        ] {
            assert!(
                completion.contains(expected),
                "bash completion missing '{}'",
                expected
            );
        }
    }

    #[cfg(feature = "agent")]
    #[test]
    fn test_shell_completions_zsh_contain_agent_commands() {
        use clap::CommandFactory;

        let cmd = Args::command();
        let mut buf = Vec::new();
        clap_complete::generate(
            clap_complete::Shell::Zsh,
            &mut cmd.clone(),
            "passless",
            &mut buf,
        );
        let completion = String::from_utf8(buf).unwrap();

        for expected in ["agent-admin", "agent", "install", "browser-control"] {
            assert!(
                completion.contains(expected),
                "zsh completion missing '{}'",
                expected
            );
        }
    }

    #[cfg(feature = "agent")]
    #[test]
    fn test_config_print_includes_agent_fields() {
        let mut default_args = Args::parse_from(["passless"]);
        let config = AppConfig::from(&mut default_args.config);
        let toml_output = config.to_toml_with_comments();

        assert!(
            toml_output.contains("backend_type"),
            "config print missing backend_type"
        );
        assert!(
            toml_output.contains("[security]"),
            "config print missing [security] section"
        );
        assert!(
            toml_output.contains("[pin]"),
            "config print missing [pin] section"
        );
        assert!(
            toml_output.contains("always_uv"),
            "config print missing always_uv"
        );
        assert!(
            toml_output.contains("notification_timeout"),
            "config print missing notification_timeout"
        );
    }

    #[test]
    fn test_config_print_contains_passless_header() {
        let mut default_args = Args::parse_from(["passless"]);
        let config = AppConfig::from(&mut default_args.config);
        let toml_output = config.to_toml_with_comments();

        assert!(toml_output.contains("Passless Configuration File"));
        assert!(toml_output.contains("~/.config/passless/config.toml"));
    }

    #[test]
    fn test_config_print_contains_local_backend_section() {
        let mut default_args = Args::parse_from(["passless"]);
        let config = AppConfig::from(&mut default_args.config);
        let toml_output = config.to_toml_with_comments();

        assert!(toml_output.contains("[local]"));
        assert!(toml_output.contains("path"));
    }

    #[test]
    fn test_config_print_contains_pass_backend_section() {
        let mut default_args = Args::parse_from(["passless"]);
        let config = AppConfig::from(&mut default_args.config);
        let toml_output = config.to_toml_with_comments();

        assert!(toml_output.contains("[pass]"));
        assert!(toml_output.contains("store_path"));
        assert!(toml_output.contains("gpg_backend"));
    }
}
