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

    /// Automatically synchronize password-store Git around Passless operations
    #[arg(
        long = "pass-git-sync",
        env = "PASSLESS_PASS_GIT_SYNC",
        action = ArgAction::Set,
        require_equals = true,
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    #[serde(default)]
    #[default(true)]
    pub git_sync: bool,

    /// Automatically push password-store Git commits to the remote (default: true).
    /// When disabled, Git sync still pulls and commits changes locally.
    #[arg(
        long = "pass-git-auto-push",
        env = "PASSLESS_PASS_GIT_AUTO_PUSH",
        action = ArgAction::Set,
        require_equals = true,
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    #[serde(default)]
    #[default(true)]
    pub git_auto_push: bool,
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

    /// Use portable TPM backend with TPM-resident credential keys
    #[arg(long = "tpm-portable", env = "PASSLESS_TPM_PORTABLE")]
    #[serde(default)]
    #[default(false)]
    pub portable: bool,
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

    /// Enable Passless encrypted credential backup/restore vendor commands.
    ///
    /// Also sets the WebAuthn backup-eligibility (BE) flag assigned to newly
    /// registered credentials: `false` (default) marks them single-device
    /// (`BE=0`), `true` marks them backup-eligible (`BE=1`). Existing
    /// credentials are not migrated; they keep the state they were created with.
    ///
    /// Disabled by default because exporting a software credential changes its
    /// security model. TPM and other non-exportable key providers remain
    /// unsupported. Strict relying parties (e.g. Kanidm) reject a credential
    /// whose BE flag changes after registration, so keep this setting stable.
    /// See docs/CREDENTIAL_BACKUP.md.
    #[arg(
        long = "enable-credential-backup",
        env = "PASSLESS_ENABLE_CREDENTIAL_BACKUP",
        action = ArgAction::Set,
        require_equals = true,
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    #[serde(default)]
    pub enable_credential_backup: bool,

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

/// User verification provider type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UvProviderType {
    /// Fingerprint verification via fprintd D-Bus service
    Fprintd,
    /// Face recognition via webcam
    Face,
    /// Desktop notification (fallback)
    Notification,
    /// Custom command/script
    Command,
    /// Use all available providers in priority order
    #[default]
    Auto,
}

impl std::str::FromStr for UvProviderType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "fprintd" | "fingerprint" => Ok(UvProviderType::Fprintd),
            "face" | "faceid" => Ok(UvProviderType::Face),
            "notification" | "notify" => Ok(UvProviderType::Notification),
            "command" | "cmd" => Ok(UvProviderType::Command),
            "auto" | "all" => Ok(UvProviderType::Auto),
            _ => Err(format!(
                "Invalid UV provider '{}'. Must be: fprintd, face, notification, command, or auto",
                s
            )),
        }
    }
}

impl std::fmt::Display for UvProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UvProviderType::Fprintd => write!(f, "fprintd"),
            UvProviderType::Face => write!(f, "face"),
            UvProviderType::Notification => write!(f, "notification"),
            UvProviderType::Command => write!(f, "command"),
            UvProviderType::Auto => write!(f, "auto"),
        }
    }
}

/// fprintd provider configuration
#[derive(ClapSerde, Debug, Clone, Serialize, Deserialize, ConfigDoc)]
#[group(id = "uv-fprintd")]
pub struct FprintdConfig {
    /// Enable fprintd provider
    #[arg(
        long = "fprintd-enabled",
        id = "fprintd-enabled",
        env = "PASSLESS_FPRINTD_ENABLED",
        action = ArgAction::Set,
        require_equals = true,
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    #[serde(default)]
    #[default(true)]
    pub enabled: bool,
}

/// Face recognition provider configuration
#[derive(ClapSerde, Debug, Clone, Serialize, Deserialize, ConfigDoc)]
#[group(id = "uv-face")]
pub struct FaceConfig {
    /// Enable face recognition provider
    #[arg(
        long = "face-enabled",
        id = "face-enabled",
        env = "PASSLESS_FACE_ENABLED",
        action = ArgAction::Set,
        require_equals = true,
        num_args = 0..=1,
        default_missing_value = "true"
    )]
    #[serde(default)]
    #[default(true)]
    pub enabled: bool,

    /// Camera device index (0 = first camera)
    #[arg(
        long = "face-camera-index",
        id = "face-camera-index",
        env = "PASSLESS_FACE_CAMERA_INDEX",
        value_name = "INDEX"
    )]
    #[serde(default)]
    #[default(0)]
    pub camera_index: usize,

    /// Face matching threshold (0.0-1.0, higher = stricter)
    #[arg(
        long = "face-threshold",
        id = "face-threshold",
        env = "PASSLESS_FACE_THRESHOLD",
        value_name = "THRESHOLD"
    )]
    #[serde(default)]
    #[default(0.6)]
    pub threshold: f32,
}

impl FaceConfig {
    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if !self.threshold.is_finite() || self.threshold <= 0.0 || self.threshold > 1.0 {
            return Err(format!(
                "Face threshold must be finite and in (0.0, 1.0], got {}",
                self.threshold
            ));
        }
        Ok(())
    }
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

/// Command provider configuration
#[derive(ClapSerde, Debug, Clone, Serialize, Deserialize, ConfigDoc)]
#[group(id = "uv-cmd")]
pub struct CommandConfig {
    /// Enable command provider
    #[arg(
        long = "uv-command-enabled",
        id = "uv-command-enabled",
        env = "PASSLESS_UV_COMMAND_ENABLED",
        action = ArgAction::Set,
        require_equals = true,
        num_args = 0..=1,
        default_missing_value = "false"
    )]
    #[serde(default)]
    #[default(false)]
    pub enabled: bool,

    /// Command to execute for verification (exit 0 = accept, non-zero = deny)
    /// Command receives context via environment variables:
    /// PASSLESS_UV_OPERATION, PASSLESS_UV_RELYING_PARTY, PASSLESS_UV_USER
    #[arg(
        long = "uv-command",
        id = "uv-command-arg",
        env = "PASSLESS_UV_COMMAND",
        value_name = "COMMAND",
        value_delimiter = ' '
    )]
    #[serde(default)]
    pub command: Vec<String>,
}

/// User verification configuration
#[derive(ClapSerde, Debug, Clone, Serialize, Deserialize, ConfigDoc)]
#[group(id = "uv")]
pub struct UvConfig {
    /// User verification provider selection
    /// - "auto": Use all available providers in priority order (default)
    /// - "fprintd": Fingerprint only
    /// - "face": Face recognition only
    /// - "notification": Desktop notification only
    /// - "command": Custom command only
    #[arg(
        long = "uv-provider",
        env = "PASSLESS_UV_PROVIDER",
        value_name = "PROVIDER"
    )]
    #[serde(default)]
    #[default(UvProviderType::Auto)]
    pub provider: UvProviderType,

    /// Default timeout for verification (seconds)
    #[arg(
        long = "uv-timeout",
        env = "PASSLESS_UV_TIMEOUT",
        value_name = "SECONDS"
    )]
    #[serde(default)]
    #[default(30)]
    pub timeout_seconds: u32,

    /// fprintd configuration
    #[clap_serde]
    #[command(flatten)]
    pub fprintd: FprintdConfig,

    /// Face recognition configuration
    #[clap_serde]
    #[command(flatten)]
    pub face: FaceConfig,

    /// Command provider configuration
    #[clap_serde]
    #[command(flatten)]
    pub command: CommandConfig,
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
    #[command(flatten)]
    pub pass: PassBackendConfig,

    /// TPM backend configuration
    #[cfg(feature = "tpm")]
    #[clap_serde]
    #[command(flatten)]
    pub tpm: TpmBackendConfig,

    /// Local backend configuration
    #[clap_serde]
    #[command(flatten)]
    pub local: LocalBackendConfig,

    /// Security hardening configuration
    #[clap_serde]
    #[command(flatten)]
    pub security: SecurityConfig,

    /// PIN configuration
    #[clap_serde]
    #[command(flatten)]
    pub pin: PinConfig,

    /// User verification configuration
    #[clap_serde]
    #[command(flatten)]
    pub uv: UvConfig,

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
        portable: bool,
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
    /// The configuration file [`Self::load`] reads: `--config`/`PASSLESS_CONFIG`, else the default
    /// `~/.config/passless/config.toml`, if it exists.
    pub fn config_file_path(args: &Args) -> Option<PathBuf> {
        let default_config_path = dirs::config_dir().map(|p| p.join("passless/config.toml"));
        args.config_path
            .clone()
            .or(default_config_path)
            .filter(|p| p.exists())
    }

    /// Load configuration with precedence: CLI > config file > defaults
    pub fn load(args: &mut Args) -> crate::error::Result<Self> {
        let config_file_path = Self::config_file_path(args);

        if let Some(path) = config_file_path.as_ref()
            && let Ok(f) = File::open(path)
        {
            log::info!("Loading configuration from: {}", path.display());
            let content = std::io::read_to_string(BufReader::new(f)).unwrap_or_default();

            #[cfg(feature = "agent")]
            let agent_config = AgentConfig::from_toml_str(&content, &path.display().to_string())?;

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
                portable: self.tpm.portable,
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

    /// Get user verification configuration
    pub fn uv_config(&self) -> UvConfig {
        self.uv.clone()
    }

    /// Everything the daemon checks of the configuration before it starts serving: [`Self::validate`]
    /// and the backend's own validation (`main.rs` runs the same steps one by one, with its own
    /// log messages). Used by `passless config check` and `passless doctor`.
    pub fn check_startup(&self) -> crate::error::Result<()> {
        self.validate()?;
        self.backend()?.validate()
    }

    /// Validate the configuration
    pub fn validate(&self) -> crate::error::Result<()> {
        self.pin.validate()?;
        self.uv
            .face
            .validate()
            .map_err(crate::error::Error::Config)?;
        if self.uv.timeout_seconds == 0 || self.uv.timeout_seconds > 300 {
            return Err(crate::error::Error::Config(
                "uv.timeout_seconds must be between 1 and 300".into(),
            ));
        }
        match self.uv.provider {
            UvProviderType::Fprintd if !self.uv.fprintd.enabled => {
                return Err(crate::error::Error::Config(
                    "uv.provider=fprintd requires uv.fprintd.enabled=true".into(),
                ));
            }
            UvProviderType::Face if !self.uv.face.enabled => {
                return Err(crate::error::Error::Config(
                    "uv.provider=face requires uv.face.enabled=true".into(),
                ));
            }
            UvProviderType::Command
                if !self.uv.command.enabled || self.uv.command.command.is_empty() =>
            {
                return Err(crate::error::Error::Config(
                    "uv.provider=command requires an enabled non-empty trusted command".into(),
                ));
            }
            _ => {}
        }
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
    /// Manage experimental face enrollment and test matching locally
    Uv {
        #[command(subcommand)]
        action: UvAction,
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
    /// Check this host (does not need a running daemon)
    #[cfg(feature = "agent")]
    Doctor {
        /// Check the agent browser path: a supported browser binary, the interception extension,
        /// the native messaging host manifest, the notification bus, the state directory and the
        /// containment of the native WebAuthn path
        #[arg(long)]
        agents: bool,

        /// Output format: plain (default) or json
        #[arg(
            short = 'o',
            long = "output",
            value_name = "FORMAT",
            default_value = "plain"
        )]
        output: OutputFormat,
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
    /// TPM portable parent management
    #[cfg(feature = "tpm")]
    Tpm {
        #[command(subcommand)]
        action: TpmAction,
    },
}

/// Experimental face operations. These do not imply presentation-attack detection.
#[derive(Subcommand, Debug, Clone)]
pub enum UvAction {
    /// Enroll five face samples; requires a build with the face feature
    FaceEnroll {
        #[arg(long, default_value_t = 0)]
        camera_index: usize,
        #[arg(long, default_value_t = 0.6)]
        threshold: f32,
    },
    /// Exercise face matching on the local webcam; not a FIDO UV assurance check
    FaceVerify {
        #[arg(long, default_value_t = 0)]
        camera_index: usize,
        #[arg(long, default_value_t = 0.6)]
        threshold: f32,
    },
    /// Show whether a local face template exists
    FaceStatus,
}

/// TPM portable parent actions
#[cfg(feature = "tpm")]
#[derive(Subcommand, Debug, Clone)]
pub enum TpmAction {
    /// Provision the portable TPM parent from a recovery seed
    #[command(group(clap::ArgGroup::new("seed-source").args(["generate", "seed_file", "seed_stdin"])))]
    Provision {
        /// Generate a new random 32-byte recovery seed and print it
        #[arg(long)]
        generate: bool,
        /// Read the recovery seed (hex) from this file instead of prompting
        #[arg(long = "seed-file", value_name = "PATH")]
        seed_file: Option<PathBuf>,
        /// Read the recovery seed (hex) from stdin instead of prompting
        #[arg(long = "seed-stdin")]
        seed_stdin: bool,
        /// TPM storage directory
        #[arg(long = "tpm-path", env = "PASSLESS_TPM_PATH")]
        path: Option<String>,
        /// TPM TCTI configuration
        #[arg(long = "tpm-tcti", env = "PASSLESS_TPM_TCTI")]
        tcti: Option<String>,
    },
    /// Show provisioning status
    Status {
        /// TPM storage directory
        #[arg(long = "tpm-path", env = "PASSLESS_TPM_PATH")]
        path: Option<String>,
        /// TPM TCTI configuration
        #[arg(long = "tpm-tcti", env = "PASSLESS_TPM_TCTI")]
        tcti: Option<String>,
    },
    /// Remove the provisioned portable parent
    Remove {
        /// Confirm the removal
        #[arg(long)]
        confirm: bool,
        /// TPM storage directory
        #[arg(long = "tpm-path", env = "PASSLESS_TPM_PATH")]
        path: Option<String>,
        /// TPM TCTI configuration
        #[arg(long = "tpm-tcti", env = "PASSLESS_TPM_TCTI")]
        tcti: Option<String>,
    },
    /// Migrate legacy sealed credentials to portable TPM format
    #[command(group(clap::ArgGroup::new("selection").args(["credential_id", "all"]).required(true)))]
    Migrate {
        /// Migrate a specific credential by ID (hex)
        #[arg(long = "credential-id", value_name = "ID")]
        credential_id: Option<String>,
        /// Migrate all migratable legacy credentials
        #[arg(long)]
        all: bool,
        /// Show what would be migrated without making changes
        #[arg(long)]
        dry_run: bool,
        /// Directory to store backups of legacy records
        #[arg(long = "backup-dir", value_name = "PATH")]
        backup_dir: Option<String>,
        /// TPM storage directory
        #[arg(long = "tpm-path", env = "PASSLESS_TPM_PATH")]
        path: Option<String>,
        /// TPM TCTI configuration
        #[arg(long = "tpm-tcti", env = "PASSLESS_TPM_TCTI")]
        tcti: Option<String>,
    },
}

/// Configuration actions
#[derive(Subcommand, Debug, Clone)]
pub enum ConfigAction {
    /// Print the default configuration in TOML format
    Print,
    /// Validate the configuration offline, as the daemon would at startup
    ///
    /// Loads the file like the daemon does (CLI flags and file merged, agent profiles parsed) and
    /// runs the daemon's validation, including the agent profile rules and deprecation warnings.
    /// Prints the warnings and exits non-zero on an error. It needs no running daemon, D-Bus or
    /// UHID: run it before restarting the service.
    Check {
        /// Configuration file to check (default: `PASSLESS_CONFIG`, else
        /// `~/.config/passless/config.toml`)
        #[arg(short = 'c', long, value_name = "PATH")]
        config_path: Option<PathBuf>,
    },
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
    /// Persistent granted rules (escalation approvals)
    Grants {
        #[command(subcommand)]
        action: AdminGrantsAction,
    },
    /// Browser bearer sessions (session grants)
    #[command(alias = "delegation")]
    Sessions {
        #[command(subcommand)]
        action: AdminSessionsAction,
    },
    /// Principal sessions
    #[command(alias = "session")]
    Principals {
        #[command(subcommand)]
        action: AdminPrincipalsAction,
    },
    /// Browser session management
    Browser {
        #[command(subcommand)]
        action: AdminBrowserAction,
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

/// Admin granted-rule actions (ADR 0014 section 8.4)
#[cfg(feature = "agent")]
#[derive(Subcommand, Debug, Clone)]
pub enum AdminGrantsAction {
    /// List granted rules
    List {
        /// Filter by profile
        #[arg(long, value_name = "PROFILE")]
        profile: Option<String>,
    },
    /// Revoke the granted rule of one RP
    Revoke {
        /// Profile identifier
        #[arg(long, value_name = "PROFILE")]
        profile: String,
        /// Relying party ID
        #[arg(long = "rp", value_name = "RP_ID")]
        rp_id: String,
        /// Action of the granted rule
        #[arg(long, value_enum, default_value_t = AdminGrantAction::Authenticate)]
        action: AdminGrantAction,
        /// Confirm the revocation
        #[arg(long)]
        confirm: bool,
    },
    /// Revoke every granted rule of a profile
    Clear {
        /// Profile identifier
        #[arg(long, value_name = "PROFILE")]
        profile: String,
        /// Confirm the revocation
        #[arg(long)]
        confirm: bool,
    },
}

/// Action of a granted rule (only `authenticate` is ever granted)
#[cfg(feature = "agent")]
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminGrantAction {
    Authenticate,
}

/// Admin browser bearer session actions
#[cfg(feature = "agent")]
#[derive(Subcommand, Debug, Clone)]
pub enum AdminSessionsAction {
    /// Show session grant details
    Show {
        /// Grant identifier (hex)
        #[arg(value_name = "GRANT_ID")]
        grant_id: String,
    },
    /// List all session grants
    List {
        /// Filter by profile
        #[arg(long, value_name = "PROFILE")]
        profile: Option<String>,
    },
    /// Revoke a session grant
    Revoke {
        /// Grant identifier (hex)
        #[arg(value_name = "GRANT_ID")]
        grant_id: String,
        /// Confirm the revocation
        #[arg(long)]
        confirm: bool,
    },
}

/// Admin principal session actions
#[cfg(feature = "agent")]
#[derive(Subcommand, Debug, Clone)]
pub enum AdminPrincipalsAction {
    /// Show principal session details
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

/// Admin browser actions
#[cfg(feature = "agent")]
#[derive(Subcommand, Debug, Clone)]
pub enum AdminBrowserAction {
    /// Launch a browser session with the agent extension
    Launch {
        /// Profile identifier
        #[arg(long, value_name = "PROFILE")]
        profile: String,
        /// Start URL to open in the browser
        #[arg(long, value_name = "URL")]
        url: Option<String>,
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
    /// Change the stored credProtect level of credentials (requires user verification)
    ///
    /// Levels: 1 = user verification optional (presence only), 2 = optional with a credential
    /// ID list, 3 = user verification required. The credentials are shown first; lowering asks
    /// for confirmation unless --yes is given, and the authenticator asks for the PIN or, with
    /// no PIN set, shows its own prompt naming what is lowered.
    ///
    /// WARNING: lowering weakens the credentials. With
    /// security.user_verification_authentication = false, level 1 means silent signing by any
    /// process that can reach the authenticator's hidraw device. Lowering has no effect while
    /// security.always_uv = true, because the authenticator then forces user verification
    /// whatever the level. After an error, check the result with `passless client list`.
    SetCredProtect {
        /// Credential ID in hexadecimal format
        #[arg(
            long = "id",
            value_name = "CREDENTIAL_ID",
            conflicts_with = "rp_id",
            required_unless_present = "rp_id"
        )]
        credential_id: Option<String>,
        /// Apply to every credential of this relying party ID (e.g. `ssh:`)
        #[arg(long = "rp", value_name = "RP_ID")]
        rp_id: Option<String>,
        /// New credProtect level (1, 2 or 3)
        #[arg(long, value_name = "LEVEL", value_parser = clap::value_parser!(u8).range(1..=3))]
        level: u8,
        /// Do not ask for confirmation before changing every credential of --rp
        #[arg(long)]
        yes: bool,
    },
    /// Export one software-backed credential as an opaque encrypted bundle.
    Backup {
        /// Credential ID in hexadecimal format
        #[arg(value_name = "CREDENTIAL_ID")]
        credential_id: String,
        /// Authenticator-local credential-backup wrapping-key identifier
        #[arg(long, value_name = "RECIPIENT")]
        recipient: String,
        /// Destination bundle path
        #[arg(long, value_name = "PATH")]
        output_file: PathBuf,
        /// Explicitly acknowledge that a passkey is being exported
        #[arg(long = "yes-i-understand-this-exports-a-passkey")]
        confirm: bool,
    },
    /// Restore an encrypted Passless credential bundle.
    Restore {
        /// Source bundle path
        #[arg(value_name = "PATH")]
        input_file: PathBuf,
        /// Replace a credential with the same ID
        #[arg(long)]
        replace: bool,
        /// Explicitly acknowledge that a passkey is being restored
        #[arg(long = "yes-i-understand-this-restores-a-passkey")]
        confirm: bool,
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
    /// Show the profile's effective authority (per-RP rules, credential scope, session limits)
    Capabilities,
    /// Show principal instructions
    Instructions,
    /// Credential queries
    Credential {
        #[command(subcommand)]
        action: AgentCredentialAction,
    },
    /// Show browser bridge status
    BrowserStatus,
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
    /// Ensure the managed browser of this principal and print how to reach it
    ///
    /// Idempotent: the browser is started on the first call and the same endpoint is printed
    /// while it runs (the profile's `browser_scope` decides whether sessions share it). The
    /// endpoint is withheld until the interception extension is attached and allowed in
    /// incognito, so a printed endpoint is always an intercepted browser. With
    /// `browser_cdp_expose = "port"` the CDP endpoint is printed. In pipe mode (the default)
    /// there is no endpoint: the browser is ensured and CDP goes through
    /// `passless agent browser-control`. It must run inside a principal session of the profile
    /// (the browser is closed when that session ends), e.g. an agent started with
    /// `passless agent run --profile P -- <command>`.
    Browser {
        /// Print JSON ({endpoint, ...}) instead of the bare endpoint URL
        #[arg(long, conflicts_with = "env")]
        json: bool,
        /// Print `PASSLESS_CDP_URL=<endpoint>`, for `eval` or a dotenv file
        #[arg(long)]
        env: bool,
        /// Block until the browser is intercepting (attached, incognito allowed) before printing
        #[arg(long)]
        wait: bool,
        /// Start a headed browser instead of the default `--headless=new`
        #[arg(long)]
        headed: bool,
        /// Open this URL once interception is attached
        #[arg(long, value_name = "URL")]
        url: Option<String>,
    },
    /// MCP server adapters for the managed browser (stdio launchers)
    #[command(args_conflicts_with_subcommands = true)]
    Mcp {
        /// Print a ready-to-paste MCP server entry for a client instead of running a server
        #[arg(long, value_enum, value_name = "CLIENT")]
        print_config: Option<McpConfigTarget>,
        /// The adapter the printed entry runs
        #[arg(long, value_enum, default_value_t = McpAdapterKind::Playwright, requires = "print_config")]
        server: McpAdapterKind,
        #[command(subcommand)]
        adapter: Option<McpAdapter>,
    },
    /// Run Playwright MCP with lazy access to the profile's trusted CDP browser
    ///
    /// Deprecated alias of `agent mcp playwright`, kept for one release.
    #[command(hide = true)]
    PlaywrightMcp {
        /// Profile to bind the Playwright session to
        #[arg(long, value_name = "PROFILE")]
        profile: String,
        /// Start URL to open in the managed browser
        #[arg(long, value_name = "URL")]
        url: Option<String>,
        /// Absolute Playwright MCP executable and arguments
        #[arg(last = true, required = true)]
        command: Vec<std::path::PathBuf>,
    },
    /// Internal: the principal-session side of `agent mcp playwright`
    ///
    /// Started by `agent mcp playwright` through the admin socket, never by hand. It holds the
    /// principal session's capability descriptor and answers one request on its stdin, "ensure
    /// the browser", with the CDP endpoint. It exits when its stdin closes.
    #[command(hide = true)]
    McpSessionBroker {
        /// Profile of the principal session
        #[arg(long, value_name = "PROFILE")]
        profile: String,
        /// Start URL to open in the managed browser
        #[arg(long, value_name = "URL")]
        url: Option<String>,
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

/// An MCP server the adapters run against the managed browser.
#[cfg(feature = "agent")]
#[derive(Subcommand, Debug, Clone)]
pub enum McpAdapter {
    /// Run `npx @playwright/mcp --cdp-endpoint <url>` (the endpoint is resolved on first use)
    Playwright {
        /// npm package to run (default `@playwright/mcp`; pin a version here)
        #[arg(long, value_name = "SPEC")]
        package: Option<String>,
        /// npx executable (default: `npx` from PATH)
        #[arg(long, value_name = "PATH")]
        npx: Option<std::path::PathBuf>,
        /// Open this URL once interception is attached
        #[arg(long, value_name = "URL")]
        url: Option<String>,
        /// Print a ready-to-paste MCP server entry for a client instead of running the server
        #[arg(long, value_enum, value_name = "CLIENT")]
        print_config: Option<McpConfigTarget>,
        /// Extra arguments for @playwright/mcp (after `--`)
        #[arg(last = true)]
        extra: Vec<String>,
    },
    /// Run `npx chrome-devtools-mcp --browserUrl <url>`
    ///
    /// The browser starts when the server starts: puppeteer asks `<browserUrl>/json/version`
    /// at the root of the URL and cannot send the bootstrap's bearer header, so a lazy,
    /// authenticated discovery endpoint is not possible.
    ChromeDevtools {
        /// npm package to run (default `chrome-devtools-mcp`; pin a version here)
        #[arg(long, value_name = "SPEC")]
        package: Option<String>,
        /// npx executable (default: `npx` from PATH)
        #[arg(long, value_name = "PATH")]
        npx: Option<std::path::PathBuf>,
        /// Open this URL once interception is attached
        #[arg(long, value_name = "URL")]
        url: Option<String>,
        /// Print a ready-to-paste MCP server entry for a client instead of running the server
        #[arg(long, value_enum, value_name = "CLIENT")]
        print_config: Option<McpConfigTarget>,
        /// Extra arguments for chrome-devtools-mcp (after `--`)
        #[arg(last = true)]
        extra: Vec<String>,
    },
    /// Rewrite plain Playwright MCP / chrome-devtools-mcp entries of a client to run through Passless
    ///
    /// Finds entries that start their own browser (`npx @playwright/mcp`, `pnpm dlx`, `bunx`,
    /// `yarn dlx`, a `playwright-mcp` binary, `chrome-devtools-mcp`) in the client's MCP
    /// configuration and rewrites each in place to `passless agent mcp playwright|chrome-devtools`,
    /// so the agent keeps its tools and passkeys go through the managed browser and the profile's
    /// rules. A file with no such entry gets a new `playwright` server that runs through Passless
    /// (a file that does not exist is created; a different server named `playwright` is never
    /// replaced). With `--user` on Claude Code, entries kept per project by `claude mcp add`
    /// (local scope, in `projects.<path>.mcpServers`) are rewritten too. The default is a dry run
    /// that prints a diff; `--yes` writes, after saving a backup.
    /// The profile is the global `--profile`: required unless exactly one usable profile (with
    /// `browser_cdp_expose = "port"`) is configured.
    Install {
        /// The MCP client whose configuration to change
        #[arg(long, value_enum, value_name = "CLIENT")]
        client: McpInstallClient,
        /// Change the client's user-level configuration (the default)
        #[arg(long, conflicts_with = "project")]
        user: bool,
        /// Change the configuration of this project directory instead
        #[arg(long, value_name = "DIR", conflicts_with = "user")]
        project: Option<std::path::PathBuf>,
        /// Write the change (after saving `<file>.passless-backup-<UTC timestamp>`); without it,
        /// print the diff only
        #[arg(long)]
        yes: bool,
        /// Also install or refresh the bundled `passless-agent` skill for the client
        #[arg(long)]
        skill: bool,
        /// The `passless` the entries run (absolute path). Default: the first `passless` on
        /// `PATH`, else this executable
        #[arg(long, value_name = "ABS")]
        passless_path: Option<std::path::PathBuf>,
    },
}

/// Which adapter `agent mcp --print-config` prints an entry for.
#[cfg(feature = "agent")]
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpAdapterKind {
    Playwright,
    ChromeDevtools,
}

/// MCP clients `agent mcp install` can rewrite the configuration of.
#[cfg(feature = "agent")]
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpInstallClient {
    /// `opencode.json` (`mcp.servers.<name>`, or the legacy `mcp.<name>`)
    Opencode,
    /// `~/.claude.json` (`$CLAUDE_CONFIG_DIR/.claude.json`) and `.mcp.json`: `mcpServers.<name>`
    ClaudeCode,
}

/// MCP clients `agent mcp --print-config` knows the configuration format of.
#[cfg(feature = "agent")]
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpConfigTarget {
    /// `.mcp.json` / `claude mcp add-json`
    ClaudeCode,
    /// `opencode.json`
    Opencode,
    /// `.cursor/mcp.json`
    Cursor,
    /// `.vscode/mcp.json`
    Vscode,
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
    fn test_invalid_uv_timeout_and_command_config() {
        let mut cfg = AppConfig::from(&mut Args::parse_from(["passless"]).config);
        cfg.uv.timeout_seconds = 0;
        assert!(cfg.validate().is_err());
        cfg.uv.timeout_seconds = 301;
        assert!(cfg.validate().is_err());
        cfg.uv.timeout_seconds = 30;
        cfg.uv.provider = UvProviderType::Command;
        cfg.uv.command.enabled = true;
        cfg.uv.command.command.clear();
        assert!(cfg.validate().is_err());
        cfg.uv.command.command = vec!["/usr/bin/true".into()];
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_face_threshold_rejects_nonfinite_and_zero() {
        let mut cfg = FaceConfig {
            enabled: true,
            camera_index: 0,
            threshold: 0.6,
        };
        for value in [0.0, -0.1, f32::NAN, f32::INFINITY, f32::NEG_INFINITY, 1.1] {
            cfg.threshold = value;
            assert!(
                cfg.validate().is_err(),
                "value {} should be rejected",
                value
            );
        }
        cfg.threshold = 0.6;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_uv_face_cli_commands_parse() {
        let args =
            Args::try_parse_from(["passless", "uv", "face-enroll", "--camera-index", "1"]).unwrap();
        assert!(matches!(
            args.command,
            Some(Commands::Uv {
                action: UvAction::FaceEnroll {
                    camera_index: 1,
                    ..
                }
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
    fn test_agent_browser_parses() {
        let args = Args::try_parse_from([
            "passless",
            "agent",
            "--profile",
            "p",
            "browser",
            "--json",
            "--wait",
            "--headed",
        ])
        .unwrap();
        let Some(Commands::Agent {
            profile,
            action:
                AgentCommand::Browser {
                    json,
                    env,
                    wait,
                    headed,
                    url,
                },
            ..
        }) = args.command
        else {
            panic!("not agent browser");
        };
        assert_eq!(profile.as_deref(), Some("p"));
        assert!(json && wait && headed && !env && url.is_none());
        // `--profile` after the subcommand works too (it is global), and `--json` excludes `--env`.
        let args =
            Args::try_parse_from(["passless", "agent", "browser", "--env", "--profile", "p"])
                .unwrap();
        assert!(matches!(
            args.command,
            Some(Commands::Agent {
                action: AgentCommand::Browser { env: true, .. },
                ..
            })
        ));
        assert!(Args::try_parse_from(["passless", "agent", "browser", "--json", "--env"]).is_err());
    }

    #[cfg(feature = "agent")]
    #[test]
    fn test_agent_mcp_parses() {
        let args = Args::try_parse_from([
            "passless",
            "agent",
            "mcp",
            "playwright",
            "--profile",
            "p",
            "--",
            "--isolated",
        ])
        .unwrap();
        let Some(Commands::Agent {
            action:
                AgentCommand::Mcp {
                    adapter: Some(McpAdapter::Playwright { extra, .. }),
                    print_config: None,
                    ..
                },
            profile,
            ..
        }) = args.command
        else {
            panic!("not agent mcp playwright");
        };
        assert_eq!(profile.as_deref(), Some("p"));
        assert_eq!(extra, ["--isolated"]);

        let args = Args::try_parse_from(["passless", "agent", "mcp", "chrome-devtools"]).unwrap();
        assert!(matches!(
            args.command,
            Some(Commands::Agent {
                action: AgentCommand::Mcp {
                    adapter: Some(McpAdapter::ChromeDevtools { .. }),
                    ..
                },
                ..
            })
        ));

        for (name, target) in [
            ("claude-code", McpConfigTarget::ClaudeCode),
            ("opencode", McpConfigTarget::Opencode),
            ("cursor", McpConfigTarget::Cursor),
            ("vscode", McpConfigTarget::Vscode),
        ] {
            let args = Args::try_parse_from([
                "passless",
                "agent",
                "--profile",
                "p",
                "mcp",
                "--print-config",
                name,
            ])
            .unwrap();
            assert!(matches!(
                args.command,
                Some(Commands::Agent {
                    action: AgentCommand::Mcp { print_config: Some(t), adapter: None, .. },
                    ..
                }) if t == target
            ));
        }
        assert!(
            Args::try_parse_from(["passless", "agent", "mcp", "--print-config", "emacs"]).is_err()
        );
        // The same flag on the adapter subcommand, with `--profile` after it.
        let args = Args::try_parse_from([
            "passless",
            "agent",
            "mcp",
            "playwright",
            "--profile",
            "coding",
            "--print-config",
            "claude-code",
        ])
        .unwrap();
        assert!(matches!(
            args.command,
            Some(Commands::Agent {
                profile: Some(ref profile),
                action: AgentCommand::Mcp {
                    print_config: None,
                    adapter: Some(McpAdapter::Playwright {
                        print_config: Some(McpConfigTarget::ClaudeCode),
                        ..
                    }),
                    ..
                },
                ..
            }) if profile == "coding"
        ));
        assert!(
            Args::try_parse_from([
                "passless",
                "agent",
                "mcp",
                "chrome-devtools",
                "--print-config",
                "opencode",
            ])
            .is_ok()
        );
        // The old name still parses (hidden alias, one release).
        assert!(
            Args::try_parse_from([
                "passless",
                "agent",
                "playwright-mcp",
                "--profile",
                "p",
                "--",
                "/usr/bin/npx",
                "x",
            ])
            .is_ok()
        );
    }

    #[cfg(feature = "agent")]
    #[test]
    fn test_agent_mcp_install_parses() {
        let parse = |extra: &[&str]| {
            let mut argv = vec!["passless", "agent", "mcp", "install"];
            argv.extend_from_slice(extra);
            Args::try_parse_from(argv)
        };
        // The client is required; everything else is optional and the default is a dry run.
        assert!(parse(&[]).is_err());
        assert!(parse(&["--client", "emacs"]).is_err());
        let args = parse(&["--client", "opencode"]).unwrap();
        assert!(matches!(
            args.command,
            Some(Commands::Agent {
                profile: None,
                action: AgentCommand::Mcp {
                    adapter: Some(McpAdapter::Install {
                        client: McpInstallClient::Opencode,
                        user: false,
                        project: None,
                        yes: false,
                        skill: false,
                        passless_path: None,
                    }),
                    ..
                },
                ..
            })
        ));
        let args = parse(&[
            "--client",
            "claude-code",
            "--project",
            "/work/p",
            "--profile",
            "agent",
            "--yes",
            "--skill",
        ])
        .unwrap();
        match args.command {
            Some(Commands::Agent {
                profile,
                action:
                    AgentCommand::Mcp {
                        adapter:
                            Some(McpAdapter::Install {
                                client,
                                project,
                                yes,
                                skill,
                                ..
                            }),
                        ..
                    },
                ..
            }) => {
                assert_eq!(profile.as_deref(), Some("agent"));
                assert_eq!(client, McpInstallClient::ClaudeCode);
                assert_eq!(project, Some(std::path::PathBuf::from("/work/p")));
                assert!(yes && skill);
            }
            other => panic!("unexpected: {other:?}"),
        }
        // `--user` and `--project` exclude each other.
        assert!(parse(&["--client", "opencode", "--user", "--project", "/p"]).is_err());
        assert!(parse(&["--client", "opencode", "--user"]).is_ok());
        let args = parse(&[
            "--client",
            "opencode",
            "--passless-path",
            "/usr/bin/passless",
        ])
        .unwrap();
        assert!(matches!(
            args.command,
            Some(Commands::Agent {
                action: AgentCommand::Mcp {
                    adapter: Some(McpAdapter::Install { passless_path: Some(ref p), .. }),
                    ..
                },
                ..
            }) if p == std::path::Path::new("/usr/bin/passless")
        ));
    }

    #[cfg(feature = "agent")]
    #[test]
    fn test_doctor_agents_parses() {
        let args = Args::try_parse_from(["passless", "doctor", "--agents", "-o", "json"]).unwrap();
        assert!(matches!(
            args.command,
            Some(Commands::Doctor {
                agents: true,
                output: OutputFormat::Json
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
    fn test_agent_admin_grants_parse() {
        let args = Args::try_parse_from([
            "passless",
            "agent-admin",
            "grants",
            "revoke",
            "--profile",
            "coding",
            "--rp",
            "example.com",
            "--confirm",
        ])
        .unwrap();
        assert!(matches!(
            args.command,
            Some(Commands::AgentAdmin {
                action: AgentAdminAction::Grants {
                    action: AdminGrantsAction::Revoke {
                        ref profile,
                        ref rp_id,
                        action: AdminGrantAction::Authenticate,
                        confirm: true,
                    },
                },
                ..
            }) if profile == "coding" && rp_id == "example.com"
        ));
        let args = Args::try_parse_from([
            "passless",
            "agent-admin",
            "grants",
            "clear",
            "--profile",
            "p",
        ])
        .unwrap();
        assert!(matches!(
            args.command,
            Some(Commands::AgentAdmin {
                action: AgentAdminAction::Grants {
                    action: AdminGrantsAction::Clear { confirm: false, .. },
                },
                ..
            })
        ));
        assert!(Args::try_parse_from(["passless", "agent-admin", "grants", "list"]).is_ok());
    }

    #[cfg(feature = "agent")]
    #[test]
    fn test_agent_admin_renamed_session_commands_keep_hidden_aliases() {
        for (spelling, expect_sessions) in [
            ("sessions", true),
            ("delegation", true),
            ("principals", false),
            ("session", false),
        ] {
            let args = Args::try_parse_from(["passless", "agent-admin", spelling, "list"]).unwrap();
            let is_sessions = matches!(
                args.command,
                Some(Commands::AgentAdmin {
                    action: AgentAdminAction::Sessions { .. },
                    ..
                })
            );
            let is_principals = matches!(
                args.command,
                Some(Commands::AgentAdmin {
                    action: AgentAdminAction::Principals { .. },
                    ..
                })
            );
            assert_eq!(is_sessions, expect_sessions, "{spelling}");
            assert_eq!(is_principals, !expect_sessions, "{spelling}");
        }
        assert!(Args::try_parse_from(["passless", "agent", "intent", "show", "x"]).is_err());
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
            "grants",
            "sessions",
            "principals",
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

    #[test]
    fn test_config_print_produces_valid_toml_without_none_literals() {
        let mut default_args = Args::parse_from(["passless"]);
        let config = AppConfig::from(&mut default_args.config);
        let toml_output = config.to_toml_with_comments();

        for (line_no, line) in toml_output.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }
            assert!(
                !trimmed.contains("= None"),
                "Line {} contains invalid TOML 'None' literal: {}",
                line_no + 1,
                line
            );
        }

        let parse_result: Result<toml::Table, _> = toml_output.parse();
        assert!(
            parse_result.is_ok(),
            "Generated TOML is not valid: {:?}",
            parse_result.err()
        );
    }

    #[cfg(feature = "agent")]
    #[test]
    fn test_config_print_comments_out_none_option_fields() {
        let mut default_args = Args::parse_from(["passless"]);
        let config = AppConfig::from(&mut default_args.config);
        let toml_output = config.to_toml_with_comments();

        assert!(
            toml_output.contains("# audit_path = <not set>"),
            "Option::None field 'audit_path' should be commented out, got:\n{}",
            toml_output
        );
    }
}
