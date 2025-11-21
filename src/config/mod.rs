//! Application configuration
//!
//! This module defines the configuration for the authenticator.

pub mod defaults;

use std::fs;
use std::path::Path;

use clap::Args;
use libc::{MCL_CURRENT, MCL_FUTURE, PR_SET_DUMPABLE, mlockall, prctl};
use log::debug;
use nix::sys::resource::{Resource, setrlimit};
use serde::{Deserialize, Serialize};

/// Security hardening configuration
#[derive(Debug, Clone, Serialize, Deserialize, Args, Default)]
#[group(id = "security")]
pub struct SecurityConfig {
    /// Use mlock to prevent credentials from being swapped to disk
    /// Requires CAP_IPC_LOCK capability or running as root
    #[arg(
        long = "use-mlock",
        env = "PASSLESS_USE_MLOCK",
        help = "Lock credential memory to prevent swapping to disk (requires CAP_IPC_LOCK)"
    )]
    #[serde(default)]
    pub use_mlock: Option<bool>,

    /// Disable core dumps to prevent credential leakage
    #[arg(
        long = "disable-core-dumps",
        env = "PASSLESS_DISABLE_CORE_DUMPS",
        help = "Disable core dumps to prevent credential leakage in crash dumps"
    )]
    #[serde(default)]
    pub disable_core_dumps: Option<bool>,

    /// Enable constant signature counter helps RPs (relying parties) detect cloned or duplicated
    /// authenticators
    #[arg(
        long = "constant-signature-counter",
        env = "PASSLESS_CONSTANT_SIGNATURE_COUNTER",
        help = "Enable constant signature counter to help RPs detect cloned or duplicated authenticators"
    )]
    #[serde(default)]
    pub constant_signature_counter: Option<bool>,

    /// Enable user verification notification for registration
    #[arg(
        long = "user-verification-registration",
        env = "PASSLESS_USER_VERIFICATION_REGISTRATION",
        help = "Show user verification notification during registration"
    )]
    #[serde(default)]
    pub user_verification_registration: Option<bool>,

    /// Enable user verification notification for authentication
    #[arg(
        long = "user-verification-authentication",
        env = "PASSLESS_USER_VERIFICATION_AUTHENTICATION",
        help = "Show user verification notification during authentication"
    )]
    #[serde(default)]
    pub user_verification_authentication: Option<bool>,
}

/// Security hardening functions
impl SecurityConfig {
    /// Apply all enabled security hardening measures
    pub fn apply_hardening(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self
            .disable_core_dumps
            .unwrap_or(defaults::SECURITY_DISABLE_CORE_DUMPS)
        {
            self.disable_core_dumps_impl()?;
        }
        if self.use_mlock.unwrap_or(defaults::SECURITY_USE_MLOCK) {
            self.lock_all_memory()?;
        }
        Ok(())
    }

    /// Disable core dumps to prevent credential leakage
    fn disable_core_dumps_impl(&self) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Disabling core dumps to prevent credential leakage");
        // setrlimit(RLIMIT_CORE, 0)
        setrlimit(Resource::RLIMIT_CORE, 0, 0)?;
        // prctl(PR_SET_DUMPABLE, 0)
        let r = unsafe { prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if r != 0 {
            log::warn!("prctl(PR_SET_DUMPABLE) failed: {}", r);
        }
        Ok(())
    }

    /// Lock all current and future memory mappings to prevent swapping
    fn lock_all_memory(&self) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Locking all memory to prevent swapping");
        // Try to lock current and future mappings into RAM
        let r = unsafe { mlockall(MCL_CURRENT | MCL_FUTURE) };
        if r != 0 {
            // EINVAL, EPERM, ENOMEM possible. Treat as warning: mlockall often requires capabilities or raising RLIMIT_MEMLOCK.
            return Err(format!(
                "mlockall failed (errno {}). Consider increasing RLIMIT_MEMLOCK.\n\
                 Hint: grant CAP_IPC_LOCK to the binary with: 'sudo setcap cap_ipc_lock=+ep $(which passless)'",
                std::io::Error::last_os_error()
            ).into());
        }
        Ok(())
    }
}

/// Local storage backend configuration
#[derive(Debug, Clone, Serialize, Deserialize, Args, Default)]
#[group(id = "local")]
pub struct LocalBackendConfig {
    /// Path to storage directory
    #[arg(
        long = "local-path",
        env = "PASSLESS_LOCAL_PATH",
        id = "local.path",
        value_name = "PATH"
    )]
    #[serde(default)]
    pub path: Option<String>,
}

/// Pass (password-store) backend configuration
#[derive(Debug, Clone, Serialize, Deserialize, Args, Default)]
#[group(id = "pass")]
pub struct PassBackendConfig {
    /// Path to password store directory
    #[arg(
        long = "pass-store-path",
        env = "PASSLESS_PASS_STORE_PATH",
        id = "pass.store_path",
        value_name = "PATH"
    )]
    #[serde(default)]
    pub store_path: Option<String>,

    /// Relative dir to password store directory for FIDO2 entries
    #[arg(
        long = "pass-path",
        env = "PASSLESS_PASS_PATH",
        id = "pass.path",
        value_name = "PATH"
    )]
    #[serde(default)]
    pub path: Option<String>,

    /// GPG backend: "gpgme" or "gnupg-bin"
    #[arg(
        long = "pass-gpg-backend",
        env = "PASSLESS_PASS_GPG_BACKEND",
        id = "pass.gpg_backend",
        value_name = "BACKEND"
    )]
    #[serde(default)]
    pub gpg_backend: Option<String>,
}

/// TPM (Trusted Platform Module) backend configuration
#[derive(Debug, Clone, Serialize, Deserialize, Args, Default)]
#[group(id = "tpm")]
pub struct TpmBackendConfig {
    /// Path to TPM storage directory
    #[arg(
        long = "tpm-path",
        env = "PASSLESS_TPM_PATH",
        id = "tpm.path",
        value_name = "PATH"
    )]
    #[serde(default)]
    pub path: Option<String>,

    /// TPM TCTI (TPM Command Transmission Interface) configuration
    /// Examples: "device:/dev/tpm0", "device:/dev/tpmrm0", "tabrmd:", "swtpm:"
    #[arg(
        long = "tpm-tcti",
        env = "PASSLESS_TPM_TCTI",
        id = "tpm.tcti",
        value_name = "TCTI"
    )]
    #[serde(default)]
    pub tcti: Option<String>,
}

/// Storage backend configuration (type-safe enum)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BackendConfig {
    /// Local file system storage
    Local(LocalBackendConfig),
    /// Pass (password-store) backend
    Pass(PassBackendConfig),
    /// TPM (Trusted Platform Module) backend
    Tpm(TpmBackendConfig),
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self::Local(LocalBackendConfig::default())
    }
}

/// Application-level configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Backend type: "local", "pass", or "tpm"
    #[serde(default = "default_backend_type")]
    pub backend_type: String,

    /// Enable verbose logging
    #[serde(default)]
    pub verbose: bool,

    /// Local backend configuration
    #[serde(default)]
    pub local: LocalBackendConfig,

    /// Pass backend configuration
    #[serde(default)]
    pub pass: PassBackendConfig,

    /// TPM backend configuration
    #[serde(default)]
    pub tpm: TpmBackendConfig,

    /// Security hardening configuration
    #[serde(default)]
    pub security: SecurityConfig,
}

fn default_backend_type() -> String {
    defaults::BACKEND_TYPE.to_string()
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            backend_type: defaults::BACKEND_TYPE.to_string(),
            verbose: defaults::VERBOSE,
            local: LocalBackendConfig::default(),
            pass: PassBackendConfig::default(),
            tpm: TpmBackendConfig::default(),
            security: SecurityConfig::default(),
        }
    }
}

impl AppConfig {
    /// Get the active backend configuration as an enum
    pub fn backend(&self) -> BackendConfig {
        match self.backend_type.as_str() {
            "pass" => BackendConfig::Pass(self.pass.clone()),
            "tpm" => BackendConfig::Tpm(self.tpm.clone()),
            _ => BackendConfig::Local(self.local.clone()),
        }
    }
}

/// Trait for CLI arguments that provide backend configuration
pub trait CliArgs {
    fn backend_type(&self) -> Option<String>;
    fn local_config(&self) -> &LocalBackendConfig;
    fn pass_config(&self) -> &PassBackendConfig;
    fn tpm_config(&self) -> &TpmBackendConfig;
    fn verbose(&self) -> bool;
    fn security_config(&self) -> &SecurityConfig;
}

impl AppConfig {
    /// Load configuration from a TOML file
    pub fn from_toml(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file {}: {}", path.display(), e))?;
        let config: AppConfig = toml::from_str(&content)
            .map_err(|e| format!("Failed to parse config file {}: {}", path.display(), e))?;
        Ok(config)
    }

    /// Create a display config with all defaults filled in for documentation purposes
    pub fn with_defaults_filled() -> Self {
        Self {
            backend_type: defaults::BACKEND_TYPE.to_string(),
            verbose: defaults::VERBOSE,
            local: LocalBackendConfig {
                path: Some(defaults::local_path_display()),
            },
            pass: PassBackendConfig {
                store_path: Some(defaults::pass_store_path()),
                path: Some(defaults::PASS_PATH.to_string()),
                gpg_backend: Some(defaults::PASS_GPG_BACKEND.to_string()),
            },
            tpm: TpmBackendConfig {
                path: Some(defaults::tpm_path_display()),
                tcti: Some(defaults::TPM_TCTI.to_string()),
            },
            security: SecurityConfig {
                use_mlock: Some(defaults::SECURITY_USE_MLOCK),
                disable_core_dumps: Some(defaults::SECURITY_DISABLE_CORE_DUMPS),
                constant_signature_counter: Some(defaults::SECURITY_CONSTANT_SIGNATURE_COUNTER),
                user_verification_registration: Some(
                    defaults::SECURITY_USER_VERIFICATION_REGISTRATION,
                ),
                user_verification_authentication: Some(
                    defaults::SECURITY_USER_VERIFICATION_AUTHENTICATION,
                ),
            },
        }
    }

    /// Merge CLI overrides into the configuration
    /// CLI arguments take precedence over config file settings
    pub fn merge_cli_overrides<T>(&self, cli: T) -> Self
    where
        T: CliArgs,
    {
        // Helper to merge Option values: CLI takes precedence, then config, then None
        fn merge_opt<U>(cli_val: Option<U>, config_val: Option<U>) -> Option<U> {
            cli_val.or(config_val)
        }

        // Determine backend type (CLI > config > default)
        let backend_type = cli
            .backend_type()
            .unwrap_or_else(|| self.backend_type.clone());

        // Merge local backend config
        let local = LocalBackendConfig {
            path: merge_opt(cli.local_config().path.clone(), self.local.path.clone()),
        };

        // Merge pass backend config
        let pass = PassBackendConfig {
            store_path: merge_opt(
                cli.pass_config().store_path.clone(),
                self.pass.store_path.clone(),
            ),
            path: merge_opt(cli.pass_config().path.clone(), self.pass.path.clone()),
            gpg_backend: merge_opt(
                cli.pass_config().gpg_backend.clone(),
                self.pass.gpg_backend.clone(),
            ),
        };

        // Merge TPM backend config
        let tpm = TpmBackendConfig {
            path: merge_opt(cli.tpm_config().path.clone(), self.tpm.path.clone()),
            tcti: merge_opt(cli.tpm_config().tcti.clone(), self.tpm.tcti.clone()),
        };

        AppConfig {
            backend_type,
            verbose: cli.verbose() || self.verbose,
            local,
            pass,
            tpm,
            security: SecurityConfig {
                use_mlock: merge_opt(cli.security_config().use_mlock, self.security.use_mlock),
                disable_core_dumps: merge_opt(
                    cli.security_config().disable_core_dumps,
                    self.security.disable_core_dumps,
                ),
                constant_signature_counter: merge_opt(
                    cli.security_config().constant_signature_counter,
                    self.security.constant_signature_counter,
                ),
                user_verification_registration: merge_opt(
                    cli.security_config().user_verification_registration,
                    self.security.user_verification_registration,
                ),
                user_verification_authentication: merge_opt(
                    cli.security_config().user_verification_authentication,
                    self.security.user_verification_authentication,
                ),
            },
        }
    }
}
