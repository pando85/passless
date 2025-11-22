//! Application configuration using clap-serde-derive
//!
//! This module provides a unified configuration approach where settings can come from:
//! 1. CLI arguments (highest priority)
//! 2. Configuration file (medium priority)
//! 3. Default values (lowest priority)

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use clap::{ArgAction, Parser};
use clap_serde_derive::ClapSerde;
use libc::{MCL_CURRENT, MCL_FUTURE, PR_SET_DUMPABLE, mlockall, prctl};
use log::debug;
use nix::sys::resource::{Resource, setrlimit};
use serde::{Deserialize, Serialize};

/// Compute default local storage path
pub fn local_path() -> String {
    dirs::data_dir()
        .expect("Could not determine data directory: $XDG_DATA_HOME or $HOME/.local/share")
        .join("passless")
        .to_string_lossy()
        .into_owned()
}

/// Local backend configuration
#[derive(ClapSerde, Debug, Clone, Serialize, Deserialize)]
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
/// Pass backend configuration
#[derive(ClapSerde, Debug, Clone, Serialize, Deserialize)]
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
#[derive(ClapSerde, Debug, Clone, Serialize, Deserialize)]
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
#[derive(ClapSerde, Debug, Clone, Serialize, Deserialize)]
#[group(id = "security")]
pub struct SecurityConfig {
    /// Use mlock to prevent credentials from being swapped to disk (requires CAP_IPC_LOCK)
    #[arg(long = "use-mlock", env = "PASSLESS_USE_MLOCK")]
    #[serde(default)]
    #[default(true)]
    pub use_mlock: bool,

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
    #[default(false)]
    pub constant_signature_counter: bool,

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
}

impl SecurityConfig {
    /// Apply security hardening measures
    pub fn apply_hardening(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.disable_core_dumps {
            self.disable_core_dumps_impl()?;
        }
        if self.use_mlock {
            self.lock_all_memory()?;
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

    /// Lock all current and future memory mappings to prevent swapping
    fn lock_all_memory(&self) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Locking all memory to prevent swapping");
        let r = unsafe { mlockall(MCL_CURRENT | MCL_FUTURE) };
        if r != 0 {
            return Err(format!(
                "mlockall failed (errno {}).\n\
                 Hint: increase DefaultLimitMEMLOCK at /etc/systemd/system.conf and /etc/systemd/user.conf level.\n\
                 Hint: grant CAP_IPC_LOCK to the binary with: 'sudo setcap cap_ipc_lock=+ep $(which passless)'",
                std::io::Error::last_os_error()
            )
            .into());
        }
        Ok(())
    }
}

/// Main application configuration
/// Note: Cannot derive Clone/Debug because it has #[clap_serde] fields
#[derive(ClapSerde, Serialize, Deserialize, Debug)]
pub struct AppConfig {
    /// Storage backend type: local, pass, or tpm
    #[arg(short = 't', long = "backend-type", env = "PASSLESS_BACKEND_TYPE")]
    #[serde(default)]
    #[default("local".to_string())]
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

    /// Local backend configuration
    #[clap_serde]
    #[serde(default)]
    #[command(flatten)]
    pub local: LocalBackendConfig,

    /// Pass backend configuration
    #[clap_serde]
    #[serde(default)]
    #[command(flatten)]
    pub pass: PassBackendConfig,

    /// TPM backend configuration
    #[clap_serde]
    #[serde(default)]
    #[command(flatten)]
    pub tpm: TpmBackendConfig,

    /// Security hardening configuration
    #[clap_serde]
    #[serde(default)]
    #[command(flatten)]
    pub security: SecurityConfig,
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
    Tpm {
        path: String,
        tcti: String,
    },
}

impl AppConfig {
    /// Load configuration with precedence: CLI > config file > defaults
    pub fn load(args: &mut Args) -> Self {
        // Try to load config file
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
            match toml::from_str::<AppConfig>(&content) {
                Ok(file_config) => {
                    // Merge: file config + CLI args (CLI takes precedence)
                    return file_config.merge(&mut args.config);
                }
                Err(e) => log::warn!("Failed to parse config file {}: {}", path.display(), e),
            }
        }

        // No config file or parse failed - use CLI args + defaults
        AppConfig::from(&mut args.config)
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
}
