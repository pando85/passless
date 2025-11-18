//! Application configuration
//!
//! This module defines the configuration for the authenticator.

pub mod defaults;

use crate::commands::custom::{
    CMD_CREDENTIAL_MGMT, CMD_CUSTOM_CREDENTIAL_MGMT, create_credential_mgmt_command,
};
use crate::storage::CredentialStorage;

use keylib::{AuthenticatorConfig, AuthenticatorOptions, CtapCommand};

use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use clap::Args;
use libc::{MCL_CURRENT, MCL_FUTURE, PR_SET_DUMPABLE, mlockall, prctl};
use log::debug;
use nix::sys::resource::{Resource, setrlimit};
use serde::{Deserialize, Serialize};

/// AAGUID for the passless authenticator
/// "fido.passless.rs" encoded as hex
pub const AAGUID: [u8; 16] = [
    0x66, 0x69, 0x64, 0x6F, 0x2E, 0x70, 0x61, 0x73, 0x73, 0x6C, 0x65, 0x73, 0x73, 0x2E, 0x72, 0x73,
];

/// Supported extensions
pub const SUPPORTED_EXTENSIONS: &[&str] = &["credProtect"];

/// Maximum number of resident credentials
pub const MAX_RESIDENT_CREDENTIALS: u32 = 100;

/// Firmware version
pub const FIRMWARE_VERSION: u32 = 0x0001;

/// User verification configuration
#[derive(Debug, Clone, Serialize, Deserialize, Args, Default)]
#[group(id = "user_verification")]
pub struct UserVerificationConfig {
    /// Enable user verification notification for registration
    #[arg(
        long = "user-verification-registration",
        env = "PASSLESS_USER_VERIFICATION_REGISTRATION",
        help = "Show user verification notification during registration"
    )]
    #[serde(default)]
    pub registration: Option<bool>,

    /// Enable user verification notification for authentication
    #[arg(
        long = "user-verification-authentication",
        env = "PASSLESS_USER_VERIFICATION_AUTHENTICATION",
        help = "Show user verification notification during authentication"
    )]
    #[serde(default)]
    pub authentication: Option<bool>,
}

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

/// Build the authenticator configuration
///
/// This creates a configuration matching the Zig example with:
/// - FIDO 2.0 and 2.1 support
/// - Credential management enabled
/// - Resident keys (discoverable credentials)
/// - User verification
/// - PIN support
/// - Platform authenticator mode
///
/// # Arguments
///
/// * `storage` - Storage backend wrapped in Arc<Mutex<S>>
pub fn build_authenticator_config<S: CredentialStorage + 'static>(
    storage: Arc<Mutex<S>>,
) -> AuthenticatorConfig {
    let options = AuthenticatorOptions {
        // Resident keys (discoverable credentials, a.k.a passkeys)
        rk: true,
        // User presence
        up: true,
        // User verification
        uv: Some(true),
        // Platform authenticator
        plat: true,
        // Client PIN support
        client_pin: Some(false),
        // PIN UV auth token support
        pin_uv_auth_token: Some(true),
        // Credential management support
        cred_mgmt: Some(true),
        // Bio enrollment not supported
        bio_enroll: None,
        // Large blobs not supported
        large_blobs: None,
        // Enterprise attestation
        ep: None,
        // Always require user verification
        always_uv: Some(true),
    };

    AuthenticatorConfig::builder()
        .aaguid(AAGUID)
        .options(options)
        .firmware_version(FIRMWARE_VERSION)
        .commands(vec![
            CtapCommand::MakeCredential,   // 0x01
            CtapCommand::GetAssertion,     // 0x02
            CtapCommand::GetInfo,          // 0x04
            CtapCommand::ClientPin,        // 0x06
            CtapCommand::GetNextAssertion, // 0x08
            CtapCommand::Selection,        // 0x0b
        ])
        .custom_commands(vec![
            create_credential_mgmt_command(CMD_CREDENTIAL_MGMT, storage.clone()), // 0x0a (standard)
            create_credential_mgmt_command(CMD_CUSTOM_CREDENTIAL_MGMT, storage),  // 0x41 (Yubikey)
        ])
        .max_credentials(MAX_RESIDENT_CREDENTIALS)
        .extensions(
            SUPPORTED_EXTENSIONS
                .iter()
                .map(|&s| s.to_string())
                .collect(),
        )
        .build()
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

    /// User verification configuration
    #[serde(default)]
    pub user_verification: UserVerificationConfig,
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
            user_verification: UserVerificationConfig::default(),
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
    fn user_verification_config(&self) -> &UserVerificationConfig;
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
            },
            user_verification: UserVerificationConfig {
                registration: Some(defaults::USER_VERIFICATION_REGISTRATION),
                authentication: Some(defaults::USER_VERIFICATION_AUTHENTICATION),
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
            },
            user_verification: UserVerificationConfig {
                registration: merge_opt(
                    cli.user_verification_config().registration,
                    self.user_verification.registration,
                ),
                authentication: merge_opt(
                    cli.user_verification_config().authentication,
                    self.user_verification.authentication,
                ),
            },
        }
    }
}
