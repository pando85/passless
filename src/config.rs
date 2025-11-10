//! Application configuration
//!
//! This module defines the configuration for the authenticator.

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
use log::{debug, error};
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

/// Security hardening configuration
#[derive(Debug, Clone, Serialize, Deserialize, Args, Default)]
#[group(id = "security")]
pub struct SecurityConfig {
    /// Use mlock to prevent credentials from being swapped to disk
    /// Requires CAP_IPC_LOCK capability or running as root
    #[arg(
        long = "use-mlock",
        env = "PASSLESS_USE_MLOCK",
        default_value_t = true,
        help = "Lock credential memory to prevent swapping to disk (requires CAP_IPC_LOCK or root)"
    )]
    #[serde(default)]
    pub use_mlock: bool,

    /// Disable core dumps to prevent credential leakage
    #[arg(
        long = "disable-core-dumps",
        env = "PASSLESS_DISABLE_CORE_DUMPS",
        default_value_t = true,
        help = "Disable core dumps to prevent credential leakage in crash dumps"
    )]
    #[serde(default)]
    pub disable_core_dumps: bool,

    /// Set no new privileges flag to prevent privilege escalation
    #[arg(
        long = "no-new-privs",
        env = "PASSLESS_NO_NEW_PRIVS",
        default_value_t = true,
        help = "Set PR_SET_NO_NEW_PRIVS to prevent gaining new privileges"
    )]
    #[serde(default)]
    pub no_new_privs: bool,
}

/// Security hardening functions
impl SecurityConfig {
    /// Apply all enabled security hardening measures
    pub fn apply_hardening(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.disable_core_dumps {
            self.disable_core_dumps()?;
        }
        if self.use_mlock {
            self.lock_all_memory()?;
        }
        Ok(())
    }

    /// Disable core dumps to prevent credential leakage
    fn disable_core_dumps(&self) -> Result<(), Box<dyn std::error::Error>> {
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
                "mlockall failed (errno {}). Consider increasing RLIMIT_MEMLOCK or run with appropriate privileges.",
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
    #[arg(long = "local-path", env = "PASSLESS_LOCAL_PATH", id = "local.path", default_value_t = default_local_path(), value_name = "PATH")]
    #[serde(default)]
    pub path: String,
}

fn default_local_path() -> String {
    dirs::data_dir()
        .unwrap_or_else(|| {
            error!("Could not determine data directory: $XDG_DATA_HOME or $HOME/.local/share . Please, define local-path explicitly.");
            panic!()
        })
        .join("passless")
        .to_string_lossy()
        .into_owned()
}

/// Pass (password-store) backend configuration
#[derive(Debug, Clone, Serialize, Deserialize, Args, Default)]
#[group(id = "pass")]
pub struct PassBackendConfig {
    /// Path to password store directory
    #[arg(long = "pass-store-path", env = "PASSLESS_PASS_STORE_PATH", id = "pass.store_path", default_value_t = default_pass_store_path(), value_name = "PATH")]
    pub store_path: String,

    /// Relative dir to password store directory for FIDO2 entries
    #[arg(
        long = "pass-path",
        env = "PASSLESS_PASS_PATH",
        id = "pass.path",
        default_value = "fido2",
        value_name = "PATH"
    )]
    pub path: String,

    /// GPG backend: "gpgme" or "gnupg-bin"
    #[arg(
        long = "pass-gpg-backend",
        env = "PASSLESS_PASS_GPG_BACKEND",
        id = "pass.gpg_backend",
        default_value = "gnupg-bin",
        value_name = "BACKEND"
    )]
    pub gpg_backend: String,
}

fn default_pass_store_path() -> String {
    dirs::home_dir()
        .unwrap_or_else(|| {
            error!(
                "Could not determine home directory: $HOME. Please, define pass-path explicitly."
            );
            panic!()
        })
        .join(".password-store")
        .to_string_lossy()
        .into_owned()
}

/// Storage backend configuration (type-safe enum)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BackendConfig {
    /// Local file system storage
    Local(LocalBackendConfig),
    /// Pass (password-store) backend
    Pass(PassBackendConfig),
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self::Local(LocalBackendConfig::default())
    }
}

/// Application-level configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    /// Storage backend configuration
    #[serde(default)]
    pub backend: BackendConfig,

    /// Enable verbose logging
    #[serde(default)]
    pub verbose: bool,

    /// Security hardening configuration
    #[serde(default)]
    pub security: SecurityConfig,
}

/// Trait for CLI arguments that provide backend configuration
pub trait CliArgs {
    fn backend_type(&self) -> Option<String>;
    fn local_config(&self) -> &LocalBackendConfig;
    fn pass_config(&self) -> &PassBackendConfig;
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

    /// Merge CLI overrides into the configuration
    /// CLI arguments take precedence over config file settings
    pub fn merge_cli_overrides<T>(&self, cli: T) -> Self
    where
        T: CliArgs,
    {
        // Determine backend config to use
        let backend = match cli.backend_type().as_deref() {
            Some("local") => BackendConfig::Local(cli.local_config().clone()),
            Some("pass") => BackendConfig::Pass(cli.pass_config().clone()),
            _ => {
                // If no backend type override, merge CLI fields into the current backend
                match &self.backend {
                    BackendConfig::Local(_) => BackendConfig::Local(LocalBackendConfig {
                        path: cli.local_config().path.clone(),
                    }),
                    BackendConfig::Pass(_) => BackendConfig::Pass(PassBackendConfig {
                        store_path: cli.pass_config().store_path.clone(),
                        path: cli.pass_config().path.clone(),
                        gpg_backend: cli.pass_config().gpg_backend.clone(),
                    }),
                }
            }
        };

        AppConfig {
            backend,
            verbose: cli.verbose() || self.verbose,
            security: SecurityConfig {
                use_mlock: cli.security_config().use_mlock || self.security.use_mlock,
                disable_core_dumps: cli.security_config().disable_core_dumps
                    || self.security.disable_core_dumps,
                no_new_privs: cli.security_config().no_new_privs || self.security.no_new_privs,
            },
        }
    }
}
