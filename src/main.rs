mod authenticator;
mod commands;
mod config;
mod error;
mod notification;
mod storage;

use soft_fido2::Uhid;
use soft_fido2_transport::{Cmd, CommandHandler, CtapHidHandler, Packet};

use std::path::PathBuf;

use authenticator::AuthenticatorService;
use clap::{Args, Parser, Subcommand};
use commands::custom::register_yubikey_credential_mgmt;
use config::AppConfig;
use env_logger::{Builder, Env};
use error::Result;
use log::{error, info};
use storage::{CredentialStorage, LocalStorageAdapter, PassStorageAdapter, TpmStorageAdapter};

/// Wrapper for AuthenticatorService that implements CommandHandler
struct ServiceHandler<S: CredentialStorage> {
    service: std::sync::Mutex<AuthenticatorService<S>>,
}

impl<S: CredentialStorage> ServiceHandler<S> {
    fn new(service: AuthenticatorService<S>) -> Self {
        Self {
            service: std::sync::Mutex::new(service),
        }
    }
}

impl<S: CredentialStorage + 'static> CommandHandler for ServiceHandler<S> {
    fn handle_command(&mut self, cmd: Cmd, data: &[u8]) -> soft_fido2_transport::Result<Vec<u8>> {
        // Only handle CBOR commands (CTAP2)
        if cmd != Cmd::Cbor {
            return Err(soft_fido2_transport::Error::InvalidCommand);
        }

        let mut service = self.service.lock().map_err(|_| {
            soft_fido2_transport::Error::Other("Failed to lock service".to_string())
        })?;

        let mut response = Vec::new();
        service
            .handle(data, &mut response)
            .map_err(|_| soft_fido2_transport::Error::Other("Command failed".to_string()))?;

        Ok(response)
    }
}

/// Macro to create and run a storage backend
macro_rules! run_backend {
    ($adapter:ty, $config:expr, $uhid:expr, $uv_config:expr) => {{
        let storage = <$adapter>::from_config($config)?;
        let service = AuthenticatorService::new(storage, $uv_config)?;
        run_with_service(service, $uhid)
    }};
}

/// Helper function to run the main loop with any storage backend
fn run_with_service<S: CredentialStorage + 'static>(
    mut service: AuthenticatorService<S>,
    uhid: Uhid,
) -> Result<()> {
    info!("{}", service.storage_info());

    // Register custom commands for compatibility (placeholder for now)
    register_yubikey_credential_mgmt(&mut service);

    // Main loop - process CTAP packets
    info!("Authenticator is running");
    info!("Press Ctrl+C to stop");

    // Store a reference to storage for periodic cleanup (before moving service)
    let service_ref = service.storage.clone();

    let handler = ServiceHandler::new(service);
    let mut ctaphid_handler = CtapHidHandler::new(handler);
    let mut buffer = [0u8; 64];

    // Track time for periodic cache cleanup
    let mut last_cache_cleanup = std::time::Instant::now();
    const CACHE_CLEANUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

    loop {
        if last_cache_cleanup.elapsed() >= CACHE_CLEANUP_INTERVAL {
            if let Ok(mut storage) = service_ref.lock() {
                storage.cleanup_expired_cache();
            }
            last_cache_cleanup = std::time::Instant::now();
        }

        match uhid.read_packet(&mut buffer) {
            Ok(0) => {
                // No data, sleep briefly to avoid busy-waiting
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
            Ok(_) => {
                // Parse packet
                let packet = Packet::from_bytes(buffer);

                // Process through CTAP HID handler
                let response_packets = ctaphid_handler
                    .process_packet(packet)
                    .map_err(|_| error::Error::Other("CTAP HID processing failed".to_string()))?;

                // Write response packets
                for response_packet in response_packets {
                    uhid.write_packet(response_packet.as_bytes())
                        .map_err(|_| error::Error::Other("Failed to write packet".to_string()))?;
                }
            }
            Err(e) => {
                error!("Error reading packet: {:?}", e);
                break;
            }
        }
    }

    Ok(())
}

/// Passless - Software FIDO2 Authenticator
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// When no subcommand is provided, run the authenticator with these options
    #[command(flatten)]
    run_args: RunArgs,
}

/// Subcommands for passless
#[derive(Subcommand, Debug)]
enum Commands {
    /// Configuration management commands
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

/// Configuration actions
#[derive(Subcommand, Debug)]
enum ConfigAction {
    /// Print the default configuration in TOML format
    Print,
}

/// Arguments for running the authenticator (default behavior)
#[derive(Args, Debug)]
struct RunArgs {
    /// Path to configuration file (TOML format)
    #[arg(short, long, env = "PASSLESS_CONFIG")]
    config: Option<PathBuf>,

    /// Storage backend type: local, pass, tpm
    #[arg(short = 't', long, env = "PASSLESS_BACKEND_TYPE")]
    backend_type: Option<String>,

    /// Local backend configuration
    #[command(flatten)]
    local: config::LocalBackendConfig,

    /// Pass backend configuration
    #[command(flatten)]
    pass: config::PassBackendConfig,

    /// TPM backend configuration
    #[command(flatten)]
    tpm: config::TpmBackendConfig,

    /// Security hardening configuration
    #[command(flatten)]
    security: config::SecurityConfig,

    /// User verification configuration
    #[command(flatten)]
    user_verification: config::UserVerificationConfig,

    /// Enable verbose logging
    #[arg(
        short,
        long,
        help = "Enable verbose logging; PASSLESS_LOG_LEVEL and PASSLESS_LOG_STYLE envs could also be used to configure logging"
    )]
    verbose: bool,
}

impl config::CliArgs for RunArgs {
    fn backend_type(&self) -> Option<String> {
        self.backend_type.clone()
    }

    fn local_config(&self) -> &config::LocalBackendConfig {
        &self.local
    }

    fn pass_config(&self) -> &config::PassBackendConfig {
        &self.pass
    }

    fn tpm_config(&self) -> &config::TpmBackendConfig {
        &self.tpm
    }

    fn verbose(&self) -> bool {
        self.verbose
    }

    fn security_config(&self) -> &config::SecurityConfig {
        &self.security
    }

    fn user_verification_config(&self) -> &config::UserVerificationConfig {
        &self.user_verification
    }
}

const UHID_ERROR_MESSAGE: &str = "Make sure you have the uhid kernel module loaded and proper permissions.\n\
Run the following commands as root:\n\
  modprobe uhid\n\
  groupadd fido 2>/dev/null || true\n\
  usermod -a -G fido $USER\n\
  echo 'KERNEL==\"uhid\", GROUP=\"fido\", MODE=\"0660\"' > /etc/udev/rules.d/90-uinput.rules\n\
  udevadm control --reload-rules && udevadm trigger";

fn main() -> Result<()> {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Handle subcommands
    if let Some(command) = cli.command {
        return match command {
            Commands::Config { action } => match action {
                ConfigAction::Print => {
                    // Generate default configuration with all defaults filled in
                    let default_config = AppConfig::with_defaults_filled();
                    let toml_string = toml::to_string_pretty(&default_config).map_err(|e| {
                        error::Error::Config(format!("Failed to serialize config: {}", e))
                    })?;
                    println!("{}", toml_string);
                    Ok(())
                }
            },
        };
    }

    // If no subcommand, run the authenticator (default behavior)
    let run_args = cli.run_args;

    // Initialize logging with appropriate level
    let log_level = if run_args.verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    let env = Env::default()
        .filter("PASSLESS_LOG_LEVEL")
        .write_style("PASSLESS_LOG_STYLE");
    Builder::from_env(env)
        .filter_level(log_level)
        .format_timestamp_millis()
        .init();

    // Load configuration
    let config_file = if let Some(config_path) = &run_args.config {
        info!("Loading configuration from: {}", config_path.display());
        AppConfig::from_toml(config_path).map_err(|e| {
            error!("Failed to load config file: {}", e);
            error::Error::Config(format!("Failed to load config file: {}", e))
        })?
    } else {
        // Try default config location
        let default_config_path = dirs::config_dir().map(|p| p.join("passless/config.toml"));

        if let Some(ref path) = default_config_path {
            if path.exists() {
                info!("Loading configuration from: {}", path.display());
                AppConfig::from_toml(path).map_err(|e| {
                    error!("Failed to load config file: {}", e);
                    error::Error::Config(format!("Failed to load config file: {}", e))
                })?
            } else {
                info!("No config file found, using defaults");
                AppConfig::default()
            }
        } else {
            AppConfig::default()
        }
    };

    let config = config_file.merge_cli_overrides(run_args);

    info!("Applying security hardening...");
    if let Err(e) = config.security.apply_hardening() {
        error!("Failed to apply security hardening: {}", e);
        // Don't exit, just warn - some hardening may require privileges
    }

    info!("Opening UHID device...");
    let uhid = Uhid::open().inspect_err(|_e| {
        error!("Failed to open UHID device");
        error!("\n{}", UHID_ERROR_MESSAGE);
    })?;

    info!("Creating authenticator service...");
    match config.backend() {
        config::BackendConfig::Local(cfg) => {
            run_backend!(
                LocalStorageAdapter,
                &cfg,
                uhid,
                config.user_verification.clone()
            )
        }
        config::BackendConfig::Pass(cfg) => {
            run_backend!(
                PassStorageAdapter,
                &cfg,
                uhid,
                config.user_verification.clone()
            )
        }
        config::BackendConfig::Tpm(cfg) => {
            run_backend!(
                TpmStorageAdapter,
                &cfg,
                uhid,
                config.user_verification.clone()
            )
        }
    }
}
