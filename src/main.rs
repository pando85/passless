mod authenticator;
mod commands;
mod config;
mod error;
mod notification;
mod storage;

use keylib::ctaphid::{Cmd, Ctaphid};
use keylib::uhid::Uhid;

use std::path::PathBuf;

use authenticator::AuthenticatorService;
use clap::Parser;
use config::AppConfig;
use env_logger::{Builder, Env};
use error::Result;
use log::{debug, error, info};
use storage::{CredentialStorage, LocalStorageAdapter, PassStorageAdapter};

/// Helper function to run the main loop with any storage backend
fn run_with_service<S: CredentialStorage + 'static>(
    mut service: AuthenticatorService<S>,
    uhid: Uhid,
) -> Result<()> {
    info!("{}", service.storage_info());

    // Main loop - process CTAP packets
    info!("Authenticator is running");
    info!("Press Ctrl+C to stop");

    let mut ctaphid = Ctaphid::new()?;
    let mut buffer = [0u8; 64];
    let mut response_buffer = Vec::new();

    // Track time for periodic cache cleanup
    let mut last_cache_cleanup = std::time::Instant::now();
    const CACHE_CLEANUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

    loop {
        if last_cache_cleanup.elapsed() >= CACHE_CLEANUP_INTERVAL {
            service.cleanup_expired_cache();
            last_cache_cleanup = std::time::Instant::now();
        }

        match uhid.read_packet(&mut buffer) {
            Ok(0) => {
                // No data, sleep briefly to avoid busy-waiting
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
            Ok(_) => {
                // Handle CTAPHID packet
                if let Some(mut response) = ctaphid.handle(&buffer) {
                    if let Cmd::Cbor = response.command() {
                        // Process CTAP request through the service
                        match service.handle(response.data(), &mut response_buffer) {
                            Ok(_) => {
                                if let Err(e) = response.set_data(&response_buffer) {
                                    error!("Failed to set response data: {:?}", e);
                                    continue;
                                }
                                debug!("Request processed successfully");
                            }
                            Err(e) => {
                                error!("Authenticator error: {:?}", e);
                                continue;
                            }
                        }
                    }

                    // Send response packets back to the host
                    for packet in response.packets() {
                        uhid.write_packet(&packet)?;
                    }
                }
            }
            Err(e) => {
                error!("Error reading USB packet: {:?}", e);
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
    /// Path to configuration file (TOML format)
    #[arg(short, long, env = "PASSLESS_CONFIG")]
    config: Option<PathBuf>,

    /// Storage backend type: local, pass
    #[arg(short = 't', long, env = "PASSLESS_BACKEND_TYPE")]
    backend_type: Option<String>,

    /// Local backend configuration
    #[command(flatten)]
    local: config::LocalBackendConfig,

    /// Pass backend configuration
    #[command(flatten)]
    pass: config::PassBackendConfig,

    /// Security hardening configuration
    #[command(flatten)]
    security: config::SecurityConfig,

    /// Enable verbose logging
    #[arg(
        short,
        long,
        help = "Enable verbose logging; PASSLESS_LOG_LEVEL and PASSLESS_LOG_STYLE envs could also be used to configure logging"
    )]
    verbose: bool,
}

impl config::CliArgs for Cli {
    fn backend_type(&self) -> Option<String> {
        self.backend_type.clone()
    }

    fn local_config(&self) -> &config::LocalBackendConfig {
        &self.local
    }

    fn pass_config(&self) -> &config::PassBackendConfig {
        &self.pass
    }

    fn verbose(&self) -> bool {
        self.verbose
    }

    fn security_config(&self) -> &config::SecurityConfig {
        &self.security
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

    // Initialize logging with appropriate level
    let log_level = if cli.verbose {
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
    let config_file = if let Some(config_path) = &cli.config {
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

    let config = config_file.merge_cli_overrides(cli);

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
    match &config.backend {
        config::BackendConfig::Local(local_config) => {
            let storage = LocalStorageAdapter::new(local_config.path.clone().into())?;
            let service = AuthenticatorService::new(storage)?;
            run_with_service(service, uhid)
        }
        config::BackendConfig::Pass(pass_config) => {
            let gpg_backend = storage::GpgBackend::from_str(&pass_config.gpg_backend)?;
            let storage = PassStorageAdapter::new(
                pass_config.store_path.clone().into(),
                pass_config.path.clone().into(),
                gpg_backend,
            )?;
            let service = AuthenticatorService::new(storage)?;
            run_with_service(service, uhid)
        }
    }
}
