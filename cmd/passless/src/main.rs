mod authenticator;
mod commands;
mod notification;
mod storage;

use passless_core::{AppConfig, Args, BackendConfig, Commands, ConfigAction, Error, Result};

use soft_fido2::Uhid;
use soft_fido2_transport::{Cmd, CommandHandler, CtapHidHandler, Packet};

use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use authenticator::AuthenticatorService;
use clap::Parser;
use commands::custom::register_yubikey_credential_mgmt;
use env_logger::{Builder, Env};
use log::{debug, error, info, warn};
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

/// Helper function to run the main loop with any storage backend
fn run_with_service<S: CredentialStorage + 'static>(
    mut service: AuthenticatorService<S>,
    uhid: Uhid,
    shutdown: Arc<AtomicBool>,
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
        // Check if shutdown was requested
        if shutdown.load(Ordering::Relaxed) {
            info!("Shutdown signal received, cleaning up...");
            break;
        }

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
                    .map_err(|_| Error::Other("CTAP HID processing failed".to_string()))?;

                // Write response packets
                for response_packet in response_packets {
                    uhid.write_packet(response_packet.as_bytes())
                        .map_err(|_| Error::Other("Failed to write packet".to_string()))?;
                }
            }
            Err(e) => {
                error!("Error reading packet: {:?}", e);
                break;
            }
        }
    }

    // Cleanup before exit
    info!("Performing final cache cleanup...");
    if let Ok(mut storage) = service_ref.lock() {
        storage.cleanup_expired_cache();
    }
    info!("Authenticator stopped gracefully");

    Ok(())
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
    let mut args = Args::parse();

    // Handle subcommands first
    if let Some(command) = &args.command {
        return match command {
            Commands::Config { action } => match action {
                ConfigAction::Print => {
                    // Generate default configuration with helpful comments
                    let mut default_args = Args::parse_from(["passless"]);
                    let default_config = AppConfig::from(&mut default_args.config);
                    println!("{}", default_config.to_toml_with_comments());
                    Ok(())
                }
            },
        };
    }

    // Initialize logging with appropriate level
    let log_level = if args.config.verbose == Some(true) {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    let env = Env::default()
        .filter("PASSLESS_LOG_LEVEL")
        .write_style("PASSLESS_LOG_STYLE");
    Builder::from_env(env)
        .filter_level(log::LevelFilter::Debug)
        .format_timestamp_millis()
        .init();
    log::set_max_level(log_level);

    // Load config: CLI args + config file + defaults (CLI takes precedence)
    let config = AppConfig::load(&mut args);

    if config.verbose && log_level != log::LevelFilter::Debug {
        info!("Enabling verbose logging...");
        log::set_max_level(log::LevelFilter::Debug);
        debug!("Verbose logging enabled");
    }

    info!("Applying security hardening...");
    if let Err(e) = config.apply_security_hardening() {
        warn!("Failed to apply security hardening: {}", e);
    }

    info!("Opening UHID device...");
    let uhid = Uhid::open().inspect_err(|_e| {
        error!("Failed to open UHID device");
        error!("\n{}", UHID_ERROR_MESSAGE);
    })?;

    // Set up graceful shutdown handler
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    ctrlc::set_handler(move || {
        info!("Received interrupt signal (Ctrl+C)");
        info!("Initiating graceful shutdown... (will force exit in 5 seconds)");
        shutdown_clone.store(true, Ordering::Relaxed);

        // Spawn a thread that will forcefully exit after 5 seconds
        thread::spawn(|| {
            thread::sleep(Duration::from_secs(5));
            error!("Graceful shutdown timeout reached, forcing exit");
            process::exit(1);
        });
    })
    .map_err(|e| Error::Other(format!("Failed to set Ctrl-C handler: {}", e)))?;

    info!("Creating authenticator service...");

    // Get security config
    let security_config = config.security_config();

    match config.backend().map_err(|e| {
        error!("Failed to load backend config: {}", e);
        e
    })? {
        BackendConfig::Local { path } => {
            let storage = LocalStorageAdapter::new(path.into())?;
            let service = AuthenticatorService::new(storage, security_config)?;
            run_with_service(service, uhid, shutdown)
        }
        BackendConfig::Pass {
            store_path,
            path,
            gpg_backend,
        } => {
            let gpg_backend = storage::pass::GpgBackend::from_str(&gpg_backend)?;
            let storage = PassStorageAdapter::new(store_path.into(), path.into(), gpg_backend)?;
            let service = AuthenticatorService::new(storage, security_config)?;
            run_with_service(service, uhid, shutdown)
        }
        BackendConfig::Tpm { path, tcti } => {
            let storage = TpmStorageAdapter::new(path.into(), Some(tcti))?;
            let service = AuthenticatorService::new(storage, security_config)?;
            run_with_service(service, uhid, shutdown)
        }
    }
}
