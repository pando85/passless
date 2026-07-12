mod authenticator;
mod commands;
mod instance_lock;
mod notification;
mod pin_storage;
mod storage;
mod util;

use passless_core::{
    AppConfig, Args, BackendConfig, ClientAction, Commands, ConfigAction, Error, PinAction, Result,
};

use soft_fido2_transport::{Cmd, CommandHandler, CtapHidHandler, Packet, UhidDevice};

use std::process;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use authenticator::AuthenticatorService;
use clap::Parser;
use commands::custom::register_yubikey_credential_mgmt;
use env_logger::{Builder, Env};
use log::{debug, error, info, warn};
#[cfg(feature = "tpm")]
use pin_storage::TpmPinStorage;
use pin_storage::{LocalPinStorage, PassPinStorage, PinStorage};
use shadow_rs::shadow;
#[cfg(feature = "tpm")]
use storage::TpmStorageAdapter;
use storage::{CredentialStorage, LocalStorageAdapter, PassStorageAdapter};

shadow!(build);

/// CLI arguments with custom version string
#[derive(Parser)]
#[command(
    author,
    about,
    long_version = build::CLAP_LONG_VERSION,
    version = build::PKG_VERSION
)]
struct CliArgs {
    #[command(flatten)]
    args: passless_core::Args,
}

/// Wrapper for AuthenticatorService that implements CommandHandler
struct ServiceHandler<S: CredentialStorage, P: PinStorage> {
    service: std::sync::Mutex<AuthenticatorService<S, P>>,
}

impl<S: CredentialStorage, P: PinStorage> ServiceHandler<S, P> {
    fn new(service: AuthenticatorService<S, P>) -> Self {
        Self {
            service: std::sync::Mutex::new(service),
        }
    }
}

impl<S: CredentialStorage + 'static, P: PinStorage + 'static> CommandHandler
    for ServiceHandler<S, P>
{
    fn handle_command(&mut self, cmd: Cmd, data: &[u8]) -> soft_fido2_transport::Result<Vec<u8>> {
        if cmd != Cmd::Cbor {
            error!("Invalid command: {:?}", cmd);
            return Err(soft_fido2_transport::Error::InvalidCommand);
        }

        let mut service = self.service.lock().map_err(|e| {
            error!("Failed to lock service: {}", e);
            soft_fido2_transport::Error::Other("Failed to lock service".to_string())
        })?;

        let mut response = Vec::new();
        service.handle(data, &mut response).map_err(|e| {
            error!("CTAP command failed: {:?}", e);
            soft_fido2_transport::Error::Other("Command failed".to_string())
        })?;

        debug!("CTAP response: {} bytes", response.len());
        Ok(response)
    }
}

/// Helper function to run the main loop with any storage backend
fn run_with_service<S: CredentialStorage + 'static, P: PinStorage + 'static>(
    mut service: AuthenticatorService<S, P>,
    uhid: UhidDevice,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    info!("{}", service.storage_info());

    register_yubikey_credential_mgmt(&mut service);

    info!("Authenticator is running");
    info!("Press Ctrl+C to stop");

    let service_ref = service.storage.clone();

    let handler = ServiceHandler::new(service);
    let mut ctaphid_handler = CtapHidHandler::new(handler);
    let mut buffer = [0u8; 64];

    let mut last_cache_cleanup = std::time::Instant::now();
    const CACHE_CLEANUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

    loop {
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
            Ok(Some(_)) => {
                debug!("Received packet from host");
                let packet = Packet::from_bytes(buffer);

                let response_packets = ctaphid_handler.process_packet(packet).map_err(|e| {
                    error!("CTAP HID processing failed: {:?}", e);
                    Error::Other("CTAP HID processing failed".to_string())
                })?;

                debug!("Sending {} response packets", response_packets.len());
                for response_packet in response_packets {
                    uhid.write_packet(response_packet.as_bytes()).map_err(|e| {
                        error!("Failed to write packet: {:?}", e);
                        Error::Other("Failed to write packet".to_string())
                    })?;
                }
                debug!("Response sent successfully");
            }
            Ok(None) => {
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
            Err(e) => {
                error!("Error reading packet: {:?}", e);
                break;
            }
        }
    }

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
  echo uhid > /etc/modules-load.d/fido.conf\n\
  groupadd fido 2>/dev/null || true\n\
  usermod -a -G fido $USER\n\
  echo 'KERNEL==\"uhid\", GROUP=\"fido\", MODE=\"0660\"' > /etc/udev/rules.d/90-uinput.rules\n\
  udevadm control --reload-rules && udevadm trigger";

fn main() {
    // Run main logic and format errors cleanly
    if let Err(e) = run() {
        eprintln!("Error: {}", e.format_cli());
        process::exit(1);
    }
}

fn run() -> Result<()> {
    // Parse CLI arguments
    let cli_args = CliArgs::parse();
    let mut args = cli_args.args;

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
            Commands::Client {
                device,
                output,
                action,
            } => match action {
                ClientAction::Devices => commands::client::devices(*output),
                ClientAction::Info => commands::client::info(*output, device.as_deref()),
                ClientAction::Reset { confirm } => {
                    commands::client::reset(*output, device.as_deref(), *confirm)
                }
                ClientAction::List { rp_id } => {
                    commands::client::list(*output, device.as_deref(), rp_id.as_deref())
                }
                ClientAction::Delete { credential_id } => {
                    commands::client::delete(*output, device.as_deref(), credential_id)
                }
                ClientAction::Show { credential_id } => {
                    commands::client::show(*output, device.as_deref(), credential_id)
                }
                ClientAction::Rename {
                    credential_id,
                    user_name,
                    display_name,
                } => commands::client::rename(
                    *output,
                    device.as_deref(),
                    credential_id,
                    user_name.as_deref(),
                    display_name.as_deref(),
                ),
                ClientAction::Pin { action } => match action {
                    PinAction::Set { pin } => {
                        commands::client::pin_set(*output, device.as_deref(), pin)
                    }
                    PinAction::Change { old_pin, new_pin } => {
                        commands::client::pin_change(*output, device.as_deref(), old_pin, new_pin)
                    }
                    PinAction::UvReset => {
                        commands::client::pin_uv_reset(*output, device.as_deref())
                    }
                },
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

    // Validate configuration
    if let Err(e) = config.validate() {
        error!("{}", e.format_cli());
        return Err(e);
    }

    if config.verbose && log_level != log::LevelFilter::Debug {
        info!("Enabling verbose logging...");
        log::set_max_level(log::LevelFilter::Debug);
        debug!("Verbose logging enabled");
    }

    info!("Applying security hardening...");
    if let Err(e) = config.apply_security_hardening() {
        warn!("Failed to apply security hardening: {}", e);
    }

    let backend = config.backend().map_err(|e| {
        error!("Failed to load backend config: {}", e);
        e
    })?;

    info!("Acquiring instance lock...");
    let _instance_lock = instance_lock::InstanceLock::acquire(&backend)?;
    debug!("Instance lock acquired at {}", _instance_lock.lock_path().display());

    info!("Creating UHID device...");

    #[cfg(debug_assertions)]
    let (vendor_id, product_id) = {
        let vendor_id = std::env::var("PASSLESS_TEST_VENDOR_ID").ok().and_then(|s| {
            let s = s.strip_prefix("0x").unwrap_or(&s);
            u16::from_str_radix(s, 16).ok()
        });
        let product_id = std::env::var("PASSLESS_TEST_PRODUCT_ID")
            .ok()
            .and_then(|s| {
                let s = s.strip_prefix("0x").unwrap_or(&s);
                u16::from_str_radix(s, 16).ok()
            });
        (vendor_id, product_id)
    };

    #[cfg(not(debug_assertions))]
    let (vendor_id, product_id) = (Some(0x15d9), Some(0x0a37));

    let uhid = UhidDevice::create_fido_device_with_ids(None, vendor_id, product_id, None)
        .map_err(|e| Error::Uhid(format!("{:?}", e)))
        .inspect_err(|_e| {
            error!("Failed to create UHID device");
            error!("\n{}", UHID_ERROR_MESSAGE);
        })?;

    // Set up graceful shutdown handler
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    let ctrlc_pressed = Arc::new(AtomicBool::new(false));

    ctrlc::set_handler(move || {
        if ctrlc_pressed.load(Ordering::Relaxed) {
            error!("Second interrupt signal received, forcing immediate exit");
            process::exit(1);
        }
        info!("Received interrupt signal (Ctrl+C)");
        info!("Initiating graceful shutdown... (press Ctrl+C again to force exit)");
        shutdown_clone.store(true, Ordering::Relaxed);
        ctrlc_pressed.store(true, Ordering::Relaxed);
    })
    .map_err(|e| Error::Other(format!("Failed to set Ctrl-C handler: {}", e)))?;

    info!("Creating authenticator service...");

    // Get security config
    let security_config = config.security_config();

    // Get PIN config
    let pin_config = config.pin_config();

    match backend {
        BackendConfig::Local { path } => {
            let storage = LocalStorageAdapter::new(path.clone().into())?;
            let pin_storage = LocalPinStorage::new(path.into());
            let pin_storage = Arc::new(Mutex::new(pin_storage));
            let service = AuthenticatorService::with_pin_storage(
                storage,
                Some(pin_storage),
                security_config,
                pin_config,
            )?;
            run_with_service(service, uhid, shutdown)
        }
        BackendConfig::Pass {
            store_path,
            path,
            gpg_backend,
        } => {
            let gpg_backend = storage::pass::GpgBackend::from_str(&gpg_backend)?;
            let storage = PassStorageAdapter::new(
                store_path.clone().into(),
                path.clone().into(),
                gpg_backend,
            )?;
            let pin_storage = PassPinStorage::new(store_path.into(), path.into(), gpg_backend);
            let pin_storage = Arc::new(Mutex::new(pin_storage));
            let service = AuthenticatorService::with_pin_storage(
                storage,
                Some(pin_storage),
                security_config,
                pin_config,
            )?;
            run_with_service(service, uhid, shutdown)
        }
        #[cfg(feature = "tpm")]
        BackendConfig::Tpm { path, tcti } => {
            let storage = TpmStorageAdapter::new(path.clone().into(), Some(tcti.clone()))?;
            let pin_storage = TpmPinStorage::new(path.into(), Some(tcti));
            let pin_storage = Arc::new(Mutex::new(pin_storage));
            let service = AuthenticatorService::with_pin_storage(
                storage,
                Some(pin_storage),
                security_config,
                pin_config,
            )?;
            run_with_service(service, uhid, shutdown)
        }
    }
}
