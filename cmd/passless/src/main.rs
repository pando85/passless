#[cfg(feature = "agent")]
mod agent;
mod authenticator;
mod commands;
mod instance_lock;
mod notification;
mod pin_storage;
mod storage;
mod util;
mod worker;

use passless_core::{
    AppConfig, Args, BackendConfig, ClientAction, Commands, ConfigAction, Error, PinAction, Result,
};

use soft_fido2_transport::{Cmd, CommandHandler, CtapHidHandler, UhidDevice};

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
use worker::{UhidEndpoint, WorkerConfig, WorkerOutcome};

shadow!(build);

const E2E_AUTO_ACCEPT_STORAGE_ENV: &str = "PASSLESS_E2E_AUTO_ACCEPT_STORAGE";

fn allow_e2e_storage_creation() -> bool {
    #[cfg(debug_assertions)]
    {
        std::env::var(E2E_AUTO_ACCEPT_STORAGE_ENV).as_deref() == Ok("1")
    }

    #[cfg(not(debug_assertions))]
    {
        false
    }
}

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
///
/// Lock order (documented): operation_lock → service (storage).
/// The operation_lock is held across the entire CTAP service dispatch so that
/// human and delegated read-sign-update operations serialize. Never hold the
/// service/storage lock while acquiring the operation_lock.
pub(crate) struct ServiceHandler<S: CredentialStorage, P: PinStorage> {
    service: std::sync::Mutex<AuthenticatorService<S, P>>,
    operation_lock: Arc<Mutex<()>>,
}

impl<S: CredentialStorage, P: PinStorage> ServiceHandler<S, P> {
    pub(crate) fn new(service: AuthenticatorService<S, P>) -> Self {
        Self {
            service: std::sync::Mutex::new(service),
            operation_lock: Arc::new(Mutex::new(())),
        }
    }

    fn with_operation_lock(service: AuthenticatorService<S, P>, lock: Arc<Mutex<()>>) -> Self {
        Self {
            service: std::sync::Mutex::new(service),
            operation_lock: lock,
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

        let _op = self.operation_lock.lock().map_err(|e| {
            error!("Failed to lock operation: {}", e);
            soft_fido2_transport::Error::Other("Failed to lock operation".to_string())
        })?;

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
    service: AuthenticatorService<S, P>,
    uhid: UhidDevice,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    run_with_service_inner(service, uhid, shutdown, None)
}

#[cfg(feature = "agent")]
fn run_with_service_and_lock<S: CredentialStorage + 'static, P: PinStorage + 'static>(
    service: AuthenticatorService<S, P>,
    uhid: UhidDevice,
    shutdown: Arc<AtomicBool>,
    operation_lock: Arc<Mutex<()>>,
) -> Result<()> {
    run_with_service_inner(service, uhid, shutdown, Some(operation_lock))
}

fn run_with_service_inner<S: CredentialStorage + 'static, P: PinStorage + 'static>(
    mut service: AuthenticatorService<S, P>,
    uhid: UhidDevice,
    shutdown: Arc<AtomicBool>,
    operation_lock: Option<Arc<Mutex<()>>>,
) -> Result<()> {
    info!("{}", service.storage_info());

    register_yubikey_credential_mgmt(&mut service);

    info!("Authenticator is running");
    info!("Press Ctrl+C to stop");

    let service_ref = service.storage.clone();

    let handler = match operation_lock {
        Some(lock) => ServiceHandler::with_operation_lock(service, lock),
        None => ServiceHandler::new(service),
    };
    let ctaphid = CtapHidHandler::new(handler);
    let endpoint = UhidEndpoint::new(uhid);

    let config = WorkerConfig::default();

    let handle = worker::spawn(
        endpoint,
        ctaphid,
        config,
        shutdown.clone(),
        Box::new(move || {
            if let Ok(mut storage) = service_ref.lock() {
                storage.cleanup_expired_cache();
            }
        }),
    );

    while !shutdown.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    info!("Shutdown signal received, cleaning up...");
    handle.cancel();

    let outcome = handle.join();
    match outcome {
        WorkerOutcome::Clean => {
            info!("Authenticator stopped gracefully");
            Ok(())
        }
        WorkerOutcome::Error(e) => {
            error!("Worker exited with error: {}", e);
            Err(Error::Other(format!("Worker error: {}", e)))
        }
        WorkerOutcome::Panicked => {
            error!("Worker thread panicked");
            Err(Error::Other("Worker thread panicked".to_string()))
        }
    }
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
            #[cfg(feature = "agent")]
            Commands::AgentAdmin { output, action } => {
                commands::agent_admin::dispatch_admin(*output, action)
            }
            #[cfg(feature = "agent")]
            Commands::Agent {
                profile,
                output,
                action,
            } => commands::agent::dispatch(profile.as_deref(), *output, action),
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
    let config = AppConfig::load(&mut args).inspect_err(|e| {
        error!("{}", e.format_cli());
    })?;

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

    #[cfg(feature = "agent")]
    let agent_enabled = config.agents.enabled;
    #[cfg(not(feature = "agent"))]
    let agent_enabled = false;

    if agent_enabled {
        #[cfg(feature = "agent")]
        {
            use instance_lock::DaemonLocks;

            let runtime_dir = dirs::runtime_dir()
                .or_else(|| {
                    let uid = unsafe { libc::getuid() };
                    Some(std::path::PathBuf::from(format!("/tmp/passless-{}", uid)))
                })
                .ok_or_else(|| Error::Other("Failed to resolve runtime directory".to_string()))?;

            let agent_backends: Vec<BackendConfig> = config
                .agents
                .profiles
                .values()
                .filter_map(|profile| profile.storage.as_ref().map(|s| s.to_backend_config()))
                .collect();

            info!(
                "Acquiring daemon locks (human + {} agent backends)...",
                agent_backends.len()
            );
            let _daemon_locks = DaemonLocks::acquire(&backend, &agent_backends, &runtime_dir)?;
            debug!("Daemon locks acquired");

            let shutdown = Arc::new(AtomicBool::new(false));
            let mut endpoint_manager = agent::endpoint_manager::EndpointManager::new(
                config.agents.profiles.len().max(1),
                shutdown.clone(),
                worker::WorkerConfig::default(),
            );
            debug!("Endpoint manager initialized");

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

            let security_config = config.security_config();
            let pin_config = config.pin_config();
            let operation_lock = Arc::new(Mutex::new(()));
            let allow_storage_creation = allow_e2e_storage_creation();

            match backend {
                BackendConfig::Local { path } => {
                    let storage = LocalStorageAdapter::new_with_options(
                        path.clone().into(),
                        allow_storage_creation,
                    )?;
                    let boxed: Box<dyn CredentialStorage> = Box::new(storage);
                    let shared_storage = Arc::new(Mutex::new(boxed));
                    let pin_storage_inner = LocalPinStorage::new(path.into());
                    let boxed_pin: Box<dyn crate::pin_storage::PinStorage> =
                        Box::new(pin_storage_inner);
                    let pin_storage = Arc::new(Mutex::new(boxed_pin));
                    let service = AuthenticatorService::with_shared_storage(
                        shared_storage.clone(),
                        Some(pin_storage.clone()),
                        security_config.clone(),
                        pin_config.clone(),
                    )?;

                    let agent_runtime = match agent::runtime::AgentRuntime::start(
                        shared_storage.clone(),
                        pin_storage.clone(),
                        operation_lock.clone(),
                        &config.agents,
                        security_config,
                        pin_config,
                        shutdown.clone(),
                    ) {
                        Ok(rt) => Some(rt),
                        Err(e) => {
                            warn!(
                                "Agent subsystem failed to start: {}; human path remains available",
                                e
                            );
                            None
                        }
                    };

                    let result = run_with_service_and_lock(service, uhid, shutdown, operation_lock);
                    if let Some(rt) = agent_runtime {
                        rt.shutdown();
                    }
                    endpoint_manager.cancel_all();
                    let _ = endpoint_manager.shutdown_all(None);
                    result
                }
                BackendConfig::Pass {
                    store_path,
                    path,
                    gpg_backend,
                } => {
                    let gpg_backend = storage::pass::GpgBackend::from_str(&gpg_backend)?;
                    let storage = PassStorageAdapter::new_with_options(
                        store_path.clone().into(),
                        path.clone().into(),
                        gpg_backend,
                        allow_storage_creation,
                    )?;
                    let boxed: Box<dyn CredentialStorage> = Box::new(storage);
                    let shared_storage = Arc::new(Mutex::new(boxed));
                    let pin_storage_inner =
                        PassPinStorage::new(store_path.into(), path.into(), gpg_backend);
                    let boxed_pin: Box<dyn crate::pin_storage::PinStorage> =
                        Box::new(pin_storage_inner);
                    let pin_storage = Arc::new(Mutex::new(boxed_pin));
                    let service = AuthenticatorService::with_shared_storage(
                        shared_storage.clone(),
                        Some(pin_storage.clone()),
                        security_config.clone(),
                        pin_config.clone(),
                    )?;

                    let agent_runtime = match agent::runtime::AgentRuntime::start(
                        shared_storage.clone(),
                        pin_storage.clone(),
                        operation_lock.clone(),
                        &config.agents,
                        security_config,
                        pin_config,
                        shutdown.clone(),
                    ) {
                        Ok(rt) => Some(rt),
                        Err(e) => {
                            warn!(
                                "Agent subsystem failed to start: {}; human path remains available",
                                e
                            );
                            None
                        }
                    };

                    let result = run_with_service_and_lock(service, uhid, shutdown, operation_lock);
                    if let Some(rt) = agent_runtime {
                        rt.shutdown();
                    }
                    endpoint_manager.cancel_all();
                    let _ = endpoint_manager.shutdown_all(None);
                    result
                }
                #[cfg(feature = "tpm")]
                BackendConfig::Tpm { path, tcti } => {
                    let storage = TpmStorageAdapter::new_with_options(
                        path.clone().into(),
                        Some(tcti.clone()),
                        allow_storage_creation,
                    )?;
                    let boxed: Box<dyn CredentialStorage> = Box::new(storage);
                    let shared_storage = Arc::new(Mutex::new(boxed));
                    let pin_storage = TpmPinStorage::new(path.into(), Some(tcti));
                    let pin_storage: Arc<Mutex<Box<dyn crate::pin_storage::PinStorage>>> =
                        Arc::new(Mutex::new(Box::new(pin_storage)));
                    let service = AuthenticatorService::with_shared_storage(
                        shared_storage.clone(),
                        Some(pin_storage.clone()),
                        security_config.clone(),
                        pin_config.clone(),
                    )?;

                    let agent_runtime = match agent::runtime::AgentRuntime::start(
                        shared_storage.clone(),
                        pin_storage.clone(),
                        operation_lock.clone(),
                        &config.agents,
                        security_config,
                        pin_config,
                        shutdown.clone(),
                    ) {
                        Ok(rt) => Some(rt),
                        Err(e) => {
                            warn!(
                                "Agent subsystem failed to start: {}; human path remains available",
                                e
                            );
                            None
                        }
                    };

                    let result = run_with_service_and_lock(service, uhid, shutdown, operation_lock);
                    if let Some(rt) = agent_runtime {
                        rt.shutdown();
                    }
                    endpoint_manager.cancel_all();
                    let _ = endpoint_manager.shutdown_all(None);
                    result
                }
            }
        }
        #[cfg(not(feature = "agent"))]
        {
            unreachable!()
        }
    } else {
        info!("Acquiring instance lock...");
        let _instance_lock = instance_lock::InstanceLock::acquire(&backend)?;
        debug!(
            "Instance lock acquired at {}",
            _instance_lock.lock_path().display()
        );

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

        let security_config = config.security_config();
        let pin_config = config.pin_config();
        let allow_storage_creation = allow_e2e_storage_creation();

        match backend {
            BackendConfig::Local { path } => {
                let storage = LocalStorageAdapter::new_with_options(
                    path.clone().into(),
                    allow_storage_creation,
                )?;
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
                let storage = PassStorageAdapter::new_with_options(
                    store_path.clone().into(),
                    path.clone().into(),
                    gpg_backend,
                    allow_storage_creation,
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
                let storage = TpmStorageAdapter::new_with_options(
                    path.clone().into(),
                    Some(tcti.clone()),
                    allow_storage_creation,
                )?;
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
}
