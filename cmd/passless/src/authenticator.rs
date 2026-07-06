use crate::notification::show_verification_notification;
use crate::pin_storage::PinStorage;
use crate::storage::{CredentialFilter, CredentialStorage};
use crate::util::bytes_to_hex;

use passless_core::config::{PinConfig, PinEnforcement, SecurityConfig};

use soft_fido2::{
    Authenticator, AuthenticatorCallbacks, AuthenticatorConfig, AuthenticatorOptions, Credential,
    CredentialRef, CtapCommand, PinState, Result, StatusCode, UpResult, UvResult,
};

use std::sync::{Arc, LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use log::{debug, error, info, warn};

static VERSION: LazyLock<u32> = LazyLock::new(|| {
    let major = env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap_or(0);
    let minor = env!("CARGO_PKG_VERSION_MINOR").parse().unwrap_or(0);
    let patch = env!("CARGO_PKG_VERSION_PATCH").parse().unwrap_or(0);

    (major << 16) | (minor << 8) | patch
});

/// Passless vendor command for resetting built-in UV retries without deleting credentials.
pub const CMD_PASSLESS_RESET_UV_RETRIES: u8 = 0x42;

const DEFAULT_UV_RETRIES: u8 = 3;

type CustomCommandHandler =
    Arc<dyn Fn(&[u8]) -> core::result::Result<Vec<u8>, StatusCode> + Send + Sync>;

/// Wrapper to adapt passless PinStorage to soft-fido2 PinStorageCallbacks
struct PinStorageWrapper<P: PinStorage>(Arc<Mutex<P>>);

impl<P: PinStorage + 'static> soft_fido2::PinStorageCallbacks for PinStorageWrapper<P> {
    fn load_pin_state(&self) -> std::result::Result<PinState, soft_fido2::StatusCode> {
        let storage = self.0.lock().map_err(|_| soft_fido2::StatusCode::Other)?;
        storage.load_pin_state()
    }

    fn save_pin_state(&self, state: &PinState) -> std::result::Result<(), soft_fido2::StatusCode> {
        let storage = self.0.lock().map_err(|_| soft_fido2::StatusCode::Other)?;
        storage.save_pin_state(state)
    }
}

/// Passless authenticator callbacks implementation
pub struct PasslessCallbacks<S: CredentialStorage, P: PinStorage> {
    storage: Arc<Mutex<S>>,
    pin_storage: Option<Arc<Mutex<P>>>,
    security_config: SecurityConfig,
    pin_config: PinConfig,
}

impl<S: CredentialStorage, P: PinStorage> PasslessCallbacks<S, P> {
    pub fn new(
        storage: Arc<Mutex<S>>,
        pin_storage: Option<Arc<Mutex<P>>>,
        security_config: SecurityConfig,
        pin_config: PinConfig,
    ) -> Self {
        Self {
            storage,
            pin_storage,
            security_config,
            pin_config,
        }
    }
}

impl<S: CredentialStorage, P: PinStorage> AuthenticatorCallbacks for PasslessCallbacks<S, P> {
    fn request_up(&self, info: &str, user: Option<&str>, rp: &str) -> Result<UpResult> {
        // Check for E2E test mode (only available in debug builds)
        #[cfg(debug_assertions)]
        {
            if std::env::var("PASSLESS_E2E_AUTO_ACCEPT_UV").is_ok() {
                info!("E2E test mode: Auto-accepting user verification");
                return Ok(UpResult::Accepted);
            }
        }

        let is_registration = info.to_lowercase().contains("registration")
            && !info.to_lowercase().contains("credential excluded");

        let should_verify = if is_registration {
            self.security_config.user_verification_registration
        } else {
            self.security_config.user_verification_authentication
        };

        let storage = match self.storage.lock() {
            Ok(s) => s,
            Err(_) => {
                error!("Failed to acquire storage lock during user verification request");
                return Err(soft_fido2::Error::Other);
            }
        };

        if storage.disable_user_verification() && !is_registration && !should_verify {
            debug!("User verification handled by backend (e.g., GPG): {}", info);
            return Ok(UpResult::Accepted);
        }

        if !should_verify {
            debug!(
                "User verification disabled for {}: {}",
                if is_registration {
                    "registration"
                } else {
                    "authentication"
                },
                info
            );
            return Ok(UpResult::Accepted);
        }

        match show_verification_notification(
            info,
            Some(rp),
            user,
            self.security_config.notification_timeout,
        ) {
            Ok(crate::notification::NotificationResult::Accepted) => Ok(UpResult::Accepted),
            Ok(crate::notification::NotificationResult::Denied) => Ok(UpResult::Denied),
            Err(e) => {
                error!("Failed to show notification: {}", e);
                Err(soft_fido2::Error::Other)
            }
        }
    }

    fn request_uv(&self, info: &str, user: Option<&str>, rp: &str) -> Result<UvResult> {
        // Check for E2E test mode (only available in debug builds)
        #[cfg(debug_assertions)]
        {
            if std::env::var("PASSLESS_E2E_AUTO_ACCEPT_UV").is_ok() {
                info!("E2E test mode: Auto-accepting user verification");
                return Ok(UvResult::Accepted);
            }
        }

        // Check if PIN is set and apply enforcement policy
        if let Some(pin_storage) = &self.pin_storage
            && let storage = pin_storage.lock().map_err(|_| soft_fido2::Error::Other)?
            && let Ok(state) = storage.load_pin_state()
            && state.is_pin_set()
        {
            match self.pin_config.enforcement {
                PinEnforcement::Required => {
                    info!("PIN is set and enforcement=required, denying built-in UV to force PIN");
                    return Ok(UvResult::Denied);
                }
                PinEnforcement::Optional => {
                    if self.security_config.always_uv {
                        info!(
                            "PIN is set, always_uv=true, enforcement=optional, denying built-in UV"
                        );
                        return Ok(UvResult::Denied);
                    }
                    info!(
                        "PIN is set, always_uv=false, enforcement=optional, using notification fallback"
                    );
                }
                PinEnforcement::Never => {
                    info!("PIN is set but enforcement=never, using notification fallback");
                }
            }
        }

        // No PIN set or enforcement allows notification fallback
        // Return AcceptedWithUp since notification-based UV also captures user presence
        match show_verification_notification(
            info,
            Some(rp),
            user,
            self.security_config.notification_timeout,
        ) {
            Ok(crate::notification::NotificationResult::Accepted) => {
                info!("User verification via notification: accepted");
                Ok(UvResult::AcceptedWithUp)
            }
            Ok(crate::notification::NotificationResult::Denied) => {
                warn!("User verification via notification: denied");
                Ok(UvResult::Denied)
            }
            Err(e) => {
                error!("Failed to show notification: {}", e);
                Err(soft_fido2::Error::Other)
            }
        }
    }

    fn write_credential(&self, credential: &CredentialRef) -> Result<()> {
        info!("Storing credential for RP: {}", credential.rp_id);
        debug!("Credential ID: {}", bytes_to_hex(credential.id));

        let mut storage = match self.storage.lock() {
            Ok(s) => s,
            Err(_) => {
                error!("Failed to acquire storage lock while writing credential");
                return Err(soft_fido2::Error::Other);
            }
        };

        storage.write(*credential)?;
        info!(
            "Credential persisted successfully for RP: {}",
            credential.rp_id
        );
        Ok(())
    }

    fn read_credential(&self, cred_id: &[u8]) -> Result<Option<Credential>> {
        debug!("Reading credential: id={}", bytes_to_hex(cred_id));

        let mut storage = match self.storage.lock() {
            Ok(s) => s,
            Err(_) => {
                error!("Failed to acquire storage lock while reading credential");
                return Err(soft_fido2::Error::Other);
            }
        };

        match storage.read(cred_id) {
            Ok(cred) => {
                debug!("Credential found");
                Ok(Some(cred))
            }
            Err(_) => {
                debug!("Credential not found");
                Ok(None)
            }
        }
    }

    fn delete_credential(&self, cred_id: &[u8]) -> Result<()> {
        info!("Removing credential ID: {}", bytes_to_hex(cred_id));

        let mut storage = match self.storage.lock() {
            Ok(s) => s,
            Err(_) => {
                error!("Failed to acquire storage lock while deleting credential");
                return Err(soft_fido2::Error::Other);
            }
        };

        storage.delete(cred_id)?;
        debug!("Credential removed");
        Ok(())
    }

    fn list_credentials(&self, rp_id: &str, _user_id: Option<&[u8]>) -> Result<Vec<Credential>> {
        info!("Listing credentials for RP: {}", rp_id);

        let mut storage = match self.storage.lock() {
            Ok(s) => s,
            Err(e) => {
                error!(
                    "Failed to acquire storage lock while listing credentials: {}",
                    e
                );
                return Err(soft_fido2::Error::Other);
            }
        };

        let filter = CredentialFilter::ByRp(rp_id.to_string());

        let mut credentials = Vec::new();

        match storage.read_first(filter) {
            Ok(first_cred) => {
                info!(
                    "Found first credential for RP {}: id={}",
                    rp_id,
                    bytes_to_hex(&first_cred.id)
                );
                credentials.push(first_cred);

                while let Ok(cred) = storage.read_next() {
                    info!("Found additional credential: id={}", bytes_to_hex(&cred.id));
                    credentials.push(cred);
                }
            }
            Err(e) => {
                debug!("No credentials found for RP {}: {:?}", rp_id, e);
            }
        }

        info!(
            "Total credentials found for RP {}: {}",
            rp_id,
            credentials.len()
        );
        Ok(credentials)
    }

    fn enumerate_rps(&self) -> Result<Vec<(String, Option<String>, usize)>> {
        debug!("Enumerating relying parties");

        let mut storage = match self.storage.lock() {
            Ok(s) => s,
            Err(_) => {
                error!("Failed to acquire storage lock while enumerating RPs");
                return Err(soft_fido2::Error::Other);
            }
        };

        let filter = CredentialFilter::None;
        let mut all_credentials = Vec::new();

        if let Ok(first_cred) = storage.read_first(filter) {
            all_credentials.push(first_cred);

            while let Ok(cred) = storage.read_next() {
                all_credentials.push(cred);
            }
        }

        use std::collections::HashMap;
        let mut rp_map: HashMap<String, (Option<String>, usize)> = HashMap::new();

        for cred in all_credentials {
            let entry = rp_map
                .entry(cred.rp.id.clone())
                .or_insert((cred.rp.name.clone(), 0));
            entry.1 += 1;
        }

        let result: Vec<(String, Option<String>, usize)> = rp_map
            .into_iter()
            .map(|(rp_id, (rp_name, count))| (rp_id, rp_name, count))
            .collect();

        debug!("Found {} relying parties", result.len());
        Ok(result)
    }

    fn credential_count(&self) -> Result<usize> {
        debug!("Counting total credentials");

        let storage = match self.storage.lock() {
            Ok(s) => s,
            Err(_) => {
                error!("Failed to acquire storage lock while counting credentials");
                return Err(soft_fido2::Error::Other);
            }
        };

        let count = storage.count_credentials();
        debug!("Total credentials: {}", count);
        Ok(count)
    }

    fn get_timestamp_ms(&self) -> u64 {
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        since_the_epoch.as_millis() as u64
    }
}

impl<S: CredentialStorage, P: PinStorage> soft_fido2::PinStorageCallbacks
    for PasslessCallbacks<S, P>
{
    fn load_pin_state(&self) -> std::result::Result<PinState, soft_fido2::StatusCode> {
        if let Some(pin_storage) = &self.pin_storage {
            let storage = pin_storage
                .lock()
                .map_err(|_| soft_fido2::StatusCode::Other)?;
            storage.load_pin_state()
        } else {
            Ok(PinState::new())
        }
    }

    fn save_pin_state(&self, state: &PinState) -> std::result::Result<(), soft_fido2::StatusCode> {
        if let Some(pin_storage) = &self.pin_storage {
            let storage = pin_storage
                .lock()
                .map_err(|_| soft_fido2::StatusCode::Other)?;
            storage.save_pin_state(state)
        } else {
            Ok(())
        }
    }
}

/// Main authenticator service
///
/// This service orchestrates the FIDO2 authenticator:
/// - Storage is injected through the CredentialStorage trait
/// - Handles CTAP requests and generates responses
pub struct AuthenticatorService<S: CredentialStorage, P: PinStorage = ()> {
    /// The underlying soft_fido2 authenticator
    pub authenticator: Authenticator<PasslessCallbacks<S, P>>,
    /// Storage backend (injected dependency)
    pub storage: Arc<Mutex<S>>,
    /// Optional PIN state storage backend
    pin_storage: Option<Arc<Mutex<P>>>,
    security_config: SecurityConfig,
    pin_config: PinConfig,
    custom_commands: Vec<(u8, CustomCommandHandler)>,
}

impl<S: CredentialStorage + 'static> AuthenticatorService<S, ()> {
    /// Create a new authenticator service without PIN storage
    #[allow(dead_code)]
    pub fn new(storage: S, security_config: SecurityConfig, pin_config: PinConfig) -> Result<Self> {
        Self::with_pin_storage(storage, None, security_config, pin_config)
    }
}

impl<S: CredentialStorage + 'static, P: PinStorage + 'static> AuthenticatorService<S, P> {
    fn build_authenticator(
        storage: Arc<Mutex<S>>,
        pin_storage: Option<Arc<Mutex<P>>>,
        security_config: SecurityConfig,
        pin_config: PinConfig,
    ) -> Result<Authenticator<PasslessCallbacks<S, P>>> {
        // Hardcoded authenticator options (FIDO2 spec compliant)
        // These are platform authenticator defaults and shouldn't need configuration
        let options = AuthenticatorOptions {
            rk: true,                      // Resident keys (passkeys)
            up: true,                      // User presence
            uv: Some(true),                // Notification-based user verification
            plat: true,                    // Platform authenticator
            client_pin: Some(true),        // Client PIN capability
            pin_uv_auth_token: Some(true), // PIN/UV auth token support
            cred_mgmt: Some(true),         // Credential management
            bio_enroll: None,              // No biometric enrollment
            large_blobs: None,             // No large blob storage
            ep: None,                      // Enterprise attestation not enabled
            always_uv: Some(security_config.always_uv),
            make_cred_uv_not_required: Some(true),
        };

        let config = AuthenticatorConfig::builder()
            .aaguid([
                // "fido.passless.rs"
                0x66, 0x69, 0x64, 0x6F, 0x2E, 0x70, 0x61, 0x73, 0x73, 0x6C, 0x65, 0x73, 0x73, 0x2E,
                0x72, 0x73,
            ])
            .options(options)
            .commands(vec![
                CtapCommand::MakeCredential,
                CtapCommand::GetAssertion,
                CtapCommand::GetInfo,
                CtapCommand::ClientPin,
                CtapCommand::GetNextAssertion,
                CtapCommand::Selection,
            ])
            .max_credentials(100)
            .extensions(vec!["credProtect".to_string()])
            .firmware_version(*VERSION)
            .constant_sign_count(security_config.constant_signature_counter)
            .algorithms(vec![-7])
            .max_pin_retries(pin_config.max_retries)
            .auto_lock_timeout(pin_config.auto_lock_timeout)
            .build();

        let callbacks =
            PasslessCallbacks::new(storage, pin_storage.clone(), security_config, pin_config);

        if let Some(ps) = pin_storage {
            Authenticator::with_config_and_pin_storage(callbacks, config, PinStorageWrapper(ps))
        } else {
            Authenticator::with_config(callbacks, config)
        }
    }

    /// Create a new authenticator service with optional PIN storage
    pub fn with_pin_storage(
        storage: S,
        pin_storage: Option<Arc<Mutex<P>>>,
        security_config: SecurityConfig,
        pin_config: PinConfig,
    ) -> Result<Self> {
        let storage = Arc::new(Mutex::new(storage));
        let authenticator = Self::build_authenticator(
            storage.clone(),
            pin_storage.clone(),
            security_config.clone(),
            pin_config.clone(),
        )?;

        Ok(Self {
            authenticator,
            storage,
            pin_storage,
            security_config,
            pin_config,
            custom_commands: Vec::new(),
        })
    }

    fn rebuild_authenticator(&mut self) -> Result<()> {
        let mut authenticator = Self::build_authenticator(
            self.storage.clone(),
            self.pin_storage.clone(),
            self.security_config.clone(),
            self.pin_config.clone(),
        )?;

        for (command, handler) in &self.custom_commands {
            let handler = handler.clone();
            authenticator.register_custom_command(*command, move |request| handler(request));
        }

        self.authenticator = authenticator;
        Ok(())
    }

    fn reset_uv_retries(&mut self) -> core::result::Result<(), StatusCode> {
        let Some(pin_storage) = &self.pin_storage else {
            return Err(StatusCode::NotAllowed);
        };

        {
            let storage = pin_storage.lock().map_err(|_| StatusCode::Other)?;
            let mut state = storage.load_pin_state()?;
            state.uv_retries = DEFAULT_UV_RETRIES;
            storage.save_pin_state(&state)?;
        }

        self.rebuild_authenticator().map_err(|e| {
            error!(
                "Failed to rebuild authenticator after UV retry reset: {:?}",
                e
            );
            StatusCode::Other
        })?;

        Ok(())
    }

    /// Process a CTAP request and generate a response
    /// Ok(()) on success or an error
    pub fn handle(&mut self, request: &[u8], response_buffer: &mut Vec<u8>) -> Result<()> {
        if request.first() == Some(&CMD_PASSLESS_RESET_UV_RETRIES) {
            response_buffer.clear();
            if request.len() != 1 {
                response_buffer.push(StatusCode::InvalidParameter as u8);
                return Ok(());
            }

            match self.reset_uv_retries() {
                Ok(()) => {
                    response_buffer.push(0x00);
                    response_buffer.push(0xa0);
                }
                Err(status) => response_buffer.push(status as u8),
            }
            return Ok(());
        }

        self.authenticator.handle(request, response_buffer)?;
        Ok(())
    }

    /// Get storage information
    pub fn storage_info(&self) -> String {
        let storage = self.storage.lock().unwrap();
        format!("Credentials in storage: {}", storage.count_credentials())
    }

    /// Register a custom CTAP command handler
    ///
    /// This allows registering vendor-specific commands (0x40-0xFF range).
    /// Useful for compatibility with different authenticator variants.
    ///
    /// # Arguments
    ///
    /// * `command` - Command byte (0x40-0xFF vendor range)
    /// * `handler` - Handler function that processes the command
    pub fn register_custom_command<F>(&mut self, command: u8, handler: F)
    where
        F: Fn(&[u8]) -> core::result::Result<Vec<u8>, soft_fido2::StatusCode>
            + Send
            + Sync
            + 'static,
    {
        let handler: CustomCommandHandler = Arc::new(handler);
        let registered_handler = handler.clone();
        self.authenticator
            .register_custom_command(command, move |request| registered_handler(request));
        self.custom_commands.push((command, handler));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::pin_storage::{LocalPinStorage, PinStorage};
    use crate::storage::LocalStorageAdapter;

    #[test]
    fn test_service_creation() {
        let temp_dir = std::env::temp_dir().join("test_passless");
        if let Err(e) = std::fs::create_dir_all(&temp_dir) {
            panic!("Failed to create temp directory: {}", e);
        }
        let storage = match LocalStorageAdapter::new(temp_dir.clone()) {
            Ok(s) => s,
            Err(e) => panic!("Failed to create local storage: {}", e),
        };

        let security_config = SecurityConfig {
            check_mlock: false,
            disable_core_dumps: false,
            constant_signature_counter: false,
            always_uv: true,
            user_verification_registration: true,
            user_verification_authentication: true,
            notification_timeout: 30,
        };

        let pin_config = PinConfig::default();

        let service = AuthenticatorService::new(storage, security_config, pin_config);
        assert!(service.is_ok(), "Service creation should succeed");

        // Cleanup
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_reset_uv_retries_command_persists_and_reloads() {
        let temp_dir = std::env::temp_dir().join("test_passless_reset_uv_retries");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).expect("Failed to create temp directory");

        let storage =
            LocalStorageAdapter::new(temp_dir.clone()).expect("Failed to create local storage");
        let pin_storage = LocalPinStorage::new(temp_dir.clone());
        let mut pin_state = PinState::new();
        pin_state.uv_retries = 0;
        pin_storage
            .save_pin_state(&pin_state)
            .expect("Failed to save PIN state");

        let pin_storage = Arc::new(Mutex::new(pin_storage));
        let mut service = AuthenticatorService::with_pin_storage(
            storage,
            Some(pin_storage.clone()),
            SecurityConfig::default(),
            PinConfig::default(),
        )
        .expect("Service creation should succeed");

        let mut response = Vec::new();
        service
            .handle(&[CMD_PASSLESS_RESET_UV_RETRIES], &mut response)
            .expect("UV retry reset command should be handled");

        assert_eq!(response, vec![0x00, 0xa0]);

        let persisted_state = pin_storage
            .lock()
            .expect("Failed to lock PIN storage")
            .load_pin_state()
            .expect("Failed to load PIN state");
        assert_eq!(persisted_state.uv_retries, DEFAULT_UV_RETRIES);

        let mut uv_retries_response = Vec::new();
        service
            .handle(&[0x06, 0xa1, 0x02, 0x07], &mut uv_retries_response)
            .expect("getUvRetries command should be handled");

        assert_eq!(
            uv_retries_response,
            vec![0x00, 0xa1, 0x05, DEFAULT_UV_RETRIES]
        );

        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
