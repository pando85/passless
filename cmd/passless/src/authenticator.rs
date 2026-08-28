#[cfg(feature = "agent")]
use crate::agent::interaction::{AgentInteractionManager, action_from_info};
use crate::credential_backup::{
    BACKUP_COMMIT_SUBCOMMAND, BACKUP_PREPARE_SUBCOMMAND, BackupError, CMD_PASSLESS_BACKUP,
    CMD_PASSLESS_RESTORE, backup_commit_auth_data, backup_prepare_auth_data, bundle_token,
    decrypt_credential, encrypt_credential, restore_auth_data,
};
use crate::notification::{show_user_presence_notification, show_verification_notification};
use crate::pin_storage::PinStorage;
use crate::storage::{CredentialFilter, CredentialStorage};
use crate::util::bytes_to_hex;

use passless_core::config::{PinConfig, PinEnforcement, SecurityConfig};

use soft_fido2::{
    Authenticator, AuthenticatorCallbacks, AuthenticatorConfig, AuthenticatorOptions,
    BuiltInUvState, Credential, CredentialBackupState, CredentialKeyProvider, CredentialRef,
    CtapCommand, Error as SoftFido2Error, PinState, Result, SoftwareCredentialKeyProvider,
    StatusCode, UpResult, UvResult,
};

use std::collections::HashMap;
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

pub const RESET_UV_RETRIES_SUBCOMMAND: u8 = 0x01;

fn error_status_byte(error: SoftFido2Error) -> u8 {
    match error {
        SoftFido2Error::CtapError(code) => code,
        error => StatusCode::from(error) as u8,
    }
}

fn backup_state_for_export(
    source: CredentialBackupState,
) -> core::result::Result<CredentialBackupState, BackupError> {
    if !source.is_eligible() {
        return Err(BackupError::UnsupportedCredential);
    }
    Ok(CredentialBackupState::BackedUp)
}

/// Classification of UV retry count transitions for diagnostic logging
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UvRetryTransition {
    Initialized,
    NoChange,
    NormalChange,
    Low,
    Exhausted,
    Recovered,
}

/// Wrapper to adapt passless PinStorage to soft-fido2 PinStorageCallbacks
///
/// This wrapper intercepts PIN state load/save operations to enforce the configured
/// max_uv_retries limit. We clamp the uv_retries value to the configured maximum during
/// persistence as a safety measure to ensure the configured limit is always respected.
///
/// It also tracks UV retry transitions to emit actionable warnings when retries
/// approach or reach exhaustion, independent of the storage backend.
struct PinStorageWrapper<P: PinStorage> {
    storage: Arc<Mutex<P>>,
    max_uv_retries: u8,
    last_uv_retries: Mutex<Option<u8>>,
}

impl<P: PinStorage> PinStorageWrapper<P> {
    fn clamp_uv_retries(&self, state: &mut PinState) {
        if state.uv_retries > self.max_uv_retries {
            state.uv_retries = self.max_uv_retries;
        }
    }

    fn classify_uv_transition(old: Option<u8>, new: u8) -> UvRetryTransition {
        match old {
            None => UvRetryTransition::Initialized,
            Some(prev) if prev == new => UvRetryTransition::NoChange,
            Some(prev) if new == 0 && prev > 0 => UvRetryTransition::Exhausted,
            Some(prev) if new == 1 && prev > 1 => UvRetryTransition::Low,
            Some(prev) if new > prev && prev == 0 => UvRetryTransition::Recovered,
            Some(_) => UvRetryTransition::NormalChange,
        }
    }

    fn log_uv_retry_transition(&self, old: Option<u8>, new: u8) {
        match Self::classify_uv_transition(old, new) {
            UvRetryTransition::Initialized => {
                debug!("UV retries initialized: {} remaining", new);
            }
            UvRetryTransition::NoChange => {}
            UvRetryTransition::Exhausted => {
                error!(
                    "UV retries exhausted; built-in user verification is blocked. \
                     Run `passless client pin uv-reset` to restore UV retries"
                );
            }
            UvRetryTransition::Low => {
                warn!(
                    "UV retry limit is almost exhausted: 1 attempt remaining. \
                     Run `passless client pin uv-reset` to restore UV retries"
                );
            }
            UvRetryTransition::Recovered => {
                info!("UV retries restored from 0 to {} (reset/recovery)", new);
            }
            UvRetryTransition::NormalChange => {
                debug!(
                    "UV retries changed: {} -> {} remaining",
                    old.unwrap_or(0),
                    new
                );
            }
        }
    }
}

impl<P: PinStorage + 'static> soft_fido2::PinStorageCallbacks for PinStorageWrapper<P> {
    fn load_pin_state(&self) -> std::result::Result<PinState, soft_fido2::StatusCode> {
        let storage = self
            .storage
            .lock()
            .map_err(|_| soft_fido2::StatusCode::Other)?;
        let mut state = storage.load_pin_state()?;
        self.clamp_uv_retries(&mut state);
        let mut last = self
            .last_uv_retries
            .lock()
            .map_err(|_| soft_fido2::StatusCode::Other)?;
        *last = Some(state.uv_retries);
        Ok(state)
    }

    fn save_pin_state(&self, state: &PinState) -> std::result::Result<(), soft_fido2::StatusCode> {
        let storage = self
            .storage
            .lock()
            .map_err(|_| soft_fido2::StatusCode::Other)?;
        let mut clamped_state = state.clone();
        self.clamp_uv_retries(&mut clamped_state);
        storage.save_pin_state(&clamped_state)?;
        let old = {
            let mut last = self
                .last_uv_retries
                .lock()
                .map_err(|_| soft_fido2::StatusCode::Other)?;
            let old = *last;
            *last = Some(clamped_state.uv_retries);
            old
        };
        self.log_uv_retry_transition(old, clamped_state.uv_retries);
        Ok(())
    }
}

/// Passless authenticator callbacks implementation
pub struct PasslessCallbacks<S: CredentialStorage, P: PinStorage> {
    storage: Arc<Mutex<S>>,
    pin_storage: Option<Arc<Mutex<P>>>,
    security_config: SecurityConfig,
    pin_config: PinConfig,
    #[cfg(feature = "agent")]
    interaction_manager: Option<Arc<AgentInteractionManager>>,
    #[cfg(feature = "agent")]
    isolated_mode: bool,
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
            #[cfg(feature = "agent")]
            interaction_manager: None,
            #[cfg(feature = "agent")]
            isolated_mode: false,
        }
    }

    #[cfg(feature = "agent")]
    pub fn with_interaction_manager(
        storage: Arc<Mutex<S>>,
        pin_storage: Option<Arc<Mutex<P>>>,
        security_config: SecurityConfig,
        pin_config: PinConfig,
        interaction_manager: Arc<AgentInteractionManager>,
        isolated_mode: bool,
    ) -> Self {
        Self {
            storage,
            pin_storage,
            security_config,
            pin_config,
            interaction_manager: Some(interaction_manager),
            isolated_mode,
        }
    }
}

impl<S: CredentialStorage, P: PinStorage> AuthenticatorCallbacks for PasslessCallbacks<S, P> {
    fn request_up(&self, info: &str, user: Option<&str>, rp: &str) -> Result<UpResult> {
        #[cfg(feature = "agent")]
        {
            if let Some(ref manager) = self.interaction_manager {
                let action = action_from_info(info);
                let generation = 0;
                match manager.try_consume_up(rp, action, generation) {
                    Some(result) => {
                        debug!("Agent interaction override for UP: {:?}", result);
                        return Ok(result);
                    }
                    None => {
                        if manager.has_active_token() {
                            debug!(
                                "Agent interaction token active, auto-approving UP for rp={}",
                                rp
                            );
                            return Ok(UpResult::Accepted);
                        }
                    }
                }
                if self.isolated_mode {
                    debug!("Isolated mode: auto-approving UP for rp={}", rp);
                    return Ok(UpResult::Accepted);
                }
            }
        }

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

        match show_user_presence_notification(
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
        #[cfg(feature = "agent")]
        {
            if let Some(ref manager) = self.interaction_manager {
                let action = action_from_info(info);
                let generation = 0;
                match manager.try_consume_uv(rp, action, generation) {
                    Some(result) => {
                        debug!("Agent interaction override for UV: {:?}", result);
                        return Ok(result);
                    }
                    None => {
                        if manager.has_active_token() {
                            debug!(
                                "Agent interaction token active, auto-approving UV for rp={}",
                                rp
                            );
                            return Ok(UvResult::AcceptedWithUp);
                        }
                    }
                }
                if self.isolated_mode {
                    debug!("Isolated mode: auto-approving UV for rp={}", rp);
                    return Ok(UvResult::AcceptedWithUp);
                }
            }
        }

        #[cfg(debug_assertions)]
        {
            if std::env::var("PASSLESS_E2E_AUTO_ACCEPT_UV").is_ok() {
                info!("E2E test mode: Auto-accepting user verification");
                return Ok(UvResult::Accepted);
            }
        }

        let pin_set;
        let uv_retries;

        if let Some(pin_storage) = &self.pin_storage {
            let storage = pin_storage.lock().map_err(|_| soft_fido2::Error::Other)?;
            match storage.load_pin_state() {
                Ok(state) => {
                    pin_set = state.is_pin_set();
                    uv_retries = Some(state.uv_retries);
                }
                Err(e) => {
                    debug!("Failed to load PIN state for UV request: {:?}", e);
                    pin_set = false;
                    uv_retries = None;
                }
            }
        } else {
            pin_set = false;
            uv_retries = None;
        }

        if let Some(retries) = uv_retries {
            debug!(
                "UV request: pin_set={}, uv_retries={}, enforcement={}, always_uv={}",
                pin_set, retries, self.pin_config.enforcement, self.security_config.always_uv,
            );
            if retries == 0 {
                warn!(
                    "Built-in UV is blocked (0 retries remaining); \
                     falling back to notification-based verification because \
                     pin.enforcement={}",
                    self.pin_config.enforcement,
                );
            }
        }

        if pin_set {
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
            Err(soft_fido2::Error::DoesNotExist) => {
                debug!("Credential not found");
                Ok(None)
            }
            Err(e) => {
                error!("Storage error reading credential: {:?}", e);
                Err(e)
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
        if let Err(e) = crate::storage::ValidatedRpId::try_from(rp_id) {
            warn!(
                "Rejected list_credentials for invalid RP ID '{}': {}",
                rp_id, e
            );
            return Err(soft_fido2::Error::Other);
        }

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

        let result: Vec<_> = storage
            .list_relying_parties()?
            .into_iter()
            .map(|metadata| (metadata.id, metadata.name, metadata.credential_count))
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
        debug!("Total credentials found: {}", count);
        Ok(count)
    }

    fn get_timestamp_ms(&self) -> u64 {
        let start = SystemTime::now();
        let since_the_epoch = start.duration_since(UNIX_EPOCH).unwrap_or_default();
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

#[derive(Debug, Clone, Copy)]
struct BuiltInUvPolicy;

/// Main authenticator service
///
/// This service orchestrates the FIDO2 authenticator:
/// - Storage is injected through the CredentialStorage trait
/// - Handles CTAP requests and generates responses
pub struct AuthenticatorService<
    S: CredentialStorage,
    P: PinStorage = (),
    K: CredentialKeyProvider = SoftwareCredentialKeyProvider,
> {
    /// The underlying soft_fido2 authenticator
    pub authenticator: Authenticator<PasslessCallbacks<S, P>, K>,
    /// Storage backend (injected dependency)
    pub storage: Arc<Mutex<S>>,
    /// Dynamic built-in UV policy; absent for agent authenticators.
    built_in_uv_policy: Option<BuiltInUvPolicy>,
    /// Maximum UV retries (configured value)
    max_uv_retries: u8,
    /// Runtime feature gate for credential export/import.
    credential_backup_enabled: bool,
    /// False for TPM and other non-exportable key providers.
    credential_backup_supported: bool,
    /// Prepared bundles awaiting durable client-side persistence confirmation.
    pending_backups: HashMap<Vec<u8>, [u8; 32]>,
    /// PIN storage for checking whether a PIN is configured
    pin_storage: Option<Arc<Mutex<P>>>,
}

impl<S: CredentialStorage + 'static> AuthenticatorService<S, (), SoftwareCredentialKeyProvider> {
    /// Create a new authenticator service without PIN storage
    #[allow(dead_code)]
    pub fn new(storage: S, security_config: SecurityConfig, pin_config: PinConfig) -> Result<Self> {
        Self::with_shared_storage(
            Arc::new(Mutex::new(storage)),
            None,
            security_config,
            pin_config,
        )
    }
}

impl<S: CredentialStorage + 'static, P: PinStorage + 'static>
    AuthenticatorService<S, P, SoftwareCredentialKeyProvider>
{
    fn build_authenticator(
        storage: Arc<Mutex<S>>,
        pin_storage: Option<Arc<Mutex<P>>>,
        security_config: SecurityConfig,
        pin_config: PinConfig,
    ) -> Result<Authenticator<PasslessCallbacks<S, P>>> {
        #[cfg(feature = "agent")]
        {
            Self::build_authenticator_with_interaction(
                storage,
                pin_storage,
                security_config,
                pin_config,
                None,
            )
        }
        #[cfg(not(feature = "agent"))]
        {
            let options = AuthenticatorOptions {
                rk: true,
                up: true,
                uv: Some(true),
                plat: true,
                client_pin: Some(true),
                pin_uv_auth_token: Some(true),
                cred_mgmt: Some(true),
                bio_enroll: None,
                large_blobs: None,
                ep: None,
                always_uv: Some(security_config.always_uv),
                make_cred_uv_not_required: Some(true),
            };

            let config = AuthenticatorConfig::builder()
                .aaguid([
                    0x66, 0x69, 0x64, 0x6F, 0x2E, 0x70, 0x61, 0x73, 0x73, 0x6C, 0x65, 0x73, 0x73,
                    0x2E, 0x72, 0x73,
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
                .default_credential_backup_state(if security_config.enable_credential_backup {
                    CredentialBackupState::Eligible
                } else {
                    CredentialBackupState::NotEligible
                })
                .algorithms(vec![-7])
                .max_pin_retries(pin_config.max_retries)
                .auto_lock_timeout(pin_config.auto_lock_timeout)
                .build();

            let callbacks = PasslessCallbacks::new(
                storage,
                pin_storage.clone(),
                security_config,
                pin_config.clone(),
            );

            let authenticator = if let Some(ps) = pin_storage {
                Authenticator::with_config_and_pin_storage(
                    callbacks,
                    config,
                    PinStorageWrapper {
                        storage: ps,
                        max_uv_retries: pin_config.max_uv_retries,
                        last_uv_retries: Mutex::new(None),
                    },
                )
            } else {
                Authenticator::with_config(callbacks, config)
            }?;

            Ok(authenticator)
        }
    }

    #[cfg(feature = "agent")]
    fn build_authenticator_with_interaction(
        storage: Arc<Mutex<S>>,
        pin_storage: Option<Arc<Mutex<P>>>,
        security_config: SecurityConfig,
        pin_config: PinConfig,
        interaction_manager: Option<Arc<AgentInteractionManager>>,
    ) -> Result<Authenticator<PasslessCallbacks<S, P>>> {
        Self::build_authenticator_with_interaction_and_options(
            storage,
            pin_storage,
            security_config,
            pin_config,
            interaction_manager,
            true,
        )
    }

    #[cfg(feature = "agent")]
    fn build_authenticator_with_interaction_and_options(
        storage: Arc<Mutex<S>>,
        pin_storage: Option<Arc<Mutex<P>>>,
        security_config: SecurityConfig,
        pin_config: PinConfig,
        interaction_manager: Option<Arc<AgentInteractionManager>>,
        use_agent_options: bool,
    ) -> Result<Authenticator<PasslessCallbacks<S, P>>> {
        let is_agent = use_agent_options;

        let options = if is_agent {
            AuthenticatorOptions {
                rk: true,
                up: true,
                uv: Some(false),
                plat: true,
                client_pin: Some(true),
                pin_uv_auth_token: Some(true),
                cred_mgmt: Some(true),
                bio_enroll: None,
                large_blobs: None,
                ep: None,
                always_uv: Some(true),
                make_cred_uv_not_required: Some(false),
            }
        } else {
            AuthenticatorOptions {
                rk: true,
                up: true,
                uv: Some(true),
                plat: true,
                client_pin: Some(true),
                pin_uv_auth_token: Some(true),
                cred_mgmt: Some(true),
                bio_enroll: None,
                large_blobs: None,
                ep: None,
                always_uv: Some(security_config.always_uv),
                make_cred_uv_not_required: Some(true),
            }
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
            .default_credential_backup_state(CredentialBackupState::NotEligible)
            .algorithms(vec![-7])
            .max_pin_retries(pin_config.max_retries)
            .auto_lock_timeout(pin_config.auto_lock_timeout)
            .build();

        let callbacks = match interaction_manager {
            Some(ref mgr) => PasslessCallbacks::with_interaction_manager(
                storage,
                pin_storage.clone(),
                security_config,
                pin_config.clone(),
                mgr.clone(),
                use_agent_options,
            ),
            None => PasslessCallbacks::new(
                storage,
                pin_storage.clone(),
                security_config,
                pin_config.clone(),
            ),
        };

        let authenticator = if let Some(ps) = pin_storage {
            Authenticator::with_config_and_pin_storage(
                callbacks,
                config,
                PinStorageWrapper {
                    storage: ps,
                    max_uv_retries: pin_config.max_uv_retries,
                    last_uv_retries: Mutex::new(None),
                },
            )?
        } else {
            Authenticator::with_config(callbacks, config)?
        };

        Ok(authenticator)
    }

    /// Create a new authenticator service with optional PIN storage
    pub fn with_pin_storage(
        storage: S,
        pin_storage: Option<Arc<Mutex<P>>>,
        security_config: SecurityConfig,
        pin_config: PinConfig,
    ) -> Result<Self> {
        let storage = Arc::new(Mutex::new(storage));
        Self::with_shared_storage(storage, pin_storage, security_config, pin_config)
    }

    /// Create a new authenticator service with shared (Arc-wrapped) storage
    ///
    /// This constructor accepts pre-wrapped `Arc<Mutex<S>>` and `Option<Arc<Mutex<P>>>`,
    /// allowing callers (such as `AgentStorageBundle`) to share ownership of the storage
    /// without moving it. Each call creates an independent `AuthenticatorService` that
    /// references the same underlying storage.
    pub fn with_shared_storage(
        storage: Arc<Mutex<S>>,
        pin_storage: Option<Arc<Mutex<P>>>,
        security_config: SecurityConfig,
        pin_config: PinConfig,
    ) -> Result<Self> {
        let authenticator = Self::build_authenticator(
            storage.clone(),
            pin_storage.clone(),
            security_config.clone(),
            pin_config.clone(),
        )?;

        let mut service = Self {
            authenticator,
            storage,
            built_in_uv_policy: Some(BuiltInUvPolicy),
            max_uv_retries: pin_config.max_uv_retries,
            credential_backup_enabled: security_config.enable_credential_backup,
            credential_backup_supported: true,
            pending_backups: HashMap::new(),
            pin_storage,
        };
        service.refresh_built_in_uv_state()?;
        Ok(service)
    }

    /// Create a new authenticator service with shared storage and an agent interaction manager
    ///
    /// The interaction manager allows agent ceremony code to install a one-shot token
    /// that overrides UP/UV prompts. When a matching token is present, callbacks consume
    /// it once and return the pre-decided result. Without a token, the human notification
    /// path is used. Token bytes are never serialized or logged.
    #[cfg(feature = "agent")]
    #[allow(dead_code)]
    pub fn with_shared_storage_and_interaction(
        storage: Arc<Mutex<S>>,
        pin_storage: Option<Arc<Mutex<P>>>,
        security_config: SecurityConfig,
        pin_config: PinConfig,
        interaction_manager: Arc<AgentInteractionManager>,
    ) -> Result<Self> {
        let authenticator = Self::build_authenticator_with_interaction(
            storage.clone(),
            pin_storage.clone(),
            security_config.clone(),
            pin_config.clone(),
            Some(interaction_manager),
        )?;

        Ok(Self {
            authenticator,
            storage,
            built_in_uv_policy: None,
            max_uv_retries: pin_config.max_uv_retries,
            credential_backup_enabled: security_config.enable_credential_backup,
            credential_backup_supported: true,
            pending_backups: HashMap::new(),
            pin_storage,
        })
    }
}

impl<
    S: CredentialStorage + 'static,
    P: PinStorage + 'static,
    K: CredentialKeyProvider + Send + Sync + 'static,
> AuthenticatorService<S, P, K>
{
    #[cfg(feature = "tpm")]
    fn build_authenticator_with_key_provider(
        storage: Arc<Mutex<S>>,
        pin_storage: Option<Arc<Mutex<P>>>,
        security_config: SecurityConfig,
        pin_config: PinConfig,
        key_provider: K,
    ) -> Result<Authenticator<PasslessCallbacks<S, P>, K>> {
        #[cfg(feature = "agent")]
        {
            Self::build_authenticator_with_interaction_and_key_provider(
                storage,
                pin_storage,
                security_config,
                pin_config,
                None,
                key_provider,
            )
        }
        #[cfg(not(feature = "agent"))]
        {
            let options = AuthenticatorOptions {
                rk: true,
                up: true,
                uv: Some(true),
                plat: true,
                client_pin: Some(true),
                pin_uv_auth_token: Some(true),
                cred_mgmt: Some(true),
                bio_enroll: None,
                large_blobs: None,
                ep: None,
                always_uv: Some(security_config.always_uv),
                make_cred_uv_not_required: Some(true),
            };

            let config = AuthenticatorConfig::builder()
                .aaguid([
                    0x66, 0x69, 0x64, 0x6F, 0x2E, 0x70, 0x61, 0x73, 0x73, 0x6C, 0x65, 0x73, 0x73,
                    0x2E, 0x72, 0x73,
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
                .default_credential_backup_state(if security_config.enable_credential_backup {
                    CredentialBackupState::Eligible
                } else {
                    CredentialBackupState::NotEligible
                })
                .algorithms(vec![-7])
                .max_pin_retries(pin_config.max_retries)
                .auto_lock_timeout(pin_config.auto_lock_timeout)
                .build();

            let callbacks = PasslessCallbacks::new(
                storage,
                pin_storage.clone(),
                security_config,
                pin_config.clone(),
            );

            let authenticator = if let Some(ps) = pin_storage {
                Authenticator::with_config_and_pin_storage_and_key_provider(
                    callbacks,
                    config,
                    PinStorageWrapper {
                        storage: ps,
                        max_uv_retries: pin_config.max_uv_retries,
                        last_uv_retries: Mutex::new(None),
                    },
                    key_provider,
                )
            } else {
                Authenticator::with_config_and_key_provider(callbacks, config, key_provider)
            }?;

            Ok(authenticator)
        }
    }

    #[cfg(all(feature = "tpm", feature = "agent"))]
    fn build_authenticator_with_interaction_and_key_provider(
        storage: Arc<Mutex<S>>,
        pin_storage: Option<Arc<Mutex<P>>>,
        security_config: SecurityConfig,
        pin_config: PinConfig,
        interaction_manager: Option<Arc<AgentInteractionManager>>,
        key_provider: K,
    ) -> Result<Authenticator<PasslessCallbacks<S, P>, K>> {
        let is_agent = interaction_manager.is_some();

        let options = if is_agent {
            AuthenticatorOptions {
                rk: true,
                up: true,
                uv: Some(false),
                plat: true,
                client_pin: Some(true),
                pin_uv_auth_token: Some(true),
                cred_mgmt: Some(true),
                bio_enroll: None,
                large_blobs: None,
                ep: None,
                always_uv: Some(true),
                make_cred_uv_not_required: Some(false),
            }
        } else {
            AuthenticatorOptions {
                rk: true,
                up: true,
                uv: Some(true),
                plat: true,
                client_pin: Some(true),
                pin_uv_auth_token: Some(true),
                cred_mgmt: Some(true),
                bio_enroll: None,
                large_blobs: None,
                ep: None,
                always_uv: Some(security_config.always_uv),
                make_cred_uv_not_required: Some(true),
            }
        };

        let config = AuthenticatorConfig::builder()
            .aaguid([
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
            .default_credential_backup_state(CredentialBackupState::NotEligible)
            .algorithms(vec![-7])
            .max_pin_retries(pin_config.max_retries)
            .auto_lock_timeout(pin_config.auto_lock_timeout)
            .build();

        let callbacks = match interaction_manager {
            Some(ref mgr) => PasslessCallbacks::with_interaction_manager(
                storage,
                pin_storage.clone(),
                security_config,
                pin_config.clone(),
                mgr.clone(),
                is_agent,
            ),
            None => PasslessCallbacks::new(
                storage,
                pin_storage.clone(),
                security_config,
                pin_config.clone(),
            ),
        };

        let authenticator = if let Some(ps) = pin_storage {
            Authenticator::with_config_and_pin_storage_and_key_provider(
                callbacks,
                config,
                PinStorageWrapper {
                    storage: ps,
                    max_uv_retries: pin_config.max_uv_retries,
                    last_uv_retries: Mutex::new(None),
                },
                key_provider,
            )?
        } else {
            Authenticator::with_config_and_key_provider(callbacks, config, key_provider)?
        };

        Ok(authenticator)
    }

    /// Create a new authenticator service with optional PIN storage and a custom key provider
    #[cfg(feature = "tpm")]
    pub fn with_pin_storage_and_key_provider(
        storage: S,
        pin_storage: Option<Arc<Mutex<P>>>,
        key_provider: K,
        security_config: SecurityConfig,
        pin_config: PinConfig,
    ) -> Result<Self> {
        let storage = Arc::new(Mutex::new(storage));
        Self::with_shared_storage_and_key_provider(
            storage,
            pin_storage,
            key_provider,
            security_config,
            pin_config,
        )
    }

    /// Create a new authenticator service with shared (Arc-wrapped) storage and a custom key provider
    #[cfg(feature = "tpm")]
    pub fn with_shared_storage_and_key_provider(
        storage: Arc<Mutex<S>>,
        pin_storage: Option<Arc<Mutex<P>>>,
        key_provider: K,
        security_config: SecurityConfig,
        pin_config: PinConfig,
    ) -> Result<Self> {
        let authenticator = Self::build_authenticator_with_key_provider(
            storage.clone(),
            pin_storage.clone(),
            security_config.clone(),
            pin_config.clone(),
            key_provider,
        )?;

        let mut service = Self {
            authenticator,
            storage,
            built_in_uv_policy: Some(BuiltInUvPolicy),
            max_uv_retries: pin_config.max_uv_retries,
            credential_backup_enabled: false,
            credential_backup_supported: false,
            pending_backups: HashMap::new(),
            pin_storage,
        };
        service.refresh_built_in_uv_state()?;
        Ok(service)
    }

    #[cfg(all(feature = "tpm", feature = "agent"))]
    pub fn with_shared_storage_and_key_provider_and_interaction(
        storage: Arc<Mutex<S>>,
        pin_storage: Option<Arc<Mutex<P>>>,
        key_provider: K,
        security_config: SecurityConfig,
        pin_config: PinConfig,
        interaction_manager: Arc<AgentInteractionManager>,
    ) -> Result<Self> {
        let authenticator = Self::build_authenticator_with_interaction_and_key_provider(
            storage.clone(),
            pin_storage.clone(),
            security_config.clone(),
            pin_config.clone(),
            Some(interaction_manager),
            key_provider,
        )?;

        Ok(Self {
            authenticator,
            storage,
            built_in_uv_policy: None,
            max_uv_retries: pin_config.max_uv_retries,
            credential_backup_enabled: false,
            credential_backup_supported: false,
            pending_backups: HashMap::new(),
            pin_storage,
        })
    }

    fn refresh_built_in_uv_state(&mut self) -> Result<()> {
        let Some(_policy) = self.built_in_uv_policy else {
            return Ok(());
        };

        let pin_configured = self
            .pin_storage
            .as_ref()
            .and_then(|ps| ps.lock().ok())
            .and_then(|ps| ps.is_pin_configured().ok())
            .unwrap_or(false);

        let state = if pin_configured {
            BuiltInUvState::SupportedNotConfigured
        } else {
            BuiltInUvState::Configured
        };

        self.authenticator.set_built_in_uv_state(state)
    }

    fn reset_uv_retries(&mut self) -> core::result::Result<(), StatusCode> {
        self.authenticator
            .reset_uv_retries()
            .map_err(|_| StatusCode::Other)?;

        Ok(())
    }

    fn backup_error_status(error: BackupError) -> StatusCode {
        match error {
            BackupError::InvalidInput => StatusCode::InvalidParameter,
            BackupError::InvalidBundle => StatusCode::InvalidCredential,
            BackupError::UnsupportedCredential => StatusCode::UnsupportedOption,
            BackupError::CryptoUnavailable | BackupError::CryptoFailed => {
                StatusCode::IntegrityFailure
            }
            BackupError::TooLarge => StatusCode::RequestTooLarge,
        }
    }

    fn credential_ref(credential: &Credential) -> CredentialRef<'_> {
        CredentialRef {
            id: &credential.id,
            rp_id: &credential.rp.id,
            rp_name: credential.rp.name.as_deref(),
            user_id: &credential.user.id,
            user_name: credential.user.name.as_deref(),
            user_display_name: credential.user.display_name.as_deref(),
            sign_count: &credential.sign_count,
            alg: &credential.alg,
            key: &credential.key,
            created: &credential.created,
            discoverable: &credential.discoverable,
            cred_protect: credential.extensions.cred_protect.as_ref(),
            backup_state: &credential.backup_state,
            cred_random: credential.extensions.cred_random.as_ref(),
        }
    }

    fn verify_backup_authorization(
        &mut self,
        protocol: u8,
        param: &[u8],
        auth_data: &[u8],
    ) -> core::result::Result<(), u8> {
        self.authenticator
            .verify_credential_management_pin_uv_auth(protocol, param, auth_data)
            .map_err(error_status_byte)
    }

    fn handle_backup_command(&mut self, payload: &[u8], response: &mut Vec<u8>) {
        response.clear();
        if !self.credential_backup_enabled || !self.credential_backup_supported {
            response.push(StatusCode::UnsupportedOption as u8);
            return;
        }

        let parser = match soft_fido2_ctap::cbor::MapParser::from_bytes(payload) {
            Ok(parser) => parser,
            Err(status) => {
                response.push(status as u8);
                return;
            }
        };
        let subcommand: u8 = match parser.get(1) {
            Ok(value) => value,
            Err(status) => {
                response.push(status as u8);
                return;
            }
        };

        match subcommand {
            BACKUP_PREPARE_SUBCOMMAND => {
                let credential_id = match parser.get_bytes(2) {
                    Ok(value) => value,
                    Err(status) => {
                        response.push(status as u8);
                        return;
                    }
                };
                let recipient: String = match parser.get(3) {
                    Ok(value) => value,
                    Err(status) => {
                        response.push(status as u8);
                        return;
                    }
                };
                let protocol: u8 = match parser.get(4) {
                    Ok(value) => value,
                    Err(status) => {
                        response.push(status as u8);
                        return;
                    }
                };
                let param = match parser.get_bytes(5) {
                    Ok(value) => value,
                    Err(status) => {
                        response.push(status as u8);
                        return;
                    }
                };
                let auth_data = backup_prepare_auth_data(&credential_id, &recipient);
                if let Err(status) = self.verify_backup_authorization(protocol, &param, &auth_data)
                {
                    response.push(status);
                    return;
                }

                let mut credential = {
                    let mut storage = match self.storage.lock() {
                        Ok(storage) => storage,
                        Err(_) => {
                            response.push(StatusCode::Other as u8);
                            return;
                        }
                    };
                    match storage.read(&credential_id) {
                        Ok(credential) => credential,
                        Err(soft_fido2::Error::DoesNotExist) => {
                            response.push(StatusCode::NoCredentials as u8);
                            return;
                        }
                        Err(_) => {
                            response.push(StatusCode::Other as u8);
                            return;
                        }
                    }
                };
                let export_state = match backup_state_for_export(credential.backup_state) {
                    Ok(state) => state,
                    Err(error) => {
                        response.push(Self::backup_error_status(error) as u8);
                        return;
                    }
                };
                credential.backup_state = export_state;
                let bundle = match encrypt_credential(&credential, &recipient) {
                    Ok(bundle) => bundle,
                    Err(error) => {
                        response.push(Self::backup_error_status(error) as u8);
                        return;
                    }
                };
                let token = bundle_token(&bundle);
                self.pending_backups.insert(credential_id, token);

                match soft_fido2_ctap::cbor::MapBuilder::new()
                    .insert_bytes(1, &bundle)
                    .and_then(|builder| builder.insert_bytes(2, &token))
                    .and_then(|builder| builder.build())
                {
                    Ok(body) => {
                        response.push(StatusCode::Success as u8);
                        response.extend_from_slice(&body);
                    }
                    Err(_) => response.push(StatusCode::Other as u8),
                }
            }
            BACKUP_COMMIT_SUBCOMMAND => {
                let credential_id = match parser.get_bytes(2) {
                    Ok(value) => value,
                    Err(status) => {
                        response.push(status as u8);
                        return;
                    }
                };
                let token = match parser.get_bytes(3) {
                    Ok(value) => value,
                    Err(status) => {
                        response.push(status as u8);
                        return;
                    }
                };
                let protocol: u8 = match parser.get(4) {
                    Ok(value) => value,
                    Err(status) => {
                        response.push(status as u8);
                        return;
                    }
                };
                let param = match parser.get_bytes(5) {
                    Ok(value) => value,
                    Err(status) => {
                        response.push(status as u8);
                        return;
                    }
                };
                let auth_data = backup_commit_auth_data(&credential_id, &token);
                if let Err(status) = self.verify_backup_authorization(protocol, &param, &auth_data)
                {
                    response.push(status);
                    return;
                }
                if token.len() != 32
                    || self
                        .pending_backups
                        .get(&credential_id)
                        .map(|expected| expected.as_slice())
                        != Some(token.as_slice())
                {
                    response.push(StatusCode::IntegrityFailure as u8);
                    return;
                }

                let result = (|| -> Result<()> {
                    let mut storage = self.storage.lock().map_err(|_| soft_fido2::Error::Other)?;
                    let mut credential = storage.read(&credential_id)?;
                    credential.backup_state = CredentialBackupState::BackedUp;
                    storage.write(Self::credential_ref(&credential))
                })();
                match result {
                    Ok(()) => {
                        self.pending_backups.remove(&credential_id);
                        response.push(StatusCode::Success as u8);
                        response.push(0xa0);
                    }
                    Err(soft_fido2::Error::DoesNotExist) => {
                        response.push(StatusCode::NoCredentials as u8)
                    }
                    Err(_) => response.push(StatusCode::Other as u8),
                }
            }
            _ => response.push(StatusCode::InvalidSubcommand as u8),
        }
    }

    fn handle_restore_command(&mut self, payload: &[u8], response: &mut Vec<u8>) {
        response.clear();
        if !self.credential_backup_enabled || !self.credential_backup_supported {
            response.push(StatusCode::UnsupportedOption as u8);
            return;
        }

        let parser = match soft_fido2_ctap::cbor::MapParser::from_bytes(payload) {
            Ok(parser) => parser,
            Err(status) => {
                response.push(status as u8);
                return;
            }
        };
        let bundle = match parser.get_bytes(1) {
            Ok(value) => value,
            Err(status) => {
                response.push(status as u8);
                return;
            }
        };
        let replace: bool = parser.get(2).unwrap_or(false);
        let protocol: u8 = match parser.get(3) {
            Ok(value) => value,
            Err(status) => {
                response.push(status as u8);
                return;
            }
        };
        let param = match parser.get_bytes(4) {
            Ok(value) => value,
            Err(status) => {
                response.push(status as u8);
                return;
            }
        };
        let auth_data = restore_auth_data(&bundle, replace);
        if let Err(status) = self.verify_backup_authorization(protocol, &param, &auth_data) {
            response.push(status);
            return;
        }

        let mut credential = match decrypt_credential(&bundle) {
            Ok(credential) => credential,
            Err(error) => {
                response.push(Self::backup_error_status(error) as u8);
                return;
            }
        };
        credential.backup_state = CredentialBackupState::BackedUp;
        let credential_id = credential.id.clone();

        let result = (|| -> core::result::Result<(), StatusCode> {
            let mut storage = self.storage.lock().map_err(|_| StatusCode::Other)?;
            let existing = match storage.read(&credential_id) {
                Ok(existing) => Some(existing),
                Err(soft_fido2::Error::DoesNotExist) => None,
                Err(_) => return Err(StatusCode::Other),
            };
            if existing.is_some() && !replace {
                return Err(StatusCode::CredentialExcluded);
            }
            if existing.is_some() {
                storage
                    .delete(&credential_id)
                    .map_err(|_| StatusCode::Other)?;
            }
            if storage.write(Self::credential_ref(&credential)).is_err() {
                if let Some(previous) = existing {
                    let _ = storage.write(Self::credential_ref(&previous));
                }
                return Err(StatusCode::Other);
            }
            Ok(())
        })();

        match result {
            Ok(()) => match soft_fido2_ctap::cbor::MapBuilder::new()
                .insert_bytes(1, &credential_id)
                .and_then(|builder| builder.build())
            {
                Ok(body) => {
                    response.push(StatusCode::Success as u8);
                    response.extend_from_slice(&body);
                }
                Err(_) => response.push(StatusCode::Other as u8),
            },
            Err(status) => response.push(status as u8),
        }
    }

    /// Process a CTAP request and generate a response
    pub fn handle(&mut self, request: &[u8], response_buffer: &mut Vec<u8>) -> Result<()> {
        self.refresh_built_in_uv_state()?;

        if request.first() == Some(&CMD_PASSLESS_BACKUP) {
            self.handle_backup_command(&request[1..], response_buffer);
            return Ok(());
        }
        if request.first() == Some(&CMD_PASSLESS_RESTORE) {
            self.handle_restore_command(&request[1..], response_buffer);
            return Ok(());
        }
        if request.first() == Some(&CMD_PASSLESS_RESET_UV_RETRIES) {
            response_buffer.clear();

            let payload = &request[1..];
            let parser = match soft_fido2_ctap::cbor::MapParser::from_bytes(payload) {
                Ok(parser) => parser,
                Err(status) => {
                    response_buffer.push(status as u8);
                    return Ok(());
                }
            };

            let sub_command: u8 = match parser.get(1) {
                Ok(sub_command) => sub_command,
                Err(status) => {
                    response_buffer.push(status as u8);
                    return Ok(());
                }
            };

            if sub_command != RESET_UV_RETRIES_SUBCOMMAND {
                response_buffer.push(StatusCode::InvalidParameter as u8);
                return Ok(());
            }

            // pinUvAuthProtocol (key 3) and pinUvAuthParam (key 4) are optional.
            // When a PIN is configured, the client MUST include them for authorization.
            // When no PIN is configured, the client may omit them, and we skip
            // verification (the command is already gated by local UHID access and
            // the existing passless client reset command works without PIN auth).
            if let (Ok(pin_uv_auth_protocol), Ok(pin_uv_auth_param)) =
                (parser.get::<u8>(3), parser.get_bytes(4))
            {
                let auth_data = [CMD_PASSLESS_RESET_UV_RETRIES, RESET_UV_RETRIES_SUBCOMMAND];
                if let Err(error) = self.authenticator.verify_credential_management_pin_uv_auth(
                    pin_uv_auth_protocol,
                    &pin_uv_auth_param,
                    &auth_data,
                ) {
                    response_buffer.push(error_status_byte(error));
                    return Ok(());
                }
            }

            match self.reset_uv_retries() {
                Ok(()) => {
                    response_buffer.push(0x00);
                    if let Ok(cbor_data) = soft_fido2_ctap::cbor::MapBuilder::new()
                        .insert(1, self.max_uv_retries)
                        .and_then(|b| b.build())
                    {
                        response_buffer.extend_from_slice(&cbor_data);
                    } else {
                        response_buffer.push(0xa0);
                    }
                }
                Err(status) => response_buffer.push(status as u8),
            }
            return Ok(());
        }

        let result = self.authenticator.handle(request, response_buffer);
        if let Err(SoftFido2Error::CtapError(code)) = &result
            && *code == StatusCode::UvBlocked as u8
        {
            warn!(
                "CTAP request returned UV_BLOCKED (0x{:02x}); \
                 built-in user verification retries are exhausted. \
                 Run `passless client pin uv-reset` to restore",
                code
            );
        }
        result?;
        Ok(())
    }

    /// Get storage information
    pub fn storage_info(&self) -> String {
        match self.storage.lock() {
            Ok(storage) => format!("Credentials in storage: {}", storage.count_credentials()),
            Err(_) => "Failed to acquire storage lock".to_string(),
        }
    }

    /// Register a custom CTAP command handler
    pub fn register_custom_command<F>(&mut self, command: u8, handler: F)
    where
        F: Fn(&[u8]) -> core::result::Result<Vec<u8>, soft_fido2::StatusCode>
            + Send
            + Sync
            + 'static,
    {
        self.authenticator.register_custom_command(command, handler);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::storage::LocalStorageAdapter;

    use soft_fido2_ctap::SecPinHash;

    struct TestPinStorage {
        state: Mutex<PinState>,
    }

    impl TestPinStorage {
        fn new(state: PinState) -> Self {
            Self {
                state: Mutex::new(state),
            }
        }

        fn set_state(&self, state: PinState) {
            *self.state.lock().expect("test PIN storage lock") = state;
        }
    }

    impl PinStorage for TestPinStorage {
        fn load_pin_state(&self) -> core::result::Result<PinState, StatusCode> {
            self.state
                .lock()
                .map(|state| state.clone())
                .map_err(|_| StatusCode::Other)
        }

        fn save_pin_state(&self, state: &PinState) -> core::result::Result<(), StatusCode> {
            *self.state.lock().map_err(|_| StatusCode::Other)? = state.clone();
            Ok(())
        }
    }

    fn pin_state_with_pin() -> PinState {
        let mut state = PinState::new();
        state.pin_hash = Some(SecPinHash::new([0x42; 32]));
        state
    }

    fn get_info_uv(response: &[u8]) -> Option<bool> {
        assert_eq!(response.first(), Some(&0x00));
        let value: serde_cbor::Value =
            serde_cbor::from_slice(&response[1..]).expect("decode authenticatorGetInfo");
        let info = match value {
            serde_cbor::Value::Map(info) => info,
            other => panic!("expected GetInfo map, got {other:?}"),
        };
        let options = match info.get(&serde_cbor::Value::Integer(4)) {
            Some(serde_cbor::Value::Map(options)) => options,
            other => panic!("expected GetInfo options map, got {other:?}"),
        };
        match options.get(&serde_cbor::Value::Text("uv".to_string())) {
            Some(serde_cbor::Value::Bool(value)) => Some(*value),
            None => None,
            other => panic!("expected boolean uv option, got {other:?}"),
        }
    }

    #[test]
    fn test_backup_state_for_export_preserves_be_invariant() {
        assert!(matches!(
            backup_state_for_export(CredentialBackupState::NotEligible),
            Err(BackupError::UnsupportedCredential)
        ));
        assert_eq!(
            backup_state_for_export(CredentialBackupState::Eligible).unwrap(),
            CredentialBackupState::BackedUp
        );
        assert_eq!(
            backup_state_for_export(CredentialBackupState::BackedUp).unwrap(),
            CredentialBackupState::BackedUp
        );
    }

    #[test]
    fn test_get_info_tracks_runtime_pin_policy_without_consuming_uv_retries() {
        let temp_dir = tempfile::tempdir().expect("create temp directory");
        let credential_dir = temp_dir.path().join("credentials");
        std::fs::create_dir_all(&credential_dir).expect("create credential directory");
        let storage = LocalStorageAdapter::new(credential_dir).expect("create credential storage");

        let pin_state = PinState {
            uv_retries: 5,
            ..pin_state_with_pin()
        };
        let pin_storage = Arc::new(Mutex::new(TestPinStorage::new(pin_state)));

        let security_config = SecurityConfig {
            always_uv: true,
            ..Default::default()
        };
        let pin_config = PinConfig {
            enforcement: PinEnforcement::Optional,
            ..Default::default()
        };

        let mut service = AuthenticatorService::with_pin_storage(
            storage,
            Some(pin_storage.clone()),
            security_config,
            pin_config,
        )
        .expect("create authenticator service");

        assert_eq!(
            service
                .authenticator
                .built_in_uv_state()
                .expect("read built-in UV state"),
            BuiltInUvState::SupportedNotConfigured
        );

        let mut response = Vec::new();
        service
            .handle(&[0x04], &mut response)
            .expect("handle GetInfo with PIN");
        assert_eq!(get_info_uv(&response), Some(false));
        assert_eq!(
            pin_storage
                .lock()
                .expect("test PIN storage")
                .load_pin_state()
                .expect("load PIN state")
                .uv_retries,
            5
        );

        pin_storage
            .lock()
            .expect("test PIN storage")
            .set_state(PinState::new());
        service
            .handle(&[0x04], &mut response)
            .expect("handle GetInfo without PIN");
        assert_eq!(get_info_uv(&response), Some(true));
        assert_eq!(
            service
                .authenticator
                .built_in_uv_state()
                .expect("read built-in UV state"),
            BuiltInUvState::Configured
        );

        let mut pin_state = pin_state_with_pin();
        pin_state.uv_retries = 5;
        pin_storage
            .lock()
            .expect("test PIN storage")
            .set_state(pin_state);
        service
            .handle(&[0x04], &mut response)
            .expect("handle GetInfo after restoring PIN");
        assert_eq!(get_info_uv(&response), Some(false));
        assert_eq!(
            pin_storage
                .lock()
                .expect("test PIN storage")
                .load_pin_state()
                .expect("load PIN state")
                .uv_retries,
            5
        );
    }

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
            enable_credential_backup: false,
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
    fn test_reset_uv_retries_command_requires_authentication() {
        let temp_dir = std::env::temp_dir().join("test_passless_reset_uv_retries");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).expect("Failed to create temp directory");

        let storage =
            LocalStorageAdapter::new(temp_dir.clone()).expect("Failed to create local storage");
        let mut service = AuthenticatorService::with_pin_storage(
            storage,
            None::<Arc<Mutex<()>>>,
            SecurityConfig::default(),
            PinConfig::default(),
        )
        .expect("Service creation should succeed");

        let mut response = Vec::new();
        service
            .handle(&[CMD_PASSLESS_RESET_UV_RETRIES], &mut response)
            .expect("UV retry reset command should be handled");

        assert_ne!(response, vec![0x00, 0xa0]);

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_pin_storage_wrapper_clamps_on_save() {
        use crate::pin_storage::local::LocalPinStorage;
        use soft_fido2::PinStorageCallbacks;

        let temp_dir = std::env::temp_dir().join("test_passless_pin_wrapper_save");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).expect("Failed to create temp directory");

        let pin_storage = LocalPinStorage::new(temp_dir.clone());
        let wrapper = PinStorageWrapper {
            storage: Arc::new(Mutex::new(pin_storage)),
            max_uv_retries: 5,
            last_uv_retries: Mutex::new(None),
        };

        let mut state = PinState::new();
        state.uv_retries = 10;

        // Save should clamp to max_uv_retries
        wrapper.save_pin_state(&state).expect("Save should succeed");

        // Load should return clamped value
        let loaded = wrapper.load_pin_state().expect("Load should succeed");
        assert_eq!(loaded.uv_retries, 5, "uv_retries should be clamped to max");

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_pin_storage_wrapper_clamps_on_load() {
        use crate::pin_storage::local::LocalPinStorage;
        use soft_fido2::PinStorageCallbacks;

        let temp_dir = std::env::temp_dir().join("test_passless_pin_wrapper_load");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).expect("Failed to create temp directory");

        let pin_storage = LocalPinStorage::new(temp_dir.clone());

        let wrapper_high = PinStorageWrapper {
            storage: Arc::new(Mutex::new(pin_storage)),
            max_uv_retries: 8,
            last_uv_retries: Mutex::new(None),
        };
        let mut state = PinState::new();
        state.uv_retries = 8;
        wrapper_high
            .save_pin_state(&state)
            .expect("Save should succeed");

        let pin_storage2 = LocalPinStorage::new(temp_dir.clone());
        let wrapper_low = PinStorageWrapper {
            storage: Arc::new(Mutex::new(pin_storage2)),
            max_uv_retries: 3,
            last_uv_retries: Mutex::new(None),
        };

        // Load should clamp to the lower max
        let loaded = wrapper_low.load_pin_state().expect("Load should succeed");
        assert_eq!(
            loaded.uv_retries, 3,
            "uv_retries should be clamped to lower max on load"
        );

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_uv_retry_transition_classification() {
        assert_eq!(
            PinStorageWrapper::<()>::classify_uv_transition(None, 3),
            UvRetryTransition::Initialized,
        );
        assert_eq!(
            PinStorageWrapper::<()>::classify_uv_transition(Some(3), 2),
            UvRetryTransition::NormalChange,
        );
        assert_eq!(
            PinStorageWrapper::<()>::classify_uv_transition(Some(2), 1),
            UvRetryTransition::Low,
        );
        assert_eq!(
            PinStorageWrapper::<()>::classify_uv_transition(Some(1), 0),
            UvRetryTransition::Exhausted,
        );
        assert_eq!(
            PinStorageWrapper::<()>::classify_uv_transition(Some(0), 0),
            UvRetryTransition::NoChange,
        );
        assert_eq!(
            PinStorageWrapper::<()>::classify_uv_transition(Some(0), 8),
            UvRetryTransition::Recovered,
        );
        assert_eq!(
            PinStorageWrapper::<()>::classify_uv_transition(Some(5), 5),
            UvRetryTransition::NoChange,
        );
        assert_eq!(
            PinStorageWrapper::<()>::classify_uv_transition(Some(3), 1),
            UvRetryTransition::Low,
        );
        assert_eq!(
            PinStorageWrapper::<()>::classify_uv_transition(Some(2), 0),
            UvRetryTransition::Exhausted,
        );
    }

    #[test]
    fn test_pin_storage_wrapper_tracks_uv_retry_transitions() {
        use crate::pin_storage::local::LocalPinStorage;
        use soft_fido2::PinStorageCallbacks;

        let temp_dir = std::env::temp_dir().join("test_passless_uv_transitions");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).expect("Failed to create temp directory");

        let pin_storage = LocalPinStorage::new(temp_dir.clone());
        let wrapper = PinStorageWrapper {
            storage: Arc::new(Mutex::new(pin_storage)),
            max_uv_retries: 8,
            last_uv_retries: Mutex::new(None),
        };

        let mut state = PinState::new();
        state.uv_retries = 3;
        wrapper.save_pin_state(&state).expect("Save should succeed");
        {
            let last = wrapper.last_uv_retries.lock().unwrap();
            assert_eq!(*last, Some(3));
        }

        state.uv_retries = 2;
        wrapper.save_pin_state(&state).expect("Save should succeed");
        {
            let last = wrapper.last_uv_retries.lock().unwrap();
            assert_eq!(*last, Some(2));
        }

        state.uv_retries = 1;
        wrapper.save_pin_state(&state).expect("Save should succeed");
        {
            let last = wrapper.last_uv_retries.lock().unwrap();
            assert_eq!(*last, Some(1));
        }

        state.uv_retries = 0;
        wrapper.save_pin_state(&state).expect("Save should succeed");
        {
            let last = wrapper.last_uv_retries.lock().unwrap();
            assert_eq!(*last, Some(0));
        }

        state.uv_retries = 0;
        wrapper.save_pin_state(&state).expect("Save should succeed");
        {
            let last = wrapper.last_uv_retries.lock().unwrap();
            assert_eq!(*last, Some(0));
        }

        state.uv_retries = 8;
        wrapper.save_pin_state(&state).expect("Save should succeed");
        {
            let last = wrapper.last_uv_retries.lock().unwrap();
            assert_eq!(*last, Some(8));
        }

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_pin_storage_wrapper_load_initializes_last_uv_retries() {
        use crate::pin_storage::local::LocalPinStorage;
        use soft_fido2::PinStorageCallbacks;

        let temp_dir = std::env::temp_dir().join("test_passless_uv_load_init");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).expect("Failed to create temp directory");

        let pin_storage = LocalPinStorage::new(temp_dir.clone());
        let wrapper = PinStorageWrapper {
            storage: Arc::new(Mutex::new(pin_storage)),
            max_uv_retries: 8,
            last_uv_retries: Mutex::new(None),
        };

        {
            let last = wrapper.last_uv_retries.lock().unwrap();
            assert_eq!(*last, None);
        }

        let _state = wrapper.load_pin_state().expect("Load should succeed");
        {
            let last = wrapper.last_uv_retries.lock().unwrap();
            assert!(last.is_some());
        }

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[cfg(feature = "agent")]
    #[test]
    fn test_delegated_pin_storage_arc_identity() {
        use crate::pin_storage::local::LocalPinStorage;

        let temp_dir = std::env::temp_dir().join("test_passless_delegated_pin_identity");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).expect("Failed to create temp directory");

        let cred_temp = temp_dir.join("creds");
        std::fs::create_dir_all(&cred_temp).unwrap();
        let cred_storage: Arc<Mutex<Box<dyn CredentialStorage>>> = Arc::new(Mutex::new(Box::new(
            LocalStorageAdapter::new(cred_temp).unwrap(),
        )));

        let pin_storage: Arc<Mutex<Box<dyn crate::pin_storage::PinStorage>>> =
            Arc::new(Mutex::new(Box::new(LocalPinStorage::new(temp_dir.clone()))));

        let human_pin_storage_clone = pin_storage.clone();

        let security_config = SecurityConfig::default();
        let pin_config = PinConfig::default();
        let interaction_manager =
            Arc::new(crate::agent::interaction::AgentInteractionManager::new());

        let service = AuthenticatorService::with_shared_storage_and_interaction(
            cred_storage,
            Some(pin_storage.clone()),
            security_config,
            pin_config,
            interaction_manager,
        )
        .expect("Service creation should succeed");

        let _ = &service.authenticator;

        assert!(
            Arc::ptr_eq(&pin_storage, &human_pin_storage_clone),
            "delegated service must share the same Arc<Mutex<PinStorage>> as human"
        );

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_not_eligible_credential_rejected_and_state_unchanged() {
        use soft_fido2::CredentialKey;
        use soft_fido2_ctap::SecBytes;

        let temp_dir = tempfile::tempdir().expect("create temp directory");
        let credential_dir = temp_dir.path().join("credentials");
        std::fs::create_dir_all(&credential_dir).expect("create credential directory");
        let mut storage =
            LocalStorageAdapter::new(credential_dir).expect("create credential storage");

        let credential_id = vec![0x01, 0x02, 0x03];
        let credential = Credential {
            id: credential_id.clone(),
            rp: soft_fido2::RelyingParty {
                id: "example.com".to_string(),
                name: Some("Example".to_string()),
            },
            user: soft_fido2::User {
                id: vec![0x04, 0x05, 0x06],
                name: Some("alice".to_string()),
                display_name: Some("Alice".to_string()),
            },
            sign_count: 0,
            alg: -7,
            key: CredentialKey::software(SecBytes::from_slice(&[0x9d; 32])),
            created: 123,
            discoverable: true,
            backup_state: CredentialBackupState::NotEligible,
            extensions: soft_fido2::Extensions {
                cred_protect: None,
                hmac_secret: None,
                cred_random: None,
            },
        };

        let cred_ref = CredentialRef {
            id: &credential.id,
            rp_id: &credential.rp.id,
            rp_name: credential.rp.name.as_deref(),
            user_id: &credential.user.id,
            user_name: credential.user.name.as_deref(),
            user_display_name: credential.user.display_name.as_deref(),
            sign_count: &credential.sign_count,
            alg: &credential.alg,
            key: &credential.key,
            created: &credential.created,
            discoverable: &credential.discoverable,
            cred_protect: credential.extensions.cred_protect.as_ref(),
            backup_state: &credential.backup_state,
            cred_random: credential.extensions.cred_random.as_ref(),
        };
        storage.write(cred_ref).expect("write credential");

        let loaded = storage.read(&credential_id).expect("read credential");
        assert_eq!(loaded.backup_state, CredentialBackupState::NotEligible);

        assert!(matches!(
            backup_state_for_export(loaded.backup_state),
            Err(BackupError::UnsupportedCredential)
        ));

        let reloaded = storage.read(&credential_id).expect("re-read credential");
        assert_eq!(reloaded.backup_state, CredentialBackupState::NotEligible);
    }
}
