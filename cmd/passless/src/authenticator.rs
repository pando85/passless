use crate::credential_backup::{
    BACKUP_COMMIT_SUBCOMMAND, BACKUP_PREPARE_SUBCOMMAND, BackupError, CMD_PASSLESS_BACKUP,
    CMD_PASSLESS_RESTORE, backup_commit_auth_data, backup_prepare_auth_data, bundle_token,
    decrypt_credential, encrypt_credential, restore_auth_data,
};
use crate::notification::{show_user_presence_notification, show_verification_notification};
use crate::pin_storage::{PinStorage, lock_pin_storage};
use crate::storage::{CredentialFilter, CredentialStorage, lock_shared_storage};
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

const CTAP_GET_ASSERTION: u8 = 0x02;
const CRED_PROTECT_UV_REQUIRED: u8 = 0x03;

/// The parts of a GetAssertion request that decide whether it may be retried with built-in UV.
struct GetAssertionUvView {
    params: Vec<(ciborium::Value, ciborium::Value)>,
    rp_id: String,
    /// The credential IDs of the allowList.
    allow_list: Vec<Vec<u8>>,
}

impl GetAssertionUvView {
    /// Parse a GetAssertion request (parameters after the command byte) that soft-fido2 served
    /// without any user verification: `up` true, `uv` not requested, no pinUvAuthParam, and an
    /// allowList. Requests without an allowList are never retried (see
    /// [`AuthenticatorService::protected_credential_uv`]).
    ///
    /// Only called after soft-fido2 accepted the request and answered CTAP2_ERR_NO_CREDENTIALS, so
    /// its CTAP CBOR profile validation (duplicate keys, nesting depth, tags) has already passed.
    /// The byte-exact round trip additionally guarantees the rewrite re-encodes this very request.
    fn without_uv(params: &[u8]) -> Option<Self> {
        use ciborium::Value;

        let value: Value = ciborium::from_reader(params).ok()?;
        let mut reencoded = Vec::with_capacity(params.len());
        ciborium::into_writer(&value, &mut reencoded).ok()?;
        if reencoded != params {
            return None;
        }
        let Value::Map(params) = value else {
            return None;
        };

        let field = |key: u8| {
            params
                .iter()
                .find(|(k, _)| k.as_integer() == Some(key.into()))
                .map(|(_, v)| v)
        };
        if field(6).is_some() {
            return None;
        }
        if let Some(options) = field(5) {
            for (key, value) in options.as_map()? {
                match (key.as_text()?, value.as_bool()?) {
                    ("up", false) | ("uv", true) | ("rk", _) => return None,
                    _ => {}
                }
            }
        }

        let rp_id = field(1)?.as_text()?.to_string();
        let allow_list = field(3)?
            .as_array()?
            .iter()
            .map(|descriptor| {
                descriptor
                    .as_map()?
                    .iter()
                    .find(|(k, _)| k.as_text() == Some("id"))
                    .and_then(|(_, id)| id.as_bytes().cloned())
            })
            .collect::<Option<Vec<_>>>()?;

        Some(Self {
            params,
            rp_id,
            allow_list,
        })
    }

    /// Re-encode the request with `"uv": true`, keeping CTAP canonical key order.
    fn with_uv_requested(mut self) -> Option<Vec<u8>> {
        use ciborium::Value;

        // CTAP canonical (RFC 7049 section 3.9) order: shorter encoded keys first, then bytewise.
        fn encoded(key: &Value) -> Option<(usize, Vec<u8>)> {
            let mut bytes = Vec::new();
            ciborium::into_writer(key, &mut bytes).ok()?;
            Some((bytes.len(), bytes))
        }
        fn insert_canonical(map: &mut Vec<(Value, Value)>, entry: (Value, Value)) -> Option<()> {
            let key = encoded(&entry.0)?;
            let mut position = map.len();
            for (index, (existing, _)) in map.iter().enumerate() {
                if encoded(existing)? > key {
                    position = index;
                    break;
                }
            }
            map.insert(position, entry);
            Some(())
        }

        let uv = (Value::Text("uv".to_string()), Value::Bool(true));
        match self
            .params
            .iter_mut()
            .find(|(k, _)| k.as_integer() == Some(5.into()))
        {
            Some((_, Value::Map(options))) => {
                options.retain(|(key, _)| key.as_text() != Some("uv"));
                insert_canonical(options, uv)?;
            }
            Some(_) => return None,
            None => insert_canonical(
                &mut self.params,
                (Value::Integer(5.into()), Value::Map(vec![uv])),
            )?,
        }

        let mut request = vec![CTAP_GET_ASSERTION];
        ciborium::into_writer(&Value::Map(self.params), &mut request).ok()?;
        Some(request)
    }
}

/// What the human authenticator does after soft-fido2 answered CTAP2_ERR_NO_CREDENTIALS.
#[derive(Debug, PartialEq, Eq)]
enum ProtectedCredentialUv {
    /// Keep soft-fido2's response.
    AsAnswered,
    /// Retry with built-in UV (the verification prompt), as `alwaysUv` would.
    BuiltIn(Vec<u8>),
    /// A PIN is the only UV method: ask the platform for a pinUvAuthToken.
    PinRequired,
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
        let storage = lock_pin_storage(&self.storage);
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
        let storage = lock_pin_storage(&self.storage);
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

/// Thread-local stand-in for the desktop prompts, so unit tests can drive full CTAP ceremonies
/// on the human path without D-Bus and count the prompts the authenticator raised.
#[cfg(test)]
pub(crate) mod test_prompts {
    use std::cell::Cell;

    use soft_fido2::{UpResult, UvResult};

    /// How the stand-in answers every prompt.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Answer {
        Accept,
        Deny,
        /// The prompt cannot be shown (for example no notification server).
        Fail,
    }

    thread_local! {
        static ANSWER: Cell<Option<Answer>> = const { Cell::new(None) };
        static UP_PROMPTS: Cell<usize> = const { Cell::new(0) };
        static UV_PROMPTS: Cell<usize> = const { Cell::new(0) };
    }

    /// Answers every prompt on this thread while alive.
    pub(crate) struct Prompts;

    /// Accepts every prompt on this thread while alive.
    pub(crate) struct AutoAccept;

    impl AutoAccept {
        pub(crate) fn install() -> Prompts {
            Prompts::install(Answer::Accept)
        }
    }

    impl Prompts {
        pub(crate) fn install(answer: Answer) -> Self {
            ANSWER.with(|current| current.set(Some(answer)));
            UP_PROMPTS.with(|count| count.set(0));
            UV_PROMPTS.with(|count| count.set(0));
            Self
        }

        pub(crate) fn up_prompts(&self) -> usize {
            UP_PROMPTS.with(Cell::get)
        }

        pub(crate) fn uv_prompts(&self) -> usize {
            UV_PROMPTS.with(Cell::get)
        }
    }

    impl Drop for Prompts {
        fn drop(&mut self) {
            ANSWER.with(|current| current.set(None));
        }
    }

    pub(super) fn up_result() -> Option<soft_fido2::Result<UpResult>> {
        let answer = ANSWER.with(Cell::get)?;
        UP_PROMPTS.with(|count| count.set(count.get() + 1));
        Some(match answer {
            Answer::Accept => Ok(UpResult::Accepted),
            Answer::Deny => Ok(UpResult::Denied),
            Answer::Fail => Err(soft_fido2::Error::Other),
        })
    }

    pub(super) fn uv_result() -> Option<soft_fido2::Result<UvResult>> {
        let answer = ANSWER.with(Cell::get)?;
        UV_PROMPTS.with(|count| count.set(count.get() + 1));
        Some(match answer {
            Answer::Accept => Ok(UvResult::AcceptedWithUp),
            Answer::Deny => Ok(UvResult::Denied),
            Answer::Fail => Err(soft_fido2::Error::Other),
        })
    }
}

impl<S: CredentialStorage, P: PinStorage> AuthenticatorCallbacks for PasslessCallbacks<S, P> {
    fn request_up(&self, info: &str, user: Option<&str>, rp: &str) -> Result<UpResult> {
        #[cfg(test)]
        if let Some(result) = test_prompts::up_result() {
            return result;
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

        let storage = lock_shared_storage(&self.storage);

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
        #[cfg(test)]
        if let Some(result) = test_prompts::uv_result() {
            return result;
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
            let storage = lock_pin_storage(pin_storage);
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

        let mut storage = lock_shared_storage(&self.storage);

        storage.write(*credential)?;
        info!(
            "Credential persisted successfully for RP: {}",
            credential.rp_id
        );
        Ok(())
    }

    fn read_credential(&self, cred_id: &[u8]) -> Result<Option<Credential>> {
        debug!("Reading credential: id={}", bytes_to_hex(cred_id));

        let mut storage = lock_shared_storage(&self.storage);

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

        let mut storage = lock_shared_storage(&self.storage);

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

        let mut storage = lock_shared_storage(&self.storage);

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

        let mut storage = lock_shared_storage(&self.storage);

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

        let storage = lock_shared_storage(&self.storage);

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
            let storage = lock_pin_storage(pin_storage);
            storage.load_pin_state()
        } else {
            Ok(PinState::new())
        }
    }

    fn save_pin_state(&self, state: &PinState) -> std::result::Result<(), soft_fido2::StatusCode> {
        if let Some(pin_storage) = &self.pin_storage {
            let storage = lock_pin_storage(pin_storage);
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
pub struct AuthenticatorService<
    S: CredentialStorage,
    P: PinStorage = (),
    K: CredentialKeyProvider = SoftwareCredentialKeyProvider,
> {
    /// The underlying soft_fido2 authenticator
    pub authenticator: Authenticator<PasslessCallbacks<S, P>, K>,
    /// Storage backend (injected dependency)
    pub storage: Arc<Mutex<S>>,
    /// Maximum UV retries (configured value)
    max_uv_retries: u8,
    /// The configured `security.always_uv` (advertised as the `alwaysUv` option).
    always_uv: bool,
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
        let options = AuthenticatorOptions {
            rk: true,
            up: true,
            uv: Some(true),
            plat: false,
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
            max_uv_retries: pin_config.max_uv_retries,
            always_uv: security_config.always_uv,
            credential_backup_enabled: security_config.enable_credential_backup,
            credential_backup_supported: true,
            pending_backups: HashMap::new(),
            pin_storage,
        };
        service.refresh_built_in_uv_state()?;
        Ok(service)
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
        let options = AuthenticatorOptions {
            rk: true,
            up: true,
            uv: Some(true),
            plat: false,
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
            max_uv_retries: pin_config.max_uv_retries,
            always_uv: security_config.always_uv,
            credential_backup_enabled: false,
            credential_backup_supported: false,
            pending_backups: HashMap::new(),
            pin_storage,
        };
        service.refresh_built_in_uv_state()?;
        Ok(service)
    }

    fn refresh_built_in_uv_state(&mut self) -> Result<()> {
        let pin_configured = self
            .pin_storage
            .as_ref()
            .and_then(|ps| lock_pin_storage(ps).is_pin_configured().ok())
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

    /// Read authoritative PIN state for the privileged UV reset command.
    ///
    /// Unlike GetInfo, do not use the cached PIN configuration hint: a
    /// synchronized password store can acquire a PIN while that cache still
    /// reports "not configured". Backend failures must fail closed.
    fn pin_configured_for_uv_reset(&self) -> core::result::Result<bool, StatusCode> {
        match &self.pin_storage {
            Some(storage) => Ok(lock_pin_storage(storage)
                .load_pin_state()?
                .pin_hash
                .is_some()),
            None => Ok(false),
        }
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
                    let mut storage = lock_shared_storage(&self.storage);
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
                    let mut storage = lock_shared_storage(&self.storage);
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
            let mut storage = lock_shared_storage(&self.storage);
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

    /// Decide what to do after soft-fido2 answered a GetAssertion with CTAP2_ERR_NO_CREDENTIALS.
    ///
    /// When MakeCredential performs UV and the client sent no credProtect extension, soft-fido2
    /// stores credProtect level 3 (userVerificationRequired). `alwaysUv` makes every enrollment
    /// do so, including a plain `ssh-keygen -t ed25519-sk` key, and release builds from v0.16.0
    /// to v0.21.0 forced `alwaysUv` regardless of `security.always_uv`. Once
    /// `always_uv = false` is honored, OpenSSH's `{"up": true}` assertion for such a key filters
    /// it out and fails with CTAP2_ERR_NO_CREDENTIALS (issue #588).
    ///
    /// The retry only applies when all of these hold, so it never answers differently for an RP
    /// the caller cannot already name a credential of:
    /// - `always_uv = false`: with `alwaysUv`, soft-fido2 already performs UV (or asks for a PIN)
    ///   before looking credentials up, and its answer stays untouched;
    /// - the request asks for presence (`up` true), not `uv`, carries no pinUvAuthParam, and has
    ///   an allowList, so the caller already holds the random credential IDs. OpenSSH always
    ///   sends one; discoverable (no allowList) requests keep soft-fido2's answer, which is
    ///   identical whether or not the RP has protected credentials;
    /// - every allowList entry stored for this RP is at credProtect level 3 (entries that are not
    ///   stored here cannot be served either: soft-fido2 already failed to unwrap them).
    ///
    /// Retrying with UV keeps credProtect enforced: the credential is only used after UV, as with
    /// `alwaysUv`. With a PIN set, built-in UV is unavailable, so the platform is asked for a
    /// pinUvAuthToken instead (OpenSSH then prompts for the PIN and retries).
    fn protected_credential_uv(&self, params: &[u8]) -> ProtectedCredentialUv {
        if self.always_uv {
            return ProtectedCredentialUv::AsAnswered;
        }
        let Some(view) = GetAssertionUvView::without_uv(params) else {
            return ProtectedCredentialUv::AsAnswered;
        };

        let cred_protects: Vec<u8> = {
            let mut storage = lock_shared_storage(&self.storage);
            view.allow_list
                .iter()
                .filter_map(|id| storage.read(id).ok())
                .filter(|credential| credential.rp.id == view.rp_id)
                .map(|credential| credential.extensions.cred_protect.unwrap_or(1))
                .collect()
        };
        if cred_protects.is_empty()
            || cred_protects
                .iter()
                .any(|cred_protect| *cred_protect != CRED_PROTECT_UV_REQUIRED)
        {
            return ProtectedCredentialUv::AsAnswered;
        }

        match self.authenticator.built_in_uv_state() {
            Ok(BuiltInUvState::Configured) => {
                info!(
                    "GetAssertion for RP {}: the allowed credentials require user verification \
                     (credProtect); retrying with built-in UV",
                    view.rp_id
                );
                view.with_uv_requested().map_or(
                    ProtectedCredentialUv::AsAnswered,
                    ProtectedCredentialUv::BuiltIn,
                )
            }
            Ok(BuiltInUvState::SupportedNotConfigured) => {
                info!(
                    "GetAssertion for RP {}: the allowed credentials require user verification \
                     (credProtect); requesting a PIN/UV auth token",
                    view.rp_id
                );
                ProtectedCredentialUv::PinRequired
            }
            _ => ProtectedCredentialUv::AsAnswered,
        }
    }

    /// Serve a GetAssertion, retrying once with UV for credProtect-protected credentials.
    ///
    /// soft-fido2 always answers first, so its CTAP CBOR validation and every other error stays
    /// authoritative; only a CTAP2_ERR_NO_CREDENTIALS answer can change. That first attempt has
    /// no effect worth undoing: in soft-fido2-ctap's `get_assertion::handle`, a request with
    /// `up` true, no `uv`, no pinUvAuthParam and `alwaysUv` off skips the alwaysUv (step 5) and
    /// UV (step 7) blocks, then step 8 reads the allowed credentials and returns NO_CREDENTIALS
    /// before the user-presence prompt (step 10), the sign counter update and signing (step 14).
    /// It touches no UV retry counter and no PIN token; it only clears the GetNextAssertion state
    /// (as any GetAssertion does, and the retry does again) and reads storage, whose cache holds
    /// the same credentials the retry reads.
    fn handle_get_assertion(
        &mut self,
        request: &[u8],
        response_buffer: &mut Vec<u8>,
    ) -> Result<usize> {
        let answered = self.authenticator.handle(request, response_buffer)?;
        if response_buffer.as_slice() != [StatusCode::NoCredentials as u8] {
            return Ok(answered);
        }

        match self.protected_credential_uv(&request[1..]) {
            ProtectedCredentialUv::AsAnswered => Ok(answered),
            ProtectedCredentialUv::BuiltIn(with_uv) => {
                self.authenticator.handle(&with_uv, response_buffer)
            }
            ProtectedCredentialUv::PinRequired => {
                *response_buffer = vec![StatusCode::PuatRequired as u8];
                Ok(response_buffer.len())
            }
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

            // The reset is a privileged operation when a PIN is configured.
            // Missing, partially supplied, or malformed authorization must fail
            // closed rather than falling through to the unauthenticated path.
            let pin_configured = match self.pin_configured_for_uv_reset() {
                Ok(configured) => configured,
                Err(status) => {
                    response_buffer.push(status as u8);
                    return Ok(());
                }
            };

            match (parser.get::<u8>(3), parser.get_bytes(4)) {
                (Ok(pin_uv_auth_protocol), Ok(pin_uv_auth_param)) => {
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
                (Err(_), Err(_)) if !pin_configured => {
                    // Preserve the existing local recovery path without a PIN.
                }
                _ => {
                    response_buffer.push(StatusCode::PuatRequired as u8);
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

        let result = if request.first() == Some(&CTAP_GET_ASSERTION) {
            self.handle_get_assertion(request, response_buffer)
        } else {
            self.authenticator.handle(request, response_buffer)
        };
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
        let storage = lock_shared_storage(&self.storage);
        format!("Credentials in storage: {}", storage.count_credentials())
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

    /// Models a PIN backend that becomes unreadable after initialization.
    struct FailingPinConfigStorage {
        fail_load: Arc<std::sync::atomic::AtomicBool>,
    }

    impl PinStorage for FailingPinConfigStorage {
        fn load_pin_state(&self) -> core::result::Result<PinState, StatusCode> {
            if self.fail_load.load(std::sync::atomic::Ordering::SeqCst) {
                Err(StatusCode::Other)
            } else {
                Ok(pin_state_with_pin())
            }
        }

        fn save_pin_state(&self, _state: &PinState) -> core::result::Result<(), StatusCode> {
            Ok(())
        }

        fn is_pin_configured(&self) -> core::result::Result<bool, StatusCode> {
            Ok(true)
        }
    }

    /// Simulates a synchronized pass backend with an out-of-date PIN hint.
    ///
    /// The hint is suitable for GetInfo but must not authorize a UV reset.
    struct StalePinConfigStorage {
        state: Mutex<PinState>,
        cached_pin_configured: bool,
    }

    impl PinStorage for StalePinConfigStorage {
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

        fn is_pin_configured(&self) -> core::result::Result<bool, StatusCode> {
            Ok(self.cached_pin_configured)
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

    /// The human UHID authenticator is built by `with_shared_storage` in every build: since the
    /// isolated agent route was removed, the `agent` feature no longer changes its GetInfo options
    /// (it used to advertise the agent profile: `uv = false`, `makeCredUvNotRqd = false`).
    #[test]
    fn test_human_authenticator_options_do_not_depend_on_agent_feature() {
        let temp_dir = tempfile::tempdir().expect("create temp directory");
        let credential_dir = temp_dir.path().join("credentials");
        std::fs::create_dir_all(&credential_dir).expect("create credential directory");
        let storage: Arc<Mutex<LocalStorageAdapter>> = Arc::new(Mutex::new(
            LocalStorageAdapter::new(credential_dir).expect("create credential storage"),
        ));

        let security_config = SecurityConfig {
            always_uv: false,
            ..Default::default()
        };
        let mut service = AuthenticatorService::<_, (), _>::with_shared_storage(
            storage,
            None,
            security_config,
            PinConfig::default(),
        )
        .expect("the human path constructs its authenticator");

        let mut response = Vec::new();
        service
            .handle(&[0x04], &mut response)
            .expect("handle GetInfo");
        assert_eq!(response.first(), Some(&0x00));
        let value: serde_cbor::Value =
            serde_cbor::from_slice(&response[1..]).expect("decode authenticatorGetInfo");
        let serde_cbor::Value::Map(info) = value else {
            panic!("expected GetInfo map");
        };
        let Some(serde_cbor::Value::Map(options)) = info.get(&serde_cbor::Value::Integer(4)) else {
            panic!("expected GetInfo options map");
        };
        let option = |name: &str| options.get(&serde_cbor::Value::Text(name.to_string()));
        assert_eq!(option("rk"), Some(&serde_cbor::Value::Bool(true)));
        assert_eq!(option("plat"), Some(&serde_cbor::Value::Bool(false)));
        assert_eq!(
            option("makeCredUvNotRqd"),
            Some(&serde_cbor::Value::Bool(true))
        );
        assert_eq!(option("alwaysUv"), Some(&serde_cbor::Value::Bool(false)));
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
    fn test_reset_uv_retries_rejects_missing_or_partial_pin_auth() {
        use soft_fido2_ctap::cbor::MapBuilder;

        let temp_dir = tempfile::tempdir().expect("create temp directory");
        let cred_dir = temp_dir.path().join("credentials");
        std::fs::create_dir_all(&cred_dir).expect("create credential directory");
        let storage = LocalStorageAdapter::new(cred_dir).expect("create credential storage");

        let mut pin_state = pin_state_with_pin();
        pin_state.uv_retries = 0;
        let pin_storage = Arc::new(Mutex::new(TestPinStorage::new(pin_state)));
        let mut service = AuthenticatorService::with_pin_storage(
            storage,
            Some(pin_storage.clone()),
            SecurityConfig::default(),
            PinConfig::default(),
        )
        .expect("create authenticator service");

        let requests = [
            (
                "missing authorization",
                MapBuilder::new()
                    .insert(1, RESET_UV_RETRIES_SUBCOMMAND)
                    .expect("subcommand")
                    .build()
                    .expect("CBOR payload"),
            ),
            (
                "protocol only",
                MapBuilder::new()
                    .insert(1, RESET_UV_RETRIES_SUBCOMMAND)
                    .expect("subcommand")
                    .insert(3, 2u8)
                    .expect("protocol")
                    .build()
                    .expect("CBOR payload"),
            ),
            (
                "auth parameter only",
                MapBuilder::new()
                    .insert(1, RESET_UV_RETRIES_SUBCOMMAND)
                    .expect("subcommand")
                    .insert_bytes(4, &[0u8; 32])
                    .expect("auth parameter")
                    .build()
                    .expect("CBOR payload"),
            ),
            (
                "malformed protocol",
                MapBuilder::new()
                    .insert(1, RESET_UV_RETRIES_SUBCOMMAND)
                    .expect("subcommand")
                    .insert_bytes(3, &[0xff])
                    .expect("protocol")
                    .insert_bytes(4, &[0u8; 32])
                    .expect("auth parameter")
                    .build()
                    .expect("CBOR payload"),
            ),
        ];

        for (case, payload) in requests {
            let mut request = vec![CMD_PASSLESS_RESET_UV_RETRIES];
            request.extend_from_slice(&payload);
            let mut response = Vec::new();
            service
                .handle(&request, &mut response)
                .expect("handle reset request");
            assert_eq!(response, vec![StatusCode::PuatRequired as u8], "{case}");
            assert_eq!(
                pin_storage
                    .lock()
                    .expect("PIN storage lock")
                    .load_pin_state()
                    .expect("load PIN state")
                    .uv_retries,
                0,
                "{case} must not reset exhausted UV retries"
            );
        }

        // Supplying both fields without a valid token must also be rejected.
        let bogus_payload = MapBuilder::new()
            .insert(1, RESET_UV_RETRIES_SUBCOMMAND)
            .expect("subcommand")
            .insert(3, 2u8)
            .expect("protocol")
            .insert_bytes(4, &[0u8; 32])
            .expect("auth parameter")
            .build()
            .expect("CBOR payload");
        let mut request = vec![CMD_PASSLESS_RESET_UV_RETRIES];
        request.extend_from_slice(&bogus_payload);
        let mut response = Vec::new();
        service
            .handle(&request, &mut response)
            .expect("handle unauthenticated reset");
        assert_ne!(response.first(), Some(&(StatusCode::Success as u8)));
        assert_eq!(
            pin_storage
                .lock()
                .expect("PIN storage lock")
                .load_pin_state()
                .expect("load PIN state")
                .uv_retries,
            0
        );
    }

    #[test]
    fn test_reset_uv_retries_fails_closed_when_pin_state_is_unavailable() {
        use soft_fido2_ctap::cbor::MapBuilder;

        let temp_dir = tempfile::tempdir().expect("create temp directory");
        let cred_dir = temp_dir.path().join("credentials");
        std::fs::create_dir_all(&cred_dir).expect("create credential directory");
        let storage = LocalStorageAdapter::new(cred_dir).expect("create credential storage");

        let fail_load = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let pin_storage = Arc::new(Mutex::new(FailingPinConfigStorage {
            fail_load: fail_load.clone(),
        }));
        let mut service = AuthenticatorService::with_pin_storage(
            storage,
            Some(pin_storage),
            SecurityConfig::default(),
            PinConfig::default(),
        )
        .expect("create authenticator service");

        // A backend error after successful startup must not be interpreted as
        // "no PIN" even when the GetInfo path can still query a cached hint.
        fail_load.store(true, std::sync::atomic::Ordering::SeqCst);
        let payload = MapBuilder::new()
            .insert(1, RESET_UV_RETRIES_SUBCOMMAND)
            .expect("subcommand")
            .build()
            .expect("CBOR payload");
        let mut request = vec![CMD_PASSLESS_RESET_UV_RETRIES];
        request.extend_from_slice(&payload);
        let mut response = Vec::new();
        service
            .handle(&request, &mut response)
            .expect("handle reset request");
        assert_eq!(response, vec![StatusCode::Other as u8]);
    }

    #[test]
    fn test_reset_uv_retries_uses_authoritative_pin_state_not_cached_hint() {
        use soft_fido2_ctap::cbor::MapBuilder;

        // Both directions matter: a newly configured PIN must be enforced,
        // while a removed PIN must not permanently block the recovery path.
        for (cached_pin_configured, actual_pin_configured) in [(false, true), (true, false)] {
            let temp_dir = tempfile::tempdir().expect("create temp directory");
            let cred_dir = temp_dir.path().join("credentials");
            std::fs::create_dir_all(&cred_dir).expect("create credential directory");
            let storage = LocalStorageAdapter::new(cred_dir).expect("create credential storage");

            let mut state = if actual_pin_configured {
                pin_state_with_pin()
            } else {
                PinState::new()
            };
            state.uv_retries = 0;
            let pin_storage = Arc::new(Mutex::new(StalePinConfigStorage {
                state: Mutex::new(state),
                cached_pin_configured,
            }));
            let mut service = AuthenticatorService::with_pin_storage(
                storage,
                Some(pin_storage.clone()),
                SecurityConfig::default(),
                PinConfig::default(),
            )
            .expect("create authenticator service");

            let payload = MapBuilder::new()
                .insert(1, RESET_UV_RETRIES_SUBCOMMAND)
                .expect("subcommand")
                .build()
                .expect("CBOR payload");
            let mut request = vec![CMD_PASSLESS_RESET_UV_RETRIES];
            request.extend_from_slice(&payload);
            let mut response = Vec::new();
            service
                .handle(&request, &mut response)
                .expect("handle reset request");

            let persisted_retries = pin_storage
                .lock()
                .expect("PIN storage lock")
                .load_pin_state()
                .expect("load PIN state")
                .uv_retries;
            if actual_pin_configured {
                assert_eq!(response, vec![StatusCode::PuatRequired as u8]);
                assert_eq!(
                    persisted_retries, 0,
                    "unauthenticated reset changed UV retries"
                );
            } else {
                assert_eq!(response, vec![0x00, 0xa1, 0x01, 0x08]);
                assert_eq!(
                    persisted_retries, 8,
                    "PIN-less recovery was unexpectedly blocked"
                );
            }
        }
    }

    #[test]
    fn test_reset_uv_retries_without_pin_rejects_partial_or_invalid_auth() {
        use soft_fido2_ctap::cbor::MapBuilder;

        let temp_dir = tempfile::tempdir().expect("create temp directory");
        let cred_dir = temp_dir.path().join("credentials");
        std::fs::create_dir_all(&cred_dir).expect("create credential directory");
        let storage = LocalStorageAdapter::new(cred_dir).expect("create credential storage");

        let mut state = PinState::new();
        state.uv_retries = 0;
        let pin_storage = Arc::new(Mutex::new(TestPinStorage::new(state)));
        let mut service = AuthenticatorService::with_pin_storage(
            storage,
            Some(pin_storage.clone()),
            SecurityConfig::default(),
            PinConfig::default(),
        )
        .expect("create authenticator service");

        let payloads = [
            (
                "protocol only",
                MapBuilder::new()
                    .insert(1, RESET_UV_RETRIES_SUBCOMMAND)
                    .expect("subcommand")
                    .insert(3, 2u8)
                    .expect("protocol")
                    .build()
                    .expect("CBOR payload"),
            ),
            (
                "parameter only",
                MapBuilder::new()
                    .insert(1, RESET_UV_RETRIES_SUBCOMMAND)
                    .expect("subcommand")
                    .insert_bytes(4, &[0u8; 32])
                    .expect("parameter")
                    .build()
                    .expect("CBOR payload"),
            ),
            (
                "bogus complete authorization",
                MapBuilder::new()
                    .insert(1, RESET_UV_RETRIES_SUBCOMMAND)
                    .expect("subcommand")
                    .insert(3, 2u8)
                    .expect("protocol")
                    .insert_bytes(4, &[0u8; 32])
                    .expect("parameter")
                    .build()
                    .expect("CBOR payload"),
            ),
        ];

        for (case, payload) in payloads {
            let mut request = vec![CMD_PASSLESS_RESET_UV_RETRIES];
            request.extend_from_slice(&payload);
            let mut response = Vec::new();
            service
                .handle(&request, &mut response)
                .expect("handle reset request");
            assert_ne!(
                response.first(),
                Some(&(StatusCode::Success as u8)),
                "{case} should not bypass authorization checks"
            );
            assert_eq!(
                pin_storage
                    .lock()
                    .expect("PIN storage lock")
                    .load_pin_state()
                    .expect("load PIN state")
                    .uv_retries,
                0,
                "{case} must not change exhausted UV retries"
            );
        }
    }

    #[test]
    fn test_reset_uv_retries_without_pin_remains_available() {
        use soft_fido2_ctap::cbor::MapBuilder;

        let temp_dir = tempfile::tempdir().expect("create temp directory");
        let cred_dir = temp_dir.path().join("credentials");
        std::fs::create_dir_all(&cred_dir).expect("create credential directory");
        let storage = LocalStorageAdapter::new(cred_dir).expect("create credential storage");

        let mut pin_state = PinState::new();
        pin_state.uv_retries = 0;
        let pin_storage = Arc::new(Mutex::new(TestPinStorage::new(pin_state)));
        let mut service = AuthenticatorService::with_pin_storage(
            storage,
            Some(pin_storage.clone()),
            SecurityConfig::default(),
            PinConfig::default(),
        )
        .expect("create authenticator service");

        let payload = MapBuilder::new()
            .insert(1, RESET_UV_RETRIES_SUBCOMMAND)
            .expect("subcommand")
            .build()
            .expect("CBOR payload");
        let mut request = vec![CMD_PASSLESS_RESET_UV_RETRIES];
        request.extend_from_slice(&payload);
        let mut response = Vec::new();
        service
            .handle(&request, &mut response)
            .expect("handle reset without PIN");
        assert_eq!(response, vec![0x00, 0xa1, 0x01, 0x08]);
        assert_eq!(
            pin_storage
                .lock()
                .expect("PIN storage lock")
                .load_pin_state()
                .expect("load PIN state")
                .uv_retries,
            8
        );
    }

    #[test]
    fn test_reset_uv_retries_without_pin_storage_remains_available() {
        use soft_fido2_ctap::cbor::MapBuilder;

        let temp_dir = tempfile::tempdir().expect("create temp directory");
        let cred_dir = temp_dir.path().join("credentials");
        std::fs::create_dir_all(&cred_dir).expect("create credential directory");
        let storage = LocalStorageAdapter::new(cred_dir).expect("create credential storage");
        let mut service = AuthenticatorService::with_pin_storage(
            storage,
            None::<Arc<Mutex<()>>>,
            SecurityConfig::default(),
            PinConfig::default(),
        )
        .expect("create authenticator service");

        let payload = MapBuilder::new()
            .insert(1, RESET_UV_RETRIES_SUBCOMMAND)
            .expect("subcommand")
            .build()
            .expect("CBOR payload");
        let mut request = vec![CMD_PASSLESS_RESET_UV_RETRIES];
        request.extend_from_slice(&payload);
        let mut response = Vec::new();
        service
            .handle(&request, &mut response)
            .expect("handle reset without PIN storage");
        assert_eq!(response, vec![0x00, 0xa1, 0x01, 0x08]);
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

/// Issue #588: credentials minted while `alwaysUv` was in effect (the default, and forced in
/// v0.16.0 to v0.21.0 release builds regardless of `security.always_uv`) carry credProtect level 3
/// without the client asking for it. An OpenSSH GetAssertion (`up` only, no `uv`, allowList with
/// the key handle) must still sign with them after `always_uv = false`, without changing any other
/// answer and without revealing which RPs hold protected credentials.
#[cfg(test)]
mod protected_credential_tests {
    use super::test_prompts::{Answer, AutoAccept, Prompts};
    use super::*;

    use crate::storage::LocalStorageAdapter;

    use soft_fido2_ctap::SecPinHash;

    use ciborium::Value;
    use sha2::{Digest, Sha256};

    const SSH_RP_ID: &str = "ssh:";
    const EMPTY_RP_ID: &str = "nothing.example";
    const CLIENT_DATA_HASH: [u8; 32] = [0x5a; 32];
    const UP_FLAG: u8 = 0x01;
    const UV_FLAG: u8 = 0x04;

    struct FixedPinStorage(PinState);

    impl PinStorage for FixedPinStorage {
        fn load_pin_state(&self) -> core::result::Result<PinState, StatusCode> {
            Ok(self.0.clone())
        }

        fn save_pin_state(&self, _state: &PinState) -> core::result::Result<(), StatusCode> {
            Ok(())
        }

        fn is_pin_configured(&self) -> core::result::Result<bool, StatusCode> {
            Ok(self.0.pin_hash.is_some())
        }
    }

    fn text(value: &str) -> Value {
        Value::Text(value.to_string())
    }

    fn int(value: i64) -> Value {
        Value::Integer(value.into())
    }

    /// Encode a CTAP command; every map below is written in CTAP canonical key order.
    fn command(code: u8, params: Vec<(Value, Value)>) -> Vec<u8> {
        let mut request = vec![code];
        ciborium::into_writer(&Value::Map(params), &mut request).expect("encode CTAP request");
        request
    }

    /// OpenSSH `sk_enroll`. A plain `ssh-keygen -t {ed25519,ecdsa}-sk` sends no rk, no uv and no
    /// credProtect extension; `-O resident` adds rk and credProtect 2.
    fn enroll_request(alg: i64, cred_protect: Option<i64>) -> Vec<u8> {
        let mut params = vec![
            (int(1), Value::Bytes(CLIENT_DATA_HASH.to_vec())),
            (int(2), Value::Map(vec![(text("id"), text(SSH_RP_ID))])),
            (
                int(3),
                Value::Map(vec![
                    (text("id"), Value::Bytes(vec![0x42; 32])),
                    (text("name"), text("openssh")),
                ]),
            ),
            (
                int(4),
                Value::Array(vec![Value::Map(vec![
                    (text("alg"), int(alg)),
                    (text("type"), text("public-key")),
                ])]),
            ),
        ];
        if let Some(level) = cred_protect {
            params.push((int(6), Value::Map(vec![(text("credProtect"), int(level))])));
            params.push((int(7), Value::Map(vec![(text("rk"), Value::Bool(true))])));
        }
        command(0x01, params)
    }

    /// OpenSSH `sk_sign` for a key without verify-required: an allowList with the key handle and
    /// `{"up": up}`, never `uv`.
    fn sign_request(credential_ids: &[&[u8]], up: bool) -> Vec<u8> {
        let allow_list = credential_ids
            .iter()
            .map(|id| {
                Value::Map(vec![
                    (text("id"), Value::Bytes(id.to_vec())),
                    (text("type"), text("public-key")),
                ])
            })
            .collect();
        command(
            0x02,
            vec![
                (int(1), text(SSH_RP_ID)),
                (int(2), Value::Bytes(CLIENT_DATA_HASH.to_vec())),
                (int(3), Value::Array(allow_list)),
                (int(5), Value::Map(vec![(text("up"), Value::Bool(up))])),
            ],
        )
    }

    fn ssh_sign_request(credential_id: &[u8], up: bool) -> Vec<u8> {
        sign_request(&[credential_id], up)
    }

    /// A discoverable (no allowList) GetAssertion asking for presence only.
    fn discoverable_request(rp_id: &str) -> Vec<u8> {
        command(
            0x02,
            vec![
                (int(1), text(rp_id)),
                (int(2), Value::Bytes(CLIENT_DATA_HASH.to_vec())),
                (int(5), Value::Map(vec![(text("up"), Value::Bool(true))])),
            ],
        )
    }

    fn map_get<'a>(map: &'a Value, key: &Value) -> Option<&'a Value> {
        map.as_map()?
            .iter()
            .find(|(candidate, _)| candidate == key)
            .map(|(_, value)| value)
    }

    fn bytes_at(map: &Value, key: Value) -> Vec<u8> {
        map_get(map, &key)
            .and_then(Value::as_bytes)
            .cloned()
            .unwrap_or_else(|| panic!("missing byte string {key:?}"))
    }

    fn decode_success(response: &[u8]) -> Value {
        assert_eq!(
            response.first(),
            Some(&0x00),
            "CTAP status 0x{:02x}",
            response.first().copied().unwrap_or(0xff)
        );
        ciborium::from_reader(&response[1..]).expect("decode CTAP response")
    }

    fn respond<P: PinStorage + 'static>(
        service: &mut AuthenticatorService<LocalStorageAdapter, P>,
        request: &[u8],
    ) -> Vec<u8> {
        let mut response = Vec::new();
        service
            .handle(request, &mut response)
            .expect("handle CTAP request");
        response
    }

    /// soft-fido2's own answer, without the human service's protected-credential retry.
    fn soft_fido2_answer<P: PinStorage + 'static>(
        service: &mut AuthenticatorService<LocalStorageAdapter, P>,
        request: &[u8],
    ) -> Vec<u8> {
        let mut response = Vec::new();
        service
            .authenticator
            .handle(request, &mut response)
            .expect("handle CTAP request");
        response
    }

    struct Enrolled {
        credential_id: Vec<u8>,
        cose_key: Value,
    }

    fn enroll<P: PinStorage + 'static>(
        service: &mut AuthenticatorService<LocalStorageAdapter, P>,
        alg: i64,
        cred_protect: Option<i64>,
    ) -> Enrolled {
        let attestation = decode_success(&respond(service, &enroll_request(alg, cred_protect)));
        let auth_data = bytes_at(&attestation, int(2));
        // rpIdHash (32) || flags (1) || signCount (4) || aaguid (16) || idLen (2) || id || key
        let id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
        let credential_id = auth_data[55..55 + id_len].to_vec();
        let cose_key = ciborium::from_reader(&auth_data[55 + id_len..]).expect("COSE key");
        Enrolled {
            credential_id,
            cose_key,
        }
    }

    fn verify_signature(cose_key: &Value, signed: &[u8], signature: &[u8]) {
        let alg = map_get(cose_key, &int(3))
            .and_then(Value::as_integer)
            .map(i64::try_from)
            .and_then(core::result::Result::ok)
            .expect("COSE alg");
        let x = bytes_at(cose_key, int(-2));
        match alg {
            -8 => soft_fido2_crypto::eddsa::verify(&x, signed, signature)
                .expect("Ed25519 assertion signature verifies"),
            -7 => {
                let mut sec1 = vec![0x04];
                sec1.extend_from_slice(&x);
                sec1.extend_from_slice(&bytes_at(cose_key, int(-3)));
                soft_fido2_crypto::ecdsa::verify(&sec1, signed, signature)
                    .expect("ES256 assertion signature verifies")
            }
            other => panic!("unexpected COSE alg {other}"),
        }
    }

    /// Assert a successful assertion with exactly the given UP/UV flags; return its credential ID.
    fn assert_signed(response: &[u8], cose_key: Option<&Value>, flags: u8) -> Vec<u8> {
        let assertion = decode_success(response);
        let auth_data = bytes_at(&assertion, int(2));
        assert_eq!(auth_data[..32], Sha256::digest(SSH_RP_ID.as_bytes())[..]);
        assert_eq!(auth_data[32] & (UP_FLAG | UV_FLAG), flags);
        if let Some(cose_key) = cose_key {
            let signed = [auth_data.as_slice(), CLIENT_DATA_HASH.as_slice()].concat();
            verify_signature(cose_key, &signed, &bytes_at(&assertion, int(3)));
        }
        let credential = map_get(&assertion, &int(1)).expect("credential descriptor");
        bytes_at(credential, text("id"))
    }

    fn security_config(always_uv: bool) -> SecurityConfig {
        SecurityConfig {
            always_uv,
            ..Default::default()
        }
    }

    fn service_without_pin(
        storage: &Arc<Mutex<LocalStorageAdapter>>,
        always_uv: bool,
    ) -> AuthenticatorService<LocalStorageAdapter, ()> {
        AuthenticatorService::<_, (), _>::with_shared_storage(
            storage.clone(),
            None,
            security_config(always_uv),
            PinConfig::default(),
        )
        .expect("create human authenticator service")
    }

    fn service_with_pin(
        storage: &Arc<Mutex<LocalStorageAdapter>>,
        always_uv: bool,
    ) -> AuthenticatorService<LocalStorageAdapter, FixedPinStorage> {
        let mut pin_state = PinState::new();
        pin_state.pin_hash = Some(SecPinHash::new([0x42; 32]));
        AuthenticatorService::with_shared_storage(
            storage.clone(),
            Some(Arc::new(Mutex::new(FixedPinStorage(pin_state)))),
            security_config(always_uv),
            PinConfig::default(),
        )
        .expect("create human authenticator service")
    }

    fn local_storage(dir: &tempfile::TempDir) -> Arc<Mutex<LocalStorageAdapter>> {
        let path = dir.path().join("credentials");
        std::fs::create_dir_all(&path).expect("create credential directory");
        Arc::new(Mutex::new(
            LocalStorageAdapter::new(path).expect("create credential storage"),
        ))
    }

    fn stored(storage: &Arc<Mutex<LocalStorageAdapter>>, id: &[u8]) -> Credential {
        lock_shared_storage(storage)
            .read(id)
            .expect("read stored credential")
    }

    /// Enroll the way v0.21.0 release builds did: user verification forced on MakeCredential.
    fn enroll_with_forced_uv(storage: &Arc<Mutex<LocalStorageAdapter>>, alg: i64) -> Enrolled {
        let prompts = AutoAccept::install();
        let enrolled = enroll(&mut service_without_pin(storage, true), alg, Some(3));
        assert_eq!(prompts.uv_prompts(), 1, "enrollment performed built-in UV");
        assert_eq!(
            stored(storage, &enrolled.credential_id)
                .extensions
                .cred_protect,
            Some(3),
            "explicit credProtect request is honored"
        );
        enrolled
    }

    /// Enroll with `always_uv = false` and no UV: credProtect level 1.
    fn enroll_unprotected(storage: &Arc<Mutex<LocalStorageAdapter>>, alg: i64) -> Enrolled {
        let prompts = AutoAccept::install();
        let enrolled = enroll(&mut service_without_pin(storage, false), alg, None);
        assert_eq!(prompts.uv_prompts(), 0);
        assert_eq!(
            stored(storage, &enrolled.credential_id)
                .extensions
                .cred_protect,
            Some(1)
        );
        enrolled
    }

    #[test]
    fn ssh_sign_with_protected_credential_after_always_uv_is_disabled() {
        for alg in [-8, -7] {
            let dir = tempfile::tempdir().expect("create temp directory");
            let storage = local_storage(&dir);
            let enrolled = enroll_with_forced_uv(&storage, alg);

            // The daemon restarts with the user's `always_uv = false`.
            let mut service = service_without_pin(&storage, false);
            let prompts = AutoAccept::install();
            let response = respond(
                &mut service,
                &ssh_sign_request(&enrolled.credential_id, true),
            );
            // The protected credential is used only after built-in UV.
            assert_signed(&response, Some(&enrolled.cose_key), UP_FLAG | UV_FLAG);
            assert_eq!(
                prompts.uv_prompts(),
                1,
                "alg {alg}: one verification prompt"
            );
            assert_eq!(
                prompts.up_prompts(),
                0,
                "alg {alg}: UV prompt also proves presence"
            );
        }
    }

    #[test]
    fn denied_or_failed_uv_fails_closed() {
        for (answer, status) in [
            (Answer::Deny, StatusCode::OperationDenied),
            (Answer::Fail, StatusCode::Other),
        ] {
            let dir = tempfile::tempdir().expect("create temp directory");
            let storage = local_storage(&dir);
            let enrolled = enroll_with_forced_uv(&storage, -8);
            let before = stored(&storage, &enrolled.credential_id).sign_count;

            let mut service = service_without_pin(&storage, false);
            let prompts = Prompts::install(answer);
            let response = respond(
                &mut service,
                &ssh_sign_request(&enrolled.credential_id, true),
            );
            assert_eq!(response, vec![status as u8], "{answer:?}");
            assert_eq!((prompts.up_prompts(), prompts.uv_prompts()), (0, 1));
            assert_eq!(stored(&storage, &enrolled.credential_id).sign_count, before);
        }
    }

    #[test]
    fn mixed_allow_list_stays_on_presence_only_path() {
        let dir = tempfile::tempdir().expect("create temp directory");
        let storage = local_storage(&dir);
        let protected = enroll_with_forced_uv(&storage, -7);
        let plain = enroll_unprotected(&storage, -7);

        let mut service = service_without_pin(&storage, false);
        for ids in [
            [
                protected.credential_id.as_slice(),
                plain.credential_id.as_slice(),
            ],
            [
                plain.credential_id.as_slice(),
                protected.credential_id.as_slice(),
            ],
        ] {
            let prompts = AutoAccept::install();
            let response = respond(&mut service, &sign_request(&ids, true));
            let used = assert_signed(&response, Some(&plain.cose_key), UP_FLAG);
            assert_eq!(used, plain.credential_id);
            assert_eq!((prompts.up_prompts(), prompts.uv_prompts()), (1, 0));
        }
    }

    #[test]
    fn unprotected_credential_still_signs_with_presence_only() {
        let dir = tempfile::tempdir().expect("create temp directory");
        let storage = local_storage(&dir);
        let enrolled = enroll_unprotected(&storage, -8);

        let mut service = service_without_pin(&storage, false);
        let prompts = AutoAccept::install();
        let response = respond(
            &mut service,
            &ssh_sign_request(&enrolled.credential_id, true),
        );
        assert_signed(&response, Some(&enrolled.cose_key), UP_FLAG);
        assert_eq!((prompts.up_prompts(), prompts.uv_prompts()), (1, 0));
    }

    #[test]
    fn level_two_credential_keeps_soft_fido2_behaviour() {
        let dir = tempfile::tempdir().expect("create temp directory");
        let storage = local_storage(&dir);
        // `ssh-keygen -O resident`: rk and credProtect 2 (userVerificationOptionalWithCredentialIDList).
        let prompts = AutoAccept::install();
        let enrolled = enroll(&mut service_without_pin(&storage, false), -8, Some(2));
        drop(prompts);
        assert_eq!(
            stored(&storage, &enrolled.credential_id)
                .extensions
                .cred_protect,
            Some(2)
        );

        let mut service = service_without_pin(&storage, false);
        // With an allowList the credential is usable with presence only.
        let prompts = AutoAccept::install();
        let response = respond(
            &mut service,
            &ssh_sign_request(&enrolled.credential_id, true),
        );
        assert_signed(&response, Some(&enrolled.cose_key), UP_FLAG);
        assert_eq!((prompts.up_prompts(), prompts.uv_prompts()), (1, 0));

        // Without an allowList it stays hidden, with no prompt and no retry.
        let prompts = AutoAccept::install();
        let request = discoverable_request(SSH_RP_ID);
        assert_eq!(
            respond(&mut service, &request),
            vec![StatusCode::NoCredentials as u8]
        );
        assert_eq!((prompts.up_prompts(), prompts.uv_prompts()), (0, 0));
    }

    #[test]
    fn silent_probe_of_protected_credential_does_not_prompt() {
        let dir = tempfile::tempdir().expect("create temp directory");
        let storage = local_storage(&dir);
        let enrolled = enroll_with_forced_uv(&storage, -8);

        let mut service = service_without_pin(&storage, false);
        let prompts = AutoAccept::install();
        let response = respond(
            &mut service,
            &ssh_sign_request(&enrolled.credential_id, false),
        );
        assert_eq!(response, vec![StatusCode::NoCredentials as u8]);
        assert_eq!((prompts.up_prompts(), prompts.uv_prompts()), (0, 0));
    }

    #[test]
    fn protected_credential_with_pin_set_asks_the_client_for_the_pin() {
        let dir = tempfile::tempdir().expect("create temp directory");
        let storage = local_storage(&dir);
        let enrolled = enroll_with_forced_uv(&storage, -8);

        let mut service = service_with_pin(&storage, false);
        let prompts = AutoAccept::install();
        // libfido2 maps 0x36 to FIDO_ERR_PIN_REQUIRED; OpenSSH then prompts for the PIN and
        // retries with a pinUvAuthToken instead of failing with "invalid format".
        assert_eq!(
            respond(
                &mut service,
                &ssh_sign_request(&enrolled.credential_id, true)
            ),
            vec![StatusCode::PuatRequired as u8]
        );
        assert_eq!((prompts.up_prompts(), prompts.uv_prompts()), (0, 0));
    }

    #[test]
    fn always_uv_keeps_soft_fido2_answer() {
        let dir = tempfile::tempdir().expect("create temp directory");
        let storage = local_storage(&dir);
        let enrolled = enroll_with_forced_uv(&storage, -8);
        let request = ssh_sign_request(&enrolled.credential_id, true);

        // PIN set and `always_uv = true`: soft-fido2's alwaysUv step answers before any lookup.
        let mut service = service_with_pin(&storage, true);
        let prompts = AutoAccept::install();
        let expected = soft_fido2_answer(&mut service, &request);
        assert_eq!(expected, vec![StatusCode::OperationDenied as u8]);
        assert_eq!(respond(&mut service, &request), expected);
        assert_eq!((prompts.up_prompts(), prompts.uv_prompts()), (0, 0));

        // No PIN and `always_uv = true`: soft-fido2 itself performs built-in UV, once.
        let mut service = service_without_pin(&storage, true);
        let prompts = AutoAccept::install();
        let response = respond(&mut service, &request);
        assert_signed(&response, Some(&enrolled.cose_key), UP_FLAG | UV_FLAG);
        assert_eq!((prompts.up_prompts(), prompts.uv_prompts()), (0, 1));
    }

    /// No silent oracle: a discoverable request gets the same answer, and no prompt, whether or
    /// not the RP holds protected credentials.
    #[test]
    fn discoverable_requests_do_not_reveal_protected_credentials() {
        let dir = tempfile::tempdir().expect("create temp directory");
        let storage = local_storage(&dir);
        enroll_with_forced_uv(&storage, -7);

        fn answers<P: PinStorage + 'static>(
            service: &mut AuthenticatorService<LocalStorageAdapter, P>,
            case: &str,
        ) {
            let prompts = AutoAccept::install();
            let answers: Vec<_> = [SSH_RP_ID, EMPTY_RP_ID]
                .iter()
                .map(|rp_id| {
                    let request = discoverable_request(rp_id);
                    let response = respond(service, &request);
                    assert_eq!(
                        response,
                        soft_fido2_answer(service, &request),
                        "{case}: {rp_id}"
                    );
                    response
                })
                .collect();
            assert_eq!(answers[0], answers[1], "{case}: protected vs empty RP");
            assert_ne!(answers[0].first(), Some(&0x00), "{case}");
            assert_eq!(
                (prompts.up_prompts(), prompts.uv_prompts()),
                (0, 0),
                "{case}"
            );
        }

        answers(
            &mut service_with_pin(&storage, false),
            "PIN, always_uv=false",
        );
        answers(&mut service_with_pin(&storage, true), "PIN, always_uv=true");
        answers(
            &mut service_without_pin(&storage, false),
            "no PIN, always_uv=false",
        );
    }

    #[test]
    fn malformed_requests_keep_soft_fido2_answer() {
        let dir = tempfile::tempdir().expect("create temp directory");
        let storage = local_storage(&dir);
        let enrolled = enroll_with_forced_uv(&storage, -7);

        // Duplicate top-level key 1, which soft-fido2's CTAP CBOR profile rejects.
        let mut duplicate_key = ssh_sign_request(&enrolled.credential_id, true);
        assert_eq!(duplicate_key[1], 0xa4);
        duplicate_key[1] = 0xa5;
        duplicate_key.extend_from_slice(&[0x01, 0x63, b'a', b'b', b'c']);
        // A trailing item after the request map.
        let mut trailing = ssh_sign_request(&enrolled.credential_id, true);
        trailing.push(0x00);

        for request in [duplicate_key, trailing] {
            let mut with_pin = service_with_pin(&storage, false);
            let mut without_pin = service_without_pin(&storage, false);
            let prompts = AutoAccept::install();
            let expected = soft_fido2_answer(&mut with_pin, &request);
            assert_ne!(expected, vec![StatusCode::NoCredentials as u8]);
            assert_eq!(respond(&mut with_pin, &request), expected);
            assert_eq!(respond(&mut without_pin, &request), expected);
            assert_eq!((prompts.up_prompts(), prompts.uv_prompts()), (0, 0));
        }
    }

    #[test]
    fn uv_upgrade_keeps_ctap_canonical_encoding() {
        let id = vec![0x11; 16];
        let request = ssh_sign_request(&id, true);
        let view = GetAssertionUvView::without_uv(&request[1..]).expect("view");
        assert_eq!(view.allow_list, vec![id.clone()]);
        let upgraded = view.with_uv_requested().expect("upgrade");
        let value: Value = ciborium::from_reader(&upgraded[1..]).expect("decode");
        let options = map_get(&value, &int(5))
            .and_then(Value::as_map)
            .expect("options");
        let keys: Vec<_> = options.iter().filter_map(|(k, _)| k.as_text()).collect();
        assert_eq!(keys, ["up", "uv"]);

        // Without an options map, key 5 goes before any negative key (encoded 0x20 and up).
        let allow_list = Value::Array(vec![Value::Map(vec![
            (text("id"), Value::Bytes(id.clone())),
            (text("type"), text("public-key")),
        ])]);
        let request = command(
            0x02,
            vec![
                (int(1), text(SSH_RP_ID)),
                (int(2), Value::Bytes(CLIENT_DATA_HASH.to_vec())),
                (int(3), allow_list),
                (int(-1), Value::Bool(true)),
            ],
        );
        let view = GetAssertionUvView::without_uv(&request[1..]).expect("view");
        let upgraded = view.with_uv_requested().expect("upgrade");
        let value: Value = ciborium::from_reader(&upgraded[1..]).expect("decode");
        let keys: Vec<i128> = value
            .as_map()
            .expect("map")
            .iter()
            .filter_map(|(k, _)| k.as_integer().map(i128::from))
            .collect();
        assert_eq!(keys, [1, 2, 3, 5, -1]);

        // Requests that already involve UV, probe silently, or lack an allowList are not views.
        let pin_auth = command(
            0x02,
            vec![
                (int(1), text(SSH_RP_ID)),
                (int(2), Value::Bytes(CLIENT_DATA_HASH.to_vec())),
                (int(6), Value::Bytes(vec![0; 32])),
                (int(7), int(2)),
            ],
        );
        assert!(GetAssertionUvView::without_uv(&pin_auth[1..]).is_none());
        assert!(GetAssertionUvView::without_uv(&ssh_sign_request(&id, false)[1..]).is_none());
        assert!(GetAssertionUvView::without_uv(&discoverable_request(SSH_RP_ID)[1..]).is_none());

        // A non-canonical encoding (rpId key as a two-byte integer) is never re-encoded.
        let mut non_canonical = request[1..].to_vec();
        assert_eq!(non_canonical[1], 0x01);
        non_canonical.splice(1..2, [0x18, 0x01]);
        assert!(GetAssertionUvView::without_uv(&non_canonical).is_none());
    }
}
