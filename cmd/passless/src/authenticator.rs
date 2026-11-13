use crate::credential_backup::{
    BACKUP_COMMIT_SUBCOMMAND, BACKUP_PREPARE_SUBCOMMAND, BackupError, CMD_PASSLESS_BACKUP,
    CMD_PASSLESS_RESTORE, backup_commit_auth_data, backup_prepare_auth_data, bundle_token,
    decrypt_credential, encrypt_credential, restore_auth_data,
};
use crate::credential_protection::{
    CMD_PASSLESS_SET_CRED_PROTECT, CredProtectChange, PlannedChange, apply as apply_cred_protect,
    encode_response, lowering_prompt, parse_request, plan as plan_cred_protect,
    set_cred_protect_auth_data,
};
use crate::human_prompts::{PromptHandle, desktop_prompts, lock_prompts};
use crate::notification::NotificationResult;
use crate::pin_storage::{PinStorage, lock_pin_storage};
use crate::storage::{CredentialFilter, CredentialStorage, lock_shared_storage};
use crate::util::bytes_to_hex;
use crate::uv::{
    CommandProvider, FprintdProvider, NotificationProvider, UserVerificationManager,
    UserVerificationProvider, VerificationContext, VerificationResult,
};

#[cfg(feature = "face")]
use crate::uv::FaceIdProvider;

use passless_core::config::{PinConfig, PinEnforcement, SecurityConfig, UvConfig, UvProviderType};

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

/// Borrow every field of a stored credential for a storage write.
pub(crate) fn credential_ref(credential: &Credential) -> CredentialRef<'_> {
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

/// Logged when a request is answered CTAP2_ERR_UV_BLOCKED.
const UV_BLOCKED_HINT: &str = "CTAP request answered UV_BLOCKED (0x3c): built-in user \
    verification retries are exhausted. Run `passless client pin uv-reset` to restore them \
    (it asks for the PIN when one is set)";

/// Whether `response` is a bare CTAP2_ERR_UV_BLOCKED status answer.
fn is_uv_blocked_response(response: &[u8]) -> bool {
    response == [StatusCode::UvBlocked as u8]
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
    uv_manager: UserVerificationManager,
    uv_timeout_seconds: u32,
    prompts: PromptHandle,
    #[cfg(feature = "agent")]
    interaction_manager: Option<Arc<AgentInteractionManager>>,
    #[cfg(feature = "agent")]
    isolated_mode: bool,
}

impl<S: CredentialStorage, P: PinStorage> PasslessCallbacks<S, P> {
    /// Callbacks that ask through desktop notifications (used by tests; the service wires its
    /// own prompt handle through [`Self::with_prompts`]).
    #[allow(dead_code)]
    pub fn new(
        storage: Arc<Mutex<S>>,
        pin_storage: Option<Arc<Mutex<P>>>,
        security_config: SecurityConfig,
        pin_config: PinConfig,
        uv_config: UvConfig,
    ) -> Self {
        let uv_manager = build_uv_manager(&uv_config);
        let prompts = desktop_prompts();

        Self {
            storage,
            pin_storage,
            security_config,
            pin_config,
            uv_manager,
            uv_timeout_seconds: uv_config.timeout_seconds,
            prompts,
            #[cfg(feature = "agent")]
            interaction_manager: None,
            #[cfg(feature = "agent")]
            isolated_mode: false,
        }
    }

    /// Like [`Self::new`], asking the user through `prompts`.
    pub fn with_prompts(
        storage: Arc<Mutex<S>>,
        pin_storage: Option<Arc<Mutex<P>>>,
        security_config: SecurityConfig,
        pin_config: PinConfig,
        uv_config: UvConfig,
        prompts: PromptHandle,
    ) -> Self {
        let uv_manager = build_uv_manager(&uv_config);
        Self {
            storage,
            pin_storage,
            security_config,
            pin_config,
            uv_manager,
            uv_timeout_seconds: uv_config.timeout_seconds,
            prompts,
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
        uv_config: UvConfig,
        prompts: PromptHandle,
        interaction_manager: Arc<AgentInteractionManager>,
        isolated_mode: bool,
    ) -> Self {
        let uv_manager = build_uv_manager(&uv_config);
        Self {
            storage,
            pin_storage,
            security_config,
            pin_config,
            uv_manager,
            uv_timeout_seconds: uv_config.timeout_seconds,
            prompts,
            interaction_manager: Some(interaction_manager),
            isolated_mode,
        }
    }

    fn do_user_verification(
        &self,
        operation: &str,
        user: Option<&str>,
        rp: &str,
        require_strong_uv: bool,
    ) -> Result<VerificationResult> {
        #[cfg(debug_assertions)]
        {
            if std::env::var("PASSLESS_E2E_AUTO_ACCEPT_UV").as_deref() == Ok("1") {
                info!("E2E test mode: Auto-accepting user verification");
                return Ok(VerificationResult::Accepted);
            }
        }

        let is_registration = operation.to_lowercase().contains("registration")
            && !operation.to_lowercase().contains("credential excluded");

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

        if storage.disable_user_verification()
            && !is_registration
            && !should_verify
            && !require_strong_uv
        {
            debug!(
                "User verification handled by backend (e.g., GPG): {}",
                operation
            );
            return Ok(VerificationResult::Accepted);
        }

        if !should_verify && !require_strong_uv {
            debug!(
                "User verification disabled for {}: {}",
                if is_registration {
                    "registration"
                } else {
                    "authentication"
                },
                operation
            );
            return Ok(VerificationResult::Accepted);
        }

        drop(storage);
        let context = VerificationContext::new(operation)
            .with_relying_party(rp)
            .with_user(user.unwrap_or(""))
            .with_timeout(self.uv_timeout_seconds);
        let context = if require_strong_uv {
            context.require_strong_uv()
        } else {
            context
        };

        self.uv_manager.verify(&context).map_err(|e| {
            warn!("User verification failed: {}", e);
            soft_fido2::Error::Other
        })
    }
}

fn build_uv_manager(config: &UvConfig) -> UserVerificationManager {
    let mut providers: Vec<Box<dyn UserVerificationProvider>> = Vec::new();

    match config.provider {
        UvProviderType::Auto => {
            providers.extend(FprintdProvider::from_config(config.fprintd.enabled));
            #[cfg(feature = "face")]
            providers.extend(FaceIdProvider::from_config(
                config.face.enabled,
                config.face.camera_index,
                config.face.threshold,
            ));
            providers.push(NotificationProvider::from_config(config.timeout_seconds));
        }
        UvProviderType::Fprintd => {
            providers.extend(FprintdProvider::from_config(config.fprintd.enabled));
        }
        UvProviderType::Face => {
            #[cfg(feature = "face")]
            providers.extend(FaceIdProvider::from_config(
                config.face.enabled,
                config.face.camera_index,
                config.face.threshold,
            ));
            #[cfg(not(feature = "face"))]
            log::warn!("Face provider requested but 'face' feature not enabled");
        }
        UvProviderType::Notification => {
            providers.push(NotificationProvider::from_config(config.timeout_seconds));
        }
        UvProviderType::Command => {
            providers.extend(CommandProvider::from_config(
                config.command.enabled,
                config.command.command.clone(),
                config.timeout_seconds,
            ));
        }
    }

    UserVerificationManager::new(providers)
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

        let answer = lock_prompts(&self.prompts).user_presence(
            info,
            Some(rp),
            user,
            self.security_config.notification_timeout,
        );
        match answer {
            Ok(NotificationResult::Accepted) => Ok(UpResult::Accepted),
            // User presence has no retry budget: a closed or timed-out prompt refuses the
            // operation exactly like a denial.
            Ok(NotificationResult::Denied | NotificationResult::Dismissed) => Ok(UpResult::Denied),
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
            if std::env::var("PASSLESS_E2E_AUTO_ACCEPT_UV").as_deref() == Ok("1") {
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
                        "PIN is set, always_uv=false, enforcement=optional, using biometric/notification fallback"
                    );
                }
                PinEnforcement::Never => {
                    info!(
                        "PIN is set but enforcement=never, using biometric/notification fallback"
                    );
                }
            }
        }

        match self.do_user_verification(info, user, rp, true) {
            Ok(VerificationResult::Accepted) => {
                info!("User verification accepted");
                Ok(UvResult::AcceptedWithUp)
            }
            Ok(VerificationResult::Denied) => {
                warn!("User verification denied");
                Ok(UvResult::Denied)
            }
            Ok(VerificationResult::Timeout) => {
                warn!("User verification timed out");
                Ok(UvResult::Timeout)
            }
            Err(_) => {
                // Fall back to prompts-based UV (used in tests)
                let answer = lock_prompts(&self.prompts).user_verification(
                    info,
                    Some(rp),
                    user,
                    self.security_config.notification_timeout,
                );
                match answer {
                    Ok(NotificationResult::Accepted) => {
                        info!("User verification via notification: accepted");
                        Ok(UvResult::AcceptedWithUp)
                    }
                    Ok(NotificationResult::Denied) => {
                        warn!("User verification via notification: denied");
                        Ok(UvResult::Denied)
                    }
                    // Nobody refused: the prompt was dismissed or timed out. soft-fido2 consumes a UV
                    // retry on `Denied` only, and answers CTAP2_ERR_USER_ACTION_TIMEOUT here. The
                    // operation still fails closed.
                    Ok(NotificationResult::Dismissed) => {
                        warn!(
                            "User verification via notification: closed or timed out \
                             (no UV retry consumed)"
                        );
                        Ok(UvResult::Timeout)
                    }
                    Err(e) => {
                        error!("Failed to show notification: {}", e);
                        Err(soft_fido2::Error::Other)
                    }
                }
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
    /// The questions asked of the user; shared with the callbacks.
    prompts: PromptHandle,
    /// Seconds the lowering consent prompt waits before it counts as denied.
    notification_timeout: u32,
}

impl<S: CredentialStorage + 'static> AuthenticatorService<S, (), SoftwareCredentialKeyProvider> {
    /// Create a new authenticator service without PIN storage
    #[allow(dead_code)]
    pub fn new(
        storage: S,
        security_config: SecurityConfig,
        pin_config: PinConfig,
        uv_config: UvConfig,
    ) -> Result<Self> {
        Self::with_shared_storage(
            Arc::new(Mutex::new(storage)),
            None,
            security_config,
            pin_config,
            uv_config,
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
        uv_config: UvConfig,
        prompts: PromptHandle,
    ) -> Result<Authenticator<PasslessCallbacks<S, P>>> {
        #[cfg(feature = "agent")]
        {
            Self::build_authenticator_with_interaction(
                storage,
                pin_storage,
                security_config,
                pin_config,
                uv_config,
                prompts,
                None,
            )
        }
        #[cfg(not(feature = "agent"))]
        {
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

            let callbacks = PasslessCallbacks::with_prompts(
                storage,
                pin_storage.clone(),
                security_config,
                pin_config.clone(),
                uv_config,
                prompts,
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
        uv_config: UvConfig,
        prompts: PromptHandle,
        interaction_manager: Option<Arc<AgentInteractionManager>>,
    ) -> Result<Authenticator<PasslessCallbacks<S, P>>> {
        Self::build_authenticator_with_interaction_and_options(
            storage,
            pin_storage,
            security_config,
            pin_config,
            uv_config,
            prompts,
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
        uv_config: UvConfig,
        prompts: PromptHandle,
        interaction_manager: Option<Arc<AgentInteractionManager>>,
        use_agent_options: bool,
    ) -> Result<Authenticator<PasslessCallbacks<S, P>>> {
        let is_agent = use_agent_options;

        let options = if is_agent {
            AuthenticatorOptions {
                rk: true,
                up: true,
                uv: Some(false),
                plat: false,
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
                plat: false,
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
            .default_credential_backup_state(if security_config.enable_credential_backup {
                CredentialBackupState::Eligible
            } else {
                CredentialBackupState::NotEligible
            })
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
                uv_config,
                prompts,
                mgr.clone(),
                use_agent_options,
            ),
            None => PasslessCallbacks::with_prompts(
                storage,
                pin_storage.clone(),
                security_config,
                pin_config.clone(),
                uv_config,
                prompts,
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
        uv_config: UvConfig,
    ) -> Result<Self> {
        let storage = Arc::new(Mutex::new(storage));
        Self::with_shared_storage(storage, pin_storage, security_config, pin_config, uv_config)
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
        uv_config: UvConfig,
    ) -> Result<Self> {
        let prompts = desktop_prompts();
        let authenticator = Self::build_authenticator(
            storage.clone(),
            pin_storage.clone(),
            security_config.clone(),
            pin_config.clone(),
            uv_config,
            prompts.clone(),
        )?;

        let mut service = Self {
            authenticator,
            storage,
            always_uv: security_config.always_uv,
            credential_backup_enabled: security_config.enable_credential_backup,
            credential_backup_supported: true,
            pending_backups: HashMap::new(),
            pin_storage,
            prompts,
            notification_timeout: security_config.notification_timeout,
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
        uv_config: UvConfig,
        interaction_manager: Arc<AgentInteractionManager>,
    ) -> Result<Self> {
        let prompts = desktop_prompts();
        let authenticator = Self::build_authenticator_with_interaction(
            storage.clone(),
            pin_storage.clone(),
            security_config.clone(),
            pin_config.clone(),
            uv_config,
            prompts.clone(),
            Some(interaction_manager),
        )?;

        Ok(Self {
            authenticator,
            storage,
            max_uv_retries: pin_config.max_uv_retries,
            always_uv: security_config.always_uv,
            credential_backup_enabled: security_config.enable_credential_backup,
            credential_backup_supported: true,
            pending_backups: HashMap::new(),
            pin_storage,
            prompts,
            notification_timeout: security_config.notification_timeout,
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
        uv_config: UvConfig,
        key_provider: K,
        prompts: PromptHandle,
    ) -> Result<Authenticator<PasslessCallbacks<S, P>, K>> {
        #[cfg(feature = "agent")]
        {
            Self::build_authenticator_with_interaction_and_key_provider(
                storage,
                pin_storage,
                security_config,
                pin_config,
                uv_config,
                prompts,
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

            let callbacks = PasslessCallbacks::with_prompts(
                storage,
                pin_storage.clone(),
                security_config,
                pin_config.clone(),
                uv_config,
                prompts,
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
        uv_config: UvConfig,
        prompts: PromptHandle,
        interaction_manager: Option<Arc<AgentInteractionManager>>,
        key_provider: K,
    ) -> Result<Authenticator<PasslessCallbacks<S, P>, K>> {
        let is_agent = interaction_manager.is_some();

        let options = if is_agent {
            AuthenticatorOptions {
                rk: true,
                up: true,
                uv: Some(false),
                plat: false,
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
                plat: false,
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
            .default_credential_backup_state(if security_config.enable_credential_backup {
                CredentialBackupState::Eligible
            } else {
                CredentialBackupState::NotEligible
            })
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
                uv_config,
                prompts,
                mgr.clone(),
                is_agent,
            ),
            None => PasslessCallbacks::with_prompts(
                storage,
                pin_storage.clone(),
                security_config,
                pin_config.clone(),
                uv_config,
                prompts,
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
        uv_config: UvConfig,
    ) -> Result<Self> {
        let storage = Arc::new(Mutex::new(storage));
        Self::with_shared_storage_and_key_provider(
            storage,
            pin_storage,
            key_provider,
            security_config,
            pin_config,
            uv_config,
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
        uv_config: UvConfig,
    ) -> Result<Self> {
        let prompts = desktop_prompts();
        let authenticator = Self::build_authenticator_with_key_provider(
            storage.clone(),
            pin_storage.clone(),
            security_config.clone(),
            pin_config.clone(),
            uv_config,
            key_provider,
            prompts.clone(),
        )?;

        let mut service = Self {
            authenticator,
            storage,
            always_uv: security_config.always_uv,
            credential_backup_enabled: false,
            credential_backup_supported: false,
            pending_backups: HashMap::new(),
            pin_storage,
            prompts,
            notification_timeout: security_config.notification_timeout,
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
        uv_config: UvConfig,
        interaction_manager: Arc<AgentInteractionManager>,
    ) -> Result<Self> {
        let prompts = desktop_prompts();
        let authenticator = Self::build_authenticator_with_interaction_and_key_provider(
            storage.clone(),
            pin_storage.clone(),
            security_config.clone(),
            pin_config.clone(),
            uv_config,
            prompts.clone(),
            Some(interaction_manager),
            key_provider,
        )?;

        Ok(Self {
            authenticator,
            storage,
            max_uv_retries: pin_config.max_uv_retries,
            always_uv: security_config.always_uv,
            credential_backup_enabled: false,
            credential_backup_supported: false,
            pending_backups: HashMap::new(),
            pin_storage,
            prompts,
            notification_timeout: security_config.notification_timeout,
        })
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

    fn verify_credential_management_authorization(
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
                if let Err(status) =
                    self.verify_credential_management_authorization(protocol, &param, &auth_data)
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
                if let Err(status) =
                    self.verify_credential_management_authorization(protocol, &param, &auth_data)
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
                    storage.write(credential_ref(&credential))
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
        if let Err(status) =
            self.verify_credential_management_authorization(protocol, &param, &auth_data)
        {
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
            if storage.write(credential_ref(&credential)).is_err() {
                if let Some(previous) = existing {
                    let _ = storage.write(credential_ref(&previous));
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
    /// Before soft-fido2 0.18, MakeCredential with UV and no credProtect extension stored credProtect
    /// level 3 (userVerificationRequired); 0.18 stores level 2, so only credentials created by
    /// earlier passless versions need this. `alwaysUv` made every enrollment do so, including a
    /// plain `ssh-keygen -t ed25519-sk` key, and release builds from v0.16.0
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
    /// no effect worth undoing: in soft-fido2-ctap 0.17.0 `get_assertion::handle`, a request with
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

    /// Handle the Passless vendor command that changes stored `credProtect` levels.
    ///
    /// Wire format and rationale: `crate::credential_protection`. Authorization is mandatory in
    /// every mode: the request must carry a pinUvAuthParam computed with a live pinUvAuthToken
    /// that has the credential-management permission (a PIN token, or the token issued after the
    /// built-in user verification when no PIN is set). There is deliberately no path without it.
    fn handle_set_cred_protect_command(&mut self, payload: &[u8], response: &mut Vec<u8>) {
        response.clear();

        let request = match parse_request(payload) {
            Ok(request) => request,
            Err(status) => {
                response.push(status as u8);
                return;
            }
        };
        let Some((protocol, param)) = request.auth else {
            warn!("Rejected credProtect change without PIN/UV authorization");
            response.push(StatusCode::PuatRequired as u8);
            return;
        };
        let auth_data = set_cred_protect_auth_data(request.level, &request.credential_ids);
        if let Err(status) =
            self.verify_credential_management_authorization(protocol, &param, &auth_data)
        {
            warn!(
                "Rejected credProtect change: PIN/UV authorization failed (status 0x{:02x})",
                status
            );
            response.push(status);
            return;
        }

        // Read what would change, then ask for consent before any write.
        let planned = {
            let mut storage = lock_shared_storage(&self.storage);
            plan_cred_protect(&mut *storage, &request.credential_ids)
        };
        let planned = match planned {
            Ok(planned) => planned,
            Err(status) => {
                response.push(status as u8);
                return;
            }
        };
        if let Err(status) = self.confirm_lowering(&planned, request.level) {
            response.push(status as u8);
            return;
        }

        let result: core::result::Result<Vec<CredProtectChange>, StatusCode> = {
            let mut storage = lock_shared_storage(&self.storage);
            apply_cred_protect(&mut *storage, &request.credential_ids, request.level)
        };
        match result.and_then(|changes| encode_response(&changes)) {
            Ok(body) => {
                response.push(StatusCode::Success as u8);
                response.extend_from_slice(&body);
            }
            Err(status) => response.push(status as u8),
        }
    }

    /// Whether the user typed a PIN to get the credential-management token, which is itself the
    /// consent. With a PIN configured the built-in UV state is "supported, not configured"
    /// (`refresh_built_in_uv_state`), so soft-fido2 issues no UV token: the PIN is the only way.
    /// Reads the authoritative PIN state and fails closed.
    fn pin_is_the_only_consent(&self) -> core::result::Result<bool, StatusCode> {
        self.pin_configured_for_uv_reset()
    }

    /// Consent for lowering protection (raising and no-ops need none).
    ///
    /// When the token may have come from one click on the generic built-in UV prompt, which says
    /// nothing about what it authorizes, ask a dedicated question built from storage. Refuse
    /// outright when the human path auto-approves its prompts, and on any denial, timeout or
    /// error. Nothing has been written at this point.
    fn confirm_lowering(
        &self,
        planned: &[PlannedChange],
        level: u8,
    ) -> core::result::Result<(), StatusCode> {
        let Some((summary, body)) = lowering_prompt(planned, level) else {
            return Ok(());
        };
        if self.pin_is_the_only_consent()? {
            return Ok(());
        }

        let mut prompts = lock_prompts(&self.prompts);
        match prompts.interaction_is_automatic() {
            Ok(false) => {}
            Ok(true) => {
                warn!(
                    "Refused to lower credential protection: no PIN gates the request and the \
                     human path auto-approves prompts (PASSLESS_INTERACTION_MODE=automatic)"
                );
                return Err(StatusCode::NotAllowed);
            }
            Err(error) => {
                warn!("Refused to lower credential protection: {}", error);
                return Err(StatusCode::Other);
            }
        }
        match prompts.confirm_credential_protection_lowering(
            &summary,
            &body,
            self.notification_timeout,
        ) {
            Ok(NotificationResult::Accepted) => {
                info!("Lowering credential protection confirmed by the user");
                Ok(())
            }
            Ok(NotificationResult::Denied | NotificationResult::Dismissed) => {
                warn!("Refused to lower credential protection: denied, closed or timed out");
                Err(StatusCode::OperationDenied)
            }
            Err(error) => {
                warn!(
                    "Refused to lower credential protection: the prompt failed: {}",
                    error
                );
                Err(StatusCode::Other)
            }
        }
    }

    /// Process a CTAP request and generate a response
    pub fn handle(&mut self, request: &[u8], response_buffer: &mut Vec<u8>) -> Result<()> {
        let result = self.handle_request(request, response_buffer);
        // soft-fido2 reports a CTAP error as a one-byte status response, not as an `Err`, so
        // inspect what is actually answered, whichever handler answered it.
        if result.is_ok() && is_uv_blocked_response(response_buffer) {
            error!("{UV_BLOCKED_HINT}");
        }
        result
    }

    fn handle_request(&mut self, request: &[u8], response_buffer: &mut Vec<u8>) -> Result<()> {
        self.refresh_built_in_uv_state()?;

        if request.first() == Some(&CMD_PASSLESS_BACKUP) {
            self.handle_backup_command(&request[1..], response_buffer);
            return Ok(());
        }
        if request.first() == Some(&CMD_PASSLESS_RESTORE) {
            self.handle_restore_command(&request[1..], response_buffer);
            return Ok(());
        }
        if request.first() == Some(&CMD_PASSLESS_SET_CRED_PROTECT) {
            self.handle_set_cred_protect_command(&request[1..], response_buffer);
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
                    // Report the counter that is actually in effect. soft-fido2 refills its
                    // in-memory counter to its own maximum (`pin.max_retries`), not to
                    // `pin.max_uv_retries`, so the configured value may not be what the daemon
                    // now allows.
                    let in_effect = match self.authenticator.uv_retries() {
                        Ok(retries) => retries,
                        Err(_) => {
                            response_buffer.push(StatusCode::Other as u8);
                            return Ok(());
                        }
                    };
                    response_buffer.push(0x00);
                    if let Ok(cbor_data) = soft_fido2_ctap::cbor::MapBuilder::new()
                        .insert(1, in_effect)
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
        result?;
        Ok(())
    }

    /// Get storage information
    pub fn storage_info(&self) -> String {
        let storage = lock_shared_storage(&self.storage);
        format!("Credentials in storage: {}", storage.count_credentials())
    }

    /// Replace the questions asked of the user (tests).
    #[cfg(test)]
    pub fn set_prompts(&self, prompts: impl crate::human_prompts::HumanPrompts + 'static) {
        *lock_prompts(&self.prompts) = Box::new(prompts);
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

    use crate::credential_protection::set_cred_protect_auth_data;
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
            UvConfig::default(),
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
            UvConfig::default(),
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
    fn test_notification_only_cannot_satisfy_ctap_uv_even_when_up_prompts_disabled() {
        let dir = tempfile::tempdir().expect("create temp directory");
        let credential_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&credential_dir).expect("create credential dir");
        let storage = LocalStorageAdapter::new(credential_dir).expect("create credential storage");
        let security = SecurityConfig {
            user_verification_authentication: false,
            user_verification_registration: false,
            ..Default::default()
        };
        let uv = UvConfig {
            provider: UvProviderType::Notification,
            ..Default::default()
        };
        let callbacks = PasslessCallbacks::<LocalStorageAdapter, ()>::new(
            Arc::new(Mutex::new(storage)),
            None,
            security,
            PinConfig::default(),
            uv,
        );

        assert!(matches!(
            callbacks.request_up("authentication", None, "example.com"),
            Ok(UpResult::Accepted)
        ));
        assert!(callbacks.request_uv("authentication", None, "example.com").is_err());
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
        let uv_config = UvConfig::default();

        let service = AuthenticatorService::new(storage, security_config, pin_config, uv_config);
        assert!(service.is_ok(), "Service creation should succeed");

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_service_with_custom_uv_config() {
        let temp_dir = std::env::temp_dir().join("test_passless_uv");
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
            always_uv: false,
            user_verification_registration: false,
            user_verification_authentication: false,
            notification_timeout: 30,
            enable_credential_backup: false,
        };

        let pin_config = PinConfig::default();
        let uv_config = UvConfig {
            provider: passless_core::config::UvProviderType::Notification,
            timeout_seconds: 60,
            ..Default::default()
        };

        let service = AuthenticatorService::new(storage, security_config, pin_config, uv_config);
        assert!(
            service.is_ok(),
            "Service creation with custom UV config should succeed"
        );

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_service_with_uv_disabled() {
        let temp_dir = std::env::temp_dir().join("test_passless_no_uv");
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
            always_uv: false,
            user_verification_registration: false,
            user_verification_authentication: false,
            notification_timeout: 30,
            enable_credential_backup: false,
        };

        let pin_config = PinConfig::default();
        let uv_config = UvConfig::default();

        let service = AuthenticatorService::new(storage, security_config, pin_config, uv_config);
        assert!(
            service.is_ok(),
            "Service creation with UV disabled should succeed"
        );

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
            UvConfig::default(),
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
            UvConfig::default(),
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
                UvConfig::default(),
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
            UvConfig::default(),
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
            UvConfig::default(),
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
            UvConfig::default(),
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
            UvConfig::default(),
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
            UvConfig::default(),
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

    /// Platform side of the PIN/UV protocol, enough to obtain a pinUvAuthToken in process.
    mod platform {
        use super::*;

        use soft_fido2_crypto::{
            ecdh::KeyPair,
            pin_protocol::{v1, v2},
        };

        use sha2::{Digest, Sha256};
        use soft_fido2_ctap::cbor::{MapBuilder, Value, decode};
        use zeroize::Zeroizing;

        pub const PIN: &str = "1234";

        fn map_entry(value: &Value, key: i128) -> Option<Value> {
            match value {
                Value::Map(entries) => entries.iter().find_map(|(k, v)| match k {
                    Value::Integer(i) if *i == key => Some(v.clone()),
                    _ => None,
                }),
                _ => None,
            }
        }

        fn bytes(value: Option<Value>) -> Vec<u8> {
            match value {
                Some(Value::Bytes(bytes)) => bytes,
                other => panic!("expected a byte string, got {other:?}"),
            }
        }

        pub fn pin_state() -> PinState {
            let mut state = PinState::new();
            state.pin_hash = Some(SecPinHash::new(Sha256::digest(PIN.as_bytes()).into()));
            state
        }

        /// How the platform asks for the token.
        pub enum Way<'a> {
            /// getPinUvAuthTokenUsingPinWithPermissions (0x09).
            Pin(&'a str),
            /// getPinUvAuthTokenUsingUvWithPermissions (0x06): the built-in UV prompt.
            BuiltInUv,
        }

        /// Run getKeyAgreement and the token request for `protocol` (1 or 2) against `service`.
        ///
        /// Returns the pinUvAuthToken, or the status the authenticator answered.
        pub fn token<S: CredentialStorage + 'static, P: PinStorage + 'static>(
            service: &mut AuthenticatorService<S, P>,
            protocol: u8,
            way: Way<'_>,
            permissions: u8,
            rp_id: Option<&str>,
        ) -> core::result::Result<[u8; 32], u8> {
            let platform = KeyPair::generate().expect("platform key pair");

            let mut request = vec![0x06];
            request.extend(
                MapBuilder::new()
                    .insert(1, protocol)
                    .and_then(|b| b.insert(2, 0x02u8))
                    .and_then(|b| b.build())
                    .expect("getKeyAgreement"),
            );
            let mut response = Vec::new();
            service.handle(&request, &mut response).expect("handle");
            assert_eq!(response.first(), Some(&0x00), "getKeyAgreement status");
            let reply: Value = decode(&response[1..]).expect("key agreement reply");
            let cose = map_entry(&reply, 1).expect("authenticator key");
            let mut peer = vec![0x04];
            peer.extend(bytes(map_entry(&cose, -2)));
            peer.extend(bytes(map_entry(&cose, -3)));
            let shared = platform.shared_secret(&peer).expect("ECDH");
            let enc_key: Zeroizing<[u8; 32]> = if protocol == 1 {
                v1::derive_keys(&shared).0
            } else {
                v2::derive_encryption_key(&shared)
            };

            let (x, y) = platform.public_key_cose();
            let platform_cose = Value::Map(vec![
                (Value::Integer(1), Value::Integer(2)),
                (Value::Integer(3), Value::Integer(-25)),
                (Value::Integer(-1), Value::Integer(1)),
                (Value::Integer(-2), Value::Bytes(x.to_vec())),
                (Value::Integer(-3), Value::Bytes(y.to_vec())),
            ]);
            let mut builder = MapBuilder::new()
                .insert(1, protocol)
                .and_then(|b| b.insert(3, &platform_cose))
                .and_then(|b| b.insert(9, permissions))
                .expect("token request");
            builder = match way {
                Way::Pin(pin) => {
                    let pin_hash = Sha256::digest(pin.as_bytes());
                    let pin_hash_enc = if protocol == 1 {
                        v1::encrypt(&enc_key, &pin_hash[..16])
                    } else {
                        v2::encrypt(&enc_key, &pin_hash[..16])
                    }
                    .expect("encrypt PIN hash");
                    builder
                        .insert(2, 0x09u8)
                        .and_then(|b| b.insert_bytes(6, &pin_hash_enc))
                        .expect("PIN token request")
                }
                Way::BuiltInUv => builder.insert(2, 0x06u8).expect("UV token request"),
            };
            if let Some(rp_id) = rp_id {
                builder = builder.insert(10, rp_id).expect("rp id");
            }
            let mut request = vec![0x06];
            request.extend(builder.build().expect("token request"));
            let mut response = Vec::new();
            service.handle(&request, &mut response).expect("handle");
            if response.first() != Some(&0x00) {
                return Err(response.first().copied().unwrap_or(0xff));
            }
            let reply: Value = decode(&response[1..]).expect("token reply");
            let encrypted = bytes(map_entry(&reply, 2));
            let token = if protocol == 1 {
                v1::decrypt(&enc_key, &encrypted)
            } else {
                v2::decrypt(&enc_key, &encrypted)
            }
            .expect("decrypt token");
            Ok(token[..32].try_into().expect("32-byte token"))
        }

        /// A protocol 2 PIN token.
        pub fn pin_token<S: CredentialStorage + 'static, P: PinStorage + 'static>(
            service: &mut AuthenticatorService<S, P>,
            pin: &str,
            permissions: u8,
            rp_id: Option<&str>,
        ) -> core::result::Result<[u8; 32], u8> {
            token(service, 2, Way::Pin(pin), permissions, rp_id)
        }

        /// pinUvAuthParam, protocol 2.
        pub fn authenticate(token: &[u8; 32], data: &[u8]) -> Vec<u8> {
            v2::authenticate(token, data).to_vec()
        }

        /// pinUvAuthParam, protocol 1 (16 bytes).
        pub fn authenticate_v1(token: &[u8; 32], data: &[u8]) -> Vec<u8> {
            v1::authenticate(token, data).to_vec()
        }
    }

    /// Records and scripts the questions asked of the user.
    #[derive(Default)]
    struct PromptLog {
        verifications: usize,
        presences: usize,
        /// `(summary, body)` of every lowering consent question.
        lowerings: Vec<(String, String)>,
    }

    struct ScriptedPrompts {
        log: Arc<Mutex<PromptLog>>,
        verification: NotificationResult,
        lowering: core::result::Result<NotificationResult, String>,
        automatic: core::result::Result<bool, String>,
    }

    impl ScriptedPrompts {
        fn new(
            lowering: core::result::Result<NotificationResult, String>,
        ) -> (Self, Arc<Mutex<PromptLog>>) {
            let log = Arc::new(Mutex::new(PromptLog::default()));
            (
                Self {
                    log: log.clone(),
                    verification: NotificationResult::Accepted,
                    lowering,
                    automatic: Ok(false),
                },
                log,
            )
        }
    }

    impl crate::human_prompts::HumanPrompts for ScriptedPrompts {
        fn user_presence(
            &mut self,
            _: &str,
            _: Option<&str>,
            _: Option<&str>,
            _: u32,
        ) -> core::result::Result<NotificationResult, String> {
            self.log.lock().unwrap().presences += 1;
            Ok(NotificationResult::Accepted)
        }

        fn user_verification(
            &mut self,
            _: &str,
            _: Option<&str>,
            _: Option<&str>,
            _: u32,
        ) -> core::result::Result<NotificationResult, String> {
            self.log.lock().unwrap().verifications += 1;
            Ok(self.verification)
        }

        fn confirm_credential_protection_lowering(
            &mut self,
            summary: &str,
            body: &str,
            _: u32,
        ) -> core::result::Result<NotificationResult, String> {
            self.log
                .lock()
                .unwrap()
                .lowerings
                .push((summary.to_string(), body.to_string()));
            self.lowering.clone()
        }

        fn interaction_is_automatic(&self) -> core::result::Result<bool, String> {
            self.automatic.clone()
        }
    }

    /// Service over a local store seeded with `credentials` and a configured PIN.
    fn cred_protect_service(
        credentials: &[Credential],
        with_pin: bool,
    ) -> (
        AuthenticatorService<LocalStorageAdapter, TestPinStorage>,
        tempfile::TempDir,
    ) {
        cred_protect_service_with(
            credentials,
            with_pin,
            SecurityConfig::default(),
            PinConfig::default(),
        )
    }

    fn cred_protect_service_with(
        credentials: &[Credential],
        with_pin: bool,
        security_config: SecurityConfig,
        pin_config: PinConfig,
    ) -> (
        AuthenticatorService<LocalStorageAdapter, TestPinStorage>,
        tempfile::TempDir,
    ) {
        let temp_dir = tempfile::tempdir().expect("create temp directory");
        let cred_dir = temp_dir.path().join("credentials");
        std::fs::create_dir_all(&cred_dir).expect("create credential directory");
        let mut storage = LocalStorageAdapter::new(cred_dir).expect("create credential storage");
        for credential in credentials {
            storage
                .write(credential_ref(credential))
                .expect("seed credential");
        }
        let state = if with_pin {
            platform::pin_state()
        } else {
            PinState::new()
        };
        let service = AuthenticatorService::with_pin_storage(
            storage,
            Some(Arc::new(Mutex::new(TestPinStorage::new(state)))),
            security_config,
            pin_config,
            UvConfig::default(),
        )
        .expect("create authenticator service");
        (service, temp_dir)
    }

    fn stored_level(
        service: &AuthenticatorService<LocalStorageAdapter, TestPinStorage>,
        id: &[u8],
    ) -> Option<u8> {
        lock_shared_storage(&service.storage)
            .read(id)
            .expect("read credential")
            .extensions
            .cred_protect
    }

    /// Send the vendor command; `auth` is `(protocol, param)` or `None` for no authorization.
    fn send_set_cred_protect(
        service: &mut AuthenticatorService<LocalStorageAdapter, TestPinStorage>,
        ids: &[Vec<u8>],
        level: u8,
        auth: Option<(u8, Vec<u8>)>,
    ) -> Vec<u8> {
        use soft_fido2_ctap::cbor::MapBuilder;

        let mut builder = MapBuilder::new()
            .insert(1, crate::credential_protection::SET_CRED_PROTECT_SUBCOMMAND)
            .and_then(|b| {
                b.insert(
                    2,
                    ids.iter()
                        .map(|id| serde_bytes::ByteBuf::from(id.clone()))
                        .collect::<Vec<_>>(),
                )
            })
            .and_then(|b| b.insert(3, level))
            .expect("request");
        if let Some((protocol, param)) = auth {
            builder = builder
                .insert(4, protocol)
                .and_then(|b| b.insert_bytes(5, &param))
                .expect("authorization");
        }
        let mut request = vec![CMD_PASSLESS_SET_CRED_PROTECT];
        request.extend(builder.build().expect("request"));
        let mut response = Vec::new();
        service
            .handle(&request, &mut response)
            .expect("handle set-cred-protect");
        response
    }

    fn authorized(token: &[u8; 32], ids: &[Vec<u8>], level: u8) -> Option<(u8, Vec<u8>)> {
        Some((
            2,
            platform::authenticate(token, &set_cred_protect_auth_data(level, ids)),
        ))
    }

    const CM_PERMISSION: u8 = soft_fido2::request::Permission::CredentialManagement as u8;

    #[test]
    fn test_set_cred_protect_changes_only_the_level_after_pin_authorization() {
        use crate::credential_protection::{parse_response, test_support::test_credential};

        let ssh_a = test_credential(1, "ssh:", Some(3));
        let ssh_b = test_credential(2, "ssh:", Some(3));
        let other = test_credential(3, "example.com", Some(3));
        let (mut service, _dir) =
            cred_protect_service(&[ssh_a.clone(), ssh_b.clone(), other.clone()], true);
        let ids = vec![ssh_a.id.clone(), ssh_b.id.clone()];

        let token = platform::pin_token(&mut service, platform::PIN, CM_PERMISSION, None)
            .expect("PIN token");
        let response = send_set_cred_protect(&mut service, &ids, 1, authorized(&token, &ids, 1));
        assert_eq!(response.first(), Some(&0x00), "status {response:02x?}");
        let changes = parse_response(&response[1..]).expect("response");
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().all(|c| c.previous == 3 && c.current == 1));
        assert_eq!(changes[0].credential_id, ssh_a.id);

        for original in [&ssh_a, &ssh_b] {
            let stored = lock_shared_storage(&service.storage)
                .read(&original.id)
                .expect("read");
            let mut expected = original.clone();
            expected.extensions.cred_protect = Some(1);
            assert_eq!(stored, expected, "only credProtect may differ");
        }
        assert_eq!(
            stored_level(&service, &other.id),
            Some(3),
            "other RP untouched"
        );

        // Raising works too (a fresh token: the previous one covered other data).
        let token = platform::pin_token(&mut service, platform::PIN, CM_PERMISSION, None)
            .expect("PIN token");
        let one = vec![ssh_a.id.clone()];
        let response = send_set_cred_protect(&mut service, &one, 3, authorized(&token, &one, 3));
        assert_eq!(response.first(), Some(&0x00));
        assert_eq!(stored_level(&service, &ssh_a.id), Some(3));
        assert_eq!(stored_level(&service, &ssh_b.id), Some(1));
    }

    #[test]
    fn test_set_cred_protect_rejects_requests_without_valid_authorization() {
        use crate::credential_protection::test_support::test_credential;

        let credential = test_credential(1, "ssh:", Some(3));
        let ids = vec![credential.id.clone()];

        for with_pin in [true, false] {
            let (mut service, _dir) =
                cred_protect_service(std::slice::from_ref(&credential), with_pin);
            let unchanged = |service: &AuthenticatorService<_, _>| {
                assert_eq!(stored_level(service, &credential.id), Some(3));
            };

            // No authorization at all, whether or not a PIN is set.
            let response = send_set_cred_protect(&mut service, &ids, 1, None);
            assert_eq!(
                response,
                vec![StatusCode::PuatRequired as u8],
                "pin={with_pin}"
            );
            unchanged(&service);

            // An authorization parameter without any token having been issued.
            let response = send_set_cred_protect(&mut service, &ids, 1, Some((2, vec![0u8; 32])));
            assert_eq!(
                response,
                vec![StatusCode::PuatRequired as u8],
                "pin={with_pin}"
            );
            unchanged(&service);
        }

        let (mut service, _dir) = cred_protect_service(std::slice::from_ref(&credential), true);
        let token = platform::pin_token(&mut service, platform::PIN, CM_PERMISSION, None)
            .expect("PIN token");

        // A well-formed parameter computed over a different level does not authorize this one.
        let response = send_set_cred_protect(&mut service, &ids, 1, authorized(&token, &ids, 2));
        assert_eq!(response, vec![StatusCode::PinAuthInvalid as u8]);
        // Nor does one computed over a different credential.
        let other_ids = vec![vec![9u8; 32]];
        let response =
            send_set_cred_protect(&mut service, &ids, 1, authorized(&token, &other_ids, 1));
        assert_eq!(response, vec![StatusCode::PinAuthInvalid as u8]);
        // Nor does an unknown protocol.
        let response = send_set_cred_protect(
            &mut service,
            &ids,
            1,
            Some((7, platform::authenticate(&token, b"x"))),
        );
        assert_ne!(response.first(), Some(&0x00));
        assert_eq!(stored_level(&service, &credential.id), Some(3));

        // A genuine token without the credential-management permission is not enough.
        let token = platform::pin_token(
            &mut service,
            platform::PIN,
            soft_fido2::request::Permission::MakeCredential as u8,
            Some("ssh:"),
        )
        .expect("make-credential token");
        let response = send_set_cred_protect(&mut service, &ids, 1, authorized(&token, &ids, 1));
        assert_eq!(response, vec![StatusCode::UnauthorizedPermission as u8]);
        assert_eq!(stored_level(&service, &credential.id), Some(3));

        // And a wrong PIN yields no token at all.
        assert!(platform::pin_token(&mut service, "0000", CM_PERMISSION, None).is_err());
    }

    #[test]
    fn test_set_cred_protect_rejects_invalid_levels_and_unknown_credentials() {
        use crate::credential_protection::test_support::test_credential;

        let credential = test_credential(1, "ssh:", Some(3));
        let ids = vec![credential.id.clone()];
        let (mut service, _dir) = cred_protect_service(std::slice::from_ref(&credential), true);
        let token = platform::pin_token(&mut service, platform::PIN, CM_PERMISSION, None)
            .expect("PIN token");

        for level in [0u8, 4, 255] {
            let response =
                send_set_cred_protect(&mut service, &ids, level, authorized(&token, &ids, level));
            assert_eq!(
                response,
                vec![StatusCode::InvalidParameter as u8],
                "level {level}"
            );
        }
        assert_eq!(stored_level(&service, &credential.id), Some(3));

        let unknown = vec![vec![9u8; 32]];
        let response =
            send_set_cred_protect(&mut service, &unknown, 1, authorized(&token, &unknown, 1));
        assert_eq!(response, vec![StatusCode::NoCredentials as u8]);

        // A missing credential in a batch leaves the existing one unchanged.
        let batch = vec![credential.id.clone(), vec![9u8; 32]];
        let response =
            send_set_cred_protect(&mut service, &batch, 1, authorized(&token, &batch, 1));
        assert_eq!(response, vec![StatusCode::NoCredentials as u8]);
        assert_eq!(stored_level(&service, &credential.id), Some(3));
    }

    fn authorized_v1(token: &[u8; 32], ids: &[Vec<u8>], level: u8) -> Option<(u8, Vec<u8>)> {
        Some((
            1,
            platform::authenticate_v1(token, &set_cred_protect_auth_data(level, ids)),
        ))
    }

    fn ids_of(credentials: &[&Credential]) -> Vec<Vec<u8>> {
        credentials.iter().map(|c| c.id.clone()).collect()
    }

    /// Lower `ids` to `level` with a built-in UV token (no PIN configured), the prompts being
    /// `prompts`. Returns the response and the prompt log.
    fn lower_with_built_in_uv(
        service: &mut AuthenticatorService<LocalStorageAdapter, TestPinStorage>,
        ids: &[Vec<u8>],
        level: u8,
    ) -> Vec<u8> {
        let token = platform::token(service, 2, platform::Way::BuiltInUv, CM_PERMISSION, None)
            .expect("built-in UV token");
        send_set_cred_protect(service, ids, level, authorized(&token, ids, level))
    }

    #[test]
    fn test_set_cred_protect_without_pin_asks_a_dedicated_question_before_lowering() {
        use crate::credential_protection::{parse_response, test_support::test_credential};

        let ssh_a = test_credential(1, "ssh:", Some(3));
        let ssh_b = test_credential(2, "ssh:", Some(3));
        let (mut service, _dir) = cred_protect_service(&[ssh_a.clone(), ssh_b.clone()], false);
        let (prompts, log) = ScriptedPrompts::new(Ok(NotificationResult::Accepted));
        service.set_prompts(prompts);
        let ids = ids_of(&[&ssh_a, &ssh_b]);

        let response = lower_with_built_in_uv(&mut service, &ids, 1);
        assert_eq!(response.first(), Some(&0x00), "status {response:02x?}");
        let changes = parse_response(&response[1..]).expect("response");
        assert!(changes.iter().all(|c| c.previous == 3 && c.current == 1));
        assert_eq!(stored_level(&service, &ssh_a.id), Some(1));
        assert_eq!(stored_level(&service, &ssh_b.id), Some(1));

        let log = log.lock().unwrap();
        assert_eq!(log.verifications, 1, "the built-in UV prompt for the token");
        assert_eq!(log.lowerings.len(), 1, "exactly one dedicated question");
        let (summary, body) = &log.lowerings[0];
        assert!(summary.contains("Lower Credential Protection"), "{summary}");
        assert!(body.contains("2 credential(s)"), "{body}");
        assert!(body.contains("for ssh:"), "{body}");
        assert!(body.contains("3 \u{2192} 1"), "{body}");
        assert!(body.contains("presence only"), "{body}");
    }

    #[test]
    fn test_set_cred_protect_lowering_refuses_unless_the_user_accepts() {
        use crate::credential_protection::test_support::test_credential;

        let cases: [(
            &str,
            core::result::Result<NotificationResult, String>,
            Option<u8>,
        ); 4] = [
            ("accepted", Ok(NotificationResult::Accepted), None),
            (
                "denied",
                Ok(NotificationResult::Denied),
                Some(StatusCode::OperationDenied as u8),
            ),
            // A closed or timed-out notification refuses just like a denial.
            (
                "closed or timed out",
                Ok(NotificationResult::Dismissed),
                Some(StatusCode::OperationDenied as u8),
            ),
            (
                "prompt error",
                Err("no notification server".to_string()),
                Some(StatusCode::Other as u8),
            ),
        ];
        for (name, answer, refusal) in cases {
            let credential = test_credential(1, "ssh:", Some(3));
            let (mut service, _dir) =
                cred_protect_service(std::slice::from_ref(&credential), false);
            let (prompts, log) = ScriptedPrompts::new(answer);
            service.set_prompts(prompts);

            let response = lower_with_built_in_uv(&mut service, &ids_of(&[&credential]), 1);
            match refusal {
                None => {
                    assert_eq!(response.first(), Some(&0x00), "{name}");
                    assert_eq!(stored_level(&service, &credential.id), Some(1), "{name}");
                }
                Some(status) => {
                    assert_eq!(response, vec![status], "{name}");
                    assert_eq!(stored_level(&service, &credential.id), Some(3), "{name}");
                }
            }
            assert_eq!(log.lock().unwrap().lowerings.len(), 1, "{name}");
        }
    }

    #[test]
    fn test_set_cred_protect_refuses_to_lower_when_prompts_are_auto_approved() {
        use crate::credential_protection::test_support::test_credential;

        for (name, automatic, status) in [
            ("automatic", Ok(true), StatusCode::NotAllowed),
            (
                "unreadable setting",
                Err("invalid PASSLESS_INTERACTION_MODE".to_string()),
                StatusCode::Other,
            ),
        ] {
            let credential = test_credential(1, "ssh:", Some(3));
            let (mut service, _dir) =
                cred_protect_service(std::slice::from_ref(&credential), false);
            let (mut prompts, log) = ScriptedPrompts::new(Ok(NotificationResult::Accepted));
            prompts.automatic = automatic;
            service.set_prompts(prompts);

            let response = lower_with_built_in_uv(&mut service, &ids_of(&[&credential]), 1);
            assert_eq!(response, vec![status as u8], "{name}");
            assert_eq!(stored_level(&service, &credential.id), Some(3), "{name}");
            assert!(
                log.lock().unwrap().lowerings.is_empty(),
                "{name}: no question is shown, the refusal is outright"
            );
        }

        // Raising is still allowed in that mode: it weakens nothing.
        let credential = test_credential(1, "ssh:", Some(1));
        let (mut service, _dir) = cred_protect_service(std::slice::from_ref(&credential), false);
        let (mut prompts, _log) = ScriptedPrompts::new(Ok(NotificationResult::Denied));
        prompts.automatic = Ok(true);
        service.set_prompts(prompts);
        let response = lower_with_built_in_uv(&mut service, &ids_of(&[&credential]), 3);
        assert_eq!(response.first(), Some(&0x00));
        assert_eq!(stored_level(&service, &credential.id), Some(3));
    }

    #[test]
    fn test_set_cred_protect_raising_and_no_ops_need_no_extra_prompt() {
        use crate::credential_protection::test_support::test_credential;

        let low = test_credential(1, "ssh:", Some(1));
        let high = test_credential(2, "ssh:", Some(3));
        let (mut service, _dir) = cred_protect_service(&[low.clone(), high.clone()], false);
        // A denying prompt proves none is asked.
        let (prompts, log) = ScriptedPrompts::new(Ok(NotificationResult::Denied));
        service.set_prompts(prompts);

        // Raise one, leave the other (already 3) unchanged.
        let response = lower_with_built_in_uv(&mut service, &ids_of(&[&low, &high]), 3);
        assert_eq!(response.first(), Some(&0x00), "{response:02x?}");
        assert_eq!(stored_level(&service, &low.id), Some(3));
        assert!(log.lock().unwrap().lowerings.is_empty());
    }

    #[test]
    fn test_set_cred_protect_question_lists_only_what_is_lowered() {
        use crate::credential_protection::test_support::test_credential;

        let lowered = test_credential(1, "ssh:", Some(3));
        let raised = test_credential(2, "ssh:", Some(1));
        let (mut service, _dir) = cred_protect_service(&[lowered.clone(), raised.clone()], false);
        let (prompts, log) = ScriptedPrompts::new(Ok(NotificationResult::Accepted));
        service.set_prompts(prompts);

        // Level 2: credential 1 is lowered (3 -> 2), credential 2 is raised (1 -> 2).
        let response = lower_with_built_in_uv(&mut service, &ids_of(&[&lowered, &raised]), 2);
        assert_eq!(response.first(), Some(&0x00));
        let log = log.lock().unwrap();
        assert!(
            log.lowerings[0].1.contains("1 credential(s)"),
            "{:?}",
            log.lowerings
        );
        assert!(log.lowerings[0].1.contains("3 \u{2192} 2"));
    }

    #[test]
    fn test_set_cred_protect_with_a_pin_the_pin_is_the_consent() {
        use crate::credential_protection::test_support::test_credential;

        let credential = test_credential(1, "ssh:", Some(3));
        // Default configuration: pin.enforcement = optional and always_uv = true refuse the
        // built-in UV prompt while a PIN is set, so only the PIN can mint the token.
        let (mut service, _dir) = cred_protect_service(std::slice::from_ref(&credential), true);
        // A denying, auto-approved-looking prompt layer must not matter: nothing is asked.
        let (mut prompts, log) = ScriptedPrompts::new(Ok(NotificationResult::Denied));
        prompts.automatic = Ok(true);
        service.set_prompts(prompts);
        let ids = ids_of(&[&credential]);

        let token = platform::pin_token(&mut service, platform::PIN, CM_PERMISSION, None)
            .expect("PIN token");
        let response = send_set_cred_protect(&mut service, &ids, 1, authorized(&token, &ids, 1));
        assert_eq!(response.first(), Some(&0x00), "{response:02x?}");
        assert_eq!(stored_level(&service, &credential.id), Some(1));
        let log = log.lock().unwrap();
        assert!(log.lowerings.is_empty(), "no extra prompt");
        assert_eq!(log.verifications, 0);
    }

    #[test]
    fn test_set_cred_protect_with_a_pin_no_built_in_uv_token_can_be_minted() {
        use crate::credential_protection::test_support::test_credential;
        use passless_core::config::PinEnforcement;

        // The PIN is the only consent route in every PIN policy: while a PIN is set the
        // authenticator issues no token after the built-in UV prompt, so one click never
        // authorizes credential management (this is why no extra prompt is needed with a PIN).
        for (enforcement, always_uv) in [
            (PinEnforcement::Never, false),
            (PinEnforcement::Optional, false),
            (PinEnforcement::Optional, true),
            (PinEnforcement::Required, false),
        ] {
            let credential = test_credential(1, "ssh:", Some(3));
            let security = SecurityConfig {
                always_uv,
                ..SecurityConfig::default()
            };
            let pin_config = PinConfig {
                enforcement,
                ..PinConfig::default()
            };
            let (mut service, _dir) = cred_protect_service_with(
                std::slice::from_ref(&credential),
                true,
                security,
                pin_config,
            );
            let (prompts, log) = ScriptedPrompts::new(Ok(NotificationResult::Accepted));
            service.set_prompts(prompts);

            let status = platform::token(
                &mut service,
                2,
                platform::Way::BuiltInUv,
                CM_PERMISSION,
                None,
            )
            .expect_err("no UV token while a PIN is set");
            assert_eq!(status, StatusCode::NotAllowed as u8, "{enforcement:?}");
            assert_eq!(stored_level(&service, &credential.id), Some(3));
            assert!(log.lock().unwrap().lowerings.is_empty());
        }
    }

    #[test]
    fn test_set_cred_protect_rejects_an_rp_bound_credential_management_token() {
        use crate::credential_protection::test_support::test_credential;

        let credential = test_credential(1, "ssh:", Some(3));
        let ids = ids_of(&[&credential]);
        let (mut service, _dir) = cred_protect_service(std::slice::from_ref(&credential), true);

        // Even a token scoped to the credential's own RP is refused: the command spans
        // credentials and keeps the strict, unscoped requirement.
        let token = platform::pin_token(&mut service, platform::PIN, CM_PERMISSION, Some("ssh:"))
            .expect("RP-bound cm token");
        let response = send_set_cred_protect(&mut service, &ids, 1, authorized(&token, &ids, 1));
        assert_eq!(response, vec![StatusCode::UnauthorizedPermission as u8]);
        assert_eq!(stored_level(&service, &credential.id), Some(3));
    }

    #[test]
    fn test_set_cred_protect_accepts_a_protocol_one_pin_uv_auth_param() {
        use crate::credential_protection::test_support::test_credential;

        let credential = test_credential(1, "ssh:", Some(3));
        let ids = ids_of(&[&credential]);
        let (mut service, _dir) = cred_protect_service(std::slice::from_ref(&credential), true);

        let token = platform::token(
            &mut service,
            1,
            platform::Way::Pin(platform::PIN),
            CM_PERMISSION,
            None,
        )
        .expect("protocol 1 token");

        // A 32-byte (protocol 2) parameter does not fit the protocol 1 field.
        let wrong_length = Some((
            1,
            platform::authenticate(&token, &set_cred_protect_auth_data(1, &ids)),
        ));
        let response = send_set_cred_protect(&mut service, &ids, 1, wrong_length);
        assert_eq!(response, vec![StatusCode::PinAuthInvalid as u8]);
        assert_eq!(stored_level(&service, &credential.id), Some(3));

        let response = send_set_cred_protect(&mut service, &ids, 1, authorized_v1(&token, &ids, 1));
        assert_eq!(response.first(), Some(&0x00), "{response:02x?}");
        assert_eq!(stored_level(&service, &credential.id), Some(1));
    }

    /// What a closed or timed-out prompt, an explicit denial and a policy denial cost: only
    /// somebody refusing may spend one of the built-in UV retries.
    mod uv_budget {
        use super::*;

        use crate::human_prompts::HumanPrompts;

        use ciborium::Value as Cbor;

        const MAX_RETRIES: u8 = 3;
        const CLIENT_DATA_HASH: [u8; 32] = [0x5a; 32];

        /// Answers every prompt with `answer` and counts the verification prompts.
        struct Answering {
            answer: NotificationResult,
            verifications: Arc<Mutex<usize>>,
        }

        impl HumanPrompts for Answering {
            fn user_presence(
                &mut self,
                _: &str,
                _: Option<&str>,
                _: Option<&str>,
                _: u32,
            ) -> core::result::Result<NotificationResult, String> {
                Ok(self.answer)
            }

            fn user_verification(
                &mut self,
                _: &str,
                _: Option<&str>,
                _: Option<&str>,
                _: u32,
            ) -> core::result::Result<NotificationResult, String> {
                *self.verifications.lock().unwrap() += 1;
                Ok(self.answer)
            }

            fn confirm_credential_protection_lowering(
                &mut self,
                _: &str,
                _: &str,
                _: u32,
            ) -> core::result::Result<NotificationResult, String> {
                Ok(self.answer)
            }

            fn interaction_is_automatic(&self) -> core::result::Result<bool, String> {
                Ok(false)
            }
        }

        struct Harness {
            service: AuthenticatorService<LocalStorageAdapter, TestPinStorage>,
            verifications: Arc<Mutex<usize>>,
            _dir: tempfile::TempDir,
        }

        impl Harness {
            fn new(with_pin: bool, always_uv: bool, enforcement: PinEnforcement) -> Self {
                let (service, dir) = cred_protect_service_with(
                    &[],
                    with_pin,
                    SecurityConfig {
                        always_uv,
                        ..Default::default()
                    },
                    // soft-fido2 refills its in-memory counter to `max_retries`, so keep the two
                    // limits equal: an accepted UV then restores exactly MAX_RETRIES.
                    PinConfig {
                        enforcement,
                        max_retries: MAX_RETRIES,
                        max_uv_retries: MAX_RETRIES,
                        ..Default::default()
                    },
                );
                Self {
                    service,
                    verifications: Arc::new(Mutex::new(0)),
                    _dir: dir,
                }
            }

            fn answer(&self, answer: NotificationResult) {
                self.service.set_prompts(Answering {
                    answer,
                    verifications: self.verifications.clone(),
                });
            }

            fn prompts_shown(&self) -> usize {
                *self.verifications.lock().unwrap()
            }

            fn uv_retries(&self) -> u8 {
                self.service
                    .authenticator
                    .uv_retries()
                    .expect("read UV retries")
            }

            fn send(&mut self, request: &[u8]) -> Vec<u8> {
                let mut response = Vec::new();
                self.service
                    .handle(request, &mut response)
                    .expect("handle CTAP request");
                response
            }

            /// getPinUvAuthTokenUsingUvWithPermissions: the built-in UV prompt.
            fn uv_token(&mut self) -> core::result::Result<[u8; 32], u8> {
                platform::token(&mut self.service, 2, platform::Way::BuiltInUv, 0x04, None)
            }
        }

        fn text(value: &str) -> Cbor {
            Cbor::Text(value.to_string())
        }

        fn int(value: i64) -> Cbor {
            Cbor::Integer(value.into())
        }

        fn command(code: u8, params: Vec<(Cbor, Cbor)>) -> Vec<u8> {
            let mut request = vec![code];
            ciborium::into_writer(&Cbor::Map(params), &mut request).expect("encode request");
            request
        }

        /// MakeCredential asking for built-in user verification (`"uv": true`), no pinUvAuthParam.
        fn make_credential_with_uv(rp_id: &str) -> Vec<u8> {
            command(
                0x01,
                vec![
                    (int(1), Cbor::Bytes(CLIENT_DATA_HASH.to_vec())),
                    (int(2), Cbor::Map(vec![(text("id"), text(rp_id))])),
                    (
                        int(3),
                        Cbor::Map(vec![
                            (text("id"), Cbor::Bytes(vec![0x42; 16])),
                            (text("name"), text("user")),
                        ]),
                    ),
                    (
                        int(4),
                        Cbor::Array(vec![Cbor::Map(vec![
                            (text("alg"), int(-7)),
                            (text("type"), text("public-key")),
                        ])]),
                    ),
                    (int(7), Cbor::Map(vec![(text("uv"), Cbor::Bool(true))])),
                ],
            )
        }

        /// GetAssertion for `credential_id` asking for user verification, no pinUvAuthParam.
        fn get_assertion_with_uv(rp_id: &str, credential_id: &[u8]) -> Vec<u8> {
            command(
                0x02,
                vec![
                    (int(1), text(rp_id)),
                    (int(2), Cbor::Bytes(CLIENT_DATA_HASH.to_vec())),
                    (
                        int(3),
                        Cbor::Array(vec![Cbor::Map(vec![
                            (text("id"), Cbor::Bytes(credential_id.to_vec())),
                            (text("type"), text("public-key")),
                        ])]),
                    ),
                    (
                        int(5),
                        Cbor::Map(vec![
                            (text("up"), Cbor::Bool(true)),
                            (text("uv"), Cbor::Bool(true)),
                        ]),
                    ),
                ],
            )
        }

        fn enrolled_credential_id(response: &[u8]) -> Vec<u8> {
            assert_eq!(response.first(), Some(&0x00), "status {response:02x?}");
            let attestation: Cbor = ciborium::from_reader(&response[1..]).expect("attestation");
            let auth_data = match &attestation {
                Cbor::Map(entries) => entries
                    .iter()
                    .find_map(|(k, v)| match (k, v) {
                        (Cbor::Integer(i), Cbor::Bytes(bytes)) if i128::from(*i) == 2 => {
                            Some(bytes.clone())
                        }
                        _ => None,
                    })
                    .expect("authData"),
                other => panic!("expected a map, got {other:?}"),
            };
            let id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
            auth_data[55..55 + id_len].to_vec()
        }

        const USER_ACTION_TIMEOUT: u8 = StatusCode::UserActionTimeout as u8;

        #[test]
        fn an_explicit_deny_consumes_a_retry() {
            let mut harness = Harness::new(false, false, PinEnforcement::Optional);
            harness.answer(NotificationResult::Denied);

            assert_eq!(harness.uv_retries(), MAX_RETRIES);
            assert_eq!(
                harness.uv_token(),
                Err(StatusCode::OperationDenied as u8),
                "an explicit deny still fails closed"
            );
            assert_eq!(harness.uv_retries(), MAX_RETRIES - 1);

            let response = harness.send(&make_credential_with_uv("denied.example"));
            assert_eq!(response, vec![StatusCode::OperationDenied as u8]);
            assert_eq!(harness.uv_retries(), MAX_RETRIES - 2);

            // The last retry blocks built-in UV: the denial that spends it answers UV_BLOCKED.
            let response = harness.send(&make_credential_with_uv("denied.example"));
            assert_eq!(response, vec![StatusCode::UvBlocked as u8]);
            assert_eq!(harness.uv_retries(), 0);
        }

        #[test]
        fn a_closed_or_timed_out_prompt_costs_nothing_and_fails_closed() {
            let mut harness = Harness::new(false, false, PinEnforcement::Optional);
            harness.answer(NotificationResult::Dismissed);

            // getPinUvAuthTokenUsingUvWithPermissions
            assert_eq!(harness.uv_token(), Err(USER_ACTION_TIMEOUT));
            // MakeCredential with `uv`
            let response = harness.send(&make_credential_with_uv("closed.example"));
            assert_eq!(response, vec![USER_ACTION_TIMEOUT]);

            assert_eq!(harness.prompts_shown(), 2);
            assert_eq!(harness.uv_retries(), MAX_RETRIES, "nobody refused");
            assert_eq!(
                lock_shared_storage(&harness.service.storage).count_credentials(),
                0,
                "nothing is registered without verification"
            );
        }

        #[test]
        fn a_closed_prompt_costs_nothing_for_get_assertion_either() {
            let mut harness = Harness::new(false, false, PinEnforcement::Optional);
            harness.answer(NotificationResult::Accepted);
            let response = harness.send(&make_credential_with_uv("assert.example"));
            let credential_id = enrolled_credential_id(&response);
            // An accepted verification refills the counter.
            let full = MAX_RETRIES;
            assert_eq!(harness.uv_retries(), full);

            harness.answer(NotificationResult::Dismissed);
            let response = harness.send(&get_assertion_with_uv("assert.example", &credential_id));
            assert_eq!(response, vec![USER_ACTION_TIMEOUT]);
            assert_eq!(harness.uv_retries(), full);

            harness.answer(NotificationResult::Denied);
            let response = harness.send(&get_assertion_with_uv("assert.example", &credential_id));
            assert_eq!(response, vec![StatusCode::OperationDenied as u8]);
            assert_eq!(harness.uv_retries(), full - 1);
        }

        #[test]
        fn closing_every_prompt_never_blocks_built_in_uv() {
            let mut harness = Harness::new(false, false, PinEnforcement::Optional);
            harness.answer(NotificationResult::Dismissed);
            for attempt in 0..u32::from(MAX_RETRIES) * 4 {
                let result = harness.uv_token();
                assert_eq!(result, Err(USER_ACTION_TIMEOUT), "attempt {attempt}");
                assert_eq!(harness.uv_retries(), MAX_RETRIES, "attempt {attempt}");
            }

            // UV is still available for the next prompt that is accepted.
            harness.answer(NotificationResult::Accepted);
            assert!(harness.uv_token().is_ok(), "UV was never blocked");
            assert_ne!(harness.uv_retries(), 0);
        }

        #[test]
        fn closing_prompts_does_not_make_an_earlier_denial_worse() {
            let mut harness = Harness::new(false, false, PinEnforcement::Optional);
            harness.answer(NotificationResult::Denied);
            assert_eq!(harness.uv_token(), Err(StatusCode::OperationDenied as u8));
            harness.answer(NotificationResult::Dismissed);
            for _ in 0..10 {
                assert_eq!(harness.uv_token(), Err(USER_ACTION_TIMEOUT));
            }
            assert_eq!(harness.uv_retries(), MAX_RETRIES - 1);
        }

        #[test]
        fn a_closed_user_presence_prompt_still_refuses() {
            // `always_uv = false`, no UV requested: only user presence is asked.
            let mut harness = Harness::new(false, false, PinEnforcement::Optional);
            harness.answer(NotificationResult::Accepted);
            let enroll = command(
                0x01,
                vec![
                    (int(1), Cbor::Bytes(CLIENT_DATA_HASH.to_vec())),
                    (int(2), Cbor::Map(vec![(text("id"), text("up.example"))])),
                    (
                        int(3),
                        Cbor::Map(vec![(text("id"), Cbor::Bytes(vec![7; 16]))]),
                    ),
                    (
                        int(4),
                        Cbor::Array(vec![Cbor::Map(vec![
                            (text("alg"), int(-7)),
                            (text("type"), text("public-key")),
                        ])]),
                    ),
                ],
            );
            let credential_id = enrolled_credential_id(&harness.send(&enroll));

            let sign = command(
                0x02,
                vec![
                    (int(1), text("up.example")),
                    (int(2), Cbor::Bytes(CLIENT_DATA_HASH.to_vec())),
                    (
                        int(3),
                        Cbor::Array(vec![Cbor::Map(vec![
                            (text("id"), Cbor::Bytes(credential_id)),
                            (text("type"), text("public-key")),
                        ])]),
                    ),
                    (int(5), Cbor::Map(vec![(text("up"), Cbor::Bool(true))])),
                ],
            );
            for answer in [NotificationResult::Dismissed, NotificationResult::Denied] {
                harness.answer(answer);
                assert_eq!(
                    harness.send(&sign),
                    vec![StatusCode::OperationDenied as u8],
                    "{answer:?}: presence is refused"
                );
            }
        }

        /// `uv-reset` reports the counter the daemon now enforces, not the configured value.
        /// soft-fido2 refills its in-memory counter to `max_retries`, so with a smaller
        /// `max_uv_retries` the two differ until the next restart; the answer must not claim
        /// the configured one while the daemon allows more denials.
        #[test]
        fn uv_reset_reports_the_counter_in_effect() {
            for (max_retries, max_uv_retries) in [(3, 3), (8, 3)] {
                let (mut service, _dir) = cred_protect_service_with(
                    &[],
                    false,
                    SecurityConfig::default(),
                    PinConfig {
                        max_retries,
                        max_uv_retries,
                        ..Default::default()
                    },
                );
                service.set_prompts(Answering {
                    answer: NotificationResult::Denied,
                    verifications: Arc::new(Mutex::new(0)),
                });
                for _ in 0..max_uv_retries {
                    let _ = platform::token(&mut service, 2, platform::Way::BuiltInUv, 0x04, None);
                }
                assert_eq!(service.authenticator.uv_retries().unwrap(), 0);

                let payload = soft_fido2_ctap::cbor::MapBuilder::new()
                    .insert(1, RESET_UV_RETRIES_SUBCOMMAND)
                    .and_then(|b| b.build())
                    .expect("payload");
                let mut request = vec![CMD_PASSLESS_RESET_UV_RETRIES];
                request.extend_from_slice(&payload);
                let mut response = Vec::new();
                service.handle(&request, &mut response).expect("handle");

                let in_effect = service.authenticator.uv_retries().unwrap();
                assert!(in_effect > 0, "UV is usable again");
                assert_eq!(
                    response,
                    vec![0x00, 0xa1, 0x01, in_effect],
                    "max_retries={max_retries}, max_uv_retries={max_uv_retries}"
                );
                if max_retries == max_uv_retries {
                    assert_eq!(in_effect, max_uv_retries);
                }
            }
        }

        #[test]
        fn the_blocked_hint_fires_whenever_a_request_answers_uv_blocked() {
            let mut harness = Harness::new(false, false, PinEnforcement::Optional);
            harness.answer(NotificationResult::Denied);
            for _ in 0..MAX_RETRIES {
                let _ = harness.uv_token();
            }
            assert_eq!(harness.uv_retries(), 0);

            // getPinUvAuthTokenUsingUv answers UV_BLOCKED before it asks anything.
            let before = harness.prompts_shown();
            captured_log::clear();
            assert_eq!(harness.uv_token(), Err(StatusCode::UvBlocked as u8));
            assert_eq!(harness.prompts_shown(), before);
            let logged = captured_log::errors();
            assert_eq!(logged.len(), 1, "{logged:?}");
            assert!(
                logged[0].contains("passless client pin uv-reset"),
                "{logged:?}"
            );
            assert!(logged[0].contains("UV_BLOCKED"), "{logged:?}");

            // Any other request answered UV_BLOCKED logs it too, and others do not.
            captured_log::clear();
            let _ = harness.send(&[0x04]);
            assert!(captured_log::errors().is_empty());
        }

        /// With a PIN set (and the PIN hint current) built-in UV is not configured, so GetInfo
        /// advertises `uv: false` and soft-fido2 refuses UV requests before asking the callback:
        /// the policy denials in `request_uv` are never reached and no retry is touched.
        #[test]
        fn with_a_current_pin_hint_policy_denials_are_never_asked_for() {
            for (always_uv, enforcement) in [
                (false, PinEnforcement::Required),
                (true, PinEnforcement::Optional),
            ] {
                let mut harness = Harness::new(true, always_uv, enforcement);
                harness.answer(NotificationResult::Accepted);

                let info = harness.send(&[0x04]);
                assert_eq!(get_info_uv(&info), Some(false));
                for _ in 0..MAX_RETRIES * 2 {
                    assert_eq!(
                        harness.send(&make_credential_with_uv("pin.example")),
                        vec![StatusCode::InvalidOption as u8],
                        "always_uv={always_uv}, {enforcement:?}"
                    );
                    assert_eq!(harness.uv_token(), Err(StatusCode::NotAllowed as u8));
                }
                assert_eq!(harness.prompts_shown(), 0);
                assert_eq!(harness.uv_retries(), MAX_RETRIES);
            }
        }

        /// A PIN that the cached hint does not know about yet (a synchronized password store)
        /// leaves built-in UV configured, so `request_uv` is reached and refuses by policy.
        /// soft-fido2 0.18 counts that `Denied` as a failed attempt: each refusal spends a retry
        /// and the one that spends the last answers UV_BLOCKED instead of the PUAT_REQUIRED the
        /// platform needs for its PIN fallback.
        ///
        /// Needs `UvResult::Unavailable` from soft-fido2 (pando85/soft-fido2#179) to stop; when
        /// passless answers it, this test flips to "no retry consumed, always PUAT_REQUIRED".
        #[test]
        fn policy_denials_still_consume_retries_when_the_pin_hint_is_stale() {
            for (always_uv, enforcement) in [
                (false, PinEnforcement::Required),
                (true, PinEnforcement::Optional),
            ] {
                let dir = tempfile::tempdir().expect("create temp directory");
                let cred_dir = dir.path().join("credentials");
                std::fs::create_dir_all(&cred_dir).expect("create credential directory");
                let storage = LocalStorageAdapter::new(cred_dir).expect("create storage");
                let pin_storage = Arc::new(Mutex::new(StalePinConfigStorage {
                    state: Mutex::new(PinState {
                        uv_retries: MAX_RETRIES,
                        ..pin_state_with_pin()
                    }),
                    cached_pin_configured: false,
                }));
                let mut service = AuthenticatorService::with_pin_storage(
                    storage,
                    Some(pin_storage),
                    SecurityConfig {
                        always_uv,
                        ..Default::default()
                    },
                    PinConfig {
                        enforcement,
                        max_uv_retries: MAX_RETRIES,
                        ..Default::default()
                    },
                )
                .expect("create authenticator service");
                let verifications = Arc::new(Mutex::new(0));
                service.set_prompts(Answering {
                    answer: NotificationResult::Accepted,
                    verifications: verifications.clone(),
                });

                let mut answers = Vec::new();
                for _ in 0..MAX_RETRIES {
                    let mut response = Vec::new();
                    service
                        .handle(&make_credential_with_uv("pin.example"), &mut response)
                        .expect("handle CTAP request");
                    answers.push(response);
                }
                let mut expected =
                    vec![vec![StatusCode::PuatRequired as u8]; MAX_RETRIES as usize - 1];
                expected.push(vec![StatusCode::UvBlocked as u8]);
                assert_eq!(answers, expected, "always_uv={always_uv}, {enforcement:?}");
                assert_eq!(service.authenticator.uv_retries().unwrap(), 0);
                assert_eq!(*verifications.lock().unwrap(), 0, "nobody was asked");
            }
        }

        #[test]
        fn recognizes_only_a_bare_uv_blocked_status() {
            assert!(is_uv_blocked_response(&[0x3c]));
            assert!(!is_uv_blocked_response(&[0x00]));
            assert!(!is_uv_blocked_response(&[0x3c, 0x00]));
            assert!(!is_uv_blocked_response(&[]));
            assert!(UV_BLOCKED_HINT.contains("passless client pin uv-reset"));
        }

        /// Collects what this thread logs at error level. The test harness runs each test on its
        /// own thread, so the buffer is thread-local.
        mod captured_log {
            use std::cell::RefCell;

            struct Capture;

            thread_local! {
                static ERRORS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
            }

            impl log::Log for Capture {
                fn enabled(&self, _: &log::Metadata) -> bool {
                    true
                }

                fn log(&self, record: &log::Record) {
                    if record.level() == log::Level::Error {
                        ERRORS.with(|errors| errors.borrow_mut().push(record.args().to_string()));
                    }
                }

                fn flush(&self) {}
            }

            static CAPTURE: Capture = Capture;

            pub fn clear() {
                let _ = log::set_logger(&CAPTURE);
                log::set_max_level(log::LevelFilter::Trace);
                ERRORS.with(|errors| errors.borrow_mut().clear());
            }

            pub fn errors() -> Vec<String> {
                ERRORS.with(|errors| errors.borrow().clone())
            }
        }
    }
}

/// Issue #588: credentials minted while `alwaysUv` was in effect (the default, and forced in
/// v0.16.0 to v0.21.0 release builds regardless of `security.always_uv`) carry credProtect level 3
/// without the client asking for it (soft-fido2 before 0.18 defaulted to level 3 after UV). An OpenSSH GetAssertion (`up` only, no `uv`, allowList with
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
            UvConfig::default(),
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
            UvConfig::default(),
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

    /// Enroll a legacy level-3 credential, as v0.21.0 release builds stored them: user
    /// verification forced on MakeCredential. soft-fido2 0.17 defaulted to level 3 after UV;
    /// since 0.18 the default is level 2, so the fixture requests level 3 explicitly.
    fn enroll_with_forced_uv(storage: &Arc<Mutex<LocalStorageAdapter>>, alg: i64) -> Enrolled {
        let prompts = AutoAccept::install();
        let enrolled = enroll(&mut service_without_pin(storage, true), alg, Some(3));
        assert_eq!(prompts.uv_prompts(), 1, "enrollment performed built-in UV");
        assert_eq!(
            stored(storage, &enrolled.credential_id)
                .extensions
                .cred_protect,
            Some(3),
            "the fixture stores a legacy level-3 credential"
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

    /// soft-fido2 0.18 stores level 2 after UV when the client asks for no level, so new
    /// credentials need no rescue: allowList signing with presence only works directly.
    #[test]
    fn new_credential_created_with_uv_defaults_to_level_two() {
        for alg in [-8, -7] {
            let dir = tempfile::tempdir().expect("create temp directory");
            let storage = local_storage(&dir);
            let prompts = AutoAccept::install();
            let enrolled = enroll(&mut service_without_pin(&storage, true), alg, None);
            assert_eq!(
                prompts.uv_prompts(),
                1,
                "alg {alg}: enrollment performed UV"
            );
            assert_eq!(
                stored(&storage, &enrolled.credential_id)
                    .extensions
                    .cred_protect,
                Some(2),
                "alg {alg}: UV without a credProtect request stores level 2"
            );

            // `always_uv = false`: allowList, `up = true`, no UV, answered by soft-fido2 itself.
            let mut service = service_without_pin(&storage, false);
            let prompts = AutoAccept::install();
            let response = soft_fido2_answer(
                &mut service,
                &ssh_sign_request(&enrolled.credential_id, true),
            );
            assert_signed(&response, Some(&enrolled.cose_key), UP_FLAG);
            assert_eq!(
                (prompts.up_prompts(), prompts.uv_prompts()),
                (1, 0),
                "alg {alg}: presence only, no UV prompt"
            );
        }
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

    /// The desktop prompt the way a user who ignores it, or a timeout, answers it.
    struct Closing;

    impl crate::human_prompts::HumanPrompts for Closing {
        fn user_presence(
            &mut self,
            _: &str,
            _: Option<&str>,
            _: Option<&str>,
            _: u32,
        ) -> core::result::Result<NotificationResult, String> {
            Ok(NotificationResult::Dismissed)
        }

        fn user_verification(
            &mut self,
            _: &str,
            _: Option<&str>,
            _: Option<&str>,
            _: u32,
        ) -> core::result::Result<NotificationResult, String> {
            Ok(NotificationResult::Dismissed)
        }

        fn confirm_credential_protection_lowering(
            &mut self,
            _: &str,
            _: &str,
            _: u32,
        ) -> core::result::Result<NotificationResult, String> {
            Ok(NotificationResult::Dismissed)
        }

        fn interaction_is_automatic(&self) -> core::result::Result<bool, String> {
            Ok(false)
        }
    }

    /// The rescue of a protected credential asks for built-in UV on the client's behalf. Closing
    /// that prompt refuses the request (CTAP2_ERR_USER_ACTION_TIMEOUT) and spends no retry.
    #[test]
    fn closed_uv_prompt_of_the_rescue_fails_closed_without_spending_a_retry() {
        let dir = tempfile::tempdir().expect("create temp directory");
        let storage = local_storage(&dir);
        let enrolled = enroll_with_forced_uv(&storage, -8);
        let before = stored(&storage, &enrolled.credential_id).sign_count;

        let mut service = service_without_pin(&storage, false);
        service.set_prompts(Closing);
        let retries = service.authenticator.uv_retries().expect("UV retries");
        for _ in 0..20 {
            let response = respond(
                &mut service,
                &ssh_sign_request(&enrolled.credential_id, true),
            );
            assert_eq!(response, vec![StatusCode::UserActionTimeout as u8]);
        }
        assert_eq!(
            service.authenticator.uv_retries().expect("UV retries"),
            retries
        );
        assert_eq!(stored(&storage, &enrolled.credential_id).sign_count, before);
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
