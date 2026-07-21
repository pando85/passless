//! Delegated credential view for agent endpoints.
//!
//! `SharedDelegatedStorage<S>` wraps the human backend's `Arc<Mutex<S>>` directly,
//! enforcing an exact normalized RP ID set and exact typed `CredentialRef` set.
//! A daemon-only CredentialRef→raw-ID index is resolved once under the human lock.
//! During ceremonies the human adapter's iterator is never used: the exact raw ID
//! is resolved from the index and `read(id)` is called. Read/write lock the same
//! human owner; immutable/counter checks occur under that lock.
//!
//! Lock order (documented): operation_lock → storage (human `Arc<Mutex<S>>`).
//! Never hold the storage lock while acquiring the operation lock.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use passless_core::agent::CredentialRef;

use crate::storage::{CredentialFilter, CredentialStorage};

use soft_fido2::Result;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CeremonyAction {
    Register,
    Authenticate(CredentialRef),
}

struct ActiveCeremony {
    action: CeremonyAction,
    rp_id: String,
    generation: u64,
}

struct CeremonyScopeInner {
    generation: AtomicU64,
    active: Mutex<Option<ActiveCeremony>>,
}

#[derive(Clone)]
pub struct CeremonyScope {
    inner: Arc<CeremonyScopeInner>,
}

impl CeremonyScope {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(CeremonyScopeInner {
                generation: AtomicU64::new(0),
                active: Mutex::new(None),
            }),
        }
    }

    fn activate(
        &self,
        action: CeremonyAction,
        rp_id: &str,
    ) -> std::result::Result<Option<CeremonyGuard>, ScopeActivationError> {
        let rp_id = normalize_rp_id(rp_id);
        if rp_id.is_empty() {
            return Err(ScopeActivationError::EmptyRpId);
        }
        match &action {
            CeremonyAction::Authenticate(cred_ref) => {
                if cred_ref.as_bytes().iter().all(|&b| b == 0) {
                    return Err(ScopeActivationError::EmptyCredentialRef);
                }
            }
            CeremonyAction::Register => {}
        }
        let generation = self.inner.generation.fetch_add(1, Ordering::SeqCst) + 1;
        *self.inner.active.lock().unwrap() = Some(ActiveCeremony {
            action,
            rp_id,
            generation,
        });
        Ok(Some(CeremonyGuard {
            scope: self.clone(),
            generation,
        }))
    }

    pub fn activate_register_for_rp(
        &self,
        rp_id: &str,
    ) -> std::result::Result<Option<CeremonyGuard>, ScopeActivationError> {
        self.activate(CeremonyAction::Register, rp_id)
    }

    pub fn activate_authenticate_for_rp(
        &self,
        cred_ref: CredentialRef,
        rp_id: &str,
    ) -> std::result::Result<Option<CeremonyGuard>, ScopeActivationError> {
        self.activate(CeremonyAction::Authenticate(cred_ref), rp_id)
    }

    #[cfg(test)]
    pub fn activate_register(
        &self,
    ) -> std::result::Result<Option<CeremonyGuard>, ScopeActivationError> {
        self.activate_register_for_rp("example.com")
    }

    #[cfg(test)]
    pub fn activate_authenticate(
        &self,
        cred_ref: CredentialRef,
    ) -> std::result::Result<Option<CeremonyGuard>, ScopeActivationError> {
        self.activate_authenticate_for_rp(cred_ref, "example.com")
    }

    pub fn active_action(&self) -> Option<CeremonyAction> {
        self.inner
            .active
            .lock()
            .unwrap()
            .as_ref()
            .map(|a| a.action.clone())
    }

    pub fn active_cred_ref(&self) -> Option<CredentialRef> {
        self.inner
            .active
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|a| match &a.action {
                CeremonyAction::Authenticate(cred_ref) => Some(cred_ref.clone()),
                CeremonyAction::Register => None,
            })
    }

    pub fn active_rp_id(&self) -> Option<String> {
        self.inner
            .active
            .lock()
            .unwrap()
            .as_ref()
            .map(|a| a.rp_id.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeActivationError {
    EmptyCredentialRef,
    EmptyRpId,
}

impl std::fmt::Display for ScopeActivationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyCredentialRef => write!(f, "empty credential ref"),
            Self::EmptyRpId => write!(f, "empty RP ID"),
        }
    }
}

impl std::error::Error for ScopeActivationError {}

impl Default for CeremonyScope {
    fn default() -> Self {
        Self::new()
    }
}

pub struct CeremonyGuard {
    scope: CeremonyScope,
    generation: u64,
}

impl Drop for CeremonyGuard {
    fn drop(&mut self) {
        let mut active = self.scope.inner.active.lock().unwrap();
        if let Some(ref ceremony) = *active
            && ceremony.generation == self.generation
        {
            *active = None;
        }
    }
}

fn normalize_rp_id(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

fn cred_ref_from_id(credential_id: &[u8]) -> CredentialRef {
    CredentialRef::with_default_domain(credential_id)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegatedError {
    RpIdNotAllowed(String),
    CredentialNotAllowed(String),
    WriteDenied,
    DeleteDenied,
    RenameDenied,
    DiscoveryDenied,
    RegistrationDenied,
    ImmutableFieldViolation(String),
    CounterNotMonotonic,
    UnsafeCredentialType,
    Internal(String),
}

impl std::fmt::Display for DelegatedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RpIdNotAllowed(rp) => write!(f, "RP ID not allowed: {}", rp),
            Self::CredentialNotAllowed(href) => {
                write!(f, "credential not allowed: {}", href)
            }
            Self::WriteDenied => write!(f, "write denied on delegated endpoint"),
            Self::DeleteDenied => write!(f, "delete denied on delegated endpoint"),
            Self::RenameDenied => write!(f, "rename denied on delegated endpoint"),
            Self::DiscoveryDenied => write!(f, "discovery denied on delegated endpoint"),
            Self::RegistrationDenied => write!(f, "registration denied on delegated endpoint"),
            Self::ImmutableFieldViolation(field) => {
                write!(f, "immutable field violation: {}", field)
            }
            Self::CounterNotMonotonic => write!(f, "signature counter not monotonic"),
            Self::UnsafeCredentialType => {
                write!(f, "unsafe credential type for delegated update")
            }
            Self::Internal(msg) => write!(f, "internal delegated error: {}", msg),
        }
    }
}

impl std::error::Error for DelegatedError {}

impl From<DelegatedError> for soft_fido2::Error {
    fn from(_: DelegatedError) -> Self {
        soft_fido2::Error::Other
    }
}

pub struct SharedDelegatedStorage<S: CredentialStorage> {
    human: Arc<Mutex<S>>,
    allowed_rp_ids: HashSet<String>,
    allowed_cred_refs: HashSet<CredentialRef>,
    cred_ref_to_raw_id: HashMap<CredentialRef, Vec<u8>>,
    scope: CeremonyScope,
    constant_counter_mode: bool,
    registration_allowed: bool,
}

impl<S: CredentialStorage> SharedDelegatedStorage<S> {
    pub fn new(human: Arc<Mutex<S>>, rp_ids: Vec<String>, cred_refs: Vec<CredentialRef>) -> Self {
        let allowed_rp_ids: HashSet<String> =
            rp_ids.into_iter().map(|r| normalize_rp_id(&r)).collect();
        let allowed_cred_refs: HashSet<CredentialRef> = cred_refs.into_iter().collect();

        Self {
            human,
            allowed_rp_ids,
            allowed_cred_refs,
            cred_ref_to_raw_id: HashMap::new(),
            scope: CeremonyScope::new(),
            constant_counter_mode: false,
            registration_allowed: false,
        }
    }

    pub fn with_constant_counter_mode(mut self, enabled: bool) -> Self {
        self.constant_counter_mode = enabled;
        self
    }

    pub fn with_registration_allowed(mut self, allowed: bool) -> Self {
        self.registration_allowed = allowed;
        self
    }

    pub fn scope(&self) -> CeremonyScope {
        self.scope.clone()
    }

    pub fn build_index(&mut self) -> std::result::Result<(), DelegatedError> {
        let mut index = HashMap::new();
        {
            let mut human = self
                .human
                .lock()
                .map_err(|e| DelegatedError::Internal(format!("human lock poisoned: {}", e)))?;
            let first = match human.read_first(CredentialFilter::None) {
                Ok(c) => c,
                Err(soft_fido2::Error::DoesNotExist) | Err(soft_fido2::Error::NoCredentials) => {
                    self.cred_ref_to_raw_id = index;
                    return Ok(());
                }
                Err(e) => return Err(DelegatedError::Internal(format!("read_first: {}", e))),
            };
            let href = cred_ref_from_id(&first.id);
            if self.allowed_cred_refs.contains(&href) {
                index.insert(href, first.id.clone());
            }
            loop {
                match human.read_next() {
                    Ok(c) => {
                        let href = cred_ref_from_id(&c.id);
                        if self.allowed_cred_refs.contains(&href) {
                            index.insert(href, c.id.clone());
                        }
                    }
                    Err(soft_fido2::Error::DoesNotExist)
                    | Err(soft_fido2::Error::NoCredentials) => {
                        break;
                    }
                    Err(e) => {
                        return Err(DelegatedError::Internal(format!("read_next: {}", e)));
                    }
                }
            }
        }
        self.cred_ref_to_raw_id = index;
        Ok(())
    }

    #[cfg(test)]
    pub fn activate_ceremony(
        &mut self,
        cred_ref: CredentialRef,
    ) -> std::result::Result<Option<CeremonyGuard>, DelegatedError> {
        if !self.allowed_cred_refs.contains(&cred_ref) {
            return Err(DelegatedError::CredentialNotAllowed(cred_ref.to_hex()));
        }
        if !self.cred_ref_to_raw_id.contains_key(&cred_ref) {
            self.build_index()?;
        }
        let raw_id = self.resolve_raw_id(&cred_ref)?;
        let rp_id = self
            .human
            .lock()
            .map_err(|e| DelegatedError::Internal(format!("human lock poisoned: {}", e)))?
            .read(&raw_id)
            .map_err(|e| DelegatedError::Internal(format!("credential read failed: {}", e)))?
            .rp
            .id;
        self.scope
            .activate_authenticate_for_rp(cred_ref, &rp_id)
            .map_err(|_| DelegatedError::WriteDenied)
    }

    fn is_rp_allowed(&self, rp_id: &str) -> bool {
        self.allowed_rp_ids.contains(&normalize_rp_id(rp_id))
    }

    fn resolve_raw_id(
        &self,
        cred_ref: &CredentialRef,
    ) -> std::result::Result<Vec<u8>, DelegatedError> {
        self.cred_ref_to_raw_id
            .get(cred_ref)
            .cloned()
            .ok_or_else(|| DelegatedError::CredentialNotAllowed(cred_ref.to_hex()))
    }

    fn require_active_ceremony(&self) -> std::result::Result<(), soft_fido2::Error> {
        match self.scope.active_action() {
            Some(CeremonyAction::Authenticate(_)) => Ok(()),
            Some(CeremonyAction::Register) if self.registration_allowed => Ok(()),
            _ => Err(soft_fido2::Error::DoesNotExist),
        }
    }

    fn require_ceremony_cred(
        &self,
        cred_ref: &CredentialRef,
    ) -> std::result::Result<(), soft_fido2::Error> {
        match self.scope.active_cred_ref() {
            Some(ref active) if *active == *cred_ref => Ok(()),
            _ => Err(soft_fido2::Error::DoesNotExist),
        }
    }

    fn require_ceremony_rp(&self, rp_id: &str) -> std::result::Result<(), soft_fido2::Error> {
        match self.scope.active_rp_id() {
            Some(active) if active == normalize_rp_id(rp_id) => Ok(()),
            _ => Err(soft_fido2::Error::DoesNotExist),
        }
    }

    fn verify_immutable_fields(
        &self,
        old: &soft_fido2::Credential,
        new_cred: &soft_fido2::Credential,
    ) -> std::result::Result<(), DelegatedError> {
        if old.id != new_cred.id {
            return Err(DelegatedError::ImmutableFieldViolation(
                "credential_id".into(),
            ));
        }
        if normalize_rp_id(&old.rp.id) != normalize_rp_id(&new_cred.rp.id) {
            return Err(DelegatedError::ImmutableFieldViolation("rp_id".into()));
        }
        if old.user.id != new_cred.user.id {
            return Err(DelegatedError::ImmutableFieldViolation("user_id".into()));
        }
        if old.user.name != new_cred.user.name {
            return Err(DelegatedError::ImmutableFieldViolation("user_name".into()));
        }
        if old.user.display_name != new_cred.user.display_name {
            return Err(DelegatedError::ImmutableFieldViolation(
                "user_display_name".into(),
            ));
        }
        if old.alg != new_cred.alg {
            return Err(DelegatedError::ImmutableFieldViolation("alg".into()));
        }
        if old.created != new_cred.created {
            return Err(DelegatedError::ImmutableFieldViolation("created".into()));
        }
        if old.discoverable != new_cred.discoverable {
            return Err(DelegatedError::ImmutableFieldViolation(
                "discoverable".into(),
            ));
        }
        if old.key.material.as_slice() != new_cred.key.material.as_slice() {
            return Err(DelegatedError::ImmutableFieldViolation(
                "private_key".into(),
            ));
        }
        if old.extensions.cred_protect != new_cred.extensions.cred_protect {
            return Err(DelegatedError::ImmutableFieldViolation(
                "extensions.cred_protect".into(),
            ));
        }
        if old.extensions.hmac_secret != new_cred.extensions.hmac_secret {
            return Err(DelegatedError::ImmutableFieldViolation(
                "extensions.hmac_secret".into(),
            ));
        }
        if old.extensions.cred_random != new_cred.extensions.cred_random {
            return Err(DelegatedError::ImmutableFieldViolation(
                "extensions.cred_random".into(),
            ));
        }

        Ok(())
    }

    fn verify_counter(
        &self,
        old: &soft_fido2::Credential,
        new_cred: &soft_fido2::Credential,
    ) -> std::result::Result<(), DelegatedError> {
        if self.constant_counter_mode {
            if new_cred.sign_count != old.sign_count {
                return Err(DelegatedError::CounterNotMonotonic);
            }
        } else if new_cred.sign_count <= old.sign_count {
            return Err(DelegatedError::CounterNotMonotonic);
        }
        Ok(())
    }
}

impl<S: CredentialStorage> CredentialStorage for SharedDelegatedStorage<S> {
    fn read_first(&mut self, filter: CredentialFilter) -> Result<soft_fido2::Credential> {
        self.require_active_ceremony()?;
        let active_ref = self
            .scope
            .active_cred_ref()
            .ok_or(soft_fido2::Error::DoesNotExist)?;

        match &filter {
            CredentialFilter::ByRp(rp_id) => {
                if !self.is_rp_allowed(rp_id) || self.require_ceremony_rp(rp_id).is_err() {
                    return Err(soft_fido2::Error::DoesNotExist);
                }
                let raw_id = self
                    .resolve_raw_id(&active_ref)
                    .map_err(|_| soft_fido2::Error::DoesNotExist)?;
                let mut human = self.human.lock().map_err(|_| soft_fido2::Error::Other)?;
                let cred = human.read(&raw_id)?;
                if !self.is_rp_allowed(&cred.rp.id)
                    || self.require_ceremony_rp(&cred.rp.id).is_err()
                {
                    return Err(soft_fido2::Error::DoesNotExist);
                }
                Ok(cred)
            }
            CredentialFilter::ById(cred_id) => {
                let href = cred_ref_from_id(cred_id);
                if !self.allowed_cred_refs.contains(&href) {
                    return Err(soft_fido2::Error::DoesNotExist);
                }
                self.require_ceremony_cred(&href)?;
                let raw_id = self
                    .resolve_raw_id(&href)
                    .map_err(|_| soft_fido2::Error::DoesNotExist)?;
                let mut human = self.human.lock().map_err(|_| soft_fido2::Error::Other)?;
                let cred = human.read(&raw_id)?;
                if !self.is_rp_allowed(&cred.rp.id)
                    || self.require_ceremony_rp(&cred.rp.id).is_err()
                {
                    return Err(soft_fido2::Error::DoesNotExist);
                }
                Ok(cred)
            }
            CredentialFilter::None => {
                let raw_id = self
                    .resolve_raw_id(&active_ref)
                    .map_err(|_| soft_fido2::Error::DoesNotExist)?;
                let mut human = self.human.lock().map_err(|_| soft_fido2::Error::Other)?;
                let cred = human.read(&raw_id)?;
                if !self.is_rp_allowed(&cred.rp.id)
                    || self.require_ceremony_rp(&cred.rp.id).is_err()
                {
                    return Err(soft_fido2::Error::DoesNotExist);
                }
                Ok(cred)
            }
            CredentialFilter::ByHash(_hash) => Err(soft_fido2::Error::DoesNotExist),
        }
    }

    fn read_next(&mut self) -> Result<soft_fido2::Credential> {
        self.require_active_ceremony()?;
        Err(soft_fido2::Error::DoesNotExist)
    }

    fn read(&mut self, id: &[u8]) -> Result<soft_fido2::Credential> {
        self.require_active_ceremony()?;
        let href = cred_ref_from_id(id);
        self.require_ceremony_cred(&href)?;
        if !self.allowed_cred_refs.contains(&href) {
            return Err(soft_fido2::Error::DoesNotExist);
        }
        let raw_id = self
            .resolve_raw_id(&href)
            .map_err(|_| soft_fido2::Error::DoesNotExist)?;
        let mut human = self.human.lock().map_err(|_| soft_fido2::Error::Other)?;
        let cred = human.read(&raw_id)?;
        if !self.is_rp_allowed(&cred.rp.id) || self.require_ceremony_rp(&cred.rp.id).is_err() {
            return Err(soft_fido2::Error::DoesNotExist);
        }
        Ok(cred)
    }

    fn write(&mut self, cred_ref: soft_fido2::CredentialRef) -> Result<()> {
        let cred_id = cred_ref.id.to_vec();
        self.require_active_ceremony()?;
        let active_rp_id = self
            .scope
            .active_rp_id()
            .ok_or(DelegatedError::WriteDenied)?;

        if matches!(self.scope.active_action(), Some(CeremonyAction::Register)) {
            let credential_rp = normalize_rp_id(cred_ref.rp_id);
            if !self.registration_allowed
                || !self.is_rp_allowed(&credential_rp)
                || credential_rp != active_rp_id
            {
                return Err(DelegatedError::WriteDenied.into());
            }
            let mut human = self.human.lock().map_err(|_| soft_fido2::Error::Other)?;
            human.write(cred_ref)?;
            return Ok(());
        }

        let href = cred_ref_from_id(&cred_id);
        self.require_ceremony_cred(&href)?;
        if !self.allowed_cred_refs.contains(&href) {
            return Err(DelegatedError::WriteDenied.into());
        }

        let raw_id = self
            .resolve_raw_id(&href)
            .map_err(|_| DelegatedError::WriteDenied)?;

        let mut human = self.human.lock().map_err(|_| soft_fido2::Error::Other)?;

        let latest = human.read(&raw_id)?;

        if !self.is_rp_allowed(&latest.rp.id) || normalize_rp_id(&latest.rp.id) != active_rp_id {
            return Err(DelegatedError::RpIdNotAllowed(normalize_rp_id(&latest.rp.id)).into());
        }

        let mut new_cred = cred_ref.to_owned();
        new_cred.extensions.hmac_secret = latest.extensions.hmac_secret;

        self.verify_immutable_fields(&latest, &new_cred)?;
        self.verify_counter(&latest, &new_cred)?;

        human.write(cred_ref)?;
        Ok(())
    }

    fn delete(&mut self, _id: &[u8]) -> Result<()> {
        Err(DelegatedError::DeleteDenied.into())
    }

    fn count_credentials(&self) -> usize {
        match self.scope.active_cred_ref() {
            Some(ref active_ref) => self.cred_ref_to_raw_id.contains_key(active_ref) as usize,
            None => 0,
        }
    }

    fn cleanup_expired_cache(&mut self) {
        if let Ok(mut human) = self.human.lock() {
            human.cleanup_expired_cache();
        }
    }
}

pub struct ForwardingStorageHandle {
    inner: Arc<Mutex<Box<dyn CredentialStorage>>>,
}

impl ForwardingStorageHandle {
    pub fn new(inner: Arc<Mutex<Box<dyn CredentialStorage>>>) -> Self {
        Self { inner }
    }
}

impl CredentialStorage for ForwardingStorageHandle {
    fn read_first(&mut self, filter: CredentialFilter) -> Result<soft_fido2::Credential> {
        let mut inner = self.inner.lock().map_err(|_| soft_fido2::Error::Other)?;
        inner.read_first(filter)
    }

    fn read_next(&mut self) -> Result<soft_fido2::Credential> {
        let mut inner = self.inner.lock().map_err(|_| soft_fido2::Error::Other)?;
        inner.read_next()
    }

    fn read(&mut self, id: &[u8]) -> Result<soft_fido2::Credential> {
        let mut inner = self.inner.lock().map_err(|_| soft_fido2::Error::Other)?;
        inner.read(id)
    }

    fn write(&mut self, cred_ref: soft_fido2::CredentialRef) -> Result<()> {
        let mut inner = self.inner.lock().map_err(|_| soft_fido2::Error::Other)?;
        inner.write(cred_ref)
    }

    fn delete(&mut self, id: &[u8]) -> Result<()> {
        let mut inner = self.inner.lock().map_err(|_| soft_fido2::Error::Other)?;
        inner.delete(id)
    }

    fn count_credentials(&self) -> usize {
        match self.inner.lock() {
            Ok(inner) => inner.count_credentials(),
            Err(_) => 0,
        }
    }

    fn cleanup_expired_cache(&mut self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.cleanup_expired_cache();
        }
    }
}

pub struct IsolatedScopedStorage<S: CredentialStorage> {
    backend: S,
    scope: CeremonyScope,
    allowed_rp_ids: HashSet<String>,
    registration_allowed: bool,
    cred_ref_to_raw_id: HashMap<CredentialRef, Vec<u8>>,
}

impl<S: CredentialStorage> IsolatedScopedStorage<S> {
    pub fn new(
        backend: S,
        scope: CeremonyScope,
        rp_ids: Vec<String>,
        registration_allowed: bool,
    ) -> Self {
        let allowed_rp_ids: HashSet<String> =
            rp_ids.into_iter().map(|r| normalize_rp_id(&r)).collect();
        Self {
            backend,
            scope,
            allowed_rp_ids,
            registration_allowed,
            cred_ref_to_raw_id: HashMap::new(),
        }
    }

    pub fn build_index(&mut self) -> std::result::Result<(), DelegatedError> {
        let mut index = HashMap::new();
        let first = match self.backend.read_first(CredentialFilter::None) {
            Ok(c) => c,
            Err(soft_fido2::Error::DoesNotExist) | Err(soft_fido2::Error::NoCredentials) => {
                self.cred_ref_to_raw_id = index;
                return Ok(());
            }
            Err(e) => return Err(DelegatedError::Internal(format!("read_first: {}", e))),
        };
        let href = cred_ref_from_id(&first.id);
        index.insert(href, first.id.clone());
        loop {
            match self.backend.read_next() {
                Ok(c) => {
                    let href = cred_ref_from_id(&c.id);
                    index.insert(href, c.id.clone());
                }
                Err(soft_fido2::Error::DoesNotExist) | Err(soft_fido2::Error::NoCredentials) => {
                    break;
                }
                Err(e) => {
                    return Err(DelegatedError::Internal(format!("read_next: {}", e)));
                }
            }
        }
        self.cred_ref_to_raw_id = index;
        Ok(())
    }

    fn resolve_raw_id(
        &self,
        cred_ref: &CredentialRef,
    ) -> std::result::Result<Vec<u8>, DelegatedError> {
        self.cred_ref_to_raw_id
            .get(cred_ref)
            .cloned()
            .ok_or_else(|| DelegatedError::CredentialNotAllowed(cred_ref.to_hex()))
    }

    fn is_rp_allowed(&self, rp_id: &str) -> bool {
        self.allowed_rp_ids.contains(&normalize_rp_id(rp_id))
    }

    fn require_auth_scope(&self) -> std::result::Result<CredentialRef, soft_fido2::Error> {
        match self.scope.active_action() {
            Some(CeremonyAction::Authenticate(ref cred_ref)) => Ok(cred_ref.clone()),
            _ => Err(soft_fido2::Error::DoesNotExist),
        }
    }

    fn require_ceremony_rp(&self, rp_id: &str) -> std::result::Result<(), soft_fido2::Error> {
        match self.scope.active_rp_id() {
            Some(active) if active == normalize_rp_id(rp_id) => Ok(()),
            _ => Err(soft_fido2::Error::DoesNotExist),
        }
    }

    fn verify_immutable_fields(
        &self,
        old: &soft_fido2::Credential,
        new_cred: &soft_fido2::Credential,
    ) -> std::result::Result<(), DelegatedError> {
        if old.id != new_cred.id {
            return Err(DelegatedError::ImmutableFieldViolation(
                "credential_id".into(),
            ));
        }
        if normalize_rp_id(&old.rp.id) != normalize_rp_id(&new_cred.rp.id) {
            return Err(DelegatedError::ImmutableFieldViolation("rp_id".into()));
        }
        if old.user.id != new_cred.user.id {
            return Err(DelegatedError::ImmutableFieldViolation("user_id".into()));
        }
        if old.user.name != new_cred.user.name {
            return Err(DelegatedError::ImmutableFieldViolation("user_name".into()));
        }
        if old.user.display_name != new_cred.user.display_name {
            return Err(DelegatedError::ImmutableFieldViolation(
                "user_display_name".into(),
            ));
        }
        if old.alg != new_cred.alg {
            return Err(DelegatedError::ImmutableFieldViolation("alg".into()));
        }
        if old.created != new_cred.created {
            return Err(DelegatedError::ImmutableFieldViolation("created".into()));
        }
        if old.discoverable != new_cred.discoverable {
            return Err(DelegatedError::ImmutableFieldViolation(
                "discoverable".into(),
            ));
        }
        if old.key.material.as_slice() != new_cred.key.material.as_slice() {
            return Err(DelegatedError::ImmutableFieldViolation(
                "private_key".into(),
            ));
        }
        if old.extensions.cred_protect != new_cred.extensions.cred_protect {
            return Err(DelegatedError::ImmutableFieldViolation(
                "extensions.cred_protect".into(),
            ));
        }
        if old.extensions.hmac_secret != new_cred.extensions.hmac_secret {
            return Err(DelegatedError::ImmutableFieldViolation(
                "extensions.hmac_secret".into(),
            ));
        }
        if old.extensions.cred_random != new_cred.extensions.cred_random {
            return Err(DelegatedError::ImmutableFieldViolation(
                "extensions.cred_random".into(),
            ));
        }
        Ok(())
    }
}

impl<S: CredentialStorage> CredentialStorage for IsolatedScopedStorage<S> {
    fn read_first(&mut self, filter: CredentialFilter) -> Result<soft_fido2::Credential> {
        let auth_ref = self.require_auth_scope()?;

        match &filter {
            CredentialFilter::ByRp(rp_id) => {
                if !self.is_rp_allowed(rp_id) || self.require_ceremony_rp(rp_id).is_err() {
                    return Err(soft_fido2::Error::DoesNotExist);
                }
            }
            CredentialFilter::ById(cred_id) => {
                let href = cred_ref_from_id(cred_id);
                if href != auth_ref {
                    return Err(soft_fido2::Error::DoesNotExist);
                }
            }
            CredentialFilter::None => {}
            CredentialFilter::ByHash(_) => return Err(soft_fido2::Error::DoesNotExist),
        }

        let raw_id = self
            .resolve_raw_id(&auth_ref)
            .map_err(|_| soft_fido2::Error::DoesNotExist)?;
        let cred = self.backend.read(&raw_id)?;
        if !self.is_rp_allowed(&cred.rp.id) || self.require_ceremony_rp(&cred.rp.id).is_err() {
            return Err(soft_fido2::Error::DoesNotExist);
        }
        Ok(cred)
    }

    fn read_next(&mut self) -> Result<soft_fido2::Credential> {
        self.require_auth_scope()?;
        Err(soft_fido2::Error::DoesNotExist)
    }

    fn read(&mut self, id: &[u8]) -> Result<soft_fido2::Credential> {
        let auth_ref = self.require_auth_scope()?;
        let href = cred_ref_from_id(id);
        if href != auth_ref {
            return Err(soft_fido2::Error::DoesNotExist);
        }
        let raw_id = self
            .resolve_raw_id(&auth_ref)
            .map_err(|_| soft_fido2::Error::DoesNotExist)?;
        let cred = self.backend.read(&raw_id)?;
        if !self.is_rp_allowed(&cred.rp.id) || self.require_ceremony_rp(&cred.rp.id).is_err() {
            return Err(soft_fido2::Error::DoesNotExist);
        }
        Ok(cred)
    }

    fn write(&mut self, cred_ref: soft_fido2::CredentialRef) -> Result<()> {
        match self.scope.active_action() {
            Some(CeremonyAction::Register) => {
                let active_rp_id = self
                    .scope
                    .active_rp_id()
                    .ok_or(DelegatedError::WriteDenied)?;
                if !self.registration_allowed {
                    return Err(DelegatedError::RegistrationDenied.into());
                }
                if !self.is_rp_allowed(cred_ref.rp_id)
                    || normalize_rp_id(cred_ref.rp_id) != active_rp_id
                {
                    return Err(
                        DelegatedError::RpIdNotAllowed(normalize_rp_id(cred_ref.rp_id)).into(),
                    );
                }
                self.backend.write(cred_ref)?;
                Ok(())
            }
            Some(CeremonyAction::Authenticate(ref active_ref)) => {
                let active_rp_id = self
                    .scope
                    .active_rp_id()
                    .ok_or(DelegatedError::WriteDenied)?;
                let href = cred_ref_from_id(cred_ref.id);
                if href != *active_ref {
                    return Err(DelegatedError::WriteDenied.into());
                }
                let raw_id = self
                    .resolve_raw_id(active_ref)
                    .map_err(|_| DelegatedError::WriteDenied)?;
                let latest = self.backend.read(&raw_id)?;
                if !self.is_rp_allowed(&latest.rp.id)
                    || normalize_rp_id(&latest.rp.id) != active_rp_id
                {
                    return Err(
                        DelegatedError::RpIdNotAllowed(normalize_rp_id(&latest.rp.id)).into(),
                    );
                }
                let mut new_cred = cred_ref.to_owned();
                new_cred.extensions.hmac_secret = latest.extensions.hmac_secret;
                self.verify_immutable_fields(&latest, &new_cred)?;
                if new_cred.sign_count <= latest.sign_count {
                    return Err(DelegatedError::CounterNotMonotonic.into());
                }
                self.backend.write(cred_ref)?;
                Ok(())
            }
            None => Err(DelegatedError::WriteDenied.into()),
        }
    }

    fn delete(&mut self, _id: &[u8]) -> Result<()> {
        Err(DelegatedError::DeleteDenied.into())
    }

    fn count_credentials(&self) -> usize {
        match self.scope.active_action() {
            Some(CeremonyAction::Authenticate(_)) => 1,
            _ => 0,
        }
    }

    fn cleanup_expired_cache(&mut self) {
        self.backend.cleanup_expired_cache();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{CredentialFilter, CredentialStorage};
    use soft_fido2_ctap::SecBytes;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    fn make_test_cred(
        id: &[u8],
        rp_id: &str,
        user_id: &[u8],
        sign_count: u32,
    ) -> soft_fido2::Credential {
        soft_fido2::Credential {
            id: id.to_vec(),
            rp: soft_fido2_ctap::types::RelyingParty {
                id: rp_id.to_string(),
                name: Some("Test".to_string()),
            },
            user: soft_fido2_ctap::types::User {
                id: user_id.to_vec(),
                name: Some("testuser".to_string()),
                display_name: Some("Test User".to_string()),
            },
            sign_count,
            alg: -7,
            key: soft_fido2_ctap::CredentialKey::software(SecBytes::new(vec![0xAA; 32])),
            created: 1000,
            discoverable: true,
            extensions: soft_fido2::Extensions::default(),
        }
    }

    #[derive(Clone)]
    struct MockStorage {
        creds: Arc<Mutex<Vec<soft_fido2::Credential>>>,
        iteration: Arc<Mutex<VecDeque<usize>>>,
        writes: Arc<Mutex<Vec<soft_fido2::Credential>>>,
        deletes: Arc<Mutex<Vec<Vec<u8>>>>,
        iterator_calls: Arc<Mutex<usize>>,
        cleanup_calls: Arc<Mutex<usize>>,
    }

    impl MockStorage {
        fn new(creds: Vec<soft_fido2::Credential>) -> Self {
            Self {
                creds: Arc::new(Mutex::new(creds)),
                iteration: Arc::new(Mutex::new(VecDeque::new())),
                writes: Arc::new(Mutex::new(Vec::new())),
                deletes: Arc::new(Mutex::new(Vec::new())),
                iterator_calls: Arc::new(Mutex::new(0)),
                cleanup_calls: Arc::new(Mutex::new(0)),
            }
        }
    }

    impl CredentialStorage for MockStorage {
        fn read_first(&mut self, filter: CredentialFilter) -> Result<soft_fido2::Credential> {
            *self.iterator_calls.lock().unwrap() += 1;
            let creds = self.creds.lock().unwrap();
            let mut iter = self.iteration.lock().unwrap();
            iter.clear();

            let matching: Vec<usize> = match &filter {
                CredentialFilter::None => (0..creds.len()).collect(),
                CredentialFilter::ByRp(rp) => creds
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| normalize_rp_id(&c.rp.id) == normalize_rp_id(rp))
                    .map(|(i, _)| i)
                    .collect(),
                CredentialFilter::ById(id) => creds
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| c.id == *id)
                    .map(|(i, _)| i)
                    .collect(),
                CredentialFilter::ByHash(_) => vec![],
            };

            if matching.is_empty() {
                return Err(soft_fido2::Error::DoesNotExist);
            }

            for &idx in &matching[1..] {
                iter.push_back(idx);
            }

            Ok(creds[matching[0]].clone())
        }

        fn read_next(&mut self) -> Result<soft_fido2::Credential> {
            let creds = self.creds.lock().unwrap();
            let mut iter = self.iteration.lock().unwrap();
            match iter.pop_front() {
                Some(idx) => Ok(creds[idx].clone()),
                None => Err(soft_fido2::Error::DoesNotExist),
            }
        }

        fn read(&mut self, id: &[u8]) -> Result<soft_fido2::Credential> {
            let creds = self.creds.lock().unwrap();
            creds
                .iter()
                .find(|c| c.id == id)
                .cloned()
                .ok_or(soft_fido2::Error::DoesNotExist)
        }

        fn write(&mut self, cred_ref: soft_fido2::CredentialRef) -> Result<()> {
            let cred = cred_ref.to_owned();
            let mut creds = self.creds.lock().unwrap();
            let mut writes = self.writes.lock().unwrap();

            if let Some(existing) = creds.iter_mut().find(|c| c.id == cred.id) {
                *existing = cred.clone();
            } else {
                creds.push(cred.clone());
            }
            writes.push(cred);
            Ok(())
        }

        fn delete(&mut self, id: &[u8]) -> Result<()> {
            let mut creds = self.creds.lock().unwrap();
            let mut deletes = self.deletes.lock().unwrap();
            creds.retain(|c| c.id != id);
            deletes.push(id.to_vec());
            Ok(())
        }

        fn count_credentials(&self) -> usize {
            self.creds.lock().unwrap().len()
        }

        fn cleanup_expired_cache(&mut self) {
            *self.cleanup_calls.lock().unwrap() += 1;
        }
    }

    fn cred_ref_for(id: &[u8]) -> CredentialRef {
        CredentialRef::with_default_domain(id)
    }

    fn borrowed_credential_ref(cred: &soft_fido2::Credential) -> soft_fido2::CredentialRef<'_> {
        soft_fido2::CredentialRef {
            id: &cred.id,
            rp_id: &cred.rp.id,
            rp_name: cred.rp.name.as_deref(),
            user_id: &cred.user.id,
            user_name: cred.user.name.as_deref(),
            user_display_name: cred.user.display_name.as_deref(),
            sign_count: &cred.sign_count,
            alg: &cred.alg,
            key: &cred.key,
            created: &cred.created,
            discoverable: &cred.discoverable,
            cred_protect: cred.extensions.cred_protect.as_ref(),
            cred_random: None,
        }
    }

    #[test]
    fn test_delegated_registration_requires_explicit_scope_and_target() {
        let human = make_shared_mock(vec![]);
        let mut delegated =
            SharedDelegatedStorage::new(human.clone(), vec!["example.com".to_string()], vec![])
                .with_registration_allowed(true);
        delegated.build_index().unwrap();
        let scope = delegated.scope();
        let credential = make_test_cred(b"new", "example.com", b"agent", 0);

        assert!(
            delegated
                .write(borrowed_credential_ref(&credential))
                .is_err()
        );
        let _guard = scope.activate_register_for_rp("example.com").unwrap();
        delegated
            .write(borrowed_credential_ref(&credential))
            .unwrap();
        assert_eq!(human.lock().unwrap().count_credentials(), 1);
        assert!(delegated.delete(&credential.id).is_err());
    }

    #[test]
    fn test_delegated_registration_rejects_wrong_rp() {
        let human = make_shared_mock(vec![]);
        let mut delegated =
            SharedDelegatedStorage::new(human.clone(), vec!["example.com".to_string()], vec![])
                .with_registration_allowed(true);
        let scope = delegated.scope();
        let _guard = scope.activate_register_for_rp("example.com").unwrap();
        let credential = make_test_cred(b"new", "evil.com", b"agent", 0);

        assert!(
            delegated
                .write(borrowed_credential_ref(&credential))
                .is_err()
        );
        assert_eq!(human.lock().unwrap().count_credentials(), 0);
    }

    fn make_shared_mock(creds: Vec<soft_fido2::Credential>) -> Arc<Mutex<MockStorage>> {
        Arc::new(Mutex::new(MockStorage::new(creds)))
    }

    #[test]
    fn test_read_first_filters_by_rp() {
        let c1 = make_test_cred(b"cred1", "example.com", b"user1", 0);
        let c2 = make_test_cred(b"cred2", "evil.com", b"user2", 0);
        let human = make_shared_mock(vec![c1, c2]);

        let mut delegated = SharedDelegatedStorage::new(
            human,
            vec!["example.com".to_string()],
            vec![cred_ref_for(b"cred1"), cred_ref_for(b"cred2")],
        );
        delegated.build_index().unwrap();

        let _guard = delegated.activate_ceremony(cred_ref_for(b"cred1")).unwrap();
        let result = delegated.read_first(CredentialFilter::ByRp("example.com".into()));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().id, b"cred1");
    }

    #[test]
    fn test_read_first_denies_unauthorized_rp() {
        let c1 = make_test_cred(b"cred1", "evil.com", b"user1", 0);
        let human = make_shared_mock(vec![c1]);

        let mut delegated = SharedDelegatedStorage::new(
            human,
            vec!["example.com".to_string()],
            vec![cred_ref_for(b"cred1")],
        );
        delegated.build_index().unwrap();

        let _guard = delegated.activate_ceremony(cred_ref_for(b"cred1")).unwrap();
        let result = delegated.read_first(CredentialFilter::ByRp("evil.com".into()));
        assert!(result.is_err());
    }

    #[test]
    fn test_malicious_filter_rp_not_allowed() {
        let c1 = make_test_cred(b"cred1", "example.com", b"user1", 0);
        let human = make_shared_mock(vec![c1]);

        let mut delegated = SharedDelegatedStorage::new(
            human,
            vec!["example.com".to_string()],
            vec![cred_ref_for(b"cred1")],
        );
        delegated.build_index().unwrap();

        let _guard = delegated.activate_ceremony(cred_ref_for(b"cred1")).unwrap();
        let result = delegated.read_first(CredentialFilter::ByRp("attacker.com".into()));
        assert!(result.is_err());
    }

    #[test]
    fn test_malicious_filter_by_id_not_allowed() {
        let c1 = make_test_cred(b"cred1", "example.com", b"user1", 0);
        let human = make_shared_mock(vec![c1]);

        let mut delegated = SharedDelegatedStorage::new(
            human,
            vec!["example.com".to_string()],
            vec![cred_ref_for(b"other-cred")],
        );
        delegated.build_index().unwrap();

        assert!(delegated.activate_ceremony(cred_ref_for(b"cred1")).is_err());
        let result = delegated.read_first(CredentialFilter::ById(b"cred1".to_vec()));
        assert!(result.is_err());
    }

    #[test]
    fn test_credential_ref_collision_resistance() {
        let id1 = b"credential-A";
        let id2 = b"credential-B";
        let ref1 = cred_ref_for(id1);
        let ref2 = cred_ref_for(id2);
        assert_ne!(ref1, ref2);

        let id3 = b"credential-A";
        let ref3 = cred_ref_for(id3);
        assert_eq!(ref1, ref3);
    }

    #[test]
    fn test_enumeration_returns_only_active_cred() {
        let c1 = make_test_cred(b"cred1", "example.com", b"user1", 0);
        let c2 = make_test_cred(b"cred2", "example.com", b"user2", 0);
        let c3 = make_test_cred(b"cred3", "example.com", b"user3", 0);
        let human = make_shared_mock(vec![c1, c2, c3]);

        let mut delegated = SharedDelegatedStorage::new(
            human,
            vec!["example.com".to_string()],
            vec![
                cred_ref_for(b"cred1"),
                cred_ref_for(b"cred2"),
                cred_ref_for(b"cred3"),
            ],
        );
        delegated.build_index().unwrap();

        let _guard = delegated.activate_ceremony(cred_ref_for(b"cred1")).unwrap();
        let first = delegated
            .read_first(CredentialFilter::ByRp("example.com".into()))
            .unwrap();
        assert_eq!(first.id, b"cred1");

        assert!(delegated.read_next().is_err());
    }

    #[test]
    fn test_shared_human_no_iterator_during_ceremony() {
        let c1 = make_test_cred(b"cred1", "example.com", b"user1", 0);
        let c2 = make_test_cred(b"cred2", "example.com", b"user2", 0);
        let human = make_shared_mock(vec![c1, c2]);

        let mut delegated = SharedDelegatedStorage::new(
            human.clone(),
            vec!["example.com".to_string()],
            vec![cred_ref_for(b"cred1"), cred_ref_for(b"cred2")],
        );
        delegated.build_index().unwrap();

        let iter_before = *human.lock().unwrap().iterator_calls.lock().unwrap();

        let _guard = delegated.activate_ceremony(cred_ref_for(b"cred1")).unwrap();
        let _ = delegated.read(b"cred1").unwrap();
        let _ = delegated
            .read_first(CredentialFilter::ByRp("example.com".into()))
            .unwrap();

        let iter_after = *human.lock().unwrap().iterator_calls.lock().unwrap();
        assert_eq!(
            iter_before, iter_after,
            "iterator must not be called during ceremony"
        );
    }

    #[test]
    fn test_write_denied_for_new_credential() {
        let human = make_shared_mock(vec![]);

        let mut delegated =
            SharedDelegatedStorage::new(human, vec!["example.com".to_string()], vec![]);
        delegated.build_index().unwrap();

        let new_cred = make_test_cred(b"new-cred", "example.com", b"user1", 0);
        assert!(
            delegated
                .activate_ceremony(cred_ref_for(b"new-cred"))
                .is_err()
        );

        let cred_ref = soft_fido2::CredentialRef {
            id: &new_cred.id,
            rp_id: &new_cred.rp.id,
            rp_name: new_cred.rp.name.as_deref(),
            user_id: &new_cred.user.id,
            user_name: new_cred.user.name.as_deref(),
            user_display_name: new_cred.user.display_name.as_deref(),
            sign_count: &new_cred.sign_count,
            alg: &new_cred.alg,
            key: &new_cred.key,
            created: &new_cred.created,
            discoverable: &new_cred.discoverable,
            cred_protect: new_cred.extensions.cred_protect.as_ref(),
            cred_random: None,
        };

        let result = delegated.write(cred_ref);
        assert!(result.is_err());
    }

    #[test]
    fn test_delete_denied() {
        let c1 = make_test_cred(b"cred1", "example.com", b"user1", 0);
        let human = make_shared_mock(vec![c1]);

        let mut delegated = SharedDelegatedStorage::new(
            human,
            vec!["example.com".to_string()],
            vec![cred_ref_for(b"cred1")],
        );
        delegated.build_index().unwrap();

        let _guard = delegated.activate_ceremony(cred_ref_for(b"cred1")).unwrap();
        let result = delegated.delete(b"cred1");
        assert!(result.is_err());
    }

    #[test]
    fn test_post_assertion_update_allowed() {
        let c1 = make_test_cred(b"cred1", "example.com", b"user1", 5);
        let human = make_shared_mock(vec![c1.clone()]);

        let mut delegated = SharedDelegatedStorage::new(
            human,
            vec!["example.com".to_string()],
            vec![cred_ref_for(b"cred1")],
        );
        delegated.build_index().unwrap();

        let _guard = delegated.activate_ceremony(cred_ref_for(b"cred1")).unwrap();
        let _ = delegated.read(b"cred1").unwrap();

        let mut updated = c1.clone();
        updated.sign_count = 6;

        let cred_ref = soft_fido2::CredentialRef {
            id: &updated.id,
            rp_id: &updated.rp.id,
            rp_name: updated.rp.name.as_deref(),
            user_id: &updated.user.id,
            user_name: updated.user.name.as_deref(),
            user_display_name: updated.user.display_name.as_deref(),
            sign_count: &updated.sign_count,
            alg: &updated.alg,
            key: &updated.key,
            created: &updated.created,
            discoverable: &updated.discoverable,
            cred_protect: updated.extensions.cred_protect.as_ref(),
            cred_random: None,
        };

        let result = delegated.write(cred_ref);
        assert!(result.is_ok());
    }

    #[test]
    fn test_counter_not_monotonic_rejected() {
        let c1 = make_test_cred(b"cred1", "example.com", b"user1", 10);
        let human = make_shared_mock(vec![c1.clone()]);

        let mut delegated = SharedDelegatedStorage::new(
            human,
            vec!["example.com".to_string()],
            vec![cred_ref_for(b"cred1")],
        );
        delegated.build_index().unwrap();

        let _guard = delegated.activate_ceremony(cred_ref_for(b"cred1")).unwrap();
        let _ = delegated.read(b"cred1").unwrap();

        let mut regressed = c1.clone();
        regressed.sign_count = 5;

        let cred_ref = soft_fido2::CredentialRef {
            id: &regressed.id,
            rp_id: &regressed.rp.id,
            rp_name: regressed.rp.name.as_deref(),
            user_id: &regressed.user.id,
            user_name: regressed.user.name.as_deref(),
            user_display_name: regressed.user.display_name.as_deref(),
            sign_count: &regressed.sign_count,
            alg: &regressed.alg,
            key: &regressed.key,
            created: &regressed.created,
            discoverable: &regressed.discoverable,
            cred_protect: regressed.extensions.cred_protect.as_ref(),
            cred_random: None,
        };

        let result = delegated.write(cred_ref);
        assert!(result.is_err());
    }

    #[test]
    fn test_constant_counter_mode_allows_same_counter() {
        let c1 = make_test_cred(b"cred1", "example.com", b"user1", 10);
        let human = make_shared_mock(vec![c1.clone()]);

        let mut delegated = SharedDelegatedStorage::new(
            human,
            vec!["example.com".to_string()],
            vec![cred_ref_for(b"cred1")],
        )
        .with_constant_counter_mode(true);
        delegated.build_index().unwrap();

        let _guard = delegated.activate_ceremony(cred_ref_for(b"cred1")).unwrap();
        let _ = delegated.read(b"cred1").unwrap();

        let mut same_counter = c1.clone();
        same_counter.sign_count = 10;

        let cred_ref = soft_fido2::CredentialRef {
            id: &same_counter.id,
            rp_id: &same_counter.rp.id,
            rp_name: same_counter.rp.name.as_deref(),
            user_id: &same_counter.user.id,
            user_name: same_counter.user.name.as_deref(),
            user_display_name: same_counter.user.display_name.as_deref(),
            sign_count: &same_counter.sign_count,
            alg: &same_counter.alg,
            key: &same_counter.key,
            created: &same_counter.created,
            discoverable: &same_counter.discoverable,
            cred_protect: same_counter.extensions.cred_protect.as_ref(),
            cred_random: None,
        };

        let result = delegated.write(cred_ref);
        assert!(result.is_ok());
    }

    #[test]
    fn test_no_overdelegation_rp_subset() {
        let c1 = make_test_cred(b"cred1", "example.com", b"user1", 0);
        let c2 = make_test_cred(b"cred2", "other.com", b"user2", 0);
        let human = make_shared_mock(vec![c1, c2]);

        let mut delegated = SharedDelegatedStorage::new(
            human,
            vec!["example.com".to_string()],
            vec![cred_ref_for(b"cred1"), cred_ref_for(b"cred2")],
        );
        delegated.build_index().unwrap();

        let _guard = delegated.activate_ceremony(cred_ref_for(b"cred1")).unwrap();
        let result = delegated.read_first(CredentialFilter::ByRp("other.com".into()));
        assert!(result.is_err());
    }

    #[test]
    fn test_no_overdelegation_credential_subset() {
        let c1 = make_test_cred(b"cred1", "example.com", b"user1", 0);
        let c2 = make_test_cred(b"cred2", "example.com", b"user2", 0);
        let human = make_shared_mock(vec![c1, c2]);

        let mut delegated = SharedDelegatedStorage::new(
            human,
            vec!["example.com".to_string()],
            vec![cred_ref_for(b"cred1")],
        );
        delegated.build_index().unwrap();

        let _guard = delegated.activate_ceremony(cred_ref_for(b"cred1")).unwrap();
        let result = delegated.read(b"cred2");
        assert!(result.is_err());
    }

    #[test]
    fn test_discovery_denied_by_hash_filter() {
        let c1 = make_test_cred(b"cred1", "example.com", b"user1", 0);
        let human = make_shared_mock(vec![c1]);

        let mut delegated = SharedDelegatedStorage::new(
            human,
            vec!["example.com".to_string()],
            vec![cred_ref_for(b"cred1")],
        );
        delegated.build_index().unwrap();

        let _guard = delegated.activate_ceremony(cred_ref_for(b"cred1")).unwrap();
        let result = delegated.read_first(CredentialFilter::ByHash([0u8; 32]));
        assert!(result.is_err());
    }

    #[test]
    fn test_rp_id_normalization() {
        let c1 = make_test_cred(b"cred1", "EXAMPLE.COM", b"user1", 0);
        let human = make_shared_mock(vec![c1]);

        let mut delegated = SharedDelegatedStorage::new(
            human,
            vec!["example.com".to_string()],
            vec![cred_ref_for(b"cred1")],
        );
        delegated.build_index().unwrap();

        let _guard = delegated.activate_ceremony(cred_ref_for(b"cred1")).unwrap();
        let result = delegated.read_first(CredentialFilter::ByRp("EXAMPLE.COM".into()));
        assert!(result.is_ok());
    }

    #[test]
    fn test_no_second_adapter_shared_human() {
        let c1 = make_test_cred(b"cred1", "example.com", b"user1", 0);
        let human = make_shared_mock(vec![c1]);

        let human_ptr = Arc::as_ptr(&human);

        let delegated_a = SharedDelegatedStorage::new(
            human.clone(),
            vec!["example.com".to_string()],
            vec![cred_ref_for(b"cred1")],
        );
        let delegated_b = SharedDelegatedStorage::new(
            human.clone(),
            vec!["example.com".to_string()],
            vec![cred_ref_for(b"cred1")],
        );

        assert_eq!(Arc::as_ptr(&delegated_a.human), human_ptr);
        assert_eq!(Arc::as_ptr(&delegated_b.human), human_ptr);
    }

    #[test]
    fn test_concurrent_counter_updates_no_lost_increment() {
        let c1 = make_test_cred(b"cred1", "example.com", b"user1", 0);
        let human = make_shared_mock(vec![c1]);

        let op_lock = Arc::new(Mutex::new(()));

        let iterations = 20;
        let mut handles = Vec::new();

        for _ in 0..iterations {
            let human_clone = human.clone();
            let op_lock_clone = op_lock.clone();
            let handle = std::thread::spawn(move || {
                let _op = op_lock_clone.lock().unwrap();
                let mut storage = human_clone.lock().unwrap();
                let cred = storage.read(b"cred1").unwrap();
                let new_count = cred.sign_count + 1;
                let cred_ref = soft_fido2::CredentialRef {
                    id: &cred.id,
                    rp_id: &cred.rp.id,
                    rp_name: cred.rp.name.as_deref(),
                    user_id: &cred.user.id,
                    user_name: cred.user.name.as_deref(),
                    user_display_name: cred.user.display_name.as_deref(),
                    sign_count: &new_count,
                    alg: &cred.alg,
                    key: &cred.key,
                    created: &cred.created,
                    discoverable: &cred.discoverable,
                    cred_protect: cred.extensions.cred_protect.as_ref(),
                    cred_random: None,
                };
                storage.write(cred_ref).unwrap();
            });
            handles.push(handle);
        }

        for h in handles {
            h.join().unwrap();
        }

        let final_count = human.lock().unwrap().read(b"cred1").unwrap().sign_count;
        assert_eq!(final_count, iterations as u32, "no lost increments");
    }

    #[test]
    fn test_human_remains_functional_after_delegated_use() {
        let c1 = make_test_cred(b"cred1", "example.com", b"user1", 5);
        let c2 = make_test_cred(b"cred2", "example.com", b"user2", 0);
        let human = make_shared_mock(vec![c1.clone(), c2.clone()]);

        let mut delegated = SharedDelegatedStorage::new(
            human.clone(),
            vec!["example.com".to_string()],
            vec![cred_ref_for(b"cred1")],
        );
        delegated.build_index().unwrap();

        {
            let _guard = delegated.activate_ceremony(cred_ref_for(b"cred1")).unwrap();
            let _ = delegated.read(b"cred1").unwrap();
            let mut updated = c1.clone();
            updated.sign_count = 6;
            let cred_ref = soft_fido2::CredentialRef {
                id: &updated.id,
                rp_id: &updated.rp.id,
                rp_name: updated.rp.name.as_deref(),
                user_id: &updated.user.id,
                user_name: updated.user.name.as_deref(),
                user_display_name: updated.user.display_name.as_deref(),
                sign_count: &updated.sign_count,
                alg: &updated.alg,
                key: &updated.key,
                created: &updated.created,
                discoverable: &updated.discoverable,
                cred_protect: updated.extensions.cred_protect.as_ref(),
                cred_random: None,
            };
            delegated.write(cred_ref).unwrap();
        }

        let mut human_storage = human.lock().unwrap();
        assert_eq!(human_storage.count_credentials(), 2);
        let read_back = human_storage.read(b"cred1").unwrap();
        assert_eq!(read_back.sign_count, 6);
        let read_back2 = human_storage.read(b"cred2").unwrap();
        assert_eq!(read_back2.sign_count, 0);
    }

    #[test]
    fn test_exact_scope_credential_isolation() {
        let c1 = make_test_cred(b"cred1", "example.com", b"user1", 0);
        let c2 = make_test_cred(b"cred2", "example.com", b"user2", 0);
        let human = make_shared_mock(vec![c1, c2]);

        let mut delegated = SharedDelegatedStorage::new(
            human,
            vec!["example.com".to_string()],
            vec![cred_ref_for(b"cred1"), cred_ref_for(b"cred2")],
        );
        delegated.build_index().unwrap();

        let _guard = delegated.activate_ceremony(cred_ref_for(b"cred1")).unwrap();
        let result = delegated.read(b"cred1");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().id, b"cred1");

        assert!(delegated.read(b"cred2").is_err());
    }

    #[test]
    fn test_ceremony_guard_drop_clears_scope() {
        let c1 = make_test_cred(b"cred1", "example.com", b"user1", 0);
        let human = make_shared_mock(vec![c1]);

        let mut delegated = SharedDelegatedStorage::new(
            human,
            vec!["example.com".to_string()],
            vec![cred_ref_for(b"cred1")],
        );
        delegated.build_index().unwrap();

        {
            let _guard = delegated.activate_ceremony(cred_ref_for(b"cred1")).unwrap();
            assert!(delegated.read(b"cred1").is_ok());
        }

        assert!(delegated.read(b"cred1").is_err());
        assert_eq!(delegated.count_credentials(), 0);
    }

    #[test]
    fn test_ceremony_no_scope_returns_no_credentials() {
        let c1 = make_test_cred(b"cred1", "example.com", b"user1", 0);
        let human = make_shared_mock(vec![c1]);

        let mut delegated = SharedDelegatedStorage::new(
            human,
            vec!["example.com".to_string()],
            vec![cred_ref_for(b"cred1")],
        );
        delegated.build_index().unwrap();

        assert!(delegated.read(b"cred1").is_err());
        assert!(
            delegated
                .read_first(CredentialFilter::ByRp("example.com".into()))
                .is_err()
        );
        assert!(delegated.read_first(CredentialFilter::None).is_err());
        assert_eq!(delegated.count_credentials(), 0);
    }

    #[test]
    fn test_ceremony_cannot_broaden_allowlist() {
        let c1 = make_test_cred(b"cred1", "example.com", b"user1", 0);
        let human = make_shared_mock(vec![c1]);

        let mut delegated = SharedDelegatedStorage::new(
            human,
            vec!["example.com".to_string()],
            vec![cred_ref_for(b"cred1")],
        );
        delegated.build_index().unwrap();

        assert!(
            delegated
                .activate_ceremony(cred_ref_for(b"not-in-allowlist"))
                .is_err()
        );
    }

    #[test]
    fn test_ceremony_scope_clone_shares_state() {
        let scope = CeremonyScope::new();
        let scope_clone = scope.clone();

        assert!(scope.active_cred_ref().is_none());

        let _guard = scope
            .activate_authenticate_for_rp(cred_ref_for(b"cred1"), "example.com")
            .unwrap();
        assert_eq!(scope.active_cred_ref(), Some(cred_ref_for(b"cred1")));
        assert_eq!(scope_clone.active_cred_ref(), Some(cred_ref_for(b"cred1")));

        drop(_guard);
        assert!(scope.active_cred_ref().is_none());
        assert!(scope_clone.active_cred_ref().is_none());
    }

    #[test]
    fn test_ceremony_generation_monotonic() {
        let scope = CeremonyScope::new();

        let guard1 = scope
            .activate_authenticate_for_rp(cred_ref_for(b"cred1"), "example.com")
            .unwrap();
        assert_eq!(scope.active_cred_ref(), Some(cred_ref_for(b"cred1")));

        let guard2 = scope
            .activate_authenticate_for_rp(cred_ref_for(b"cred2"), "example.com")
            .unwrap();
        assert_eq!(scope.active_cred_ref(), Some(cred_ref_for(b"cred2")));

        drop(guard1);
        assert_eq!(scope.active_cred_ref(), Some(cred_ref_for(b"cred2")));

        drop(guard2);
        assert!(scope.active_cred_ref().is_none());
    }

    #[test]
    fn test_raw_ids_private_in_daemon_memory() {
        let c1 = make_test_cred(b"raw-secret-id-1", "example.com", b"user1", 0);
        let human = make_shared_mock(vec![c1]);

        let mut delegated = SharedDelegatedStorage::new(
            human,
            vec!["example.com".to_string()],
            vec![cred_ref_for(b"raw-secret-id-1")],
        );
        delegated.build_index().unwrap();

        assert!(
            delegated
                .cred_ref_to_raw_id
                .contains_key(&cred_ref_for(b"raw-secret-id-1"))
        );
        assert_eq!(
            delegated
                .cred_ref_to_raw_id
                .get(&cred_ref_for(b"raw-secret-id-1"))
                .unwrap(),
            &b"raw-secret-id-1".to_vec()
        );
    }

    #[test]
    fn test_delegated_scope_rejects_other_allowed_rp() {
        let credential = make_test_cred(b"cred1", "example.com", b"user1", 5);
        let human = make_shared_mock(vec![credential.clone()]);
        let mut delegated = SharedDelegatedStorage::new(
            human,
            vec!["example.com".to_string(), "other.example".to_string()],
            vec![cred_ref_for(b"cred1")],
        );
        delegated.build_index().unwrap();

        let _guard = delegated
            .scope
            .activate_authenticate_for_rp(cred_ref_for(b"cred1"), "other.example")
            .unwrap();

        assert!(delegated.read(b"cred1").is_err());

        let mut updated = credential;
        updated.sign_count = 6;
        let credential_ref = soft_fido2::CredentialRef {
            id: &updated.id,
            rp_id: &updated.rp.id,
            rp_name: updated.rp.name.as_deref(),
            user_id: &updated.user.id,
            user_name: updated.user.name.as_deref(),
            user_display_name: updated.user.display_name.as_deref(),
            sign_count: &updated.sign_count,
            alg: &updated.alg,
            key: &updated.key,
            created: &updated.created,
            discoverable: &updated.discoverable,
            cred_protect: updated.extensions.cred_protect.as_ref(),
            cred_random: None,
        };
        assert!(delegated.write(credential_ref).is_err());
    }

    #[test]
    fn test_delegated_cleanup_reaches_human_storage() {
        let human = make_shared_mock(vec![]);
        let cleanup_calls = human.lock().unwrap().cleanup_calls.clone();
        let mut delegated = SharedDelegatedStorage::new(human, vec![], vec![]);

        delegated.cleanup_expired_cache();

        assert_eq!(*cleanup_calls.lock().unwrap(), 1);
    }

    #[test]
    fn test_immutable_field_violation_rp_id() {
        let c1 = make_test_cred(b"cred1", "example.com", b"user1", 5);
        let human = make_shared_mock(vec![c1.clone()]);

        let mut delegated = SharedDelegatedStorage::new(
            human,
            vec!["example.com".to_string(), "evil.com".to_string()],
            vec![cred_ref_for(b"cred1")],
        );
        delegated.build_index().unwrap();

        let _guard = delegated.activate_ceremony(cred_ref_for(b"cred1")).unwrap();
        let _ = delegated.read(b"cred1").unwrap();

        let mut tampered = c1.clone();
        tampered.rp.id = "evil.com".to_string();
        tampered.sign_count = 6;

        let cred_ref = soft_fido2::CredentialRef {
            id: &tampered.id,
            rp_id: &tampered.rp.id,
            rp_name: tampered.rp.name.as_deref(),
            user_id: &tampered.user.id,
            user_name: tampered.user.name.as_deref(),
            user_display_name: tampered.user.display_name.as_deref(),
            sign_count: &tampered.sign_count,
            alg: &tampered.alg,
            key: &tampered.key,
            created: &tampered.created,
            discoverable: &tampered.discoverable,
            cred_protect: tampered.extensions.cred_protect.as_ref(),
            cred_random: None,
        };

        let result = delegated.write(cred_ref);
        assert!(result.is_err());
    }

    #[test]
    fn test_immutable_field_violation_private_key() {
        let c1 = make_test_cred(b"cred1", "example.com", b"user1", 5);
        let human = make_shared_mock(vec![c1.clone()]);

        let mut delegated = SharedDelegatedStorage::new(
            human,
            vec!["example.com".to_string()],
            vec![cred_ref_for(b"cred1")],
        );
        delegated.build_index().unwrap();

        let _guard = delegated.activate_ceremony(cred_ref_for(b"cred1")).unwrap();
        let _ = delegated.read(b"cred1").unwrap();

        let mut tampered = c1.clone();
        tampered.key = soft_fido2_ctap::CredentialKey::software(SecBytes::new(vec![0xBB; 32]));
        tampered.sign_count = 6;

        let cred_ref = soft_fido2::CredentialRef {
            id: &tampered.id,
            rp_id: &tampered.rp.id,
            rp_name: tampered.rp.name.as_deref(),
            user_id: &tampered.user.id,
            user_name: tampered.user.name.as_deref(),
            user_display_name: tampered.user.display_name.as_deref(),
            sign_count: &tampered.sign_count,
            alg: &tampered.alg,
            key: &tampered.key,
            created: &tampered.created,
            discoverable: &tampered.discoverable,
            cred_protect: tampered.extensions.cred_protect.as_ref(),
            cred_random: None,
        };

        let result = delegated.write(cred_ref);
        assert!(result.is_err());
    }

    mod isolated_scoped_storage_tests {
        use super::*;
        use crate::agent::storage::IsolatedScopedStorage;

        fn make_isolated(
            creds: Vec<soft_fido2::Credential>,
            rp_ids: Vec<String>,
            registration_allowed: bool,
        ) -> (IsolatedScopedStorage<MockStorage>, CeremonyScope) {
            let backend = MockStorage::new(creds);
            let scope = CeremonyScope::new();
            let mut isolated =
                IsolatedScopedStorage::new(backend, scope.clone(), rp_ids, registration_allowed);
            isolated.build_index().unwrap();
            (isolated, scope)
        }

        fn cred_ref_to_soft_fido2(cred: &soft_fido2::Credential) -> soft_fido2::CredentialRef<'_> {
            soft_fido2::CredentialRef {
                id: &cred.id,
                rp_id: &cred.rp.id,
                rp_name: cred.rp.name.as_deref(),
                user_id: &cred.user.id,
                user_name: cred.user.name.as_deref(),
                user_display_name: cred.user.display_name.as_deref(),
                sign_count: &cred.sign_count,
                alg: &cred.alg,
                key: &cred.key,
                created: &cred.created,
                discoverable: &cred.discoverable,
                cred_protect: cred.extensions.cred_protect.as_ref(),
                cred_random: None,
            }
        }

        #[test]
        fn test_isolated_no_scope_returns_nothing() {
            let c1 = make_test_cred(b"cred1", "example.com", b"user1", 0);
            let (mut isolated, _scope) =
                make_isolated(vec![c1], vec!["example.com".to_string()], false);

            assert!(isolated.read(b"cred1").is_err());
            assert!(
                isolated
                    .read_first(CredentialFilter::ByRp("example.com".into()))
                    .is_err()
            );
            assert!(isolated.read_first(CredentialFilter::None).is_err());
            assert_eq!(isolated.count_credentials(), 0);
        }

        #[test]
        fn test_isolated_register_scope_no_registration_allowed() {
            let (mut isolated, scope) =
                make_isolated(vec![], vec!["example.com".to_string()], false);

            let _guard = scope.activate_register().unwrap();

            let new_cred = make_test_cred(b"new-cred", "example.com", b"user1", 0);
            let cred_ref = cred_ref_to_soft_fido2(&new_cred);
            let result = isolated.write(cred_ref);
            assert!(result.is_err());
        }

        #[test]
        fn test_isolated_register_scope_creates_credential() {
            let (mut isolated, scope) =
                make_isolated(vec![], vec!["example.com".to_string()], true);

            let _guard = scope.activate_register().unwrap();

            let new_cred = make_test_cred(b"new-cred", "example.com", b"user1", 0);
            let cred_ref = cred_ref_to_soft_fido2(&new_cred);
            let result = isolated.write(cred_ref);
            assert!(result.is_ok());
        }

        #[test]
        fn test_isolated_register_scope_denied_for_wrong_rp() {
            let (mut isolated, scope) =
                make_isolated(vec![], vec!["example.com".to_string()], true);

            let _guard = scope.activate_register().unwrap();

            let new_cred = make_test_cred(b"new-cred", "evil.com", b"user1", 0);
            let cred_ref = cred_ref_to_soft_fido2(&new_cred);
            let result = isolated.write(cred_ref);
            assert!(result.is_err());
        }

        #[test]
        fn test_isolated_register_scope_binds_exact_rp() {
            let (mut isolated, scope) = make_isolated(
                vec![],
                vec!["example.com".to_string(), "other.example".to_string()],
                true,
            );
            let _guard = scope.activate_register_for_rp("example.com").unwrap();

            let other_credential = make_test_cred(b"other-cred", "other.example", b"user1", 0);

            assert!(
                isolated
                    .write(cred_ref_to_soft_fido2(&other_credential))
                    .is_err()
            );
        }

        #[test]
        fn test_isolated_auth_scope_returns_exact_credential() {
            let c1 = make_test_cred(b"cred1", "example.com", b"user1", 5);
            let c2 = make_test_cred(b"cred2", "example.com", b"user2", 0);
            let (mut isolated, scope) =
                make_isolated(vec![c1, c2], vec!["example.com".to_string()], false);

            let cred_ref = cred_ref_for(b"cred1");
            let _guard = scope.activate_authenticate(cred_ref).unwrap();

            let result = isolated.read_first(CredentialFilter::ByRp("example.com".into()));
            assert!(result.is_ok());
            assert_eq!(result.unwrap().id, b"cred1");

            assert!(isolated.read_next().is_err());
        }

        #[test]
        fn test_isolated_auth_scope_hides_second_credential() {
            let c1 = make_test_cred(b"cred1", "example.com", b"user1", 0);
            let c2 = make_test_cred(b"cred2", "example.com", b"user2", 0);
            let (mut isolated, scope) =
                make_isolated(vec![c1, c2], vec!["example.com".to_string()], false);

            let cred_ref = cred_ref_for(b"cred1");
            let _guard = scope.activate_authenticate(cred_ref).unwrap();

            assert!(isolated.read(b"cred2").is_err());
            assert_eq!(isolated.count_credentials(), 1);
        }

        #[test]
        fn test_isolated_auth_scope_discovery_returns_exact_credential() {
            let c1 = make_test_cred(b"cred1", "example.com", b"user1", 0);
            let c2 = make_test_cred(b"cred2", "example.com", b"user2", 0);
            let (mut isolated, scope) =
                make_isolated(vec![c1, c2], vec!["example.com".to_string()], false);

            let cred_ref = cred_ref_for(b"cred1");
            let _guard = scope.activate_authenticate(cred_ref).unwrap();

            let result = isolated.read_first(CredentialFilter::None);
            assert!(result.is_ok());
            assert_eq!(result.unwrap().id, b"cred1");

            assert!(isolated.read_next().is_err());
        }

        #[test]
        fn test_isolated_auth_scope_wrong_ref_denied() {
            let c1 = make_test_cred(b"cred1", "example.com", b"user1", 0);
            let (mut isolated, scope) =
                make_isolated(vec![c1], vec!["example.com".to_string()], false);

            let cred_ref = cred_ref_for(b"cred1");
            let _guard = scope.activate_authenticate(cred_ref).unwrap();

            assert!(isolated.read(b"wrong-id").is_err());
        }

        #[test]
        fn test_isolated_auth_scope_write_monotonic_counter() {
            let c1 = make_test_cred(b"cred1", "example.com", b"user1", 5);
            let (mut isolated, scope) =
                make_isolated(vec![c1.clone()], vec!["example.com".to_string()], false);

            let cred_ref = cred_ref_for(b"cred1");
            let _guard = scope.activate_authenticate(cred_ref).unwrap();

            let mut updated = c1.clone();
            updated.sign_count = 6;
            let cred_ref_write = cred_ref_to_soft_fido2(&updated);
            let result = isolated.write(cred_ref_write);
            assert!(result.is_ok());
        }

        #[test]
        fn test_isolated_auth_scope_write_rejects_regressed_counter() {
            let c1 = make_test_cred(b"cred1", "example.com", b"user1", 10);
            let (mut isolated, scope) =
                make_isolated(vec![c1.clone()], vec!["example.com".to_string()], false);

            let cred_ref = cred_ref_for(b"cred1");
            let _guard = scope.activate_authenticate(cred_ref).unwrap();

            let mut regressed = c1.clone();
            regressed.sign_count = 5;
            let cred_ref_write = cred_ref_to_soft_fido2(&regressed);
            let result = isolated.write(cred_ref_write);
            assert!(result.is_err());
        }

        #[test]
        fn test_isolated_auth_scope_write_rejects_wrong_credential() {
            let c1 = make_test_cred(b"cred1", "example.com", b"user1", 5);
            let c2 = make_test_cred(b"cred2", "example.com", b"user2", 0);
            let (mut isolated, scope) = make_isolated(
                vec![c1.clone(), c2.clone()],
                vec!["example.com".to_string()],
                false,
            );

            let cred_ref = cred_ref_for(b"cred1");
            let _guard = scope.activate_authenticate(cred_ref).unwrap();

            let mut updated_c2 = c2.clone();
            updated_c2.sign_count = 1;
            let cred_ref_write = cred_ref_to_soft_fido2(&updated_c2);
            let result = isolated.write(cred_ref_write);
            assert!(result.is_err());
        }

        #[test]
        fn test_isolated_delete_always_denied() {
            let c1 = make_test_cred(b"cred1", "example.com", b"user1", 0);
            let (mut isolated, scope) =
                make_isolated(vec![c1], vec!["example.com".to_string()], false);

            let cred_ref = cred_ref_for(b"cred1");
            let _guard = scope.activate_authenticate(cred_ref).unwrap();

            assert!(isolated.delete(b"cred1").is_err());
        }

        #[test]
        fn test_isolated_register_scope_no_read() {
            let (mut isolated, scope) =
                make_isolated(vec![], vec!["example.com".to_string()], true);

            let _guard = scope.activate_register().unwrap();

            assert!(isolated.read(b"anything").is_err());
            assert!(
                isolated
                    .read_first(CredentialFilter::ByRp("example.com".into()))
                    .is_err()
            );
            assert!(isolated.read_first(CredentialFilter::None).is_err());
            assert_eq!(isolated.count_credentials(), 0);
        }

        #[test]
        fn test_isolated_guard_drop_clears_scope() {
            let c1 = make_test_cred(b"cred1", "example.com", b"user1", 0);
            let (mut isolated, scope) =
                make_isolated(vec![c1], vec!["example.com".to_string()], false);

            {
                let cred_ref = cred_ref_for(b"cred1");
                let _guard = scope.activate_authenticate(cred_ref).unwrap();
                assert!(isolated.read(b"cred1").is_ok());
            }

            assert!(isolated.read(b"cred1").is_err());
            assert_eq!(isolated.count_credentials(), 0);
        }

        #[test]
        fn test_isolated_action_binding_register() {
            let scope = CeremonyScope::new();
            let _guard = scope.activate_register().unwrap();

            assert_eq!(scope.active_action(), Some(CeremonyAction::Register));
            assert_eq!(scope.active_cred_ref(), None);
        }

        #[test]
        fn test_isolated_action_binding_authenticate() {
            let scope = CeremonyScope::new();
            let cred_ref = cred_ref_for(b"cred1");
            let _guard = scope.activate_authenticate(cred_ref.clone()).unwrap();

            assert_eq!(
                scope.active_action(),
                Some(CeremonyAction::Authenticate(cred_ref.clone()))
            );
            assert_eq!(scope.active_cred_ref(), Some(cred_ref));
        }

        #[test]
        fn test_isolated_register_then_auth_flow() {
            let (mut isolated, scope) =
                make_isolated(vec![], vec!["example.com".to_string()], true);

            {
                let _guard = scope.activate_register().unwrap();
                let new_cred = make_test_cred(b"new-cred", "example.com", b"user1", 0);
                let cred_ref = cred_ref_to_soft_fido2(&new_cred);
                isolated.write(cred_ref).unwrap();
            }

            isolated.build_index().unwrap();

            assert!(isolated.read(b"new-cred").is_err());
            assert_eq!(isolated.count_credentials(), 0);

            {
                let auth_ref = cred_ref_for(b"new-cred");
                let _guard = scope.activate_authenticate(auth_ref).unwrap();
                assert_eq!(isolated.count_credentials(), 1);
                let result = isolated.read_first(CredentialFilter::None);
                assert!(result.is_ok());
            }
        }

        #[test]
        fn test_isolated_wrong_action_denies_operations() {
            let c1 = make_test_cred(b"cred1", "example.com", b"user1", 0);
            let (mut isolated, scope) =
                make_isolated(vec![c1], vec!["example.com".to_string()], false);

            let _guard = scope.activate_register().unwrap();

            assert!(isolated.read(b"cred1").is_err());
            assert!(
                isolated
                    .read_first(CredentialFilter::ByRp("example.com".into()))
                    .is_err()
            );
            assert_eq!(isolated.count_credentials(), 0);

            let new_cred = make_test_cred(b"new-cred", "example.com", b"user1", 0);
            let cred_ref = cred_ref_to_soft_fido2(&new_cred);
            assert!(isolated.write(cred_ref).is_err());
        }
    }
}
