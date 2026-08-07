//! Complete credential backend handles for agent WebAuthn operations.
//!
//! Storage, key-provider selection, PIN state, and operation serialization are
//! deliberately carried as one unit. A handler must never reopen a backend or
//! substitute a software provider after the mode has selected this handle.
//! Same-user handles intentionally point at the human backend; isolated handles
//! intentionally point at a profile-owned backend.

use std::sync::{Arc, Mutex};

use passless_core::agent::ProfileId;
use soft_fido2::CredentialKeyProvider;

use crate::pin_storage::PinStorage;
use crate::storage::CredentialStorage;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialNamespace {
    Human,
    Isolated(ProfileId),
}

#[derive(Clone)]
pub struct CredentialBackendHandle {
    pub namespace: CredentialNamespace,
    pub credential_storage: Arc<Mutex<Box<dyn CredentialStorage>>>,
    pub pin_storage: Arc<Mutex<Box<dyn PinStorage>>>,
    pub key_provider: Arc<dyn CredentialKeyProvider + Send + Sync>,
    pub operation_lock: Arc<Mutex<()>>,
}

impl core::fmt::Debug for CredentialBackendHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CredentialBackendHandle")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl CredentialBackendHandle {
    pub fn human(
        credential_storage: Arc<Mutex<Box<dyn CredentialStorage>>>,
        pin_storage: Arc<Mutex<Box<dyn PinStorage>>>,
        key_provider: Arc<dyn CredentialKeyProvider + Send + Sync>,
        operation_lock: Arc<Mutex<()>>,
    ) -> Self {
        Self {
            namespace: CredentialNamespace::Human,
            credential_storage,
            pin_storage,
            key_provider,
            operation_lock,
        }
    }

    pub fn isolated(
        profile_id: ProfileId,
        credential_storage: Arc<Mutex<Box<dyn CredentialStorage>>>,
        pin_storage: Arc<Mutex<Box<dyn PinStorage>>>,
        key_provider: Arc<dyn CredentialKeyProvider + Send + Sync>,
        operation_lock: Arc<Mutex<()>>,
    ) -> Self {
        Self {
            namespace: CredentialNamespace::Isolated(profile_id),
            credential_storage,
            pin_storage,
            key_provider,
            operation_lock,
        }
    }

    pub fn is_human(&self) -> bool {
        matches!(self.namespace, CredentialNamespace::Human)
    }
}
