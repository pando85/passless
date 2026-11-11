//! Storage implementations for credentials
//!
//! This module provides storage backends for FIDO2 credentials.

pub mod credential;
pub mod index;
pub mod local;
pub mod pass;
mod pass_refresh;
pub mod rp_id;
#[cfg(feature = "tpm")]
pub mod tpm;

// Internal credential type with controlled serialization
#[allow(unused_imports)]
pub(crate) use credential::Credential;
pub use local::LocalStorageAdapter;
pub use pass_refresh::PassStorageAdapter;
pub use rp_id::ValidatedRpId;
#[cfg(feature = "tpm")]
pub use tpm::TpmStorageAdapter;

use soft_fido2::Result;

use std::sync::{Mutex, MutexGuard};

use log::warn;

/// Lock the credential storage of the human authenticator, recovering a poisoned lock.
///
/// Same-user agent ceremonies share this mutex (ADR 0014 invariant 3), so a panic in one of them
/// must not disable the human path for the rest of the daemon's life (invariant 23). Release
/// builds abort on panic, so this matters for debug and test builds and for any future unwind
/// build; agent code under this lock is kept panic-free as well.
///
/// Recovering is sound because the guarded adapter is never left half-updated in a way that
/// matters:
/// - Agent ceremonies touch the adapter only through `CredentialStorage` methods. A panic in agent
///   code (selection, audit reservation, re-check) leaves it between two complete calls, a state
///   the human path itself produces; an iteration cursor left mid-way is reset by the next
///   `read_first`.
/// - Inside an adapter method (code the human path runs too), a credential file is written
///   atomically (temporary file and rename, or GnuPG writing the target) before the in-memory
///   index is updated and the cached entry dropped: memory is a cache of the files, never the
///   other way round. A panic before the rename changes nothing; after it, at worst the index
///   lacks the new credential until the next start, or a cached copy of the previous contents
///   lives until `CREDENTIAL_CACHE_TTL` expires. A pass Git-sync bracket left open defers the Git
///   commit. None of these corrupts a credential or a key, or grants anything.
pub fn lock_shared_storage<S: ?Sized>(storage: &Mutex<S>) -> MutexGuard<'_, S> {
    storage.lock().unwrap_or_else(|poisoned| {
        warn!("credential storage lock was poisoned by a panicked thread; recovering");
        storage.clear_poison();
        poisoned.into_inner()
    })
}

/// Filter criteria for reading credentials
#[derive(Debug, Clone)]
pub enum CredentialFilter {
    /// No filter - return all credentials
    None,
    /// Filter by credential ID
    #[allow(dead_code)]
    ById(Vec<u8>),
    /// Filter by relying party ID
    ByRp(String),
    /// Filter by relying party ID hash
    #[allow(dead_code)]
    ByHash([u8; 32]),
}

/// Relying-party metadata that can be discovered without loading secret credential data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelyingPartyMetadata {
    pub id: String,
    pub name: Option<String>,
    pub credential_count: usize,
}

/// Trait defining the storage interface for credentials
///
/// Any storage backend must implement this trait.
pub trait CredentialStorage: Send + Sync {
    /// Start a new iteration and return the first matching credential
    fn read_first(&mut self, filter: CredentialFilter) -> Result<soft_fido2::Credential>;

    /// Continue the current iteration and return the next credential
    fn read_next(&mut self) -> Result<soft_fido2::Credential>;

    /// Read a specific credential by ID and RP
    fn read(&mut self, id: &[u8]) -> Result<soft_fido2::Credential>;

    /// Store a new credential
    fn write(&mut self, cred: soft_fido2::CredentialRef) -> Result<()>;

    /// Delete a credential by ID
    fn delete(&mut self, id: &[u8]) -> Result<()>;

    /// Enumerate relying parties.
    ///
    /// Backends with an index should override this method so discovery does not
    /// require loading or decrypting every credential. The compatibility default
    /// preserves the historical behavior for backends without metadata indexes.
    fn list_relying_parties(&mut self) -> Result<Vec<RelyingPartyMetadata>> {
        let mut credentials = Vec::new();
        if let Ok(first) = self.read_first(CredentialFilter::None) {
            credentials.push(first);
            while let Ok(credential) = self.read_next() {
                credentials.push(credential);
            }
        }

        let mut by_rp: std::collections::HashMap<String, (Option<String>, usize)> =
            std::collections::HashMap::new();
        for credential in credentials {
            let entry = by_rp
                .entry(credential.rp.id.clone())
                .or_insert((credential.rp.name.clone(), 0));
            entry.1 += 1;
        }

        let mut result: Vec<_> = by_rp
            .into_iter()
            .map(|(id, (name, credential_count))| RelyingPartyMetadata {
                id,
                name,
                credential_count,
            })
            .collect();
        result.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(result)
    }

    /// Count total number of stored credentials
    fn count_credentials(&self) -> usize;

    /// Check if user verification should be disabled for this backend
    ///
    /// Some backends (like pass) don't support user verification.
    /// The default implementation returns false (UV enabled).
    ///
    /// # Returns
    ///
    /// true if UV should be disabled, false otherwise
    fn disable_user_verification(&self) -> bool {
        false
    }

    /// Begin a logical authenticator operation.
    ///
    /// Backends may use this boundary to batch persistence/synchronization work.
    fn begin_operation(&mut self) -> Result<()> {
        Ok(())
    }

    /// End a logical authenticator operation.
    fn end_operation(&mut self) -> Result<()> {
        Ok(())
    }

    /// Cleanup expired cache entries (if caching is supported)
    ///
    /// This method should be called periodically to ensure cached credentials
    /// don't remain in memory beyond their TTL, even when idle.
    ///
    /// Default implementation does nothing (for backends without caching).
    ///
    /// # Security
    ///
    /// Important for security: ensures sensitive data is removed promptly.
    fn cleanup_expired_cache(&mut self) {
        // Default: no-op for backends that don't cache
    }
}

impl CredentialStorage for Box<dyn CredentialStorage> {
    fn read_first(&mut self, filter: CredentialFilter) -> Result<soft_fido2::Credential> {
        (**self).read_first(filter)
    }

    fn read_next(&mut self) -> Result<soft_fido2::Credential> {
        (**self).read_next()
    }

    fn read(&mut self, id: &[u8]) -> Result<soft_fido2::Credential> {
        (**self).read(id)
    }

    fn write(&mut self, cred: soft_fido2::CredentialRef) -> Result<()> {
        (**self).write(cred)
    }

    fn delete(&mut self, id: &[u8]) -> Result<()> {
        (**self).delete(id)
    }

    fn list_relying_parties(&mut self) -> Result<Vec<RelyingPartyMetadata>> {
        (**self).list_relying_parties()
    }

    fn count_credentials(&self) -> usize {
        (**self).count_credentials()
    }

    fn disable_user_verification(&self) -> bool {
        (**self).disable_user_verification()
    }

    fn begin_operation(&mut self) -> Result<()> {
        (**self).begin_operation()
    }

    fn end_operation(&mut self) -> Result<()> {
        (**self).end_operation()
    }

    fn cleanup_expired_cache(&mut self) {
        (**self).cleanup_expired_cache()
    }
}
