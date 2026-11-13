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
///   atomically before the in-memory index is updated: `local` and `tpm` write a temporary file
///   and rename it (`util::atomic_write_in_dir`), and `pass` has GnuPG encrypt to a temporary file
///   in the same directory that is fsynced and renamed over the target
///   (`pass::encrypt_with_gnupg_binary`; GnuPG's own `--output <target>` truncates in place and is
///   not used on the target). The index is memory built from the files, never the other way round.
///   A panic before the rename changes nothing; after it, at worst the index lacks the new
///   credential until the next start. The `pass` and `tpm` backends also cache decrypted
///   credentials (the `local` backend has no cache): a panic after the rename can leave a cached
///   copy of the previous contents until `CREDENTIAL_CACHE_TTL` expires. None of these corrupts
///   a credential or a key, or grants anything.
/// - The `pass` Git-sync coordinator ends a one-call (implicit) operation from a drop guard, so a
///   panic cannot leave its depth counter raised, and it recovers its own poisoned lock. A panic
///   inside the human path's explicit operation bracket (`main.rs`, `handle_command`) is not
///   unwound that way; it only matters for unwind builds, since release builds abort.
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

    /// How many credentials the store holds for exactly `rp_id`, when the backend can tell
    /// without decrypting or unsealing anything (ADR 0014 amendment section 5.2).
    ///
    /// The count is shown to the human in a registration prompt only. It must come from metadata
    /// such as the path index, never from [`Self::list_relying_parties`]'s default (which reads
    /// every credential) or any other decrypting read. A backend that cannot count that way keeps
    /// the default `None`, and the prompt then omits the count instead of showing 0.
    // Read by the agent registration path only.
    #[cfg_attr(not(feature = "agent"), allow(dead_code))]
    fn count_for_rp(&self, _rp_id: &str) -> Option<usize> {
        None
    }

    /// Every credential the store holds as `(RP ID, credential ID)`, when the backend can tell
    /// without decrypting or unsealing anything. The agent doctor checks locate profile pins
    /// (`credential_refs`) with it. Like [`Self::count_for_rp`] it must come from the path index
    /// only; a backend that cannot list that way keeps the default `None`.
    // Read by the agent doctor checks only.
    #[cfg_attr(not(feature = "agent"), allow(dead_code))]
    fn indexed_credentials(&self) -> Option<Vec<(String, Vec<u8>)>> {
        None
    }

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

    fn count_for_rp(&self, rp_id: &str) -> Option<usize> {
        (**self).count_for_rp(rp_id)
    }

    fn indexed_credentials(&self) -> Option<Vec<(String, Vec<u8>)>> {
        (**self).indexed_credentials()
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
