//! Storage implementations for credentials
//!
//! This module provides storage backends for FIDO2 credentials.

pub mod local;
pub mod pass;

use keylib::credential::RelyingParty;
use keylib::{Credential, CredentialRef, Result};

pub use local::LocalStorageAdapter;
pub use pass::{GpgBackend, PassStorageAdapter};

/// Filter criteria for reading credentials
#[derive(Debug, Clone)]
pub enum CredentialFilter {
    /// No filter - return all credentials
    None,
    /// Filter by credential ID
    ById(Vec<u8>),
    /// Filter by relying party ID
    ByRp(String),
    /// Filter by relying party ID hash
    ByHash([u8; 32]),
}

/// Trait defining the storage interface for credentials
///
/// Any storage backend must implement this trait.
pub trait CredentialStorage: Send + Sync {
    /// Start a new iteration and return the first matching credential
    ///
    /// # Arguments
    ///
    /// * `filter` - Filter criteria to apply
    ///
    /// # Returns
    ///
    /// The first matching credential or an error if none found
    fn read_first(&mut self, filter: CredentialFilter) -> Result<Credential>;

    /// Continue the current iteration and return the next credential
    ///
    /// # Returns
    ///
    /// The next matching credential or an error if no more credentials
    fn read_next(&mut self) -> Result<Credential>;

    /// Read a specific credential by ID and RP
    ///
    /// # Arguments
    ///
    /// * `id` - The credential ID
    /// * `rp` - The relying party ID
    ///
    /// # Returns
    ///
    /// The credential bytes or an error
    fn read(&mut self, id: &str, rp: &str) -> Result<Vec<u8>>;

    /// Store a new credential
    ///
    /// # Arguments
    ///
    /// * `id` - The credential ID
    /// * `rp` - The relying party ID
    /// * `cred` - The credential reference to store
    ///
    /// # Returns
    ///
    /// Ok(()) on success or an error
    fn write(&mut self, id: &str, rp: &str, cred: CredentialRef) -> Result<()>;

    /// Delete a credential by ID
    ///
    /// # Arguments
    ///
    /// * `id` - The credential ID to delete
    ///
    /// # Returns
    ///
    /// Ok(()) on success or an error
    fn delete(&mut self, id: &str) -> Result<()>;

    /// Get all user names for a given relying party
    ///
    /// # Arguments
    ///
    /// * `rp_id` - The relying party ID
    ///
    /// # Returns
    ///
    /// Vector of user names
    fn select_users(&self, rp_id: &str) -> Vec<String>;

    /// Count total number of stored credentials
    ///
    /// # Returns
    ///
    /// The number of credentials in storage
    fn count_credentials(&self) -> usize;

    /// Get all relying parties that have credentials
    ///
    /// # Returns
    ///
    /// Vector of relying party IDs
    fn get_relying_parties(&self) -> Result<Vec<RelyingParty>>;

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
