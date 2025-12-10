//! Storage implementations for credentials
//!
//! This module provides storage backends for FIDO2 credentials.

pub mod credential;
pub mod index;
pub mod local;
pub mod pass;
pub mod tpm;

// Internal credential type with controlled serialization
#[allow(unused_imports)]
pub(crate) use credential::Credential;
pub use local::LocalStorageAdapter;
pub use pass::PassStorageAdapter;
pub use tpm::TpmStorageAdapter;

use soft_fido2::Result;

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

    /// Update user information for a credential
    #[allow(dead_code)]
    fn update_user_info(
        &mut self,
        id: &[u8],
        user_name: Option<&str>,
        display_name: Option<&str>,
    ) -> Result<()>;

    /// Get all user names for a given relying party
    #[allow(dead_code)]
    fn select_users(&self, rp_id: &str) -> Vec<String>;

    /// Count total number of stored credentials
    fn count_credentials(&self) -> usize;

    /// Get all relying parties that have credentials
    #[allow(dead_code)]
    fn get_relying_parties(&self) -> Result<Vec<soft_fido2_ctap::types::RelyingParty>>;

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
