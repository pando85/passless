use crate::config::build_authenticator_config;
use crate::notification::show_verification_notification;
use crate::storage::CredentialStorage;

use keylib::{
    Authenticator, CallbacksBuilder, Credential, CredentialRef, Result, UpResult, UvResult,
};

use std::sync::{Arc, Mutex};

use log::{debug, error, info};
/// Main authenticator service
///
/// This service orchestrates the FIDO2 authenticator:
/// - Storage is injected through the CredentialStorage trait
/// - Handles CTAP requests and generates responses
pub struct AuthenticatorService<S: CredentialStorage> {
    /// The underlying keylib authenticator
    authenticator: Authenticator,
    /// Storage backend (injected dependency)
    storage: Arc<Mutex<S>>,
}

impl<S: CredentialStorage + 'static> AuthenticatorService<S> {
    /// Create a new authenticator service
    ///
    /// # Arguments
    ///
    /// * `storage` - The storage backend implementation
    ///
    /// # Returns
    ///
    /// A new AuthenticatorService instance
    pub fn new(storage: S) -> Result<Self> {
        let storage = Arc::new(Mutex::new(storage));
        let storage_for_callbacks = storage.clone();
        let storage_for_config = storage.clone();

        // Build callbacks
        let callbacks = Self::build_callbacks(storage_for_callbacks)?;

        // Build authenticator with custom commands that use storage
        let auth_config = build_authenticator_config(storage_for_config);
        let authenticator = Authenticator::with_config(callbacks, auth_config)?;

        Ok(Self {
            authenticator,
            storage,
        })
    }

    /// Process a CTAP request and generate a response
    ///
    /// # Arguments
    ///
    /// * `request` - The CTAP request data
    /// * `response_buffer` - Buffer to write the response into
    ///
    /// # Returns
    ///
    /// Ok(()) on success or an error
    pub fn handle(&mut self, request: &[u8], response_buffer: &mut Vec<u8>) -> Result<()> {
        self.authenticator.handle(request, response_buffer)?;
        Ok(())
    }

    /// Get storage information
    pub fn storage_info(&self) -> String {
        let storage = self.storage.lock().unwrap();
        format!("Credentials in storage: {}", storage.count_credentials())
    }

    /// Cleanup expired cache entries from storage
    ///
    /// This method should be called periodically (e.g., every few seconds)
    /// to ensure cached credentials don't remain in memory beyond their TTL,
    /// even when the authenticator is idle.
    ///
    /// # Security
    ///
    /// Critical for security: ensures sensitive credential data is removed
    /// from memory promptly, minimizing exposure time.
    pub fn cleanup_expired_cache(&self) {
        if let Ok(mut storage) = self.storage.lock() {
            storage.cleanup_expired_cache();
        }
    }

    /// Build callbacks for the authenticator
    fn build_callbacks(storage: Arc<Mutex<S>>) -> Result<keylib::Callbacks> {
        let storage_for_up = storage.clone();

        let up_callback = Arc::new(
            move |info: &str, user: Option<&str>, rp: Option<&str>| -> Result<UpResult> {
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

                if storage_for_up.lock().unwrap().disable_user_verification() && !is_registration {
                    debug!("User verification handled by backend (e.g., GPG): {}", info);
                    return Ok(UpResult::Accepted);
                }

                match show_verification_notification(
                    info.split(":").next().unwrap_or("Unknown"),
                    rp,
                    user,
                ) {
                    Ok(crate::notification::NotificationResult::Accepted) => Ok(UpResult::Accepted),
                    Ok(crate::notification::NotificationResult::Denied) => Ok(UpResult::Denied),
                    Err(e) => {
                        error!("Failed to show notification: {}", e);
                        Err(keylib::Error::Other)
                    }
                }
            },
        );

        let uv_callback = Arc::new(
            |_info: &str, _user: Option<&str>, _rp: Option<&str>| -> Result<UvResult> {
                info!("User verification confirmed");
                Ok(UvResult::Accepted)
            },
        );

        let storage_for_select = storage.clone();
        let select_callback = Arc::new(move |rp_id: &str| -> Result<Vec<String>> {
            let storage = storage_for_select.lock().unwrap();
            let users = storage.select_users(rp_id);
            debug!("Found {} users for RP: {}", users.len(), rp_id);
            Ok(users)
        });

        let storage_for_read = storage.clone();
        let read_callback = Arc::new(move |id: &str, rp: &str| -> Result<Vec<u8>> {
            debug!("Reading credential: rp={}, id={}", rp, id);
            let mut storage = storage_for_read.lock().unwrap();
            match storage.read(id, rp) {
                Ok(bytes) => {
                    debug!("Credential found");
                    Ok(bytes)
                }
                Err(e) => {
                    debug!("Credential not found");
                    Err(e)
                }
            }
        });

        let storage_for_write = storage.clone();
        let write_callback = Arc::new(
            move |id: &str, rp: &str, cred_ref: CredentialRef| -> Result<()> {
                info!("Storing credential for RP: {}", rp);
                let mut storage = storage_for_write.lock().unwrap();
                storage.write(id, rp, cred_ref)?;
                debug!("Credential persisted");
                Ok(())
            },
        );

        let storage_for_delete = storage.clone();
        let delete_callback = Arc::new(move |id: &str| -> Result<()> {
            info!("Removing credential ID: {}", id);
            let mut storage = storage_for_delete.lock().unwrap();
            storage.delete(id)?;
            debug!("Credential removed");
            Ok(())
        });

        let storage_for_read_first = storage.clone();
        let read_first_callback = Arc::new(
            move |id: Option<&str>,
                  rp: Option<&str>,
                  hash: Option<[u8; 32]>|
                  -> Result<Credential> {
                debug!("Read first: id={:?}, rp={:?}", id, rp);
                let mut storage = storage_for_read_first.lock().unwrap();

                use crate::storage::CredentialFilter;
                let filter = if let Some(id) = id {
                    CredentialFilter::ById(id.as_bytes().to_vec())
                } else if let Some(rp) = rp {
                    CredentialFilter::ByRp(rp.to_string())
                } else if let Some(hash) = hash {
                    CredentialFilter::ByHash(hash)
                } else {
                    CredentialFilter::None
                };

                let cred = storage.read_first(filter)?;
                debug!(
                    "Found credential: rp={}, user={}",
                    cred.rp.id,
                    String::from_utf8_lossy(&cred.user.id)
                );
                Ok(cred)
            },
        );

        let storage_for_read_next = storage.clone();
        let read_next_callback = Arc::new(move || -> Result<Credential> {
            debug!("Getting next credential");
            let mut storage = storage_for_read_next.lock().unwrap();
            let cred = storage.read_next()?;
            debug!(
                "Found next credential: rp={}, user={}",
                cred.rp.id,
                String::from_utf8_lossy(&cred.user.id)
            );
            Ok(cred)
        });

        Ok(CallbacksBuilder::new()
            .up(up_callback)
            .uv(uv_callback)
            .select(select_callback)
            .read(read_callback)
            .write(write_callback)
            .delete(delete_callback)
            .read_first(read_first_callback)
            .read_next(read_next_callback)
            .build())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::LocalStorageAdapter;

    #[test]
    fn test_service_creation() {
        let temp_dir = std::env::temp_dir().join("test_passless");
        let storage = LocalStorageAdapter::new(temp_dir.clone()).unwrap();

        let service = AuthenticatorService::new(storage);
        assert!(service.is_ok());

        // Cleanup
        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
