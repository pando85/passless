use crate::notification::show_verification_notification;
use crate::storage::{CredentialFilter, CredentialStorage};
use crate::util::bytes_to_hex;

use passless_core::config::SecurityConfig;

use soft_fido2::{
    Authenticator, AuthenticatorCallbacks, AuthenticatorConfig, AuthenticatorOptions, Credential,
    CredentialRef, CtapCommand, Result, UpResult, UvResult,
};

use std::sync::{Arc, Mutex};

use log::{debug, error, info};

/// Passless authenticator callbacks implementation
pub struct PasslessCallbacks<S: CredentialStorage> {
    storage: Arc<Mutex<S>>,
    security_config: SecurityConfig,
}

impl<S: CredentialStorage> PasslessCallbacks<S> {
    pub fn new(storage: Arc<Mutex<S>>, security_config: SecurityConfig) -> Self {
        Self {
            storage,
            security_config,
        }
    }
}

impl<S: CredentialStorage> AuthenticatorCallbacks for PasslessCallbacks<S> {
    fn request_up(&self, info: &str, user: Option<&str>, rp: &str) -> Result<UpResult> {
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

        // Check if user verification should be bypassed for this operation
        let should_verify = if is_registration {
            self.security_config.user_verification_registration
        } else {
            self.security_config.user_verification_authentication
        };

        // If backend handles verification (e.g., GPG) and not registration, skip notification
        if self.storage.lock().unwrap().disable_user_verification()
            && !is_registration
            && !should_verify
        {
            debug!("User verification handled by backend (e.g., GPG): {}", info);
            return Ok(UpResult::Accepted);
        }

        // If user verification is disabled for this operation type, auto-accept
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

        match show_verification_notification(info, Some(rp), user) {
            Ok(crate::notification::NotificationResult::Accepted) => Ok(UpResult::Accepted),
            Ok(crate::notification::NotificationResult::Denied) => Ok(UpResult::Denied),
            Err(e) => {
                error!("Failed to show notification: {}", e);
                Err(soft_fido2::Error::Other)
            }
        }
    }

    fn request_uv(&self, _info: &str, _user: Option<&str>, _rp: &str) -> Result<UvResult> {
        info!("User verification confirmed");
        Ok(UvResult::Accepted)
    }

    fn write_credential(
        &self,
        cred_id: &[u8],
        rp_id: &str,
        credential: &CredentialRef,
    ) -> Result<()> {
        info!("Storing credential for RP: {}", rp_id);
        debug!("Credential ID: {}", bytes_to_hex(cred_id));
        let mut storage = self.storage.lock().unwrap();
        storage.write(cred_id, rp_id, *credential)?;
        info!("Credential persisted successfully for RP: {}", rp_id);
        Ok(())
    }

    fn read_credential(&self, cred_id: &[u8], rp_id: &str) -> Result<Option<Credential>> {
        debug!(
            "Reading credential: rp={}, id={}",
            rp_id,
            bytes_to_hex(cred_id)
        );
        let mut storage = self.storage.lock().unwrap();

        match storage.read(cred_id, rp_id) {
            Ok(bytes) => {
                debug!("Credential found, deserializing");
                // Deserialize the credential from bytes
                match serde_cbor::from_slice::<Credential>(&bytes) {
                    Ok(cred) => {
                        debug!("Credential deserialized successfully");
                        Ok(Some(cred))
                    }
                    Err(e) => {
                        error!("Failed to deserialize credential: {}", e);
                        Err(soft_fido2::Error::Other)
                    }
                }
            }
            Err(_) => {
                debug!("Credential not found");
                Ok(None)
            }
        }
    }

    fn delete_credential(&self, cred_id: &[u8]) -> Result<()> {
        info!("Removing credential ID: {}", bytes_to_hex(cred_id));
        let mut storage = self.storage.lock().unwrap();
        storage.delete(cred_id)?;
        debug!("Credential removed");
        Ok(())
    }

    fn list_credentials(&self, rp_id: &str, _user_id: Option<&[u8]>) -> Result<Vec<Credential>> {
        info!("Listing credentials for RP: {}", rp_id);
        let mut storage = self.storage.lock().unwrap();

        let filter = CredentialFilter::ByRp(rp_id.to_string());

        let mut credentials = Vec::new();

        // Read first credential
        match storage.read_first(filter) {
            Ok(first_cred) => {
                info!(
                    "Found first credential for RP {}: id={}",
                    rp_id,
                    bytes_to_hex(&first_cred.id)
                );
                credentials.push(first_cred);

                // Read remaining credentials
                while let Ok(cred) = storage.read_next() {
                    info!("Found additional credential: id={}", bytes_to_hex(&cred.id));
                    credentials.push(cred);
                }
            }
            Err(e) => {
                info!("No credentials found for RP {}: {:?}", rp_id, e);
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
        let mut storage = self.storage.lock().unwrap();

        // Get all credentials
        let filter = CredentialFilter::None;
        let mut all_credentials = Vec::new();

        if let Ok(first_cred) = storage.read_first(filter) {
            all_credentials.push(first_cred);

            while let Ok(cred) = storage.read_next() {
                all_credentials.push(cred);
            }
        }

        // Group by RP ID and count
        use std::collections::HashMap;
        let mut rp_map: HashMap<String, (Option<String>, usize)> = HashMap::new();

        for cred in all_credentials {
            let entry = rp_map
                .entry(cred.rp.id.clone())
                .or_insert((cred.rp.name.clone(), 0));
            entry.1 += 1;
        }

        let result: Vec<(String, Option<String>, usize)> = rp_map
            .into_iter()
            .map(|(rp_id, (rp_name, count))| (rp_id, rp_name, count))
            .collect();

        debug!("Found {} relying parties", result.len());
        Ok(result)
    }

    fn credential_count(&self) -> Result<usize> {
        debug!("Counting total credentials");
        let storage = self.storage.lock().unwrap();
        let count = storage.count_credentials();
        debug!("Total credentials: {}", count);
        Ok(count)
    }
}

/// Main authenticator service
///
/// This service orchestrates the FIDO2 authenticator:
/// - Storage is injected through the CredentialStorage trait
/// - Handles CTAP requests and generates responses
pub struct AuthenticatorService<S: CredentialStorage> {
    /// The underlying soft_fido2 authenticator
    pub authenticator: Authenticator<PasslessCallbacks<S>>,
    /// Storage backend (injected dependency)
    pub storage: Arc<Mutex<S>>,
}

impl<S: CredentialStorage + 'static> AuthenticatorService<S> {
    /// Create a new authenticator service
    pub fn new(storage: S, security_config: SecurityConfig) -> Result<Self> {
        let options = AuthenticatorOptions {
            rk: true,                      // Resident keys (passkeys)
            up: true,                      // User presence
            uv: Some(true),                // User verification
            plat: true,                    // Platform authenticator
            client_pin: Some(true),        // Client PIN support
            pin_uv_auth_token: Some(true), // PIN UV auth token
            cred_mgmt: Some(true),         // Credential management enabled
            bio_enroll: None,
            large_blobs: None,
            ep: None,
            always_uv: Some(true),
            make_cred_uv_not_required: Some(true),
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
                CtapCommand::CredentialManagement, // Standard credential management (0x0a)
                CtapCommand::Selection,
            ])
            .max_credentials(100)
            .extensions(vec!["credProtect".to_string()])
            .firmware_version(0x0001)
            .constant_sign_count(security_config.constant_signature_counter)
            .build();

        let storage = Arc::new(Mutex::new(storage));
        let callbacks = PasslessCallbacks::new(storage.clone(), security_config);
        let authenticator = Authenticator::with_config(callbacks, config)?;

        Ok(Self {
            authenticator,
            storage,
        })
    }

    /// Process a CTAP request and generate a response
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

    /// Register a custom CTAP command handler
    ///
    /// This allows registering vendor-specific commands (0x40-0xFF range).
    /// Useful for compatibility with different authenticator variants.
    ///
    /// # Arguments
    ///
    /// * `command` - Command byte (0x40-0xFF vendor range)
    /// * `handler` - Handler function that processes the command
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

    #[test]
    fn test_service_creation() {
        let temp_dir = std::env::temp_dir().join("test_passless");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let storage = LocalStorageAdapter::new(temp_dir.clone()).unwrap();

        let security_config = SecurityConfig {
            check_mlock: false,
            disable_core_dumps: false,
            constant_signature_counter: false,
            user_verification_registration: true,
            user_verification_authentication: true,
        };

        let service = AuthenticatorService::new(storage, security_config);
        assert!(service.is_ok());

        // Cleanup
        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
