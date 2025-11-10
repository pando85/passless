use crate::commands::credential_mgmt;
use crate::storage::CredentialStorage;

use keylib::CustomCommand;

use std::sync::Arc;

use log::{debug, error};

/// Command byte for standard credential management (0x0a)
pub const CMD_CREDENTIAL_MGMT: u8 = 0x0a;

/// Command byte for custom credential management (0x41 - Yubikey variant)
pub const CMD_CUSTOM_CREDENTIAL_MGMT: u8 = 0x41;

/// Create a credential management command handler (works for both 0x0a and 0x41)
///
/// This creates a handler that bridges the CTAP command interface to the
/// credential management implementation.
///
/// # Arguments
///
/// * `cmd_byte` - The command byte (0x0a or 0x41)
/// * `storage_ptr` - Raw pointer to the storage backend (will be cast back to Arc<Mutex<S>>)
///
/// # Safety
///
/// The storage_ptr must be a valid pointer to Arc<Mutex<S>> where S: CredentialStorage
pub fn create_credential_mgmt_command<S: CredentialStorage + 'static>(
    cmd_byte: u8,
    storage: std::sync::Arc<std::sync::Mutex<S>>,
) -> CustomCommand {
    let handler = Arc::new(
        move |_auth: *mut std::ffi::c_void, request: &[u8], response: &mut [u8]| -> usize {
            log::info!(
                "🔧 Custom handler 0x{:02x} called with {} bytes, request: {:02x?}",
                cmd_byte,
                request.len(),
                &request[..request.len().min(32)]
            );

            // Check minimum request size
            if request.is_empty() {
                error!("Credential management: Empty request");
                return 0; // Error: return 0
            }

            // Lock storage for the duration of this call
            let storage_guard = match storage.lock() {
                Ok(guard) => guard,
                Err(e) => {
                    error!("Failed to lock storage: {}", e);
                    return 0; // Error: return 0
                }
            };

            // Call the credential management handler
            match credential_mgmt::authenticator_credential_management(request, &*storage_guard) {
                Ok(response_data) => {
                    // Check if response buffer is large enough (NO status byte, just CBOR data)
                    if response.len() < response_data.len() {
                        error!(
                            "Response buffer too small: need {}, have {}",
                            response_data.len(),
                            response.len()
                        );
                        return 0; // Error: return 0
                    }

                    // Success: write CBOR data directly (Zig trampoline handles status code)
                    response[..response_data.len()].copy_from_slice(&response_data);
                    debug!(
                        "Credential management 0x{:02x} completed successfully, {} bytes CBOR data, response: {:02x?}",
                        cmd_byte,
                        response_data.len(),
                        &response_data[..response_data.len().min(64)]
                    );
                    response_data.len()
                }
                Err(e) => {
                    error!("Credential management error: {:?}", e);
                    0 // Error: return 0
                }
            }
        },
    );

    CustomCommand::new(cmd_byte, handler)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::local::LocalStorageAdapter;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_custom_command_creation() {
        let storage = Arc::new(Mutex::new(
            LocalStorageAdapter::new(PathBuf::from("/tmp/test_storage")).unwrap(),
        ));
        let cmd = create_credential_mgmt_command(CMD_CUSTOM_CREDENTIAL_MGMT, storage);
        assert_eq!(cmd.cmd, CMD_CUSTOM_CREDENTIAL_MGMT);
    }

    #[test]
    fn test_standard_command_creation() {
        let storage = Arc::new(Mutex::new(
            LocalStorageAdapter::new(PathBuf::from("/tmp/test_storage")).unwrap(),
        ));
        let cmd = create_credential_mgmt_command(CMD_CREDENTIAL_MGMT, storage);
        assert_eq!(cmd.cmd, CMD_CREDENTIAL_MGMT);
    }

    #[test]
    fn test_custom_command_empty_request() {
        let storage = Arc::new(Mutex::new(
            LocalStorageAdapter::new(PathBuf::from("/tmp/test_storage")).unwrap(),
        ));
        let cmd = create_credential_mgmt_command(CMD_CUSTOM_CREDENTIAL_MGMT, storage);

        let request = vec![];
        let mut response = vec![0u8; 7609];

        let response_len = (cmd.handler)(std::ptr::null_mut(), &request, &mut response);

        // Should return 0 for error
        assert_eq!(response_len, 0);
    }
}
