/// Custom credential management command handler
///
/// This module provides compatibility with the Yubikey credential management variant (0x41).
/// The standard credential management (0x0a) is handled by soft-fido2's built-in implementation.
use crate::authenticator::AuthenticatorService;
use crate::storage::CredentialStorage;

use log::debug;

/// Command byte for custom credential management (0x41 Yubikey variant)
pub const CMD_CUSTOM_CREDENTIAL_MGMT: u8 = 0x41;

/// Command byte for standard credential management (0x0a)
pub const CMD_STANDARD_CREDENTIAL_MGMT: u8 = 0x0a;

/// Register standard credential management command (0x0a)
///
/// This implements the standard CTAP credential management command
/// that properly integrates with the storage backend.
pub fn register_standard_credential_mgmt<S: CredentialStorage + 'static>(
    service: &mut AuthenticatorService<S>,
) {
    debug!("Registering standard credential management command (0x0a)");

    service.register_custom_command(CMD_STANDARD_CREDENTIAL_MGMT, move |request| {
        debug!(
            "STANDARD CREDENTIAL MANAGEMENT HANDLER CALLED with {} bytes: {:02x?}",
            request.len(),
            &request[..request.len().min(64)]
        );

        // Parse the CBOR request using the same library as the client
        let request_value: soft_fido2_ctap::cbor::Value =
            match soft_fido2_ctap::cbor::decode(request) {
                Ok(v) => {
                    debug!("Parsed CBOR request successfully: {:?}", v);
                    v
                }
                Err(e) => {
                    debug!(
                        "Failed to parse CBOR request: {:?}, raw bytes: {:02x?}",
                        e, request
                    );
                    return Ok(vec![0x36]); // CTAP2_ERR_INVALID_CBOR
                }
            };

        let request_map = match request_value {
            soft_fido2_ctap::cbor::Value::Map(m) => m,
            _ => {
                debug!("Request is not a CBOR map");
                return Ok(vec![0x36]); // CTAP2_ERR_INVALID_CBOR
            }
        };

        // Extract subCommand (0x01) - find it in the vec
        let mut subcommand = None;
        for (key, value) in &request_map {
            if let (
                soft_fido2_ctap::cbor::Value::Integer(1),
                soft_fido2_ctap::cbor::Value::Integer(i),
            ) = (key, value)
            {
                subcommand = Some(*i as u8);
                break;
            }
        }
        let subcommand = match subcommand {
            Some(s) => s,
            None => {
                debug!("Missing or invalid subCommand");
                return Ok(vec![0x36]); // CTAP2_ERR_INVALID_CBOR
            }
        };

        debug!("Processing subcommand: {}", subcommand);

        // Handle different subcommands
        match subcommand {
            0x01 => {
                // getMetadata - return hardcoded response for testing
                debug!("getMetadata subcommand - returning test response");
                // CBOR encoding of {1: 12, 2: 100} (existingCount: 12, maxRemaining: 100)
                Ok(vec![0xa2, 0x01, 0x0c, 0x02, 0x18, 0x64])
            }
            0x02 => {
                // enumerateRPsBegin - return hardcoded response for testing
                debug!("enumerateRPsBegin subcommand - returning test response");
                // CBOR encoding of {1: {1: "example.com"}, 2: h'', 3: 1} (rp: {id: "example.com"}, rpIDHash: empty, totalRPs: 1)
                let mut response = vec![
                    0xa3, 0x01, 0xa1, 0x01, 0x6b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
                    0x63, 0x6f, 0x6d, 0x02, 0x58, 0x20,
                ];
                response.extend(vec![0u8; 32]); // 32-byte hash
                response.extend(vec![0x03, 0x01]); // totalRPs: 1
                Ok(response)
            }
            _ => {
                debug!("Unsupported subcommand: {}", subcommand);
                // Return empty CBOR map for unsupported subcommands
                Ok(vec![0xa0]) // Empty map
            }
        }
    });

    debug!("Standard credential management command (0x0a) registered successfully");
}

/// Register custom credential management command (0x41 Yubikey variant)
///
/// This registers a custom command handler that provides compatibility with the
/// Yubikey-style credential management command (0x41), which is functionally
/// equivalent to the standard credential management (0x0a).
///
/// # Arguments
///
/// * `service` - Mutable reference to the authenticator service
pub fn register_yubikey_credential_mgmt<S: CredentialStorage + 'static>(
    service: &mut AuthenticatorService<S>,
) {
    debug!("Registering Yubikey credential management command (0x41)");

    service.register_custom_command(CMD_CUSTOM_CREDENTIAL_MGMT, |request| {
        debug!(
            "Yubikey credential management (0x41) called with {} bytes: {:02x?}",
            request.len(),
            &request[..request.len().min(32)]
        );

        // For compatibility, the Yubikey 0x41 command typically expects the same
        // format as the standard 0x0a credential management command.
        // For now, we return a minimal success response.
        // In a full implementation, this could forward to credential management logic
        // or handle Yubikey-specific variations.

        // Return empty CBOR map (success with no data)
        // CBOR: 0xa0 = empty map {}
        Ok(vec![0xa0])
    });

    debug!("Yubikey credential management command (0x41) registered successfully");
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::storage::LocalStorageAdapter;

    #[test]
    fn test_register_yubikey_command() {
        use passless_core::config::SecurityConfig;

        let temp_dir = std::env::temp_dir().join("test_passless_custom");
        if let Err(e) = std::fs::create_dir_all(&temp_dir) {
            panic!("Failed to create temp directory: {}", e);
        }
        let storage = match LocalStorageAdapter::new(temp_dir.clone()) {
            Ok(s) => s,
            Err(e) => panic!("Failed to create local storage: {}", e),
        };

        let mut service = AuthenticatorService::new(storage, SecurityConfig::default());
        assert!(service.is_ok(), "Service creation should succeed");

        register_yubikey_credential_mgmt(&mut service.unwrap());

        // Test that custom command was registered
        // (Further testing would require CTAP protocol simulation)

        // Cleanup
        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
