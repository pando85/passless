/// Custom credential management command handler
///
/// This module provides compatibility with the Yubikey credential management variant (0x41).
/// The standard credential management (0x0a) is handled by soft-fido2's built-in implementation,
use crate::authenticator::AuthenticatorService;
use crate::pin_storage::PinStorage;
use crate::storage::CredentialStorage;

use log::debug;

/// Command byte for custom credential management (0x41 Yubikey variant)
pub const CMD_CUSTOM_CREDENTIAL_MGMT: u8 = 0x41;

/// Register custom credential management command (0x41 Yubikey variant)
///
/// This registers a custom command handler that provides compatibility with the
/// Yubikey-style credential management command (0x41), which is functionally
/// equivalent to the standard credential management (0x0a).
///
/// # Arguments
///
/// * `service` - Mutable reference to the authenticator service
pub fn register_yubikey_credential_mgmt<S: CredentialStorage + 'static, P: PinStorage + 'static>(
    service: &mut AuthenticatorService<S, P>,
) {
    debug!("Registering Yubikey credential management command (0x41)");

    service.register_custom_command(CMD_CUSTOM_CREDENTIAL_MGMT, |request| {
        debug!(
            "Yubikey credential management (0x41) called with {} bytes: {:02x?}",
            request.len(),
            &request[..request.len().min(32)]
        );

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
        use passless_core::config::{PinConfig, SecurityConfig, UvConfig};

        let temp_dir = std::env::temp_dir().join("test_passless_custom");
        if let Err(e) = std::fs::create_dir_all(&temp_dir) {
            panic!("Failed to create temp directory: {}", e);
        }
        let storage = match LocalStorageAdapter::new(temp_dir.clone()) {
            Ok(s) => s,
            Err(e) => panic!("Failed to create local storage: {}", e),
        };

        let service = AuthenticatorService::new(
            storage,
            SecurityConfig::default(),
            PinConfig::default(),
            UvConfig::default(),
        );
        assert!(service.is_ok(), "Service creation should succeed");

        register_yubikey_credential_mgmt(&mut service.unwrap());

        // Cleanup
        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
