//! HMAC auth session with parameter encryption for sensitive TPM operations

use soft_fido2::Result;

use log::error;
use tss_esapi::Context;
use tss_esapi::constants::SessionType;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::SymmetricDefinitionObject;

/// Execute a closure with an HMAC auth session using AES-128-CFB parameter encryption.
///
/// This mirrors the legacy seal path's session setup to encrypt sensitive parameters
/// (key material, secrets) on the wire to the TPM.
pub fn execute_with_encrypted_session<F, T>(context: &mut Context, f: F) -> Result<T>
where
    F: FnOnce(&mut Context) -> Result<T>,
{
    let session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinitionObject::AES_128_CFB.into(),
            HashingAlgorithm::Sha256,
        )
        .map_err(|e| {
            error!("Failed to start HMAC auth session: {}", e);
            soft_fido2::Error::Other
        })?
        .ok_or_else(|| {
            error!("HMAC auth session returned None");
            soft_fido2::Error::Other
        })?;

    let saved_sessions = context.sessions();
    context.set_sessions((Some(session), None, None));

    let result = f(context);

    context.set_sessions(saved_sessions);

    if let AuthSession::HmacSession(
        tss_esapi::interface_types::session_handles::HmacSession::HmacSession {
            session_handle,
            ..
        },
    ) = session
    {
        let _ = context.flush_context(session_handle.into());
    }

    result
}
