//! User Verification (UV) module for FIDO2 authenticator
//!
//! This module provides a pluggable user verification system with multiple providers:
//! - FprintdProvider: Fingerprint verification via D-Bus
//! - FaceIdProvider: Face recognition via webcam (requires "face" feature)
//! - NotificationProvider: Desktop notification (fallback)
//! - CommandProvider: Custom command/script execution

mod command;
mod fprintd;
mod manager;
mod notification;

#[cfg(feature = "face")]
mod face;

use std::fmt;

pub use command::CommandProvider;
#[cfg(feature = "face")]
pub use face::FaceIdProvider;
pub use fprintd::FprintdProvider;
pub use manager::UserVerificationManager;
pub use notification::NotificationProvider;

/// Result of a user verification attempt
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationResult {
    /// User successfully verified
    Accepted,
    /// User explicitly denied verification
    Denied,
    /// Verification timed out
    Timeout,
}

/// Error during user verification
#[derive(Debug, Clone)]
pub enum VerificationError {
    /// Provider is not available (not installed, no device, etc.)
    NotAvailable(String),
    /// Device or system error during verification
    DeviceError(String),
    /// User cancelled the operation
    #[allow(dead_code)]
    UserCancelled,
    /// Provider is not enrolled (no biometric data registered)
    NotEnrolled,
    /// Unknown error
    Other(String),
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerificationError::NotAvailable(msg) => write!(f, "Not available: {}", msg),
            VerificationError::DeviceError(msg) => write!(f, "Device error: {}", msg),
            VerificationError::UserCancelled => write!(f, "User cancelled"),
            VerificationError::NotEnrolled => write!(f, "Not enrolled"),
            VerificationError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl std::error::Error for VerificationError {}

/// Context for user verification request
#[derive(Debug, Clone)]
pub struct VerificationContext {
    /// Type of operation (e.g., "registration", "authentication")
    pub operation: String,
    /// Relying party ID (domain)
    pub relying_party: Option<String>,
    /// User identifier
    pub user: Option<String>,
    /// Timeout in seconds
    pub timeout_seconds: u32,
}

impl VerificationContext {
    /// Create a new verification context
    pub fn new(operation: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            relying_party: None,
            user: None,
            timeout_seconds: 30,
        }
    }

    /// Set the relying party
    pub fn with_relying_party(mut self, rp: impl Into<String>) -> Self {
        self.relying_party = Some(rp.into());
        self
    }

    /// Set the user
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    /// Set the timeout
    pub fn with_timeout(mut self, seconds: u32) -> Self {
        self.timeout_seconds = seconds;
        self
    }
}

/// Trait for user verification providers
///
/// Each provider implements biometric or other verification methods.
/// Providers are tried in order of priority until one succeeds.
pub trait UserVerificationProvider: Send + Sync {
    /// Unique name for this provider
    fn name(&self) -> &str;

    /// Check if this provider is available (device present, service running, etc.)
    fn available(&self) -> bool;

    /// Perform user verification
    ///
    /// Returns:
    /// - `Ok(Accepted)` - User successfully verified
    /// - `Ok(Denied)` - User explicitly denied
    /// - `Ok(Timeout)` - Verification timed out
    /// - `Err(_)` - Error occurred, try next provider
    fn verify(
        &self,
        context: &VerificationContext,
    ) -> Result<VerificationResult, VerificationError>;

    /// Priority of this provider (higher = preferred)
    ///
    /// Default priorities:
    /// - fprintd: 100
    /// - face: 90
    /// - notification: 10
    fn priority(&self) -> u8 {
        50
    }

    /// Whether this provider supports enrollment
    fn supports_enrollment(&self) -> bool {
        false
    }

    /// Enroll user for verification (e.g., capture face, fingerprint)
    #[allow(dead_code)]
    fn enroll(&self) -> Result<(), VerificationError> {
        Err(VerificationError::NotAvailable(
            "Enrollment not supported".into(),
        ))
    }

    /// Whether this provider requires enrollment before use
    fn requires_enrollment(&self) -> bool {
        self.supports_enrollment()
    }

    /// Check if the user is enrolled
    fn is_enrolled(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_new() {
        let ctx = VerificationContext::new("registration");
        assert_eq!(ctx.operation, "registration");
        assert_eq!(ctx.relying_party, None);
        assert_eq!(ctx.user, None);
        assert_eq!(ctx.timeout_seconds, 30);
    }

    #[test]
    fn test_context_builder() {
        let ctx = VerificationContext::new("authentication")
            .with_relying_party("example.com")
            .with_user("alice")
            .with_timeout(60);

        assert_eq!(ctx.operation, "authentication");
        assert_eq!(ctx.relying_party, Some("example.com".to_string()));
        assert_eq!(ctx.user, Some("alice".to_string()));
        assert_eq!(ctx.timeout_seconds, 60);
    }

    #[test]
    fn test_verification_error_display() {
        assert_eq!(
            VerificationError::NotAvailable("test".into()).to_string(),
            "Not available: test"
        );
        assert_eq!(
            VerificationError::DeviceError("failed".into()).to_string(),
            "Device error: failed"
        );
        assert_eq!(
            VerificationError::UserCancelled.to_string(),
            "User cancelled"
        );
        assert_eq!(VerificationError::NotEnrolled.to_string(), "Not enrolled");
        assert_eq!(
            VerificationError::Other("oops".into()).to_string(),
            "Error: oops"
        );
    }
}
