//! User Verification (UV) module for FIDO2 authenticator
//!
//! This module provides a pluggable user verification system with multiple providers:
//! - [`FprintdProvider`]: Fingerprint verification via D-Bus
//! - [`FaceIdProvider`]: Face recognition via webcam (requires "face" feature)
//! - [`NotificationProvider`]: Desktop notification (fallback)
//! - [`CommandProvider`]: Custom command/script execution
//!
//! # Architecture
//!
//! Providers implement the [`UserVerificationProvider`] trait and are managed by
//! [`UserVerificationManager`], which handles priority ordering and automatic fallback.
//!
//! # Example
//!
//! ```ignore
//! use passless::uv::{
//!     UserVerificationManager, FprintdProvider, NotificationProvider,
//!     VerificationContext, UserVerificationProvider,
//! };
//!
//! let manager = UserVerificationManager::new(vec![
//!     Box::new(FprintdProvider::new()),
//!     Box::new(NotificationProvider::new(30)),
//! ]);
//!
//! let ctx = VerificationContext::new("authentication")
//!     .with_relying_party("example.com");
//!
//! match manager.verify(&ctx) {
//!     Ok(VerificationResult::Accepted) => { /* success */ }
//!     Ok(VerificationResult::Denied) => { /* denied */ }
//!     Ok(VerificationResult::Timeout) => { /* timeout */ }
//!     Err(e) => { /* error */ }
//! }
//! ```

mod command;
mod fprintd;
mod manager;
mod notification;

#[cfg(feature = "face")]
mod face;

pub use command::CommandProvider;
#[cfg(feature = "face")]
pub use face::FaceIdProvider;
pub use fprintd::FprintdProvider;
pub use manager::UserVerificationManager;
pub use notification::NotificationProvider;

/// Default timeout for user verification (seconds)
pub const DEFAULT_TIMEOUT_SECONDS: u32 = 30;

/// Provider priority constants (higher = preferred)
pub mod priority {
    /// Fingerprint provider priority (highest - most secure biometric)
    pub const FPRINTD: u8 = 100;
    /// Face recognition provider priority
    #[cfg(feature = "face")]
    pub const FACE: u8 = 90;
    /// Custom command provider priority (configurable)
    pub const COMMAND: u8 = 50;
    /// Notification provider priority (lowest - fallback)
    pub const NOTIFICATION: u8 = 10;
}

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
#[derive(Debug, Clone, thiserror::Error)]
pub enum VerificationError {
    /// Provider is not available (not installed, no device, etc.)
    #[error("Not available: {0}")]
    NotAvailable(String),
    /// Device or system error during verification
    #[error("Device error: {0}")]
    DeviceError(String),
    /// User cancelled the operation
    #[error("User cancelled")]
    #[allow(dead_code)]
    UserCancelled,
    /// Provider is not enrolled (no biometric data registered)
    #[error("Not enrolled")]
    NotEnrolled,
    /// Unknown error
    #[error("Error: {0}")]
    Other(String),
}

impl From<std::io::Error> for VerificationError {
    fn from(err: std::io::Error) -> Self {
        VerificationError::DeviceError(err.to_string())
    }
}

impl From<zbus::Error> for VerificationError {
    fn from(err: zbus::Error) -> Self {
        match err {
            zbus::Error::MethodError(_, _, _) => {
                VerificationError::DeviceError(format!("D-Bus method failed: {}", err))
            }
            zbus::Error::InterfaceNotFound => {
                VerificationError::NotAvailable("D-Bus interface not found".into())
            }
            zbus::Error::FDO(e) => {
                VerificationError::DeviceError(format!("D-Bus freedesktop error: {}", e))
            }
            _ => VerificationError::DeviceError(format!("D-Bus error: {}", err)),
        }
    }
}

impl From<zbus::zvariant::Error> for VerificationError {
    fn from(err: zbus::zvariant::Error) -> Self {
        VerificationError::DeviceError(format!("D-Bus variant error: {}", err))
    }
}

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
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
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
    /// See [`priority`] module for standard values.
    fn priority(&self) -> u8 {
        priority::COMMAND
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
        assert_eq!(ctx.timeout_seconds, DEFAULT_TIMEOUT_SECONDS);
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

    #[test]
    fn test_verification_error_from_io() {
        let err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let uv_err: VerificationError = err.into();
        assert!(matches!(uv_err, VerificationError::DeviceError(_)));
    }
}
