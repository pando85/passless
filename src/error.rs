//! Error types for Passless
//!
//! This module defines all error types used in the Passless authenticator.
//! We use `thiserror` for structured error handling with proper error context.

use std::io;
use thiserror::Error;

/// Result type alias using PasslessError
pub type Result<T> = std::result::Result<T, Error>;

/// Passless-specific errors
///
/// These errors represent domain and infrastructure failures.
/// They can be converted to keylib::Error when needed for compatibility.
#[derive(Error, Debug)]
pub enum Error {
    /// Storage-related errors
    #[error("Storage error: {0}")]
    Storage(String),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),

    /// UHID device errors
    #[error("UHID error: {0}")]
    Uhid(String),

    /// Credential management errors
    #[error("Credential management error: {0}")]
    CredentialManagement(String),

    /// User verification failed
    #[error("User verification failed: {0}")]
    UserVerificationFailed(String),

    /// Operation cancelled by user
    #[error("Operation cancelled by user")]
    Cancelled,

    /// Generic IO error
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Invalid data format
    #[error("Invalid data: {0}")]
    InvalidData(String),
}

/// Convert keylib::Error to Error for error handling
impl From<keylib::Error> for Error {
    fn from(err: keylib::Error) -> Self {
        Error::CredentialManagement(format!("{:?}", err))
    }
}

/// Convert Error to keylib::Error for compatibility
impl From<Error> for keylib::Error {
    fn from(err: Error) -> Self {
        match err {
            Error::Storage(ref msg) if msg.contains("not found") => keylib::Error::DoesNotExist,
            Error::Storage(ref msg) if msg.contains("No more credentials") => {
                keylib::Error::DoesNotExist
            }
            _ => keylib::Error::Other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keylib_error_conversion() {
        let err: Error = keylib::Error::DoesNotExist.into();
        assert!(matches!(err, Error::CredentialManagement(_)));

        let err: keylib::Error = Error::Storage("not found".to_string()).into();
        assert!(matches!(err, keylib::Error::DoesNotExist));
    }
}
