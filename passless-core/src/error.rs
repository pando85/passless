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

    /// Generic other error
    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Format error for command-line output
    ///
    /// Provides clean, user-friendly error messages without Rust Debug formatting
    pub fn format_cli(&self) -> String {
        match self {
            Error::Storage(msg) => format!("Storage error: {}", msg),
            Error::Config(msg) => format!("Configuration error: {}", msg),
            Error::Uhid(msg) => format!("UHID error: {}", msg),
            Error::CredentialManagement(msg) => format!("Credential management error: {}", msg),
            Error::UserVerificationFailed(msg) => format!("User verification failed: {}", msg),
            Error::Cancelled => "Operation cancelled by user".to_string(),
            Error::Io(err) => format!("IO error: {}", err),
            Error::Serialization(msg) => format!("Serialization error: {}", msg),
            Error::InvalidData(msg) => format!("Invalid data: {}", msg),
            Error::Other(msg) => msg.clone(),
        }
    }
}

/// Convert soft_fido2::Error to Error for error handling
impl From<soft_fido2::Error> for Error {
    fn from(err: soft_fido2::Error) -> Self {
        Error::CredentialManagement(format!("{:?}", err))
    }
}

/// Convert Error to soft_fido2::Error for compatibility
impl From<Error> for soft_fido2::Error {
    fn from(err: Error) -> Self {
        match err {
            Error::Storage(ref msg) if msg.contains("not found") => soft_fido2::Error::DoesNotExist,
            Error::Storage(ref msg) if msg.contains("No more credentials") => {
                soft_fido2::Error::DoesNotExist
            }
            _ => soft_fido2::Error::Other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_soft_fido2_error_conversion() {
        let err: Error = soft_fido2::Error::DoesNotExist.into();
        assert!(matches!(err, Error::CredentialManagement(_)));

        let err: soft_fido2::Error = Error::Storage("not found".to_string()).into();
        assert!(matches!(err, soft_fido2::Error::DoesNotExist));
    }
}
