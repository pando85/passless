//! TEE (Trusted Execution Environment) detection and utilities
//!
//! This crate provides hardware detection for TEE capabilities
//! including Intel SGX and AMD SEV.

mod detection;

pub use detection::{TeeBackend, TeeCapabilities, detect_tee};
