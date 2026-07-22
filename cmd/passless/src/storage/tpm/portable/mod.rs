//! Portable TPM credential key provider
//!
//! Implements TPM-resident credential signing keys that can be synchronized
//! across multiple TPMs provisioned from the same recovery seed.

pub mod parent;
pub mod provider;

pub use provider::TpmCredentialKeyProvider;
