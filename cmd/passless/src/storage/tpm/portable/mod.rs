//! Portable TPM credential key provider
//!
//! Implements TPM-resident credential signing keys that can be synchronized
//! across multiple TPMs provisioned from the same recovery seed.

pub mod kdf;
pub mod parent;
pub mod provider;
pub mod session;

pub use parent::PortableParent;
pub use provider::TpmCredentialKeyProvider;
