//! Portable TPM credential key provider
//!
//! Implements TPM-resident credential signing keys that can be synchronized
//! across multiple TPMs provisioned from the same recovery seed.

pub(crate) mod context;
pub mod kdf;
pub mod parent;
pub mod provider;
pub mod provision;
pub mod session;

pub use parent::PortableParent;
pub use provider::TpmCredentialKeyProvider;

use crate::pin_storage::tpm::TpmPinStorage;
use crate::storage::tpm::TpmStorageAdapter;
use passless_core::Error;
use std::path::PathBuf;

pub fn build_portable_bundle(
    path: PathBuf,
    tcti: Option<String>,
    allow_storage_creation: bool,
) -> Result<(TpmCredentialKeyProvider, TpmStorageAdapter, TpmPinStorage), Error> {
    let provider = TpmCredentialKeyProvider::new(path.clone(), tcti.clone())
        .map_err(|e| Error::Other(format!("Failed to create TPM key provider: {:?}", e)))?;
    if !provider.is_ready() {
        return Err(Error::Other(
            "TPM portable parent is not provisioned. Run: passless tpm provision".to_string(),
        ));
    }
    let storage =
        TpmStorageAdapter::new_portable(path.clone(), tcti.clone(), allow_storage_creation)?;
    let pin_storage = TpmPinStorage::new_portable(path, tcti);
    Ok((provider, storage, pin_storage))
}
