//! TPM 2.0 PIN storage

use crate::pin_storage::{PinStorage, SerializablePinState};

use soft_fido2::{PinState, StatusCode};

use std::path::PathBuf;

use log::{debug, warn};

const PIN_STATE_FILENAME: &str = "pin_state.json.tpm";

/// TPM 2.0 PIN storage
///
/// Stores PIN state as TPM-sealed data.
pub struct TpmPinStorage {
    path: PathBuf,
    #[allow(dead_code)]
    tcti: String,
}

impl TpmPinStorage {
    /// Create a new TPM PIN storage
    pub fn new(storage_dir: PathBuf, tcti: Option<String>) -> Self {
        let path = storage_dir.join(PIN_STATE_FILENAME);
        let tcti = tcti.unwrap_or_else(|| "device:/dev/tpmrm0".to_string());
        debug!("TPM PIN storage path: {}, TCTI: {}", path.display(), tcti);
        Self { path, tcti }
    }
}

impl PinStorage for TpmPinStorage {
    fn load_pin_state(&self) -> Result<PinState, StatusCode> {
        debug!(
            "Loading PIN state from TPM storage: {}",
            self.path.display()
        );

        if !self.path.exists() {
            debug!("PIN state file does not exist, returning default state");
            return Ok(PinState::new());
        }

        let sealed_data = std::fs::read(&self.path).map_err(|e| {
            warn!("Failed to read sealed PIN state: {}", e);
            StatusCode::Other
        })?;

        let json_bytes = self.unseal(&sealed_data)?;

        let state: SerializablePinState = serde_json::from_slice(&json_bytes).map_err(|e| {
            warn!("Failed to parse PIN state: {}", e);
            StatusCode::InvalidParameter
        })?;

        Ok(state.into())
    }

    fn save_pin_state(&self, state: &PinState) -> Result<(), StatusCode> {
        debug!("Saving PIN state to TPM storage: {}", self.path.display());

        let serializable = SerializablePinState::from(state);
        let json_bytes = serde_json::to_vec(&serializable).map_err(|_| StatusCode::Other)?;

        let sealed_data = self.seal(&json_bytes)?;

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                warn!("Failed to create directory: {}", e);
                StatusCode::Other
            })?;
        }

        std::fs::write(&self.path, &sealed_data).map_err(|e| {
            warn!("Failed to write sealed PIN state: {}", e);
            StatusCode::Other
        })?;

        debug!("PIN state saved successfully");
        Ok(())
    }
}

impl TpmPinStorage {
    fn seal(&self, data: &[u8]) -> Result<Vec<u8>, StatusCode> {
        #[cfg(feature = "tpm")]
        {
            use tss_esapi::{
                attributes::SessionAttributesBuilder,
                handles::KeyHandle,
                interface_types::{resource_handles::Hierarchy, session_handles::PolicySession},
                structures::{Auth, MaxBuffer, SensitiveData},
                Context,
            };

            let tcti_str = self.tcti.as_str();
            let mut context = Context::new(tss_esapi::tcti_ldr::TctiNameConf::from_str(tcti_str))
                .map_err(|e| {
                warn!("Failed to connect to TPM: {:?}", e);
                StatusCode::Other
            })?;

            let parent = context
                .execute_without_session(|ctx| {
                    ctx.tr_from_tpm_public(Hierarchy::Owner.try_into().unwrap())
                        .map(|h| KeyHandle::from(h))
                })
                .map_err(|e| {
                    warn!("Failed to get owner hierarchy: {:?}", e);
                    StatusCode::Other
                })?;

            let auth = Auth::try_from(vec![]).map_err(|_| StatusCode::Other)?;

            let sensitive_data =
                SensitiveData::try_from(data.to_vec()).map_err(|_| StatusCode::Other)?;

            let (sealed, _auth_value) = context
                .execute_with_session(Some(SessionAttributesBuilder::new().build()), |ctx| {
                    ctx.seal(parent, sensitive_data, auth)
                })
                .map_err(|e| {
                    warn!("Failed to seal data: {:?}", e);
                    StatusCode::Other
                })?;

            let sealed_bytes = bincode::serialize(&sealed).map_err(|e| {
                warn!("Failed to serialize sealed data: {:?}", e);
                StatusCode::Other
            })?;

            Ok(sealed_bytes)
        }

        #[cfg(not(feature = "tpm"))]
        {
            warn!("TPM feature not enabled, storing unencrypted (not recommended)");
            Ok(data.to_vec())
        }
    }

    fn unseal(&self, sealed_data: &[u8]) -> Result<Vec<u8>, StatusCode> {
        #[cfg(feature = "tpm")]
        {
            use tss_esapi::{
                attributes::SessionAttributesBuilder, handles::KeyHandle,
                interface_types::session_handles::PolicySession, structures::MaxBuffer, Context,
            };

            let tcti_str = self.tcti.as_str();
            let mut context = Context::new(tss_esapi::tcti_ldr::TctiNameConf::from_str(tcti_str))
                .map_err(|e| {
                warn!("Failed to connect to TPM: {:?}", e);
                StatusCode::Other
            })?;

            let sealed: tss_esapi::structures::Sealed =
                bincode::deserialize(sealed_data).map_err(|e| {
                    warn!("Failed to deserialize sealed data: {:?}", e);
                    StatusCode::Other
                })?;

            let unsealed = context
                .execute_with_session(Some(SessionAttributesBuilder::new().build()), |ctx| {
                    ctx.unseal(sealed)
                })
                .map_err(|e| {
                    warn!("Failed to unseal data: {:?}", e);
                    StatusCode::Other
                })?;

            Ok(unsealed.to_vec())
        }

        #[cfg(not(feature = "tpm"))]
        {
            Ok(sealed_data.to_vec())
        }
    }
}
