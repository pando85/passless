//! PIN storage trait and implementations
//!
//! This module provides persistent storage for PIN state across different backends.
//! PIN state includes the PIN hash, retry counters, and configuration.

use std::path::PathBuf;
use std::fs;
use std::io::{Read, Write};

use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use soft_fido2::{PinState, StatusCode};
use zeroize::Zeroizing;

use crate::util::create_secure_file;

pub mod local;
pub mod pass;
#[cfg(feature = "tpm")]
pub mod tpm;

pub use local::LocalPinStorage;
pub use pass::PassPinStorage;
#[cfg(feature = "tpm")]
pub use tpm::TpmPinStorage;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializablePinState {
    #[serde(with = "option_pin_hash")]
    pub pin_hash: Option<[u8; 16]>,
    pub retries: u8,
    pub uv_retries: u8,
    pub min_pin_length: u8,
    pub version: u64,
    pub force_pin_change: bool,
}

mod option_pin_hash {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &Option<[u8; 16]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(hash) => serializer.serialize_str(&hex::encode(hash)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 16]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
                if bytes.len() != 16 {
                    return Err(serde::de::Error::custom("PIN hash must be 16 bytes"));
                }
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&bytes);
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}

impl From<PinState> for SerializablePinState {
    fn from(state: PinState) -> Self {
        let hash_bytes = state.pin_hash.as_ref().map(|h| {
            let slice = h.as_ref();
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&slice[..16]);
            arr
        });
        Self {
            pin_hash: hash_bytes,
            retries: state.retries,
            uv_retries: state.uv_retries,
            min_pin_length: state.min_pin_length,
            version: state.version,
            force_pin_change: state.force_pin_change,
        }
    }
}

impl From<SerializablePinState> for PinState {
    fn from(state: SerializablePinState) -> Self {
        use soft_fido2_ctap::sec_bytes::SecPinHash;

        let sec_hash = state.pin_hash.map(|h| {
            let mut full_hash = [0u8; 32];
            full_hash[..16].copy_from_slice(&h);
            SecPinHash::from(full_hash.to_vec())
        });
        Self {
            pin_hash: sec_hash,
            retries: state.retries,
            uv_retries: state.uv_retries,
            min_pin_length: state.min_pin_length,
            version: state.version,
            force_pin_change: state.force_pin_change,
        }
    }
}

fn load_pin_state_from_file(path: &PathBuf) -> Result<PinState, StatusCode> {
    if !path.exists() {
        debug!("PIN state file does not exist, creating new state");
        return Ok(PinState::new());
    }

    let mut file = fs::File::open(path).map_err(|_| StatusCode::Other)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .map_err(|_| StatusCode::Other)?;

    let serializable: SerializablePinState =
        serde_json::from_slice(&contents).map_err(|e| {
            warn!("Failed to parse PIN state file: {}", e);
            StatusCode::Other
        })?;

    info!("Loaded PIN state from {}", path.display());
    Ok(serializable.into())
}

fn save_pin_state_to_file(path: &PathBuf, state: &PinState) -> Result<(), StatusCode> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| StatusCode::Other)?;
    }

    let serializable = SerializablePinState::from(state.clone());
    let bytes = Zeroizing::new(
        serde_json::to_vec_pretty(&serializable).map_err(|_| StatusCode::Other)?,
    );

    let mut file = create_secure_file(path).map_err(|_| StatusCode::Other)?;
    file.write_all(&bytes).map_err(|_| StatusCode::Other)?;

    debug!("Saved PIN state to {}", path.display());
    Ok(())
}