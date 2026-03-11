//! PIN storage backends for FIDO2 authenticator
//!
//! This module provides storage backends for persisting PIN state.

pub mod local;
pub mod pass;
#[cfg(feature = "tpm")]
pub mod tpm;

pub use local::LocalPinStorage;
pub use pass::PassPinStorage;
#[cfg(feature = "tpm")]
pub use tpm::TpmPinStorage;

use serde::{Deserialize, Serialize};
use soft_fido2::{PinState, StatusCode};

/// Serializable PIN state for storage
///
/// This struct represents the PIN state in a format suitable for serialization
/// to JSON or other formats. It contains the PIN hash as raw bytes (if set),
/// retry counters, and configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializablePinState {
    /// PIN hash as raw bytes (None if no PIN set)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_hash: Option<Vec<u8>>,
    /// Remaining PIN retry attempts (0-8)
    pub retries: u8,
    /// Remaining UV retry attempts (0-3)
    #[serde(default = "default_uv_retries")]
    pub uv_retries: u8,
    /// Minimum PIN length (4-63)
    pub min_pin_length: u8,
    /// State version for rollback detection
    pub version: u64,
    /// Force PIN change flag
    #[serde(default)]
    pub force_pin_change: bool,
}

fn default_uv_retries() -> u8 {
    3
}

impl Default for SerializablePinState {
    fn default() -> Self {
        Self {
            pin_hash: None,
            retries: 8,
            uv_retries: 3,
            min_pin_length: 4,
            version: 0,
            force_pin_change: false,
        }
    }
}

impl From<&PinState> for SerializablePinState {
    fn from(state: &PinState) -> Self {
        Self {
            pin_hash: state.pin_hash.as_ref().map(|h| h.as_array().to_vec()),
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
        use soft_fido2_ctap::SecPinHash;
        Self {
            pin_hash: state.pin_hash.map(|h| {
                let arr: [u8; 32] = h.as_slice().try_into().unwrap_or([0u8; 32]);
                SecPinHash::new(arr)
            }),
            retries: state.retries,
            uv_retries: state.uv_retries,
            min_pin_length: state.min_pin_length,
            version: state.version,
            force_pin_change: state.force_pin_change,
        }
    }
}

impl SerializablePinState {
    /// Convert to JSON bytes
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, StatusCode> {
        serde_json::to_vec(self).map_err(|_| StatusCode::Other)
    }

    /// Convert from JSON bytes
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, StatusCode> {
        serde_json::from_slice(bytes).map_err(|_| StatusCode::InvalidParameter)
    }
}

/// Trait for PIN storage backends
///
/// This trait is implemented by storage backends that can persist PIN state.
/// The soft-fido2 library calls these methods when PIN state changes.
pub trait PinStorage: Send + Sync {
    /// Load PIN state from storage
    ///
    /// Returns default state if no state is stored.
    fn load_pin_state(&self) -> Result<PinState, StatusCode>;

    /// Save PIN state to storage
    fn save_pin_state(&self, state: &PinState) -> Result<(), StatusCode>;
}

/// No-op PIN storage implementation
impl PinStorage for () {
    fn load_pin_state(&self) -> Result<PinState, StatusCode> {
        Ok(PinState::new())
    }

    fn save_pin_state(&self, _state: &PinState) -> Result<(), StatusCode> {
        Ok(())
    }
}
