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

/// Serializable PIN config for storage (synced across machines)
///
/// Contains PIN configuration that should be synchronized across all machines
/// using the same password-store. Changes to this file are committed to git.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct SerializablePinConfig {
    /// PIN hash as raw bytes (None if no PIN set)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_hash: Option<Vec<u8>>,
    /// Minimum PIN length (4-63)
    #[serde(default = "default_min_pin_length")]
    pub min_pin_length: u8,
    /// State version for rollback detection
    #[serde(default)]
    pub version: u64,
    /// Force PIN change flag
    #[serde(default)]
    pub force_pin_change: bool,
    /// Modification timestamp in milliseconds since Unix epoch
    /// Used for conflict resolution when syncing across machines
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<u64>,
}

fn default_min_pin_length() -> u8 {
    4
}

impl SerializablePinConfig {
    /// Convert to JSON bytes
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, StatusCode> {
        serde_json::to_vec(self).map_err(|_| StatusCode::Other)
    }

    /// Convert from JSON bytes
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, StatusCode> {
        serde_json::from_slice(bytes).map_err(|_| StatusCode::InvalidParameter)
    }

    /// Check if PIN is set
    pub fn is_pin_set(&self) -> bool {
        self.pin_hash.is_some()
    }
}

impl From<&PinState> for SerializablePinConfig {
    fn from(state: &PinState) -> Self {
        let modified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .ok();
        Self {
            pin_hash: state.pin_hash.as_ref().map(|h| h.as_array().to_vec()),
            min_pin_length: state.min_pin_length,
            version: state.version,
            force_pin_change: state.force_pin_change,
            modified_at,
        }
    }
}

/// Serializable PIN retry state for storage (local-only, not synced)
///
/// Contains retry counters and lock state that are machine-specific.
/// These should NOT be synced to git to avoid conflicts and commit spam.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializablePinRetries {
    /// Remaining PIN retry attempts (0-8)
    #[serde(default = "default_retries")]
    pub retries: u8,
    /// Remaining UV retry attempts (0-3)
    #[serde(default = "default_uv_retries")]
    pub uv_retries: u8,
    /// Auto-lock timestamp in milliseconds since Unix epoch (None = not locked)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked_until: Option<u64>,
}

fn default_retries() -> u8 {
    8
}

fn default_uv_retries() -> u8 {
    3
}

impl Default for SerializablePinRetries {
    fn default() -> Self {
        Self {
            retries: 8,
            uv_retries: 3,
            locked_until: None,
        }
    }
}

impl SerializablePinRetries {
    /// Convert to JSON bytes
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, StatusCode> {
        serde_json::to_vec(self).map_err(|_| StatusCode::Other)
    }

    /// Convert from JSON bytes
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, StatusCode> {
        serde_json::from_slice(bytes).map_err(|_| StatusCode::InvalidParameter)
    }
}

impl From<&PinState> for SerializablePinRetries {
    fn from(state: &PinState) -> Self {
        Self {
            retries: state.retries,
            uv_retries: state.uv_retries,
            locked_until: state.locked_until,
        }
    }
}

/// Serializable PIN state for storage (legacy, single-file format)
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
    /// Auto-lock timestamp in milliseconds since Unix epoch (None = not locked)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked_until: Option<u64>,
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
            locked_until: None,
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
            locked_until: state.locked_until,
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
            locked_until: state.locked_until,
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

    /// Create from config and retries parts
    pub fn from_parts(config: &SerializablePinConfig, retries: &SerializablePinRetries) -> Self {
        Self {
            pin_hash: config.pin_hash.clone(),
            retries: retries.retries,
            uv_retries: retries.uv_retries,
            min_pin_length: config.min_pin_length,
            version: config.version,
            force_pin_change: config.force_pin_change,
            locked_until: retries.locked_until,
        }
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
