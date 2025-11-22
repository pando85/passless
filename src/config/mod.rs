//! Application configuration
//!
//! This module defines the configuration for the authenticator using a type-state pattern.

#[macro_use]
pub mod macros;

pub mod app;
pub mod defaults;
pub mod local;
pub mod pass;
pub mod security;
pub mod state;
pub mod tpm;

// Re-export main types for convenience
pub use app::{AppConfig, BackendConfig};
pub use local::{LocalBackendConfig, LocalBackendConfigArgs};
pub use pass::{PassBackendConfig, PassBackendConfigArgs};
pub use security::{SecurityConfig, SecurityConfigArgs};
pub use state::{Raw, Resolved};
pub use tpm::{TpmBackendConfig, TpmBackendConfigArgs};
