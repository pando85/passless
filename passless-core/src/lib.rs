//! Core types and configuration for Passless
//!
//! This crate contains the core types and configuration structures used by both
//! the build script (for generating shell completions) and the runtime binary.

pub mod config;
pub mod error;
pub mod secure_memory;

pub use config::{AppConfig, Args, BackendConfig, Commands, ConfigAction, SecurityConfig};
pub use error::{Error, Result};
pub use secure_memory::{LockedBuffer, LockedCredentialArena};
