//! Core types and configuration for Passless
//!
//! This crate contains the core types and configuration structures used by both
//! the build script (for generating shell completions) and the runtime binary.

pub mod config;
pub mod error;

pub use config::{
    AppConfig, Args, BackendConfig, ClientAction, Commands, ConfigAction, OutputFormat, PinAction,
    PinConfig, SecurityConfig,
};
pub use error::{Error, Result};
