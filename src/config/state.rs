//! Type-state pattern for configuration
//!
//! This module implements a type-state pattern for configuration management,
//! ensuring that configuration is properly resolved before use.

use std::marker::PhantomData;

/// Marker type for raw configuration state (contains Option<T> fields)
#[derive(Debug, Clone)]
pub struct Raw;

/// Marker type for resolved configuration state (contains T fields with defaults applied)
#[derive(Debug, Clone)]
pub struct Resolved;

/// Trait that defines how fields are represented in different states
pub trait ConfigState {
    /// The field type for a given value type T
    type Field<T: std::fmt::Debug + Clone>: std::fmt::Debug + Clone;
}

impl ConfigState for Raw {
    type Field<T: std::fmt::Debug + Clone> = Option<T>;
}

impl ConfigState for Resolved {
    type Field<T: std::fmt::Debug + Clone> = T;
}

/// Type alias for fields in a given state
pub type Field<State, T> = <State as ConfigState>::Field<T>;

/// Helper struct to hold phantom state marker
#[derive(Debug, Clone)]
pub struct StateMarker<State>(PhantomData<State>);

impl<State> StateMarker<State> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<State> Default for StateMarker<State> {
    fn default() -> Self {
        Self::new()
    }
}
