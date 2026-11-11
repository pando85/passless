//! Interception readiness per bearer (plan D6 layer 1).
//!
//! The extension worker says `hello` on its native port when it starts and again whenever its
//! `webAuthenticationProxy` attachment changes. This registry keeps the last state each bearer
//! reported, so a launch can wait until the worker has attached before it hands out the CDP
//! endpoint, and can tell when the port dropped.
//!
//! The registry lock is a leaf (`LockLevel::TransportReadiness`, LOCKING.md): it is never held
//! across another acquisition, so it may be read and waited on while the caller holds the profile
//! lifecycle lock and the browser manager. The hello path never takes those locks.

use std::collections::HashMap;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::agent::lock_order::{self, LockLevel};

/// Most bearers remembered. Beyond it, the disconnected bearers that left first are forgotten.
const MAX_TRACKED_BEARERS: usize = 1024;

/// The last state a bearer's worker reported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BearerReadiness {
    /// A transport connection that said a valid hello for this bearer is open.
    pub connected: bool,
    /// The last hello reported `attached = true` (`webAuthenticationProxy.attach()` resolved). It
    /// keeps the last reported value after a disconnect; check `connected` as well.
    pub attached: bool,
    /// The last hello's `chrome.extension.isAllowedIncognitoAccess()`.
    pub incognito_allowed: bool,
    /// The extension's build version from the last hello.
    pub build_version: Option<String>,
    /// The relay's build version from the last hello.
    pub relay_version: Option<String>,
    /// When the last connection of this bearer closed, if one did.
    pub last_disconnect: Option<Instant>,
    /// Since when the bearer has not been both connected and attached: set by the first hello
    /// that reports `attached = false` or by a disconnect, cleared by an attached hello. `None`
    /// while connected and attached. A lease is degraded once this is older than its grace period.
    pub detached_since: Option<Instant>,
}

struct Entry {
    state: BearerReadiness,
    /// The connection that owns `connected`; a superseded connection's close leaves it alone.
    connection: Option<u64>,
}

/// What a hello reported.
pub(crate) struct HelloState {
    pub attached: bool,
    pub incognito_allowed: bool,
    pub build_version: Option<String>,
    pub relay_version: Option<String>,
}

/// Interception readiness keyed by bearer token.
#[derive(Default)]
pub struct ReadinessRegistry {
    entries: Mutex<HashMap<String, Entry>>,
    changed: Condvar,
}

impl ReadinessRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// The last reported state of `bearer`, or `None` if no worker ever said hello with it.
    pub fn status(&self, bearer: &str) -> Option<BearerReadiness> {
        lock_order::lock(&self.entries, LockLevel::TransportReadiness)
            .get(bearer)
            .map(|entry| entry.state.clone())
    }

    /// Block until `bearer` is connected and attached, or until `timeout` passes. Returns the
    /// state that satisfied the wait, or `None` on timeout.
    pub fn wait_attached(&self, bearer: &str, timeout: Duration) -> Option<BearerReadiness> {
        let deadline = Instant::now() + timeout;
        let mut entries = lock_order::lock(&self.entries, LockLevel::TransportReadiness);
        loop {
            if let Some(entry) = entries.get(bearer)
                && entry.state.connected
                && entry.state.attached
            {
                return Some(entry.state.clone());
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            entries = entries.wait_timeout(&self.changed, deadline - now);
        }
    }

    /// Record a valid hello of `bearer` on `connection`. Returns the connection it supersedes, if
    /// another one of this bearer was open.
    pub(crate) fn on_hello(&self, bearer: &str, connection: u64, hello: HelloState) -> Option<u64> {
        let mut entries = lock_order::lock(&self.entries, LockLevel::TransportReadiness);
        if !entries.contains_key(bearer) && entries.len() >= MAX_TRACKED_BEARERS {
            evict_one(&mut entries);
        }
        let entry = entries.entry(bearer.to_string()).or_insert_with(|| Entry {
            state: BearerReadiness {
                connected: false,
                attached: false,
                incognito_allowed: false,
                build_version: None,
                relay_version: None,
                last_disconnect: None,
                detached_since: None,
            },
            connection: None,
        });
        let superseded = entry.connection.filter(|previous| *previous != connection);
        entry.connection = Some(connection);
        apply_hello(&mut entry.state, hello);
        drop(entries);
        self.changed.notify_all();
        superseded
    }

    /// Record a repeated hello (an attach-state update) of `bearer` on `connection`. Only the
    /// connection that currently owns the bearer may update it: a superseded connection whose
    /// hello arrives late changes nothing. Returns whether the state was updated.
    pub(crate) fn on_repeated_hello(
        &self,
        bearer: &str,
        connection: u64,
        hello: HelloState,
    ) -> bool {
        let mut entries = lock_order::lock(&self.entries, LockLevel::TransportReadiness);
        let Some(entry) = entries
            .get_mut(bearer)
            .filter(|entry| entry.connection == Some(connection))
        else {
            return false;
        };
        apply_hello(&mut entry.state, hello);
        drop(entries);
        self.changed.notify_all();
        true
    }

    /// Record that `connection` of `bearer` closed. A connection that was already superseded
    /// changes nothing.
    pub(crate) fn on_disconnect(&self, bearer: &str, connection: u64) {
        let mut entries = lock_order::lock(&self.entries, LockLevel::TransportReadiness);
        if let Some(entry) = entries.get_mut(bearer)
            && entry.connection == Some(connection)
        {
            entry.connection = None;
            entry.state.connected = false;
            let now = Instant::now();
            entry.state.last_disconnect = Some(now);
            entry.state.detached_since = entry.state.detached_since.or(Some(now));
        }
        drop(entries);
        self.changed.notify_all();
    }
}

#[cfg(test)]
impl ReadinessRegistry {
    /// Test hook: what a valid hello of `bearer` on `connection` records.
    pub(crate) fn simulate_hello(
        &self,
        bearer: &str,
        connection: u64,
        attached: bool,
        incognito_allowed: bool,
    ) {
        self.on_hello(
            bearer,
            connection,
            HelloState {
                attached,
                incognito_allowed,
                build_version: None,
                relay_version: None,
            },
        );
    }

    /// Test hook: what the close of `connection` records.
    pub(crate) fn simulate_disconnect(&self, bearer: &str, connection: u64) {
        self.on_disconnect(bearer, connection);
    }

    /// Test hook: pretend the bearer has been detached for `age` already.
    pub(crate) fn backdate_detached(&self, bearer: &str, age: Duration) {
        let mut entries = lock_order::lock(&self.entries, LockLevel::TransportReadiness);
        if let Some(entry) = entries.get_mut(bearer) {
            entry.state.detached_since = Instant::now().checked_sub(age);
        }
    }
}

/// What a hello on the owning connection records.
fn apply_hello(state: &mut BearerReadiness, hello: HelloState) {
    state.connected = true;
    state.attached = hello.attached;
    state.incognito_allowed = hello.incognito_allowed;
    state.build_version = hello.build_version;
    state.relay_version = hello.relay_version;
    state.detached_since = if hello.attached {
        None
    } else {
        state.detached_since.or(Some(Instant::now()))
    };
}

/// Forget one bearer: the disconnected one that left first, else any disconnected one, else any.
fn evict_one(entries: &mut HashMap<String, Entry>) {
    let victim = entries
        .iter()
        .filter(|(_, entry)| entry.connection.is_none())
        .min_by_key(|(_, entry)| entry.state.last_disconnect)
        .or_else(|| entries.iter().next())
        .map(|(bearer, _)| bearer.clone());
    if let Some(victim) = victim {
        entries.remove(&victim);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(attached: bool) -> HelloState {
        HelloState {
            attached,
            incognito_allowed: false,
            build_version: None,
            relay_version: None,
        }
    }

    #[test]
    fn a_stale_hello_of_a_superseded_connection_changes_nothing() {
        let registry = ReadinessRegistry::new();
        assert_eq!(registry.on_hello("b", 1, hello(true)), None);
        // Connection 2 supersedes connection 1.
        assert_eq!(registry.on_hello("b", 2, hello(true)), Some(1));
        // A late attach-state update from connection 1 does not take the bearer back.
        assert!(!registry.on_repeated_hello("b", 1, hello(false)));
        let state = registry.status("b").unwrap();
        assert!(state.connected && state.attached);
        assert_eq!(state.detached_since, None);
        // Nor does its close.
        registry.on_disconnect("b", 1);
        let state = registry.status("b").unwrap();
        assert!(state.connected && state.attached);
        // The owner's update applies.
        assert!(registry.on_repeated_hello("b", 2, hello(false)));
        assert!(!registry.status("b").unwrap().attached);
        // An unknown bearer is not created by a repeated hello.
        assert!(!registry.on_repeated_hello("other", 3, hello(true)));
        assert!(registry.status("other").is_none());
    }
}
