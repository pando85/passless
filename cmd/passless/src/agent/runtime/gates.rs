//! Pure admission gates of the runtime, kept apart from the handlers so that each refusal is
//! unit-tested on its own (ADR 0014 sections 4.2 and 5: `max_concurrent_sessions`, the pipe-mode
//! browser user, `browser-control` in port mode).

use passless_core::agent::ProfileId;
use passless_core::agent::config::{BrowserScope, CdpExposeMode};
use passless_core::agent::protocol::{ErrorCode, ProtocolError, RecommendedAction};

use crate::agent::browser::InterceptionState;

/// Refuse a new principal when `live` sessions already fill `max_concurrent_sessions`.
///
/// A maximum of 0 means unlimited, and only for `browser_scope = "profile"` (config validation
/// rejects 0 elsewhere, so a 0 under another scope refuses everything: fail closed).
pub(super) fn check_session_limit(
    profile_id: &ProfileId,
    live: usize,
    max_concurrent_sessions: u16,
    scope: BrowserScope,
) -> Result<(), ProtocolError> {
    let unlimited = scope == BrowserScope::Profile && max_concurrent_sessions == 0;
    let limit = usize::from(max_concurrent_sessions);
    if !unlimited && live >= limit {
        return Err(ProtocolError::new(
            ErrorCode::Conflict,
            format!(
                "profile '{}' reached max_concurrent_sessions ({})",
                profile_id, limit
            ),
            RecommendedAction::RetryWithBackoff,
        ));
    }
    Ok(())
}

/// In pipe mode under a root daemon the browser runs as its own user, which must differ from the
/// principal (the principal could otherwise reach the browser process), from the daemon, and must
/// not be root. Port mode trusts the agent and is exempt, as is a non-root daemon.
pub(super) fn validate_pipe_browser_user(
    profile: &str,
    daemon_is_root: bool,
    port_mode: bool,
    browser_uid: u32,
    principal_uid: u32,
    daemon_uid: u32,
) -> Result<(), String> {
    if !daemon_is_root || port_mode {
        return Ok(());
    }
    if browser_uid == principal_uid {
        return Err(format!(
            "profile '{profile}': browser uid {browser_uid} must differ from principal uid \
             {principal_uid}"
        ));
    }
    if browser_uid == daemon_uid {
        return Err(format!(
            "profile '{profile}': browser uid {browser_uid} must differ from daemon uid \
             {daemon_uid}"
        ));
    }
    if browser_uid == 0 {
        return Err(format!("profile '{profile}': browser must not be root"));
    }
    Ok(())
}

/// `browser-control` relays CDP over the lease's pipes; a port-mode lease has none
/// (`has_cdp_pipes == Some(false)`) and is refused. The endpoint is not named: it is handed out
/// only by the bootstrap, which withholds it while the lease's interception is degraded.
pub(super) fn check_browser_control_available(
    has_cdp_pipes: Option<bool>,
) -> Result<(), ProtocolError> {
    if has_cdp_pipes == Some(false) {
        return Err(ProtocolError::new(
            ErrorCode::Forbidden,
            "browser-control is unavailable in port mode; get the CDP endpoint from the \
             browser bootstrap",
            RecommendedAction::FixRequest,
        ));
    }
    Ok(())
}

/// `EnsureBrowser` from a caller that can only use a CDP endpoint (`direct_cdp`: the Playwright
/// bootstrap, the chrome-devtools adapter) is refused for a pipe-mode profile before a browser is
/// started, because a pipe-mode browser has no endpoint to give. Every other caller (`agent
/// browser`) is served in both modes: pipe mode ensures the lease and CDP goes through
/// `browser-control` (ADR 0014 section 4.3).
pub(super) fn check_ensure_browser_mode(
    mode: CdpExposeMode,
    direct_cdp: bool,
) -> Result<(), ProtocolError> {
    if direct_cdp && mode != CdpExposeMode::Port {
        return Err(ProtocolError::new(
            ErrorCode::Forbidden,
            "Playwright browser discovery requires browser_cdp_expose = 'port' (trusted agents \
             only); in pipe mode run `passless agent browser` and drive the browser with \
             `passless agent browser-control`",
            RecommendedAction::FixRequest,
        ));
    }
    Ok(())
}

/// How a live lease is reached in `mode`, `None` when it cannot be used in that mode (a stale
/// lease, or one launched under the other mode before a reload). `Some(Some(endpoint))` is a
/// port-mode lease with its loopback endpoint; `Some(None)` is a pipe-mode lease with its CDP
/// pipes, which has no endpoint: only `browser-control` reaches it.
pub(super) fn cdp_access(
    mode: CdpExposeMode,
    endpoint: Option<String>,
    has_cdp_pipes: Option<bool>,
) -> Option<Option<String>> {
    match mode {
        CdpExposeMode::Port => endpoint.map(Some),
        CdpExposeMode::Pipe => (has_cdp_pipes == Some(true)).then_some(None),
    }
}

/// `browser-control` is refused while the lease's WebAuthn interception is degraded (or the lease
/// has no extension record), like the port-mode bootstrap withholds its endpoint: the daemon
/// cannot confirm that the browser's ceremonies reach it. A lease that is reconnecting within its
/// grace period (`Pending`) is served: the proxy attachment outlives the worker, and a request
/// wakes it (interception.rs), so `browser-control` need not wait for the re-attach as the
/// bootstrap does while it holds the browser manager.
pub(super) fn check_control_interception(
    state: Option<InterceptionState>,
) -> Result<(), ProtocolError> {
    match state {
        Some(InterceptionState::Attached | InterceptionState::Pending) => Ok(()),
        Some(InterceptionState::Degraded) | None => Err(ProtocolError::new(
            ErrorCode::Conflict,
            "the managed browser's WebAuthn interception is degraded: its passless extension \
             worker is not attached, or is not allowed in incognito, so browser-control is \
             refused until it re-attaches (see `passless agent browser-status`)",
            RecommendedAction::RetryWithBackoff,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> ProfileId {
        ProfileId::new("coding").unwrap()
    }

    #[test]
    fn the_session_limit_refuses_the_session_past_the_maximum() {
        // Below the maximum: admitted.
        assert!(check_session_limit(&profile(), 0, 1, BrowserScope::Session).is_ok());
        assert!(check_session_limit(&profile(), 2, 3, BrowserScope::Session).is_ok());
        // At the default maximum of 1, a second live principal is a retryable conflict.
        let refused = check_session_limit(&profile(), 1, 1, BrowserScope::Session).unwrap_err();
        assert_eq!(refused.code, ErrorCode::Conflict);
        assert_eq!(
            refused.recommended_action,
            RecommendedAction::RetryWithBackoff
        );
        assert!(
            refused
                .message
                .contains("reached max_concurrent_sessions (1)"),
            "{}",
            refused.message
        );
        assert!(refused.message.contains("coding"));
        // Over the maximum (a lowered limit after a reload) stays refused.
        assert!(check_session_limit(&profile(), 5, 3, BrowserScope::Profile).is_err());
    }

    #[test]
    fn zero_means_unlimited_only_for_profile_scope() {
        assert!(check_session_limit(&profile(), 1000, 0, BrowserScope::Profile).is_ok());
        // Any other scope with 0 admits nobody (config validation rejects it first).
        assert!(check_session_limit(&profile(), 0, 0, BrowserScope::Session).is_err());
    }

    #[test]
    fn a_pipe_mode_browser_user_must_differ_from_principal_daemon_and_root() {
        let check = |browser, principal, daemon| {
            validate_pipe_browser_user("coding", true, false, browser, principal, daemon)
        };
        assert!(check(2000, 1000, 500).is_ok());

        let same_as_principal = check(1000, 1000, 500).unwrap_err();
        assert!(
            same_as_principal.contains("must differ from principal uid 1000"),
            "{same_as_principal}"
        );
        let same_as_daemon = check(500, 1000, 500).unwrap_err();
        assert!(
            same_as_daemon.contains("must differ from daemon uid 500"),
            "{same_as_daemon}"
        );
        let root = check(0, 1000, 500).unwrap_err();
        assert!(root.contains("must not be root"), "{root}");
        // The principal check wins when several apply.
        assert!(check(1000, 1000, 1000).unwrap_err().contains("principal"));
    }

    #[test]
    fn the_browser_user_rules_apply_only_to_a_root_daemon_in_pipe_mode() {
        // Port mode trusts the agent, so the browser user may equal the principal.
        assert!(validate_pipe_browser_user("p", true, true, 1000, 1000, 500).is_ok());
        // A non-root daemon cannot switch users at all; nothing to validate.
        assert!(validate_pipe_browser_user("p", false, false, 1000, 1000, 1000).is_ok());
    }

    #[test]
    fn browser_control_is_refused_for_a_port_mode_lease_only() {
        let refused = check_browser_control_available(Some(false)).unwrap_err();
        assert_eq!(refused.code, ErrorCode::Forbidden);
        assert!(
            refused.message.contains("unavailable in port mode"),
            "{}",
            refused.message
        );
        // The refusal does not name the endpoint.
        assert!(!refused.message.contains("127.0.0.1"));
        // Pipe-mode leases, and a lease the manager no longer knows, fall through to the usual
        // handling.
        assert!(check_browser_control_available(Some(true)).is_ok());
        assert!(check_browser_control_available(None).is_ok());
    }

    #[test]
    fn a_direct_cdp_caller_is_refused_in_pipe_mode_only() {
        let refused = check_ensure_browser_mode(CdpExposeMode::Pipe, true).unwrap_err();
        assert_eq!(refused.code, ErrorCode::Forbidden);
        assert!(
            refused
                .message
                .contains("requires browser_cdp_expose = 'port'"),
            "{}",
            refused.message
        );
        assert!(refused.message.contains("browser-control"));
        // `agent browser` (no direct CDP) is served in both modes, and port mode serves everyone.
        assert!(check_ensure_browser_mode(CdpExposeMode::Pipe, false).is_ok());
        assert!(check_ensure_browser_mode(CdpExposeMode::Port, false).is_ok());
        assert!(check_ensure_browser_mode(CdpExposeMode::Port, true).is_ok());
    }

    #[test]
    fn a_lease_is_reachable_through_the_channel_of_the_mode_in_force() {
        let endpoint = || Some("ws://127.0.0.1:1/devtools/browser/x".to_string());
        // Port mode: the endpoint, nothing else.
        assert_eq!(
            cdp_access(CdpExposeMode::Port, endpoint(), Some(false)),
            Some(endpoint())
        );
        assert_eq!(cdp_access(CdpExposeMode::Port, None, Some(true)), None);
        // Pipe mode: the pipes, no endpoint.
        assert_eq!(
            cdp_access(CdpExposeMode::Pipe, None, Some(true)),
            Some(None)
        );
        assert_eq!(
            cdp_access(CdpExposeMode::Pipe, endpoint(), Some(false)),
            None
        );
        assert_eq!(cdp_access(CdpExposeMode::Pipe, None, None), None);
    }

    #[test]
    fn browser_control_needs_an_attached_or_reconnecting_worker() {
        assert!(check_control_interception(Some(InterceptionState::Attached)).is_ok());
        assert!(check_control_interception(Some(InterceptionState::Pending)).is_ok());
        for state in [Some(InterceptionState::Degraded), None] {
            let refused = check_control_interception(state).unwrap_err();
            assert_eq!(refused.code, ErrorCode::Conflict);
            assert_eq!(
                refused.recommended_action,
                RecommendedAction::RetryWithBackoff
            );
            assert!(refused.message.contains("degraded"), "{}", refused.message);
        }
    }
}
