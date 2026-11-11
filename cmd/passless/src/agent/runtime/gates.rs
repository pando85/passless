//! Pure admission gates of the runtime, kept apart from the handlers so that each refusal is
//! unit-tested on its own (ADR 0014 sections 4.2 and 5: `max_concurrent_sessions`, the pipe-mode
//! browser user, `browser-control` in port mode).

use passless_core::agent::ProfileId;
use passless_core::agent::config::BrowserScope;
use passless_core::agent::protocol::{ErrorCode, ProtocolError, RecommendedAction};

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
}
