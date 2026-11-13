//! Desktop notification handling for user presence and verification
//!
//! This module provides desktop notification support with compatibility for
//! different notification servers (notify-osd, mako, Dunst, etc.).

use std::sync::{Arc, Mutex};

use log::{debug, info, warn};
use notify_rust::{Notification, Timeout, Urgency};

const INTERACTION_MODE_ENV: &str = "PASSLESS_INTERACTION_MODE";

/// Result of user interaction via notification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationResult {
    /// User approved the operation
    Accepted,
    /// User explicitly refused the operation (clicked Deny) or answered with an action the
    /// prompt never offered
    Denied,
    /// The notification was closed without an answer: the user dismissed it, or it timed out.
    /// The operation is still refused, but nobody refused it, so it must not be counted as a
    /// failed verification attempt.
    Dismissed,
}

/// Result of a yes/no question via notification
///
/// Closing the notification answers no: these questions have no retry budget to protect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YesNoResult {
    Accepted,
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PromptKind {
    UserPresence,
    UserVerification,
    /// A dedicated consent prompt for lowering credential protection. Never auto-approved.
    CredentialProtection,
    YesNo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InteractionMode {
    Desktop,
    Automatic,
}

fn interaction_mode_from_value(value: Option<&str>) -> Result<InteractionMode, String> {
    let Some(value) = value else {
        return Ok(InteractionMode::Desktop);
    };

    match value.trim().to_ascii_lowercase().as_str() {
        "desktop" => Ok(InteractionMode::Desktop),
        "automatic" => Ok(InteractionMode::Automatic),
        other => Err(format!(
            "invalid {} value '{}'; expected 'desktop' or 'automatic'",
            INTERACTION_MODE_ENV, other
        )),
    }
}

fn configured_interaction_mode() -> Result<InteractionMode, String> {
    match std::env::var(INTERACTION_MODE_ENV) {
        Ok(value) => interaction_mode_from_value(Some(&value)),
        Err(std::env::VarError::NotPresent) => interaction_mode_from_value(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(format!("{} must contain valid UTF-8", INTERACTION_MODE_ENV))
        }
    }
}

/// Whether `PASSLESS_INTERACTION_MODE=automatic` makes the human path approve its prompts
/// without user interaction. The agent subsystem refuses to start in that mode unless it is
/// acknowledged (ADR 0014 section 7, R19). An invalid value is not automatic: the human path then
/// fails every prompt instead of approving it.
#[cfg(feature = "agent")]
pub fn human_path_is_automatic() -> bool {
    matches!(
        configured_interaction_mode(),
        Ok(InteractionMode::Automatic)
    )
}

/// Whether `PASSLESS_INTERACTION_MODE=automatic` makes the human path approve its prompts
/// without user interaction. `Err` for an unparsable value: callers must then refuse.
pub fn interaction_mode_is_automatic() -> Result<bool, String> {
    Ok(configured_interaction_mode()? == InteractionMode::Automatic)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotificationActionMode {
    Explicit,
    Default,
    DunstDefault,
}

impl NotificationActionMode {
    fn uses_default_action(self) -> bool {
        matches!(self, Self::Default | Self::DunstDefault)
    }
}

/// Determine how actions should be exposed for a notification server.
///
/// Legacy compatibility servers use a default action for all prompt types.
/// Dunst gets that behavior only for CTAP user presence: its actions are
/// supported but normally invoked through Dunst's interaction model instead
/// of visible buttons. User verification deliberately keeps explicit actions
/// so the UP compatibility path cannot silently weaken UV semantics.
fn action_mode_for_server(
    server_name: &str,
    server_version: &str,
    prompt_kind: PromptKind,
) -> NotificationActionMode {
    let server_name = server_name.to_lowercase();

    match (server_name.as_str(), server_version) {
        ("notify-osd", "1.0") | ("mako", "0.0.0") | ("quickshell", "") => {
            NotificationActionMode::Default
        }
        ("dunst", _) if prompt_kind == PromptKind::UserPresence => {
            NotificationActionMode::DunstDefault
        }
        _ => NotificationActionMode::Explicit,
    }
}

fn notification_action_mode(prompt_kind: PromptKind) -> NotificationActionMode {
    notify_rust::get_server_information()
        .map(|server| {
            let mode = action_mode_for_server(&server.name, &server.version, prompt_kind);
            debug!(
                "Notification server: {} (version: {})",
                server.name, server.version
            );

            match mode {
                NotificationActionMode::Default => {
                    info!("Detected {} - using default action mode", server.name);
                }
                NotificationActionMode::DunstDefault => {
                    info!("Detected Dunst - using UP-specific default action mode");
                }
                NotificationActionMode::Explicit => {}
            }

            mode
        })
        .unwrap_or_else(|e| {
            warn!("Failed to get notification server info: {}", e);
            NotificationActionMode::Explicit
        })
}

fn action_is_accepted(
    action: &str,
    affirmative_action: &str,
    action_mode: NotificationActionMode,
) -> bool {
    if action == affirmative_action {
        return true;
    }

    action == "default" && action_mode.uses_default_action()
}

fn show_confirmation_notification(
    operation: &str,
    relying_party: Option<&str>,
    user: Option<&str>,
    timeout_seconds: u32,
    prompt_kind: PromptKind,
) -> Result<NotificationResult, String> {
    debug_assert!(!matches!(
        prompt_kind,
        PromptKind::YesNo | PromptKind::CredentialProtection
    ));

    if configured_interaction_mode()? == InteractionMode::Automatic {
        warn!(
            "{}=automatic: auto-approving {:?} without user interaction (rp={})",
            INTERACTION_MODE_ENV,
            prompt_kind,
            relying_party.unwrap_or("<unknown>")
        );
        return Ok(NotificationResult::Accepted);
    }

    let mut message = format!("Operation: {}", operation);
    if let Some(rp) = relying_party {
        message.push_str(&format!("\nRelying Party: {}", rp));
    }
    if let Some(user) = user {
        message.push_str(&format!("\nUser: {}", user));
    }

    let summary = match prompt_kind {
        PromptKind::UserPresence => "👆 User Presence Required",
        PromptKind::UserVerification => "🔒 User Verification Required",
        PromptKind::CredentialProtection | PromptKind::YesNo => {
            unreachable!("handled by their own functions")
        }
    };

    show_prompt(summary, message, timeout_seconds, prompt_kind)
}

/// Name `notify-rust` gives the action reported when a notification is closed without an answer
/// (dismissed by the user or timed out).
const CLOSED_ACTION: &str = "__closed";

/// Classify the action a notification reported. Anything but the affirmative action refuses;
/// only an explicit `deny` (or an action the prompt never offered) is a denial, a close is not.
fn answer_from_action(
    action: &str,
    affirmative_action: &str,
    action_mode: NotificationActionMode,
) -> NotificationResult {
    if action_is_accepted(action, affirmative_action, action_mode) {
        NotificationResult::Accepted
    } else if action == CLOSED_ACTION {
        NotificationResult::Dismissed
    } else {
        if action != "deny" {
            debug!("Unknown action '{}' - treating as denied", action);
        }
        NotificationResult::Denied
    }
}

/// Show `message` under `summary` with Accept and Deny actions and wait for the answer.
/// Clicking Deny denies. Closing the notification or letting it time out is `Dismissed`:
/// the operation is refused, but nobody refused it.
fn show_prompt(
    summary: &str,
    mut message: String,
    timeout_seconds: u32,
    prompt_kind: PromptKind,
) -> Result<NotificationResult, String> {
    let action_mode = notification_action_mode(prompt_kind);

    if action_mode == NotificationActionMode::DunstDefault {
        message.push_str(
            "\n\nDunst: confirm by invoking this notification's action \
             (middle-click by default). Closing the notification refuses the request.",
        );
    }

    info!("Showing {} notification", summary);

    let action_result = Arc::new(Mutex::new(None));
    let action_result_clone = action_result.clone();

    let mut notification = Notification::new();
    notification
        .summary(summary)
        .body(&message)
        .icon("security-high")
        .timeout(Timeout::Milliseconds(timeout_seconds * 1000))
        .urgency(Urgency::Critical);

    if action_mode.uses_default_action() {
        notification.action("default", "");
    } else {
        notification.action("approve", "Accept");
        notification.action("deny", "Deny");
    }

    let handle = notification
        .show()
        .map_err(|e| format!("Failed to show notification: {}", e))?;

    handle.wait_for_action(|action| {
        debug!("User action received: {}", action);
        let mut result = action_result_clone
            .lock()
            .expect("Failed to lock action result");
        *result = Some(action.to_string());
    });

    let action = action_result
        .lock()
        .expect("Failed to lock action result")
        .clone()
        .unwrap_or_else(|| CLOSED_ACTION.to_string());

    let answer = answer_from_action(&action, "approve", action_mode);
    match answer {
        NotificationResult::Accepted => info!("Notification accepted"),
        NotificationResult::Denied => info!("Notification denied"),
        NotificationResult::Dismissed => info!("Notification closed or timed out"),
    }
    Ok(answer)
}

/// Ask the human to confirm lowering the protection of stored credentials.
///
/// `body` must be derived by the daemon from its own storage, never from the client request.
/// This is a dedicated consent question: it is never auto-approved, not even with
/// `PASSLESS_INTERACTION_MODE=automatic` (it is denied there), and closing the notification or
/// letting it time out denies.
pub fn show_credential_protection_notification(
    summary: &str,
    body: &str,
    timeout_seconds: u32,
) -> Result<NotificationResult, String> {
    if configured_interaction_mode()? == InteractionMode::Automatic {
        warn!(
            "{}=automatic: denying {:?} instead of auto-approving it",
            INTERACTION_MODE_ENV,
            PromptKind::CredentialProtection
        );
        return Ok(NotificationResult::Denied);
    }
    show_prompt(
        summary,
        body.to_string(),
        timeout_seconds,
        PromptKind::CredentialProtection,
    )
}

/// Show a CTAP user-presence notification and wait for response.
///
/// User presence is a consent gesture (for example, touching a hardware key),
/// so notification activation may be used as the explicit gesture on daemons
/// such as Dunst that do not expose action buttons directly.
pub fn show_user_presence_notification(
    operation: &str,
    relying_party: Option<&str>,
    user: Option<&str>,
    timeout_seconds: u32,
) -> Result<NotificationResult, String> {
    show_confirmation_notification(
        operation,
        relying_party,
        user,
        timeout_seconds,
        PromptKind::UserPresence,
    )
}

/// Show a user-verification notification and wait for response.
///
/// Unlike user presence, Dunst activation is not treated as verification: the
/// user must invoke the explicit Accept action through Dunst's action UI.
pub fn show_verification_notification(
    operation: &str,
    relying_party: Option<&str>,
    user: Option<&str>,
    timeout_seconds: u32,
) -> Result<NotificationResult, String> {
    show_confirmation_notification(
        operation,
        relying_party,
        user,
        timeout_seconds,
        PromptKind::UserVerification,
    )
}

/// Show a yes/no question notification and wait for response
///
/// # Arguments
///
/// * `title` - Title of the notification
/// * `question` - The question to ask
///
/// # Returns
///
/// Result indicating whether the user answered yes (Accepted) or no or closed it (Denied)
pub fn show_yes_no_notification(title: &str, question: &str) -> Result<YesNoResult, String> {
    info!("Showing yes/no notification: {}", title);

    let action_mode = notification_action_mode(PromptKind::YesNo);

    let action_result = Arc::new(Mutex::new(None));
    let action_result_clone = action_result.clone();

    let mut notification = Notification::new();
    notification
        .summary(title)
        .body(question)
        .icon("dialog-question")
        .timeout(Timeout::Never)
        .urgency(Urgency::Critical);

    if action_mode.uses_default_action() {
        notification.action("default", "");
    } else {
        notification.action("yes", "Yes");
        notification.action("no", "No");
    }

    let handle = notification
        .show()
        .map_err(|e| format!("Failed to show notification: {}", e))?;

    handle.wait_for_action(|action| {
        debug!("User action received: {}", action);
        let mut result = action_result_clone
            .lock()
            .expect("Failed to lock action result");
        *result = Some(action.to_string());
    });

    let action = action_result
        .lock()
        .expect("Failed to lock action result")
        .clone()
        .unwrap_or_else(|| CLOSED_ACTION.to_string());

    if action_is_accepted(&action, "yes", action_mode) {
        info!("User answered yes");
        Ok(YesNoResult::Accepted)
    } else {
        if action != "no" && action != CLOSED_ACTION {
            debug!("Unknown action '{}' - treating as no", action);
        }
        info!("User answered no or closed notification");
        Ok(YesNoResult::Denied)
    }
}

/// Show an informational notification (no user response needed)
///
/// # Arguments
///
/// * `title` - Title of the notification
/// * `message` - The message to display
///
/// # Returns
///
/// Ok if notification was shown successfully
pub fn show_info_notification(title: &str, message: &str) -> Result<(), String> {
    info!("Showing info notification: {}", title);

    Notification::new()
        .summary(title)
        .body(message)
        .icon("dialog-information")
        .timeout(Timeout::Milliseconds(5000))
        .show()
        .map_err(|e| format!("Failed to show notification: {}", e))?;

    Ok(())
}

/// Show an error notification
///
/// # Arguments
///
/// * `title` - Title of the notification
/// * `error_message` - The error message to display
///
/// # Returns
///
/// Ok if notification was shown successfully
pub fn show_error_notification(title: &str, error_message: &str) -> Result<(), String> {
    warn!("Showing error notification: {}", title);

    Notification::new()
        .summary(title)
        .body(error_message)
        .icon("dialog-error")
        .timeout(Timeout::Milliseconds(8000))
        .show()
        .map_err(|e| format!("Failed to show notification: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notification_result_equality() {
        assert_eq!(NotificationResult::Accepted, NotificationResult::Accepted);
        assert_eq!(NotificationResult::Denied, NotificationResult::Denied);
        assert_ne!(NotificationResult::Accepted, NotificationResult::Denied);
        assert_ne!(NotificationResult::Denied, NotificationResult::Dismissed);
    }

    #[test]
    fn test_only_an_explicit_deny_is_a_denial() {
        let mode = NotificationActionMode::Explicit;
        let answer = |action: &str| answer_from_action(action, "approve", mode);

        assert_eq!(answer("approve"), NotificationResult::Accepted);
        assert_eq!(answer("deny"), NotificationResult::Denied);
        // Dismissed by the user or timed out: neither accepted nor denied.
        assert_eq!(answer("__closed"), NotificationResult::Dismissed);
        // An action the prompt never offered stays a denial, so it fails closed and counts.
        assert_eq!(answer("whatever"), NotificationResult::Denied);
        assert_eq!(answer(""), NotificationResult::Denied);
        // "default" is only an answer on daemons that offer nothing else.
        assert_eq!(answer("default"), NotificationResult::Denied);
    }

    #[test]
    fn test_dunst_default_action_accepts_and_close_is_dismissed() {
        let mode = NotificationActionMode::DunstDefault;
        assert_eq!(
            answer_from_action("default", "approve", mode),
            NotificationResult::Accepted
        );
        assert_eq!(
            answer_from_action("__closed", "approve", mode),
            NotificationResult::Dismissed
        );
    }

    #[test]
    fn test_interaction_mode_defaults_to_desktop() {
        assert_eq!(
            interaction_mode_from_value(None).unwrap(),
            InteractionMode::Desktop
        );
        assert_eq!(
            interaction_mode_from_value(Some("desktop")).unwrap(),
            InteractionMode::Desktop
        );
    }

    #[test]
    fn test_interaction_mode_supports_explicit_automatic_mode() {
        assert_eq!(
            interaction_mode_from_value(Some("automatic")).unwrap(),
            InteractionMode::Automatic
        );
        assert_eq!(
            interaction_mode_from_value(Some(" Automatic ")).unwrap(),
            InteractionMode::Automatic
        );
    }

    #[test]
    fn test_interaction_mode_rejects_unknown_values() {
        let error = interaction_mode_from_value(Some("headless")).unwrap_err();
        assert!(error.contains(INTERACTION_MODE_ENV));
        assert!(error.contains("desktop"));
        assert!(error.contains("automatic"));
    }

    #[test]
    fn test_dunst_default_action_is_up_only() {
        assert_eq!(
            action_mode_for_server("dunst", "1.13.0", PromptKind::UserPresence),
            NotificationActionMode::DunstDefault
        );
        assert_eq!(
            action_mode_for_server("Dunst", "1.13.0", PromptKind::UserPresence),
            NotificationActionMode::DunstDefault
        );
        assert_eq!(
            action_mode_for_server("dunst", "1.13.0", PromptKind::UserVerification),
            NotificationActionMode::Explicit
        );
        assert_eq!(
            action_mode_for_server("dunst", "1.13.0", PromptKind::YesNo),
            NotificationActionMode::Explicit
        );
        assert_eq!(
            action_mode_for_server("dunst", "1.13.0", PromptKind::CredentialProtection),
            NotificationActionMode::Explicit,
            "the lowering consent needs the explicit Accept action"
        );
    }

    #[test]
    fn test_legacy_default_action_servers_are_preserved() {
        for (name, version) in [("notify-osd", "1.0"), ("mako", "0.0.0"), ("quickshell", "")] {
            for prompt_kind in [
                PromptKind::UserPresence,
                PromptKind::UserVerification,
                PromptKind::CredentialProtection,
                PromptKind::YesNo,
            ] {
                assert_eq!(
                    action_mode_for_server(name, version, prompt_kind),
                    NotificationActionMode::Default
                );
            }
        }
    }

    #[test]
    fn test_unknown_servers_use_explicit_actions() {
        assert_eq!(
            action_mode_for_server("gnome-shell", "47", PromptKind::UserPresence),
            NotificationActionMode::Explicit
        );
    }

    #[test]
    fn test_default_action_acceptance_is_mode_specific() {
        assert!(action_is_accepted(
            "default",
            "approve",
            NotificationActionMode::DunstDefault
        ));
        assert!(action_is_accepted(
            "default",
            "approve",
            NotificationActionMode::Default
        ));
        assert!(!action_is_accepted(
            "default",
            "approve",
            NotificationActionMode::Explicit
        ));
        assert!(action_is_accepted(
            "approve",
            "approve",
            NotificationActionMode::Explicit
        ));
        assert!(!action_is_accepted(
            "deny",
            "approve",
            NotificationActionMode::DunstDefault
        ));
        assert!(!action_is_accepted(
            "__closed",
            "approve",
            NotificationActionMode::DunstDefault
        ));
    }
}
