//! Desktop notification handling for user presence and verification
//!
//! This module provides desktop notification support with compatibility for
//! different notification servers (notify-osd, mako, Dunst, etc.).

use std::sync::{Arc, Mutex};

use log::{debug, info, warn};
use notify_rust::{Notification, Timeout, Urgency};

/// Result of user interaction via notification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationResult {
    /// User approved the operation
    Accepted,
    /// User denied the operation
    Denied,
}

/// Result of a yes/no question via notification
pub type YesNoResult = NotificationResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PromptKind {
    UserPresence,
    UserVerification,
    YesNo,
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
    debug_assert!(prompt_kind != PromptKind::YesNo);

    let action_mode = notification_action_mode(prompt_kind);

    let mut message = format!("Operation: {}", operation);
    if let Some(rp) = relying_party {
        message.push_str(&format!("\nRelying Party: {}", rp));
    }
    if let Some(user) = user {
        message.push_str(&format!("\nUser: {}", user));
    }

    if action_mode == NotificationActionMode::DunstDefault {
        message.push_str(
            "\n\nDunst: confirm by invoking this notification's action \
             (middle-click by default). Closing the notification denies the request.",
        );
    }

    let summary = match prompt_kind {
        PromptKind::UserPresence => "👆 User Presence Required",
        PromptKind::UserVerification => "🔒 User Verification Required",
        PromptKind::YesNo => unreachable!("yes/no prompts use show_yes_no_notification"),
    };

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
        .unwrap_or_else(|| "__closed".to_string());

    if action_is_accepted(&action, "approve", action_mode) {
        info!("Notification accepted");
        Ok(NotificationResult::Accepted)
    } else {
        if action != "deny" && action != "__closed" {
            debug!("Unknown action '{}' - treating as denied", action);
        }
        info!("Notification denied or closed");
        Ok(NotificationResult::Denied)
    }
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
/// Result indicating whether the user answered yes (Accepted) or no (Denied)
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
        .unwrap_or_else(|| "__closed".to_string());

    if action_is_accepted(&action, "yes", action_mode) {
        info!("User answered yes");
        Ok(YesNoResult::Accepted)
    } else {
        if action != "no" && action != "__closed" {
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
    }

    #[test]
    fn test_legacy_default_action_servers_are_preserved() {
        for (name, version) in [
            ("notify-osd", "1.0"),
            ("mako", "0.0.0"),
            ("quickshell", ""),
        ] {
            for prompt_kind in [
                PromptKind::UserPresence,
                PromptKind::UserVerification,
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

    #[test]
    fn test_notification_action_mode_doesnt_panic() {
        let _ = notification_action_mode(PromptKind::UserPresence);
    }
}
