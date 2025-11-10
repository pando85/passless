//! Desktop notification handling for user verification
//!
//! This module provides desktop notification support with compatibility for
//! different notification servers (notify-osd, mako, etc.).

use log::{debug, info, warn};
use notify_rust::{Notification, Timeout};
use std::sync::{Arc, Mutex};

/// Result of user verification via notification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationResult {
    /// User approved the operation
    Accepted,
    /// User denied the operation
    Denied,
}

/// Check if the notification server requires special handling
///
/// Some servers (notify-osd 1.0, mako 0.0.0) don't support action buttons properly
/// and require using a "default" action instead.
fn requires_default_action() -> bool {
    notify_rust::get_server_information()
        .map(|info| {
            let server_name = info.name.to_lowercase();
            debug!(
                "Notification server: {} (version: {})",
                info.name, info.version
            );

            match (server_name.as_str(), info.version.as_str()) {
                ("notify-osd", "1.0") | ("mako", "0.0.0") => {
                    info!("Detected {} - using default action mode", server_name);
                    true
                }
                _ => false,
            }
        })
        .unwrap_or_else(|e| {
            warn!("Failed to get notification server info: {}", e);
            false
        })
}

/// Show a user verification notification and wait for response
///
/// # Arguments
///
/// * `operation` - Description of the operation (e.g., "Registration", "Authentication")
/// * `relying_party` - Optional relying party identifier
/// * `user` - Optional user identifier
///
/// # Returns
///
/// Result indicating whether the user accepted or denied the operation,
/// or an error if the notification failed to show.
pub fn show_verification_notification(
    operation: &str,
    relying_party: Option<&str>,
    user: Option<&str>,
) -> Result<NotificationResult, String> {
    // Build notification message
    let mut message = format!("Operation: {}", operation);
    if let Some(rp) = relying_party {
        message.push_str(&format!("\nRelying Party: {}", rp));
    }
    if let Some(user) = user {
        message.push_str(&format!("\nUser: {}", user));
    }

    info!("Showing user verification notification");

    // Check if we need to use default action mode
    let default_means_user_present = requires_default_action();

    // Shared state to capture the action
    let action_result = Arc::new(Mutex::new(None));
    let action_result_clone = action_result.clone();

    // Build notification with appropriate actions
    let mut notification = Notification::new();
    notification
        .summary("🔒 User Verification Required")
        .body(&message)
        .icon("security-high")
        .timeout(Timeout::Never); // Wait for user action

    if default_means_user_present {
        // For servers that don't support action buttons properly,
        // use a single "default" action that accepts on click
        notification.action("default", "");
    } else {
        // For servers with proper action button support
        notification.action("approve", "Accept");
        notification.action("deny", "Deny");
    }

    // Show the notification
    let handle = notification
        .show()
        .map_err(|e| format!("Failed to show notification: {}", e))?;

    // Wait for user action
    handle.wait_for_action(|action| {
        debug!("User action received: {}", action);
        let mut result = action_result_clone.lock().unwrap();
        *result = Some(action.to_string());
    });

    // Process the action taken
    let action = action_result
        .lock()
        .unwrap()
        .clone()
        .unwrap_or_else(|| "__closed".to_string());

    let user_present = match action.as_str() {
        "approve" => true,
        "deny" => false,
        "default" => default_means_user_present,
        "__closed" => false,
        other => {
            debug!("Unknown action '{}' - treating as denied", other);
            false
        }
    };

    if user_present {
        info!("User verification accepted via notification");
        Ok(NotificationResult::Accepted)
    } else {
        info!("User verification denied or notification closed");
        Ok(NotificationResult::Denied)
    }
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
    fn test_requires_default_action_doesnt_panic() {
        // Just ensure the function doesn't panic
        let _ = requires_default_action();
    }
}
