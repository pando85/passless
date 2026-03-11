//! Desktop notification handling for user verification
//!
//! This module provides desktop notification support with compatibility for
//! different notification servers (notify-osd, mako, etc.).

use std::sync::{Arc, Mutex};

use log::{debug, info, warn};
use notify_rust::{Notification, Timeout};

/// Result of user verification via notification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationResult {
    /// User approved the operation
    Accepted,
    /// User denied the operation
    Denied,
}

/// Result of a yes/no question via notification
pub type YesNoResult = NotificationResult;

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
pub fn show_verification_notification(
    operation: &str,
    relying_party: Option<&str>,
    user: Option<&str>,
    timeout_seconds: u32,
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
        .timeout(Timeout::Milliseconds(timeout_seconds * 1000));

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
        let mut result = action_result_clone
            .lock()
            .expect("Failed to lock action result");
        *result = Some(action.to_string());
    });

    // Process the action taken
    let action = action_result
        .lock()
        .expect("Failed to lock action result")
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

    // Check if we need to use default action mode
    let default_means_yes = requires_default_action();

    // Shared state to capture the action
    let action_result = Arc::new(Mutex::new(None));
    let action_result_clone = action_result.clone();

    // Build notification with appropriate actions
    let mut notification = Notification::new();
    notification
        .summary(title)
        .body(question)
        .icon("dialog-question")
        .timeout(Timeout::Never); // Wait for user action

    if default_means_yes {
        // For servers that don't support action buttons properly
        notification.action("default", "");
    } else {
        // For servers with proper action button support
        notification.action("yes", "Yes");
        notification.action("no", "No");
    }

    // Show the notification
    let handle = notification
        .show()
        .map_err(|e| format!("Failed to show notification: {}", e))?;

    // Wait for user action
    handle.wait_for_action(|action| {
        debug!("User action received: {}", action);
        let mut result = action_result_clone
            .lock()
            .expect("Failed to lock action result");
        *result = Some(action.to_string());
    });

    // Process the action taken
    let action = action_result
        .lock()
        .expect("Failed to lock action result")
        .clone()
        .unwrap_or_else(|| "__closed".to_string());

    let user_said_yes = match action.as_str() {
        "yes" => true,
        "no" => false,
        "default" => default_means_yes,
        "__closed" => false,
        other => {
            debug!("Unknown action '{}' - treating as no", other);
            false
        }
    };

    if user_said_yes {
        info!("User answered yes");
        Ok(YesNoResult::Accepted)
    } else {
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

pub fn prompt_pin(title: &str, message: &str) -> Result<Option<String>, String> {
    #[cfg(debug_assertions)]
    {
        if let Ok(pin) = std::env::var("PASSLESS_TEST_PIN") {
            info!("Using PIN from environment variable (debug mode)");
            return Ok(Some(pin));
        }
    }

    if let Some(pin) = prompt_pin_zenity(title, message)? {
        return Ok(Some(pin));
    }

    if let Some(pin) = prompt_pin_pinentry(title, message)? {
        return Ok(Some(pin));
    }

    if atty::is(atty::Stream::Stdin) {
        prompt_pin_terminal(title, message)
    } else {
        Err("No PIN input method available. Install zenity or pinentry.".to_string())
    }
}

fn prompt_pin_zenity(title: &str, message: &str) -> Result<Option<String>, String> {
    let output = std::process::Command::new("zenity")
        .args([
            "--entry",
            "--hide-text",
            "--title",
            title,
            "--text",
            message,
        ])
        .output();

    match output {
        Ok(output) => {
            if output.status.success() {
                let pin = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if pin.is_empty() {
                    Ok(None)
                } else {
                    info!("PIN entered via zenity");
                    Ok(Some(pin))
                }
            } else {
                debug!("zenity dialog cancelled");
                Ok(None)
            }
        }
        Err(e) => {
            debug!("zenity not available: {}", e);
            Ok(None)
        }
    }
}

fn prompt_pin_pinentry(title: &str, message: &str) -> Result<Option<String>, String> {
    let pinentry_commands = format!(
        "SETTITLE {}\nSETDESC {}\nSETPROMPT PIN:\nGETPIN\n",
        title, message
    );

    let pinentry_programs = [
        "pinentry-gnome3",
        "pinentry-gtk-2",
        "pinentry-qt",
        "pinentry-curses",
        "pinentry",
    ];

    for program in &pinentry_programs {
        let output = std::process::Command::new(program)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn();

        match output {
            Ok(mut child) => {
                use std::io::Write;
                if let Some(stdin) = child.stdin.as_mut() {
                    if let Err(e) = stdin.write_all(pinentry_commands.as_bytes()) {
                        debug!("Failed to write to {}: {}", program, e);
                        continue;
                    }
                }

                match child.wait_with_output() {
                    Ok(output) => {
                        let response = String::from_utf8_lossy(&output.stdout);
                        for line in response.lines() {
                            if line.starts_with("D ") {
                                let pin = line[2..].to_string();
                                info!("PIN entered via {}", program);
                                return Ok(Some(pin));
                            }
                            if line == "ERR 83886179 Operation cancelled" {
                                debug!("{} cancelled", program);
                                return Ok(None);
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Failed to read from {}: {}", program, e);
                    }
                }
            }
            Err(e) => {
                debug!("{} not available: {}", program, e);
            }
        }
    }

    Ok(None)
}

fn prompt_pin_terminal(title: &str, message: &str) -> Result<Option<String>, String> {
    use rpassword::read_password;

    println!("\n{}", title);
    println!("{}\n", message);
    print!("Enter PIN: ");

    match read_password() {
        Ok(pin) => {
            if pin.is_empty() {
                Ok(None)
            } else {
                info!("PIN entered via terminal");
                Ok(Some(pin))
            }
        }
        Err(e) => {
            warn!("Failed to read PIN from terminal: {}", e);
            Err(format!("Failed to read PIN: {}", e))
        }
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
