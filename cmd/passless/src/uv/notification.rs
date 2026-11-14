//! Notification-based User Verification Provider
//!
//! Uses desktop notifications for user verification.
//! This is the fallback provider when no biometric methods are available.

use super::{
    UserVerificationProvider, VerificationContext, VerificationError, VerificationResult, priority,
};

use log::debug;

use std::sync::{Arc, Mutex};

use notify_rust::{Notification, Timeout};

/// Check if the notification server requires special handling
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
                    debug!("Detected {} - using default action mode", server_name);
                    true
                }
                _ => false,
            }
        })
        .unwrap_or_else(|e| {
            debug!("Failed to get notification server info: {}", e);
            false
        })
}

/// Notification-based user verification provider
pub struct NotificationProvider {
    #[allow(dead_code)]
    timeout_seconds: u32,
}

impl NotificationProvider {
    /// Create a new notification provider
    pub fn new(timeout_seconds: u32) -> Self {
        Self { timeout_seconds }
    }

    /// Create a provider with timeout
    pub fn from_config(timeout_seconds: u32) -> Box<dyn UserVerificationProvider> {
        Box::new(Self::new(timeout_seconds))
    }

    /// Show verification notification and wait for response
    fn show_notification(
        &self,
        context: &VerificationContext,
    ) -> Result<VerificationResult, VerificationError> {
        let mut message = format!("Operation: {}", context.operation);
        if let Some(rp) = &context.relying_party {
            message.push_str(&format!("\nRelying Party: {}", rp));
        }
        if let Some(user) = &context.user {
            message.push_str(&format!("\nUser: {}", user));
        }

        debug!("Showing user verification notification");

        let default_means_accept = requires_default_action();
        let action_result = Arc::new(Mutex::new(None));
        let action_result_clone = action_result.clone();

        let mut notification = Notification::new();
        notification
            .summary("User Verification Required")
            .body(&message)
            .icon("security-high")
            .timeout(Timeout::Milliseconds(context.timeout_seconds * 1000));

        if default_means_accept {
            notification.action("default", "");
        } else {
            notification.action("approve", "Accept");
            notification.action("deny", "Deny");
        }

        let handle = notification.show().map_err(|e| {
            VerificationError::DeviceError(format!("Failed to show notification: {}", e))
        })?;

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

        let accepted = match action.as_str() {
            "approve" => true,
            "deny" => false,
            "default" => default_means_accept,
            "__closed" => false,
            other => {
                debug!("Unknown action '{}' - treating as denied", other);
                false
            }
        };

        if accepted {
            debug!("User verification accepted via notification");
            Ok(VerificationResult::Accepted)
        } else {
            debug!("User verification denied or notification closed");
            Ok(VerificationResult::Denied)
        }
    }
}

impl UserVerificationProvider for NotificationProvider {
    fn name(&self) -> &str {
        "notification"
    }

    fn available(&self) -> bool {
        true
    }

    fn verify(
        &self,
        context: &VerificationContext,
    ) -> Result<VerificationResult, VerificationError> {
        self.show_notification(context)
    }

    fn priority(&self) -> u8 {
        priority::NOTIFICATION
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notification_provider_always_available() {
        let provider = NotificationProvider::new(30);
        assert!(provider.available());
    }

    #[test]
    fn test_notification_provider_priority() {
        let provider = NotificationProvider::new(30);
        assert_eq!(provider.priority(), priority::NOTIFICATION);
    }

    #[test]
    fn test_notification_provider_name() {
        let provider = NotificationProvider::new(30);
        assert_eq!(provider.name(), "notification");
    }
}
