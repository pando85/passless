//! The questions the human authenticator asks the user, behind one seam.
//!
//! Production uses [`DesktopPrompts`] (desktop notifications). Tests install a scripted
//! implementation, so in-process tests never open a notification and never depend on
//! environment variables.

use crate::notification::{
    NotificationResult, interaction_mode_is_automatic, show_credential_protection_notification,
    show_user_presence_notification, show_verification_notification,
};

use std::sync::{Arc, Mutex, MutexGuard};

/// Questions asked of the user on the human CTAP path.
pub trait HumanPrompts: Send {
    /// CTAP user presence (touch).
    fn user_presence(
        &mut self,
        operation: &str,
        relying_party: Option<&str>,
        user: Option<&str>,
        timeout_seconds: u32,
    ) -> Result<NotificationResult, String>;

    /// CTAP built-in user verification. Only `Denied` may count as a failed attempt: closing
    /// the prompt or letting it time out is `Dismissed`.
    fn user_verification(
        &mut self,
        operation: &str,
        relying_party: Option<&str>,
        user: Option<&str>,
        timeout_seconds: u32,
    ) -> Result<NotificationResult, String>;

    /// Consent to lower the protection of stored credentials. `body` is daemon-derived text.
    /// Closing the prompt or letting it time out is `Dismissed`, which refuses just like `Denied`.
    fn confirm_credential_protection_lowering(
        &mut self,
        summary: &str,
        body: &str,
        timeout_seconds: u32,
    ) -> Result<NotificationResult, String>;

    /// Whether prompts are approved without user interaction
    /// (`PASSLESS_INTERACTION_MODE=automatic`). `Err` when the setting cannot be read.
    fn interaction_is_automatic(&self) -> Result<bool, String>;
}

/// Desktop notifications.
pub struct DesktopPrompts;

impl HumanPrompts for DesktopPrompts {
    fn user_presence(
        &mut self,
        operation: &str,
        relying_party: Option<&str>,
        user: Option<&str>,
        timeout_seconds: u32,
    ) -> Result<NotificationResult, String> {
        show_user_presence_notification(operation, relying_party, user, timeout_seconds)
    }

    fn user_verification(
        &mut self,
        operation: &str,
        relying_party: Option<&str>,
        user: Option<&str>,
        timeout_seconds: u32,
    ) -> Result<NotificationResult, String> {
        show_verification_notification(operation, relying_party, user, timeout_seconds)
    }

    fn confirm_credential_protection_lowering(
        &mut self,
        summary: &str,
        body: &str,
        timeout_seconds: u32,
    ) -> Result<NotificationResult, String> {
        // The E2E harness (debug builds only) auto-accepts every prompt it cannot show.
        #[cfg(debug_assertions)]
        {
            if std::env::var("PASSLESS_E2E_AUTO_ACCEPT_UV").is_ok() {
                return Ok(NotificationResult::Accepted);
            }
        }
        show_credential_protection_notification(summary, body, timeout_seconds)
    }

    fn interaction_is_automatic(&self) -> Result<bool, String> {
        interaction_mode_is_automatic()
    }
}

/// Shared by the callbacks and the service, so a test can swap the implementation.
pub type PromptHandle = Arc<Mutex<Box<dyn HumanPrompts>>>;

/// Prompts that show desktop notifications.
pub fn desktop_prompts() -> PromptHandle {
    Arc::new(Mutex::new(Box::new(DesktopPrompts)))
}

/// Lock the prompts, recovering a poisoned lock (a panicked prompt must not disable the path).
pub fn lock_prompts(handle: &PromptHandle) -> MutexGuard<'_, Box<dyn HumanPrompts>> {
    handle
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
