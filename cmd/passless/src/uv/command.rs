//! Command-based User Verification Provider
//!
//! Executes a user-defined command/script for verification.
//!
//! # Configuration
//!
//! The command should:
//! - Exit with code 0 for accepted
//! - Exit with non-zero code for denied
//! - Receive operation context via environment variables
//!
//! # Environment Variables
//!
//! - `PASSLESS_UV_OPERATION`: Operation type (registration/authentication)
//! - `PASSLESS_UV_RELYING_PARTY`: Relying party ID (if available)
//! - `PASSLESS_UV_USER`: User identifier (if available)
//! - `PASSLESS_UV_TIMEOUT`: Timeout in seconds

use super::{UserVerificationProvider, VerificationContext, VerificationError, VerificationResult};

use log::{debug, info};

use std::process::Command;

/// Command-based user verification provider
pub struct CommandProvider {
    command: Vec<String>,
    #[allow(dead_code)]
    timeout_seconds: u32,
}

impl CommandProvider {
    /// Create a new command provider
    ///
    /// # Arguments
    ///
    /// * `command` - Command and arguments to execute
    /// * `timeout_seconds` - Timeout for the command
    pub fn new(command: Vec<String>, timeout_seconds: u32) -> Self {
        Self {
            command,
            timeout_seconds,
        }
    }

    /// Execute the verification command
    fn execute(
        &self,
        context: &VerificationContext,
    ) -> Result<VerificationResult, VerificationError> {
        if self.command.is_empty() {
            return Err(VerificationError::NotAvailable(
                "No command configured".into(),
            ));
        }

        let program = &self.command[0];
        let args = &self.command[1..];

        debug!("Executing UV command: {} {:?}", program, args);

        let mut cmd = Command::new(program);
        cmd.args(args);

        cmd.env("PASSLESS_UV_OPERATION", &context.operation);

        if let Some(ref rp) = context.relying_party {
            cmd.env("PASSLESS_UV_RELYING_PARTY", rp);
        }

        if let Some(ref user) = context.user {
            cmd.env("PASSLESS_UV_USER", user);
        }

        cmd.env("PASSLESS_UV_TIMEOUT", context.timeout_seconds.to_string());

        let result = cmd.output().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                VerificationError::NotAvailable(format!("Command not found: {}", program))
            } else {
                VerificationError::DeviceError(format!("Failed to execute command: {}", e))
            }
        })?;

        debug!(
            "Command exit code: {}, stdout: {}, stderr: {}",
            result.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&result.stdout).trim(),
            String::from_utf8_lossy(&result.stderr).trim()
        );

        if result.status.success() {
            info!("User verification accepted via command");
            Ok(VerificationResult::Accepted)
        } else {
            info!(
                "User verification denied via command (exit code: {:?})",
                result.status.code()
            );
            Ok(VerificationResult::Denied)
        }
    }
}

impl UserVerificationProvider for CommandProvider {
    fn name(&self) -> &str {
        "command"
    }

    fn available(&self) -> bool {
        if self.command.is_empty() {
            return false;
        }

        let program = &self.command[0];

        if program.contains('/') {
            std::path::Path::new(program).exists()
        } else {
            which::which(program).is_ok()
        }
    }

    fn verify(
        &self,
        context: &VerificationContext,
    ) -> Result<VerificationResult, VerificationError> {
        self.execute(context)
    }

    fn priority(&self) -> u8 {
        50
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_provider_name() {
        let provider = CommandProvider::new(vec!["echo".to_string()], 30);
        assert_eq!(provider.name(), "command");
    }

    #[test]
    fn test_command_provider_priority() {
        let provider = CommandProvider::new(vec!["echo".to_string()], 30);
        assert_eq!(provider.priority(), 50);
    }

    #[test]
    fn test_command_provider_empty_unavailable() {
        let provider = CommandProvider::new(vec![], 30);
        assert!(!provider.available());
    }

    #[test]
    fn test_command_provider_empty_verify_fails() {
        let provider = CommandProvider::new(vec![], 30);
        let ctx = VerificationContext::new("test");
        let result = provider.verify(&ctx);
        assert!(result.is_err());
        match result.unwrap_err() {
            VerificationError::NotAvailable(_) => {}
            _ => panic!("Expected NotAvailable error"),
        }
    }

    #[test]
    fn test_command_provider_echo() {
        let provider = CommandProvider::new(vec!["echo".to_string(), "accepted".to_string()], 30);
        assert!(provider.available());

        let ctx = VerificationContext::new("test");
        let result = provider.verify(&ctx);
        assert_eq!(result.unwrap(), VerificationResult::Accepted);
    }

    #[test]
    fn test_command_provider_false() {
        let provider = CommandProvider::new(vec!["false".to_string()], 30);

        if !provider.available() {
            return;
        }

        let ctx = VerificationContext::new("test");
        let result = provider.verify(&ctx);
        assert_eq!(result.unwrap(), VerificationResult::Denied);
    }

    #[test]
    fn test_command_provider_exit_1_denied() {
        let provider = CommandProvider::new(
            vec!["sh".to_string(), "-c".to_string(), "exit 1".to_string()],
            30,
        );

        if !provider.available() {
            return;
        }

        let ctx = VerificationContext::new("test");
        let result = provider.verify(&ctx);
        assert_eq!(result.unwrap(), VerificationResult::Denied);
    }

    #[test]
    fn test_command_provider_nonexistent() {
        let provider = CommandProvider::new(vec!["nonexistent_command_12345".to_string()], 30);
        assert!(!provider.available());

        let ctx = VerificationContext::new("test");
        let result = provider.verify(&ctx);
        assert!(result.is_err());
        match result.unwrap_err() {
            VerificationError::NotAvailable(_) => {}
            _ => panic!("Expected NotAvailable error"),
        }
    }

    #[test]
    fn test_command_provider_with_context() {
        let provider = CommandProvider::new(
            vec![
                "sh".to_string(),
                "-c".to_string(),
                "test \"$PASSLESS_UV_OPERATION\" = 'registration' && test -n \"$PASSLESS_UV_RELYING_PARTY\"".to_string(),
            ],
            30,
        );

        if !provider.available() {
            return;
        }

        let ctx = VerificationContext::new("registration")
            .with_relying_party("example.com")
            .with_user("alice")
            .with_timeout(60);

        let result = provider.verify(&ctx);
        assert_eq!(result.unwrap(), VerificationResult::Accepted);
    }

    #[test]
    fn test_command_provider_absolute_path() {
        let provider = CommandProvider::new(vec!["/bin/true".to_string()], 30);

        if std::path::Path::new("/bin/true").exists() {
            assert!(provider.available());
            let ctx = VerificationContext::new("test");
            let result = provider.verify(&ctx);
            assert_eq!(result.unwrap(), VerificationResult::Accepted);
        }
    }
}
