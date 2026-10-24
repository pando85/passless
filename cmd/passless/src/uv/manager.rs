//! User Verification Manager
//!
//! Manages a chain of UV providers with automatic fallback.

use super::{UserVerificationProvider, VerificationContext, VerificationError, VerificationResult};

use log::{debug, info, warn};
use std::cmp::Reverse;

/// Manages user verification providers with fallback chain
pub struct UserVerificationManager {
    providers: Vec<Box<dyn UserVerificationProvider>>,
}

impl UserVerificationManager {
    /// Create a new manager with the given providers
    ///
    /// Providers are sorted by priority (highest first) and will be tried in order.
    pub fn new(providers: Vec<Box<dyn UserVerificationProvider>>) -> Self {
        let mut providers = providers;
        providers.sort_by_key(|p| Reverse(p.priority()));
        Self { providers }
    }

    /// Create a manager with default providers (empty)
    #[allow(dead_code)]
    pub fn empty() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Add a provider to the chain
    #[allow(dead_code)]
    pub fn add_provider(&mut self, provider: Box<dyn UserVerificationProvider>) {
        self.providers.push(provider);
        self.providers.sort_by_key(|p| Reverse(p.priority()));
    }

    /// Get list of available providers
    pub fn available_providers(&self) -> Vec<&dyn UserVerificationProvider> {
        self.providers
            .iter()
            .filter(|p| p.available())
            .map(|p| p.as_ref())
            .collect()
    }

    /// Perform user verification with automatic fallback
    ///
    /// Tries providers in priority order until one succeeds.
    /// Falls back to next provider on error or timeout.
    /// Returns first non-error result (Accepted, Denied, or Timeout from last provider).
    pub fn verify(
        &self,
        context: &VerificationContext,
    ) -> Result<VerificationResult, VerificationError> {
        let available: Vec<_> = self.available_providers();

        if available.is_empty() {
            warn!("No UV providers available");
            return Err(VerificationError::NotAvailable(
                "No user verification providers available".into(),
            ));
        }

        info!(
            "Starting user verification with {} available provider(s)",
            available.len()
        );

        let mut last_error: Option<VerificationError> = None;

        for provider in &available {
            debug!(
                "Trying UV provider: {} (priority {})",
                provider.name(),
                provider.priority()
            );

            // Check enrollment
            if provider.requires_enrollment() && !provider.is_enrolled() {
                debug!("Provider {} not enrolled, skipping", provider.name());
                last_error = Some(VerificationError::NotEnrolled);
                continue;
            }

            match provider.verify(context) {
                Ok(result @ VerificationResult::Accepted) => {
                    info!("User verification accepted via {}", provider.name());
                    return Ok(result);
                }
                Ok(result @ VerificationResult::Denied) => {
                    info!("User verification denied via {}", provider.name());
                    return Ok(result);
                }
                Ok(VerificationResult::Timeout) => {
                    warn!("UV provider {} timed out, trying next", provider.name());
                    last_error = Some(VerificationError::Other("Timeout".into()));
                    continue;
                }
                Err(e) => {
                    warn!("UV provider {} failed: {}, trying next", provider.name(), e);
                    last_error = Some(e);
                    continue;
                }
            }
        }

        // All providers failed
        let error = last_error.unwrap_or_else(|| {
            VerificationError::Other("All verification providers failed".into())
        });
        Err(error)
    }

    /// Get a provider by name for enrollment
    #[allow(dead_code)]
    pub fn get_provider(&self, name: &str) -> Option<&dyn UserVerificationProvider> {
        self.providers
            .iter()
            .find(|p| p.name() == name)
            .map(|p| p.as_ref())
    }

    /// List all providers (for CLI status command)
    #[allow(dead_code)]
    pub fn list_providers(&self) -> &[Box<dyn UserVerificationProvider>] {
        &self.providers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProvider {
        name: &'static str,
        priority: u8,
        available: bool,
        result: VerificationResult,
        requires_enrollment: bool,
        is_enrolled: bool,
    }

    impl MockProvider {
        fn new(
            name: &'static str,
            priority: u8,
            available: bool,
            result: VerificationResult,
        ) -> Self {
            Self {
                name,
                priority,
                available,
                result,
                requires_enrollment: false,
                is_enrolled: true,
            }
        }

        fn with_enrollment(mut self, requires: bool, enrolled: bool) -> Self {
            self.requires_enrollment = requires;
            self.is_enrolled = enrolled;
            self
        }
    }

    impl UserVerificationProvider for MockProvider {
        fn name(&self) -> &str {
            self.name
        }

        fn available(&self) -> bool {
            self.available
        }

        fn verify(
            &self,
            _context: &VerificationContext,
        ) -> Result<VerificationResult, VerificationError> {
            if !self.available {
                return Err(VerificationError::NotAvailable("Not available".into()));
            }
            Ok(self.result)
        }

        fn priority(&self) -> u8 {
            self.priority
        }

        fn requires_enrollment(&self) -> bool {
            self.requires_enrollment
        }

        fn is_enrolled(&self) -> bool {
            self.is_enrolled
        }
    }

    #[test]
    fn test_provider_ordering_by_priority() {
        let low = MockProvider::new("low", 10, true, VerificationResult::Accepted);
        let high = MockProvider::new("high", 100, true, VerificationResult::Accepted);

        let manager = UserVerificationManager::new(vec![Box::new(low), Box::new(high)]);

        assert_eq!(manager.list_providers()[0].name(), "high");
        assert_eq!(manager.list_providers()[1].name(), "low");
    }

    #[test]
    fn test_fallback_on_timeout() {
        let fail = MockProvider::new("fail", 100, true, VerificationResult::Timeout);
        let succeed = MockProvider::new("succeed", 50, true, VerificationResult::Accepted);

        let manager = UserVerificationManager::new(vec![Box::new(fail), Box::new(succeed)]);

        let ctx = VerificationContext::new("test");
        let result = manager.verify(&ctx);
        assert_eq!(result.unwrap(), VerificationResult::Accepted);
    }

    #[test]
    fn test_no_available_providers() {
        let unavailable =
            MockProvider::new("unavailable", 100, false, VerificationResult::Accepted);

        let manager = UserVerificationManager::new(vec![Box::new(unavailable)]);
        let ctx = VerificationContext::new("test");
        let result = manager.verify(&ctx);

        assert!(result.is_err());
        match result.unwrap_err() {
            VerificationError::NotAvailable(_) => {}
            _ => panic!("Expected NotAvailable error"),
        }
    }

    #[test]
    fn test_denied_returns_immediately() {
        let deny = MockProvider::new("deny", 100, true, VerificationResult::Denied);
        let accept = MockProvider::new("accept", 50, true, VerificationResult::Accepted);

        let manager = UserVerificationManager::new(vec![Box::new(deny), Box::new(accept)]);

        let ctx = VerificationContext::new("test");
        let result = manager.verify(&ctx);
        assert_eq!(result.unwrap(), VerificationResult::Denied);
    }

    #[test]
    fn test_skip_unenrolled_provider() {
        let unenrolled = MockProvider::new("unenrolled", 100, true, VerificationResult::Accepted)
            .with_enrollment(true, false);
        let fallback = MockProvider::new("fallback", 50, true, VerificationResult::Accepted);

        let manager = UserVerificationManager::new(vec![Box::new(unenrolled), Box::new(fallback)]);

        let ctx = VerificationContext::new("test");
        let result = manager.verify(&ctx);
        assert_eq!(result.unwrap(), VerificationResult::Accepted);
    }

    #[test]
    fn test_all_providers_fail() {
        let fail1 = MockProvider::new("fail1", 100, true, VerificationResult::Timeout);
        let fail2 = MockProvider::new("fail2", 50, true, VerificationResult::Timeout);

        let manager = UserVerificationManager::new(vec![Box::new(fail1), Box::new(fail2)]);

        let ctx = VerificationContext::new("test");
        let result = manager.verify(&ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_available_providers_filter() {
        let available = MockProvider::new("available", 100, true, VerificationResult::Accepted);
        let unavailable = MockProvider::new("unavailable", 50, false, VerificationResult::Accepted);

        let manager =
            UserVerificationManager::new(vec![Box::new(available), Box::new(unavailable)]);

        let available_list = manager.available_providers();
        assert_eq!(available_list.len(), 1);
        assert_eq!(available_list[0].name(), "available");
    }

    #[test]
    fn test_get_provider_by_name() {
        let provider = MockProvider::new("test_provider", 100, true, VerificationResult::Accepted);

        let manager = UserVerificationManager::new(vec![Box::new(provider)]);

        assert!(manager.get_provider("test_provider").is_some());
        assert!(manager.get_provider("nonexistent").is_none());
    }

    #[test]
    fn test_empty_manager() {
        let manager = UserVerificationManager::empty();
        assert!(manager.list_providers().is_empty());

        let ctx = VerificationContext::new("test");
        let result = manager.verify(&ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_provider() {
        let mut manager = UserVerificationManager::empty();
        let provider = MockProvider::new("test", 100, true, VerificationResult::Accepted);

        manager.add_provider(Box::new(provider));
        assert_eq!(manager.list_providers().len(), 1);
    }
}
