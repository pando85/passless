use std::fmt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use passless_core::agent::protocol::IntentAction;
use soft_fido2::{UpResult, UvResult};

pub(crate) fn derive_action_from_info(info: &str) -> IntentAction {
    let lower = info.to_lowercase();
    if lower.contains("registration") && !lower.contains("credential excluded") {
        IntentAction::Register
    } else {
        IntentAction::Authenticate
    }
}

struct AgentInteractionToken {
    rp_id: String,
    action: IntentAction,
    generation: u64,
    up_approved: bool,
    uv_approved: bool,
    up_consumed: AtomicBool,
    uv_consumed: AtomicBool,
    expires_at: Instant,
}

impl AgentInteractionToken {
    fn new(
        rp_id: String,
        action: IntentAction,
        generation: u64,
        up_approved: bool,
        uv_approved: bool,
        ttl: Duration,
    ) -> Self {
        Self {
            rp_id,
            action,
            generation,
            up_approved,
            uv_approved,
            up_consumed: AtomicBool::new(false),
            uv_consumed: AtomicBool::new(false),
            expires_at: Instant::now() + ttl,
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    fn matches(&self, rp_id: &str, action: &IntentAction, generation: u64) -> bool {
        self.rp_id == rp_id && self.action == *action && self.generation == generation
    }

    fn try_consume_up(&self) -> Option<UpResult> {
        if self.is_expired() {
            return None;
        }
        if self
            .up_consumed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            Some(if self.up_approved {
                UpResult::Accepted
            } else {
                UpResult::Denied
            })
        } else {
            None
        }
    }

    fn try_consume_uv(&self) -> Option<UvResult> {
        if self.is_expired() {
            return None;
        }
        if self
            .uv_consumed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            Some(if self.uv_approved {
                UvResult::AcceptedWithUp
            } else {
                UvResult::Denied
            })
        } else {
            None
        }
    }
}

impl fmt::Debug for AgentInteractionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentInteractionToken")
            .field("rp_id", &self.rp_id)
            .field("action", &self.action)
            .field("generation", &self.generation)
            .field("up_approved", &self.up_approved)
            .field("uv_approved", &self.uv_approved)
            .field("up_consumed", &self.up_consumed.load(Ordering::Acquire))
            .field("uv_consumed", &self.uv_consumed.load(Ordering::Acquire))
            .finish()
    }
}

pub struct AgentInteractionManager {
    active: Mutex<Option<AgentInteractionToken>>,
}

impl AgentInteractionManager {
    pub fn new() -> Self {
        Self {
            active: Mutex::new(None),
        }
    }

    pub fn mint(
        &self,
        rp_id: String,
        action: IntentAction,
        generation: u64,
        up_approved: bool,
        uv_approved: bool,
        ttl: Duration,
    ) {
        let token =
            AgentInteractionToken::new(rp_id, action, generation, up_approved, uv_approved, ttl);
        let mut active = self.active.lock().unwrap();
        *active = Some(token);
    }

    pub fn try_consume_up(
        &self,
        rp_id: &str,
        action: IntentAction,
        generation: u64,
    ) -> Option<UpResult> {
        let active = self.active.lock().unwrap();
        match active.as_ref() {
            Some(token) if token.matches(rp_id, &action, generation) => token.try_consume_up(),
            _ => None,
        }
    }

    pub fn try_consume_uv(
        &self,
        rp_id: &str,
        action: IntentAction,
        generation: u64,
    ) -> Option<UvResult> {
        let active = self.active.lock().unwrap();
        match active.as_ref() {
            Some(token) if token.matches(rp_id, &action, generation) => token.try_consume_uv(),
            _ => None,
        }
    }

    pub fn clear(&self) {
        let mut active = self.active.lock().unwrap();
        *active = None;
    }

    pub fn has_active_token(&self) -> bool {
        let active = self.active.lock().unwrap();
        active.as_ref().is_some_and(|t| !t.is_expired())
    }
}

impl Default for AgentInteractionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for AgentInteractionManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentInteractionManager")
            .field("active", &"<redacted>")
            .finish()
    }
}

pub struct InteractionTokenGuard {
    manager: std::sync::Arc<AgentInteractionManager>,
}

impl InteractionTokenGuard {
    pub fn new(manager: std::sync::Arc<AgentInteractionManager>) -> Self {
        Self { manager }
    }
}

impl Drop for InteractionTokenGuard {
    fn drop(&mut self) {
        self.manager.clear();
    }
}

pub(crate) use self::derive_action_from_info as action_from_info;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn test_token_ttl() -> Duration {
        Duration::from_secs(60)
    }

    #[test]
    fn test_derive_action_registration() {
        assert_eq!(
            derive_action_from_info("Registration"),
            IntentAction::Register
        );
        assert_eq!(
            derive_action_from_info("registration"),
            IntentAction::Register
        );
        assert_eq!(
            derive_action_from_info("FIDO2 Registration"),
            IntentAction::Register
        );
    }

    #[test]
    fn test_derive_action_authentication() {
        assert_eq!(
            derive_action_from_info("Authentication"),
            IntentAction::Authenticate
        );
        assert_eq!(
            derive_action_from_info("GetAssertion"),
            IntentAction::Authenticate
        );
        assert_eq!(
            derive_action_from_info("credential excluded registration"),
            IntentAction::Authenticate
        );
    }

    #[test]
    fn test_mint_and_consume_up() {
        let manager = AgentInteractionManager::new();
        manager.mint(
            "example.com".to_string(),
            IntentAction::Authenticate,
            1,
            true,
            true,
            test_token_ttl(),
        );

        let result = manager.try_consume_up("example.com", IntentAction::Authenticate, 1);
        assert_eq!(result, Some(UpResult::Accepted));
    }

    #[test]
    fn test_mint_and_consume_up_denied() {
        let manager = AgentInteractionManager::new();
        manager.mint(
            "example.com".to_string(),
            IntentAction::Authenticate,
            1,
            false,
            true,
            test_token_ttl(),
        );

        let result = manager.try_consume_up("example.com", IntentAction::Authenticate, 1);
        assert_eq!(result, Some(UpResult::Denied));
    }

    #[test]
    fn test_mint_and_consume_uv() {
        let manager = AgentInteractionManager::new();
        manager.mint(
            "example.com".to_string(),
            IntentAction::Authenticate,
            1,
            true,
            true,
            test_token_ttl(),
        );

        let result = manager.try_consume_uv("example.com", IntentAction::Authenticate, 1);
        assert_eq!(result, Some(UvResult::AcceptedWithUp));
    }

    #[test]
    fn test_mint_and_consume_uv_denied() {
        let manager = AgentInteractionManager::new();
        manager.mint(
            "example.com".to_string(),
            IntentAction::Authenticate,
            1,
            true,
            false,
            test_token_ttl(),
        );

        let result = manager.try_consume_uv("example.com", IntentAction::Authenticate, 1);
        assert_eq!(result, Some(UvResult::Denied));
    }

    #[test]
    fn test_wrong_rp_fails() {
        let manager = AgentInteractionManager::new();
        manager.mint(
            "example.com".to_string(),
            IntentAction::Authenticate,
            1,
            true,
            true,
            test_token_ttl(),
        );

        let result = manager.try_consume_up("evil.com", IntentAction::Authenticate, 1);
        assert_eq!(result, None);
    }

    #[test]
    fn test_wrong_action_fails() {
        let manager = AgentInteractionManager::new();
        manager.mint(
            "example.com".to_string(),
            IntentAction::Authenticate,
            1,
            true,
            true,
            test_token_ttl(),
        );

        let result = manager.try_consume_up("example.com", IntentAction::Register, 1);
        assert_eq!(result, None);
    }

    #[test]
    fn test_wrong_generation_fails() {
        let manager = AgentInteractionManager::new();
        manager.mint(
            "example.com".to_string(),
            IntentAction::Authenticate,
            1,
            true,
            true,
            test_token_ttl(),
        );

        let result = manager.try_consume_up("example.com", IntentAction::Authenticate, 2);
        assert_eq!(result, None);
    }

    #[test]
    fn test_reuse_up_fails() {
        let manager = AgentInteractionManager::new();
        manager.mint(
            "example.com".to_string(),
            IntentAction::Authenticate,
            1,
            true,
            true,
            test_token_ttl(),
        );

        let first = manager.try_consume_up("example.com", IntentAction::Authenticate, 1);
        assert_eq!(first, Some(UpResult::Accepted));

        let second = manager.try_consume_up("example.com", IntentAction::Authenticate, 1);
        assert_eq!(second, None);
    }

    #[test]
    fn test_reuse_uv_fails() {
        let manager = AgentInteractionManager::new();
        manager.mint(
            "example.com".to_string(),
            IntentAction::Authenticate,
            1,
            true,
            true,
            test_token_ttl(),
        );

        let first = manager.try_consume_uv("example.com", IntentAction::Authenticate, 1);
        assert_eq!(first, Some(UvResult::AcceptedWithUp));

        let second = manager.try_consume_uv("example.com", IntentAction::Authenticate, 1);
        assert_eq!(second, None);
    }

    #[test]
    fn test_up_and_uv_independent_consumption() {
        let manager = AgentInteractionManager::new();
        manager.mint(
            "example.com".to_string(),
            IntentAction::Authenticate,
            1,
            true,
            true,
            test_token_ttl(),
        );

        let up = manager.try_consume_up("example.com", IntentAction::Authenticate, 1);
        assert_eq!(up, Some(UpResult::Accepted));

        let uv = manager.try_consume_uv("example.com", IntentAction::Authenticate, 1);
        assert_eq!(uv, Some(UvResult::AcceptedWithUp));

        let up_again = manager.try_consume_up("example.com", IntentAction::Authenticate, 1);
        assert_eq!(up_again, None);

        let uv_again = manager.try_consume_uv("example.com", IntentAction::Authenticate, 1);
        assert_eq!(uv_again, None);
    }

    #[test]
    fn test_expired_token_returns_none() {
        let manager = AgentInteractionManager::new();
        manager.mint(
            "example.com".to_string(),
            IntentAction::Authenticate,
            1,
            true,
            true,
            Duration::from_millis(1),
        );

        std::thread::sleep(Duration::from_millis(10));

        let result = manager.try_consume_up("example.com", IntentAction::Authenticate, 1);
        assert_eq!(result, None);
    }

    #[test]
    fn test_clear_removes_token() {
        let manager = AgentInteractionManager::new();
        manager.mint(
            "example.com".to_string(),
            IntentAction::Authenticate,
            1,
            true,
            true,
            test_token_ttl(),
        );

        assert!(manager.has_active_token());
        manager.clear();
        assert!(!manager.has_active_token());

        let result = manager.try_consume_up("example.com", IntentAction::Authenticate, 1);
        assert_eq!(result, None);
    }

    #[test]
    fn test_no_token_returns_none() {
        let manager = AgentInteractionManager::new();
        let result = manager.try_consume_up("example.com", IntentAction::Authenticate, 1);
        assert_eq!(result, None);
    }

    #[test]
    fn test_guard_clears_on_drop() {
        let manager = Arc::new(AgentInteractionManager::new());
        manager.mint(
            "example.com".to_string(),
            IntentAction::Authenticate,
            1,
            true,
            true,
            test_token_ttl(),
        );

        assert!(manager.has_active_token());
        {
            let _guard = InteractionTokenGuard::new(manager.clone());
            assert!(manager.has_active_token());
        }
        assert!(!manager.has_active_token());
    }

    #[test]
    fn test_mint_replaces_previous_token() {
        let manager = AgentInteractionManager::new();
        manager.mint(
            "example.com".to_string(),
            IntentAction::Authenticate,
            1,
            true,
            true,
            test_token_ttl(),
        );
        manager.mint(
            "other.com".to_string(),
            IntentAction::Register,
            2,
            false,
            false,
            test_token_ttl(),
        );

        let old = manager.try_consume_up("example.com", IntentAction::Authenticate, 1);
        assert_eq!(old, None);

        let new = manager.try_consume_up("other.com", IntentAction::Register, 2);
        assert_eq!(new, Some(UpResult::Denied));
    }

    #[test]
    fn test_debug_redacts_token_bytes() {
        let manager = AgentInteractionManager::new();
        manager.mint(
            "example.com".to_string(),
            IntentAction::Authenticate,
            1,
            true,
            true,
            test_token_ttl(),
        );

        let debug_str = format!("{:?}", manager);
        assert!(debug_str.contains("<redacted>"));
        assert!(!debug_str.contains("token_bytes"));
    }

    #[test]
    fn test_policy_alone_cannot_satisfy_up() {
        let manager = AgentInteractionManager::new();
        let result = manager.try_consume_up("example.com", IntentAction::Authenticate, 1);
        assert_eq!(result, None, "no token minted → no UP satisfaction");
    }

    #[test]
    fn test_policy_alone_cannot_satisfy_uv() {
        let manager = AgentInteractionManager::new();
        let result = manager.try_consume_uv("example.com", IntentAction::Authenticate, 1);
        assert_eq!(result, None, "no token minted → no UV satisfaction");
    }

    #[test]
    fn test_ceremony_token_up_accepted_uv_denied() {
        let manager = AgentInteractionManager::new();
        manager.mint(
            "example.com".to_string(),
            IntentAction::Authenticate,
            0,
            true,
            false,
            test_token_ttl(),
        );

        let up = manager.try_consume_up("example.com", IntentAction::Authenticate, 0);
        assert_eq!(up, Some(UpResult::Accepted));

        let uv = manager.try_consume_uv("example.com", IntentAction::Authenticate, 0);
        assert_eq!(uv, Some(UvResult::Denied));
    }

    #[test]
    fn test_active_token_blocks_fallback_notification() {
        let manager = AgentInteractionManager::new();
        manager.mint(
            "example.com".to_string(),
            IntentAction::Authenticate,
            0,
            true,
            false,
            test_token_ttl(),
        );

        assert!(manager.has_active_token());

        let up_miss = manager.try_consume_up("other.com", IntentAction::Authenticate, 0);
        assert_eq!(up_miss, None);
        assert!(manager.has_active_token());

        let uv_miss = manager.try_consume_uv("other.com", IntentAction::Authenticate, 0);
        assert_eq!(uv_miss, None);
        assert!(manager.has_active_token());
    }

    #[test]
    fn test_token_consumed_no_longer_active_for_fallback() {
        let manager = AgentInteractionManager::new();
        manager.mint(
            "example.com".to_string(),
            IntentAction::Authenticate,
            0,
            true,
            false,
            test_token_ttl(),
        );

        let _ = manager.try_consume_up("example.com", IntentAction::Authenticate, 0);
        let _ = manager.try_consume_uv("example.com", IntentAction::Authenticate, 0);

        assert!(manager.has_active_token());

        let up_again = manager.try_consume_up("example.com", IntentAction::Authenticate, 0);
        assert_eq!(up_again, None);
        let uv_again = manager.try_consume_uv("example.com", IntentAction::Authenticate, 0);
        assert_eq!(uv_again, None);
    }
}
