/// Manages agent interaction tokens for overriding UP/UV prompts during agent ceremonies.
///
/// When a matching token is present, callbacks consume it once and return the
/// pre-decided result. Without a token, the human notification path is used.
pub struct AgentInteractionManager {
    _private: (),
}

impl AgentInteractionManager {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for AgentInteractionManager {
    fn default() -> Self {
        Self::new()
    }
}
