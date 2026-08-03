use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use log::{debug, info, warn};
use notify_rust::{Notification, Timeout, Urgency};
use serde::{Deserialize, Serialize};

use passless_core::agent::{CredentialRef, ProfileId};

const MAX_UNTRUSTED_LEN: usize = 256;
const MAX_RP_ID_LEN: usize = 253;
const MAX_CREDENTIAL_LABEL_LEN: usize = 128;
const DEFAULT_PROMPT_TIMEOUT_SECS: u64 = 60;
const MAX_PROMPT_TIMEOUT_SECS: u64 = 300;
const MIN_PROMPT_TIMEOUT_SECS: u64 = 5;
const DEFAULT_MIN_REVIEW_DELAY_MS: u64 = 1000;
const MAX_MIN_REVIEW_DELAY_MS: u64 = 30_000;
#[cfg(test)]
const MIN_MIN_REVIEW_DELAY_MS: u64 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptMode {
    Isolated,
}

impl fmt::Display for PromptMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Isolated => write!(f, "isolated"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptAction {
    Register,
    Authenticate,
}

impl fmt::Display for PromptAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Register => write!(f, "register"),
            Self::Authenticate => write!(f, "authenticate"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptDecision {
    Approved,
    Denied,
    Timeout,
    Error,
}

impl fmt::Display for PromptDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approved => write!(f, "approved"),
            Self::Denied => write!(f, "denied"),
            Self::Timeout => write!(f, "timeout"),
            Self::Error => write!(f, "error"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptErrorKind {
    NotificationUnsupported,
    ServerCapabilityRejected,
    RenderFailed,
    ActionAmbiguous,
    InternalError,
}

impl fmt::Display for PromptErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotificationUnsupported => write!(f, "notification_unsupported"),
            Self::ServerCapabilityRejected => write!(f, "server_capability_rejected"),
            Self::RenderFailed => write!(f, "render_failed"),
            Self::ActionAmbiguous => write!(f, "action_ambiguous"),
            Self::InternalError => write!(f, "internal_error"),
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PromptError {
    pub kind: PromptErrorKind,
}

impl fmt::Display for PromptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "prompt error: {}", self.kind)
    }
}

impl std::error::Error for PromptError {}

#[derive(Debug, Clone)]
pub struct BoundedString<const MAX: usize>(String);

impl<const MAX: usize> BoundedString<MAX> {
    pub fn new(s: impl Into<String>) -> Self {
        let mut s = s.into();
        if s.len() > MAX {
            s.truncate(MAX);
        }
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[allow(dead_code)]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl<const MAX: usize> Serialize for BoundedString<MAX> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for BoundedString<MAX> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self::new(s))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptRequest {
    profile_id: ProfileId,
    mode: PromptMode,
    action: PromptAction,
    rp_id: String,
    credential_label: Option<String>,
    credential_ref: Option<CredentialRef>,
    grant_ttl_secs: u64,
    session_ttl_secs: u64,
    untrusted_reason: BoundedString<MAX_UNTRUSTED_LEN>,
    untrusted_page_title: BoundedString<MAX_UNTRUSTED_LEN>,
    untrusted_page_url: BoundedString<MAX_UNTRUSTED_LEN>,
    untrusted_account_label: BoundedString<MAX_UNTRUSTED_LEN>,
}

impl PromptRequest {
    pub fn builder() -> PromptRequestBuilder {
        PromptRequestBuilder::new()
    }

    pub fn profile_id(&self) -> &ProfileId {
        &self.profile_id
    }

    pub fn mode(&self) -> PromptMode {
        self.mode
    }

    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    pub fn action(&self) -> PromptAction {
        self.action
    }

    pub fn credential_label(&self) -> Option<&str> {
        self.credential_label.as_deref()
    }

    pub fn credential_ref(&self) -> Option<&CredentialRef> {
        self.credential_ref.as_ref()
    }

    pub fn grant_ttl_secs(&self) -> u64 {
        self.grant_ttl_secs
    }

    pub fn session_ttl_secs(&self) -> u64 {
        self.session_ttl_secs
    }

    pub fn untrusted_reason(&self) -> &str {
        self.untrusted_reason.as_str()
    }

    pub fn untrusted_page_title(&self) -> &str {
        self.untrusted_page_title.as_str()
    }

    pub fn untrusted_page_url(&self) -> &str {
        self.untrusted_page_url.as_str()
    }

    pub fn untrusted_account_label(&self) -> &str {
        self.untrusted_account_label.as_str()
    }

    #[cfg(test)]
    pub fn snapshot(&self) -> PromptSnapshot {
        PromptSnapshot {
            profile_id: self.profile_id.as_str().to_string(),
            mode: self.mode,
            action: self.action,
            rp_id: self.rp_id.clone(),
            credential_label: self.credential_label.clone(),
            credential_ref: self.credential_ref.as_ref().map(|c| c.to_hex()),
            grant_ttl_secs: self.grant_ttl_secs,
            session_ttl_secs: self.session_ttl_secs,
            untrusted_reason: self.untrusted_reason.as_str().to_string(),
            untrusted_page_title: self.untrusted_page_title.as_str().to_string(),
            untrusted_page_url: self.untrusted_page_url.as_str().to_string(),
            untrusted_account_label: self.untrusted_account_label.as_str().to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct PromptSnapshot {
    pub profile_id: String,
    pub mode: PromptMode,
    pub action: PromptAction,
    pub rp_id: String,
    pub credential_label: Option<String>,
    pub credential_ref: Option<String>,
    pub grant_ttl_secs: u64,
    pub session_ttl_secs: u64,
    pub untrusted_reason: String,
    pub untrusted_page_title: String,
    pub untrusted_page_url: String,
    pub untrusted_account_label: String,
}

pub struct PromptRequestBuilder {
    profile_id: Option<ProfileId>,
    mode: Option<PromptMode>,
    action: Option<PromptAction>,
    rp_id: Option<String>,
    credential_label: Option<String>,
    credential_ref: Option<CredentialRef>,
    grant_ttl_secs: u64,
    session_ttl_secs: u64,
    untrusted_reason: String,
    untrusted_page_title: String,
    untrusted_page_url: String,
    untrusted_account_label: String,
}

impl PromptRequestBuilder {
    pub fn new() -> Self {
        Self {
            profile_id: None,
            mode: None,
            action: None,
            rp_id: None,
            credential_label: None,
            credential_ref: None,
            grant_ttl_secs: 300,
            session_ttl_secs: 3600,
            untrusted_reason: String::new(),
            untrusted_page_title: String::new(),
            untrusted_page_url: String::new(),
            untrusted_account_label: String::new(),
        }
    }

    pub fn profile_id(mut self, id: ProfileId) -> Self {
        self.profile_id = Some(id);
        self
    }

    pub fn mode(mut self, mode: PromptMode) -> Self {
        self.mode = Some(mode);
        self
    }

    pub fn action(mut self, action: PromptAction) -> Self {
        self.action = Some(action);
        self
    }

    pub fn rp_id(mut self, rp_id: impl Into<String>) -> Self {
        self.rp_id = Some(rp_id.into());
        self
    }

    pub fn credential_label(mut self, label: impl Into<String>) -> Self {
        self.credential_label = Some(label.into());
        self
    }

    #[cfg(test)]
    pub fn credential_ref(mut self, cr: CredentialRef) -> Self {
        self.credential_ref = Some(cr);
        self
    }

    pub fn credential_ref_opt(mut self, cr: Option<CredentialRef>) -> Self {
        self.credential_ref = cr;
        self
    }

    pub fn grant_ttl_secs(mut self, secs: u64) -> Self {
        self.grant_ttl_secs = secs;
        self
    }

    pub fn session_ttl_secs(mut self, secs: u64) -> Self {
        self.session_ttl_secs = secs;
        self
    }

    pub fn untrusted_reason(mut self, reason: impl Into<String>) -> Self {
        self.untrusted_reason = reason.into();
        self
    }

    #[cfg(test)]
    pub fn untrusted_page_title(mut self, title: impl Into<String>) -> Self {
        self.untrusted_page_title = title.into();
        self
    }

    #[cfg(test)]
    pub fn untrusted_page_url(mut self, url: impl Into<String>) -> Self {
        self.untrusted_page_url = url.into();
        self
    }

    #[cfg(test)]
    pub fn untrusted_account_label(mut self, label: impl Into<String>) -> Self {
        self.untrusted_account_label = label.into();
        self
    }

    pub fn build(self) -> Result<PromptRequest, PromptBuildError> {
        let profile_id = self
            .profile_id
            .ok_or(PromptBuildError::MissingField("profile_id"))?;
        let mode = self.mode.ok_or(PromptBuildError::MissingField("mode"))?;
        let action = self
            .action
            .ok_or(PromptBuildError::MissingField("action"))?;
        let raw_rp_id = self.rp_id.ok_or(PromptBuildError::MissingField("rp_id"))?;

        let normalized_rp_id = normalize_rp_id(&raw_rp_id)?;

        let credential_label = self.credential_label.map(|mut l| {
            if l.len() > MAX_CREDENTIAL_LABEL_LEN {
                l.truncate(MAX_CREDENTIAL_LABEL_LEN);
            }
            l
        });

        Ok(PromptRequest {
            profile_id,
            mode,
            action,
            rp_id: normalized_rp_id,
            credential_label,
            credential_ref: self.credential_ref,
            grant_ttl_secs: self.grant_ttl_secs,
            session_ttl_secs: self.session_ttl_secs,
            untrusted_reason: BoundedString::new(self.untrusted_reason),
            untrusted_page_title: BoundedString::new(self.untrusted_page_title),
            untrusted_page_url: BoundedString::new(self.untrusted_page_url),
            untrusted_account_label: BoundedString::new(self.untrusted_account_label),
        })
    }
}

impl Default for PromptRequestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptBuildError {
    MissingField(&'static str),
    EmptyRpId,
    RpIdTooLong,
    WildcardRpId,
}

impl fmt::Display for PromptBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField(field) => write!(f, "missing required field: {}", field),
            Self::EmptyRpId => write!(f, "RP ID must not be empty"),
            Self::RpIdTooLong => write!(f, "RP ID exceeds maximum length"),
            Self::WildcardRpId => write!(f, "wildcard RP ID not allowed"),
        }
    }
}

impl std::error::Error for PromptBuildError {}

fn normalize_rp_id(raw: &str) -> Result<String, PromptBuildError> {
    let trimmed = raw.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return Err(PromptBuildError::EmptyRpId);
    }
    if trimmed.len() > MAX_RP_ID_LEN {
        return Err(PromptBuildError::RpIdTooLong);
    }
    if trimmed.contains('*') || trimmed.starts_with('.') {
        return Err(PromptBuildError::WildcardRpId);
    }
    Ok(trimmed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerCapability {
    FullActions,
    DefaultActionOnly,
    Unknown,
}

pub fn query_server_capabilities() -> ServerCapability {
    match notify_rust::get_server_information() {
        Ok(info) => {
            let server_name = info.name.to_lowercase();
            debug!(
                "Prompt: notification server: {} (version: {})",
                info.name, info.version
            );
            match (server_name.as_str(), info.version.as_str()) {
                ("notify-osd", "1.0") | ("mako", "0.0.0") | ("quickshell", "") => {
                    ServerCapability::DefaultActionOnly
                }
                _ => ServerCapability::FullActions,
            }
        }
        Err(e) => {
            warn!("Prompt: failed to query notification server: {}", e);
            ServerCapability::Unknown
        }
    }
}

pub trait PromptHandle: Send + Sync {
    fn prompt(&self, request: &PromptRequest) -> PromptResult;
}

#[derive(Debug, Clone)]
pub struct PromptResult {
    pub decision: PromptDecision,
    pub error_kind: Option<PromptErrorKind>,
    pub latency_ms: u64,
}

impl PromptResult {
    pub fn approved(latency_ms: u64) -> Self {
        Self {
            decision: PromptDecision::Approved,
            error_kind: None,
            latency_ms,
        }
    }

    pub fn denied(latency_ms: u64) -> Self {
        Self {
            decision: PromptDecision::Denied,
            error_kind: None,
            latency_ms,
        }
    }

    pub fn timeout(latency_ms: u64) -> Self {
        Self {
            decision: PromptDecision::Timeout,
            error_kind: None,
            latency_ms,
        }
    }

    pub fn error(kind: PromptErrorKind, latency_ms: u64) -> Self {
        Self {
            decision: PromptDecision::Error,
            error_kind: Some(kind),
            latency_ms,
        }
    }
}

pub struct DesktopPromptHandle {
    timeout_secs: u64,
    min_review_delay_ms: u64,
}

impl DesktopPromptHandle {
    pub fn new(timeout_secs: u64, min_review_delay_ms: u64) -> Self {
        let timeout_secs = timeout_secs.clamp(MIN_PROMPT_TIMEOUT_SECS, MAX_PROMPT_TIMEOUT_SECS);
        let min_review_delay_ms = min_review_delay_ms.min(MAX_MIN_REVIEW_DELAY_MS);
        Self {
            timeout_secs,
            min_review_delay_ms,
        }
    }

    pub fn default_config() -> Self {
        Self::new(DEFAULT_PROMPT_TIMEOUT_SECS, DEFAULT_MIN_REVIEW_DELAY_MS)
    }

    #[cfg(test)]
    pub fn timeout_secs(&self) -> u64 {
        self.timeout_secs
    }

    #[cfg(test)]
    pub fn min_review_delay_ms(&self) -> u64 {
        self.min_review_delay_ms
    }
}

impl PromptHandle for DesktopPromptHandle {
    fn prompt(&self, request: &PromptRequest) -> PromptResult {
        let start = Instant::now();

        let cap = query_server_capabilities();
        match cap {
            ServerCapability::DefaultActionOnly => {
                warn!("Prompt: rejecting server that requires default/single-action fallback");
                return PromptResult::error(
                    PromptErrorKind::ServerCapabilityRejected,
                    start.elapsed().as_millis() as u64,
                );
            }
            ServerCapability::Unknown => {
                warn!("Prompt: unknown server capability, failing closed");
                return PromptResult::error(
                    PromptErrorKind::NotificationUnsupported,
                    start.elapsed().as_millis() as u64,
                );
            }
            ServerCapability::FullActions => {}
        }

        let title = build_security_title(request.action());
        let body = build_security_body(request);

        let action_result = Arc::new(Mutex::new(None));
        let action_result_clone = Arc::clone(&action_result);
        let show_start = Instant::now();

        let mut notification = Notification::new();
        notification
            .summary(&title)
            .body(&body)
            .icon("security-high")
            .timeout(Timeout::Milliseconds((self.timeout_secs * 1000) as u32))
            .urgency(Urgency::Critical)
            .action("approve", "Approve")
            .action("deny", "Deny");

        let handle = match notification.show() {
            Ok(h) => h,
            Err(e) => {
                warn!("Prompt: failed to render notification: {}", e);
                return PromptResult::error(
                    PromptErrorKind::RenderFailed,
                    start.elapsed().as_millis() as u64,
                );
            }
        };

        handle.wait_for_action(|action| {
            debug!("Prompt: user action received: {}", action);
            let mut result = action_result_clone
                .lock()
                .expect("prompt action result lock poisoned");
            *result = Some(action.to_string());
        });

        let elapsed_since_show = show_start.elapsed();

        let action = action_result
            .lock()
            .expect("prompt action result lock poisoned")
            .clone()
            .unwrap_or_else(|| "__closed".to_string());

        let decision = match action.as_str() {
            "approve" => {
                if elapsed_since_show < Duration::from_millis(self.min_review_delay_ms) {
                    warn!(
                        "Prompt: approval arrived before min review delay ({}ms < {}ms), denying",
                        elapsed_since_show.as_millis(),
                        self.min_review_delay_ms
                    );
                    PromptDecision::Denied
                } else {
                    PromptDecision::Approved
                }
            }
            "deny" => PromptDecision::Denied,
            "__closed" => PromptDecision::Timeout,
            _other => {
                warn!("Prompt: ambiguous action '{}', failing closed", _other);
                return PromptResult::error(
                    PromptErrorKind::ActionAmbiguous,
                    start.elapsed().as_millis() as u64,
                );
            }
        };

        let latency = start.elapsed().as_millis() as u64;
        info!("Prompt: decision={:?} latency_ms={}", decision, latency);

        match decision {
            PromptDecision::Approved => PromptResult::approved(latency),
            PromptDecision::Denied => PromptResult::denied(latency),
            PromptDecision::Timeout => PromptResult::timeout(latency),
            PromptDecision::Error => PromptResult::error(PromptErrorKind::InternalError, latency),
        }
    }
}

fn build_security_title(action: PromptAction) -> String {
    match action {
        PromptAction::Register => "Passless: New credential registration".to_string(),
        PromptAction::Authenticate => "Passless: Authentication request".to_string(),
    }
}

fn build_security_body(request: &PromptRequest) -> String {
    let mut body = String::new();

    body.push_str(&format!(
        "Profile (trusted): {}",
        request.profile_id().as_str()
    ));
    body.push_str(&format!("\nMode (trusted): {}", request.mode()));
    body.push_str(&format!(
        "\nExact relying party (trusted): {}",
        request.rp_id()
    ));
    body.push_str(&format!("\nAction (trusted): {}", request.action()));

    if let Some(label) = request.credential_label() {
        body.push_str(&format!("\nCredential label (trusted): {}", label));
    }
    if let Some(cred_ref) = request.credential_ref() {
        body.push_str(&format!(
            "\nCredential ref (trusted): {}",
            cred_ref.to_hex()
        ));
    }

    body.push_str(&format!("\nGrant TTL: {}s", request.grant_ttl_secs()));
    body.push_str(&format!(
        "\nBrowser session TTL: {}s",
        request.session_ttl_secs()
    ));

    let reason = request.untrusted_reason();
    if !reason.is_empty() {
        body.push_str(&format!("\nAgent-supplied reason (untrusted): {}", reason));
    }

    let page_title = request.untrusted_page_title();
    if !page_title.is_empty() {
        body.push_str(&format!("\nPage title (untrusted): {}", page_title));
    }

    let page_url = request.untrusted_page_url();
    if !page_url.is_empty() {
        body.push_str(&format!("\nPage URL (untrusted): {}", page_url));
    }

    let account_label = request.untrusted_account_label();
    if !account_label.is_empty() {
        body.push_str(&format!("\nAccount label (untrusted): {}", account_label));
    }

    body
}

#[cfg(test)]
pub struct MockPromptHandle {
    decision: Mutex<PromptDecision>,
    latency_ms: u64,
}

#[cfg(test)]
impl MockPromptHandle {
    pub fn new(decision: PromptDecision, latency_ms: u64) -> Self {
        Self {
            decision: Mutex::new(decision),
            latency_ms,
        }
    }

    pub fn set_decision(&self, decision: PromptDecision) {
        *self.decision.lock().unwrap() = decision;
    }
}

#[cfg(test)]
impl PromptHandle for MockPromptHandle {
    fn prompt(&self, _request: &PromptRequest) -> PromptResult {
        let decision = *self.decision.lock().unwrap();
        match decision {
            PromptDecision::Approved => PromptResult::approved(self.latency_ms),
            PromptDecision::Denied => PromptResult::denied(self.latency_ms),
            PromptDecision::Timeout => PromptResult::timeout(self.latency_ms),
            PromptDecision::Error => {
                PromptResult::error(PromptErrorKind::InternalError, self.latency_ms)
            }
        }
    }
}

#[cfg(test)]
pub struct AutoApproveHandle {
    latency_ms: u64,
}

#[cfg(test)]
impl AutoApproveHandle {
    pub fn new(latency_ms: u64) -> Self {
        Self { latency_ms }
    }
}

#[cfg(test)]
impl PromptHandle for AutoApproveHandle {
    fn prompt(&self, _request: &PromptRequest) -> PromptResult {
        PromptResult::approved(self.latency_ms)
    }
}

#[cfg(test)]
fn test_prompt_handle_auto_approve() -> AutoApproveHandle {
    AutoApproveHandle::new(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use passless_core::agent::ProfileId;

    fn test_profile_id() -> ProfileId {
        ProfileId::new("test-profile").unwrap()
    }

    fn test_cred() -> CredentialRef {
        CredentialRef::with_default_domain(b"test-credential-id")
    }

    fn build_test_request() -> PromptRequest {
        PromptRequest::builder()
            .profile_id(test_profile_id())
            .mode(PromptMode::Isolated)
            .action(PromptAction::Authenticate)
            .rp_id("example.com")
            .credential_label("my-key")
            .credential_ref(test_cred())
            .grant_ttl_secs(300)
            .session_ttl_secs(3600)
            .untrusted_reason("Login to example.com")
            .untrusted_page_title("Example Login")
            .untrusted_page_url("https://example.com/login")
            .untrusted_account_label("user@example.com")
            .build()
            .unwrap()
    }

    #[test]
    fn test_prompt_request_builder_success() {
        let req = build_test_request();
        assert_eq!(req.profile_id().as_str(), "test-profile");
        assert_eq!(req.mode(), PromptMode::Isolated);
        assert_eq!(req.action(), PromptAction::Authenticate);
        assert_eq!(req.rp_id(), "example.com");
        assert_eq!(req.credential_label(), Some("my-key"));
        assert!(req.credential_ref().is_some());
        assert_eq!(req.grant_ttl_secs(), 300);
        assert_eq!(req.session_ttl_secs(), 3600);
    }

    #[test]
    fn test_prompt_request_normalizes_rp_id() {
        let req = PromptRequest::builder()
            .profile_id(test_profile_id())
            .mode(PromptMode::Isolated)
            .action(PromptAction::Register)
            .rp_id("  EXAMPLE.COM  ")
            .build()
            .unwrap();
        assert_eq!(req.rp_id(), "example.com");
    }

    #[test]
    fn test_prompt_request_rejects_empty_rp_id() {
        let result = PromptRequest::builder()
            .profile_id(test_profile_id())
            .mode(PromptMode::Isolated)
            .action(PromptAction::Register)
            .rp_id("")
            .build();
        assert!(matches!(result, Err(PromptBuildError::EmptyRpId)));
    }

    #[test]
    fn test_prompt_request_rejects_wildcard_rp_id() {
        let result = PromptRequest::builder()
            .profile_id(test_profile_id())
            .mode(PromptMode::Isolated)
            .action(PromptAction::Register)
            .rp_id("*.example.com")
            .build();
        assert!(matches!(result, Err(PromptBuildError::WildcardRpId)));
    }

    #[test]
    fn test_prompt_request_rejects_missing_profile_id() {
        let result = PromptRequest::builder()
            .mode(PromptMode::Isolated)
            .action(PromptAction::Register)
            .rp_id("example.com")
            .build();
        assert!(matches!(
            result,
            Err(PromptBuildError::MissingField("profile_id"))
        ));
    }

    #[test]
    fn test_prompt_request_rejects_missing_mode() {
        let result = PromptRequest::builder()
            .profile_id(test_profile_id())
            .action(PromptAction::Register)
            .rp_id("example.com")
            .build();
        assert!(matches!(
            result,
            Err(PromptBuildError::MissingField("mode"))
        ));
    }

    #[test]
    fn test_prompt_request_rejects_missing_action() {
        let result = PromptRequest::builder()
            .profile_id(test_profile_id())
            .mode(PromptMode::Isolated)
            .rp_id("example.com")
            .build();
        assert!(matches!(
            result,
            Err(PromptBuildError::MissingField("action"))
        ));
    }

    #[test]
    fn test_prompt_request_rejects_missing_rp_id() {
        let result = PromptRequest::builder()
            .profile_id(test_profile_id())
            .mode(PromptMode::Isolated)
            .action(PromptAction::Register)
            .build();
        assert!(matches!(
            result,
            Err(PromptBuildError::MissingField("rp_id"))
        ));
    }

    #[test]
    fn test_untrusted_fields_bounded() {
        let long_string = "A".repeat(1000);
        let req = PromptRequest::builder()
            .profile_id(test_profile_id())
            .mode(PromptMode::Isolated)
            .action(PromptAction::Authenticate)
            .rp_id("example.com")
            .untrusted_reason(&long_string)
            .untrusted_page_title(&long_string)
            .untrusted_page_url(&long_string)
            .untrusted_account_label(&long_string)
            .build()
            .unwrap();

        assert!(req.untrusted_reason().len() <= MAX_UNTRUSTED_LEN);
        assert!(req.untrusted_page_title().len() <= MAX_UNTRUSTED_LEN);
        assert!(req.untrusted_page_url().len() <= MAX_UNTRUSTED_LEN);
        assert!(req.untrusted_account_label().len() <= MAX_UNTRUSTED_LEN);
    }

    #[test]
    fn test_untrusted_fields_clearly_separated() {
        let req = build_test_request();
        let snapshot = req.snapshot();
        assert_eq!(snapshot.untrusted_reason, "Login to example.com");
        assert_eq!(snapshot.untrusted_page_title, "Example Login");
        assert_eq!(snapshot.untrusted_page_url, "https://example.com/login");
        assert_eq!(snapshot.untrusted_account_label, "user@example.com");

        let json = serde_json::to_value(&snapshot).unwrap();
        let obj = json.as_object().unwrap();
        let untrusted_keys: Vec<&String> =
            obj.keys().filter(|k| k.starts_with("untrusted_")).collect();
        assert_eq!(
            untrusted_keys.len(),
            4,
            "expected 4 untrusted_ prefixed keys"
        );
        assert!(obj.contains_key("profile_id"));
        assert!(obj.contains_key("rp_id"));
        assert!(!obj["rp_id"].as_str().unwrap().contains("untrusted"));
    }

    #[test]
    fn test_untrusted_injection_does_not_affect_trusted_fields() {
        let req = PromptRequest::builder()
            .profile_id(test_profile_id())
            .mode(PromptMode::Isolated)
            .action(PromptAction::Authenticate)
            .rp_id("example.com")
            .untrusted_reason("example.com\nevil.com")
            .untrusted_page_title("<script>alert('xss')</script>")
            .untrusted_page_url("https://evil.com/phish?rp=example.com")
            .untrusted_account_label("admin@evil.com")
            .build()
            .unwrap();

        assert_eq!(req.rp_id(), "example.com");
        assert_eq!(req.action(), PromptAction::Authenticate);
        assert_eq!(req.mode(), PromptMode::Isolated);
        assert_eq!(req.profile_id().as_str(), "test-profile");
        assert_eq!(req.untrusted_reason(), "example.com\nevil.com");
    }

    #[test]
    fn test_prompt_decision_serialization() {
        assert_eq!(
            serde_json::to_string(&PromptDecision::Approved).unwrap(),
            "\"approved\""
        );
        assert_eq!(
            serde_json::to_string(&PromptDecision::Denied).unwrap(),
            "\"denied\""
        );
        assert_eq!(
            serde_json::to_string(&PromptDecision::Timeout).unwrap(),
            "\"timeout\""
        );
        assert_eq!(
            serde_json::to_string(&PromptDecision::Error).unwrap(),
            "\"error\""
        );
    }

    #[test]
    fn test_prompt_mode_serialization() {
        assert_eq!(
            serde_json::to_string(&PromptMode::Isolated).unwrap(),
            "\"isolated\""
        );
    }

    #[test]
    fn test_prompt_action_serialization() {
        assert_eq!(
            serde_json::to_string(&PromptAction::Register).unwrap(),
            "\"register\""
        );
        assert_eq!(
            serde_json::to_string(&PromptAction::Authenticate).unwrap(),
            "\"authenticate\""
        );
    }

    #[test]
    fn test_prompt_error_kind_serialization() {
        assert_eq!(
            serde_json::to_string(&PromptErrorKind::NotificationUnsupported).unwrap(),
            "\"notification_unsupported\""
        );
        assert_eq!(
            serde_json::to_string(&PromptErrorKind::ServerCapabilityRejected).unwrap(),
            "\"server_capability_rejected\""
        );
        assert_eq!(
            serde_json::to_string(&PromptErrorKind::RenderFailed).unwrap(),
            "\"render_failed\""
        );
        assert_eq!(
            serde_json::to_string(&PromptErrorKind::ActionAmbiguous).unwrap(),
            "\"action_ambiguous\""
        );
        assert_eq!(
            serde_json::to_string(&PromptErrorKind::InternalError).unwrap(),
            "\"internal_error\""
        );
    }

    #[test]
    fn test_prompt_snapshot_roundtrip() {
        let req = build_test_request();
        let snapshot = req.snapshot();
        let json = serde_json::to_string(&snapshot).unwrap();
        let deserialized: PromptSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.profile_id, snapshot.profile_id);
        assert_eq!(deserialized.rp_id, snapshot.rp_id);
        assert_eq!(deserialized.mode, snapshot.mode);
    }

    #[test]
    fn test_prompt_result_constructors() {
        let r = PromptResult::approved(42);
        assert_eq!(r.decision, PromptDecision::Approved);
        assert!(r.error_kind.is_none());
        assert_eq!(r.latency_ms, 42);

        let r = PromptResult::denied(10);
        assert_eq!(r.decision, PromptDecision::Denied);

        let r = PromptResult::timeout(5000);
        assert_eq!(r.decision, PromptDecision::Timeout);

        let r = PromptResult::error(PromptErrorKind::RenderFailed, 1);
        assert_eq!(r.decision, PromptDecision::Error);
        assert_eq!(r.error_kind, Some(PromptErrorKind::RenderFailed));
    }

    #[test]
    fn test_mock_prompt_handle_approve() {
        let mock = MockPromptHandle::new(PromptDecision::Approved, 5);
        let req = build_test_request();
        let result = mock.prompt(&req);
        assert_eq!(result.decision, PromptDecision::Approved);
        assert_eq!(result.latency_ms, 5);
    }

    #[test]
    fn test_mock_prompt_handle_deny() {
        let mock = MockPromptHandle::new(PromptDecision::Denied, 10);
        let req = build_test_request();
        let result = mock.prompt(&req);
        assert_eq!(result.decision, PromptDecision::Denied);
    }

    #[test]
    fn test_mock_prompt_handle_timeout() {
        let mock = MockPromptHandle::new(PromptDecision::Timeout, 60000);
        let req = build_test_request();
        let result = mock.prompt(&req);
        assert_eq!(result.decision, PromptDecision::Timeout);
    }

    #[test]
    fn test_mock_prompt_handle_error() {
        let mock = MockPromptHandle::new(PromptDecision::Error, 0);
        let req = build_test_request();
        let result = mock.prompt(&req);
        assert_eq!(result.decision, PromptDecision::Error);
        assert!(result.error_kind.is_some());
    }

    #[test]
    fn test_mock_prompt_set_decision() {
        let mock = MockPromptHandle::new(PromptDecision::Denied, 0);
        let req = build_test_request();

        let result = mock.prompt(&req);
        assert_eq!(result.decision, PromptDecision::Denied);

        mock.set_decision(PromptDecision::Approved);
        let result = mock.prompt(&req);
        assert_eq!(result.decision, PromptDecision::Approved);
    }

    #[test]
    fn test_auto_approve_only_in_test() {
        let handle = test_prompt_handle_auto_approve();
        let req = build_test_request();
        let result = handle.prompt(&req);
        assert_eq!(result.decision, PromptDecision::Approved);
    }

    #[test]
    fn test_desktop_handle_config_clamping() {
        let h = DesktopPromptHandle::new(0, 0);
        assert_eq!(h.timeout_secs(), MIN_PROMPT_TIMEOUT_SECS);
        assert_eq!(h.min_review_delay_ms(), MIN_MIN_REVIEW_DELAY_MS);

        let h = DesktopPromptHandle::new(999_999, 999_999);
        assert_eq!(h.timeout_secs(), MAX_PROMPT_TIMEOUT_SECS);
        assert_eq!(h.min_review_delay_ms(), MAX_MIN_REVIEW_DELAY_MS);
    }

    #[test]
    fn test_desktop_handle_default_config() {
        let h = DesktopPromptHandle::default_config();
        assert_eq!(h.timeout_secs(), DEFAULT_PROMPT_TIMEOUT_SECS);
        assert_eq!(h.min_review_delay_ms(), DEFAULT_MIN_REVIEW_DELAY_MS);
    }

    #[test]
    fn test_server_capability_variants() {
        assert_ne!(
            ServerCapability::FullActions,
            ServerCapability::DefaultActionOnly
        );
        assert_ne!(ServerCapability::FullActions, ServerCapability::Unknown);
        assert_ne!(
            ServerCapability::DefaultActionOnly,
            ServerCapability::Unknown
        );
    }

    #[test]
    fn test_query_server_capabilities_does_not_panic() {
        let _ = query_server_capabilities();
    }

    #[test]
    fn test_build_security_title_register() {
        let title = build_security_title(PromptAction::Register);
        assert!(title.contains("registration"));
        assert!(title.contains("Passless"));
    }

    #[test]
    fn test_build_security_title_authenticate() {
        let title = build_security_title(PromptAction::Authenticate);
        assert!(title.contains("Authentication"));
        assert!(title.contains("Passless"));
    }

    #[test]
    fn test_build_security_body_contains_trusted_info() {
        let req = build_test_request();
        let body = build_security_body(&req);
        assert!(body.contains("example.com"));
        assert!(body.contains("test-profile"));
        assert!(body.contains("authenticate"));
        assert!(body.contains("my-key"));
    }

    #[test]
    fn test_build_security_body_without_credential_label() {
        let req = PromptRequest::builder()
            .profile_id(test_profile_id())
            .mode(PromptMode::Isolated)
            .action(PromptAction::Register)
            .rp_id("example.com")
            .build()
            .unwrap();
        let body = build_security_body(&req);
        assert!(body.contains("example.com"));
        assert!(!body.contains("Credential:"));
    }

    #[test]
    fn test_credential_label_bounded() {
        let long_label = "B".repeat(500);
        let req = PromptRequest::builder()
            .profile_id(test_profile_id())
            .mode(PromptMode::Isolated)
            .action(PromptAction::Authenticate)
            .rp_id("example.com")
            .credential_label(&long_label)
            .build()
            .unwrap();
        assert!(req.credential_label().unwrap().len() <= MAX_CREDENTIAL_LABEL_LEN);
    }

    #[test]
    fn test_prompt_request_snapshot_no_free_text_in_trusted() {
        let req = build_test_request();
        let snapshot = req.snapshot();
        let json = serde_json::to_value(&snapshot).unwrap();
        let obj = json.as_object().unwrap();

        let trusted_keys_with_strings =
            ["profile_id", "rp_id", "credential_label", "credential_ref"];
        for key in &trusted_keys_with_strings {
            if let Some(val) = obj.get(*key)
                && let Some(s) = val.as_str()
            {
                assert!(
                    s.len() <= MAX_UNTRUSTED_LEN,
                    "trusted field '{}' exceeds max length",
                    key
                );
            }
        }
    }

    #[test]
    fn test_prompt_request_closed_struct_no_extra_fields() {
        let req = build_test_request();
        let json = serde_json::to_value(&req).unwrap();
        let obj = json.as_object().unwrap();
        let expected_keys: std::collections::HashSet<&str> = [
            "profile_id",
            "mode",
            "rp_id",
            "action",
            "credential_label",
            "credential_ref",
            "grant_ttl_secs",
            "session_ttl_secs",
            "untrusted_reason",
            "untrusted_page_title",
            "untrusted_page_url",
            "untrusted_account_label",
        ]
        .iter()
        .copied()
        .collect();
        let actual_keys: std::collections::HashSet<&str> = obj.keys().map(|k| k.as_str()).collect();
        assert_eq!(
            actual_keys, expected_keys,
            "PromptRequest has unexpected fields"
        );
    }

    #[test]
    fn test_min_review_delay_enforcement() {
        let handle = DesktopPromptHandle::new(60, 5000);
        assert_eq!(handle.min_review_delay_ms(), 5000);
    }

    #[test]
    fn test_prompt_request_rejects_leading_dot_rp_id() {
        let result = PromptRequest::builder()
            .profile_id(test_profile_id())
            .mode(PromptMode::Isolated)
            .action(PromptAction::Register)
            .rp_id(".example.com")
            .build();
        assert!(matches!(result, Err(PromptBuildError::WildcardRpId)));
    }

    #[test]
    fn test_build_security_body_exact_trusted_labels() {
        let req = build_test_request();
        let body = build_security_body(&req);

        assert!(body.contains("Profile (trusted): test-profile"));
        assert!(body.contains("Mode (trusted): isolated"));
        assert!(body.contains("Exact relying party (trusted): example.com"));
        assert!(body.contains("Action (trusted): authenticate"));
        assert!(body.contains("Credential label (trusted): my-key"));
        assert!(body.contains("Credential ref (trusted):"));

        assert!(body.contains("Agent-supplied reason (untrusted):"));
        assert!(body.contains("Page title (untrusted):"));
        assert!(body.contains("Page URL (untrusted):"));
        assert!(body.contains("Account label (untrusted):"));

        assert!(!body.contains("\nProfile: "));
        assert!(!body.contains("\nMode: "));
        assert!(!body.contains("\nRelying party: "));
        assert!(!body.contains("\nAction: "));
    }

    #[test]
    fn test_build_security_body_exact_snapshot_with_clamped_ttls() {
        let req = PromptRequest::builder()
            .profile_id(test_profile_id())
            .mode(PromptMode::Isolated)
            .action(PromptAction::Register)
            .rp_id("login.example.com")
            .credential_label("work-key")
            .grant_ttl_secs(300)
            .session_ttl_secs(3600)
            .untrusted_reason("Sign in")
            .untrusted_page_title("Login Page")
            .untrusted_page_url("https://login.example.com/auth")
            .untrusted_account_label("user@example.com")
            .build()
            .unwrap();

        let body = build_security_body(&req);

        let expected = "Profile (trusted): test-profile\n\
            Mode (trusted): isolated\n\
            Exact relying party (trusted): login.example.com\n\
            Action (trusted): register\n\
            Credential label (trusted): work-key\n\
            Grant TTL: 300s\n\
            Browser session TTL: 3600s\n\
            Agent-supplied reason (untrusted): Sign in\n\
            Page title (untrusted): Login Page\n\
            Page URL (untrusted): https://login.example.com/auth\n\
            Account label (untrusted): user@example.com";

        assert_eq!(body, expected);
    }

    #[test]
    fn test_build_security_body_no_credential_ref_omits_label() {
        let req = PromptRequest::builder()
            .profile_id(test_profile_id())
            .mode(PromptMode::Isolated)
            .action(PromptAction::Register)
            .rp_id("example.com")
            .build()
            .unwrap();

        let body = build_security_body(&req);
        assert!(!body.contains("Credential label"));
        assert!(!body.contains("Credential ref"));
    }
}

#[cfg(all(test, feature = "agent"))]
mod dbus_tests {
    use std::collections::HashMap;
    use std::env;
    use std::process::Command;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tokio::sync::{Mutex as AsyncMutex, Notify};
    use zbus::connection::Builder;
    use zbus::interface;

    use super::*;
    use passless_core::agent::{CredentialRef, ProfileId};

    const TEST_TIMEOUT_SECS: u64 = 10;
    const NOTIFY_WAIT_TIMEOUT_MS: u64 = 5000;

    static DBUS_ENV_LOCK: AsyncMutex<()> = AsyncMutex::const_new(());

    #[derive(Debug, Clone)]
    struct CapturedNotification {
        app_name: String,
        summary: String,
        body: String,
        actions: Vec<String>,
        expire_timeout: i32,
    }

    #[derive(Clone, Copy)]
    enum ServerKind {
        FullActions,
        DefaultActionOnly,
        Unknown,
    }

    struct SharedState {
        next_id: u32,
        captured: Option<CapturedNotification>,
    }

    struct TestNotificationService {
        state: Arc<Mutex<SharedState>>,
        notify_ready: Arc<Notify>,
        server_kind: ServerKind,
    }

    impl TestNotificationService {
        fn new(server_kind: ServerKind) -> (Self, Arc<Mutex<SharedState>>, Arc<Notify>) {
            let state = Arc::new(Mutex::new(SharedState {
                next_id: 1,
                captured: None,
            }));
            let notify_ready = Arc::new(Notify::new());
            let svc = Self {
                state: Arc::clone(&state),
                notify_ready: Arc::clone(&notify_ready),
                server_kind,
            };
            (svc, state, notify_ready)
        }
    }

    #[interface(name = "org.freedesktop.Notifications")]
    impl TestNotificationService {
        async fn get_capabilities(&self) -> Vec<String> {
            match self.server_kind {
                ServerKind::FullActions => {
                    vec![
                        "actions".to_string(),
                        "body".to_string(),
                        "body-markup".to_string(),
                    ]
                }
                ServerKind::DefaultActionOnly => {
                    vec!["body".to_string()]
                }
                ServerKind::Unknown => {
                    vec![]
                }
            }
        }

        // The freedesktop Notifications D-Bus method has this fixed external signature.
        #[allow(clippy::too_many_arguments)]
        async fn notify(
            &self,
            app_name: &str,
            replaces_id: u32,
            _app_icon: &str,
            summary: &str,
            body: &str,
            actions: Vec<String>,
            _hints: HashMap<String, zbus::zvariant::Value<'_>>,
            expire_timeout: i32,
        ) -> zbus::fdo::Result<u32> {
            let mut state = self.state.lock().unwrap();
            let id = if replaces_id == 0 {
                let id = state.next_id;
                state.next_id += 1;
                id
            } else {
                replaces_id
            };

            state.captured = Some(CapturedNotification {
                app_name: app_name.to_string(),
                summary: summary.to_string(),
                body: body.to_string(),
                actions,
                expire_timeout,
            });

            self.notify_ready.notify_one();
            Ok(id)
        }

        async fn close_notification(&self, id: u32) -> zbus::fdo::Result<()> {
            let _ = id;
            Ok(())
        }

        async fn get_server_information(
            &self,
        ) -> zbus::fdo::Result<(String, String, String, String)> {
            match self.server_kind {
                ServerKind::FullActions => Ok((
                    "TestNotificationServer".to_string(),
                    "1.0".to_string(),
                    "1.0".to_string(),
                    "1.2".to_string(),
                )),
                ServerKind::DefaultActionOnly => Ok((
                    "notify-osd".to_string(),
                    "1.0".to_string(),
                    "1.0".to_string(),
                    "1.2".to_string(),
                )),
                ServerKind::Unknown => Err(zbus::fdo::Error::Failed(
                    "no notification server".to_string(),
                )),
            }
        }
    }

    async fn emit_action_invoked(conn: &zbus::Connection, id: u32, action: &str) {
        let _ = conn
            .emit_signal(
                None::<zbus::names::BusName<'_>>,
                "/org/freedesktop/Notifications",
                "org.freedesktop.Notifications",
                "ActionInvoked",
                &(id, action),
            )
            .await;
    }

    async fn emit_notification_closed(conn: &zbus::Connection, id: u32, reason: u32) {
        let _ = conn
            .emit_signal(
                None::<zbus::names::BusName<'_>>,
                "/org/freedesktop/Notifications",
                "org.freedesktop.Notifications",
                "NotificationClosed",
                &(id, reason),
            )
            .await;
    }

    struct PrivateDBus {
        pid: u32,
        address: String,
    }

    impl PrivateDBus {
        fn start() -> Self {
            let output = Command::new("dbus-daemon")
                .args(["--print-address=1", "--print-pid=2", "--fork", "--session"])
                .output()
                .expect("failed to start dbus-daemon");

            let address = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let pid_str = String::from_utf8_lossy(&output.stderr).trim().to_string();

            assert!(!address.is_empty(), "dbus-daemon did not print address");
            assert!(!pid_str.is_empty(), "dbus-daemon did not print pid");

            let pid: u32 = pid_str.parse().expect("invalid pid from dbus-daemon");

            Self { pid, address }
        }

        fn address(&self) -> &str {
            &self.address
        }
    }

    impl Drop for PrivateDBus {
        fn drop(&mut self) {
            unsafe {
                libc::kill(self.pid as i32, libc::SIGKILL);
            }
        }
    }

    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
    }

    impl EnvGuard {
        unsafe fn set(key: &'static str, value: &str) -> Self {
            let prev = env::var(key).ok();
            unsafe {
                env::set_var(key, value);
            }
            Self { key, prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                if let Some(ref val) = self.prev {
                    env::set_var(self.key, val);
                } else {
                    env::remove_var(self.key);
                }
            }
        }
    }

    fn test_profile_id() -> ProfileId {
        ProfileId::new("test-profile").unwrap()
    }

    fn test_cred() -> CredentialRef {
        CredentialRef::with_default_domain(b"test-credential-id")
    }

    fn build_test_request() -> PromptRequest {
        PromptRequest::builder()
            .profile_id(test_profile_id())
            .mode(PromptMode::Isolated)
            .action(PromptAction::Authenticate)
            .rp_id("example.com")
            .credential_label("my-key")
            .credential_ref(test_cred())
            .grant_ttl_secs(300)
            .session_ttl_secs(3600)
            .untrusted_reason("Login to example.com")
            .untrusted_page_title("Example Login")
            .untrusted_page_url("https://example.com/login")
            .untrusted_account_label("user@example.com")
            .build()
            .unwrap()
    }

    async fn run_prompt_test<F, Fut>(
        server_kind: ServerKind,
        _timeout_secs: u64,
        _min_review_delay_ms: u64,
        test_fn: F,
    ) -> PromptResult
    where
        F: FnOnce(Arc<Mutex<SharedState>>, Arc<zbus::Connection>, Arc<Notify>) -> Fut
            + Send
            + 'static,
        Fut: std::future::Future<Output = PromptResult> + Send,
    {
        let _lock = DBUS_ENV_LOCK.lock().await;

        let dbus = PrivateDBus::start();
        let _env_guard = unsafe { EnvGuard::set("DBUS_SESSION_BUS_ADDRESS", dbus.address()) };

        let timeout_result = tokio::time::timeout(Duration::from_secs(TEST_TIMEOUT_SECS), async {
            let (service, state, notify_ready) = TestNotificationService::new(server_kind);

            let conn = Builder::session()
                .unwrap()
                .name("org.freedesktop.Notifications")
                .unwrap()
                .serve_at("/org/freedesktop/Notifications", service)
                .unwrap()
                .build()
                .await
                .unwrap();

            let conn = Arc::new(conn);

            let result = test_fn(state, Arc::clone(&conn), notify_ready).await;

            let _ = (*conn).clone().close().await;
            result
        })
        .await;

        match timeout_result {
            Ok(result) => result,
            Err(_) => panic!("Test timed out after {}s", TEST_TIMEOUT_SECS),
        }
    }

    #[test]
    fn test_desktop_prompt_trusted_content() {
        let request = build_test_request();
        let title = build_security_title(request.action());
        let body = build_security_body(&request);

        assert!(title.contains("Authentication"));
        assert!(body.contains("Profile (trusted): test-profile"));
        assert!(body.contains("Mode (trusted): isolated"));
        assert!(body.contains("Exact relying party (trusted): example.com"));
        assert!(body.contains("Action (trusted): authenticate"));
        assert!(body.contains("Agent-supplied reason (untrusted): Login to example.com"));
        assert!(body.contains("Page title (untrusted): Example Login"));
        assert!(body.contains("Page URL (untrusted): https://example.com/login"));
    }

    #[test]
    fn test_desktop_prompt_timeout_with_private_dbus() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            run_prompt_test(
                ServerKind::FullActions,
                5,
                10,
                |state, conn, notify_ready| async move {
                    let handle = Arc::new(DesktopPromptHandle::new(5, 10));
                    let request = build_test_request();

                    let prompt_task = tokio::task::spawn_blocking({
                        let handle = Arc::clone(&handle);
                        let request = request.clone();
                        move || handle.prompt(&request)
                    });

                    let wait_result = tokio::time::timeout(
                        Duration::from_millis(NOTIFY_WAIT_TIMEOUT_MS),
                        notify_ready.notified(),
                    )
                    .await;
                    assert!(wait_result.is_ok(), "Notify() was not called");

                    let captured = state
                        .lock()
                        .unwrap()
                        .captured
                        .clone()
                        .expect("notification not captured");
                    assert!(!captured.app_name.is_empty());
                    assert!(captured.summary.contains("Authentication"));
                    assert!(captured.body.contains("example.com"));
                    assert!(captured.actions.contains(&"approve".to_string()));
                    assert!(captured.actions.contains(&"deny".to_string()));
                    assert_eq!(captured.expire_timeout, 5000);

                    tokio::time::sleep(Duration::from_millis(100)).await;
                    emit_notification_closed(&conn, 1, 1).await;

                    prompt_task.await.unwrap()
                },
            )
            .await
        });

        assert_eq!(result.decision, PromptDecision::Timeout);
    }

    #[test]
    fn test_desktop_prompt_delayed_approve() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            run_prompt_test(
                ServerKind::FullActions,
                5,
                100,
                |_state, conn, notify_ready| async move {
                    let handle = Arc::new(DesktopPromptHandle::new(5, 100));
                    let request = build_test_request();

                    let prompt_task = tokio::task::spawn_blocking({
                        let handle = Arc::clone(&handle);
                        let request = request.clone();
                        move || handle.prompt(&request)
                    });

                    let wait_result = tokio::time::timeout(
                        Duration::from_millis(NOTIFY_WAIT_TIMEOUT_MS),
                        notify_ready.notified(),
                    )
                    .await;
                    assert!(wait_result.is_ok(), "Notify() was not called");

                    tokio::time::sleep(Duration::from_millis(150)).await;
                    emit_action_invoked(&conn, 1, "approve").await;

                    prompt_task.await.unwrap()
                },
            )
            .await
        });

        assert_eq!(result.decision, PromptDecision::Approved);
    }

    #[test]
    fn test_desktop_prompt_premature_approve_denied() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            run_prompt_test(
                ServerKind::FullActions,
                5,
                1000,
                |_state, conn, notify_ready| async move {
                    let handle = Arc::new(DesktopPromptHandle::new(5, 1000));
                    let request = build_test_request();

                    let prompt_task = tokio::task::spawn_blocking({
                        let handle = Arc::clone(&handle);
                        let request = request.clone();
                        move || handle.prompt(&request)
                    });

                    let wait_result = tokio::time::timeout(
                        Duration::from_millis(NOTIFY_WAIT_TIMEOUT_MS),
                        notify_ready.notified(),
                    )
                    .await;
                    assert!(wait_result.is_ok(), "Notify() was not called");

                    tokio::time::sleep(Duration::from_millis(50)).await;
                    emit_action_invoked(&conn, 1, "approve").await;

                    prompt_task.await.unwrap()
                },
            )
            .await
        });

        assert_eq!(result.decision, PromptDecision::Denied);
    }

    #[test]
    fn test_desktop_prompt_explicit_deny() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            run_prompt_test(
                ServerKind::FullActions,
                5,
                100,
                |state, conn, notify_ready| async move {
                    let handle = Arc::new(DesktopPromptHandle::new(5, 100));
                    let request = build_test_request();

                    let prompt_task = tokio::task::spawn_blocking({
                        let handle = Arc::clone(&handle);
                        let request = request.clone();
                        move || handle.prompt(&request)
                    });

                    let wait_result = tokio::time::timeout(
                        Duration::from_millis(NOTIFY_WAIT_TIMEOUT_MS),
                        notify_ready.notified(),
                    )
                    .await;
                    assert!(wait_result.is_ok(), "Notify() was not called");

                    let captured = state
                        .lock()
                        .unwrap()
                        .captured
                        .clone()
                        .expect("notification not captured");
                    assert!(captured.summary.contains("Authentication"));
                    assert!(captured.body.contains("test-profile"));

                    tokio::time::sleep(Duration::from_millis(150)).await;
                    emit_action_invoked(&conn, 1, "deny").await;

                    prompt_task.await.unwrap()
                },
            )
            .await
        });

        assert_eq!(result.decision, PromptDecision::Denied);
    }

    #[test]
    fn test_desktop_prompt_close_signal() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            run_prompt_test(
                ServerKind::FullActions,
                5,
                100,
                |_state, conn, notify_ready| async move {
                    let handle = Arc::new(DesktopPromptHandle::new(5, 100));
                    let request = build_test_request();

                    let prompt_task = tokio::task::spawn_blocking({
                        let handle = Arc::clone(&handle);
                        let request = request.clone();
                        move || handle.prompt(&request)
                    });

                    let wait_result = tokio::time::timeout(
                        Duration::from_millis(NOTIFY_WAIT_TIMEOUT_MS),
                        notify_ready.notified(),
                    )
                    .await;
                    assert!(wait_result.is_ok(), "Notify() was not called");

                    tokio::time::sleep(Duration::from_millis(100)).await;
                    emit_notification_closed(&conn, 1, 2).await;

                    prompt_task.await.unwrap()
                },
            )
            .await
        });

        assert_eq!(result.decision, PromptDecision::Timeout);
    }

    #[test]
    fn test_desktop_prompt_capability_default_action_only_rejected() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            run_prompt_test(
                ServerKind::DefaultActionOnly,
                5,
                100,
                |_state, _conn, _notify_ready| async move {
                    let handle = Arc::new(DesktopPromptHandle::new(5, 100));
                    let request = build_test_request();

                    let prompt_task = tokio::task::spawn_blocking({
                        let handle = Arc::clone(&handle);
                        let request = request.clone();
                        move || handle.prompt(&request)
                    });

                    prompt_task.await.unwrap()
                },
            )
            .await
        });

        assert_eq!(result.decision, PromptDecision::Error);
        assert_eq!(
            result.error_kind,
            Some(PromptErrorKind::ServerCapabilityRejected)
        );
    }

    #[test]
    fn test_desktop_prompt_capability_unknown_rejected() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            run_prompt_test(
                ServerKind::Unknown,
                5,
                100,
                |_state, _conn, _notify_ready| async move {
                    let handle = Arc::new(DesktopPromptHandle::new(5, 100));
                    let request = build_test_request();

                    let prompt_task = tokio::task::spawn_blocking({
                        let handle = Arc::clone(&handle);
                        let request = request.clone();
                        move || handle.prompt(&request)
                    });

                    prompt_task.await.unwrap()
                },
            )
            .await
        });

        assert_eq!(result.decision, PromptDecision::Error);
        assert_eq!(
            result.error_kind,
            Some(PromptErrorKind::NotificationUnsupported)
        );
    }
}
