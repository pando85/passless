use std::fmt;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use passless_core::agent::{
    BrowserLeaseId, CredentialRef, EndpointId, GrantId, IntentId, PrincipalSessionId, ProfileId,
};

use super::grant::{CeremonyId, GrantRequestId};
use super::prompt::{PromptAction, PromptErrorKind, PromptMode};

pub const AUDIT_SCHEMA_VERSION: u32 = 2;

// The closed-schema tests apply these deny lists to every constructible event.
#[cfg(test)]
const FORBIDDEN_FIELD_NAMES: &[&str] = &[
    "message",
    "msg",
    "detail",
    "details",
    "description",
    "secret",
    "key",
    "token",
    "pin",
    "password",
    "passphrase",
    "raw_bytes",
    "data",
    "payload",
    "credential_data",
    "private_key",
    "secret_key",
    "shared_secret",
    "note",
    "comment",
    "reason_text",
    "error_message",
    "free_text",
    "arbitrary",
];

#[cfg(test)]
const FORBIDDEN_KEY_SUBSTRINGS: &[&str] = &["secret", "password", "token", "pin", "private_key"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditBuildError {
    EmptyVersion,
    EmptyRpId,
    InvalidFingerprint,
}

impl fmt::Display for AuditBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyVersion => write!(f, "version must not be empty"),
            Self::EmptyRpId => write!(f, "RP ID must not be empty"),
            Self::InvalidFingerprint => write!(f, "invalid credential fingerprint"),
        }
    }
}

impl std::error::Error for AuditBuildError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    v: u32,
    ts: u64,
    #[serde(flatten)]
    payload: AuditPayload,
}

impl AuditEvent {
    fn new(payload: AuditPayload) -> Self {
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            v: AUDIT_SCHEMA_VERSION,
            ts,
            payload,
        }
    }

    #[cfg(test)]
    fn with_timestamp(payload: AuditPayload, ts: u64) -> Self {
        Self {
            v: AUDIT_SCHEMA_VERSION,
            ts,
            payload,
        }
    }

    pub fn schema_version(&self) -> u32 {
        self.v
    }

    pub fn timestamp_ms(&self) -> u64 {
        self.ts
    }

    pub fn kind_name(&self) -> &'static str {
        self.payload.kind_name()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum AuditPayload {
    #[serde(rename = "daemon.start")]
    DaemonStart(DaemonStartMeta),
    #[serde(rename = "daemon.stop")]
    DaemonStop(DaemonStopMeta),
    #[serde(rename = "daemon.config_reload")]
    ConfigReload(ConfigReloadMeta),
    #[serde(rename = "daemon.recover")]
    DaemonRecover(DaemonRecoverMeta),

    #[serde(rename = "profile.create")]
    ProfileCreate(ProfileCreateMeta),
    #[serde(rename = "profile.destroy")]
    ProfileDestroy(ProfileDestroyMeta),
    #[serde(rename = "profile.fail")]
    ProfileFail(ProfileFailMeta),

    #[serde(rename = "endpoint.create")]
    EndpointCreate(EndpointCreateMeta),
    #[serde(rename = "endpoint.destroy")]
    EndpointDestroy(EndpointDestroyMeta),
    #[serde(rename = "endpoint.fail")]
    EndpointFail(EndpointFailMeta),

    #[serde(rename = "principal.launch")]
    PrincipalLaunch(PrincipalLaunchMeta),
    #[serde(rename = "principal.deny")]
    PrincipalDeny(PrincipalDenyMeta),
    #[serde(rename = "principal.exit")]
    PrincipalExit(PrincipalExitMeta),

    #[serde(rename = "browser_lease.launch")]
    BrowserLeaseLaunch(BrowserLeaseLaunchMeta),
    #[serde(rename = "browser_lease.revoke")]
    BrowserLeaseRevoke(BrowserLeaseRevokeMeta),
    #[serde(rename = "browser_lease.expire")]
    BrowserLeaseExpire(BrowserLeaseExpireMeta),
    #[serde(rename = "browser_lease.crash")]
    BrowserLeaseCrash(BrowserLeaseCrashMeta),
    #[serde(rename = "browser_lease.cleanup")]
    BrowserLeaseCleanup(BrowserLeaseCleanupMeta),
    #[serde(rename = "browser_lease.quarantine")]
    BrowserLeaseQuarantine(BrowserLeaseQuarantineMeta),

    #[serde(rename = "browser_control.request")]
    BrowserControlRequest(BrowserControlRequestMeta),

    #[serde(rename = "intent.create")]
    IntentCreate(IntentCreateMeta),
    #[serde(rename = "intent.approve")]
    IntentApprove(IntentApproveMeta),
    #[serde(rename = "intent.deny")]
    IntentDeny(IntentDenyMeta),
    #[serde(rename = "intent.cancel")]
    IntentCancel(IntentCancelMeta),
    #[serde(rename = "intent.claim")]
    IntentClaim(IntentClaimMeta),
    #[serde(rename = "intent.consume")]
    IntentConsume(IntentConsumeMeta),
    #[serde(rename = "intent.expire")]
    IntentExpire(IntentExpireMeta),

    #[serde(rename = "grant.request")]
    GrantRequest(GrantRequestMeta),
    #[serde(rename = "grant.approve")]
    GrantApprove(GrantApproveMeta),
    #[serde(rename = "grant.revoke")]
    GrantRevoke(GrantRevokeMeta),
    #[serde(rename = "grant.expire")]
    GrantExpire(GrantExpireMeta),
    #[serde(rename = "grant.claim")]
    GrantClaim(GrantClaimMeta),
    #[serde(rename = "grant.consume")]
    GrantConsume(GrantConsumeMeta),

    #[serde(rename = "policy.allow")]
    PolicyAllow(PolicyAllowMeta),
    #[serde(rename = "policy.deny")]
    PolicyDeny(PolicyDenyMeta),

    #[serde(rename = "ceremony.start")]
    CeremonyStart(CeremonyStartMeta),
    #[serde(rename = "ceremony.success")]
    CeremonySuccess(CeremonySuccessMeta),
    #[serde(rename = "ceremony.failure")]
    CeremonyFailure(CeremonyFailureMeta),

    #[serde(rename = "credential.create")]
    CredentialCreate(CredentialCreateMeta),
    #[serde(rename = "credential.update")]
    CredentialUpdate(CredentialUpdateMeta),
    #[serde(rename = "credential.delete")]
    CredentialDelete(CredentialDeleteMeta),
    #[serde(rename = "credential.list")]
    CredentialList(CredentialListMeta),

    #[serde(rename = "pin.success")]
    PinSuccess(PinSuccessMeta),
    #[serde(rename = "pin.failure")]
    PinFailure(PinFailureMeta),
    #[serde(rename = "uv.success")]
    UvSuccess(UvSuccessMeta),
    #[serde(rename = "uv.failure")]
    UvFailure(UvFailureMeta),

    #[serde(rename = "prompt.display")]
    PromptDisplay(PromptDisplayMeta),
    #[serde(rename = "prompt.approve")]
    PromptApprove(PromptApproveMeta),
    #[serde(rename = "prompt.deny")]
    PromptDeny(PromptDenyMeta),
    #[serde(rename = "prompt.timeout")]
    PromptTimeout(PromptTimeoutMeta),
    #[serde(rename = "prompt.error")]
    PromptError(PromptErrorMeta),

    #[serde(rename = "admin.profile_enable")]
    AdminProfileEnable(AdminProfileEnableMeta),
    #[serde(rename = "admin.profile_disable")]
    AdminProfileDisable(AdminProfileDisableMeta),
    #[serde(rename = "admin.profile_disable_request")]
    AdminProfileDisableRequest(AdminProfileDisableRequestMeta),
    #[serde(rename = "admin.profile_disable_failed")]
    AdminProfileDisableFailed(AdminProfileDisableFailedMeta),
    #[serde(rename = "admin.policy_recompile")]
    AdminPolicyRecompile(AdminPolicyRecompileMeta),
    #[serde(rename = "admin.credential_revoke")]
    AdminCredentialRevoke(AdminCredentialRevokeMeta),
    #[serde(rename = "admin.credential_delete")]
    AdminCredentialDelete(AdminCredentialDeleteMeta),
    #[serde(rename = "admin.credential_rename")]
    AdminCredentialRename(AdminCredentialRenameMeta),
    #[serde(rename = "admin.grant_revoke")]
    AdminGrantRevoke(AdminGrantRevokeMeta),
    #[serde(rename = "admin.session_revoke")]
    AdminSessionRevoke(AdminSessionRevokeMeta),
    #[serde(rename = "admin.shutdown_request")]
    AdminShutdownRequest(AdminShutdownRequestMeta),
}

impl AuditPayload {
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::DaemonStart(_) => "daemon.start",
            Self::DaemonStop(_) => "daemon.stop",
            Self::ConfigReload(_) => "daemon.config_reload",
            Self::DaemonRecover(_) => "daemon.recover",
            Self::ProfileCreate(_) => "profile.create",
            Self::ProfileDestroy(_) => "profile.destroy",
            Self::ProfileFail(_) => "profile.fail",
            Self::EndpointCreate(_) => "endpoint.create",
            Self::EndpointDestroy(_) => "endpoint.destroy",
            Self::EndpointFail(_) => "endpoint.fail",
            Self::PrincipalLaunch(_) => "principal.launch",
            Self::PrincipalDeny(_) => "principal.deny",
            Self::PrincipalExit(_) => "principal.exit",
            Self::BrowserLeaseLaunch(_) => "browser_lease.launch",
            Self::BrowserLeaseRevoke(_) => "browser_lease.revoke",
            Self::BrowserLeaseExpire(_) => "browser_lease.expire",
            Self::BrowserLeaseCrash(_) => "browser_lease.crash",
            Self::BrowserLeaseCleanup(_) => "browser_lease.cleanup",
            Self::BrowserLeaseQuarantine(_) => "browser_lease.quarantine",
            Self::BrowserControlRequest(_) => "browser_control.request",
            Self::IntentCreate(_) => "intent.create",
            Self::IntentApprove(_) => "intent.approve",
            Self::IntentDeny(_) => "intent.deny",
            Self::IntentCancel(_) => "intent.cancel",
            Self::IntentClaim(_) => "intent.claim",
            Self::IntentConsume(_) => "intent.consume",
            Self::IntentExpire(_) => "intent.expire",
            Self::GrantRequest(_) => "grant.request",
            Self::GrantApprove(_) => "grant.approve",
            Self::GrantRevoke(_) => "grant.revoke",
            Self::GrantExpire(_) => "grant.expire",
            Self::GrantClaim(_) => "grant.claim",
            Self::GrantConsume(_) => "grant.consume",
            Self::PolicyAllow(_) => "policy.allow",
            Self::PolicyDeny(_) => "policy.deny",
            Self::CeremonyStart(_) => "ceremony.start",
            Self::CeremonySuccess(_) => "ceremony.success",
            Self::CeremonyFailure(_) => "ceremony.failure",
            Self::CredentialCreate(_) => "credential.create",
            Self::CredentialUpdate(_) => "credential.update",
            Self::CredentialDelete(_) => "credential.delete",
            Self::CredentialList(_) => "credential.list",
            Self::PinSuccess(_) => "pin.success",
            Self::PinFailure(_) => "pin.failure",
            Self::UvSuccess(_) => "uv.success",
            Self::UvFailure(_) => "uv.failure",
            Self::PromptDisplay(_) => "prompt.display",
            Self::PromptApprove(_) => "prompt.approve",
            Self::PromptDeny(_) => "prompt.deny",
            Self::PromptTimeout(_) => "prompt.timeout",
            Self::PromptError(_) => "prompt.error",
            Self::AdminProfileEnable(_) => "admin.profile_enable",
            Self::AdminProfileDisable(_) => "admin.profile_disable",
            Self::AdminProfileDisableRequest(_) => "admin.profile_disable_request",
            Self::AdminProfileDisableFailed(_) => "admin.profile_disable_failed",
            Self::AdminPolicyRecompile(_) => "admin.policy_recompile",
            Self::AdminCredentialRevoke(_) => "admin.credential_revoke",
            Self::AdminCredentialDelete(_) => "admin.credential_delete",
            Self::AdminCredentialRename(_) => "admin.credential_rename",
            Self::AdminGrantRevoke(_) => "admin.grant_revoke",
            Self::AdminSessionRevoke(_) => "admin.session_revoke",
            Self::AdminShutdownRequest(_) => "admin.shutdown_request",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    Local,
    Pass,
    Tpm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    Register,
    Authenticate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    GracefulShutdown,
    Signal,
    FatalError,
    OomKill,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailReason {
    DeviceCreationFailed,
    CreateRejected,
    SandboxViolation,
    ResourceExhausted,
    Timeout,
    InternalError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    PolicyDenied,
    ProfileNotFound,
    SessionUnbound,
    IdentityMismatch,
    RateLimited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitReason {
    Normal,
    Signal,
    Crash,
    Evicted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevokeReason {
    AdminRevoked,
    PrincipalExit,
    PolicyReload,
    DaemonShutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    IntegrityViolation,
    SymlinkEscape,
    PermissionDrift,
    ManifestTampered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CeremonyFailReason {
    GrantExpired,
    GrantRevoked,
    PolicyMismatch,
    SessionMismatch,
    ConsumedTwice,
    IntentNotApproved,
    CredentialMismatch,
    UvRequired,
    InnerHandlerError,
    ResponseParseError,
    AuditWriteFailed,
    ConsumeFailed,
    ScopeActivationFailed,
    CommandClassDenied,
    GetNextAssertionDenied,
    UserDenied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinOutcome {
    Success,
    InvalidPin,
    Blocked,
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UvOutcome {
    Success,
    NotVerified,
    Failed,
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStartMeta {
    version: String,
    pid: u32,
    backend: BackendKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStopMeta {
    reason: StopReason,
    uptime_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigReloadMeta {
    generation: u64,
    changed_field_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryReason {
    IncompleteTailTruncated,
    AnchorViolation,
    SegmentGapDetected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonRecoverMeta {
    reason: RecoveryReason,
    truncated_size: u64,
    anchor_segment: u64,
    anchor_sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileCreateMeta {
    profile_id: ProfileId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileDestroyMeta {
    profile_id: ProfileId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileFailMeta {
    profile_id: ProfileId,
    reason: FailReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointCreateMeta {
    endpoint_id: EndpointId,
    profile_id: ProfileId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointDestroyMeta {
    endpoint_id: EndpointId,
    profile_id: ProfileId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointFailMeta {
    endpoint_id: EndpointId,
    profile_id: ProfileId,
    reason: FailReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalLaunchMeta {
    session_id: PrincipalSessionId,
    profile_id: ProfileId,
    uid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalDenyMeta {
    session_id: PrincipalSessionId,
    profile_id: ProfileId,
    reason: DenyReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalExitMeta {
    session_id: PrincipalSessionId,
    profile_id: ProfileId,
    reason: ExitReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserLeaseLaunchMeta {
    lease_id: BrowserLeaseId,
    profile_id: ProfileId,
    endpoint_id: EndpointId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cdp_expose: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserLeaseRevokeMeta {
    lease_id: BrowserLeaseId,
    reason: RevokeReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserLeaseExpireMeta {
    lease_id: BrowserLeaseId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserLeaseCrashMeta {
    lease_id: BrowserLeaseId,
    exit_code: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserLeaseCleanupMeta {
    lease_id: BrowserLeaseId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserLeaseQuarantineMeta {
    lease_id: BrowserLeaseId,
    reason: QuarantineReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserControlOutcome {
    Requested,
    Success,
    Denied,
    Error,
    Timeout,
    BrowserExit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserControlRequestMeta {
    profile_id: ProfileId,
    lease_id: BrowserLeaseId,
    cdp_method: String,
    outcome: BrowserControlOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentCreateMeta {
    intent_id: IntentId,
    profile_id: ProfileId,
    action: AuditAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentApproveMeta {
    intent_id: IntentId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentDenyMeta {
    intent_id: IntentId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentCancelMeta {
    intent_id: IntentId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentClaimMeta {
    intent_id: IntentId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentConsumeMeta {
    intent_id: IntentId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentExpireMeta {
    intent_id: IntentId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantRequestMeta {
    request_id: String,
    profile_id: ProfileId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantApproveMeta {
    grant_id: GrantId,
    profile_id: ProfileId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantRevokeMeta {
    grant_id: GrantId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantExpireMeta {
    grant_id: GrantId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantClaimMeta {
    grant_id: GrantId,
    ceremony_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantConsumeMeta {
    grant_id: GrantId,
    ceremony_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAllowMeta {
    profile_id: ProfileId,
    action: AuditAction,
    rp_id: String,
    authorization: String,
    user_presence: String,
    user_verification: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDenyMeta {
    profile_id: ProfileId,
    action: AuditAction,
    rp_id: String,
    reason: PolicyDenyReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDenyReason {
    DefaultDeny,
    ActionNotAllowed,
    RpIdNotMatch,
    CredentialNotMatch,
    GrantExpired,
    GrantNotFound,
    SessionMismatch,
    UvRequired,
    StaleGeneration,
    OriginInvalid,
    OriginMismatch,
    AllowCredentialsMismatch,
    AuditFailure,
    CounterPersistenceFailure,
    GrantRevoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyStartMeta {
    ceremony_id: String,
    grant_id: Option<GrantId>,
    intent_id: IntentId,
    profile_id: ProfileId,
    action: AuditAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonySuccessMeta {
    ceremony_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyFailureMeta {
    ceremony_id: String,
    reason: CeremonyFailReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialCreateMeta {
    credential: CredentialRef,
    rp_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialUpdateMeta {
    credential: CredentialRef,
    rp_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDeleteMeta {
    credential: CredentialRef,
    rp_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialListMeta {
    rp_id: String,
    count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinSuccessMeta {
    profile_id: ProfileId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinFailureMeta {
    profile_id: ProfileId,
    outcome: PinOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UvSuccessMeta {
    profile_id: ProfileId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UvFailureMeta {
    profile_id: ProfileId,
    outcome: UvOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptDisplayMeta {
    profile_id: ProfileId,
    mode: PromptMode,
    action: PromptAction,
    rp_id: String,
    credential_ref: Option<CredentialRef>,
    grant_ttl_secs: u64,
    session_ttl_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptApproveMeta {
    profile_id: ProfileId,
    mode: PromptMode,
    action: PromptAction,
    rp_id: String,
    latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptDenyMeta {
    profile_id: ProfileId,
    mode: PromptMode,
    action: PromptAction,
    rp_id: String,
    latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptTimeoutMeta {
    profile_id: ProfileId,
    mode: PromptMode,
    action: PromptAction,
    rp_id: String,
    timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptErrorMeta {
    profile_id: ProfileId,
    mode: PromptMode,
    action: PromptAction,
    rp_id: String,
    error_kind: PromptErrorKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminProfileEnableMeta {
    profile_id: ProfileId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminProfileDisableMeta {
    profile_id: ProfileId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisableRequestReason {
    AdminRequested,
    PolicyReload,
    DaemonShutdown,
    EndpointFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminProfileDisableRequestMeta {
    profile_id: ProfileId,
    reason: DisableRequestReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminProfileDisableFailedMeta {
    profile_id: ProfileId,
    reason: DisableRequestReason,
    error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminPolicyRecompileMeta {
    profile_id: ProfileId,
    generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminCredentialRevokeMeta {
    credential: CredentialRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminCredentialDeleteMeta {
    credential: CredentialRef,
    rp_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminCredentialRenameMeta {
    credential: CredentialRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminGrantRevokeMeta {
    grant_id: GrantId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSessionRevokeMeta {
    session_id: PrincipalSessionId,
    profile_id: ProfileId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminShutdownRequestMeta {
    pid: u32,
}

pub struct DaemonStartBuilder {
    version: String,
    pid: u32,
    backend: BackendKind,
}

impl DaemonStartBuilder {
    pub fn new(pid: u32, backend: BackendKind) -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").into(),
            pid,
            backend,
        }
    }

    pub fn version(mut self, v: &str) -> Self {
        self.version = v.into();
        self
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::DaemonStart(DaemonStartMeta {
            version: self.version,
            pid: self.pid,
            backend: self.backend,
        }))
    }
}

pub struct DaemonStopBuilder {
    reason: StopReason,
    uptime_secs: u64,
}

impl DaemonStopBuilder {
    pub fn new(reason: StopReason, uptime_secs: u64) -> Self {
        Self {
            reason,
            uptime_secs,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::DaemonStop(DaemonStopMeta {
            reason: self.reason,
            uptime_secs: self.uptime_secs,
        }))
    }
}

pub struct ConfigReloadBuilder {
    generation: u64,
    changed_field_count: u32,
}

impl ConfigReloadBuilder {
    pub fn new(generation: u64, changed_field_count: u32) -> Self {
        Self {
            generation,
            changed_field_count,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::ConfigReload(ConfigReloadMeta {
            generation: self.generation,
            changed_field_count: self.changed_field_count,
        }))
    }
}

pub struct DaemonRecoverBuilder {
    reason: RecoveryReason,
    truncated_size: u64,
    anchor_segment: u64,
    anchor_sequence: u64,
}

impl DaemonRecoverBuilder {
    pub fn new(
        reason: RecoveryReason,
        truncated_size: u64,
        anchor_segment: u64,
        anchor_sequence: u64,
    ) -> Self {
        Self {
            reason,
            truncated_size,
            anchor_segment,
            anchor_sequence,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::DaemonRecover(DaemonRecoverMeta {
            reason: self.reason,
            truncated_size: self.truncated_size,
            anchor_segment: self.anchor_segment,
            anchor_sequence: self.anchor_sequence,
        }))
    }
}

pub struct ProfileCreateBuilder {
    profile_id: ProfileId,
}

impl ProfileCreateBuilder {
    pub fn new(profile_id: ProfileId) -> Self {
        Self { profile_id }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::ProfileCreate(ProfileCreateMeta {
            profile_id: self.profile_id,
        }))
    }
}

pub struct ProfileDestroyBuilder {
    profile_id: ProfileId,
}

impl ProfileDestroyBuilder {
    pub fn new(profile_id: ProfileId) -> Self {
        Self { profile_id }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::ProfileDestroy(ProfileDestroyMeta {
            profile_id: self.profile_id,
        }))
    }
}

pub struct ProfileFailBuilder {
    profile_id: ProfileId,
    reason: FailReason,
}

impl ProfileFailBuilder {
    pub fn new(profile_id: ProfileId, reason: FailReason) -> Self {
        Self { profile_id, reason }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::ProfileFail(ProfileFailMeta {
            profile_id: self.profile_id,
            reason: self.reason,
        }))
    }
}

pub struct EndpointCreateBuilder {
    endpoint_id: EndpointId,
    profile_id: ProfileId,
}

impl EndpointCreateBuilder {
    pub fn new(endpoint_id: EndpointId, profile_id: ProfileId) -> Self {
        Self {
            endpoint_id,
            profile_id,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::EndpointCreate(EndpointCreateMeta {
            endpoint_id: self.endpoint_id,
            profile_id: self.profile_id,
        }))
    }
}

pub struct EndpointDestroyBuilder {
    endpoint_id: EndpointId,
    profile_id: ProfileId,
}

impl EndpointDestroyBuilder {
    pub fn new(endpoint_id: EndpointId, profile_id: ProfileId) -> Self {
        Self {
            endpoint_id,
            profile_id,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::EndpointDestroy(EndpointDestroyMeta {
            endpoint_id: self.endpoint_id,
            profile_id: self.profile_id,
        }))
    }
}

pub struct EndpointFailBuilder {
    endpoint_id: EndpointId,
    profile_id: ProfileId,
    reason: FailReason,
}

impl EndpointFailBuilder {
    pub fn new(endpoint_id: EndpointId, profile_id: ProfileId, reason: FailReason) -> Self {
        Self {
            endpoint_id,
            profile_id,
            reason,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::EndpointFail(EndpointFailMeta {
            endpoint_id: self.endpoint_id,
            profile_id: self.profile_id,
            reason: self.reason,
        }))
    }
}

pub struct PrincipalLaunchBuilder {
    session_id: PrincipalSessionId,
    profile_id: ProfileId,
    uid: u32,
}

impl PrincipalLaunchBuilder {
    pub fn new(session_id: PrincipalSessionId, profile_id: ProfileId, uid: u32) -> Self {
        Self {
            session_id,
            profile_id,
            uid,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::PrincipalLaunch(PrincipalLaunchMeta {
            session_id: self.session_id,
            profile_id: self.profile_id,
            uid: self.uid,
        }))
    }
}

pub struct PrincipalDenyBuilder {
    session_id: PrincipalSessionId,
    profile_id: ProfileId,
    reason: DenyReason,
}

impl PrincipalDenyBuilder {
    pub fn new(session_id: PrincipalSessionId, profile_id: ProfileId, reason: DenyReason) -> Self {
        Self {
            session_id,
            profile_id,
            reason,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::PrincipalDeny(PrincipalDenyMeta {
            session_id: self.session_id,
            profile_id: self.profile_id,
            reason: self.reason,
        }))
    }
}

pub struct PrincipalExitBuilder {
    session_id: PrincipalSessionId,
    profile_id: ProfileId,
    reason: ExitReason,
}

impl PrincipalExitBuilder {
    pub fn new(session_id: PrincipalSessionId, profile_id: ProfileId, reason: ExitReason) -> Self {
        Self {
            session_id,
            profile_id,
            reason,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::PrincipalExit(PrincipalExitMeta {
            session_id: self.session_id,
            profile_id: self.profile_id,
            reason: self.reason,
        }))
    }
}

pub struct BrowserLeaseLaunchBuilder {
    lease_id: BrowserLeaseId,
    profile_id: ProfileId,
    endpoint_id: EndpointId,
    cdp_expose: Option<String>,
}

impl BrowserLeaseLaunchBuilder {
    pub fn new(lease_id: BrowserLeaseId, profile_id: ProfileId, endpoint_id: EndpointId) -> Self {
        Self {
            lease_id,
            profile_id,
            endpoint_id,
            cdp_expose: None,
        }
    }

    pub fn with_cdp_expose(mut self, mode: String) -> Self {
        self.cdp_expose = Some(mode);
        self
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::BrowserLeaseLaunch(BrowserLeaseLaunchMeta {
            lease_id: self.lease_id,
            profile_id: self.profile_id,
            endpoint_id: self.endpoint_id,
            cdp_expose: self.cdp_expose,
        }))
    }
}

pub struct BrowserLeaseRevokeBuilder {
    lease_id: BrowserLeaseId,
    reason: RevokeReason,
}

impl BrowserLeaseRevokeBuilder {
    pub fn new(lease_id: BrowserLeaseId, reason: RevokeReason) -> Self {
        Self { lease_id, reason }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::BrowserLeaseRevoke(BrowserLeaseRevokeMeta {
            lease_id: self.lease_id,
            reason: self.reason,
        }))
    }
}

pub struct BrowserLeaseExpireBuilder {
    lease_id: BrowserLeaseId,
}

impl BrowserLeaseExpireBuilder {
    pub fn new(lease_id: BrowserLeaseId) -> Self {
        Self { lease_id }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::BrowserLeaseExpire(BrowserLeaseExpireMeta {
            lease_id: self.lease_id,
        }))
    }
}

pub struct BrowserLeaseCrashBuilder {
    lease_id: BrowserLeaseId,
    exit_code: i32,
}

impl BrowserLeaseCrashBuilder {
    pub fn new(lease_id: BrowserLeaseId, exit_code: i32) -> Self {
        Self {
            lease_id,
            exit_code,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::BrowserLeaseCrash(BrowserLeaseCrashMeta {
            lease_id: self.lease_id,
            exit_code: self.exit_code,
        }))
    }
}

pub struct BrowserLeaseCleanupBuilder {
    lease_id: BrowserLeaseId,
}

impl BrowserLeaseCleanupBuilder {
    pub fn new(lease_id: BrowserLeaseId) -> Self {
        Self { lease_id }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::BrowserLeaseCleanup(BrowserLeaseCleanupMeta {
            lease_id: self.lease_id,
        }))
    }
}

pub struct BrowserLeaseQuarantineBuilder {
    lease_id: BrowserLeaseId,
    reason: QuarantineReason,
}

impl BrowserLeaseQuarantineBuilder {
    pub fn new(lease_id: BrowserLeaseId, reason: QuarantineReason) -> Self {
        Self { lease_id, reason }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::BrowserLeaseQuarantine(
            BrowserLeaseQuarantineMeta {
                lease_id: self.lease_id,
                reason: self.reason,
            },
        ))
    }
}

pub struct BrowserControlRequestBuilder {
    profile_id: ProfileId,
    lease_id: BrowserLeaseId,
    cdp_method: String,
    outcome: BrowserControlOutcome,
}

impl BrowserControlRequestBuilder {
    pub fn new(
        profile_id: ProfileId,
        lease_id: BrowserLeaseId,
        cdp_method: &str,
        outcome: BrowserControlOutcome,
    ) -> Self {
        Self {
            profile_id,
            lease_id,
            cdp_method: cdp_method.to_string(),
            outcome,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::BrowserControlRequest(
            BrowserControlRequestMeta {
                profile_id: self.profile_id,
                lease_id: self.lease_id,
                cdp_method: self.cdp_method,
                outcome: self.outcome,
            },
        ))
    }
}

pub struct IntentCreateBuilder {
    intent_id: IntentId,
    profile_id: ProfileId,
    action: AuditAction,
}

impl IntentCreateBuilder {
    pub fn new(intent_id: IntentId, profile_id: ProfileId, action: AuditAction) -> Self {
        Self {
            intent_id,
            profile_id,
            action,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::IntentCreate(IntentCreateMeta {
            intent_id: self.intent_id,
            profile_id: self.profile_id,
            action: self.action,
        }))
    }
}

pub struct IntentApproveBuilder {
    intent_id: IntentId,
}

impl IntentApproveBuilder {
    pub fn new(intent_id: IntentId) -> Self {
        Self { intent_id }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::IntentApprove(IntentApproveMeta {
            intent_id: self.intent_id,
        }))
    }
}

pub struct IntentDenyBuilder {
    intent_id: IntentId,
}

impl IntentDenyBuilder {
    pub fn new(intent_id: IntentId) -> Self {
        Self { intent_id }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::IntentDeny(IntentDenyMeta {
            intent_id: self.intent_id,
        }))
    }
}

pub struct IntentCancelBuilder {
    intent_id: IntentId,
}

impl IntentCancelBuilder {
    pub fn new(intent_id: IntentId) -> Self {
        Self { intent_id }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::IntentCancel(IntentCancelMeta {
            intent_id: self.intent_id,
        }))
    }
}

pub struct IntentClaimBuilder {
    intent_id: IntentId,
}

impl IntentClaimBuilder {
    pub fn new(intent_id: IntentId) -> Self {
        Self { intent_id }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::IntentClaim(IntentClaimMeta {
            intent_id: self.intent_id,
        }))
    }
}

pub struct IntentConsumeBuilder {
    intent_id: IntentId,
}

impl IntentConsumeBuilder {
    pub fn new(intent_id: IntentId) -> Self {
        Self { intent_id }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::IntentConsume(IntentConsumeMeta {
            intent_id: self.intent_id,
        }))
    }
}

pub struct IntentExpireBuilder {
    intent_id: IntentId,
}

impl IntentExpireBuilder {
    pub fn new(intent_id: IntentId) -> Self {
        Self { intent_id }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::IntentExpire(IntentExpireMeta {
            intent_id: self.intent_id,
        }))
    }
}

pub struct GrantRequestBuilder {
    request_id: String,
    profile_id: ProfileId,
}

impl GrantRequestBuilder {
    pub fn new(request_id: &GrantRequestId, profile_id: ProfileId) -> Self {
        Self {
            request_id: request_id.as_str().to_string(),
            profile_id,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::GrantRequest(GrantRequestMeta {
            request_id: self.request_id,
            profile_id: self.profile_id,
        }))
    }
}

pub struct GrantApproveBuilder {
    grant_id: GrantId,
    profile_id: ProfileId,
}

impl GrantApproveBuilder {
    pub fn new(grant_id: GrantId, profile_id: ProfileId) -> Self {
        Self {
            grant_id,
            profile_id,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::GrantApprove(GrantApproveMeta {
            grant_id: self.grant_id,
            profile_id: self.profile_id,
        }))
    }
}

pub struct GrantRevokeBuilder {
    grant_id: GrantId,
}

impl GrantRevokeBuilder {
    pub fn new(grant_id: GrantId) -> Self {
        Self { grant_id }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::GrantRevoke(GrantRevokeMeta {
            grant_id: self.grant_id,
        }))
    }
}

pub struct GrantExpireBuilder {
    grant_id: GrantId,
}

impl GrantExpireBuilder {
    pub fn new(grant_id: GrantId) -> Self {
        Self { grant_id }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::GrantExpire(GrantExpireMeta {
            grant_id: self.grant_id,
        }))
    }
}

pub struct GrantClaimBuilder {
    grant_id: GrantId,
    ceremony_id: String,
}

impl GrantClaimBuilder {
    pub fn new(grant_id: GrantId, ceremony_id: &CeremonyId) -> Self {
        Self {
            grant_id,
            ceremony_id: ceremony_id.as_str().to_string(),
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::GrantClaim(GrantClaimMeta {
            grant_id: self.grant_id,
            ceremony_id: self.ceremony_id,
        }))
    }
}

pub struct GrantConsumeBuilder {
    grant_id: GrantId,
    ceremony_id: String,
}

impl GrantConsumeBuilder {
    pub fn new(grant_id: GrantId, ceremony_id: &CeremonyId) -> Self {
        Self {
            grant_id,
            ceremony_id: ceremony_id.as_str().to_string(),
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::GrantConsume(GrantConsumeMeta {
            grant_id: self.grant_id,
            ceremony_id: self.ceremony_id,
        }))
    }
}

pub struct PolicyAllowBuilder {
    profile_id: ProfileId,
    action: AuditAction,
    rp_id: String,
    authorization: String,
    user_presence: String,
    user_verification: String,
}

impl PolicyAllowBuilder {
    pub fn new(profile_id: ProfileId, action: AuditAction, rp_id: &str) -> Self {
        Self {
            profile_id,
            action,
            rp_id: rp_id.to_string(),
            authorization: "confirm".to_string(),
            user_presence: "human".to_string(),
            user_verification: "none".to_string(),
        }
    }

    pub fn evidence_sources(
        mut self,
        authorization: &str,
        user_presence: &str,
        user_verification: &str,
    ) -> Self {
        self.authorization = authorization.to_string();
        self.user_presence = user_presence.to_string();
        self.user_verification = user_verification.to_string();
        self
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::PolicyAllow(PolicyAllowMeta {
            profile_id: self.profile_id,
            action: self.action,
            rp_id: self.rp_id,
            authorization: self.authorization,
            user_presence: self.user_presence,
            user_verification: self.user_verification,
        }))
    }
}

pub struct PolicyDenyBuilder {
    profile_id: ProfileId,
    action: AuditAction,
    rp_id: String,
    reason: PolicyDenyReason,
}

impl PolicyDenyBuilder {
    pub fn new(
        profile_id: ProfileId,
        action: AuditAction,
        rp_id: &str,
        reason: PolicyDenyReason,
    ) -> Self {
        Self {
            profile_id,
            action,
            rp_id: rp_id.to_string(),
            reason,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::PolicyDeny(PolicyDenyMeta {
            profile_id: self.profile_id,
            action: self.action,
            rp_id: self.rp_id,
            reason: self.reason,
        }))
    }
}

pub struct CeremonyStartBuilder {
    ceremony_id: String,
    grant_id: Option<GrantId>,
    intent_id: IntentId,
    profile_id: ProfileId,
    action: AuditAction,
}

impl CeremonyStartBuilder {
    pub fn new(
        ceremony_id: &CeremonyId,
        grant_id: Option<GrantId>,
        intent_id: IntentId,
        profile_id: ProfileId,
        action: AuditAction,
    ) -> Self {
        Self {
            ceremony_id: ceremony_id.as_str().to_string(),
            grant_id,
            intent_id,
            profile_id,
            action,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::CeremonyStart(CeremonyStartMeta {
            ceremony_id: self.ceremony_id,
            grant_id: self.grant_id,
            intent_id: self.intent_id,
            profile_id: self.profile_id,
            action: self.action,
        }))
    }
}

pub struct CeremonySuccessBuilder {
    ceremony_id: String,
}

impl CeremonySuccessBuilder {
    pub fn new(ceremony_id: &CeremonyId) -> Self {
        Self {
            ceremony_id: ceremony_id.as_str().to_string(),
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::CeremonySuccess(CeremonySuccessMeta {
            ceremony_id: self.ceremony_id,
        }))
    }
}

pub struct CeremonyFailureBuilder {
    ceremony_id: String,
    reason: CeremonyFailReason,
}

impl CeremonyFailureBuilder {
    pub fn new(ceremony_id: &CeremonyId, reason: CeremonyFailReason) -> Self {
        Self {
            ceremony_id: ceremony_id.as_str().to_string(),
            reason,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::CeremonyFailure(CeremonyFailureMeta {
            ceremony_id: self.ceremony_id,
            reason: self.reason,
        }))
    }
}

pub struct CredentialCreateBuilder {
    credential: CredentialRef,
    rp_id: String,
}

impl CredentialCreateBuilder {
    pub fn new(credential: CredentialRef, rp_id: &str) -> Self {
        Self {
            credential,
            rp_id: rp_id.to_string(),
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::CredentialCreate(CredentialCreateMeta {
            credential: self.credential,
            rp_id: self.rp_id,
        }))
    }
}

pub struct CredentialUpdateBuilder {
    credential: CredentialRef,
    rp_id: String,
}

impl CredentialUpdateBuilder {
    pub fn new(credential: CredentialRef, rp_id: &str) -> Self {
        Self {
            credential,
            rp_id: rp_id.to_string(),
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::CredentialUpdate(CredentialUpdateMeta {
            credential: self.credential,
            rp_id: self.rp_id,
        }))
    }
}

pub struct CredentialDeleteBuilder {
    credential: CredentialRef,
    rp_id: String,
}

impl CredentialDeleteBuilder {
    pub fn new(credential: CredentialRef, rp_id: &str) -> Self {
        Self {
            credential,
            rp_id: rp_id.to_string(),
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::CredentialDelete(CredentialDeleteMeta {
            credential: self.credential,
            rp_id: self.rp_id,
        }))
    }
}

pub struct CredentialListBuilder {
    rp_id: String,
    count: u32,
}

impl CredentialListBuilder {
    pub fn new(rp_id: &str, count: u32) -> Self {
        Self {
            rp_id: rp_id.to_string(),
            count,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::CredentialList(CredentialListMeta {
            rp_id: self.rp_id,
            count: self.count,
        }))
    }
}

pub struct PinSuccessBuilder {
    profile_id: ProfileId,
}

impl PinSuccessBuilder {
    pub fn new(profile_id: ProfileId) -> Self {
        Self { profile_id }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::PinSuccess(PinSuccessMeta {
            profile_id: self.profile_id,
        }))
    }
}

pub struct PinFailureBuilder {
    profile_id: ProfileId,
    outcome: PinOutcome,
}

impl PinFailureBuilder {
    pub fn new(profile_id: ProfileId, outcome: PinOutcome) -> Self {
        Self {
            profile_id,
            outcome,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::PinFailure(PinFailureMeta {
            profile_id: self.profile_id,
            outcome: self.outcome,
        }))
    }
}

pub struct UvSuccessBuilder {
    profile_id: ProfileId,
}

impl UvSuccessBuilder {
    pub fn new(profile_id: ProfileId) -> Self {
        Self { profile_id }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::UvSuccess(UvSuccessMeta {
            profile_id: self.profile_id,
        }))
    }
}

pub struct UvFailureBuilder {
    profile_id: ProfileId,
    outcome: UvOutcome,
}

impl UvFailureBuilder {
    pub fn new(profile_id: ProfileId, outcome: UvOutcome) -> Self {
        Self {
            profile_id,
            outcome,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::UvFailure(UvFailureMeta {
            profile_id: self.profile_id,
            outcome: self.outcome,
        }))
    }
}

pub struct PromptDisplayBuilder {
    profile_id: ProfileId,
    mode: PromptMode,
    action: PromptAction,
    rp_id: String,
    credential_ref: Option<CredentialRef>,
    grant_ttl_secs: u64,
    session_ttl_secs: u64,
}

impl PromptDisplayBuilder {
    pub fn new(
        profile_id: ProfileId,
        mode: PromptMode,
        action: PromptAction,
        rp_id: &str,
        credential_ref: Option<CredentialRef>,
        grant_ttl_secs: u64,
        session_ttl_secs: u64,
    ) -> Self {
        Self {
            profile_id,
            mode,
            action,
            rp_id: rp_id.to_string(),
            credential_ref,
            grant_ttl_secs,
            session_ttl_secs,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::PromptDisplay(PromptDisplayMeta {
            profile_id: self.profile_id,
            mode: self.mode,
            action: self.action,
            rp_id: self.rp_id,
            credential_ref: self.credential_ref,
            grant_ttl_secs: self.grant_ttl_secs,
            session_ttl_secs: self.session_ttl_secs,
        }))
    }
}

pub struct PromptApproveBuilder {
    profile_id: ProfileId,
    mode: PromptMode,
    action: PromptAction,
    rp_id: String,
    latency_ms: u64,
}

impl PromptApproveBuilder {
    pub fn new(
        profile_id: ProfileId,
        mode: PromptMode,
        action: PromptAction,
        rp_id: &str,
        latency_ms: u64,
    ) -> Self {
        Self {
            profile_id,
            mode,
            action,
            rp_id: rp_id.to_string(),
            latency_ms,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::PromptApprove(PromptApproveMeta {
            profile_id: self.profile_id,
            mode: self.mode,
            action: self.action,
            rp_id: self.rp_id,
            latency_ms: self.latency_ms,
        }))
    }
}

pub struct PromptDenyBuilder {
    profile_id: ProfileId,
    mode: PromptMode,
    action: PromptAction,
    rp_id: String,
    latency_ms: u64,
}

impl PromptDenyBuilder {
    pub fn new(
        profile_id: ProfileId,
        mode: PromptMode,
        action: PromptAction,
        rp_id: &str,
        latency_ms: u64,
    ) -> Self {
        Self {
            profile_id,
            mode,
            action,
            rp_id: rp_id.to_string(),
            latency_ms,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::PromptDeny(PromptDenyMeta {
            profile_id: self.profile_id,
            mode: self.mode,
            action: self.action,
            rp_id: self.rp_id,
            latency_ms: self.latency_ms,
        }))
    }
}

pub struct PromptTimeoutBuilder {
    profile_id: ProfileId,
    mode: PromptMode,
    action: PromptAction,
    rp_id: String,
    timeout_secs: u64,
}

impl PromptTimeoutBuilder {
    pub fn new(
        profile_id: ProfileId,
        mode: PromptMode,
        action: PromptAction,
        rp_id: &str,
        timeout_secs: u64,
    ) -> Self {
        Self {
            profile_id,
            mode,
            action,
            rp_id: rp_id.to_string(),
            timeout_secs,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::PromptTimeout(PromptTimeoutMeta {
            profile_id: self.profile_id,
            mode: self.mode,
            action: self.action,
            rp_id: self.rp_id,
            timeout_secs: self.timeout_secs,
        }))
    }
}

pub struct PromptErrorBuilder {
    profile_id: ProfileId,
    mode: PromptMode,
    action: PromptAction,
    rp_id: String,
    error_kind: PromptErrorKind,
}

impl PromptErrorBuilder {
    pub fn new(
        profile_id: ProfileId,
        mode: PromptMode,
        action: PromptAction,
        rp_id: &str,
        error_kind: PromptErrorKind,
    ) -> Self {
        Self {
            profile_id,
            mode,
            action,
            rp_id: rp_id.to_string(),
            error_kind,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::PromptError(PromptErrorMeta {
            profile_id: self.profile_id,
            mode: self.mode,
            action: self.action,
            rp_id: self.rp_id,
            error_kind: self.error_kind,
        }))
    }
}

pub struct AdminProfileEnableBuilder {
    profile_id: ProfileId,
}

impl AdminProfileEnableBuilder {
    pub fn new(profile_id: ProfileId) -> Self {
        Self { profile_id }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::AdminProfileEnable(AdminProfileEnableMeta {
            profile_id: self.profile_id,
        }))
    }
}

pub struct AdminProfileDisableBuilder {
    profile_id: ProfileId,
}

impl AdminProfileDisableBuilder {
    pub fn new(profile_id: ProfileId) -> Self {
        Self { profile_id }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::AdminProfileDisable(AdminProfileDisableMeta {
            profile_id: self.profile_id,
        }))
    }
}

pub struct AdminProfileDisableRequestBuilder {
    profile_id: ProfileId,
    reason: DisableRequestReason,
}

impl AdminProfileDisableRequestBuilder {
    pub fn new(profile_id: ProfileId, reason: DisableRequestReason) -> Self {
        Self { profile_id, reason }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::AdminProfileDisableRequest(
            AdminProfileDisableRequestMeta {
                profile_id: self.profile_id,
                reason: self.reason,
            },
        ))
    }
}

pub struct AdminProfileDisableFailedBuilder {
    profile_id: ProfileId,
    reason: DisableRequestReason,
    error: String,
}

impl AdminProfileDisableFailedBuilder {
    pub fn new(profile_id: ProfileId, reason: DisableRequestReason, error: String) -> Self {
        Self {
            profile_id,
            reason,
            error,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::AdminProfileDisableFailed(
            AdminProfileDisableFailedMeta {
                profile_id: self.profile_id,
                reason: self.reason,
                error: self.error,
            },
        ))
    }
}

pub struct AdminPolicyRecompileBuilder {
    profile_id: ProfileId,
    generation: u64,
}

impl AdminPolicyRecompileBuilder {
    pub fn new(profile_id: ProfileId, generation: u64) -> Self {
        Self {
            profile_id,
            generation,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::AdminPolicyRecompile(
            AdminPolicyRecompileMeta {
                profile_id: self.profile_id,
                generation: self.generation,
            },
        ))
    }
}

pub struct AdminCredentialRevokeBuilder {
    credential: CredentialRef,
}

impl AdminCredentialRevokeBuilder {
    pub fn new(credential: CredentialRef) -> Self {
        Self { credential }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::AdminCredentialRevoke(
            AdminCredentialRevokeMeta {
                credential: self.credential,
            },
        ))
    }
}

pub struct AdminCredentialDeleteBuilder {
    credential: CredentialRef,
    rp_id: String,
}

impl AdminCredentialDeleteBuilder {
    pub fn new(credential: CredentialRef, rp_id: &str) -> Self {
        Self {
            credential,
            rp_id: rp_id.to_string(),
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::AdminCredentialDelete(
            AdminCredentialDeleteMeta {
                credential: self.credential,
                rp_id: self.rp_id,
            },
        ))
    }
}

pub struct AdminCredentialRenameBuilder {
    credential: CredentialRef,
}

impl AdminCredentialRenameBuilder {
    pub fn new(credential: CredentialRef) -> Self {
        Self { credential }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::AdminCredentialRename(
            AdminCredentialRenameMeta {
                credential: self.credential,
            },
        ))
    }
}

pub struct AdminGrantRevokeBuilder {
    grant_id: GrantId,
}

impl AdminGrantRevokeBuilder {
    pub fn new(grant_id: GrantId) -> Self {
        Self { grant_id }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::AdminGrantRevoke(AdminGrantRevokeMeta {
            grant_id: self.grant_id,
        }))
    }
}

pub struct AdminSessionRevokeBuilder {
    session_id: PrincipalSessionId,
    profile_id: ProfileId,
}

impl AdminSessionRevokeBuilder {
    pub fn new(session_id: PrincipalSessionId, profile_id: ProfileId) -> Self {
        Self {
            session_id,
            profile_id,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::AdminSessionRevoke(AdminSessionRevokeMeta {
            session_id: self.session_id,
            profile_id: self.profile_id,
        }))
    }
}

pub struct AdminShutdownRequestBuilder {
    pid: u32,
}

impl AdminShutdownRequestBuilder {
    pub fn new(pid: u32) -> Self {
        Self { pid }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::AdminShutdownRequest(
            AdminShutdownRequestMeta { pid: self.pid },
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn test_profile_id() -> ProfileId {
        ProfileId::new("test-profile").unwrap()
    }

    fn test_endpoint_id() -> EndpointId {
        EndpointId::new()
    }

    fn test_session_id() -> PrincipalSessionId {
        PrincipalSessionId::new()
    }

    fn test_intent_id() -> IntentId {
        IntentId::new()
    }

    fn test_grant_id() -> GrantId {
        GrantId::new()
    }

    fn test_lease_id() -> BrowserLeaseId {
        BrowserLeaseId::new()
    }

    fn test_cred() -> CredentialRef {
        CredentialRef::with_default_domain(b"test-credential-id")
    }

    fn all_test_events() -> Vec<AuditEvent> {
        let pid = test_profile_id();
        let eid = test_endpoint_id();
        let sid = test_session_id();
        let iid = test_intent_id();
        let gid = test_grant_id();
        let lid = test_lease_id();
        let cred = test_cred();
        let req_id = GrantRequestId::new();
        let cer_id = CeremonyId::new();

        vec![
            DaemonStartBuilder::new(1234, BackendKind::Local).build(),
            DaemonStopBuilder::new(StopReason::GracefulShutdown, 3600).build(),
            ConfigReloadBuilder::new(1, 3).build(),
            DaemonRecoverBuilder::new(RecoveryReason::IncompleteTailTruncated, 0, 0, 0).build(),
            ProfileCreateBuilder::new(pid.clone()).build(),
            ProfileDestroyBuilder::new(pid.clone()).build(),
            ProfileFailBuilder::new(pid.clone(), FailReason::InternalError).build(),
            EndpointCreateBuilder::new(eid.clone(), pid.clone()).build(),
            EndpointDestroyBuilder::new(eid.clone(), pid.clone()).build(),
            EndpointFailBuilder::new(eid.clone(), pid.clone(), FailReason::Timeout).build(),
            PrincipalLaunchBuilder::new(sid.clone(), pid.clone(), 1000).build(),
            PrincipalDenyBuilder::new(sid.clone(), pid.clone(), DenyReason::PolicyDenied).build(),
            PrincipalExitBuilder::new(sid.clone(), pid.clone(), ExitReason::Normal).build(),
            BrowserLeaseLaunchBuilder::new(lid.clone(), pid.clone(), eid.clone()).build(),
            BrowserLeaseRevokeBuilder::new(lid.clone(), RevokeReason::AdminRevoked).build(),
            BrowserLeaseExpireBuilder::new(lid.clone()).build(),
            BrowserLeaseCrashBuilder::new(lid.clone(), -11).build(),
            BrowserLeaseCleanupBuilder::new(lid.clone()).build(),
            BrowserLeaseQuarantineBuilder::new(lid.clone(), QuarantineReason::SymlinkEscape)
                .build(),
            IntentCreateBuilder::new(iid.clone(), pid.clone(), AuditAction::Register).build(),
            IntentApproveBuilder::new(iid.clone()).build(),
            IntentDenyBuilder::new(iid.clone()).build(),
            IntentCancelBuilder::new(iid.clone()).build(),
            IntentClaimBuilder::new(iid.clone()).build(),
            IntentConsumeBuilder::new(iid.clone()).build(),
            IntentExpireBuilder::new(iid.clone()).build(),
            GrantRequestBuilder::new(&req_id, pid.clone()).build(),
            GrantApproveBuilder::new(gid.clone(), pid.clone()).build(),
            GrantRevokeBuilder::new(gid.clone()).build(),
            GrantExpireBuilder::new(gid.clone()).build(),
            GrantClaimBuilder::new(gid.clone(), &cer_id).build(),
            GrantConsumeBuilder::new(gid.clone(), &cer_id).build(),
            PolicyAllowBuilder::new(pid.clone(), AuditAction::Authenticate, "example.com").build(),
            PolicyDenyBuilder::new(
                pid.clone(),
                AuditAction::Register,
                "evil.com",
                PolicyDenyReason::DefaultDeny,
            )
            .build(),
            CeremonyStartBuilder::new(
                &cer_id,
                Some(gid.clone()),
                iid.clone(),
                pid.clone(),
                AuditAction::Authenticate,
            )
            .build(),
            CeremonySuccessBuilder::new(&cer_id).build(),
            CeremonyFailureBuilder::new(&cer_id, CeremonyFailReason::GrantExpired).build(),
            CredentialCreateBuilder::new(cred.clone(), "example.com").build(),
            CredentialUpdateBuilder::new(cred.clone(), "example.com").build(),
            CredentialDeleteBuilder::new(cred.clone(), "example.com").build(),
            CredentialListBuilder::new("example.com", 5).build(),
            PinSuccessBuilder::new(pid.clone()).build(),
            PinFailureBuilder::new(pid.clone(), PinOutcome::InvalidPin).build(),
            UvSuccessBuilder::new(pid.clone()).build(),
            UvFailureBuilder::new(pid.clone(), UvOutcome::NotVerified).build(),
            PromptDisplayBuilder::new(
                pid.clone(),
                PromptMode::Isolated,
                PromptAction::Authenticate,
                "example.com",
                Some(cred.clone()),
                300,
                3600,
            )
            .build(),
            PromptApproveBuilder::new(
                pid.clone(),
                PromptMode::Isolated,
                PromptAction::Authenticate,
                "example.com",
                42,
            )
            .build(),
            PromptDenyBuilder::new(
                pid.clone(),
                PromptMode::Isolated,
                PromptAction::Register,
                "example.com",
                10,
            )
            .build(),
            PromptTimeoutBuilder::new(
                pid.clone(),
                PromptMode::Isolated,
                PromptAction::Authenticate,
                "example.com",
                60,
            )
            .build(),
            PromptErrorBuilder::new(
                pid.clone(),
                PromptMode::Isolated,
                PromptAction::Authenticate,
                "example.com",
                PromptErrorKind::RenderFailed,
            )
            .build(),
        ]
    }

    fn collect_json_keys(value: &serde_json::Value, keys: &mut HashSet<String>) {
        match value {
            serde_json::Value::Object(obj) => {
                for (k, v) in obj {
                    keys.insert(k.clone());
                    collect_json_keys(v, keys);
                }
            }
            serde_json::Value::Array(arr) => {
                for v in arr {
                    collect_json_keys(v, keys);
                }
            }
            _ => {}
        }
    }

    fn assert_no_forbidden_keys(value: &serde_json::Value, context: &str) {
        let mut keys = HashSet::new();
        collect_json_keys(value, &mut keys);
        for forbidden in FORBIDDEN_FIELD_NAMES {
            assert!(
                !keys.contains(*forbidden),
                "forbidden field '{}' found in {} (all keys: {:?})",
                forbidden,
                context,
                keys
            );
        }
    }

    fn assert_no_forbidden_substrings(value: &serde_json::Value, context: &str) {
        match value {
            serde_json::Value::Object(obj) => {
                for (k, v) in obj {
                    for sub in FORBIDDEN_KEY_SUBSTRINGS {
                        assert!(
                            !k.contains(sub),
                            "field '{}' contains forbidden substring '{}' in {}",
                            k,
                            sub,
                            context
                        );
                    }
                    assert_no_forbidden_substrings(v, context);
                }
            }
            serde_json::Value::Array(arr) => {
                for v in arr {
                    assert_no_forbidden_substrings(v, context);
                }
            }
            _ => {}
        }
    }

    fn assert_no_byte_arrays(value: &serde_json::Value, context: &str) {
        match value {
            serde_json::Value::Array(arr) => {
                if !arr.is_empty() {
                    let all_small_ints = arr.iter().all(|v| v.as_u64().is_some_and(|n| n <= 255));
                    assert!(
                        !all_small_ints,
                        "potential raw byte array found in {} (length {})",
                        context,
                        arr.len()
                    );
                }
                for v in arr {
                    assert_no_byte_arrays(v, context);
                }
            }
            serde_json::Value::Object(obj) => {
                for (k, v) in obj {
                    assert!(
                        !k.contains("byte") && !k.contains("raw") && !k.contains("bytes"),
                        "field name '{}' suggests raw bytes in {}",
                        k,
                        context
                    );
                    assert_no_byte_arrays(v, context);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn test_schema_version_present_in_all_events() {
        for event in all_test_events() {
            let json = serde_json::to_value(&event).unwrap();
            assert_eq!(
                json.get("v").unwrap().as_u64().unwrap(),
                AUDIT_SCHEMA_VERSION as u64,
                "schema version missing or wrong in {}",
                event.kind_name()
            );
        }
    }

    #[test]
    fn test_timestamp_present_in_all_events() {
        for event in all_test_events() {
            let json = serde_json::to_value(&event).unwrap();
            assert!(
                json.get("ts").unwrap().as_u64().is_some(),
                "timestamp missing in {}",
                event.kind_name()
            );
        }
    }

    #[test]
    fn test_kind_tag_present_in_all_events() {
        for event in all_test_events() {
            let json = serde_json::to_value(&event).unwrap();
            let kind = json.get("kind").unwrap().as_str().unwrap();
            assert_eq!(
                kind,
                event.kind_name(),
                "kind tag mismatch for {}",
                event.kind_name()
            );
        }
    }

    #[test]
    fn test_no_forbidden_field_names_in_any_event() {
        for event in all_test_events() {
            let json = serde_json::to_value(&event).unwrap();
            assert_no_forbidden_keys(&json, event.kind_name());
        }
    }

    #[test]
    fn test_no_forbidden_key_substrings_in_any_event() {
        for event in all_test_events() {
            let json = serde_json::to_value(&event).unwrap();
            assert_no_forbidden_substrings(&json, event.kind_name());
        }
    }

    #[test]
    fn test_no_raw_byte_arrays_in_any_event() {
        for event in all_test_events() {
            let json = serde_json::to_value(&event).unwrap();
            assert_no_byte_arrays(&json, event.kind_name());
        }
    }

    #[test]
    fn test_all_event_kinds_constructible() {
        let events = all_test_events();
        assert_eq!(events.len(), 50);
        let mut kinds = HashSet::new();
        for event in &events {
            kinds.insert(event.kind_name().to_string());
        }
        assert_eq!(kinds.len(), 50, "duplicate kind names detected");
    }

    #[test]
    fn test_reason_codes_serialize_stably() {
        assert_eq!(
            serde_json::to_string(&StopReason::GracefulShutdown).unwrap(),
            "\"graceful_shutdown\""
        );
        assert_eq!(
            serde_json::to_string(&StopReason::FatalError).unwrap(),
            "\"fatal_error\""
        );
        assert_eq!(
            serde_json::to_string(&FailReason::DeviceCreationFailed).unwrap(),
            "\"device_creation_failed\""
        );
        assert_eq!(
            serde_json::to_string(&DenyReason::PolicyDenied).unwrap(),
            "\"policy_denied\""
        );
        assert_eq!(
            serde_json::to_string(&ExitReason::Normal).unwrap(),
            "\"normal\""
        );
        assert_eq!(
            serde_json::to_string(&RevokeReason::AdminRevoked).unwrap(),
            "\"admin_revoked\""
        );
        assert_eq!(
            serde_json::to_string(&QuarantineReason::SymlinkEscape).unwrap(),
            "\"symlink_escape\""
        );
        assert_eq!(
            serde_json::to_string(&CeremonyFailReason::GrantExpired).unwrap(),
            "\"grant_expired\""
        );
        assert_eq!(
            serde_json::to_string(&PinOutcome::InvalidPin).unwrap(),
            "\"invalid_pin\""
        );
        assert_eq!(
            serde_json::to_string(&UvOutcome::NotVerified).unwrap(),
            "\"not_verified\""
        );
        assert_eq!(
            serde_json::to_string(&PolicyDenyReason::DefaultDeny).unwrap(),
            "\"default_deny\""
        );
        assert_eq!(
            serde_json::to_string(&BackendKind::Local).unwrap(),
            "\"local\""
        );
        assert_eq!(
            serde_json::to_string(&AuditAction::Register).unwrap(),
            "\"register\""
        );
    }

    #[test]
    fn test_reason_codes_roundtrip() {
        let json_strings = vec![
            serde_json::to_string(&StopReason::GracefulShutdown).unwrap(),
            serde_json::to_string(&FailReason::Timeout).unwrap(),
            serde_json::to_string(&DenyReason::RateLimited).unwrap(),
            serde_json::to_string(&ExitReason::Crash).unwrap(),
            serde_json::to_string(&RevokeReason::PolicyReload).unwrap(),
            serde_json::to_string(&QuarantineReason::ManifestTampered).unwrap(),
            serde_json::to_string(&CeremonyFailReason::ConsumedTwice).unwrap(),
            serde_json::to_string(&PinOutcome::Blocked).unwrap(),
            serde_json::to_string(&UvOutcome::Timeout).unwrap(),
            serde_json::to_string(&PolicyDenyReason::StaleGeneration).unwrap(),
        ];
        for json in &json_strings {
            assert!(json.starts_with('"'));
            assert!(json.ends_with('"'));
            let inner = &json[1..json.len() - 1];
            assert!(
                !inner.contains(' '),
                "reason code '{}' contains spaces",
                inner
            );
            assert!(
                inner.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "reason code '{}' contains invalid chars",
                inner
            );
        }
    }

    #[test]
    fn test_credential_ref_serializes_as_hex_not_bytes() {
        let cred = test_cred();
        let json = serde_json::to_value(&cred).unwrap();
        assert!(
            json.is_string(),
            "CredentialRef should serialize as hex string, got: {:?}",
            json
        );
        let hex_str = json.as_str().unwrap();
        assert_eq!(hex_str.len(), 64, "hex fingerprint should be 64 chars");
        assert!(
            hex_str.chars().all(|c| c.is_ascii_hexdigit()),
            "credential should be all hex digits"
        );
    }

    #[test]
    fn test_daemon_start_builder_default_version() {
        let event = DaemonStartBuilder::new(42, BackendKind::Tpm).build();
        let json = serde_json::to_value(&event).unwrap();
        let version = json.get("version").unwrap().as_str().unwrap();
        assert!(!version.is_empty());
        assert_eq!(version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_daemon_start_builder_custom_version() {
        let event = DaemonStartBuilder::new(42, BackendKind::Pass)
            .version("1.2.3")
            .build();
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json.get("version").unwrap().as_str().unwrap(), "1.2.3");
    }

    #[test]
    fn test_event_roundtrip_serialization() {
        for event in all_test_events() {
            let json = serde_json::to_string(&event).unwrap();
            let deserialized: AuditEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized.schema_version(), event.schema_version());
            assert_eq!(deserialized.kind_name(), event.kind_name());
        }
    }

    #[test]
    fn test_closed_taxonomy_completeness() {
        let expected_kinds = [
            "daemon.start",
            "daemon.stop",
            "daemon.config_reload",
            "daemon.recover",
            "profile.create",
            "profile.destroy",
            "profile.fail",
            "endpoint.create",
            "endpoint.destroy",
            "endpoint.fail",
            "principal.launch",
            "principal.deny",
            "principal.exit",
            "browser_lease.launch",
            "browser_lease.revoke",
            "browser_lease.expire",
            "browser_lease.crash",
            "browser_lease.cleanup",
            "browser_lease.quarantine",
            "intent.create",
            "intent.approve",
            "intent.deny",
            "intent.cancel",
            "intent.claim",
            "intent.consume",
            "intent.expire",
            "grant.request",
            "grant.approve",
            "grant.revoke",
            "grant.expire",
            "grant.claim",
            "grant.consume",
            "policy.allow",
            "policy.deny",
            "ceremony.start",
            "ceremony.success",
            "ceremony.failure",
            "credential.create",
            "credential.update",
            "credential.delete",
            "credential.list",
            "pin.success",
            "pin.failure",
            "uv.success",
            "uv.failure",
            "prompt.display",
            "prompt.approve",
            "prompt.deny",
            "prompt.timeout",
            "prompt.error",
        ];
        let events = all_test_events();
        let mut actual_kinds: Vec<&str> = events.iter().map(|e| e.kind_name()).collect();
        actual_kinds.sort();
        let mut expected = expected_kinds.to_vec();
        expected.sort();
        assert_eq!(actual_kinds, expected, "taxonomy mismatch");
    }

    #[test]
    fn test_no_arbitrary_string_fields_in_credential_events() {
        let cred = test_cred();
        let event = CredentialCreateBuilder::new(cred, "example.com").build();
        let json = serde_json::to_value(&event).unwrap();
        let obj = json.as_object().unwrap();
        let string_keys: Vec<&String> = obj
            .iter()
            .filter(|(_, v)| v.is_string())
            .map(|(k, _)| k)
            .collect();
        for key in &string_keys {
            let k = key.as_str();
            assert!(
                k == "kind"
                    || k == "credential"
                    || k == "rp_id"
                    || k == "v"
                    || k == "ts"
                    || k.starts_with("v"),
                "unexpected string field '{}' in credential event",
                k
            );
        }
    }

    #[test]
    fn test_policy_deny_uses_enum_not_string() {
        let event = PolicyDenyBuilder::new(
            test_profile_id(),
            AuditAction::Register,
            "evil.com",
            PolicyDenyReason::DefaultDeny,
        )
        .build();
        let json = serde_json::to_value(&event).unwrap();
        let reason = json.get("reason").unwrap();
        assert!(
            reason.is_string(),
            "reason should be a stable enum string, got: {:?}",
            reason
        );
        assert_eq!(reason.as_str().unwrap(), "default_deny");
    }

    #[test]
    fn test_browser_lease_crash_exit_code_is_integer() {
        let event = BrowserLeaseCrashBuilder::new(test_lease_id(), -9).build();
        let json = serde_json::to_value(&event).unwrap();
        let exit_code = json.get("exit_code").unwrap();
        assert!(exit_code.is_i64());
        assert_eq!(exit_code.as_i64().unwrap(), -9);
    }

    #[test]
    fn test_credential_list_count_is_integer() {
        let event = CredentialListBuilder::new("example.com", 42).build();
        let json = serde_json::to_value(&event).unwrap();
        let count = json.get("count").unwrap();
        assert!(count.is_u64());
        assert_eq!(count.as_u64().unwrap(), 42);
    }

    #[test]
    fn test_fixed_timestamp_in_test_events() {
        let payload = AuditPayload::DaemonStop(DaemonStopMeta {
            reason: StopReason::Signal,
            uptime_secs: 100,
        });
        let event = AuditEvent::with_timestamp(payload, 1_700_000_000_000);
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json.get("ts").unwrap().as_u64().unwrap(), 1_700_000_000_000);
    }

    #[test]
    fn test_no_message_field_in_any_serialized_event() {
        for event in all_test_events() {
            let json_str = serde_json::to_string(&event).unwrap();
            assert!(
                !json_str.contains("\"message\""),
                "serialized event {} contains 'message' field",
                event.kind_name()
            );
            assert!(
                !json_str.contains("\"detail\""),
                "serialized event {} contains 'detail' field",
                event.kind_name()
            );
            assert!(
                !json_str.contains("\"description\""),
                "serialized event {} contains 'description' field",
                event.kind_name()
            );
        }
    }

    #[test]
    fn test_no_secret_value_patterns() {
        for event in all_test_events() {
            let json_str = serde_json::to_string(&event).unwrap();
            assert!(
                !json_str.contains("\"secret\""),
                "serialized event {} contains 'secret' field",
                event.kind_name()
            );
            assert!(
                !json_str.contains("\"password\""),
                "serialized event {} contains 'password' field",
                event.kind_name()
            );
            assert!(
                !json_str.contains("\"private_key\""),
                "serialized event {} contains 'private_key' field",
                event.kind_name()
            );
        }
    }
}
