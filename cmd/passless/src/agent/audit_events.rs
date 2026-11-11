use std::fmt;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use passless_core::agent::{
    BrowserLeaseId, CredentialRef, GrantId, IntentId, PrincipalSessionId, ProfileId,
};

use super::grant::{CeremonyId, GrantRequestId};
use super::granted_rules::{GrantKind, PermittingRule};
use super::prompt::{PromptAction, PromptErrorKind, PromptMode};

/// The audit event schema version, written as `v` in every record.
///
/// - 1: the original records.
/// - 2: `policy.*` records carry the origin context (`origin`, `top_origin`, `cross_origin`).
/// - 3 (ADR 0014 section 12, P8): every operation record (`policy.allow`, `policy.deny`,
///   `policy.replay_served`, `operation.terminal`) carries the full field set of
///   [`OperationRecord`], with every key always present (null when it does not apply yet); a
///   reservation (`policy.allow`) is followed by exactly one `operation.terminal`; escalation
///   records carry `origin` and `rule`; `rule` is the matched rule everywhere (`exact` or `*`, as in
///   the granted-rules store), with `grant_source` on operation records; session grant records
///   carry `principal`, the RP scope and the TTL.
///
/// Readers accept every version: fields added in a later version default when absent.
pub const AUDIT_SCHEMA_VERSION: u32 = 3;

/// ADR 0014 section 12: the fields every operation record carries. This is the single canonical
/// list: `OperationRecord` serializes exactly these keys, and the field-presence tests check
/// every operation record type against it.
#[cfg(test)]
const SECTION_12_OPERATION_FIELDS: &[&str] = &[
    "session_id_hash",
    "request_id",
    "escalation_id",
    "profile_id",
    "mode",
    "principal_relationship",
    "revocation_epoch",
    "grant_epoch",
    "action",
    "rp_id",
    "origin",
    "top_origin",
    "cross_origin",
    "rule",
    "grant_source",
    "decision",
    "evidence_source",
    "credential_ref",
    "selection_rule",
    "backend",
    "key_provider",
    "counter_before",
    "counter_after",
    "result",
    "failure_class",
];

/// The record kinds that carry [`SECTION_12_OPERATION_FIELDS`].
#[cfg(test)]
const SECTION_12_OPERATION_KINDS: &[&str] = &[
    "policy.allow",
    "policy.deny",
    "policy.replay_served",
    "operation.terminal",
];

/// The kind-specific fields of the operation records, besides the common set.
#[cfg(test)]
const SECTION_12_OPERATION_EXTRAS: &[(&str, &[&str])] = &[
    (
        "policy.allow",
        &["authorization", "user_presence", "user_verification"],
    ),
    ("policy.deny", &["reason"]),
    ("policy.replay_served", &["reason"]),
    ("operation.terminal", &[]),
];

/// ADR 0014 section 12, "also recorded": the fields of the escalation, session grant and
/// browser-lease records, per kind. The kind-specific outcome fields (`latency_ms`, `cause`,
/// `reason`) are listed too, so a field added to a record without being listed here fails.
#[cfg(test)]
const SECTION_12_OTHER_RECORD_FIELDS: &[(&str, &[&str])] = &[
    (
        "escalation.requested",
        &[
            "escalation_id",
            "profile_id",
            "action",
            "rp_id",
            "origin",
            "rule",
        ],
    ),
    (
        "escalation.approved",
        &[
            "escalation_id",
            "profile_id",
            "action",
            "rp_id",
            "origin",
            "rule",
            "latency_ms",
        ],
    ),
    (
        "escalation.denied",
        &[
            "escalation_id",
            "profile_id",
            "action",
            "rp_id",
            "origin",
            "rule",
            "cause",
        ],
    ),
    (
        "escalation.expired",
        &[
            "escalation_id",
            "profile_id",
            "action",
            "rp_id",
            "origin",
            "rule",
            "reason",
        ],
    ),
    (
        "escalation.revoked",
        &[
            "escalation_id",
            "profile_id",
            "action",
            "rp_id",
            "origin",
            "rule",
            "reason",
        ],
    ),
    (
        "granted_rule.add",
        &[
            "profile_id",
            "rp_id",
            "grant_kind",
            "escalation_id",
            "rule",
            "credential_ref",
        ],
    ),
    ("granted_rule.revoke", &["profile_id", "rp_id", "revoked"]),
    (
        "grant.request",
        &[
            "request_id",
            "profile_id",
            "principal",
            "rp_ids",
            "ttl_secs",
        ],
    ),
    (
        "grant.approve",
        &["grant_id", "profile_id", "principal", "rp_ids", "ttl_secs"],
    ),
    (
        "browser_lease.launch",
        &["lease_id", "profile_id", "cdp_expose"],
    ),
    ("browser_lease.revoke", &["lease_id", "reason"]),
    ("browser_lease.expire", &["lease_id"]),
    ("browser_lease.crash", &["lease_id", "exit_code"]),
    ("browser_lease.cleanup", &["lease_id"]),
];

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

    /// The request ID of an operation reservation (`policy.allow`), if this is one.
    pub fn reservation_request_id(&self) -> Option<&str> {
        match &self.payload {
            AuditPayload::PolicyAllow(meta) => meta.op.request_id.as_deref(),
            _ => None,
        }
    }

    /// The request ID of the reservation an `operation.terminal` record closes, if this is one.
    pub fn terminal_request_id(&self) -> Option<&str> {
        match &self.payload {
            AuditPayload::OperationTerminal(meta) => meta.op.request_id.as_deref(),
            _ => None,
        }
    }

    /// For a reservation (`policy.allow`): the terminal record that closes it as abandoned (a
    /// restart found it open). The reservation's fields are copied; the result is `error` and the
    /// failure class `abandoned`.
    pub fn abandoned_terminal(&self) -> Option<AuditEvent> {
        match &self.payload {
            AuditPayload::PolicyAllow(meta) if meta.op.request_id.is_some() => Some(
                OperationTerminalBuilder::new(
                    (*meta.op).clone(),
                    Some(PolicyDenyReason::Abandoned),
                )
                .build(),
            ),
            _ => None,
        }
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
    /// A launched lease's WebAuthn interception became degraded (its extension worker stayed
    /// detached past the grace period) or re-attached (plan D6 layer 1). One record per change.
    #[serde(rename = "browser_lease.interception")]
    BrowserLeaseInterception(BrowserLeaseInterceptionMeta),

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
    /// A duplicate request was served the original outcome without a new key use (ADR 0014
    /// section 9). The `reason` is always `replay_served`.
    #[serde(rename = "policy.replay_served")]
    PolicyReplayServed(PolicyDenyMeta),
    /// The terminal record of an operation reservation (`policy.allow`): exactly one follows
    /// every reservation, on every exit path (ADR 0014 section 12).
    #[serde(rename = "operation.terminal")]
    OperationTerminal(OperationTerminalMeta),

    /// A sign-transport connection said hello with a build or relay version that differs from the
    /// daemon's (plan V-L5). Not fatal; recorded once per connection.
    #[serde(rename = "transport.version_skew")]
    TransportVersionSkew(TransportVersionSkewMeta),
    /// A sign-transport hello with a valid bearer came from a peer whose UID is not the lease's
    /// browser UID (`SO_PEERCRED`); it was refused.
    #[serde(rename = "transport.peer_refused")]
    TransportPeerRefused(TransportPeerRefusedMeta),

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

    /// An operator revoked persistent granted rules (ADR 0014 section 8.4).
    #[serde(rename = "granted_rule.revoke")]
    GrantedRuleRevoke(GrantedRuleRevokeMeta),
    /// An approved escalation (or a registration after one) persisted a granted rule (ADR 0014
    /// section 8.4).
    #[serde(rename = "granted_rule.add")]
    GrantedRuleAdd(GrantedRuleAddMeta),

    /// A ceremony that resolved to `request` raised an escalation (ADR 0014 section 8.1). A failed
    /// write of this record fails the escalation.
    #[serde(rename = "escalation.requested")]
    EscalationRequested(EscalationRequestedMeta),
    /// The human chose "Allow always" on the escalation prompt.
    #[serde(rename = "escalation.approved")]
    EscalationApproved(EscalationApprovedMeta),
    /// The escalation was denied: by the human, by a dismissal or an early approval, or because the
    /// prompt, the audit or the grant write failed.
    #[serde(rename = "escalation.denied")]
    EscalationDenied(EscalationDeniedMeta),
    /// The escalation ended without a decision: its last waiter timed out or aborted, or the
    /// notification server went away.
    #[serde(rename = "escalation.expired")]
    EscalationExpired(EscalationExpiredMeta),
    /// A pending escalation was cancelled by a policy reload.
    #[serde(rename = "escalation.revoked")]
    EscalationRevoked(EscalationRevokedMeta),

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
            Self::BrowserLeaseInterception(_) => "browser_lease.interception",
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
            Self::PolicyReplayServed(_) => "policy.replay_served",
            Self::OperationTerminal(_) => "operation.terminal",
            Self::TransportVersionSkew(_) => "transport.version_skew",
            Self::TransportPeerRefused(_) => "transport.peer_refused",
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
            Self::GrantedRuleRevoke(_) => "granted_rule.revoke",
            Self::GrantedRuleAdd(_) => "granted_rule.add",
            Self::EscalationRequested(_) => "escalation.requested",
            Self::EscalationApproved(_) => "escalation.approved",
            Self::EscalationDenied(_) => "escalation.denied",
            Self::EscalationExpired(_) => "escalation.expired",
            Self::EscalationRevoked(_) => "escalation.revoked",
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

impl BackendKind {
    /// The name audit records carry (`local`, `pass` or `tpm`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Pass => "pass",
            Self::Tpm => "tpm",
        }
    }
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

/// Payload of an `endpoint.*` record written before the isolated UHID route was removed (ADR 0014
/// section 5). Nothing emits these any more; the variants stay so that old logs still deserialize.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointCreateMeta {
    endpoint_id: String,
    profile_id: ProfileId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointDestroyMeta {
    endpoint_id: String,
    profile_id: ProfileId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointFailMeta {
    endpoint_id: String,
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
pub struct BrowserLeaseInterceptionMeta {
    lease_id: BrowserLeaseId,
    profile_id: ProfileId,
    state: InterceptionAuditState,
}

/// The interception state a `browser_lease.interception` record reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterceptionAuditState {
    Degraded,
    Attached,
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
    /// Hex digest of the principal process the session grant is for.
    #[serde(default)]
    principal: String,
    /// The RP scope of the requested grant.
    rp_ids: Vec<String>,
    #[serde(default)]
    ttl_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantApproveMeta {
    grant_id: GrantId,
    profile_id: ProfileId,
    /// Hex digest of the principal process the session grant is bound to.
    #[serde(default)]
    principal: String,
    /// The RP scope of the approved grant.
    #[serde(default)]
    rp_ids: Vec<String>,
    ttl_secs: u64,
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
    #[serde(flatten)]
    op: Box<OperationRecord>,
    authorization: String,
    user_presence: String,
    user_verification: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDenyMeta {
    #[serde(flatten)]
    op: Box<OperationRecord>,
    reason: PolicyDenyReason,
}

/// The terminal record of a reservation: the common operation fields with the final result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationTerminalMeta {
    #[serde(flatten)]
    op: Box<OperationRecord>,
}

/// Which source granted the matched rule its `allow` (ADR 0014 section 12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleGrantSource {
    /// The configured rule itself decided.
    Config,
    /// A persisted granted rule upgraded a configured `request` to `allow` (section 8.4).
    Granted,
}

/// How an operation ended (ADR 0014 section 12, "terminal result").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationResult {
    /// The key was used and the outcome returned.
    Success,
    /// A duplicate was served the original outcome; no new key use.
    ReplayServed,
    /// Refused by policy, validation or a human decision.
    Denied,
    /// The browser cancelled the request.
    Aborted,
    /// Authority was revoked, expired or changed before the operation finished.
    Revoked,
    /// An escalation expired without a decision.
    Timeout,
    /// Refused because a capacity limit was reached.
    Busy,
    /// An internal failure: audit, storage, key provider or lease activation.
    Error,
}

impl OperationResult {
    /// The result a failure class implies.
    pub fn of_failure(failure: PolicyDenyReason) -> Self {
        use PolicyDenyReason as R;
        match failure {
            R::Aborted => Self::Aborted,
            R::PolicyRevoked
            | R::GrantRevoked
            | R::GrantExpired
            | R::BearerRevoked
            | R::SessionExpired
            | R::StaleGeneration => Self::Revoked,
            R::EscalationExpired | R::JoinTimeout => Self::Timeout,
            R::EscalationBusy | R::EscalationQueueFull | R::EscalationWaiterCap => Self::Busy,
            R::ReplayServed => Self::ReplayServed,
            R::AuditFailure
            | R::CounterPersistenceFailure
            | R::LeaseActivationFailed
            | R::SigningFailed
            | R::KeyGenerationFailed
            | R::CredentialWriteFailed
            | R::CredentialUnavailable
            | R::InternalFailure
            | R::Abandoned => Self::Error,
            R::DefaultDeny
            | R::ActionNotAllowed
            | R::RpIdNotMatch
            | R::CredentialNotMatch
            | R::GrantNotFound
            | R::SessionMismatch
            | R::UvRequired
            | R::OriginInvalid
            | R::OriginMismatch
            | R::AllowCredentialsMismatch
            | R::EscalationUnavailable
            | R::EscalationCooldown
            | R::GrantCapReached
            | R::GrantsUnavailable
            | R::EscalationDenied
            | R::CrossOriginDenied
            | R::AlgorithmUnsupported
            | R::PrincipalMismatch
            | R::Replayed
            | R::ChallengeReused
            | R::BudgetExhausted
            | R::UnsupportedOption
            | R::CredentialExcluded => Self::Denied,
        }
    }
}

/// The fields every operation record carries (ADR 0014 section 12). Every key is always
/// serialized; a value that does not apply yet (the credential of a refusal, the counter after a
/// reservation) is null. Records written before schema version 3 deserialize with the new fields
/// null.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationRecord {
    /// Hash of the bearer session's random identifier (never the bearer itself).
    #[serde(default)]
    session_id_hash: Option<String>,
    /// The daemon-assigned ID of the ceremony; a reservation and its terminal record share it.
    #[serde(default)]
    request_id: Option<String>,
    /// The escalation the ceremony waited on, if any.
    #[serde(default)]
    escalation_id: Option<String>,
    profile_id: ProfileId,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    principal_relationship: Option<String>,
    /// The live revocation epoch when the record was written.
    #[serde(default)]
    revocation_epoch: Option<u64>,
    /// The live grant epoch when the record was written.
    #[serde(default)]
    grant_epoch: Option<u64>,
    action: AuditAction,
    rp_id: String,
    #[serde(flatten)]
    origin: OriginContextMeta,
    /// The matched rule: `exact` (the RP's own rule; `rp_id` names it) or `*` (the wildcard).
    /// Null when no rule matched or resolution had not happened.
    #[serde(default)]
    rule: Option<String>,
    #[serde(default)]
    grant_source: Option<RuleGrantSource>,
    #[serde(default)]
    decision: Option<PolicyDecision>,
    /// `agent` when the validated agent session was the UP/UV evidence; null when none was used.
    #[serde(default)]
    evidence_source: Option<String>,
    #[serde(default)]
    credential_ref: Option<CredentialRef>,
    #[serde(default)]
    selection_rule: Option<String>,
    /// The storage backend the operation used (`local`, `pass` or `tpm`): the human backend's
    /// kind for a same-user profile, the profile's own storage kind for an isolated one.
    #[serde(default)]
    backend: Option<String>,
    /// The key provider type (`software` or `tpm`).
    #[serde(default)]
    key_provider: Option<String>,
    #[serde(default)]
    counter_before: Option<u32>,
    #[serde(default)]
    counter_after: Option<u32>,
    #[serde(default)]
    result: Option<OperationResult>,
    #[serde(default)]
    failure_class: Option<PolicyDenyReason>,
}

impl OperationRecord {
    pub fn new(profile_id: ProfileId, action: AuditAction, rp_id: &str) -> Self {
        Self {
            session_id_hash: None,
            request_id: None,
            escalation_id: None,
            profile_id,
            mode: None,
            principal_relationship: None,
            revocation_epoch: None,
            grant_epoch: None,
            action,
            rp_id: rp_id.to_string(),
            origin: OriginContextMeta::default(),
            rule: None,
            grant_source: None,
            decision: None,
            evidence_source: None,
            credential_ref: None,
            selection_rule: None,
            backend: None,
            key_provider: None,
            counter_before: None,
            counter_after: None,
            result: None,
            failure_class: None,
        }
    }

    /// The request's origin, top origin (null on the proxy path) and cross-origin flag.
    pub fn origin_context(
        mut self,
        origin: Option<&str>,
        top_origin: Option<&str>,
        cross_origin: Option<bool>,
    ) -> Self {
        self.origin = OriginContextMeta::new(origin, top_origin, cross_origin);
        self
    }

    pub fn session(mut self, session_id_hash: Option<String>, request_id: Option<String>) -> Self {
        self.session_id_hash = session_id_hash;
        self.request_id = request_id;
        self
    }

    pub fn escalation(mut self, escalation_id: Option<String>) -> Self {
        self.escalation_id = escalation_id;
        self
    }

    pub fn deployment(
        mut self,
        mode: Option<String>,
        principal_relationship: Option<String>,
        backend: Option<String>,
        key_provider: Option<String>,
    ) -> Self {
        self.mode = mode;
        self.principal_relationship = principal_relationship;
        self.backend = backend;
        self.key_provider = key_provider;
        self
    }

    pub fn epochs(mut self, revocation_epoch: u64, grant_epoch: u64) -> Self {
        self.revocation_epoch = Some(revocation_epoch);
        self.grant_epoch = Some(grant_epoch);
        self
    }

    pub fn matched(mut self, rule: Option<String>, grant_source: Option<RuleGrantSource>) -> Self {
        self.rule = rule;
        self.grant_source = grant_source;
        self
    }

    pub fn credential(
        mut self,
        credential_ref: Option<CredentialRef>,
        selection_rule: Option<String>,
    ) -> Self {
        self.credential_ref = credential_ref;
        self.selection_rule = selection_rule;
        self
    }

    pub fn counters(mut self, before: Option<u32>, after: Option<u32>) -> Self {
        self.counter_before = before;
        self.counter_after = after;
        self
    }

    pub fn decision(mut self, decision: PolicyDecision, evidence_source: Option<&str>) -> Self {
        self.decision = Some(decision);
        self.evidence_source = evidence_source.map(str::to_string);
        self
    }

    /// The final result and its failure class (`None` for a success).
    pub fn outcome(mut self, result: OperationResult, failure: Option<PolicyDenyReason>) -> Self {
        self.result = Some(result);
        self.failure_class = failure;
        self
    }
}

/// The origin context of a ceremony record (ADR 0014 section 12). Every key is always written:
/// `top_origin` is null on the proxy path, where the browser never supplies it (section 11), and
/// all three are null in a record about an RP only (a refused request whose origin is unknown).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OriginContextMeta {
    #[serde(default)]
    origin: Option<String>,
    #[serde(default)]
    top_origin: Option<String>,
    #[serde(default)]
    cross_origin: Option<bool>,
}

impl OriginContextMeta {
    fn new(origin: Option<&str>, top_origin: Option<&str>, cross_origin: Option<bool>) -> Self {
        Self {
            origin: origin.map(str::to_string),
            top_origin: top_origin.map(str::to_string),
            cross_origin,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportPeerRefusedMeta {
    profile_id: ProfileId,
    expected_uid: u32,
    peer_uid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportVersionSkewMeta {
    profile_id: ProfileId,
    daemon_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    build_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay_version: Option<String>,
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
    /// A ceremony needed a human decision but no escalation prompt can be shown: no session bus
    /// can be resolved, or the notification server was rejected by the capability gate. The
    /// ceremony is denied and never reaches a prompt or the native path.
    EscalationUnavailable,
    /// The escalation key is in its cooldown after a deny, a timeout or repeated withdrawals
    /// (ADR 0014 section 8.1); denied without a prompt.
    EscalationCooldown,
    /// The profile's escalation queue is full (one active prompt plus a bounded FIFO).
    EscalationQueueFull,
    /// A waiter cap was reached: per session, per profile or global (ADR 0014 section 8.2).
    EscalationWaiterCap,
    /// A registration escalation for the same profile and RP is already pending; registration
    /// escalations are not joinable (ADR 0014 section 8.3).
    EscalationBusy,
    /// The profile holds `max_granted_rules` granted rules already.
    GrantCapReached,
    /// The profile's granted-rules store is disabled (unreadable, wrongly owned or corrupt), so no
    /// grant can be persisted.
    GrantsUnavailable,
    /// The human denied the escalation the ceremony waited on (Deny, a dismissal or an approval
    /// before the minimum review delay); the escalation itself is recorded as
    /// `escalation.denied`.
    EscalationDenied,
    /// The escalation the ceremony waited on expired: the ceremony deadline passed, or the
    /// notification server went away (`escalation.expired`).
    EscalationExpired,
    /// The request came from a frame whose origin differs from its ancestors; cross-origin fails closed.
    CrossOriginDenied,
    /// The request used a bearer whose browser lease was revoked or whose browser exited.
    BearerRevoked,
    /// None of the requested public-key algorithms is supported by the selected backend.
    AlgorithmUnsupported,
    /// The session is not bound to the principal the session grant was issued to (ADR 0014 section 7).
    PrincipalMismatch,
    /// The revocation epoch moved, or the rule no longer resolves to `allow`, after the session was
    /// created or while the operation was in flight (ADR 0014 sections 6.4 and 9).
    PolicyRevoked,
    /// The bearer session's TTL passed.
    SessionExpired,
    /// The replay key was already used in this session and its outcome is no longer returned.
    Replayed,
    /// The challenge was already used by a request with a different action, RP or origin.
    ChallengeReused,
    /// The session's operation budget is used up.
    BudgetExhausted,
    /// The RP asked for an option or extension the agent authenticator cannot honor.
    UnsupportedOption,
    /// A credential in `excludeCredentials` already exists.
    CredentialExcluded,
    /// Not a denial of the RP request: a duplicate of a completed or in-flight request was served
    /// the original outcome without a new key use (ADR 0014 section 9).
    ReplayServed,
    /// The assertion was made but the browser lease could not be activated; it was withheld.
    LeaseActivationFailed,
    /// The browser cancelled the request (`onRequestCanceled`, or its connection closed) before
    /// key use. Nothing was signed or created.
    Aborted,
    /// The key provider failed to sign, after the reservation.
    SigningFailed,
    /// The key provider failed to generate a key, or returned an unusable one, after the
    /// reservation.
    KeyGenerationFailed,
    /// The new credential could not be written to storage, after the reservation.
    CredentialWriteFailed,
    /// The selected credential could not be read back from storage.
    CredentialUnavailable,
    /// An internal failure after the reservation that no other class names.
    InternalFailure,
    /// The ceremony ended without recording an outcome (a panic, or a daemon exit or kill that
    /// recovery found at the next start); the terminal record comes from the drop guard or from
    /// recovery.
    Abandoned,
    /// A duplicate's own ceremony deadline passed while it waited for the identical request that
    /// is still in flight (ADR 0014 section 9). Nothing was signed or created for the duplicate.
    JoinTimeout,
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
pub struct GrantedRuleRevokeMeta {
    profile_id: ProfileId,
    /// The revoked RP; null when every granted rule of the profile was cleared.
    #[serde(default)]
    rp_id: Option<String>,
    revoked: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantedRuleAddMeta {
    profile_id: ProfileId,
    rp_id: String,
    /// `escalation` or `registration` (`kind` is the record's own tag).
    grant_kind: GrantKind,
    /// The approving escalation's ID.
    escalation_id: String,
    /// The permitting rule: `exact` or `*`.
    rule: String,
    /// The credential a registration grant pins; null for an authentication grant.
    #[serde(default)]
    credential_ref: Option<CredentialRef>,
}

/// Why an escalation was denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationDenyCause {
    /// The human chose "Deny".
    User,
    /// "Allow always" arrived before the minimum review delay; treated as a deny.
    EarlyApproval,
    /// The human dismissed the notification.
    Dismissed,
    /// The prompt could not be shown (no bus, rejected server, prompt child failure).
    PromptUnavailable,
    /// The approval could not be audited.
    AuditFailure,
    /// The approval could not be persisted as a granted rule.
    GrantWriteFailed,
}

/// Why an escalation expired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationExpireReason {
    /// The last waiter's ceremony deadline passed.
    Timeout,
    /// The last waiter left (the ceremony was aborted, or its session became invalid).
    Aborted,
    /// The notification server went away while the prompt was shown.
    ServerLost,
}

/// Why a pending escalation was revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationRevokeReason {
    PolicyReload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationRequestedMeta {
    escalation_id: String,
    profile_id: ProfileId,
    action: AuditAction,
    rp_id: String,
    origin: String,
    /// The matched rule: `exact` or `*`.
    rule: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationApprovedMeta {
    escalation_id: String,
    profile_id: ProfileId,
    action: AuditAction,
    rp_id: String,
    #[serde(default)]
    origin: String,
    #[serde(default)]
    rule: String,
    latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationDeniedMeta {
    escalation_id: String,
    profile_id: ProfileId,
    action: AuditAction,
    rp_id: String,
    #[serde(default)]
    origin: String,
    #[serde(default)]
    rule: String,
    cause: EscalationDenyCause,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationExpiredMeta {
    escalation_id: String,
    profile_id: ProfileId,
    action: AuditAction,
    rp_id: String,
    #[serde(default)]
    origin: String,
    #[serde(default)]
    rule: String,
    reason: EscalationExpireReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationRevokedMeta {
    escalation_id: String,
    profile_id: ProfileId,
    action: AuditAction,
    rp_id: String,
    #[serde(default)]
    origin: String,
    #[serde(default)]
    rule: String,
    reason: EscalationRevokeReason,
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
    profile_id: ProfileId,
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
    cdp_expose: Option<String>,
}

impl BrowserLeaseLaunchBuilder {
    pub fn new(lease_id: BrowserLeaseId, profile_id: ProfileId) -> Self {
        Self {
            lease_id,
            profile_id,
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

pub struct BrowserLeaseInterceptionBuilder {
    lease_id: BrowserLeaseId,
    profile_id: ProfileId,
    state: InterceptionAuditState,
}

impl BrowserLeaseInterceptionBuilder {
    pub fn new(
        lease_id: BrowserLeaseId,
        profile_id: ProfileId,
        state: InterceptionAuditState,
    ) -> Self {
        Self {
            lease_id,
            profile_id,
            state,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::BrowserLeaseInterception(
            BrowserLeaseInterceptionMeta {
                lease_id: self.lease_id,
                profile_id: self.profile_id,
                state: self.state,
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

pub struct GrantRequestBuilder {
    request_id: String,
    profile_id: ProfileId,
    principal: String,
    rp_ids: Vec<String>,
    ttl_secs: u64,
}

impl GrantRequestBuilder {
    pub fn new(
        request_id: &GrantRequestId,
        profile_id: ProfileId,
        principal_digest: &[u8; 32],
        rp_ids: Vec<String>,
        ttl_secs: u64,
    ) -> Self {
        Self {
            request_id: request_id.as_str().to_string(),
            profile_id,
            principal: hex::encode(principal_digest),
            rp_ids,
            ttl_secs,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::GrantRequest(GrantRequestMeta {
            request_id: self.request_id,
            profile_id: self.profile_id,
            principal: self.principal,
            rp_ids: self.rp_ids,
            ttl_secs: self.ttl_secs,
        }))
    }
}

pub struct GrantApproveBuilder {
    grant_id: GrantId,
    profile_id: ProfileId,
    principal: String,
    rp_ids: Vec<String>,
    ttl_secs: u64,
}

impl GrantApproveBuilder {
    pub fn new(
        grant_id: GrantId,
        profile_id: ProfileId,
        principal_digest: &[u8; 32],
        rp_ids: Vec<String>,
        ttl_secs: u64,
    ) -> Self {
        Self {
            grant_id,
            profile_id,
            principal: hex::encode(principal_digest),
            rp_ids,
            ttl_secs,
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::GrantApprove(GrantApproveMeta {
            grant_id: self.grant_id,
            profile_id: self.profile_id,
            principal: self.principal,
            rp_ids: self.rp_ids,
            ttl_secs: self.ttl_secs,
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
    op: OperationRecord,
    authorization: String,
    user_presence: String,
    user_verification: String,
}

impl PolicyAllowBuilder {
    pub fn new(profile_id: ProfileId, action: AuditAction, rp_id: &str) -> Self {
        Self {
            op: OperationRecord::new(profile_id, action, rp_id),
            authorization: "confirm".to_string(),
            user_presence: "human".to_string(),
            user_verification: "none".to_string(),
        }
    }

    /// The request's origin, top origin (null on the proxy path) and cross-origin flag.
    pub fn origin_context(
        mut self,
        origin: Option<&str>,
        top_origin: Option<&str>,
        cross_origin: Option<bool>,
    ) -> Self {
        self.op = self.op.origin_context(origin, top_origin, cross_origin);
        self
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

    /// The section 12 operation fields (session, rule, credential, backend, counters and so on).
    /// The decision is `allow`, and the evidence source `agent` when the agent session supplied
    /// UP and UV.
    pub fn operation(mut self, op: OperationRecord) -> Self {
        self.op = op;
        self
    }

    pub fn build(self) -> AuditEvent {
        let evidence =
            (self.user_presence == "agent" && self.user_verification == "agent").then_some("agent");
        AuditEvent::new(AuditPayload::PolicyAllow(PolicyAllowMeta {
            op: Box::new(self.op.decision(PolicyDecision::Allow, evidence)),
            authorization: self.authorization,
            user_presence: self.user_presence,
            user_verification: self.user_verification,
        }))
    }
}

pub struct PolicyDenyBuilder {
    op: OperationRecord,
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
            op: OperationRecord::new(profile_id, action, rp_id),
            reason,
        }
    }

    /// The request's origin, top origin (null on the proxy path) and cross-origin flag.
    pub fn origin_context(
        mut self,
        origin: Option<&str>,
        top_origin: Option<&str>,
        cross_origin: Option<bool>,
    ) -> Self {
        self.op = self.op.origin_context(origin, top_origin, cross_origin);
        self
    }

    /// The section 12 operation fields. The decision, result and failure class are set from the
    /// reason.
    pub fn operation(mut self, op: OperationRecord) -> Self {
        self.op = op;
        self
    }

    pub fn build(self) -> AuditEvent {
        let replay = self.reason == PolicyDenyReason::ReplayServed;
        let op = if replay {
            // Not a refusal: a duplicate served the original outcome.
            self.op
                .decision(PolicyDecision::Allow, Some("agent"))
                .outcome(OperationResult::ReplayServed, None)
        } else {
            self.op
                .decision(PolicyDecision::Deny, None)
                .outcome(OperationResult::of_failure(self.reason), Some(self.reason))
        };
        let meta = PolicyDenyMeta {
            op: Box::new(op),
            reason: self.reason,
        };
        if replay {
            AuditEvent::new(AuditPayload::PolicyReplayServed(meta))
        } else {
            AuditEvent::new(AuditPayload::PolicyDeny(meta))
        }
    }
}

/// The terminal record of an operation reservation: the same operation fields as the
/// reservation, with the final result, the failure class (`None` on success) and the counter
/// after.
pub struct OperationTerminalBuilder {
    op: OperationRecord,
    failure: Option<PolicyDenyReason>,
}

impl OperationTerminalBuilder {
    pub fn new(op: OperationRecord, failure: Option<PolicyDenyReason>) -> Self {
        Self { op, failure }
    }

    pub fn build(self) -> AuditEvent {
        let result = self
            .failure
            .map_or(OperationResult::Success, OperationResult::of_failure);
        AuditEvent::new(AuditPayload::OperationTerminal(OperationTerminalMeta {
            op: Box::new(
                self.op
                    .decision(PolicyDecision::Allow, Some("agent"))
                    .outcome(result, self.failure),
            ),
        }))
    }
}

/// A sign-transport hello refused because its peer UID is not the lease's browser UID.
pub struct TransportPeerRefusedBuilder {
    profile_id: ProfileId,
    expected_uid: u32,
    peer_uid: Option<u32>,
}

impl TransportPeerRefusedBuilder {
    pub fn new(profile_id: ProfileId, expected_uid: u32) -> Self {
        Self {
            profile_id,
            expected_uid,
            peer_uid: None,
        }
    }

    /// The peer's UID, if the kernel reported one.
    pub fn peer_uid(mut self, peer_uid: Option<u32>) -> Self {
        self.peer_uid = peer_uid;
        self
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::TransportPeerRefused(
            TransportPeerRefusedMeta {
                profile_id: self.profile_id,
                expected_uid: self.expected_uid,
                peer_uid: self.peer_uid,
            },
        ))
    }
}

/// A sign-transport hello whose build or relay version differs from the daemon's (plan V-L5).
pub struct TransportVersionSkewBuilder {
    profile_id: ProfileId,
    daemon_version: String,
    build_version: Option<String>,
    relay_version: Option<String>,
}

impl TransportVersionSkewBuilder {
    pub fn new(profile_id: ProfileId, daemon_version: &str) -> Self {
        Self {
            profile_id,
            daemon_version: daemon_version.to_string(),
            build_version: None,
            relay_version: None,
        }
    }

    /// The versions the hello reported (bounded and stripped of control characters by the caller).
    pub fn reported(mut self, build_version: Option<&str>, relay_version: Option<&str>) -> Self {
        self.build_version = build_version.map(str::to_string);
        self.relay_version = relay_version.map(str::to_string);
        self
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::TransportVersionSkew(
            TransportVersionSkewMeta {
                profile_id: self.profile_id,
                daemon_version: self.daemon_version,
                build_version: self.build_version,
                relay_version: self.relay_version,
            },
        ))
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

pub struct GrantedRuleRevokeBuilder {
    profile_id: ProfileId,
    rp_id: Option<String>,
    revoked: u32,
}

impl GrantedRuleRevokeBuilder {
    pub fn new(profile_id: ProfileId, rp_id: Option<String>, revoked: usize) -> Self {
        Self {
            profile_id,
            rp_id,
            revoked: u32::try_from(revoked).unwrap_or(u32::MAX),
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::GrantedRuleRevoke(GrantedRuleRevokeMeta {
            profile_id: self.profile_id,
            rp_id: self.rp_id,
            revoked: self.revoked,
        }))
    }
}

pub struct GrantedRuleAddBuilder {
    meta: GrantedRuleAddMeta,
}

impl GrantedRuleAddBuilder {
    pub fn new(
        profile_id: ProfileId,
        rp_id: &str,
        kind: GrantKind,
        escalation_id: &str,
        rule: PermittingRule,
    ) -> Self {
        Self {
            meta: GrantedRuleAddMeta {
                profile_id,
                rp_id: rp_id.to_string(),
                grant_kind: kind,
                escalation_id: escalation_id.to_string(),
                rule: rule.as_str().to_string(),
                credential_ref: None,
            },
        }
    }

    pub fn credential_ref(mut self, credential_ref: Option<CredentialRef>) -> Self {
        self.meta.credential_ref = credential_ref;
        self
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::GrantedRuleAdd(self.meta))
    }
}

/// The fields every `escalation.*` record carries.
#[derive(Debug, Clone)]
pub struct EscalationAuditContext {
    pub escalation_id: String,
    pub profile_id: ProfileId,
    pub action: AuditAction,
    pub rp_id: String,
    /// The origin of the ceremony that raised the escalation.
    pub origin: String,
    pub rule: PermittingRule,
}

impl EscalationAuditContext {
    fn rule_name(&self) -> String {
        self.rule.as_str().to_string()
    }

    pub fn requested(&self) -> AuditEvent {
        AuditEvent::new(AuditPayload::EscalationRequested(EscalationRequestedMeta {
            escalation_id: self.escalation_id.clone(),
            profile_id: self.profile_id.clone(),
            action: self.action,
            rp_id: self.rp_id.clone(),
            origin: self.origin.clone(),
            rule: self.rule_name(),
        }))
    }

    pub fn approved(&self, latency_ms: u64) -> AuditEvent {
        AuditEvent::new(AuditPayload::EscalationApproved(EscalationApprovedMeta {
            escalation_id: self.escalation_id.clone(),
            profile_id: self.profile_id.clone(),
            action: self.action,
            rp_id: self.rp_id.clone(),
            origin: self.origin.clone(),
            rule: self.rule_name(),
            latency_ms,
        }))
    }

    pub fn denied(&self, cause: EscalationDenyCause) -> AuditEvent {
        AuditEvent::new(AuditPayload::EscalationDenied(EscalationDeniedMeta {
            escalation_id: self.escalation_id.clone(),
            profile_id: self.profile_id.clone(),
            action: self.action,
            rp_id: self.rp_id.clone(),
            origin: self.origin.clone(),
            rule: self.rule_name(),
            cause,
        }))
    }

    pub fn expired(&self, reason: EscalationExpireReason) -> AuditEvent {
        AuditEvent::new(AuditPayload::EscalationExpired(EscalationExpiredMeta {
            escalation_id: self.escalation_id.clone(),
            profile_id: self.profile_id.clone(),
            action: self.action,
            rp_id: self.rp_id.clone(),
            origin: self.origin.clone(),
            rule: self.rule_name(),
            reason,
        }))
    }

    pub fn revoked(&self, reason: EscalationRevokeReason) -> AuditEvent {
        AuditEvent::new(AuditPayload::EscalationRevoked(EscalationRevokedMeta {
            escalation_id: self.escalation_id.clone(),
            profile_id: self.profile_id.clone(),
            action: self.action,
            rp_id: self.rp_id.clone(),
            origin: self.origin.clone(),
            rule: self.rule_name(),
            reason,
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
    profile_id: ProfileId,
    credential: CredentialRef,
    rp_id: String,
}

impl AdminCredentialDeleteBuilder {
    pub fn new(profile_id: ProfileId, credential: CredentialRef, rp_id: &str) -> Self {
        Self {
            profile_id,
            credential,
            rp_id: rp_id.to_string(),
        }
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent::new(AuditPayload::AdminCredentialDelete(
            AdminCredentialDeleteMeta {
                profile_id: self.profile_id,
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
    use std::collections::{BTreeSet, HashSet};

    use super::*;

    fn test_profile_id() -> ProfileId {
        ProfileId::new("test-profile").unwrap()
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

    /// An `intent.*` record as written before the intent protocol was removed (P7). Nothing
    /// emits these any more; the payload variants stay so that old logs still deserialize.
    fn historic_intent_event(kind: &str, iid: &IntentId, pid: Option<&ProfileId>) -> AuditEvent {
        let mut payload = serde_json::json!({ "kind": kind, "intent_id": iid });
        if let Some(pid) = pid {
            payload["profile_id"] = serde_json::to_value(pid).unwrap();
            payload["action"] = serde_json::json!("register");
        }
        AuditEvent::new(serde_json::from_value(payload).unwrap())
    }

    /// An `endpoint.*` record as written before the isolated UHID route was removed (ADR 0014
    /// section 5). Nothing emits these any more; the payload variants stay so that old logs still
    /// deserialize.
    fn historic_endpoint_event(kind: &str, pid: &ProfileId) -> AuditEvent {
        let mut payload = serde_json::json!({
            "kind": kind,
            "endpoint_id": "ep-historic",
            "profile_id": pid,
        });
        if kind == "endpoint.fail" {
            payload["reason"] = serde_json::json!("timeout");
        }
        AuditEvent::new(serde_json::from_value(payload).unwrap())
    }

    fn escalation_context(pid: &ProfileId) -> EscalationAuditContext {
        EscalationAuditContext {
            escalation_id: "esc-1".to_string(),
            profile_id: pid.clone(),
            action: AuditAction::Authenticate,
            rp_id: "example.com".to_string(),
            origin: "https://example.com".to_string(),
            rule: PermittingRule::Exact,
        }
    }

    /// An operation record with every field set.
    fn full_operation_record(pid: &ProfileId, cred: &CredentialRef) -> OperationRecord {
        OperationRecord::new(pid.clone(), AuditAction::Authenticate, "example.com")
            .origin_context(Some("https://example.com"), None, Some(false))
            .session(Some("ab".repeat(32)), Some("req-1".to_string()))
            .escalation(Some("esc-1".to_string()))
            .deployment(
                Some("same-user".to_string()),
                Some("shared-uid".to_string()),
                Some("local".to_string()),
                Some("software".to_string()),
            )
            .epochs(3, 2)
            .matched(Some("*".to_string()), Some(RuleGrantSource::Granted))
            .credential(Some(cred.clone()), Some("single".to_string()))
            .counters(Some(4), Some(5))
    }

    fn all_test_events() -> Vec<AuditEvent> {
        let pid = test_profile_id();
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
            historic_endpoint_event("endpoint.create", &pid),
            historic_endpoint_event("endpoint.destroy", &pid),
            historic_endpoint_event("endpoint.fail", &pid),
            PrincipalLaunchBuilder::new(sid.clone(), pid.clone(), 1000).build(),
            PrincipalDenyBuilder::new(sid.clone(), pid.clone(), DenyReason::PolicyDenied).build(),
            PrincipalExitBuilder::new(sid.clone(), pid.clone(), ExitReason::Normal).build(),
            BrowserLeaseLaunchBuilder::new(lid.clone(), pid.clone())
                .with_cdp_expose("pipe".to_string())
                .build(),
            BrowserLeaseRevokeBuilder::new(lid.clone(), RevokeReason::AdminRevoked).build(),
            BrowserLeaseExpireBuilder::new(lid.clone()).build(),
            BrowserLeaseCrashBuilder::new(lid.clone(), -11).build(),
            BrowserLeaseCleanupBuilder::new(lid.clone()).build(),
            BrowserLeaseQuarantineBuilder::new(lid.clone(), QuarantineReason::SymlinkEscape)
                .build(),
            BrowserLeaseInterceptionBuilder::new(
                lid.clone(),
                pid.clone(),
                InterceptionAuditState::Degraded,
            )
            .build(),
            historic_intent_event("intent.create", &iid, Some(&pid)),
            historic_intent_event("intent.approve", &iid, None),
            historic_intent_event("intent.deny", &iid, None),
            historic_intent_event("intent.cancel", &iid, None),
            historic_intent_event("intent.claim", &iid, None),
            historic_intent_event("intent.consume", &iid, None),
            historic_intent_event("intent.expire", &iid, None),
            GrantRequestBuilder::new(
                &req_id,
                pid.clone(),
                &[7u8; 32],
                vec!["example.com".to_string()],
                300,
            )
            .build(),
            GrantApproveBuilder::new(
                gid.clone(),
                pid.clone(),
                &[7u8; 32],
                vec!["example.com".to_string()],
                300,
            )
            .build(),
            GrantRevokeBuilder::new(gid.clone()).build(),
            GrantExpireBuilder::new(gid.clone()).build(),
            GrantClaimBuilder::new(gid.clone(), &cer_id).build(),
            GrantConsumeBuilder::new(gid.clone(), &cer_id).build(),
            GrantedRuleRevokeBuilder::new(pid.clone(), Some("example.com".to_string()), 1).build(),
            GrantedRuleAddBuilder::new(
                pid.clone(),
                "example.com",
                GrantKind::Registration,
                "esc-1",
                PermittingRule::Wildcard,
            )
            .credential_ref(Some(cred.clone()))
            .build(),
            escalation_context(&pid).requested(),
            escalation_context(&pid).approved(1500),
            escalation_context(&pid).denied(EscalationDenyCause::User),
            escalation_context(&pid).expired(EscalationExpireReason::Aborted),
            escalation_context(&pid).revoked(EscalationRevokeReason::PolicyReload),
            PolicyAllowBuilder::new(pid.clone(), AuditAction::Authenticate, "example.com")
                .evidence_sources("allow", "agent", "agent")
                .operation(full_operation_record(&pid, &cred))
                .build(),
            PolicyDenyBuilder::new(
                pid.clone(),
                AuditAction::Authenticate,
                "example.com",
                PolicyDenyReason::EscalationDenied,
            )
            .operation(full_operation_record(&pid, &cred))
            .build(),
            PolicyDenyBuilder::new(
                pid.clone(),
                AuditAction::Authenticate,
                "example.com",
                PolicyDenyReason::ReplayServed,
            )
            .operation(full_operation_record(&pid, &cred))
            .build(),
            OperationTerminalBuilder::new(full_operation_record(&pid, &cred), None).build(),
            TransportVersionSkewBuilder::new(pid.clone(), "0.21.0+abc")
                .reported(Some("0.20.0+def"), None)
                .build(),
            TransportPeerRefusedBuilder::new(pid.clone(), 1001)
                .peer_uid(Some(1000))
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

    fn envelope_free_keys(json: &serde_json::Value) -> BTreeSet<String> {
        json.as_object()
            .unwrap()
            .keys()
            .filter(|key| !matches!(key.as_str(), "v" | "ts" | "kind"))
            .cloned()
            .collect()
    }

    #[test]
    fn test_schema_version_is_bumped_for_the_section_12_records() {
        assert_eq!(
            AUDIT_SCHEMA_VERSION, 3,
            "operation records changed shape in P8: the version must stay above 2"
        );
    }

    #[test]
    fn test_section_12_field_list_has_no_duplicates() {
        let unique: BTreeSet<_> = SECTION_12_OPERATION_FIELDS.iter().collect();
        assert_eq!(unique.len(), SECTION_12_OPERATION_FIELDS.len());
    }

    #[test]
    fn test_every_operation_record_carries_exactly_the_canonical_section_12_fields() {
        let events = all_test_events();
        for kind in SECTION_12_OPERATION_KINDS {
            let extras = SECTION_12_OPERATION_EXTRAS
                .iter()
                .find(|(extras_kind, _)| extras_kind == kind)
                .unwrap_or_else(|| panic!("no extras row for {kind}"))
                .1;
            let expected: BTreeSet<String> = SECTION_12_OPERATION_FIELDS
                .iter()
                .chain(extras)
                .map(|field| field.to_string())
                .collect();
            let samples: Vec<_> = events.iter().filter(|e| e.kind_name() == *kind).collect();
            assert!(!samples.is_empty(), "no sample record of kind {kind}");
            for event in samples {
                let keys = envelope_free_keys(&serde_json::to_value(event).unwrap());
                let missing: Vec<_> = expected.difference(&keys).collect();
                let unlisted: Vec<_> = keys.difference(&expected).collect();
                assert!(
                    missing.is_empty(),
                    "{kind} lacks the section 12 field(s) {missing:?}"
                );
                assert!(
                    unlisted.is_empty(),
                    "{kind} carries field(s) {unlisted:?} that the section 12 list does not name"
                );
            }
        }
    }

    #[test]
    fn test_no_other_record_claims_the_operation_fields_without_being_listed() {
        // A record kind that carries the operation record's fields must be in the kinds list.
        for event in all_test_events() {
            let json = serde_json::to_value(&event).unwrap();
            if json.get("session_id_hash").is_some() {
                assert!(
                    SECTION_12_OPERATION_KINDS.contains(&event.kind_name()),
                    "{} carries operation fields but is not in SECTION_12_OPERATION_KINDS",
                    event.kind_name()
                );
            }
        }
    }

    #[test]
    fn test_escalation_session_grant_and_lease_records_carry_exactly_their_listed_fields() {
        let events = all_test_events();
        for (kind, fields) in SECTION_12_OTHER_RECORD_FIELDS {
            let expected: BTreeSet<String> = fields.iter().map(|field| field.to_string()).collect();
            let event = events
                .iter()
                .find(|e| e.kind_name() == *kind)
                .unwrap_or_else(|| panic!("no sample record of kind {kind}"));
            let keys = envelope_free_keys(&serde_json::to_value(event).unwrap());
            let missing: Vec<_> = expected.difference(&keys).collect();
            let unlisted: Vec<_> = keys.difference(&expected).collect();
            assert!(
                missing.is_empty(),
                "{kind} lacks the section 12 field(s) {missing:?}"
            );
            assert!(
                unlisted.is_empty(),
                "{kind} carries field(s) {unlisted:?} that the section 12 list does not name"
            );
        }
    }

    #[test]
    fn test_section_12_lists_cover_every_escalation_kind() {
        for kind in [
            "escalation.requested",
            "escalation.approved",
            "escalation.denied",
            "escalation.expired",
            "escalation.revoked",
            "granted_rule.add",
            "granted_rule.revoke",
        ] {
            assert!(
                SECTION_12_OTHER_RECORD_FIELDS
                    .iter()
                    .any(|(listed, _)| *listed == kind),
                "{kind} is not in the section 12 list"
            );
        }
    }

    #[test]
    fn test_operation_record_values() {
        let pid = test_profile_id();
        let cred = test_cred();
        let terminal = [
            OperationTerminalBuilder::new(full_operation_record(&pid, &cred), None).build(),
            OperationTerminalBuilder::new(
                full_operation_record(&pid, &cred),
                Some(PolicyDenyReason::SigningFailed),
            )
            .build(),
        ]
        .map(|event| serde_json::to_value(event).unwrap());
        assert_eq!(terminal[0]["result"], "success");
        assert!(terminal[0]["failure_class"].is_null());
        assert_eq!(terminal[0]["decision"], "allow");
        assert_eq!(terminal[0]["evidence_source"], "agent");
        assert_eq!(terminal[0]["counter_before"], 4);
        assert_eq!(terminal[0]["counter_after"], 5);
        assert_eq!(terminal[0]["rule"], "*");
        assert_eq!(terminal[0]["grant_source"], "granted");
        assert_eq!(terminal[1]["result"], "error");
        assert_eq!(terminal[1]["failure_class"], "signing_failed");
    }

    #[test]
    fn test_failure_classes_map_to_results() {
        use PolicyDenyReason as R;
        for (failure, result) in [
            (R::Aborted, OperationResult::Aborted),
            (R::PolicyRevoked, OperationResult::Revoked),
            (R::GrantRevoked, OperationResult::Revoked),
            (R::BearerRevoked, OperationResult::Revoked),
            (R::SessionExpired, OperationResult::Revoked),
            (R::EscalationExpired, OperationResult::Timeout),
            (R::EscalationQueueFull, OperationResult::Busy),
            (R::EscalationWaiterCap, OperationResult::Busy),
            (R::EscalationDenied, OperationResult::Denied),
            (R::ActionNotAllowed, OperationResult::Denied),
            (R::OriginInvalid, OperationResult::Denied),
            (R::SigningFailed, OperationResult::Error),
            (R::CounterPersistenceFailure, OperationResult::Error),
            (R::Abandoned, OperationResult::Error),
        ] {
            assert_eq!(OperationResult::of_failure(failure), result, "{failure:?}");
        }
    }

    #[test]
    fn test_records_of_an_older_schema_still_deserialize() {
        let old_records = [
            serde_json::json!({
                "v": 2, "ts": 1, "kind": "policy.allow", "profile_id": "test-profile",
                "action": "authenticate", "rp_id": "example.com", "authorization": "allow",
                "user_presence": "agent", "user_verification": "agent",
                "origin": "https://example.com", "top_origin": null, "cross_origin": false
            }),
            serde_json::json!({
                "v": 2, "ts": 1, "kind": "policy.deny", "profile_id": "test-profile",
                "action": "authenticate", "rp_id": "example.com", "reason": "default_deny"
            }),
            serde_json::json!({
                "v": 2, "ts": 1, "kind": "escalation.approved", "escalation_id": "esc-1",
                "profile_id": "test-profile", "action": "authenticate", "rp_id": "example.com",
                "latency_ms": 5
            }),
            serde_json::json!({
                "v": 2, "ts": 1, "kind": "escalation.requested", "escalation_id": "esc-1",
                "profile_id": "test-profile", "action": "authenticate", "rp_id": "example.com",
                "origin": "https://example.com", "rule": "exact"
            }),
            serde_json::json!({
                "v": 2, "ts": 1, "kind": "grant.request", "request_id": "r",
                "profile_id": "test-profile", "rp_ids": ["example.com"]
            }),
            serde_json::json!({
                "v": 2, "ts": 1, "kind": "grant.approve", "grant_id": test_grant_id(),
                "profile_id": "test-profile", "ttl_secs": 300
            }),
        ];
        for old in old_records {
            let kind = old["kind"].as_str().unwrap().to_string();
            let event: AuditEvent = serde_json::from_value(old)
                .unwrap_or_else(|e| panic!("a version 2 {kind} record no longer parses: {e}"));
            assert_eq!(event.schema_version(), 2);
            assert_eq!(event.kind_name(), kind);
        }
    }

    #[test]
    fn test_escalation_records_name_the_rule_as_exact_or_star() {
        let pid = test_profile_id();
        for (rule, name) in [
            (PermittingRule::Exact, "exact"),
            (PermittingRule::Wildcard, "*"),
        ] {
            let mut context = escalation_context(&pid);
            context.rule = rule;
            for event in [
                context.requested(),
                context.approved(1),
                context.denied(EscalationDenyCause::User),
                context.expired(EscalationExpireReason::Timeout),
                context.revoked(EscalationRevokeReason::PolicyReload),
            ] {
                let json = serde_json::to_value(&event).unwrap();
                assert_eq!(json["rule"], name, "{}", event.kind_name());
            }
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
        assert_eq!(events.len(), 62);
        let mut kinds = HashSet::new();
        for event in &events {
            kinds.insert(event.kind_name().to_string());
        }
        assert_eq!(kinds.len(), 62, "duplicate kind names detected");
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
    fn test_escalation_reason_codes_serialize_stably() {
        for (reason, expected) in [
            (PolicyDenyReason::EscalationCooldown, "escalation_cooldown"),
            (
                PolicyDenyReason::EscalationQueueFull,
                "escalation_queue_full",
            ),
            (
                PolicyDenyReason::EscalationWaiterCap,
                "escalation_waiter_cap",
            ),
            (PolicyDenyReason::EscalationBusy, "escalation_busy"),
            (PolicyDenyReason::GrantCapReached, "grant_cap_reached"),
            (PolicyDenyReason::GrantsUnavailable, "grants_unavailable"),
            (PolicyDenyReason::EscalationDenied, "escalation_denied"),
            (PolicyDenyReason::EscalationExpired, "escalation_expired"),
            (
                PolicyDenyReason::EscalationUnavailable,
                "escalation_unavailable",
            ),
        ] {
            assert_eq!(serde_json::to_value(reason).unwrap(), expected);
        }
        for (reason, expected) in [
            (EscalationExpireReason::Timeout, "timeout"),
            (EscalationExpireReason::Aborted, "aborted"),
            (EscalationExpireReason::ServerLost, "server_lost"),
        ] {
            assert_eq!(serde_json::to_value(reason).unwrap(), expected);
        }
        assert_eq!(
            serde_json::to_value(EscalationRevokeReason::PolicyReload).unwrap(),
            "policy_reload"
        );
        let event = escalation_context(&test_profile_id()).expired(EscalationExpireReason::Timeout);
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["kind"], "escalation.expired");
        assert_eq!(json["reason"], "timeout");
        assert_eq!(json["escalation_id"], "esc-1");
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
            "browser_lease.interception",
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
            "granted_rule.revoke",
            "granted_rule.add",
            "escalation.requested",
            "escalation.approved",
            "escalation.denied",
            "escalation.expired",
            "escalation.revoked",
            "policy.allow",
            "policy.deny",
            "policy.replay_served",
            "operation.terminal",
            "transport.version_skew",
            "transport.peer_refused",
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
