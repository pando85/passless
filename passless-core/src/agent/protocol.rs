use serde::{Deserialize, Serialize};
use std::fmt;

use super::ids::{
    CredentialRef, EndpointId, GrantId, PendingRequestId, PrincipalSessionId, ProfileId,
    RegistrationGrantId,
};

#[cfg(target_os = "linux")]
use std::os::unix::io::RawFd;

pub const MAX_MESSAGE_SIZE: usize = 16_384;
pub const CAPABILITY_PROOF_BYTES: usize = 32;
const MAX_ARGV_LEN: usize = 256;
const MAX_ARGV_COUNT: usize = 64;
const MAX_CDP_REQUEST_LEN: usize = 8 * 1024;
const MAX_CDP_TIMEOUT_MS: u32 = 30_000;

pub const CURRENT_VERSION: ProtocolVersion = ProtocolVersion { major: 1, minor: 1 };

const MAX_RP_ID_LEN: usize = 253;
const MAX_PROFILE_ID_LEN: usize = 128;
const MAX_USER_NAME_LEN: usize = 256;
const MAX_DISPLAY_NAME_LEN: usize = 256;
const MAX_REASON_LEN: usize = 1024;
const MAX_DIAGNOSTIC_LEN: usize = 4096;
const MAX_REG_ORIGIN_LEN: usize = 2048;
const MAX_REG_CHALLENGE_B64U_LEN: usize = 1376;
const MAX_REG_USER_ID_B64U_LEN: usize = 88;
const MAX_REG_EXCLUDE_CREDENTIALS: usize = 64;
const MAX_REG_EXCLUDE_CREDENTIAL_ENTRY_LEN: usize = 344;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    pub fn negotiate(offer: ProtocolVersion) -> Result<ProtocolVersion, ProtocolError> {
        if offer.major == 0 {
            return Err(ProtocolError {
                code: ErrorCode::VersionMismatch,
                message: "major version must be >= 1".into(),
                recommended_action: RecommendedAction::UpgradeClient,
            });
        }
        if offer.major != CURRENT_VERSION.major {
            return Err(ProtocolError {
                code: ErrorCode::VersionMismatch,
                message: format!(
                    "incompatible major version: offered {}, supported {}",
                    offer.major, CURRENT_VERSION.major,
                ),
                recommended_action: RecommendedAction::UpgradeClient,
            });
        }
        Ok(ProtocolVersion {
            major: CURRENT_VERSION.major,
            #[allow(clippy::unnecessary_min_or_max)]
            minor: offer.minor.min(CURRENT_VERSION.minor),
        })
    }
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        CURRENT_VERSION
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PrincipalCapabilityProof(#[serde(with = "hex_32")] [u8; CAPABILITY_PROOF_BYTES]);

mod hex_32 {
    use serde::de;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(de::Error::custom)?;
        if v.len() != 32 {
            return Err(de::Error::custom(format!(
                "expected 32 bytes, got {}",
                v.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&v);
        Ok(arr)
    }
}

impl PrincipalCapabilityProof {
    pub fn from_bytes(bytes: [u8; CAPABILITY_PROOF_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; CAPABILITY_PROOF_BYTES] {
        &self.0
    }

    pub fn verify_constant_time(&self, other: &Self) -> bool {
        let mut diff = 0u8;
        for i in 0..CAPABILITY_PROOF_BYTES {
            diff |= self.0[i] ^ other.0[i];
        }
        diff == 0
    }
}

impl fmt::Debug for PrincipalCapabilityProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrincipalCapabilityProof(***)")
    }
}

impl fmt::Display for PrincipalCapabilityProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    Admin,
    Principal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    InteractionRequired,
    Internal,
    VersionMismatch,
    MessageTooLarge,
    MalformedMessage,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRequest => write!(f, "bad_request"),
            Self::Unauthorized => write!(f, "unauthorized"),
            Self::Forbidden => write!(f, "forbidden"),
            Self::NotFound => write!(f, "not_found"),
            Self::Conflict => write!(f, "conflict"),
            Self::InteractionRequired => write!(f, "interaction_required"),
            Self::Internal => write!(f, "internal"),
            Self::VersionMismatch => write!(f, "version_mismatch"),
            Self::MessageTooLarge => write!(f, "message_too_large"),
            Self::MalformedMessage => write!(f, "malformed_message"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendedAction {
    None,
    Retry,
    RetryWithBackoff,
    FixRequest,
    UpgradeClient,
    Abort,
}

impl fmt::Display for RecommendedAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Retry => write!(f, "retry"),
            Self::RetryWithBackoff => write!(f, "retry_with_backoff"),
            Self::FixRequest => write!(f, "fix_request"),
            Self::UpgradeClient => write!(f, "upgrade_client"),
            Self::Abort => write!(f, "abort"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolError {
    pub code: ErrorCode,
    pub message: String,
    pub recommended_action: RecommendedAction,
}

impl ProtocolError {
    pub fn new(code: ErrorCode, message: impl Into<String>, action: RecommendedAction) -> Self {
        Self {
            code,
            message: message.into(),
            recommended_action: action,
        }
    }

    pub fn malformed(message: impl Into<String>) -> Self {
        Self::new(
            ErrorCode::MalformedMessage,
            message,
            RecommendedAction::FixRequest,
        )
    }

    pub fn oversized(size: usize, max: usize) -> Self {
        Self::new(
            ErrorCode::MessageTooLarge,
            format!("message size {} exceeds maximum {}", size, max),
            RecommendedAction::FixRequest,
        )
    }

    pub fn version_mismatch(offer: &ProtocolVersion) -> Self {
        Self::new(
            ErrorCode::VersionMismatch,
            format!(
                "incompatible protocol version {}: supported {}",
                offer, CURRENT_VERSION,
            ),
            RecommendedAction::UpgradeClient,
        )
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for ProtocolError {}

impl ProtocolError {
    pub fn validate_message(message: &str) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();
        if message.len() > MAX_DIAGNOSTIC_LEN {
            errors.push(format!(
                "error message exceeds maximum length {} (got {})",
                MAX_DIAGNOSTIC_LEN,
                message.len()
            ));
        }
        if message.contains('\0') {
            errors.push("error message must not contain null bytes".to_string());
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationErrors(errors))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum AdminRequest {
    Ping,
    Status,
    ListCredentials {
        #[serde(skip_serializing_if = "Option::is_none")]
        rp_id: Option<String>,
    },
    DeleteCredential {
        credential_ref: CredentialRef,
    },
    RenameCredential {
        credential_ref: CredentialRef,
        #[serde(skip_serializing_if = "Option::is_none")]
        user_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        display_name: Option<String>,
    },
    ProfileStatus {
        profile_id: ProfileId,
    },
    ReloadPolicy {
        profile_id: ProfileId,
    },
    ListGrants {
        #[serde(skip_serializing_if = "Option::is_none")]
        profile_id: Option<ProfileId>,
    },
    ShowGrant {
        grant_id: GrantId,
    },
    RevokeGrant {
        grant_id: GrantId,
    },
    ListSessions {
        #[serde(skip_serializing_if = "Option::is_none")]
        profile_id: Option<ProfileId>,
    },
    ShowSession {
        session_id: PrincipalSessionId,
    },
    RevokeSession {
        session_id: PrincipalSessionId,
    },
    AuditStatus,
    AuditVerify,
    AuditExport {
        format: AuditExportFormat,
    },
    ListProfiles,
    ShowProfile {
        profile_id: ProfileId,
    },
    EnableProfile {
        profile_id: ProfileId,
    },
    DisableProfile {
        profile_id: ProfileId,
    },
    ShowPolicy {
        profile_id: ProfileId,
    },
    ShowCredential {
        credential_ref: CredentialRef,
    },
    RevokeCredential {
        credential_ref: CredentialRef,
    },
    ShowDelegation {
        grant_id: GrantId,
    },
    ListDelegations {
        #[serde(skip_serializing_if = "Option::is_none")]
        profile_id: Option<ProfileId>,
    },
    RevokeDelegation {
        grant_id: GrantId,
    },
    LaunchPrincipal {
        profile_id: ProfileId,
        command: Vec<String>,
    },
    TerminatePrincipal {
        profile_id: ProfileId,
    },
    WaitPrincipal {
        session_id: PrincipalSessionId,
        timeout_ms: u32,
    },
    ProfileCheck {
        profile_id: ProfileId,
    },
    RequestDelegation {
        profile_id: ProfileId,
        rp_id: String,
        credential_ref: CredentialRef,
        max_session_ttl: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    RequestRegistration {
        profile_id: ProfileId,
        rp_id: String,
        max_session_ttl: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    LaunchBrowser {
        profile_id: ProfileId,
        #[serde(skip_serializing_if = "Option::is_none")]
        start_url: Option<String>,
    },
    Shutdown,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum AdminResponse {
    Pong,
    Status(DaemonStatus),
    CredentialList(CredentialList),
    Deleted,
    Renamed,
    ProfileStatus(ProfileStatusResponse),
    PolicyReloaded,
    PolicyRecompiled,
    GrantList(GrantList),
    GrantInfo(GrantInfo),
    SessionList(SessionList),
    SessionInfo(SessionInfo),
    GrantRevoked,
    SessionRevoked,
    AuditStatus(AuditStatusResponse),
    AuditVerified(AuditVerifyResponse),
    AuditExported(AuditExportedResponse),
    ProfileList(ProfileList),
    ProfileInfo(ProfileInfo),
    ProfileEnabled,
    ProfileDisabled,
    PolicyInfo(PolicyInfo),
    CredentialInfo(CredentialInfo),
    CredentialRevoked,
    DelegationInfo(GrantInfo),
    DelegationList(GrantList),
    DelegationRevoked,
    PrincipalLaunched(PrincipalLaunchedResponse),
    BrowserLaunched(BrowserLaunchedResponse),
    PrincipalTerminated,
    PrincipalWait(PrincipalWaitResponse),
    ProfileCheck(ProfileDiagnosticReport),
    DelegationRequested {
        request_id: PendingRequestId,
    },
    RegistrationGranted {
        registration_grant_id: RegistrationGrantId,
    },
    ShutdownAccepted,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum PrincipalRequest {
    Ping,
    Status,
    Capabilities,
    Authority,
    Instructions,
    Doctor,
    CreateIntent {
        profile_id: ProfileId,
        action: IntentAction,
        rp_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        credential_ref: Option<CredentialRef>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        grant_ttl_secs: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        session_ttl_secs: Option<u64>,
    },
    ShowIntent {
        request_id: PendingRequestId,
    },
    WaitIntent {
        request_id: PendingRequestId,
    },
    CancelIntent {
        request_id: PendingRequestId,
    },
    RequestDelegation {
        profile_id: ProfileId,
        rp_id: String,
        credential_ref: CredentialRef,
        max_session_ttl: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    ShowDelegation {
        request_id: PendingRequestId,
    },
    WaitDelegation {
        request_id: PendingRequestId,
    },
    CancelDelegation {
        request_id: PendingRequestId,
    },
    ListCredentials {
        profile_id: ProfileId,
    },
    BrowserStatus,
    EndpointStatus,
    BrowserControl {
        request_json: String,
        timeout_ms: u32,
    },
    SignAssertion(SignAssertionRequest),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum IntentAction {
    Register,
    Authenticate,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum PrincipalResponse {
    Pong,
    Status(DaemonStatus),
    Capabilities(PrincipalCapabilities),
    Authority(EffectiveAuthority),
    Instructions(PrincipalInstructions),
    Doctor(DoctorResponse),
    IntentCreated {
        request_id: PendingRequestId,
    },
    IntentStatus {
        request_id: PendingRequestId,
        state: IntentState,
    },
    IntentCancelled,
    DelegationRequested {
        request_id: PendingRequestId,
    },
    DelegationStatus {
        request_id: PendingRequestId,
        state: DelegationState,
    },
    DelegationCancelled,
    CredentialList(PrincipalCredentialList),
    BrowserStatus(BrowserStatusResponse),
    EndpointStatus(EndpointStatusResponse),
    BrowserControl {
        messages: Vec<String>,
    },
    SignAssertionResult(SignAssertionResponse),
}

const MAX_ORIGIN_LEN: usize = 512;
const MAX_B64U_LEN: usize = 1024;
const MAX_ALLOW_CREDENTIALS: usize = 64;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterCredentialRequest {
    pub origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_origin: Option<String>,
    pub rp_id: String,
    pub challenge_b64u: String,
    pub user_id_b64u: String,
    pub user_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp_name: Option<String>,
    pub exclude_credentials: Vec<String>,
    #[serde(default)]
    pub pub_key_cred_params: Vec<i32>,
    pub user_verification: bool,
    pub cross_origin: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterCredentialResponse {
    pub credential_id_b64u: String,
    pub public_key_algorithm: i32,
    pub authenticator_data_b64u: String,
    pub attestation_object_b64u: String,
    pub client_data_json_b64u: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignAssertionRequest {
    pub origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_origin: Option<String>,
    pub rp_id: String,
    pub challenge_b64u: String,
    #[serde(default)]
    pub allow_credentials: Vec<String>,
    #[serde(default)]
    pub user_verification: bool,
    #[serde(default)]
    pub cross_origin: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignAssertionResponse {
    pub credential_id_b64u: String,
    pub authenticator_data_b64u: String,
    pub signature_b64u: String,
    pub user_handle_b64u: String,
    pub client_data_json_b64u: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalCapabilities {
    pub profile_id: String,
    pub mode: String,
    pub allowed_rp_ids: Vec<String>,
    pub registration_allowed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveAuthority {
    pub profile_id: String,
    pub mode: String,
    pub identity: AuthorityIdentity,
    pub policy_generation: String,
    pub rp_rules: Vec<AuthorityRpRule>,
    pub credentials: AuthorityCredentialScope,
    pub session: AuthoritySession,
    pub browser: AuthorityBrowser,
    pub risk_flags: Vec<AuthorityRisk>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityIdentity {
    pub acts_as_human: bool,
    pub credential_namespace: String,
    pub rp_identity: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRpRule {
    pub rp_id: String,
    pub wildcard: bool,
    pub authenticate: AuthorityCeremony,
    pub register: AuthorityCeremony,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityCeremony {
    pub authorization: String,
    pub user_presence: String,
    pub user_verification: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityCredentialScope {
    pub dynamic_per_rp: bool,
    pub configured_reference_count: u32,
    pub selection: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySession {
    pub max_session_ttl_secs: u64,
    pub principal_remaining_ttl_secs: u64,
    pub max_operations: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operations_used: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operations_remaining: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityBrowser {
    pub active: bool,
    pub cdp_exposure: String,
    pub direct_cdp: bool,
    pub full_session_authority: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityRisk {
    HumanIdentity,
    GlobalRpScope,
    AutonomousAuthentication,
    HumanBackendRegistration,
    DirectCdpPort,
    AmbiguousCredentialSelection,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalInstructions {
    pub profile_id: String,
    pub mode: String,
    pub instructions: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentState {
    Pending,
    Approved,
    Denied,
    Cancelled,
    Expired,
}

impl fmt::Display for IntentState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Approved => write!(f, "approved"),
            Self::Denied => write!(f, "denied"),
            Self::Cancelled => write!(f, "cancelled"),
            Self::Expired => write!(f, "expired"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationState {
    Pending,
    Approved,
    Denied,
    Cancelled,
    Expired,
    Revoked,
}

impl fmt::Display for DelegationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Approved => write!(f, "approved"),
            Self::Denied => write!(f, "denied"),
            Self::Cancelled => write!(f, "cancelled"),
            Self::Expired => write!(f, "expired"),
            Self::Revoked => write!(f, "revoked"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditExportFormat {
    Json,
    Csv,
}

impl fmt::Display for AuditExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json => write!(f, "json"),
            Self::Csv => write!(f, "csv"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileStatusResponse {
    pub profile_id: String,
    pub mode: String,
    pub policy_generation: u64,
    pub active_grants: u32,
    pub active_sessions: u32,
    pub pending_intents: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantInfo {
    pub grant_id: GrantId,
    pub profile_id: String,
    pub rp_id: String,
    pub credential_ref: CredentialRef,
    pub state: DelegationState,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantList {
    pub grants: Vec<GrantInfo>,
    pub total: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionInfo {
    pub session_id: PrincipalSessionId,
    pub profile_id: String,
    pub pid: u32,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionList {
    pub sessions: Vec<SessionInfo>,
    pub total: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditStatusResponse {
    pub enabled: bool,
    pub entry_count: u64,
    pub latest_entry_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditVerifyResponse {
    pub verified: bool,
    pub entries_checked: u64,
    pub integrity_ok: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditExportedResponse {
    pub entry_count: u64,
    pub format: AuditExportFormat,
    pub path: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalLaunchedResponse {
    pub session_id: PrincipalSessionId,
    pub pid: u32,
    pub profile_id: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserLaunchedResponse {
    pub lease_id: String,
    pub profile_id: String,
    pub pid: u32,
    pub start_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cdp_endpoint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalWaitResponse {
    pub running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorResponse {
    pub healthy: bool,
    pub checks: Vec<DoctorCheck>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoctorCheck {
    pub name: String,
    pub passed: bool,
    pub message: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointDiagnosticState {
    Ready,
    Unavailable,
}

impl fmt::Display for EndpointDiagnosticState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready => write!(f, "ready"),
            Self::Unavailable => write!(f, "unavailable"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileDiagnosticReport {
    pub profile_id: String,
    pub enabled: bool,
    pub mode: String,
    pub endpoint_state: EndpointDiagnosticState,
    pub browser_lease_state: Option<String>,
    pub policy_generation: u64,
    pub audit_gate_healthy: bool,
    pub pin_storage_available: bool,
    pub pin_set: bool,
    pub checks: Vec<DoctorCheck>,
}

impl ProfileDiagnosticReport {
    pub fn is_healthy(&self) -> bool {
        self.enabled
            && self.audit_gate_healthy
            && self.pin_storage_available
            && self.checks.iter().all(|c| c.passed)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserStatusResponse {
    pub running: bool,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cdp_endpoint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointStatusResponse {
    pub endpoint_id: EndpointId,
    pub status: String,
    pub connected: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalCredentialSummary {
    pub credential_ref: CredentialRef,
    pub rp_id: String,
    pub user_name: String,
    pub display_name: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalCredentialList {
    pub credentials: Vec<PrincipalCredentialSummary>,
    pub total: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonStatus {
    pub daemon_version: String,
    pub protocol_version: ProtocolVersion,
    pub backend: String,
    pub uptime_secs: u64,
    pub credential_count: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialSummary {
    pub credential_ref: CredentialRef,
    pub rp_id: String,
    pub user_name: String,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialList {
    pub credentials: Vec<CredentialSummary>,
    pub total: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSummary {
    pub profile_id: String,
    pub enabled: bool,
    pub mode: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileList {
    pub profiles: Vec<ProfileSummary>,
    pub total: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileInfo {
    pub profile_id: String,
    pub enabled: bool,
    pub mode: String,
    pub policy_generation: u64,
    pub active_grants: u32,
    pub active_sessions: u32,
    pub pending_intents: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyInfo {
    pub profile_id: String,
    pub policy_generation: u64,
    pub digest: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialInfo {
    pub credential_ref: CredentialRef,
    pub rp_id: String,
    pub user_name: String,
    pub display_name: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "role", rename_all = "lowercase")]
pub enum RequestFrame {
    Admin(AdminRequestFrame),
    Principal(PrincipalRequestFrame),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminRequestFrame {
    pub v: ProtocolVersion,
    pub seq: u64,
    pub action: AdminRequest,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalRequestFrame {
    pub v: ProtocolVersion,
    pub seq: u64,
    pub action: PrincipalRequest,
    pub capability_proof: PrincipalCapabilityProof,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "role", rename_all = "lowercase")]
pub enum ResponseFrame {
    Admin(AdminResponseFrame),
    Principal(PrincipalResponseFrame),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "status", rename_all = "lowercase")]
pub enum AdminResponseFrame {
    Ok {
        v: ProtocolVersion,
        seq: u64,
        action: AdminResponse,
    },
    Error {
        v: ProtocolVersion,
        seq: u64,
        error: ProtocolError,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "status", rename_all = "lowercase")]
pub enum PrincipalResponseFrame {
    Ok {
        v: ProtocolVersion,
        seq: u64,
        action: Box<PrincipalResponse>,
    },
    Error {
        v: ProtocolVersion,
        seq: u64,
        error: ProtocolError,
    },
}

impl RequestFrame {
    pub fn version(&self) -> ProtocolVersion {
        match self {
            Self::Admin(f) => f.v,
            Self::Principal(f) => f.v,
        }
    }

    pub fn seq(&self) -> u64 {
        match self {
            Self::Admin(f) => f.seq,
            Self::Principal(f) => f.seq,
        }
    }

    pub fn role(&self) -> Role {
        match self {
            Self::Admin(_) => Role::Admin,
            Self::Principal(_) => Role::Principal,
        }
    }
}

impl ResponseFrame {
    pub fn version(&self) -> ProtocolVersion {
        match self {
            Self::Admin(AdminResponseFrame::Ok { v, .. }) => *v,
            Self::Admin(AdminResponseFrame::Error { v, .. }) => *v,
            Self::Principal(PrincipalResponseFrame::Ok { v, .. }) => *v,
            Self::Principal(PrincipalResponseFrame::Error { v, .. }) => *v,
        }
    }

    pub fn seq(&self) -> u64 {
        match self {
            Self::Admin(AdminResponseFrame::Ok { seq, .. }) => *seq,
            Self::Admin(AdminResponseFrame::Error { seq, .. }) => *seq,
            Self::Principal(PrincipalResponseFrame::Ok { seq, .. }) => *seq,
            Self::Principal(PrincipalResponseFrame::Error { seq, .. }) => *seq,
        }
    }

    pub fn role(&self) -> Role {
        match self {
            Self::Admin(_) => Role::Admin,
            Self::Principal(_) => Role::Principal,
        }
    }

    pub fn is_ok(&self) -> bool {
        matches!(
            self,
            Self::Admin(AdminResponseFrame::Ok { .. })
                | Self::Principal(PrincipalResponseFrame::Ok { .. }),
        )
    }
}

impl AdminRequestFrame {
    pub fn new(seq: u64, action: AdminRequest) -> Self {
        Self {
            v: CURRENT_VERSION,
            seq,
            action,
        }
    }
}

impl PrincipalRequestFrame {
    pub fn new(
        seq: u64,
        action: PrincipalRequest,
        capability_proof: PrincipalCapabilityProof,
    ) -> Self {
        Self {
            v: CURRENT_VERSION,
            seq,
            action,
            capability_proof,
        }
    }
}

impl AdminResponseFrame {
    pub fn ok(seq: u64, action: AdminResponse) -> Self {
        Self::Ok {
            v: CURRENT_VERSION,
            seq,
            action,
        }
    }

    pub fn error(seq: u64, error: ProtocolError) -> Self {
        Self::Error {
            v: CURRENT_VERSION,
            seq,
            error,
        }
    }
}

impl PrincipalResponseFrame {
    pub fn ok(seq: u64, action: PrincipalResponse) -> Self {
        Self::Ok {
            v: CURRENT_VERSION,
            seq,
            action: Box::new(action),
        }
    }

    pub fn error(seq: u64, error: ProtocolError) -> Self {
        Self::Error {
            v: CURRENT_VERSION,
            seq,
            error,
        }
    }
}

pub trait Validate {
    fn validate(&self) -> Result<(), ValidationErrors>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct ValidationErrors(pub Vec<String>);

impl ValidationErrors {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for ValidationErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "validation failed: {}", self.0.join("; "))
    }
}

impl std::error::Error for ValidationErrors {}

fn check_str(s: &str, field: &str, max_len: usize, errors: &mut Vec<String>) {
    if s.is_empty() {
        errors.push(format!("{}: must not be empty", field));
    } else if s.len() > max_len {
        errors.push(format!(
            "{}: exceeds maximum length {} (got {})",
            field,
            max_len,
            s.len(),
        ));
    }
    if s.contains('\0') {
        errors.push(format!("{}: must not contain null bytes", field));
    }
}

impl Validate for AdminRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();
        match self {
            Self::Ping | Self::Status | Self::Shutdown | Self::AuditStatus | Self::AuditVerify => {}
            Self::ListCredentials { rp_id } => {
                if let Some(id) = rp_id {
                    check_str(id, "rp_id", MAX_RP_ID_LEN, &mut errors);
                }
            }
            Self::DeleteCredential { .. } => {}
            Self::RenameCredential {
                user_name,
                display_name,
                ..
            } => {
                if user_name.is_none() && display_name.is_none() {
                    errors
                        .push("rename: at least one of user_name or display_name required".into());
                }
                if let Some(name) = user_name {
                    check_str(name, "user_name", MAX_USER_NAME_LEN, &mut errors);
                }
                if let Some(name) = display_name {
                    check_str(name, "display_name", MAX_DISPLAY_NAME_LEN, &mut errors);
                }
            }
            Self::ProfileStatus { .. }
            | Self::ReloadPolicy { .. }
            | Self::ListGrants { .. }
            | Self::ShowGrant { .. }
            | Self::RevokeGrant { .. }
            | Self::ListSessions { .. }
            | Self::ShowSession { .. }
            | Self::RevokeSession { .. }
            | Self::ListProfiles
            | Self::EnableProfile { .. }
            | Self::DisableProfile { .. }
            | Self::ShowCredential { .. }
            | Self::RevokeCredential { .. }
            | Self::ShowDelegation { .. }
            | Self::ListDelegations { .. }
            | Self::RevokeDelegation { .. } => {}
            Self::ShowProfile { .. } | Self::ShowPolicy { .. } | Self::ProfileCheck { .. } => {}
            Self::AuditExport { .. } => {}
            Self::LaunchBrowser { .. } => {}
            Self::LaunchPrincipal { command, .. } => {
                if command.is_empty() {
                    errors.push("launch_principal: command must not be empty".into());
                }
                if command.len() > MAX_ARGV_COUNT {
                    errors.push(format!(
                        "launch_principal: command exceeds maximum arg count {} (got {})",
                        MAX_ARGV_COUNT,
                        command.len()
                    ));
                }
                for (i, arg) in command.iter().enumerate() {
                    if arg.contains('\0') {
                        errors.push(format!(
                            "launch_principal: command[{}] must not contain null bytes",
                            i
                        ));
                    }
                    if arg.len() > MAX_ARGV_LEN {
                        errors.push(format!(
                            "launch_principal: command[{}] exceeds maximum length {} (got {})",
                            i,
                            MAX_ARGV_LEN,
                            arg.len()
                        ));
                    }
                }
            }
            Self::TerminatePrincipal { .. } => {}
            Self::RequestDelegation { rp_id, reason, .. } => {
                check_str(rp_id, "rp_id", MAX_RP_ID_LEN, &mut errors);
                if let Some(r) = reason {
                    check_str(r, "reason", MAX_REASON_LEN, &mut errors);
                }
            }
            Self::RequestRegistration { rp_id, reason, .. } => {
                check_str(rp_id, "rp_id", MAX_RP_ID_LEN, &mut errors);
                if let Some(r) = reason {
                    check_str(r, "reason", MAX_REASON_LEN, &mut errors);
                }
            }
            Self::WaitPrincipal { timeout_ms, .. } => {
                if *timeout_ms > 5000 {
                    errors.push(format!(
                        "wait_principal: timeout_ms must be <= 5000 (got {})",
                        timeout_ms
                    ));
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationErrors(errors))
        }
    }
}

impl Validate for PrincipalRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();
        match self {
            Self::Ping
            | Self::Status
            | Self::Capabilities
            | Self::Authority
            | Self::Instructions
            | Self::Doctor
            | Self::BrowserStatus
            | Self::EndpointStatus => {}
            Self::CreateIntent {
                profile_id,
                rp_id,
                reason,
                ..
            } => {
                check_str(
                    profile_id.as_str(),
                    "profile_id",
                    MAX_PROFILE_ID_LEN,
                    &mut errors,
                );
                check_str(rp_id, "rp_id", MAX_RP_ID_LEN, &mut errors);
                if let Some(r) = reason {
                    check_str(r, "reason", MAX_REASON_LEN, &mut errors);
                }
            }
            Self::ShowIntent { .. } | Self::WaitIntent { .. } | Self::CancelIntent { .. } => {}
            Self::RequestDelegation {
                profile_id,
                rp_id,
                reason,
                ..
            } => {
                check_str(
                    profile_id.as_str(),
                    "profile_id",
                    MAX_PROFILE_ID_LEN,
                    &mut errors,
                );
                check_str(rp_id, "rp_id", MAX_RP_ID_LEN, &mut errors);
                if let Some(r) = reason {
                    check_str(r, "reason", MAX_REASON_LEN, &mut errors);
                }
            }
            Self::ShowDelegation { .. }
            | Self::WaitDelegation { .. }
            | Self::CancelDelegation { .. } => {}
            Self::ListCredentials { .. } => {}
            Self::BrowserControl {
                request_json,
                timeout_ms,
            } => {
                if request_json.is_empty() {
                    errors.push("browser_control: request_json must not be empty".into());
                }
                if request_json.len() > MAX_CDP_REQUEST_LEN {
                    errors.push(format!(
                        "browser_control: request_json exceeds maximum length {} (got {})",
                        MAX_CDP_REQUEST_LEN,
                        request_json.len()
                    ));
                }
                if request_json.contains('\0') {
                    errors.push("browser_control: request_json must not contain null bytes".into());
                }
                if *timeout_ms == 0 || *timeout_ms > MAX_CDP_TIMEOUT_MS {
                    errors.push(format!(
                        "browser_control: timeout_ms must be between 1 and {}",
                        MAX_CDP_TIMEOUT_MS
                    ));
                }
            }
            Self::SignAssertion(req) => {
                check_str(&req.origin, "origin", MAX_ORIGIN_LEN, &mut errors);
                if let Some(ref top_origin) = req.top_origin {
                    check_str(top_origin, "top_origin", MAX_ORIGIN_LEN, &mut errors);
                }
                check_str(&req.rp_id, "rp_id", MAX_RP_ID_LEN, &mut errors);
                check_str(
                    &req.challenge_b64u,
                    "challenge_b64u",
                    MAX_B64U_LEN,
                    &mut errors,
                );
                if req.challenge_b64u.is_empty() {
                    errors.push("sign_assertion: challenge_b64u must not be empty".into());
                }
                if req.allow_credentials.len() > MAX_ALLOW_CREDENTIALS {
                    errors.push(format!(
                        "sign_assertion: allow_credentials exceeds maximum length {} (got {})",
                        MAX_ALLOW_CREDENTIALS,
                        req.allow_credentials.len()
                    ));
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationErrors(errors))
        }
    }
}

impl Validate for RegisterCredentialRequest {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();
        check_str(&self.origin, "origin", MAX_REG_ORIGIN_LEN, &mut errors);
        if let Some(ref top_origin) = self.top_origin {
            check_str(top_origin, "top_origin", MAX_REG_ORIGIN_LEN, &mut errors);
        }
        check_str(&self.rp_id, "rp_id", MAX_RP_ID_LEN, &mut errors);
        check_str(
            &self.challenge_b64u,
            "challenge_b64u",
            MAX_REG_CHALLENGE_B64U_LEN,
            &mut errors,
        );
        if self.challenge_b64u.is_empty() {
            errors.push("challenge_b64u: must not be empty".into());
        }
        check_str(
            &self.user_id_b64u,
            "user_id_b64u",
            MAX_REG_USER_ID_B64U_LEN,
            &mut errors,
        );
        if self.user_id_b64u.is_empty() {
            errors.push("user_id_b64u: must not be empty".into());
        }
        check_str(&self.user_name, "user_name", MAX_USER_NAME_LEN, &mut errors);
        if let Some(ref name) = self.user_display_name {
            check_str(name, "user_display_name", MAX_DISPLAY_NAME_LEN, &mut errors);
        }
        if let Some(ref name) = self.rp_name {
            check_str(name, "rp_name", MAX_DISPLAY_NAME_LEN, &mut errors);
        }
        if self.pub_key_cred_params.is_empty() {
            errors.push("pub_key_cred_params: must contain at least one algorithm".into());
        }
        if self.pub_key_cred_params.len() > 16 {
            errors.push("pub_key_cred_params: exceeds maximum count 16".into());
        }
        if self.exclude_credentials.len() > MAX_REG_EXCLUDE_CREDENTIALS {
            errors.push(format!(
                "exclude_credentials: exceeds maximum count {} (got {})",
                MAX_REG_EXCLUDE_CREDENTIALS,
                self.exclude_credentials.len()
            ));
        }
        for (i, cred) in self.exclude_credentials.iter().enumerate() {
            if cred.len() > MAX_REG_EXCLUDE_CREDENTIAL_ENTRY_LEN {
                errors.push(format!(
                    "exclude_credentials[{}]: exceeds maximum length {} (got {})",
                    i,
                    MAX_REG_EXCLUDE_CREDENTIAL_ENTRY_LEN,
                    cred.len()
                ));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationErrors(errors))
        }
    }
}

impl Validate for RequestFrame {
    fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();

        if let Err(e) = ProtocolVersion::negotiate(self.version()) {
            errors.push(e.message);
        }

        let action_result = match self {
            Self::Admin(f) => f.action.validate(),
            Self::Principal(f) => f.action.validate(),
        };
        if let Err(ve) = action_result {
            errors.extend(ve.0);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationErrors(errors))
        }
    }
}

#[derive(Debug)]
pub enum CodecError {
    Serialize(String),
    Deserialize(String),
    Oversized { size: usize, max: usize },
    Truncated,
    Io(std::io::Error),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialize(e) => write!(f, "serialization error: {}", e),
            Self::Deserialize(e) => write!(f, "deserialization error: {}", e),
            Self::Oversized { size, max } => {
                write!(f, "message too large: {} bytes (max {})", size, max)
            }
            Self::Truncated => write!(f, "message truncated (exceeds buffer)"),
            Self::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for CodecError {}

impl From<serde_json::Error> for CodecError {
    fn from(e: serde_json::Error) -> Self {
        Self::Deserialize(e.to_string())
    }
}

impl From<std::io::Error> for CodecError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[cfg(target_os = "linux")]
pub struct SeqpacketCodec;

#[cfg(target_os = "linux")]
impl SeqpacketCodec {
    pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, CodecError> {
        let bytes = serde_json::to_vec(msg).map_err(|e| CodecError::Serialize(e.to_string()))?;
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(CodecError::Oversized {
                size: bytes.len(),
                max: MAX_MESSAGE_SIZE,
            });
        }
        Ok(bytes)
    }

    pub fn decode<T: serde::de::DeserializeOwned>(buf: &[u8]) -> Result<T, CodecError> {
        if buf.len() > MAX_MESSAGE_SIZE {
            return Err(CodecError::Oversized {
                size: buf.len(),
                max: MAX_MESSAGE_SIZE,
            });
        }
        serde_json::from_slice(buf).map_err(|e| CodecError::Deserialize(e.to_string()))
    }

    pub fn send_msg<T: Serialize>(fd: RawFd, msg: &T) -> Result<usize, CodecError> {
        let bytes = Self::encode(msg)?;
        let n = unsafe { libc::send(fd, bytes.as_ptr() as *const libc::c_void, bytes.len(), 0) };
        if n < 0 {
            return Err(CodecError::Io(std::io::Error::last_os_error()));
        }
        Ok(n as usize)
    }

    pub fn recv_msg<T: serde::de::DeserializeOwned>(fd: RawFd) -> Result<T, CodecError> {
        let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: MAX_MESSAGE_SIZE,
        };
        let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
        hdr.msg_iov = &mut iov;
        hdr.msg_iovlen = 1;

        let n = unsafe { libc::recvmsg(fd, &mut hdr, 0) };
        if n < 0 {
            return Err(CodecError::Io(std::io::Error::last_os_error()));
        }
        if hdr.msg_flags & libc::MSG_TRUNC != 0 {
            return Err(CodecError::Truncated);
        }
        Self::decode(&buf[..n as usize])
    }

    pub fn send_msg_with_fds<T: Serialize>(
        fd: RawFd,
        msg: &T,
        fds: &[RawFd],
    ) -> Result<usize, CodecError> {
        let bytes = Self::encode(msg)?;

        let mut iov = libc::iovec {
            iov_base: bytes.as_ptr() as *mut libc::c_void,
            iov_len: bytes.len(),
        };

        let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
        hdr.msg_iov = &mut iov;
        hdr.msg_iovlen = 1;

        let mut cmsg_buf: Vec<u8> = Vec::new();
        if !fds.is_empty() {
            let fds_len = std::mem::size_of_val(fds);
            let cmsg_space = unsafe { libc::CMSG_SPACE(fds_len as libc::c_uint) } as usize;
            cmsg_buf.resize(cmsg_space, 0);

            hdr.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
            hdr.msg_controllen = cmsg_space;

            let cmsg = unsafe { libc::CMSG_FIRSTHDR(&hdr) };
            if cmsg.is_null() {
                return Err(CodecError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "CMSG_FIRSTHDR returned null",
                )));
            }

            unsafe {
                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = libc::SCM_RIGHTS;
                (*cmsg).cmsg_len = libc::CMSG_LEN(fds_len as libc::c_uint) as usize;
                let data_ptr = libc::CMSG_DATA(cmsg);
                std::ptr::copy_nonoverlapping(fds.as_ptr() as *const u8, data_ptr, fds_len);
            }
        }

        let n = unsafe { libc::sendmsg(fd, &hdr, 0) };
        if n < 0 {
            return Err(CodecError::Io(std::io::Error::last_os_error()));
        }
        Ok(n as usize)
    }

    pub fn recv_msg_with_fds<T: serde::de::DeserializeOwned>(
        fd: RawFd,
        max_fds: usize,
    ) -> Result<(T, Vec<RawFd>), CodecError> {
        let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: MAX_MESSAGE_SIZE,
        };

        let fds_len = std::mem::size_of::<RawFd>() * max_fds;
        let cmsg_space = unsafe { libc::CMSG_SPACE(fds_len as libc::c_uint) } as usize;
        let mut cmsg_buf = vec![0u8; cmsg_space];

        let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
        hdr.msg_iov = &mut iov;
        hdr.msg_iovlen = 1;
        hdr.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        hdr.msg_controllen = cmsg_space;

        let n = unsafe { libc::recvmsg(fd, &mut hdr, libc::MSG_CMSG_CLOEXEC) };
        if n < 0 {
            return Err(CodecError::Io(std::io::Error::last_os_error()));
        }
        if hdr.msg_flags & libc::MSG_TRUNC != 0 {
            return Err(CodecError::Truncated);
        }
        if hdr.msg_flags & libc::MSG_CTRUNC != 0 {
            return Err(CodecError::Truncated);
        }

        let mut received_fds = Vec::new();
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&hdr) };
        while !cmsg.is_null() {
            let cmsg_ref = unsafe { &*cmsg };
            let cmsg_len_zero = unsafe { libc::CMSG_LEN(0) } as usize;
            if (cmsg_ref.cmsg_len as usize) < cmsg_len_zero {
                for &fd in &received_fds {
                    unsafe { libc::close(fd) };
                }
                return Err(CodecError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "cmsg_len < CMSG_LEN(0)",
                )));
            }
            if cmsg_ref.cmsg_level == libc::SOL_SOCKET && cmsg_ref.cmsg_type == libc::SCM_RIGHTS {
                let data_ptr = unsafe { libc::CMSG_DATA(cmsg) };
                let data_len = cmsg_ref.cmsg_len as usize - cmsg_len_zero;
                let fd_size = std::mem::size_of::<RawFd>();
                if !data_len.is_multiple_of(fd_size) {
                    for &fd in &received_fds {
                        unsafe { libc::close(fd) };
                    }
                    return Err(CodecError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "non-integral fd payload in SCM_RIGHTS",
                    )));
                }
                let fd_count = data_len / fd_size;
                if received_fds.len() + fd_count > max_fds {
                    for &fd in &received_fds {
                        unsafe { libc::close(fd) };
                    }
                    for i in 0..fd_count {
                        let excess_fd = unsafe {
                            std::ptr::read_unaligned(data_ptr.add(i * fd_size) as *const RawFd)
                        };
                        unsafe { libc::close(excess_fd) };
                    }
                    return Err(CodecError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "fd_count {} exceeds max_fds {}",
                            received_fds.len() + fd_count,
                            max_fds
                        ),
                    )));
                }
                for i in 0..fd_count {
                    let received_fd = unsafe {
                        std::ptr::read_unaligned(data_ptr.add(i * fd_size) as *const RawFd)
                    };
                    received_fds.push(received_fd);
                }
            }
            cmsg = unsafe { libc::CMSG_NXTHDR(&hdr, cmsg) };
        }

        match Self::decode(&buf[..n as usize]) {
            Ok(msg) => Ok((msg, received_fds)),
            Err(e) => {
                for &fd in &received_fds {
                    unsafe { libc::close(fd) };
                }
                Err(e)
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerCred {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

#[cfg(target_os = "linux")]
impl PeerCred {
    pub fn from_fd(fd: RawFd) -> std::io::Result<Self> {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut libc::ucred as *mut libc::c_void,
                &mut len,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(PeerCred {
            pid: cred.pid,
            uid: cred.uid,
            gid: cred.gid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cred_ref(seed: &str) -> CredentialRef {
        CredentialRef::with_default_domain(seed.as_bytes())
    }

    fn test_capability_proof() -> PrincipalCapabilityProof {
        PrincipalCapabilityProof::from_bytes([0x42u8; CAPABILITY_PROOF_BYTES])
    }

    fn json_roundtrip<T>(val: &T) -> T
    where
        T: Serialize + serde::de::DeserializeOwned + PartialEq + fmt::Debug,
    {
        let json = serde_json::to_string(val).unwrap();
        serde_json::from_str::<T>(&json).unwrap()
    }

    fn json_bytes_roundtrip<T>(val: &T) -> T
    where
        T: Serialize + serde::de::DeserializeOwned + PartialEq + fmt::Debug,
    {
        let bytes = serde_json::to_vec(val).unwrap();
        serde_json::from_slice::<T>(&bytes).unwrap()
    }

    #[test]
    fn version_current_is_1_1() {
        assert_eq!(CURRENT_VERSION.major, 1);
        assert_eq!(CURRENT_VERSION.minor, 1);
    }

    #[test]
    fn version_negotiate_exact() {
        let negotiated = ProtocolVersion::negotiate(CURRENT_VERSION).unwrap();
        assert_eq!(negotiated, CURRENT_VERSION);
    }

    #[test]
    fn version_negotiate_lower_minor() {
        let offer = ProtocolVersion::new(1, 0);
        let negotiated = ProtocolVersion::negotiate(offer).unwrap();
        assert_eq!(negotiated, ProtocolVersion::new(1, 0));
    }

    #[test]
    fn version_negotiate_higher_minor_clamped() {
        let offer = ProtocolVersion::new(1, 5);
        let negotiated = ProtocolVersion::negotiate(offer).unwrap();
        assert_eq!(negotiated, ProtocolVersion::new(1, 1));
    }

    #[test]
    fn version_negotiate_rejects_incompatible_major() {
        let offer = ProtocolVersion::new(2, 0);
        let err = ProtocolVersion::negotiate(offer).unwrap_err();
        assert_eq!(err.code, ErrorCode::VersionMismatch);
        assert_eq!(err.recommended_action, RecommendedAction::UpgradeClient);
    }

    #[test]
    fn version_negotiate_rejects_zero_major() {
        let offer = ProtocolVersion::new(0, 1);
        let err = ProtocolVersion::negotiate(offer).unwrap_err();
        assert_eq!(err.code, ErrorCode::VersionMismatch);
    }

    #[test]
    fn version_display() {
        assert_eq!(CURRENT_VERSION.to_string(), "1.1");
        assert_eq!(ProtocolVersion::new(2, 3).to_string(), "2.3");
    }

    #[test]
    fn version_serde_roundtrip() {
        let v = ProtocolVersion::new(1, 2);
        assert_eq!(json_roundtrip(&v), v);
    }

    #[test]
    fn version_rejects_unknown_fields() {
        let json = r#"{"major":1,"minor":0,"extra":"bad"}"#;
        assert!(serde_json::from_str::<ProtocolVersion>(json).is_err());
    }

    #[test]
    fn version_ordering() {
        assert!(ProtocolVersion::new(1, 0) < ProtocolVersion::new(1, 1));
        assert!(ProtocolVersion::new(1, 1) < ProtocolVersion::new(2, 0));
    }

    #[test]
    fn version_default_is_current() {
        assert_eq!(ProtocolVersion::default(), CURRENT_VERSION);
    }

    #[test]
    fn error_code_serde_roundtrip() {
        for code in [
            ErrorCode::BadRequest,
            ErrorCode::Unauthorized,
            ErrorCode::Forbidden,
            ErrorCode::NotFound,
            ErrorCode::Conflict,
            ErrorCode::InteractionRequired,
            ErrorCode::Internal,
            ErrorCode::VersionMismatch,
            ErrorCode::MessageTooLarge,
            ErrorCode::MalformedMessage,
        ] {
            assert_eq!(json_roundtrip(&code), code);
        }
    }

    #[test]
    fn recommended_action_serde_roundtrip() {
        for action in [
            RecommendedAction::None,
            RecommendedAction::Retry,
            RecommendedAction::RetryWithBackoff,
            RecommendedAction::FixRequest,
            RecommendedAction::UpgradeClient,
            RecommendedAction::Abort,
        ] {
            assert_eq!(json_roundtrip(&action), action);
        }
    }

    #[test]
    fn protocol_error_serde_roundtrip() {
        let err = ProtocolError::new(
            ErrorCode::NotFound,
            "credential not found",
            RecommendedAction::FixRequest,
        );
        assert_eq!(json_roundtrip(&err), err);
    }

    #[test]
    fn protocol_error_constructors() {
        let e = ProtocolError::malformed("bad json");
        assert_eq!(e.code, ErrorCode::MalformedMessage);
        assert_eq!(e.recommended_action, RecommendedAction::FixRequest);

        let e = ProtocolError::oversized(20_000, MAX_MESSAGE_SIZE);
        assert_eq!(e.code, ErrorCode::MessageTooLarge);

        let e = ProtocolError::version_mismatch(&ProtocolVersion::new(2, 0));
        assert_eq!(e.code, ErrorCode::VersionMismatch);
    }

    #[test]
    fn protocol_error_display() {
        let e = ProtocolError::new(ErrorCode::NotFound, "gone", RecommendedAction::Abort);
        assert_eq!(e.to_string(), "[not_found] gone");
    }

    #[test]
    fn admin_ping_request_roundtrip() {
        let frame = RequestFrame::Admin(AdminRequestFrame::new(1, AdminRequest::Ping));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn admin_status_request_roundtrip() {
        let frame = RequestFrame::Admin(AdminRequestFrame::new(2, AdminRequest::Status));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn admin_list_credentials_no_filter_roundtrip() {
        let frame = RequestFrame::Admin(AdminRequestFrame::new(
            3,
            AdminRequest::ListCredentials { rp_id: None },
        ));
        let json = serde_json::to_string(&frame).unwrap();
        assert!(!json.contains("rp_id"));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn admin_list_credentials_with_filter_roundtrip() {
        let frame = RequestFrame::Admin(AdminRequestFrame::new(
            4,
            AdminRequest::ListCredentials {
                rp_id: Some("example.com".into()),
            },
        ));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn admin_delete_credential_uses_ref() {
        let frame = RequestFrame::Admin(AdminRequestFrame::new(
            5,
            AdminRequest::DeleteCredential {
                credential_ref: test_cred_ref("abcdef01"),
            },
        ));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn admin_rename_credential_uses_ref() {
        let frame = RequestFrame::Admin(AdminRequestFrame::new(
            6,
            AdminRequest::RenameCredential {
                credential_ref: test_cred_ref("deadbeef"),
                user_name: Some("alice".into()),
                display_name: None,
            },
        ));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn admin_shutdown_roundtrip() {
        let frame = RequestFrame::Admin(AdminRequestFrame::new(7, AdminRequest::Shutdown));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn admin_pong_response_roundtrip() {
        let frame = ResponseFrame::Admin(AdminResponseFrame::ok(1, AdminResponse::Pong));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn admin_status_response_roundtrip() {
        let status = DaemonStatus {
            daemon_version: "0.13.0".into(),
            protocol_version: CURRENT_VERSION,
            backend: "local".into(),
            uptime_secs: 3600,
            credential_count: 42,
        };
        let frame = ResponseFrame::Admin(AdminResponseFrame::ok(2, AdminResponse::Status(status)));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn admin_credential_list_response_uses_ref() {
        let list = CredentialList {
            credentials: vec![CredentialSummary {
                credential_ref: test_cred_ref("abcdef01"),
                rp_id: "example.com".into(),
                user_name: "alice".into(),
                display_name: "Alice".into(),
                created_at: Some(1700000000),
            }],
            total: 1,
        };
        let frame = ResponseFrame::Admin(AdminResponseFrame::ok(
            3,
            AdminResponse::CredentialList(list),
        ));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn admin_deleted_response_roundtrip() {
        let frame = ResponseFrame::Admin(AdminResponseFrame::ok(4, AdminResponse::Deleted));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn admin_renamed_response_roundtrip() {
        let frame = ResponseFrame::Admin(AdminResponseFrame::ok(5, AdminResponse::Renamed));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn admin_error_response_roundtrip() {
        let err = ProtocolError::new(
            ErrorCode::NotFound,
            "credential not found",
            RecommendedAction::FixRequest,
        );
        let frame = ResponseFrame::Admin(AdminResponseFrame::error(6, err));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn principal_ping_request_roundtrip() {
        let frame = RequestFrame::Principal(PrincipalRequestFrame::new(
            1,
            PrincipalRequest::Ping,
            test_capability_proof(),
        ));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn principal_status_request_roundtrip() {
        let frame = RequestFrame::Principal(PrincipalRequestFrame::new(
            2,
            PrincipalRequest::Status,
            test_capability_proof(),
        ));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn principal_capabilities_request_roundtrip() {
        let frame = RequestFrame::Principal(PrincipalRequestFrame::new(
            3,
            PrincipalRequest::Capabilities,
            test_capability_proof(),
        ));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn principal_authority_request_roundtrip() {
        let frame = RequestFrame::Principal(PrincipalRequestFrame::new(
            4,
            PrincipalRequest::Authority,
            test_capability_proof(),
        ));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn principal_create_intent_roundtrip() {
        let frame = RequestFrame::Principal(PrincipalRequestFrame::new(
            4,
            PrincipalRequest::CreateIntent {
                profile_id: ProfileId::new("test").unwrap(),
                action: IntentAction::Authenticate,
                rp_id: "example.com".into(),
                credential_ref: Some(test_cred_ref("abcdef01")),
                reason: Some("login".into()),
                grant_ttl_secs: None,
                session_ttl_secs: None,
            },
            test_capability_proof(),
        ));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn principal_request_delegation_roundtrip() {
        let frame = RequestFrame::Principal(PrincipalRequestFrame::new(
            5,
            PrincipalRequest::RequestDelegation {
                profile_id: ProfileId::new("test").unwrap(),
                rp_id: "example.com".into(),
                credential_ref: test_cred_ref("abcdef01"),
                max_session_ttl: 900,
                reason: None,
            },
            test_capability_proof(),
        ));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn principal_cancel_intent_roundtrip() {
        let req_id = PendingRequestId::new();
        let frame = RequestFrame::Principal(PrincipalRequestFrame::new(
            6,
            PrincipalRequest::CancelIntent { request_id: req_id },
            test_capability_proof(),
        ));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn principal_pong_response_roundtrip() {
        let frame =
            ResponseFrame::Principal(PrincipalResponseFrame::ok(1, PrincipalResponse::Pong));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn principal_capabilities_response_roundtrip() {
        let caps = PrincipalCapabilities {
            profile_id: "test".into(),
            mode: "isolated".into(),
            allowed_rp_ids: vec!["example.com".into()],
            registration_allowed: true,
        };
        let frame = ResponseFrame::Principal(PrincipalResponseFrame::ok(
            2,
            PrincipalResponse::Capabilities(caps),
        ));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn principal_error_response_roundtrip() {
        let err = ProtocolError::new(
            ErrorCode::Unauthorized,
            "not allowed",
            RecommendedAction::Abort,
        );
        let frame = ResponseFrame::Principal(PrincipalResponseFrame::error(3, err));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn bytes_roundtrip_request() {
        let frame = RequestFrame::Admin(AdminRequestFrame::new(1, AdminRequest::Ping));
        assert_eq!(json_bytes_roundtrip(&frame), frame);
    }

    #[test]
    fn bytes_roundtrip_response() {
        let frame = ResponseFrame::Admin(AdminResponseFrame::ok(1, AdminResponse::Pong));
        assert_eq!(json_bytes_roundtrip(&frame), frame);
    }

    #[test]
    fn request_json_has_role_tag() {
        let frame = RequestFrame::Admin(AdminRequestFrame::new(1, AdminRequest::Ping));
        let json = serde_json::to_string(&frame).unwrap();
        assert!(json.contains(r#""role":"admin""#));
    }

    #[test]
    fn response_json_has_role_and_status_tags() {
        let frame = ResponseFrame::Admin(AdminResponseFrame::ok(1, AdminResponse::Pong));
        let json = serde_json::to_string(&frame).unwrap();
        assert!(json.contains(r#""role":"admin""#));
        assert!(json.contains(r#""status":"ok""#));
    }

    #[test]
    fn error_response_json_has_status_error() {
        let err = ProtocolError::new(ErrorCode::Internal, "oops", RecommendedAction::Retry);
        let frame = ResponseFrame::Admin(AdminResponseFrame::error(1, err));
        let json = serde_json::to_string(&frame).unwrap();
        assert!(json.contains(r#""status":"error""#));
    }

    #[test]
    fn request_frame_accessors() {
        let frame = RequestFrame::Admin(AdminRequestFrame::new(42, AdminRequest::Status));
        assert_eq!(frame.version(), CURRENT_VERSION);
        assert_eq!(frame.seq(), 42);
        assert_eq!(frame.role(), Role::Admin);
    }

    #[test]
    fn response_frame_accessors() {
        let frame =
            ResponseFrame::Principal(PrincipalResponseFrame::ok(7, PrincipalResponse::Pong));
        assert_eq!(frame.version(), CURRENT_VERSION);
        assert_eq!(frame.seq(), 7);
        assert_eq!(frame.role(), Role::Principal);
        assert!(frame.is_ok());
    }

    #[test]
    fn error_response_is_not_ok() {
        let err = ProtocolError::new(ErrorCode::Internal, "fail", RecommendedAction::Abort);
        let frame = ResponseFrame::Admin(AdminResponseFrame::error(1, err));
        assert!(!frame.is_ok());
    }

    #[test]
    fn validate_admin_ping_ok() {
        assert!(AdminRequest::Ping.validate().is_ok());
    }

    #[test]
    fn validate_admin_status_ok() {
        assert!(AdminRequest::Status.validate().is_ok());
    }

    #[test]
    fn validate_admin_shutdown_ok() {
        assert!(AdminRequest::Shutdown.validate().is_ok());
    }

    #[test]
    fn validate_delete_credential_valid_ref() {
        let req = AdminRequest::DeleteCredential {
            credential_ref: test_cred_ref("valid"),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn validate_delete_credential_rejects_invalid_hex_serde() {
        let json = r#"{"delete_credential":{"credential_ref":"xyz!"}}"#;
        assert!(serde_json::from_str::<AdminRequest>(json).is_err());
    }

    #[test]
    fn validate_delete_credential_rejects_short_hex_serde() {
        let json = r#"{"delete_credential":{"credential_ref":"abc"}}"#;
        assert!(serde_json::from_str::<AdminRequest>(json).is_err());
    }

    #[test]
    fn validate_rename_with_user_name_only() {
        let req = AdminRequest::RenameCredential {
            credential_ref: test_cred_ref("a"),
            user_name: Some("alice".into()),
            display_name: None,
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn validate_rename_with_display_name_only() {
        let req = AdminRequest::RenameCredential {
            credential_ref: test_cred_ref("b"),
            user_name: None,
            display_name: Some("Alice".into()),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn validate_rename_with_both_names() {
        let req = AdminRequest::RenameCredential {
            credential_ref: test_cred_ref("c"),
            user_name: Some("alice".into()),
            display_name: Some("Alice".into()),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn validate_rename_no_fields_rejected() {
        let req = AdminRequest::RenameCredential {
            credential_ref: test_cred_ref("d"),
            user_name: None,
            display_name: None,
        };
        let errs = req.validate().unwrap_err();
        assert!(errs.0.iter().any(|e| e.contains("at least one")));
    }

    #[test]
    fn validate_rename_empty_user_name() {
        let req = AdminRequest::RenameCredential {
            credential_ref: test_cred_ref("e"),
            user_name: Some(String::new()),
            display_name: None,
        };
        let errs = req.validate().unwrap_err();
        assert!(errs.0.iter().any(|e| e.contains("user_name")));
    }

    #[test]
    fn validate_string_with_null_bytes() {
        let req = AdminRequest::RenameCredential {
            credential_ref: test_cred_ref("f"),
            user_name: Some("alice\0bob".into()),
            display_name: None,
        };
        let errs = req.validate().unwrap_err();
        assert!(errs.0.iter().any(|e| e.contains("null")));
    }

    #[test]
    fn validate_oversized_string() {
        let req = AdminRequest::RenameCredential {
            credential_ref: test_cred_ref("g"),
            user_name: Some("x".repeat(MAX_USER_NAME_LEN + 1)),
            display_name: None,
        };
        let errs = req.validate().unwrap_err();
        assert!(errs.0.iter().any(|e| e.contains("maximum length")));
    }

    #[test]
    fn validate_list_credentials_valid_rp_id() {
        let req = AdminRequest::ListCredentials {
            rp_id: Some("example.com".into()),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn validate_list_credentials_empty_rp_id() {
        let req = AdminRequest::ListCredentials {
            rp_id: Some(String::new()),
        };
        let errs = req.validate().unwrap_err();
        assert!(errs.0.iter().any(|e| e.contains("rp_id")));
    }

    #[test]
    fn validate_list_credentials_oversized_rp_id() {
        let req = AdminRequest::ListCredentials {
            rp_id: Some("x".repeat(MAX_RP_ID_LEN + 1)),
        };
        let errs = req.validate().unwrap_err();
        assert!(errs.0.iter().any(|e| e.contains("rp_id")));
    }

    #[test]
    fn validate_principal_ping_ok() {
        assert!(PrincipalRequest::Ping.validate().is_ok());
    }

    #[test]
    fn validate_principal_create_intent_ok() {
        let req = PrincipalRequest::CreateIntent {
            profile_id: ProfileId::new("test").unwrap(),
            action: IntentAction::Authenticate,
            rp_id: "example.com".into(),
            credential_ref: Some(test_cred_ref("abcdef01")),
            reason: None,
            grant_ttl_secs: None,
            session_ttl_secs: None,
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn validate_principal_create_intent_empty_profile() {
        let req = PrincipalRequest::CreateIntent {
            profile_id: ProfileId::from_string_unchecked(String::new()),
            action: IntentAction::Authenticate,
            rp_id: "example.com".into(),
            credential_ref: None,
            reason: None,
            grant_ttl_secs: None,
            session_ttl_secs: None,
        };
        let errs = req.validate().unwrap_err();
        assert!(errs.0.iter().any(|e| e.contains("profile_id")));
    }

    #[test]
    fn validate_principal_request_delegation_ok() {
        let req = PrincipalRequest::RequestDelegation {
            profile_id: ProfileId::new("test").unwrap(),
            rp_id: "example.com".into(),
            credential_ref: test_cred_ref("abcdef01"),
            max_session_ttl: 900,
            reason: None,
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn validate_principal_request_delegation_rejects_invalid_ref_serde() {
        let json = r#"{"request_delegation":{"profile_id":"test","rp_id":"example.com","credential_ref":"","max_session_ttl":900}}"#;
        assert!(serde_json::from_str::<PrincipalRequest>(json).is_err());
    }

    #[test]
    fn validate_request_frame_version_check() {
        let frame = RequestFrame::Admin(AdminRequestFrame {
            v: ProtocolVersion::new(2, 0),
            seq: 1,
            action: AdminRequest::Ping,
        });
        let errs = frame.validate().unwrap_err();
        assert!(errs.0.iter().any(|e| e.contains("incompatible")));
    }

    #[test]
    fn validate_request_frame_propagates_action_errors() {
        let frame = RequestFrame::Admin(AdminRequestFrame {
            v: CURRENT_VERSION,
            seq: 1,
            action: AdminRequest::RenameCredential {
                credential_ref: test_cred_ref("x"),
                user_name: None,
                display_name: None,
            },
        });
        let errs = frame.validate().unwrap_err();
        assert!(errs.0.iter().any(|e| e.contains("at least one")));
    }

    #[test]
    fn validate_request_frame_ok() {
        let frame = RequestFrame::Admin(AdminRequestFrame::new(1, AdminRequest::Ping));
        assert!(frame.validate().is_ok());
    }

    #[test]
    fn reject_unknown_field_in_admin_request() {
        let json =
            r#"{"role":"admin","v":{"major":1,"minor":0},"seq":1,"action":"ping","extra":"bad"}"#;
        assert!(serde_json::from_str::<RequestFrame>(json).is_err());
    }

    #[test]
    fn reject_unknown_role() {
        let json = r#"{"role":"superadmin","v":{"major":1,"minor":0},"seq":1,"action":"ping"}"#;
        assert!(serde_json::from_str::<RequestFrame>(json).is_err());
    }

    #[test]
    fn reject_unknown_admin_action() {
        let json = r#"{"role":"admin","v":{"major":1,"minor":0},"seq":1,"action":"nuke"}"#;
        assert!(serde_json::from_str::<RequestFrame>(json).is_err());
    }

    #[test]
    fn reject_unknown_field_in_protocol_version() {
        let json =
            r#"{"role":"admin","v":{"major":1,"minor":0,"patch":1},"seq":1,"action":"ping"}"#;
        assert!(serde_json::from_str::<RequestFrame>(json).is_err());
    }

    #[test]
    fn reject_unknown_field_in_protocol_error() {
        let json = r#"{"code":"internal","message":"oops","recommended_action":"retry","extra":1}"#;
        assert!(serde_json::from_str::<ProtocolError>(json).is_err());
    }

    #[test]
    fn reject_malformed_json() {
        let json = r#"{"role":"admin","v":{"major":1,"#;
        assert!(serde_json::from_str::<RequestFrame>(json).is_err());
    }

    #[test]
    fn reject_empty_input() {
        assert!(serde_json::from_str::<RequestFrame>("").is_err());
        assert!(serde_json::from_str::<ResponseFrame>("").is_err());
    }

    #[test]
    fn reject_missing_required_field() {
        let json = r#"{"role":"admin","seq":1,"action":"ping"}"#;
        assert!(serde_json::from_str::<RequestFrame>(json).is_err());
    }

    #[test]
    fn reject_wrong_type_for_field() {
        let json = r#"{"role":"admin","v":"not_an_object","seq":1,"action":"ping"}"#;
        assert!(serde_json::from_str::<RequestFrame>(json).is_err());
    }

    #[test]
    fn codec_encode_decode_roundtrip() {
        let frame = RequestFrame::Admin(AdminRequestFrame::new(1, AdminRequest::Ping));
        let bytes = SeqpacketCodec::encode(&frame).unwrap();
        let decoded: RequestFrame = SeqpacketCodec::decode(&bytes).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn codec_encode_response_roundtrip() {
        let frame = ResponseFrame::Admin(AdminResponseFrame::ok(1, AdminResponse::Pong));
        let bytes = SeqpacketCodec::encode(&frame).unwrap();
        let decoded: ResponseFrame = SeqpacketCodec::decode(&bytes).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn codec_reject_oversized_encode() {
        let big = AdminRequest::ListCredentials {
            rp_id: Some("x".repeat(MAX_MESSAGE_SIZE)),
        };
        let frame = RequestFrame::Admin(AdminRequestFrame::new(1, big));
        let err = SeqpacketCodec::encode(&frame).unwrap_err();
        assert!(matches!(err, CodecError::Oversized { .. }));
    }

    #[test]
    fn codec_reject_oversized_decode() {
        let big_buf = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let err = SeqpacketCodec::decode::<RequestFrame>(&big_buf).unwrap_err();
        assert!(matches!(err, CodecError::Oversized { .. }));
    }

    #[test]
    fn codec_reject_malformed_decode() {
        let bad = b"not json at all";
        let err = SeqpacketCodec::decode::<RequestFrame>(bad).unwrap_err();
        assert!(matches!(err, CodecError::Deserialize(_)));
    }

    #[test]
    fn codec_empty_buffer_rejected() {
        let err = SeqpacketCodec::decode::<RequestFrame>(b"").unwrap_err();
        assert!(matches!(err, CodecError::Deserialize(_)));
    }

    #[test]
    fn max_message_size_is_bounded() {
        assert_eq!(MAX_MESSAGE_SIZE, 16_384);
        const { assert!(MAX_MESSAGE_SIZE > 0) };
        const { assert!(MAX_MESSAGE_SIZE <= 65_536) };
    }

    #[test]
    fn peer_cred_construction() {
        let cred = PeerCred {
            pid: 1234,
            uid: 1000,
            gid: 1000,
        };
        assert_eq!(cred.pid, 1234);
        assert_eq!(cred.uid, 1000);
        assert_eq!(cred.gid, 1000);
    }

    #[test]
    fn peer_cred_equality() {
        let a = PeerCred {
            pid: 1,
            uid: 2,
            gid: 3,
        };
        let b = PeerCred {
            pid: 1,
            uid: 2,
            gid: 3,
        };
        let c = PeerCred {
            pid: 99,
            uid: 2,
            gid: 3,
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn peer_cred_clone_and_debug() {
        let cred = PeerCred {
            pid: 42,
            uid: 0,
            gid: 0,
        };
        let cloned = cred;
        assert_eq!(cloned, cred);
        let debug = format!("{:?}", cred);
        assert!(debug.contains("42"));
    }

    #[test]
    fn daemon_status_serde_roundtrip() {
        let status = DaemonStatus {
            daemon_version: "0.13.0".into(),
            protocol_version: CURRENT_VERSION,
            backend: "pass".into(),
            uptime_secs: 7200,
            credential_count: 100,
        };
        assert_eq!(json_roundtrip(&status), status);
    }

    #[test]
    fn credential_summary_without_created_at() {
        let summary = CredentialSummary {
            credential_ref: test_cred_ref("aa"),
            rp_id: "example.com".into(),
            user_name: "alice".into(),
            display_name: "Alice".into(),
            created_at: None,
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(!json.contains("created_at"));
        assert_eq!(json_roundtrip(&summary), summary);
    }

    #[test]
    fn credential_summary_with_created_at() {
        let summary = CredentialSummary {
            credential_ref: test_cred_ref("bb"),
            rp_id: "test.org".into(),
            user_name: "bob".into(),
            display_name: "Bob".into(),
            created_at: Some(1700000000),
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("created_at"));
        assert_eq!(json_roundtrip(&summary), summary);
    }

    #[test]
    fn credential_list_empty() {
        let list = CredentialList {
            credentials: vec![],
            total: 0,
        };
        assert_eq!(json_roundtrip(&list), list);
    }

    #[test]
    fn credential_list_multiple() {
        let list = CredentialList {
            credentials: vec![
                CredentialSummary {
                    credential_ref: test_cred_ref("aa"),
                    rp_id: "a.com".into(),
                    user_name: "u1".into(),
                    display_name: "U1".into(),
                    created_at: None,
                },
                CredentialSummary {
                    credential_ref: test_cred_ref("bb"),
                    rp_id: "b.com".into(),
                    user_name: "u2".into(),
                    display_name: "U2".into(),
                    created_at: Some(100),
                },
            ],
            total: 2,
        };
        assert_eq!(json_roundtrip(&list), list);
    }

    #[test]
    fn data_types_reject_unknown_fields() {
        let json = r#"{"daemon_version":"1","protocol_version":{"major":1,"minor":0},"backend":"local","uptime_secs":0,"credential_count":0,"extra":true}"#;
        assert!(serde_json::from_str::<DaemonStatus>(json).is_err());

        let json =
            r#"{"credential_ref":"aa","rp_id":"x","user_name":"u","display_name":"d","extra":1}"#;
        assert!(serde_json::from_str::<CredentialSummary>(json).is_err());

        let json = r#"{"credentials":[],"total":0,"extra":1}"#;
        assert!(serde_json::from_str::<CredentialList>(json).is_err());
    }

    #[test]
    fn validation_errors_display() {
        let errs = ValidationErrors(vec!["field1: bad".into(), "field2: worse".into()]);
        let s = errs.to_string();
        assert!(s.contains("field1: bad"));
        assert!(s.contains("field2: worse"));
    }

    #[test]
    fn validation_errors_is_empty() {
        assert!(ValidationErrors(vec![]).is_empty());
        assert!(!ValidationErrors(vec!["err".into()]).is_empty());
    }

    #[test]
    fn admin_frame_rejects_principal_action() {
        let json = r#"{"role":"admin","v":{"major":1,"minor":0},"seq":1,"action":{"create_intent":{"profile_id":"t","action":"authenticate","rp_id":"x"}}}"#;
        assert!(serde_json::from_str::<RequestFrame>(json).is_err());
    }

    #[test]
    fn principal_frame_rejects_admin_action() {
        let json = r#"{"role":"principal","v":{"major":1,"minor":0},"seq":1,"action":"shutdown"}"#;
        assert!(serde_json::from_str::<RequestFrame>(json).is_err());
    }

    #[test]
    fn response_rejects_unknown_status() {
        let json = r#"{"role":"admin","status":"maybe","v":{"major":1,"minor":0},"seq":1,"action":"pong"}"#;
        assert!(serde_json::from_str::<ResponseFrame>(json).is_err());
    }

    #[test]
    fn response_ok_requires_action() {
        let json = r#"{"role":"admin","status":"ok","v":{"major":1,"minor":0},"seq":1}"#;
        assert!(serde_json::from_str::<ResponseFrame>(json).is_err());
    }

    #[test]
    fn response_error_requires_error_field() {
        let json = r#"{"role":"admin","status":"error","v":{"major":1,"minor":0},"seq":1}"#;
        assert!(serde_json::from_str::<ResponseFrame>(json).is_err());
    }

    #[test]
    fn principal_has_no_uv_authority() {
        let json_ack = r#"{"role":"principal","v":{"major":1,"minor":0},"seq":1,"action":{"acknowledge_uv":{"prompt_id":1}}}"#;
        assert!(
            serde_json::from_str::<RequestFrame>(json_ack).is_err(),
            "principal must not have AcknowledgeUv"
        );

        let json_cancel = r#"{"role":"principal","v":{"major":1,"minor":0},"seq":1,"action":{"cancel_uv":{"prompt_id":1}}}"#;
        assert!(
            serde_json::from_str::<RequestFrame>(json_cancel).is_err(),
            "principal must not have CancelUv"
        );
    }

    #[test]
    fn principal_capabilities_response_no_secrets() {
        let caps = PrincipalCapabilities {
            profile_id: "test".into(),
            mode: "isolated".into(),
            allowed_rp_ids: vec!["example.com".into()],
            registration_allowed: false,
        };
        let json = serde_json::to_string(&caps).unwrap();
        assert!(!json.contains("private"));
        assert!(!json.contains("key"));
        assert!(!json.contains("pin"));
        assert!(!json.contains("secret"));
    }

    #[cfg(target_os = "linux")]
    fn create_seqpacket_pair() -> (std::os::unix::io::RawFd, std::os::unix::io::RawFd) {
        let mut fds = [0 as std::os::unix::io::RawFd; 2];
        let ret = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        assert_eq!(
            ret,
            0,
            "socketpair failed: {}",
            std::io::Error::last_os_error()
        );
        (fds[0], fds[1])
    }

    #[cfg(target_os = "linux")]
    fn close_fd(fd: std::os::unix::io::RawFd) {
        unsafe {
            libc::close(fd);
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn seqpacket_socketpair_send_recv_roundtrip() {
        let (fd0, fd1) = create_seqpacket_pair();
        let frame = RequestFrame::Admin(AdminRequestFrame::new(42, AdminRequest::Ping));
        let sent = SeqpacketCodec::send_msg(fd0, &frame).unwrap();
        assert!(sent > 0);
        let decoded: RequestFrame = SeqpacketCodec::recv_msg(fd1).unwrap();
        assert_eq!(decoded, frame);
        close_fd(fd0);
        close_fd(fd1);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn seqpacket_socketpair_response_roundtrip() {
        let (fd0, fd1) = create_seqpacket_pair();
        let frame = ResponseFrame::Admin(AdminResponseFrame::ok(7, AdminResponse::Pong));
        SeqpacketCodec::send_msg(fd0, &frame).unwrap();
        let decoded: ResponseFrame = SeqpacketCodec::recv_msg(fd1).unwrap();
        assert_eq!(decoded, frame);
        close_fd(fd0);
        close_fd(fd1);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn seqpacket_socketpair_multiple_messages() {
        let (fd0, fd1) = create_seqpacket_pair();
        let msg1 = RequestFrame::Admin(AdminRequestFrame::new(1, AdminRequest::Ping));
        let msg2 = RequestFrame::Admin(AdminRequestFrame::new(2, AdminRequest::Status));
        let msg3 = RequestFrame::Admin(AdminRequestFrame::new(3, AdminRequest::Shutdown));
        SeqpacketCodec::send_msg(fd0, &msg1).unwrap();
        SeqpacketCodec::send_msg(fd0, &msg2).unwrap();
        SeqpacketCodec::send_msg(fd0, &msg3).unwrap();
        let r1: RequestFrame = SeqpacketCodec::recv_msg(fd1).unwrap();
        let r2: RequestFrame = SeqpacketCodec::recv_msg(fd1).unwrap();
        let r3: RequestFrame = SeqpacketCodec::recv_msg(fd1).unwrap();
        assert_eq!(r1, msg1);
        assert_eq!(r2, msg2);
        assert_eq!(r3, msg3);
        close_fd(fd0);
        close_fd(fd1);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn seqpacket_socketpair_truncation_detected() {
        let (fd0, fd1) = create_seqpacket_pair();
        let big = AdminRequest::ListCredentials {
            rp_id: Some("x".repeat(MAX_MESSAGE_SIZE + 100)),
        };
        let frame = RequestFrame::Admin(AdminRequestFrame::new(1, big));
        let encode_err = SeqpacketCodec::send_msg(fd0, &frame).unwrap_err();
        assert!(matches!(encode_err, CodecError::Oversized { .. }));
        close_fd(fd0);
        close_fd(fd1);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn seqpacket_socketpair_peer_cred() {
        let (fd0, fd1) = create_seqpacket_pair();
        let cred = PeerCred::from_fd(fd1).unwrap();
        assert!(cred.pid > 0, "peer pid should be positive");
        assert_eq!(cred.uid, unsafe { libc::getuid() });
        assert_eq!(cred.gid, unsafe { libc::getgid() });
        let _ = fd0;
        close_fd(fd0);
        close_fd(fd1);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn seqpacket_socketpair_preserves_message_boundaries() {
        let (fd0, fd1) = create_seqpacket_pair();
        let small = RequestFrame::Admin(AdminRequestFrame::new(1, AdminRequest::Ping));
        let small_bytes = SeqpacketCodec::encode(&small).unwrap();
        let n = unsafe {
            libc::send(
                fd0,
                small_bytes.as_ptr() as *const libc::c_void,
                small_bytes.len(),
                0,
            )
        };
        assert_eq!(n as usize, small_bytes.len());
        let mut buf = vec![0u8; MAX_MESSAGE_SIZE * 2];
        let n = unsafe { libc::recv(fd1, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        assert_eq!(n as usize, small_bytes.len());
        let decoded: RequestFrame = SeqpacketCodec::decode(&buf[..n as usize]).unwrap();
        assert_eq!(decoded, small);
        close_fd(fd0);
        close_fd(fd1);
    }

    #[test]
    fn capability_proof_debug_redacted() {
        let proof = PrincipalCapabilityProof::from_bytes([0x71; CAPABILITY_PROOF_BYTES]);
        let debug = format!("{:?}", proof);
        assert_eq!(debug, "PrincipalCapabilityProof(***)");
        let hex_str = "71".repeat(CAPABILITY_PROOF_BYTES);
        assert!(!debug.contains(&hex_str));
    }

    #[test]
    fn capability_proof_display_redacted() {
        let proof = PrincipalCapabilityProof::from_bytes([0xAB; CAPABILITY_PROOF_BYTES]);
        let display = format!("{}", proof);
        assert_eq!(display, "***");
    }

    #[test]
    fn capability_proof_serde_roundtrip() {
        let proof = PrincipalCapabilityProof::from_bytes([0x42; CAPABILITY_PROOF_BYTES]);
        let json = serde_json::to_string(&proof).unwrap();
        let parsed: PrincipalCapabilityProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, parsed);
    }

    #[test]
    fn capability_proof_verify_constant_time_matching() {
        let a = PrincipalCapabilityProof::from_bytes([0x11; CAPABILITY_PROOF_BYTES]);
        let b = PrincipalCapabilityProof::from_bytes([0x11; CAPABILITY_PROOF_BYTES]);
        assert!(a.verify_constant_time(&b));
    }

    #[test]
    fn capability_proof_verify_constant_time_mismatch() {
        let a = PrincipalCapabilityProof::from_bytes([0x00; CAPABILITY_PROOF_BYTES]);
        let mut bytes_b = [0x00; CAPABILITY_PROOF_BYTES];
        bytes_b[15] = 1;
        let b = PrincipalCapabilityProof::from_bytes(bytes_b);
        assert!(!a.verify_constant_time(&b));
    }

    #[test]
    fn capability_proof_rejects_wrong_length() {
        let json = r#""aabb""#;
        let result: Result<PrincipalCapabilityProof, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn principal_request_frame_requires_capability_proof() {
        let json_without_proof =
            r#"{"role":"principal","v":{"major":1,"minor":0},"seq":1,"action":"ping"}"#;
        assert!(serde_json::from_str::<RequestFrame>(json_without_proof).is_err());
    }

    #[test]
    fn principal_request_frame_with_proof_deserializes() {
        let proof_hex = "42".repeat(CAPABILITY_PROOF_BYTES);
        let json = format!(
            r#"{{"role":"principal","v":{{"major":1,"minor":0}},"seq":1,"action":"ping","capability_proof":"{}"}}"#,
            proof_hex
        );
        let frame: RequestFrame = serde_json::from_str(&json).unwrap();
        assert_eq!(frame.role(), Role::Principal);
    }

    #[test]
    fn admin_launch_principal_roundtrip() {
        let frame = RequestFrame::Admin(AdminRequestFrame::new(
            10,
            AdminRequest::LaunchPrincipal {
                profile_id: ProfileId::new("test").unwrap(),
                command: vec!["/usr/bin/passless".into(), "--principal".into()],
            },
        ));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn admin_terminate_principal_roundtrip() {
        let frame = RequestFrame::Admin(AdminRequestFrame::new(
            11,
            AdminRequest::TerminatePrincipal {
                profile_id: ProfileId::new("test").unwrap(),
            },
        ));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn admin_principal_launched_response_roundtrip() {
        let resp = PrincipalLaunchedResponse {
            session_id: PrincipalSessionId::new(),
            pid: 12345,
            profile_id: "test".into(),
        };
        let frame = ResponseFrame::Admin(AdminResponseFrame::ok(
            12,
            AdminResponse::PrincipalLaunched(resp),
        ));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn admin_principal_terminated_response_roundtrip() {
        let frame = ResponseFrame::Admin(AdminResponseFrame::ok(
            13,
            AdminResponse::PrincipalTerminated,
        ));
        assert_eq!(json_roundtrip(&frame), frame);
    }

    #[test]
    fn validate_launch_principal_empty_command() {
        let req = AdminRequest::LaunchPrincipal {
            profile_id: ProfileId::new("test").unwrap(),
            command: vec![],
        };
        let errs = req.validate().unwrap_err();
        assert!(
            errs.0
                .iter()
                .any(|e| e.contains("command must not be empty"))
        );
    }

    #[test]
    fn validate_launch_principal_nul_in_arg() {
        let req = AdminRequest::LaunchPrincipal {
            profile_id: ProfileId::new("test").unwrap(),
            command: vec!["/bin/true\0evil".into()],
        };
        let errs = req.validate().unwrap_err();
        assert!(errs.0.iter().any(|e| e.contains("null")));
    }

    #[test]
    fn validate_launch_principal_too_many_args() {
        let req = AdminRequest::LaunchPrincipal {
            profile_id: ProfileId::new("test").unwrap(),
            command: (0..MAX_ARGV_COUNT + 1)
                .map(|i| format!("arg{}", i))
                .collect(),
        };
        let errs = req.validate().unwrap_err();
        assert!(errs.0.iter().any(|e| e.contains("maximum arg count")));
    }

    #[test]
    fn validate_launch_principal_valid() {
        let req = AdminRequest::LaunchPrincipal {
            profile_id: ProfileId::new("test").unwrap(),
            command: vec!["/usr/bin/passless".into(), "--flag".into()],
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn validate_terminate_principal_valid() {
        let req = AdminRequest::TerminatePrincipal {
            profile_id: ProfileId::new("test").unwrap(),
        };
        assert!(req.validate().is_ok());
    }

    fn valid_sign_request() -> SignAssertionRequest {
        SignAssertionRequest {
            origin: "https://example.com".to_string(),
            top_origin: None,
            rp_id: "example.com".to_string(),
            challenge_b64u: "dGVzdA".to_string(),
            allow_credentials: vec![],
            user_verification: false,
            cross_origin: false,
        }
    }

    #[test]
    fn sign_assertion_valid_roundtrip() {
        let req = valid_sign_request();
        assert!(
            PrincipalRequest::SignAssertion(req.clone())
                .validate()
                .is_ok()
        );
        let json = serde_json::to_string(&req).unwrap();
        let decoded: SignAssertionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn sign_assertion_empty_origin_rejected() {
        let mut req = valid_sign_request();
        req.origin = String::new();
        let errs = PrincipalRequest::SignAssertion(req).validate().unwrap_err();
        assert!(errs.0.iter().any(|e| e.contains("origin")));
    }

    #[test]
    fn sign_assertion_oversized_origin_rejected() {
        let mut req = valid_sign_request();
        req.origin = "x".repeat(MAX_ORIGIN_LEN + 1);
        let errs = PrincipalRequest::SignAssertion(req).validate().unwrap_err();
        assert!(errs.0.iter().any(|e| e.contains("origin")));
    }

    #[test]
    fn sign_assertion_empty_rp_id_rejected() {
        let mut req = valid_sign_request();
        req.rp_id = String::new();
        let errs = PrincipalRequest::SignAssertion(req).validate().unwrap_err();
        assert!(errs.0.iter().any(|e| e.contains("rp_id")));
    }

    #[test]
    fn sign_assertion_oversized_rp_id_rejected() {
        let mut req = valid_sign_request();
        req.rp_id = "x".repeat(MAX_RP_ID_LEN + 1);
        let errs = PrincipalRequest::SignAssertion(req).validate().unwrap_err();
        assert!(errs.0.iter().any(|e| e.contains("rp_id")));
    }

    #[test]
    fn sign_assertion_empty_challenge_rejected() {
        let mut req = valid_sign_request();
        req.challenge_b64u = String::new();
        let errs = PrincipalRequest::SignAssertion(req).validate().unwrap_err();
        assert!(errs.0.iter().any(|e| e.contains("challenge_b64u")));
    }

    #[test]
    fn sign_assertion_oversized_challenge_rejected() {
        let mut req = valid_sign_request();
        req.challenge_b64u = "x".repeat(MAX_B64U_LEN + 1);
        let errs = PrincipalRequest::SignAssertion(req).validate().unwrap_err();
        assert!(errs.0.iter().any(|e| e.contains("challenge_b64u")));
    }

    #[test]
    fn sign_assertion_oversized_allow_credentials_rejected() {
        let mut req = valid_sign_request();
        req.allow_credentials = vec!["x".repeat(64); MAX_ALLOW_CREDENTIALS + 1];
        let errs = PrincipalRequest::SignAssertion(req).validate().unwrap_err();
        assert!(errs.0.iter().any(|e| e.contains("allow_credentials")));
    }

    #[test]
    fn sign_assertion_null_in_origin_rejected() {
        let mut req = valid_sign_request();
        req.origin = "https://exam\0ple.com".to_string();
        let errs = PrincipalRequest::SignAssertion(req).validate().unwrap_err();
        assert!(errs.0.iter().any(|e| e.contains("origin")));
    }

    #[test]
    fn sign_assertion_user_verification_roundtrip() {
        let mut req = valid_sign_request();
        req.user_verification = true;
        assert!(
            PrincipalRequest::SignAssertion(req.clone())
                .validate()
                .is_ok()
        );
        let json = serde_json::to_string(&req).unwrap();
        let decoded: SignAssertionRequest = serde_json::from_str(&json).unwrap();
        assert!(decoded.user_verification);
    }

    #[test]
    fn sign_assertion_rejects_unknown_fields() {
        let json = r#"{"origin":"https://example.com","rp_id":"example.com","challenge_b64u":"dGVzdA","allow_credentials":[],"user_verification":false,"cross_origin":false,"extra":"bad"}"#;
        assert!(serde_json::from_str::<SignAssertionRequest>(json).is_err());
    }
}
