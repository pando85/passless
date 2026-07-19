#[cfg(feature = "agent")]
pub mod agent;
pub mod config;
pub mod error;

#[cfg(feature = "agent")]
pub use agent::{
    AgentConfig, AgentMode, AgentProfileConfig, AgentStorageConfig, BoundedDuration, CredentialRef,
    DeviceIdentity, GrantId, IdError, PendingRequestId, Policy, PolicyDigest, PolicyError,
    PolicyParams, PrincipalSessionId, ProfileId, validate_rp_id,
};
#[cfg(feature = "agent")]
pub use config::{
    AdminAuditAction, AdminAuditExportFormat, AdminCredentialAction, AdminDelegationAction,
    AdminPolicyAction, AdminProfileAction, AdminSessionAction, AgentAdminAction, AgentCommand,
    AgentCredentialAction, AgentDelegationAction, AgentIntentAction, AgentIntentActionType,
};
pub use config::{
    AgentSkillScope, AgentSkillTarget, AppConfig, Args, BackendConfig, ClientAction, Commands,
    ConfigAction, OutputFormat, PinAction, SecurityConfig,
};
pub use error::{Error, Result};
