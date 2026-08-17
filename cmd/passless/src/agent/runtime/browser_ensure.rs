use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use passless_core::agent::config::CdpExposeMode;
use passless_core::agent::protocol::{
    BrowserStatusResponse, ErrorCode, PrincipalResponse, ProtocolError, RecommendedAction,
};
use passless_core::agent::{BrowserLeaseId, PrincipalSessionId, ProfileId};

use super::{ActiveBrowserLease, AgentRuntime, ProfileRuntime};
use crate::agent::browser::{BrowserConfig, LeaseState};
use crate::agent::intent::ProcessIdentityDigest;
use crate::storage::CredentialFilter;

const BROWSER_TTL: Duration = Duration::from_secs(3600);
const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_ACTIVE_TTL_SECS: u64 = 86_400;

impl AgentRuntime {
    /// Ensure that the verified principal owns a live trusted-port browser.
    ///
    /// This is intentionally principal-scoped. It must never adopt a browser lease created by
    /// an admin command or by another principal session. The lifecycle lock makes concurrent
    /// Playwright discovery requests single-flight for the profile.
    pub(super) fn handle_ensure_browser(
        &self,
        profile_id: &ProfileId,
        session_id: &PrincipalSessionId,
        process_digest: &ProcessIdentityDigest,
        start_url: Option<&str>,
        profile: &Arc<ProfileRuntime>,
    ) -> Result<PrincipalResponse, ProtocolError> {
        if profile
            .profile_config
            .browser_cdp_expose
            .unwrap_or_default()
            != CdpExposeMode::Port
        {
            return Err(ProtocolError::new(
                ErrorCode::Forbidden,
                "Playwright browser discovery requires browser_cdp_expose = 'port' (trusted agents only)",
                RecommendedAction::FixRequest,
            ));
        }

        let _lifecycle = profile.lifecycle_lock.lock().map_err(|_| {
            ProtocolError::new(
                ErrorCode::Internal,
                "profile lifecycle lock poisoned",
                RecommendedAction::Abort,
            )
        })?;

        // Fast path: a browser explicitly owned by this principal session is still alive.
        {
            let current = profile.active_browser.lock().map_err(|_| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    "active browser lock poisoned",
                    RecommendedAction::Abort,
                )
            })?;
            if let Some(active) = current.as_ref()
                && active.session_id != *session_id
            {
                return Err(ProtocolError::new(
                    ErrorCode::Conflict,
                    "profile browser is owned by another principal session",
                    RecommendedAction::RetryWithBackoff,
                ));
            }
        }

        let mut browser_manager = self.browser_manager.lock().map_err(|_| {
            ProtocolError::new(
                ErrorCode::Internal,
                "browser manager lock poisoned",
                RecommendedAction::Abort,
            )
        })?;

        let active_lease = profile
            .active_browser
            .lock()
            .map_err(|_| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    "active browser lock poisoned",
                    RecommendedAction::Abort,
                )
            })?
            .clone();

        if let Some(active) = active_lease {
            if let Some(snapshot) = browser_manager.snapshot(&active.lease_id)
                && matches!(
                    snapshot.state,
                    LeaseState::Active | LeaseState::AuthenticationPending
                )
                && let Some(endpoint) = browser_manager
                    .lease_cdp_endpoint(&active.lease_id)
                    .flatten()
            {
                return Ok(browser_ensured(snapshot.state.to_string(), endpoint));
            }

            // The profile bookkeeping is stale. Revoke any sign token bound to the old lease
            // before allowing a replacement browser to be created.
            self.sign_registry
                .revoke_by_lease(&active.lease_id.to_string());
            let _ = browser_manager.revoke(&active.lease_id);
            let _ = browser_manager.terminate(&active.lease_id);
            let _ = browser_manager.cleanup(&active.lease_id);
            browser_manager.remove(&active.lease_id);
            *profile.active_browser.lock().map_err(|_| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    "active browser lock poisoned",
                    RecommendedAction::Abort,
                )
            })? = None;
        }

        // Do not silently adopt an admin-launched or otherwise unowned lease. A CDP port is full
        // browser authority, so ownership ambiguity is a hard conflict rather than a reuse hint.
        if browser_manager
            .find_live_lease_for_profile(profile_id)
            .is_some()
        {
            return Err(ProtocolError::new(
                ErrorCode::Conflict,
                "a live browser exists for the profile but is not owned by this principal session",
                RecommendedAction::RetryWithBackoff,
            ));
        }

        let endpoint_id = profile
            .endpoint_id
            .lock()
            .map_err(|_| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    "endpoint lock poisoned",
                    RecommendedAction::Abort,
                )
            })?
            .clone()
            .ok_or_else(|| {
                ProtocolError::new(
                    ErrorCode::NotFound,
                    format!("profile '{}' has no active endpoint", profile_id),
                    RecommendedAction::FixRequest,
                )
            })?;

        let profile_config = &profile.profile_config;
        let browser_command = profile_config.browser_command.as_ref().ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::BadRequest,
                format!("profile '{}' has no browser_command configured", profile_id),
                RecommendedAction::FixRequest,
            )
        })?;
        if browser_command.is_empty() {
            return Err(ProtocolError::new(
                ErrorCode::BadRequest,
                "browser_command must contain an executable",
                RecommendedAction::FixRequest,
            ));
        }

        let runtime_root = profile_config
            .browser_runtime_root
            .clone()
            .unwrap_or_else(|| {
                dirs::runtime_dir()
                    .unwrap_or_else(|| PathBuf::from("/tmp"))
                    .join("passless")
                    .join("browser")
            });
        let rp_ids = if !profile_config.rp_ids.is_empty() {
            profile_config.rp_ids.clone()
        } else {
            profile_config.allowed_rp_ids()
        };
        let config = BrowserConfig {
            executable: PathBuf::from(&browser_command[0]),
            start_url: start_url
                .map(str::to_owned)
                .or_else(|| profile_config.start_url.clone()),
            extra_args: browser_command[1..].to_vec(),
            runtime_root,
            ttl: BROWSER_TTL,
            login_timeout: LOGIN_TIMEOUT,
            rp_ids,
            target_uid: profile.browser_uid.unwrap_or(profile.daemon_uid),
            target_gid: profile.browser_gid.unwrap_or(profile.daemon_gid),
            daemon_uid: profile.daemon_uid,
            daemon_gid: profile.daemon_gid,
            cdp_expose: CdpExposeMode::Port,
            cdp_port: profile_config.browser_cdp_port.unwrap_or(0),
        };

        let bearer_token = crate::agent::sign::generate_bearer_token().map_err(|e| {
            ProtocolError::new(
                ErrorCode::Internal,
                format!("failed to generate browser bearer token: {e}"),
                RecommendedAction::Abort,
            )
        })?;

        let registration_ctx = crate::agent::register::RegisterContext {
            profile_id: profile_id.clone(),
            // Browser startup never implicitly creates enrollment authority.
            registration_grants: std::collections::HashMap::new(),
            profile_config: profile_config.clone(),
        };
        let registration_handler = Arc::new(crate::agent::register::RegisterHandler {
            credential_storage: profile.backend.credential_storage.clone(),
            policy_runtime: self.policy_runtime.clone(),
            audit_gate: self.audit_gate.clone(),
            key_provider: profile.backend.key_provider.clone(),
            security_config: profile.endpoint_spec.security_config.clone(),
            operation_lock: profile.backend.operation_lock.clone(),
        });
        self.sign_registry
            .register_pending_registration(
                bearer_token.clone(),
                registration_ctx,
                registration_handler,
            )
            .map_err(|e| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    format!("failed to register browser registration context: {e}"),
                    RecommendedAction::Abort,
                )
            })?;

        let metadata = crate::agent::browser::AgentEndpointMetadata {
            port: self.sign_port,
            bearer_token: bearer_token.clone(),
        };
        let lease_id = match browser_manager.launch_pending_with_agent_endpoint(
            &config,
            endpoint_id.clone(),
            profile_id.clone(),
            Some(&metadata),
        ) {
            Ok(id) => id,
            Err(e) => {
                self.sign_registry.revoke_registration(&bearer_token);
                return Err(ProtocolError::new(
                    ErrorCode::Internal,
                    format!("failed to launch browser: {e}"),
                    RecommendedAction::FixRequest,
                ));
            }
        };

        let result = self.finish_principal_browser_launch(
            profile_id,
            session_id,
            process_digest,
            profile,
            &config,
            &endpoint_id,
            &bearer_token,
            &lease_id,
            &mut browser_manager,
        );

        if result.is_err() {
            self.sign_registry.revoke(&bearer_token);
            self.sign_registry.revoke_registration(&bearer_token);
            self.sign_registry.revoke_by_lease(&lease_id.to_string());
            let _ = browser_manager.revoke(&lease_id);
            let _ = browser_manager.terminate(&lease_id);
            let _ = browser_manager.cleanup(&lease_id);
            browser_manager.remove(&lease_id);
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_principal_browser_launch(
        &self,
        profile_id: &ProfileId,
        session_id: &PrincipalSessionId,
        process_digest: &ProcessIdentityDigest,
        profile: &Arc<ProfileRuntime>,
        config: &BrowserConfig,
        endpoint_id: &passless_core::agent::EndpointId,
        bearer_token: &str,
        lease_id: &BrowserLeaseId,
        browser_manager: &mut crate::agent::browser::BrowserProcessManager,
    ) -> Result<PrincipalResponse, ProtocolError> {
        let profile_config = &profile.profile_config;
        let mut credential_refs = Vec::new();
        if let Ok(mut storage) = profile.backend.credential_storage.lock()
            && let Ok(mut credential) = storage.read_first(CredentialFilter::None)
        {
            loop {
                let rp_allowed = config
                    .rp_ids
                    .iter()
                    .any(|rp| rp.eq_ignore_ascii_case(&credential.rp.id));
                let credential_ref =
                    passless_core::agent::CredentialRef::with_default_domain(&credential.id);
                let credential_allowed = profile_config
                    .credential_refs
                    .as_ref()
                    .is_none_or(|refs| refs.iter().any(|candidate| candidate == &credential_ref));
                if rp_allowed && credential_allowed {
                    credential_refs.push(credential_ref);
                }
                match storage.read_next() {
                    Ok(next) => credential = next,
                    Err(_) => break,
                }
            }
        }

        let dynamic_credential_scope = profile_config.credential_refs.is_none();
        if dynamic_credential_scope || !credential_refs.is_empty() {
            let params = crate::agent::grant::GrantRequestParams {
                profile_id: profile_id.clone(),
                session_id: session_id.clone(),
                endpoint_id: endpoint_id.clone(),
                principal_digest: *process_digest.as_bytes(),
                rp_ids: config.rp_ids.clone(),
                credentials: if dynamic_credential_scope {
                    Vec::new()
                } else {
                    credential_refs
                },
                requested_ttl_secs: profile_config
                    .max_session_ttl
                    .as_ref()
                    .map(|ttl| ttl.as_secs())
                    .unwrap_or(300),
            };
            let request_id = if dynamic_credential_scope {
                self.policy_runtime.admin_request_dynamic_grant(params)
            } else {
                self.policy_runtime.admin_request_grant(params)
            }
            .map_err(|e| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    format!("failed to prepare browser authentication grant: {e}"),
                    RecommendedAction::Abort,
                )
            })?;
            // This is an internal approval, not admin IPC. The request reached this point only
            // after principal capability/peer/process verification and explicit trusted port mode.
            let grant_id = self
                .policy_runtime
                .admin_approve_grant(&request_id, &crate::agent::intent::admin_authority())
                .map_err(|e| {
                    ProtocolError::new(
                        ErrorCode::Internal,
                        format!("failed to activate browser authentication grant: {e}"),
                        RecommendedAction::Abort,
                    )
                })?;

            let sign_ctx = crate::agent::sign::SignContext {
                profile_id: profile_id.clone(),
                active_grant_id: grant_id.clone(),
                profile_config: profile_config.clone(),
            };
            let sign_handler = Arc::new(crate::agent::sign::SignHandler {
                credential_storage: profile.backend.credential_storage.clone(),
                policy_runtime: self.policy_runtime.clone(),
                audit_gate: self.audit_gate.clone(),
                security_config: profile.endpoint_spec.security_config.clone(),
                key_provider: profile.backend.key_provider.clone(),
                operation_lock: profile.backend.operation_lock.clone(),
            });
            if let Err(e) = self.sign_registry.register_pending(
                bearer_token.to_string(),
                sign_ctx,
                sign_handler,
            ) {
                let _ = self
                    .policy_runtime
                    .admin_revoke_grant(&grant_id, &crate::agent::intent::admin_authority());
                return Err(ProtocolError::new(
                    ErrorCode::Internal,
                    format!("failed to register browser sign context: {e}"),
                    RecommendedAction::Abort,
                ));
            }
            if let Err(e) = self
                .sign_registry
                .bind_lease(bearer_token, lease_id.to_string())
            {
                self.sign_registry.revoke(bearer_token);
                let _ = self
                    .policy_runtime
                    .admin_revoke_grant(&grant_id, &crate::agent::intent::admin_authority());
                return Err(ProtocolError::new(
                    ErrorCode::Internal,
                    format!("failed to bind browser sign context: {e}"),
                    RecommendedAction::Abort,
                ));
            }
        }

        let active_ttl = profile_config
            .max_session_ttl
            .as_ref()
            .map(|ttl| ttl.as_secs())
            .unwrap_or(300)
            .clamp(1, MAX_ACTIVE_TTL_SECS);
        browser_manager
            .activate_after_assertion(lease_id, Duration::from_secs(active_ttl))
            .map_err(|e| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    format!("failed to activate browser lease: {e}"),
                    RecommendedAction::Abort,
                )
            })?;

        let endpoint = browser_manager
            .lease_cdp_endpoint(lease_id)
            .flatten()
            .ok_or_else(|| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    "port-mode browser did not expose a CDP endpoint",
                    RecommendedAction::Abort,
                )
            })?;

        *profile.active_browser.lock().map_err(|_| {
            ProtocolError::new(
                ErrorCode::Internal,
                "active browser lock poisoned",
                RecommendedAction::Abort,
            )
        })? = Some(ActiveBrowserLease {
            lease_id: lease_id.clone(),
            session_id: session_id.clone(),
        });

        Ok(browser_ensured("active".to_string(), endpoint))
    }
}

fn browser_ensured(status: String, endpoint: String) -> PrincipalResponse {
    PrincipalResponse::BrowserEnsured(BrowserStatusResponse {
        running: true,
        status,
        cdp_endpoint: Some(endpoint),
    })
}
