use std::sync::Arc;
use std::time::Duration;

use passless_core::agent::config::CdpExposeMode;
use passless_core::agent::protocol::{
    BrowserStatusResponse, ErrorCode, PrincipalResponse, ProtocolError, RecommendedAction,
};
use passless_core::agent::{BrowserLeaseId, BrowserScope, PrincipalSessionId, ProfileId};

use super::{ActiveBrowserLease, AgentRuntime, ProfileRuntime, SharedBrowserLease, gates};
use crate::agent::audit_events::RevokeReason;
use crate::agent::browser::{
    BrowserConfig, INTERCEPTION_ATTACH_TIMEOUT, InterceptionState, LeaseState,
};
use crate::agent::identity::ProcessIdentityDigest;
use crate::agent::sign::BrowserLeaseActivation;
use crate::storage::CredentialFilter;

const BROWSER_TTL: Duration = Duration::from_secs(3600);
const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_ACTIVE_TTL_SECS: u64 = 86_400;

impl AgentRuntime {
    /// Ensure that the verified principal owns a live managed browser, in the profile's CDP mode.
    ///
    /// Port mode returns the loopback CDP endpoint. Pipe mode (the default) returns none: the
    /// browser's CDP pipes stay with the daemon and the principal drives the browser through
    /// `browser-control` (ADR 0014 section 4.3). Everything else is the same for both modes: the
    /// principal checks of `handle_principal`, the interception gate (no result before the
    /// worker attached and is allowed in incognito), the grants and bearers bound to the session,
    /// the B1 lifetime and the lease audit records.
    ///
    /// For session-scoped profiles, each session gets its own browser lease.
    /// For profile-scoped profiles, sessions on the same profile share a single browser.
    /// The lifecycle lock makes concurrent Playwright discovery requests single-flight.
    ///
    /// `direct_cdp` is set by callers that can only use an endpoint; a pipe-mode profile refuses
    /// them before anything is started.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_ensure_browser(
        &self,
        profile_id: &ProfileId,
        session_id: &PrincipalSessionId,
        process_digest: &ProcessIdentityDigest,
        start_url: Option<&str>,
        headed: bool,
        direct_cdp: bool,
        profile: &ProfileRuntime,
    ) -> Result<PrincipalResponse, ProtocolError> {
        // Rules, limits, the CDP mode and the session TTL come from the configuration in force,
        // which a policy reload may have replaced since the daemon started (ADR 0014 section 6.4).
        let live_config = self.live_profile_config(profile);
        let profile_config = &live_config;
        let mode = profile_config.browser_cdp_expose.unwrap_or_default();
        gates::check_ensure_browser_mode(mode, direct_cdp)?;

        let _lifecycle = crate::agent::lock_order::lock(
            &profile.lifecycle_lock,
            crate::agent::lock_order::LockLevel::ProfileLifecycle,
        );

        let mut browser_manager = crate::agent::lock_order::lock(
            &self.browser_manager,
            crate::agent::lock_order::LockLevel::BrowserManager,
        );

        if profile.profile_config.browser_scope == BrowserScope::Profile {
            let shared_lease_id = profile
                .shared_browsers
                .lock()
                .map_err(|_| {
                    ProtocolError::new(
                        ErrorCode::Internal,
                        "shared browser lock poisoned",
                        RecommendedAction::Abort,
                    )
                })?
                .get(profile_id)
                .map(|lease| lease.lease_id.clone());

            if let Some(lease_id) = shared_lease_id {
                if let Some(snapshot) = browser_manager.snapshot(&lease_id)
                    && matches!(
                        snapshot.state,
                        LeaseState::Active | LeaseState::AuthenticationPending
                    )
                    && let Some(endpoint) = lease_cdp_access(&browser_manager, &lease_id, mode)
                {
                    // A degraded lease is withheld until its worker re-attaches.
                    let (interception, incognito_allowed) =
                        self.require_attached_interception(&mut browser_manager, &lease_id)?;
                    {
                        let mut shared = profile.shared_browsers.lock().map_err(|_| {
                            ProtocolError::new(
                                ErrorCode::Internal,
                                "shared browser lock poisoned",
                                RecommendedAction::Abort,
                            )
                        })?;
                        let lease = shared.get_mut(profile_id).unwrap();
                        if lease.attach(session_id) {
                            lease.sync_ref_count();
                        }
                    }
                    profile
                        .active_browser
                        .lock()
                        .map_err(|_| {
                            ProtocolError::new(
                                ErrorCode::Internal,
                                "active browser lock poisoned",
                                RecommendedAction::Abort,
                            )
                        })?
                        .insert(
                            session_id.clone(),
                            ActiveBrowserLease {
                                lease_id: lease_id.clone(),
                                session_id: session_id.clone(),
                            },
                        );
                    return Ok(browser_ensured(
                        snapshot.state.to_string(),
                        endpoint,
                        mode,
                        true,
                        interception,
                        incognito_allowed,
                    ));
                }

                self.close_lease(&mut browser_manager, &lease_id, RevokeReason::Superseded);
                profile
                    .shared_browsers
                    .lock()
                    .map_err(|_| {
                        ProtocolError::new(
                            ErrorCode::Internal,
                            "shared browser lock poisoned",
                            RecommendedAction::Abort,
                        )
                    })?
                    .remove(profile_id);
            }
        }

        let active_lease_id = profile
            .active_browser
            .lock()
            .map_err(|_| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    "active browser lock poisoned",
                    RecommendedAction::Abort,
                )
            })?
            .get(session_id)
            .map(|active| active.lease_id.clone());

        if let Some(lease_id) = active_lease_id {
            if let Some(snapshot) = browser_manager.snapshot(&lease_id)
                && matches!(
                    snapshot.state,
                    LeaseState::Active | LeaseState::AuthenticationPending
                )
                && let Some(endpoint) = lease_cdp_access(&browser_manager, &lease_id, mode)
            {
                // A degraded lease is withheld until its worker re-attaches.
                let (interception, incognito_allowed) =
                    self.require_attached_interception(&mut browser_manager, &lease_id)?;
                return Ok(browser_ensured(
                    snapshot.state.to_string(),
                    endpoint,
                    mode,
                    false,
                    interception,
                    incognito_allowed,
                ));
            }

            // The profile bookkeeping is stale. Revoke any sign token bound to the old lease
            // before allowing a replacement browser to be created.
            self.close_lease(&mut browser_manager, &lease_id, RevokeReason::Superseded);
            profile
                .active_browser
                .lock()
                .map_err(|_| {
                    ProtocolError::new(
                        ErrorCode::Internal,
                        "active browser lock poisoned",
                        RecommendedAction::Abort,
                    )
                })?
                .remove(session_id);
        }

        // Other sessions (and admin-launched browsers) may have live leases for the same
        // authority profile. They are intentionally outside this principal's ownership namespace.

        // The browser binary: the profile's `browser_command`, else `agents.browser_path`, else
        // auto-detection. Branded Google Chrome and chrome-headless-shell are refused (R14), and a
        // distinct-UID principal only gets a root-owned, principal-unwritable binary (V-H7).
        let launch = self.resolve_browser_launch(profile, profile_config, headed)?;

        let runtime_root = profile_config
            .browser_runtime_root
            .clone()
            .unwrap_or_else(|| crate::agent::browser::default_runtime_root().1);
        let rp_ids = profile_config.rule_rp_ids();
        let config = BrowserConfig {
            executable: launch.executable,
            start_url: start_url
                .map(str::to_owned)
                .or_else(|| profile_config.start_url.clone()),
            extra_args: launch.extra_args,
            runtime_root,
            ttl: BROWSER_TTL,
            login_timeout: LOGIN_TIMEOUT,
            rp_ids,
            start_url_rules: profile_config.rules.clone(),
            target_uid: profile.browser_uid.unwrap_or(profile.daemon_uid),
            target_gid: profile.browser_gid.unwrap_or(profile.daemon_gid),
            daemon_uid: profile.daemon_uid,
            daemon_gid: profile.daemon_gid,
            cdp_expose: mode,
            cdp_port: match mode {
                CdpExposeMode::Port => profile_config.browser_cdp_port.unwrap_or(0),
                CdpExposeMode::Pipe => 0,
            },
            // Every scope: the browser is forked on the long-lived launcher thread, so its
            // parent-death signal fires only when the daemon dies (defect B1); revocation,
            // expiry and session end terminate it explicitly.
            bind_parent_death: true,
        };

        // The browser's relay must be able to reach a sign socket of its own UID; refuse up front
        // rather than time out waiting for an attach that cannot happen.
        let sign_socket = self.sign_socket_for(config.target_uid)?;

        let bearer_token = crate::agent::sign::generate_bearer_token().map_err(|e| {
            ProtocolError::new(
                ErrorCode::Internal,
                format!("failed to generate browser bearer token: {e}"),
                RecommendedAction::Abort,
            )
        })?;

        // Registration authority is policy only (`register = "allow"` on an exact RP rule); the
        // bearer is bound to the browser lease in `finish_principal_browser_launch` and revoked
        // with it.
        // One bearer session backs both the sign and the registration context of this bearer: it
        // is bound to the principal digest, the revocation epoch now in force and the session TTL
        // (ADR 0014 section 9).
        let session =
            self.new_bearer_session(profile_id, *process_digest.as_bytes(), profile_config);
        session.bind_browser_uid(config.target_uid);
        let registration_ctx =
            crate::agent::register::RegisterContext::new(profile_id.clone(), session.clone());
        let registration_handler = Arc::new(crate::agent::register::RegisterHandler {
            policy_runtime: self.policy_runtime.clone(),
            credential_storage: profile.backend.credential_storage.clone(),
            audit_gate: self.audit_gate.clone(),
            key_provider: profile.backend.key_provider.clone(),
            security_config: profile.security_config.clone(),
            operation_lock: profile.backend.operation_lock.clone(),
            escalation: self.escalation.clone(),
            audit_deployment: profile.audit_deployment(),
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
            socket_path: sign_socket.to_string_lossy().into_owned(),
            bearer_token: bearer_token.clone(),
        };
        let lease_id = match browser_manager.launch_pending_with_agent_endpoint(
            &config,
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
        self.audit_launch(&lease_id, profile_id, &config);

        let result = self.finish_principal_browser_launch(
            profile_id,
            session_id,
            process_digest,
            &session,
            profile,
            &config,
            &bearer_token,
            &lease_id,
            &mut browser_manager,
        );

        if result.is_err() {
            self.sign_registry.revoke(&bearer_token);
            self.sign_registry.revoke_registration(&bearer_token);
            self.close_lease(&mut browser_manager, &lease_id, RevokeReason::LaunchFailed);
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_principal_browser_launch(
        &self,
        profile_id: &ProfileId,
        session_id: &PrincipalSessionId,
        process_digest: &ProcessIdentityDigest,
        session: &Arc<crate::agent::session::AgentSession>,
        profile: &ProfileRuntime,
        config: &BrowserConfig,
        bearer_token: &str,
        lease_id: &BrowserLeaseId,
        browser_manager: &mut crate::agent::browser::BrowserProcessManager,
    ) -> Result<PrincipalResponse, ProtocolError> {
        let live_config = self.live_profile_config(profile);
        let profile_config = &live_config;
        self.sign_registry
            .bind_registration_lease(bearer_token, lease_id.to_string())
            .map_err(|e| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    format!("failed to bind browser registration context: {e}"),
                    RecommendedAction::Abort,
                )
            })?;
        // Ready means intercepted (plan D6 layer 1): no endpoint is handed out before the lease's
        // worker said hello with `attached = true`. The registration bearer was registered before
        // the spawn, so the transport accepts that hello even before the binding above. On a
        // timeout the caller stops the browser and revokes the bearer.
        let readiness = browser_manager
            .await_interception(lease_id, &self.sign_readiness, INTERCEPTION_ATTACH_TIMEOUT)
            .map_err(|e| {
                log::warn!("browser launch for profile={profile_id} failed: {e}");
                ProtocolError::new(
                    ErrorCode::Internal,
                    format!("failed to launch browser: {e}"),
                    RecommendedAction::FixRequest,
                )
            })?;
        let mut credential_refs = Vec::new();
        let mut storage = crate::agent::lock_order::lock(
            &profile.backend.credential_storage,
            crate::agent::lock_order::LockLevel::Storage,
        );
        if let Ok(mut credential) = storage.read_first(CredentialFilter::None) {
            loop {
                // A `*` scope covers every RP but `localhost` (ADR 0014 section 6.1).
                let rp_allowed = config.rp_ids.iter().any(|rp| {
                    rp.eq_ignore_ascii_case(&credential.rp.id)
                        || (rp == passless_core::agent::config::ANY_RP_ID
                            && !credential.rp.id.eq_ignore_ascii_case(
                                passless_core::agent::config::LOCALHOST_RP_ID,
                            ))
                });
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
        drop(storage);

        let dynamic_credential_scope = profile_config.credential_refs.is_none();
        // With a `*` rule the pins constrain exact-rule matches only and the sign path reads them
        // from the live policy, so the grant is created even when no pinned credential is in the
        // store; its credential list is for audit and `sessions show` only (ADR 0014 amendment
        // 2.1). Without `*`, as before: pins with no stored credential create no grant.
        let wildcard_scope = config
            .rp_ids
            .iter()
            .any(|rp| rp == passless_core::agent::config::ANY_RP_ID);
        let empty_credentials_allowed = dynamic_credential_scope || wildcard_scope;
        if !config.rp_ids.is_empty() && (empty_credentials_allowed || !credential_refs.is_empty()) {
            let params = crate::agent::grant::GrantRequestParams {
                profile_id: profile_id.clone(),
                session_id: session_id.clone(),
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
            // The session grant is bounded by `max_session_ttl`, not `max_grant_ttl` (defect B5).
            let request_id = self
                .policy_runtime
                .admin_request_session_grant(params, empty_credentials_allowed)
                .map_err(|e| {
                    ProtocolError::new(
                        ErrorCode::Internal,
                        format!("failed to prepare browser authentication grant: {e}"),
                        RecommendedAction::Abort,
                    )
                })?;
            // This is an internal approval, not admin IPC. The request reached this point only
            // after principal capability/peer/process verification. Pipe mode mediates every CDP
            // command (`browser-control`); port mode is the explicitly trusted mode.
            let grant_id = self
                .policy_runtime
                .admin_approve_grant(&request_id, &crate::agent::identity::admin_authority())
                .map_err(|e| {
                    ProtocolError::new(
                        ErrorCode::Internal,
                        format!("failed to activate browser authentication grant: {e}"),
                        RecommendedAction::Abort,
                    )
                })?;

            let _ = session.bind_grant(grant_id.clone());
            let active_ttl = profile_config
                .max_session_ttl
                .as_ref()
                .map(|ttl| ttl.as_secs())
                .unwrap_or(300)
                .clamp(1, MAX_ACTIVE_TTL_SECS);
            // The lease is activated after the first assertion, outside every backend lock
            // (review H1): the browser manager is global and may be held by another launch.
            let lease_activation = BrowserLeaseActivation::new(
                self.browser_manager.clone(),
                lease_id.clone(),
                Duration::from_secs(active_ttl),
            );
            let sign_ctx = crate::agent::sign::SignContext {
                profile_id: profile_id.clone(),
                active_grant_id: grant_id.clone(),
                session: session.clone(),
                lease_activation: Some(lease_activation),
            };
            let sign_handler = Arc::new(crate::agent::sign::SignHandler {
                credential_storage: profile.backend.credential_storage.clone(),
                policy_runtime: self.policy_runtime.clone(),
                audit_gate: self.audit_gate.clone(),
                security_config: profile.security_config.clone(),
                key_provider: profile.backend.key_provider.clone(),
                operation_lock: profile.backend.operation_lock.clone(),
                escalation: self.escalation.clone(),
                audit_deployment: profile.audit_deployment(),
            });
            if let Err(e) = self.sign_registry.register_pending(
                bearer_token.to_string(),
                sign_ctx,
                sign_handler,
            ) {
                let _ = self
                    .policy_runtime
                    .admin_revoke_grant(&grant_id, &crate::agent::identity::admin_authority());
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
                    .admin_revoke_grant(&grant_id, &crate::agent::identity::admin_authority());
                return Err(ProtocolError::new(
                    ErrorCode::Internal,
                    format!("failed to bind browser sign context: {e}"),
                    RecommendedAction::Abort,
                ));
            }
        }

        let mode = config.cdp_expose;
        let endpoint = lease_cdp_access(browser_manager, lease_id, mode).ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::Internal,
                match mode {
                    CdpExposeMode::Port => "port-mode browser did not expose a CDP endpoint",
                    CdpExposeMode::Pipe => "pipe-mode browser did not open its CDP pipes",
                },
                RecommendedAction::Abort,
            )
        })?;

        profile
            .active_browser
            .lock()
            .map_err(|_| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    "active browser lock poisoned",
                    RecommendedAction::Abort,
                )
            })?
            .insert(
                session_id.clone(),
                ActiveBrowserLease {
                    lease_id: lease_id.clone(),
                    session_id: session_id.clone(),
                },
            );

        if profile_config.browser_scope == BrowserScope::Profile {
            let mut attached = std::collections::HashSet::new();
            attached.insert(session_id.clone());
            profile
                .shared_browsers
                .lock()
                .map_err(|_| {
                    ProtocolError::new(
                        ErrorCode::Internal,
                        "shared browser lock poisoned",
                        RecommendedAction::Abort,
                    )
                })?
                .insert(
                    profile_id.clone(),
                    SharedBrowserLease {
                        lease_id: lease_id.clone(),
                        owner_session: session_id.clone(),
                        ref_count: 1,
                        attached_sessions: attached,
                    },
                );
        }

        // The start URL is opened only now that interception is attached and the bearer's
        // contexts are registered (defect B2).
        self.open_deferred_start_url(browser_manager, lease_id);

        Ok(browser_ensured(
            LeaseState::AuthenticationPending.to_string(),
            endpoint,
            mode,
            profile_config.browser_scope == BrowserScope::Profile,
            InterceptionState::Attached,
            readiness.incognito_allowed,
        ))
    }
}

/// The lease's CDP channel in `mode` (see [`gates::cdp_access`]): `Some(Some(endpoint))` in port
/// mode, `Some(None)` for a pipe-mode lease, `None` when it has none for that mode.
pub(super) fn lease_cdp_access(
    browser_manager: &crate::agent::browser::BrowserProcessManager,
    lease_id: &BrowserLeaseId,
    mode: CdpExposeMode,
) -> Option<Option<String>> {
    gates::cdp_access(
        mode,
        browser_manager.lease_cdp_endpoint(lease_id).flatten(),
        browser_manager.lease_has_cdp_pipes(lease_id),
    )
}

fn browser_ensured(
    status: String,
    endpoint: Option<String>,
    mode: CdpExposeMode,
    shared: bool,
    interception: InterceptionState,
    incognito_allowed: bool,
) -> PrincipalResponse {
    PrincipalResponse::BrowserEnsured(BrowserStatusResponse {
        running: true,
        status,
        cdp_endpoint: endpoint,
        shared_browser_context: if shared { Some(true) } else { None },
        interception: Some(interception.to_string()),
        incognito_allowed: Some(incognito_allowed),
        cdp_exposure: Some(mode.to_string()),
    })
}
