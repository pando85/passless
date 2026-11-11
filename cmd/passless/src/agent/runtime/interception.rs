//! WebAuthn interception readiness of browser leases (plan D6 layer 1).
//!
//! A launch reports success only after the lease's extension worker said hello with
//! `attached = true` (`BrowserProcessManager::await_interception`), and only then opens the start
//! URL (defect B2). Afterwards a lease whose worker stays detached for longer than
//! `INTERCEPTION_DEGRADED_GRACE` is degraded: `browser status` reports it, the principal bootstrap
//! (`EnsureBrowser`) withholds its CDP endpoint until the worker re-attaches, and the runtime loop
//! logs and audits the change once.
//!
//! The degraded state is evaluated lazily from the readiness registry (the bearer's
//! `detached_since`), so status and bootstrap are exact whenever they are asked. The audit record
//! comes from the runtime loop, which re-evaluates every live lease about every 50 ms
//! (`poll_interception`) and records each change once, whether or not anybody asks; the transport's
//! disconnect path would only know that a grace period started, not that it ran out.
//!
//! What "degraded" means (ADR 0014 sections 7 and 11): the daemon cannot currently confirm the
//! interception, not that requests go native. The proxy attachment is browser-side state that
//! outlives the worker, so while the extension stays loaded a request wakes a stopped or
//! disconnected worker and is delivered to it. Only a lost or failed attachment (the worker
//! reports `attached = false`) would leave requests to the browser's native path; containing that
//! case is the private `/dev` (plan D6 layer 3, `containment.rs`), not this layer.
//!
//! "Attached" includes incognito access (plan D4): a worker that reports
//! `isAllowedIncognitoAccess() = false` would leave off-the-record and CDP-created contexts
//! unintercepted, so its launch fails and its endpoint is withheld like a degraded one.
//!
//! In port mode the withholding is discovery hygiene, not a boundary: the launcher removes
//! Chromium's `DevToolsActivePort` from the profile once it has read the endpoint, and the
//! `cdp-endpoint` file the daemon writes into the lease directory exists only while the lease is
//! attached, but a same-UID agent can still find the loopback listener (`/proc/net/tcp` and the
//! descriptors of its own processes) and DevTools' `/json/version` names the WebSocket URL. Port
//! mode trusts the local environment (ADR 0014 section 4.3); what a request that bypasses the
//! extension could reach is bounded by the private `/dev` either way.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use log::{info, warn};

use passless_core::agent::BrowserLeaseId;
use passless_core::agent::protocol::{ErrorCode, ProtocolError, RecommendedAction};

use super::AgentRuntime;
use crate::agent::audit_events::{BrowserLeaseInterceptionBuilder, InterceptionAuditState};
use crate::agent::browser::{
    BrowserProcessManager, INTERCEPTION_DEGRADED_GRACE, InterceptionState,
};
use crate::agent::transport::ReadinessRegistry;

impl AgentRuntime {
    /// The interception state and incognito access of a lease, as `browser status` and an admin
    /// launch report them. `(None, None)` for a lease without the extension.
    pub(super) fn lease_interception_report(
        &self,
        browser_manager: &BrowserProcessManager,
        lease_id: &BrowserLeaseId,
    ) -> (Option<String>, Option<bool>) {
        match browser_manager.interception_state(
            lease_id,
            &self.sign_readiness,
            INTERCEPTION_DEGRADED_GRACE,
        ) {
            Some((state, readiness)) => (
                Some(state.to_string()),
                readiness.map(|r| r.incognito_allowed),
            ),
            None => (None, None),
        }
    }

    /// The sign socket a browser running as `browser_uid` connects to: the daemon's own for the
    /// daemon's UID, otherwise that UID's socket (`SignTransportServer::add_uid_socket`). An
    /// unavailable socket is a launch error with the reason.
    pub(super) fn sign_socket_for(&self, browser_uid: u32) -> Result<PathBuf, ProtocolError> {
        sign_socket_for(
            browser_uid,
            self.daemon_uid,
            &self.sign_socket_path,
            &self.sign_uid_sockets,
        )
        .map_err(|why| {
            ProtocolError::new(
                ErrorCode::Forbidden,
                format!("cannot launch a managed browser as uid {browser_uid}: {why}"),
                RecommendedAction::FixRequest,
            )
        })
    }

    /// Before the bootstrap hands out an existing lease's endpoint (see [`require_attached`]).
    pub(super) fn require_attached_interception(
        &self,
        browser_manager: &mut BrowserProcessManager,
        lease_id: &BrowserLeaseId,
    ) -> Result<(InterceptionState, bool), ProtocolError> {
        require_attached(
            browser_manager,
            &self.sign_readiness,
            lease_id,
            INTERCEPTION_DEGRADED_GRACE,
        )
    }

    /// Opens a lease's deferred start URL once its interception is ready. A failure is logged,
    /// not fatal: the browser is usable, it just shows a blank page.
    pub(super) fn open_deferred_start_url(
        &self,
        browser_manager: &mut BrowserProcessManager,
        lease_id: &BrowserLeaseId,
    ) {
        match browser_manager.open_deferred_start_url(lease_id) {
            Ok(Some(url)) => info!("browser lease {}: opened start URL {}", lease_id, url),
            Ok(None) => {}
            Err(e) => warn!(
                "browser lease {}: failed to open the start URL: {}",
                lease_id, e
            ),
        }
    }

    /// Logs and audits every lease whose interception became degraded or re-attached since the
    /// last call (called from the runtime loop with the browser manager held).
    pub(super) fn report_interception_transitions(
        &self,
        browser_manager: &mut BrowserProcessManager,
    ) {
        for transition in
            browser_manager.poll_interception(&self.sign_readiness, INTERCEPTION_DEGRADED_GRACE)
        {
            let state = if transition.degraded {
                warn!(
                    "browser lease {} (profile={}): WebAuthn interception degraded, the extension \
                     worker has not re-attached within {} s; its CDP endpoint is withheld",
                    transition.lease_id,
                    transition.profile_id,
                    INTERCEPTION_DEGRADED_GRACE.as_secs()
                );
                InterceptionAuditState::Degraded
            } else {
                info!(
                    "browser lease {} (profile={}): WebAuthn interception re-attached",
                    transition.lease_id, transition.profile_id
                );
                InterceptionAuditState::Attached
            };
            let _ = self.audit_gate.record(
                BrowserLeaseInterceptionBuilder::new(
                    transition.lease_id,
                    transition.profile_id,
                    state,
                )
                .build(),
            );
        }
    }
}

/// See [`AgentRuntime::sign_socket_for`].
pub(super) fn sign_socket_for(
    browser_uid: u32,
    daemon_uid: u32,
    daemon_socket: &Path,
    uid_sockets: &HashMap<u32, Result<PathBuf, String>>,
) -> Result<PathBuf, String> {
    if browser_uid == daemon_uid {
        return Ok(daemon_socket.to_path_buf());
    }
    match uid_sockets.get(&browser_uid) {
        Some(Ok(path)) => Ok(path.clone()),
        Some(Err(why)) => Err(why.clone()),
        None => Err(format!(
            "the daemon has no sign socket for browser uid {browser_uid} (browser_user changed \
             since the daemon started?); restart the agent daemon"
        )),
    }
}

/// The bootstrap's check before it hands out an existing lease's endpoint: the lease must be
/// attached. A lease whose worker is reconnecting gets the rest of its grace period to re-attach; a
/// degraded lease (or one without the extension) is refused until it re-attaches. Returns the state
/// to report and the worker's incognito access.
fn require_attached(
    browser_manager: &mut BrowserProcessManager,
    readiness: &ReadinessRegistry,
    lease_id: &BrowserLeaseId,
    grace: Duration,
) -> Result<(InterceptionState, bool), ProtocolError> {
    let degraded = || {
        ProtocolError::new(
            ErrorCode::Conflict,
            "the managed browser's WebAuthn interception is degraded: its passless extension \
             worker is not attached, or is not allowed in incognito, so the CDP endpoint is \
             withheld until it re-attaches (see `passless agent browser-status`)",
            RecommendedAction::RetryWithBackoff,
        )
    };
    let Some((state, status)) = browser_manager.interception_state(lease_id, readiness, grace)
    else {
        return Err(degraded());
    };
    match state {
        InterceptionState::Attached => Ok((state, status.is_some_and(|r| r.incognito_allowed))),
        InterceptionState::Pending => {
            let remaining = status
                .as_ref()
                .and_then(|r| r.detached_since)
                .map(|since| grace.saturating_sub(since.elapsed()))
                .unwrap_or_default();
            match browser_manager.await_reattach(lease_id, readiness, remaining) {
                Ok(status) => Ok((InterceptionState::Attached, status.incognito_allowed)),
                Err(e) => {
                    warn!("browser lease {} did not re-attach: {}", lease_id, e);
                    Err(degraded())
                }
            }
        }
        InterceptionState::Degraded => Err(degraded()),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Instant;

    use passless_core::agent::config::CdpExposeMode;
    use passless_core::agent::{EndpointId, ProfileId};

    use super::*;
    use crate::agent::browser::{
        AgentEndpointMetadata, BrowserConfig, DirectExecSpawner, MockClock,
    };

    const BEARER: &str = "bootstrap-test-bearer";

    struct Fixture {
        _dir: tempfile::TempDir,
        mgr: BrowserProcessManager,
        readiness: ReadinessRegistry,
        lease_id: BrowserLeaseId,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.mgr.terminate(&self.lease_id);
        }
    }

    /// A launched lease whose worker attached, as `finish_principal_browser_launch` leaves it.
    fn attached_lease() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let runtime_root = dir.path().join("runtime-root");
        std::fs::create_dir_all(&runtime_root).unwrap();
        std::fs::set_permissions(&runtime_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let config = BrowserConfig {
            executable: PathBuf::from("/bin/sleep"),
            start_url: None,
            extra_args: vec!["60".to_string()],
            runtime_root,
            ttl: Duration::from_secs(300),
            login_timeout: Duration::from_secs(120),
            rp_ids: vec!["example.com".to_string()],
            start_url_rules: Vec::new(),
            target_uid: uid,
            target_gid: gid,
            daemon_uid: 0,
            daemon_gid: 0,
            cdp_expose: CdpExposeMode::Pipe,
            cdp_port: 0,
            bind_parent_death: true,
        };
        let mut mgr = BrowserProcessManager::with_spawner(
            Arc::new(MockClock::new()),
            Arc::new(DirectExecSpawner),
        );
        let metadata = AgentEndpointMetadata {
            socket_path: "/tmp/test/sock".to_string(),
            bearer_token: BEARER.to_string(),
        };
        let lease_id = mgr
            .launch_pending_with_agent_endpoint(
                &config,
                EndpointId::new(),
                ProfileId::new("test-profile").unwrap(),
                Some(&metadata),
            )
            .unwrap();
        let readiness = ReadinessRegistry::new();
        readiness.simulate_hello(BEARER, 1, true, true);
        mgr.await_interception(&lease_id, &readiness, Duration::from_secs(1))
            .unwrap();
        Fixture {
            _dir: dir,
            mgr,
            readiness,
            lease_id,
        }
    }

    const GRACE: Duration = INTERCEPTION_DEGRADED_GRACE;

    #[test]
    fn bootstrap_hands_out_an_attached_lease() {
        let mut f = attached_lease();
        let (state, incognito) =
            require_attached(&mut f.mgr, &f.readiness, &f.lease_id, GRACE).unwrap();
        assert_eq!(state, InterceptionState::Attached);
        assert!(incognito);
    }

    #[test]
    fn bootstrap_refuses_a_degraded_lease_until_it_re_attaches() {
        let mut f = attached_lease();
        f.readiness.simulate_disconnect(BEARER, 1);
        f.readiness
            .backdate_detached(BEARER, GRACE + Duration::from_secs(1));

        let started = Instant::now();
        let err = require_attached(&mut f.mgr, &f.readiness, &f.lease_id, GRACE).unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "no wait once degraded"
        );
        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(err.message.contains("degraded"), "{}", err.message);
        assert!(err.message.contains("withheld"), "{}", err.message);

        // Attached without incognito access is still withheld (plan D4, D6.1).
        f.readiness.simulate_hello(BEARER, 2, true, false);
        let err = require_attached(&mut f.mgr, &f.readiness, &f.lease_id, GRACE).unwrap_err();
        assert_eq!(err.code, ErrorCode::Conflict);
        assert!(err.message.contains("incognito"), "{}", err.message);

        f.readiness.simulate_hello(BEARER, 2, true, true);
        let (state, incognito) =
            require_attached(&mut f.mgr, &f.readiness, &f.lease_id, GRACE).unwrap();
        assert_eq!(state, InterceptionState::Attached);
        assert!(incognito);
    }

    #[test]
    fn bootstrap_waits_out_the_grace_period_for_a_reconnecting_worker() {
        let mut f = attached_lease();
        f.readiness.simulate_disconnect(BEARER, 1);
        let readiness = &f.readiness;
        let (state, _) = std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(200));
                readiness.simulate_hello(BEARER, 2, true, true);
            });
            require_attached(&mut f.mgr, readiness, &f.lease_id, GRACE)
        })
        .unwrap();
        assert_eq!(state, InterceptionState::Attached);
    }

    #[test]
    fn bootstrap_refuses_a_worker_that_does_not_reconnect_within_the_grace_period() {
        let mut f = attached_lease();
        f.readiness.simulate_disconnect(BEARER, 1);
        let started = Instant::now();
        let err = require_attached(
            &mut f.mgr,
            &f.readiness,
            &f.lease_id,
            Duration::from_millis(300),
        )
        .unwrap_err();
        assert!(started.elapsed() >= Duration::from_millis(250));
        assert_eq!(err.code, ErrorCode::Conflict);
    }

    #[test]
    fn a_browser_of_the_daemon_uid_uses_the_daemon_socket() {
        let daemon = Path::new("/run/agent/sign/sock");
        let none = HashMap::new();
        assert_eq!(
            sign_socket_for(1000, 1000, daemon, &none).unwrap(),
            daemon.to_path_buf()
        );
    }

    #[test]
    fn a_browser_of_another_uid_uses_its_own_socket_or_is_refused_with_the_reason() {
        let daemon = Path::new("/run/agent/sign/sock");
        let mut sockets = HashMap::new();
        sockets.insert(2000, Ok(PathBuf::from("/run/agent/sign/2000/sock")));
        sockets.insert(
            3000,
            Err(
                "the daemon is not running as root, so it cannot give browser user 3000 its own \
                 sign socket"
                    .to_string(),
            ),
        );
        assert_eq!(
            sign_socket_for(2000, 1000, daemon, &sockets).unwrap(),
            PathBuf::from("/run/agent/sign/2000/sock")
        );
        let refused = sign_socket_for(3000, 1000, daemon, &sockets).unwrap_err();
        assert!(refused.contains("not running as root"), "{refused}");
        let unknown = sign_socket_for(4000, 1000, daemon, &sockets).unwrap_err();
        assert!(unknown.contains("restart the agent daemon"), "{unknown}");
    }
}
