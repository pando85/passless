//! Tests of the framed sign transport, the request parse and the response JSON.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use passless_core::agent::protocol::ErrorCode;
use passless_core::agent::{AgentRequestLimits, CredentialSelection, ProfileId, RuleAction};
use passless_core::config::SecurityConfig;

use super::frame::{FrameError, MAX_FRAME_LEN, read_frame, write_frame};
use super::webauthn::{self, Op, ParsedCeremony};
use super::{
    PeerUidSource, ReadinessRegistry, SignTransportServer, TransportOptions, build_version,
    hold_result_from, wire_error_code,
};

use crate::agent::audit::AuditGate;
use crate::agent::audit::test_support::read_audit_events;
use crate::agent::capacity::RequestLimiter;
use crate::agent::grant::GrantRequestParams;
use crate::agent::identity;
use crate::agent::policy_engine::PolicyRuntime;
use crate::agent::register::{RegisterContext, RegisterHandler};
use crate::agent::session::{AgentSession, SessionBinding};
use crate::agent::sign::tests::sign_handler_tests::{
    MockClock, RecordingKeyProvider, WriteCountingStorage, rule, test_agent_config,
    test_profile_config,
};
use crate::agent::sign::{
    SignContext, SignContextRegistry, SignHandler, b64u_decode, b64u_encode, generate_bearer_token,
};
use crate::storage::CredentialStorage;

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use soft_fido2::{
    CredentialBackupState, CredentialKeyProvider, RelyingParty, SoftwareCredentialKeyProvider, User,
};

pub(crate) const ORIGIN: &str = "https://example.com";
pub(crate) const RP_ID: &str = "example.com";
const READ_TIMEOUT: Duration = Duration::from_secs(10);

// --- fixture ---------------------------------------------------------------------------------

/// A profile with `authenticate = register = allow` for `example.com`, a dynamic grant, and
/// optionally one stored credential.
pub(crate) struct Fixture {
    pub profile_id: ProfileId,
    pub policy_runtime: Arc<PolicyRuntime>,
    pub storage: Arc<Mutex<Box<dyn CredentialStorage>>>,
    pub key_provider: Arc<RecordingKeyProvider>,
    pub operation_lock: Arc<Mutex<()>>,
    pub registry: Arc<SignContextRegistry>,
    pub audit_dir: PathBuf,
    /// SEC1 public key of the stored credential, when there is one.
    pub seeded_public_key: Option<Vec<u8>>,
    audit_gate: Arc<AuditGate>,
    grant_id: passless_core::agent::GrantId,
    _dirs: Vec<tempfile::TempDir>,
}

impl Fixture {
    pub fn new(seed: bool) -> Self {
        let audit_tmp = tempfile::tempdir().unwrap();
        let audit_dir = audit_tmp.path().join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::fs::set_permissions(&audit_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let audit_gate = Arc::new(AuditGate::open(&audit_dir).unwrap());

        let profile_id = ProfileId::new("test-profile").unwrap();
        let storage_impl = WriteCountingStorage::new();
        let mut seeded_public_key = None;
        if seed {
            let generated = SoftwareCredentialKeyProvider.generate(-7).unwrap();
            seeded_public_key = Some(generated.cose_public_key.clone());
            storage_impl.add_cred(soft_fido2::Credential {
                id: vec![1u8; 32],
                rp: RelyingParty::new(RP_ID.into()),
                user: User::new(vec![1, 2, 3]),
                sign_count: 0,
                alg: -7,
                key: generated.key,
                created: 0,
                discoverable: true,
                backup_state: CredentialBackupState::NotEligible,
                extensions: soft_fido2::Extensions::default(),
            });
        }
        let storage: Arc<Mutex<Box<dyn CredentialStorage>>> =
            Arc::new(Mutex::new(Box::new(storage_impl)));

        let profile_config = test_profile_config(
            vec![rule(RP_ID, RuleAction::Allow, RuleAction::Allow)],
            None,
            CredentialSelection::Single,
        );
        let policy_runtime = Arc::new(
            PolicyRuntime::new(
                &test_agent_config(profile_config),
                Arc::new(MockClock::new()),
                None,
            )
            .unwrap(),
        );
        let request_id = policy_runtime
            .admin_request_dynamic_grant(GrantRequestParams {
                profile_id: profile_id.clone(),
                session_id: passless_core::agent::PrincipalSessionId::new(),
                endpoint_id: passless_core::agent::EndpointId::new(),
                principal_digest: [0u8; 32],
                rp_ids: vec![RP_ID.to_string()],
                credentials: vec![],
                requested_ttl_secs: 300,
            })
            .unwrap();
        let grant_id = policy_runtime
            .admin_approve_grant(&request_id, &identity::admin_authority())
            .unwrap();

        Self {
            profile_id,
            policy_runtime,
            storage,
            key_provider: Arc::new(RecordingKeyProvider::new()),
            operation_lock: Arc::new(Mutex::new(())),
            registry: Arc::new(SignContextRegistry::new()),
            audit_dir,
            seeded_public_key,
            audit_gate,
            grant_id,
            _dirs: vec![audit_tmp],
        }
    }

    fn security_config() -> SecurityConfig {
        SecurityConfig {
            check_mlock: false,
            disable_core_dumps: false,
            constant_signature_counter: true,
            enable_credential_backup: false,
            always_uv: false,
            user_verification_registration: false,
            user_verification_authentication: false,
            notification_timeout: 0,
        }
    }

    /// A bearer with a sign and a registration context sharing one session, bound to `lease`
    /// unless `lease` is `None`.
    pub fn bearer(&self, lease: Option<&str>) -> String {
        self.bearer_for_browser_uid(lease, None)
    }

    /// Like [`Self::bearer`], with the lease's browser UID bound to the session.
    pub fn bearer_for_browser_uid(&self, lease: Option<&str>, browser_uid: Option<u32>) -> String {
        let token = generate_bearer_token().unwrap();
        let session = AgentSession::new(SessionBinding {
            profile_id: self.profile_id.clone(),
            principal_digest: [0u8; 32],
            revocation_epoch: self.policy_runtime.revocation_epoch(),
            ttl: Duration::from_secs(600),
        });
        if let Some(uid) = browser_uid {
            session.bind_browser_uid(uid);
        }
        let sign_handler = Arc::new(SignHandler {
            credential_storage: self.storage.clone(),
            policy_runtime: self.policy_runtime.clone(),
            audit_gate: self.audit_gate.clone(),
            security_config: Self::security_config(),
            key_provider: self.key_provider.clone(),
            operation_lock: self.operation_lock.clone(),
            escalation: crate::agent::escalation::test_support::idle_service(
                self.audit_gate.clone(),
            ),
        });
        let register_handler = Arc::new(RegisterHandler {
            policy_runtime: self.policy_runtime.clone(),
            credential_storage: self.storage.clone(),
            audit_gate: self.audit_gate.clone(),
            key_provider: self.key_provider.clone(),
            security_config: Self::security_config(),
            operation_lock: self.operation_lock.clone(),
            escalation: crate::agent::escalation::test_support::idle_service(
                self.audit_gate.clone(),
            ),
        });
        self.registry
            .register_pending(
                token.clone(),
                SignContext {
                    profile_id: self.profile_id.clone(),
                    active_grant_id: self.grant_id.clone(),
                    session: session.clone(),
                    lease_activation: None,
                },
                sign_handler,
            )
            .unwrap();
        self.registry
            .register_pending_registration(
                token.clone(),
                RegisterContext::new(self.profile_id.clone(), session),
                register_handler,
            )
            .unwrap();
        if let Some(lease) = lease {
            self.registry.bind_lease(&token, lease.to_string()).unwrap();
            self.registry
                .bind_registration_lease(&token, lease.to_string())
                .unwrap();
        }
        token
    }

    pub fn events(&self) -> Vec<Value> {
        read_audit_events(&self.audit_dir)
    }

    /// `(kind, reason)` of every policy record, oldest first.
    pub fn policy_records(&self) -> Vec<(String, Option<String>)> {
        self.events()
            .iter()
            .filter(|e| e["kind"].as_str().is_some_and(|k| k.starts_with("policy.")))
            .map(|e| {
                (
                    e["kind"].as_str().unwrap().to_string(),
                    e["reason"].as_str().map(str::to_string),
                )
            })
            .collect()
    }

    pub fn has_reason(&self, reason: &str) -> bool {
        self.policy_records()
            .iter()
            .any(|(_, r)| r.as_deref() == Some(reason))
    }

    /// Wait until an audit record with `reason` appears.
    pub fn wait_for_reason(&self, reason: &str) -> bool {
        let deadline = Instant::now() + READ_TIMEOUT;
        while Instant::now() < deadline {
            if self.has_reason(reason) {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        false
    }

    pub fn credential_count(&self) -> usize {
        self.storage.lock().unwrap().count_credentials()
    }
}

// --- server and client -------------------------------------------------------------------------

pub(crate) struct TestServer {
    pub sock: PathBuf,
    pub readiness: Arc<ReadinessRegistry>,
    pub limiter: Arc<RequestLimiter>,
    shutdown: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    _dir: tempfile::TempDir,
}

impl TestServer {
    pub fn start(registry: Arc<SignContextRegistry>) -> Self {
        Self::start_with(
            registry,
            AgentRequestLimits::default(),
            TransportOptions::default(),
        )
    }

    pub fn start_with(
        registry: Arc<SignContextRegistry>,
        limits: AgentRequestLimits,
        options: TransportOptions,
    ) -> Self {
        Self::start_full(registry, limits, options, None)
    }

    /// A server whose peer UIDs come from `peer_uid` instead of `SO_PEERCRED`.
    pub fn start_with_peer_uid(registry: Arc<SignContextRegistry>, peer_uid: Option<u32>) -> Self {
        Self::start_full(
            registry,
            AgentRequestLimits::default(),
            TransportOptions::default(),
            Some(Arc::new(move |_: &UnixStream| peer_uid)),
        )
    }

    fn start_full(
        registry: Arc<SignContextRegistry>,
        limits: AgentRequestLimits,
        options: TransportOptions,
        peer_uid: Option<PeerUidSource>,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("sign").join("sock");
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut server = SignTransportServer::bind(sock.clone(), shutdown.clone()).unwrap();
        if let Some(peer_uid) = peer_uid {
            server = server.with_peer_uid_source(peer_uid);
        }
        let readiness = Arc::new(ReadinessRegistry::new());
        let limiter = RequestLimiter::new(limits);
        let handle = server.serve(registry, limiter.clone(), readiness.clone(), options);
        Self {
            sock,
            readiness,
            limiter,
            shutdown,
            handle: Some(handle),
            _dir: dir,
        }
    }

    pub fn connect(&self) -> Client {
        Client::connect(&self.sock)
    }

    /// Wait until `n` requests are admitted.
    pub fn wait_admitted(&self, n: usize) {
        let deadline = Instant::now() + READ_TIMEOUT;
        while self.limiter.active() < n {
            assert!(Instant::now() < deadline, "requests were not admitted");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

pub(crate) struct Client {
    pub stream: UnixStream,
}

impl Client {
    pub fn connect(sock: &Path) -> Self {
        let stream = UnixStream::connect(sock).unwrap();
        stream.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        Self { stream }
    }

    pub fn send(&mut self, frame: Value) {
        write_frame(&mut self.stream, frame.to_string().as_bytes()).unwrap();
    }

    /// The next frame that is not a keepalive.
    pub fn next(&mut self) -> Result<Map<String, Value>, FrameError> {
        loop {
            let frame = read_frame(&mut self.stream)?;
            if frame["type"] != "keepalive" {
                return Ok(frame);
            }
        }
    }

    pub fn hello_with(&mut self, bearer: &str, attached: bool) -> Map<String, Value> {
        self.send(json!({
            "type": "hello",
            "v": 2,
            "build_version": build_version(),
            "bearer": bearer,
            "attached": attached,
            "incognito_allowed": true,
            "socket": "/unused",
        }));
        self.next().unwrap()
    }

    pub fn hello(&mut self, bearer: &str) {
        let ack = self.hello_with(bearer, true);
        assert_eq!(ack["type"], "hello", "{ack:?}");
        assert_eq!(ack["v"], 2);
        assert_eq!(ack["build_version"], build_version());
    }

    /// Send a request whose frame fields are copied from `body`, as the worker does.
    pub fn request(&mut self, id: u32, op: &str, body: &str) {
        let parsed: Value = serde_json::from_str(body).unwrap();
        let client_override = &parsed["extensions"]["remoteDesktopClientOverride"];
        self.send(json!({
            "type": "request",
            "id": id,
            "op": op,
            "timeout_ms": parsed["timeout"],
            "origin": client_override["origin"],
            "cross_origin": !client_override["sameOriginWithAncestors"].as_bool().unwrap_or(false),
            "body": body,
        }));
    }

    pub fn result(&mut self) -> Map<String, Value> {
        let frame = self.next().unwrap();
        assert_eq!(frame["type"], "result", "{frame:?}");
        frame
    }

    /// Whether the daemon closed the connection (after any frames still queued).
    pub fn closed(&mut self) -> bool {
        loop {
            match read_frame(&mut self.stream) {
                Ok(_) => continue,
                Err(FrameError::Eof) => return true,
                Err(FrameError::Io(e)) => {
                    return !matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    );
                }
                Err(_) => return true,
            }
        }
    }
}

pub(crate) fn override_entry(origin: &str, same_origin: bool) -> Value {
    json!({ "origin": origin, "sameOriginWithAncestors": same_origin })
}

pub(crate) fn get_body_with(challenge: &[u8], extra: Value) -> String {
    let mut body = json!({
        "allowCredentials": [],
        "challenge": b64u_encode(challenge),
        "extensions": { "remoteDesktopClientOverride": override_entry(ORIGIN, true) },
        "rpId": RP_ID,
        "timeout": 180000,
        "userVerification": "preferred",
    });
    merge(&mut body, extra);
    body.to_string()
}

pub(crate) fn get_body(challenge: &[u8]) -> String {
    get_body_with(challenge, json!({}))
}

pub(crate) fn create_body_with(challenge: &[u8], extra: Value) -> String {
    let mut body = json!({
        "attestation": "none",
        "authenticatorSelection": { "residentKey": "required", "userVerification": "preferred" },
        "challenge": b64u_encode(challenge),
        "excludeCredentials": [],
        "extensions": { "remoteDesktopClientOverride": override_entry(ORIGIN, true) },
        "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
        "rp": { "id": RP_ID, "name": "Example" },
        "timeout": 180000,
        "user": { "id": b64u_encode(b"user-1"), "name": "alice", "displayName": "Alice" },
    });
    merge(&mut body, extra);
    body.to_string()
}

pub(crate) fn create_body(challenge: &[u8]) -> String {
    create_body_with(challenge, json!({}))
}

/// Shallow-merge `extra` into `body` (`extensions` is merged one level deeper).
fn merge(body: &mut Value, extra: Value) {
    let Value::Object(extra) = extra else {
        return;
    };
    for (key, value) in extra {
        if key == "extensions"
            && let (Some(Value::Object(target)), Value::Object(source)) =
                (body.get_mut("extensions"), value.clone())
        {
            target.extend(source);
            continue;
        }
        body[key] = value;
    }
}

fn error_code(result: &Map<String, Value>) -> (&str, &str) {
    assert_eq!(result["ok"], false, "{result:?}");
    (
        result["error"]["code"].as_str().unwrap(),
        result["error"]["dom"].as_str().unwrap(),
    )
}

fn response_json(result: &Map<String, Value>) -> Value {
    assert_eq!(result["ok"], true, "{result:?}");
    serde_json::from_str(result["body"].as_str().unwrap()).unwrap()
}

fn b64(value: &Value) -> Vec<u8> {
    b64u_decode(value.as_str().unwrap()).unwrap()
}

/// Verify an ES256 assertion with `key` the way an RP does.
fn verify_assertion(response: &Value, key: &VerifyingKey) {
    let authenticator_data = b64(&response["response"]["authenticatorData"]);
    let client_data = b64(&response["response"]["clientDataJSON"]);
    let signature = Signature::from_der(&b64(&response["response"]["signature"])).unwrap();
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data));
    key.verify(&signed, &signature)
        .expect("signature over authenticatorData || SHA-256(clientDataJSON)");
}

fn short_options() -> TransportOptions {
    TransportOptions {
        keepalive_interval: Duration::from_millis(100),
        ..TransportOptions::default()
    }
}

// --- framing and connection handling ----------------------------------------------------------

#[test]
fn the_socket_is_owner_only_in_an_owner_only_directory() {
    let f = Fixture::new(false);
    let server = TestServer::start(f.registry.clone());
    let socket_mode = std::fs::metadata(&server.sock)
        .unwrap()
        .permissions()
        .mode();
    let dir_mode = std::fs::metadata(server.sock.parent().unwrap())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(socket_mode & 0o777, 0o600);
    assert_eq!(dir_mode & 0o777, 0o700);
}

#[test]
fn an_oversize_frame_length_closes_the_connection_before_any_payload_is_read() {
    let f = Fixture::new(false);
    let server = TestServer::start(f.registry.clone());
    let mut client = server.connect();
    // Only the length is sent. A daemon that allocated and read the payload would block here.
    std::io::Write::write_all(
        &mut client.stream,
        &((MAX_FRAME_LEN as u32) + 1).to_le_bytes(),
    )
    .unwrap();
    let error = client.next().unwrap();
    assert_eq!(error["type"], "error");
    assert_eq!(error["code"], "bad_frame");
    assert!(client.closed());
}

#[test]
fn a_payload_that_is_not_an_object_or_has_an_unknown_type_closes_the_connection() {
    let f = Fixture::new(false);
    let server = TestServer::start(f.registry.clone());
    let token = f.bearer(Some("lease"));
    let mut client = server.connect();
    client.hello(&token);
    write_frame(&mut client.stream, b"[1,2,3]").unwrap();
    assert_eq!(client.next().unwrap()["code"], "bad_frame");
    assert!(client.closed());

    let mut client = server.connect();
    client.hello(&token);
    client.send(json!({"type": "teleport"}));
    assert_eq!(client.next().unwrap()["code"], "bad_frame");
    assert!(client.closed());
}

#[test]
fn any_frame_before_hello_closes_the_connection() {
    let f = Fixture::new(true);
    let server = TestServer::start(f.registry.clone());
    f.bearer(Some("lease"));
    let mut client = server.connect();
    client.request(1, "get", &get_body(b"c1"));
    let error = client.next().unwrap();
    assert_eq!(error["type"], "error");
    assert_eq!(error["code"], "unauthorized");
    assert!(client.closed());
    assert_eq!(f.key_provider.sign_calls(), 0);
}

#[test]
fn hello_with_an_unknown_or_revoked_bearer_is_unauthorized() {
    let f = Fixture::new(false);
    let server = TestServer::start(f.registry.clone());
    let live = f.bearer(Some("lease"));

    for bearer in [
        generate_bearer_token().unwrap(),
        live[..live.len() - 1].to_string(),
    ] {
        let mut client = server.connect();
        let error = client.hello_with(&bearer, true);
        assert_eq!(error["type"], "error");
        assert_eq!(error["code"], "unauthorized");
        assert!(client.closed());
    }
    assert!(
        f.policy_records().is_empty(),
        "unknown bearers are not audited"
    );

    // A bearer revoked with its lease is refused, and the attempt is audited.
    let revoked = f.bearer(Some("lease-2"));
    f.registry.revoke_by_lease("lease-2");
    let mut client = server.connect();
    assert_eq!(client.hello_with(&revoked, true)["code"], "unauthorized");
    assert!(client.closed());
    assert_eq!(
        f.policy_records(),
        vec![(
            "policy.deny".to_string(),
            Some("bearer_revoked".to_string())
        )]
    );
    assert!(server.readiness.status(&revoked).is_none());
}

#[test]
fn hello_with_another_protocol_version_fails_closed() {
    let f = Fixture::new(false);
    let server = TestServer::start(f.registry.clone());
    let token = f.bearer(Some("lease"));
    for version in [json!(1), json!(3), json!("2"), Value::Null] {
        let mut client = server.connect();
        client.send(json!({"type": "hello", "v": version, "bearer": token}));
        assert_eq!(client.next().unwrap()["code"], "protocol_version");
        assert!(client.closed());
    }
}

#[test]
fn an_unbound_bearer_may_say_hello_but_its_requests_need_the_binding() {
    let f = Fixture::new(true);
    let server = TestServer::start(f.registry.clone());
    let token = f.bearer(None);
    let mut client = server.connect();
    client.hello(&token);
    client.request(1, "get", &get_body(b"unbound"));
    assert_eq!(
        error_code(&client.result()),
        ("unauthorized", "NotAllowedError")
    );
    client.request(2, "create", &create_body(b"unbound-create"));
    assert_eq!(error_code(&client.result()).0, "unauthorized");
    assert_eq!(f.key_provider.sign_calls(), 0);
    assert_eq!(f.credential_count(), 1);
}

#[test]
fn a_repeated_hello_updates_the_state_and_may_not_change_the_bearer() {
    let f = Fixture::new(false);
    let server = TestServer::start(f.registry.clone());
    let token = f.bearer(Some("lease"));
    let other = f.bearer(Some("lease-other"));
    let mut client = server.connect();
    let ack = client.hello_with(&token, false);
    assert_eq!(ack["type"], "hello");
    assert!(!server.readiness.status(&token).unwrap().attached);
    client.send(json!({"type": "hello", "v": 2, "bearer": token, "attached": true}));
    client.send(json!({"type": "keepalive"}));
    let deadline = Instant::now() + READ_TIMEOUT;
    while !server.readiness.status(&token).unwrap().attached {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    client.send(json!({"type": "hello", "v": 2, "bearer": other, "attached": true}));
    assert_eq!(client.next().unwrap()["code"], "unauthorized");
    assert!(client.closed());
}

#[test]
fn a_new_connection_of_the_same_bearer_supersedes_the_old_one_and_cancels_its_requests() {
    let f = Fixture::new(true);
    let server = TestServer::start(f.registry.clone());
    let token = f.bearer(Some("lease"));
    let mut old = server.connect();
    old.hello(&token);

    let op = f.operation_lock.lock().unwrap();
    old.request(1, "get", &get_body(b"superseded"));
    server.wait_admitted(1);

    let mut new = server.connect();
    new.hello(&token);
    let error = old.next().unwrap();
    assert_eq!(error["type"], "error");
    assert_eq!(error["code"], "superseded");
    assert!(old.closed());
    drop(op);

    assert!(f.wait_for_reason("aborted"), "{:?}", f.policy_records());
    assert_eq!(
        f.key_provider.sign_calls(),
        0,
        "the superseded request never signs"
    );
    new.request(1, "get", &get_body(b"after"));
    assert_eq!(new.result()["ok"], true);
    assert!(server.readiness.status(&token).unwrap().connected);
}

#[test]
fn the_daemon_writes_keepalives_while_the_connection_is_open() {
    let f = Fixture::new(false);
    let server = TestServer::start_with(
        f.registry.clone(),
        AgentRequestLimits::default(),
        short_options(),
    );
    let token = f.bearer(Some("lease"));
    let mut client = server.connect();
    client.hello(&token);
    let started = Instant::now();
    let frame = read_frame(&mut client.stream).unwrap();
    assert_eq!(frame["type"], "keepalive");
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn a_write_that_times_out_closes_the_connection() {
    let f = Fixture::new(false);
    let options = TransportOptions {
        write_timeout: Duration::from_millis(200),
        ..TransportOptions::default()
    };
    let server = TestServer::start_with(f.registry.clone(), AgentRequestLimits::default(), options);
    let token = f.bearer(Some("lease"));
    let mut client = server.connect();
    client.hello(&token);
    client
        .stream
        .set_write_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    // Every malformed request is answered at once; the client never reads, so the daemon's writes
    // block, time out, and close the connection.
    let frame = json!({"type": "request", "id": 1, "op": "nope"}).to_string();
    let started = Instant::now();
    while write_frame(&mut client.stream, frame.as_bytes()).is_ok() {
        assert!(started.elapsed() < READ_TIMEOUT, "the daemon kept reading");
    }
    thread::sleep(Duration::from_millis(500));
    assert!(client.closed(), "the daemon closed the connection");
    let deadline = Instant::now() + READ_TIMEOUT;
    while server.readiness.status(&token).unwrap().connected {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
}

// --- requests -----------------------------------------------------------------------------------

#[test]
fn every_request_revalidates_the_bearer() {
    let f = Fixture::new(true);
    let server = TestServer::start(f.registry.clone());
    let token = f.bearer(Some("lease"));
    let mut client = server.connect();
    client.hello(&token);
    client.request(1, "get", &get_body(b"first"));
    assert_eq!(client.result()["ok"], true);

    f.registry.revoke(&token);
    client.request(2, "get", &get_body(b"second"));
    assert_eq!(
        error_code(&client.result()),
        ("unauthorized", "NotAllowedError")
    );
    // The connection stays open; the bearer is refused per request.
    client.send(json!({"type": "keepalive"}));
    client.request(3, "get", &get_body(b"third"));
    assert_eq!(error_code(&client.result()).0, "unauthorized");
    assert_eq!(f.key_provider.sign_calls(), 1);
}

#[test]
fn a_revoked_registration_bearer_is_refused_per_request_and_audited() {
    let f = Fixture::new(false);
    let server = TestServer::start(f.registry.clone());
    let token = f.bearer(Some("lease"));
    let mut client = server.connect();
    client.hello(&token);
    client.request(1, "create", &create_body(b"reg-1"));
    assert_eq!(client.result()["ok"], true);
    assert_eq!(f.credential_count(), 1);

    f.registry.revoke_by_lease("lease");
    client.request(2, "create", &create_body(b"reg-2"));
    assert_eq!(error_code(&client.result()).0, "unauthorized");
    assert_eq!(f.credential_count(), 1);
    let denies: Vec<Value> = f
        .events()
        .into_iter()
        .filter(|e| e["kind"] == "policy.deny")
        .collect();
    assert_eq!(denies.len(), 1, "{denies:?}");
    assert_eq!(denies[0]["reason"], "bearer_revoked");
    assert_eq!(denies[0]["action"], "register");
    assert_eq!(denies[0]["rp_id"], RP_ID);
}

#[test]
fn a_sign_bearer_revoked_by_a_policy_change_is_refused_and_audited() {
    let f = Fixture::new(true);
    let server = TestServer::start(f.registry.clone());
    let token = f.bearer(Some("lease"));
    let mut client = server.connect();
    client.hello(&token);
    client.request(1, "get", &get_body(b"before"));
    assert_eq!(client.result()["ok"], true);

    // What a grant revocation or a reload does: bump the epoch, drop the stale bearers.
    let epoch = f.policy_runtime.bump_revocation_epoch();
    let stale = f.registry.revoke_stale_sessions(epoch);
    assert_eq!(stale.lease_ids, vec!["lease".to_string()]);

    // The late request is refused up front, and audited as a revoked bearer, not left silent.
    client.request(2, "get", &get_body(b"after"));
    assert_eq!(error_code(&client.result()).0, "unauthorized");
    assert_eq!(f.key_provider.sign_calls(), 1);
    let denies: Vec<Value> = f
        .events()
        .into_iter()
        .filter(|e| e["kind"] == "policy.deny")
        .collect();
    assert_eq!(denies.len(), 1, "{denies:?}");
    assert_eq!(denies[0]["reason"], "bearer_revoked");
    assert_eq!(denies[0]["action"], "authenticate");
    assert_eq!(denies[0]["rp_id"], RP_ID);

    // A new connection with the dead bearer is refused at hello, once per attempt.
    let mut late = server.connect();
    assert_eq!(late.hello_with(&token, true)["code"], "unauthorized");
    let denies = f
        .events()
        .into_iter()
        .filter(|e| e["kind"] == "policy.deny")
        .count();
    assert_eq!(denies, 2);
}

#[test]
fn a_revocation_epoch_change_refuses_the_next_request() {
    let f = Fixture::new(true);
    let server = TestServer::start(f.registry.clone());
    let token = f.bearer(Some("lease"));
    let mut client = server.connect();
    client.hello(&token);
    client.request(1, "get", &get_body(b"before"));
    assert_eq!(client.result()["ok"], true);

    f.policy_runtime.bump_revocation_epoch();
    client.request(2, "get", &get_body(b"after"));
    assert_eq!(error_code(&client.result()).0, "unauthorized");
    assert_eq!(
        f.policy_records().last().unwrap().1.as_deref(),
        Some("policy_revoked")
    );
    assert_eq!(f.key_provider.sign_calls(), 1);
}

#[test]
fn an_abort_before_key_use_signs_nothing_and_is_audited() {
    let f = Fixture::new(true);
    let server = TestServer::start(f.registry.clone());
    let token = f.bearer(Some("lease"));
    let mut client = server.connect();
    client.hello(&token);

    let op = f.operation_lock.lock().unwrap();
    client.request(7, "get", &get_body(b"abort-me"));
    server.wait_admitted(1);
    client.send(json!({"type": "abort", "id": 7}));
    thread::sleep(Duration::from_millis(100));
    drop(op);

    let result = client.result();
    assert_eq!(result["id"], 7);
    assert_eq!(error_code(&result), ("aborted", "AbortError"));
    assert_eq!(f.key_provider.sign_calls(), 0);
    assert_eq!(
        f.policy_records().last().unwrap().1.as_deref(),
        Some("aborted")
    );
}

#[test]
fn an_abort_after_key_use_still_gets_exactly_one_result_and_one_signature() {
    let f = Fixture::new(true);
    let server = TestServer::start_with(
        f.registry.clone(),
        AgentRequestLimits::default(),
        short_options(),
    );
    let token = f.bearer(Some("lease"));
    let mut client = server.connect();
    client.hello(&token);

    let (reached_tx, reached_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let release_rx = Arc::new(Mutex::new(release_rx));
    let reached_tx = Mutex::new(reached_tx);
    f.key_provider.set_on_sign(Some(Arc::new(move || {
        reached_tx.lock().unwrap().send(()).unwrap();
        release_rx.lock().unwrap().recv().unwrap();
    })));
    client.request(3, "get", &get_body(b"late-abort"));
    reached_rx.recv_timeout(READ_TIMEOUT).unwrap();
    client.send(json!({"type": "abort", "id": 3}));
    thread::sleep(Duration::from_millis(100));
    release_tx.send(()).unwrap();

    let result = client.result();
    assert_eq!(result["id"], 3);
    assert_eq!(
        result["ok"], true,
        "the signature was made: the result is delivered"
    );
    // No second result follows within a window; keepalives may.
    client
        .stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let window = Instant::now() + Duration::from_millis(500);
    while Instant::now() < window {
        if let Ok(frame) = read_frame(&mut client.stream) {
            assert_eq!(frame["type"], "keepalive", "exactly one result: {frame:?}");
        }
    }
    f.key_provider.set_on_sign(None);
    assert_eq!(f.key_provider.sign_calls(), 1);
}

#[test]
fn eof_cancels_every_in_flight_request() {
    let f = Fixture::new(true);
    let server = TestServer::start(f.registry.clone());
    let token = f.bearer(Some("lease"));
    let mut client = server.connect();
    client.hello(&token);

    let op = f.operation_lock.lock().unwrap();
    client.request(1, "get", &get_body(b"eof-1"));
    client.request(2, "create", &create_body(b"eof-2"));
    server.wait_admitted(2);
    drop(client);
    let deadline = Instant::now() + READ_TIMEOUT;
    while server.readiness.status(&token).unwrap().connected {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    drop(op);

    let deadline = Instant::now() + READ_TIMEOUT;
    while server.limiter.active() > 0 {
        assert!(Instant::now() < deadline, "the cancelled requests finish");
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(f.key_provider.sign_calls(), 0);
    assert_eq!(f.credential_count(), 1, "no credential was created");
    let aborted = f
        .policy_records()
        .iter()
        .filter(|(_, r)| r.as_deref() == Some("aborted"))
        .count();
    assert_eq!(aborted, 2, "{:?}", f.policy_records());
}

#[test]
fn a_duplicate_live_id_closes_the_connection_so_no_id_gets_two_results() {
    let f = Fixture::new(true);
    let server = TestServer::start(f.registry.clone());
    let token = f.bearer(Some("lease"));
    let mut client = server.connect();
    client.hello(&token);
    let op = f.operation_lock.lock().unwrap();
    client.request(5, "get", &get_body(b"dup-id-1"));
    server.wait_admitted(1);
    client.request(5, "get", &get_body(b"dup-id-2"));
    let error = client.next().unwrap();
    assert_eq!(error["type"], "error", "{error:?}");
    assert_eq!(error["code"], "bad_frame");
    assert!(client.closed(), "no result follows for either request");
    drop(op);
    // The original was cancelled with the connection, before key use.
    assert!(f.wait_for_reason("aborted"), "{:?}", f.policy_records());
    assert_eq!(f.key_provider.sign_calls(), 0);
}

#[test]
fn identical_requests_are_coalesced_into_one_signature() {
    let f = Fixture::new(true);
    let server = TestServer::start(f.registry.clone());
    let token = f.bearer(Some("lease"));
    let mut client = server.connect();
    client.hello(&token);
    let op = f.operation_lock.lock().unwrap();
    let body = get_body(b"same");
    for id in 1..=4 {
        client.request(id, "get", &body);
    }
    // The original holds its permit; the joined duplicates suspend theirs while they wait, so
    // they do not hold request slots (they are bounded per key instead).
    server.wait_admitted(1);
    let deadline = Instant::now() + READ_TIMEOUT;
    while server.limiter.active() != 1 || server.limiter.active_for_profile(&f.profile_id) != 1 {
        assert!(Instant::now() < deadline, "duplicates kept their permits");
        thread::sleep(Duration::from_millis(10));
    }
    thread::sleep(Duration::from_millis(200));
    assert_eq!(server.limiter.active(), 1);
    drop(op);
    let bodies: Vec<String> = (0..4)
        .map(|_| client.result()["body"].as_str().unwrap().to_string())
        .collect();
    assert!(bodies.windows(2).all(|w| w[0] == w[1]), "identical results");
    assert_eq!(f.key_provider.sign_calls(), 1);
}

#[test]
fn requests_over_the_connection_cap_get_an_explicit_busy_and_none_is_dropped() {
    let f = Fixture::new(true);
    let limits = AgentRequestLimits {
        max_concurrent_requests: 32,
        max_requests_per_profile: 32,
        max_requests_per_connection: 2,
        max_requests_per_session: 32,
    };
    let server = TestServer::start_with(f.registry.clone(), limits, TransportOptions::default());
    let token = f.bearer(Some("lease"));
    let mut client = server.connect();
    client.hello(&token);
    let op = f.operation_lock.lock().unwrap();
    for id in 1..=6u32 {
        client.request(id, "get", &get_body(&[b'c', id as u8]));
    }
    let mut busy = Vec::new();
    for _ in 0..4 {
        let result = client.result();
        assert_eq!(error_code(&result), ("busy", "NotAllowedError"));
        busy.push(result["id"].as_u64().unwrap());
    }
    assert_eq!(busy, vec![3, 4, 5, 6]);
    assert_eq!(f.key_provider.sign_calls(), 0);
    drop(op);
    let mut served: Vec<u64> = (0..2)
        .map(|_| {
            let result = client.result();
            assert_eq!(result["ok"], true);
            result["id"].as_u64().unwrap()
        })
        .collect();
    served.sort();
    assert_eq!(served, vec![1, 2], "no request was dropped");
    assert_eq!(f.key_provider.sign_calls(), 2);
}

#[test]
fn twenty_concurrent_ceremonies_on_one_connection_all_complete() {
    let f = Fixture::new(true);
    let limits = AgentRequestLimits {
        max_concurrent_requests: 32,
        max_requests_per_profile: 32,
        max_requests_per_connection: 32,
        max_requests_per_session: 32,
    };
    let server = TestServer::start_with(f.registry.clone(), limits, TransportOptions::default());
    let token = f.bearer(Some("lease"));
    let mut client = server.connect();
    client.hello(&token);
    for id in 1..=20u32 {
        client.request(id, "get", &get_body(&[b'p', id as u8]));
    }
    let mut ids: Vec<u64> = (0..20)
        .map(|_| {
            let result = client.result();
            assert_eq!(result["ok"], true, "{result:?}");
            result["id"].as_u64().unwrap()
        })
        .collect();
    ids.sort();
    assert_eq!(ids, (1..=20).collect::<Vec<u64>>());
    assert_eq!(f.key_provider.sign_calls(), 20);
}

#[test]
fn connections_over_the_connection_cap_are_answered_busy() {
    let f = Fixture::new(false);
    let limits = AgentRequestLimits {
        max_concurrent_requests: 1,
        max_requests_per_profile: 1,
        max_requests_per_connection: 1,
        max_requests_per_session: 1,
    };
    let server = TestServer::start_with(f.registry.clone(), limits, TransportOptions::default());
    let idle: Vec<Client> = (0..server.limiter.max_connections())
        .map(|_| server.connect())
        .collect();
    thread::sleep(Duration::from_millis(300));
    let mut over = server.connect();
    let error = over.next().unwrap();
    assert_eq!(error["type"], "error");
    assert_eq!(error["code"], "busy");
    assert!(over.closed());
    drop(idle);
}

// --- the daemon's own parse, clientDataJSON and responseJson ---------------------------------

#[test]
fn the_daemon_builds_client_data_and_the_frame_cannot_change_it() {
    let f = Fixture::new(true);
    let server = TestServer::start(f.registry.clone());
    let token = f.bearer(Some("lease"));
    let mut client = server.connect();
    client.hello(&token);

    // Stray top-level fields in the body cannot set the type, origin or challenge.
    let body = get_body_with(
        b"real-challenge",
        json!({
            "type": "webauthn.create",
            "origin": "https://evil.example",
            "clientDataJSON": "e30",
            "topOrigin": "https://evil.example",
        }),
    );
    client.request(1, "get", &body);
    let response = response_json(&client.result());
    let client_data = b64(&response["response"]["clientDataJSON"]);
    assert_eq!(
        String::from_utf8(client_data).unwrap(),
        format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}"}}"#,
            b64u_encode(b"real-challenge"),
            ORIGIN
        )
    );
    let key = VerifyingKey::from_sec1_bytes(f.seeded_public_key.as_ref().unwrap()).unwrap();
    verify_assertion(&response, &key);

    // A frame whose origin or cross-origin flag disagrees with the body is refused.
    let mut forged = get_body(b"forged");
    let mut frame: Value = json!({
        "type": "request", "id": 2, "op": "get", "timeout_ms": null,
        "origin": "https://evil.example", "cross_origin": false, "body": forged,
    });
    client.send(frame.clone());
    assert_eq!(
        error_code(&client.result()),
        ("bad_request", "NotAllowedError")
    );
    frame["id"] = json!(3);
    frame["origin"] = json!(ORIGIN);
    frame["cross_origin"] = json!(true);
    client.send(frame);
    assert_eq!(error_code(&client.result()).0, "bad_request");
    // A body without the browser's override is refused too.
    forged = json!({"challenge": "Y2g", "rpId": RP_ID}).to_string();
    client.send(json!({
        "type": "request", "id": 4, "op": "get",
        "origin": ORIGIN, "cross_origin": false, "body": forged,
    }));
    assert_eq!(error_code(&client.result()).0, "bad_request");
    assert_eq!(f.key_provider.sign_calls(), 1);
}

#[test]
fn a_cross_origin_request_is_denied_and_audited_without_a_top_origin() {
    let f = Fixture::new(true);
    let server = TestServer::start(f.registry.clone());
    let token = f.bearer(Some("lease"));
    let mut client = server.connect();
    client.hello(&token);
    let body = get_body_with(
        b"cross",
        json!({"extensions": {"remoteDesktopClientOverride": override_entry(ORIGIN, false)}}),
    );
    client.request(1, "get", &body);
    assert_eq!(
        error_code(&client.result()),
        ("forbidden", "NotAllowedError")
    );
    assert_eq!(f.key_provider.sign_calls(), 0);
    let deny = f
        .events()
        .into_iter()
        .find(|e| e["kind"] == "policy.deny")
        .unwrap();
    assert_eq!(deny["reason"], "cross_origin_denied");
    assert_eq!(deny["origin"], ORIGIN);
    assert_eq!(deny["cross_origin"], true);
    assert!(deny.get("top_origin").unwrap().is_null());
}

#[test]
fn ceremony_audit_records_carry_the_origin_context() {
    let f = Fixture::new(true);
    let server = TestServer::start(f.registry.clone());
    let token = f.bearer(Some("lease"));
    let mut client = server.connect();
    client.hello(&token);
    client.request(1, "get", &get_body(b"audited"));
    assert_eq!(client.result()["ok"], true);
    let allow = f
        .events()
        .into_iter()
        .find(|e| e["kind"] == "policy.allow")
        .unwrap();
    assert_eq!(allow["origin"], ORIGIN);
    assert_eq!(allow["cross_origin"], false);
    assert!(allow.get("top_origin").unwrap().is_null());
}

#[test]
fn unsupported_extensions_are_not_supported_but_the_browser_override_is_not_one() {
    let f = Fixture::new(true);
    let server = TestServer::start(f.registry.clone());
    let token = f.bearer(Some("lease"));
    let mut client = server.connect();
    client.hello(&token);
    client.request(
        1,
        "get",
        &get_body_with(b"prf", json!({"extensions": {"prf": {}}})),
    );
    assert_eq!(
        error_code(&client.result()),
        ("not_supported", "NotSupportedError")
    );
    client.request(
        2,
        "get",
        &get_body_with(
            b"appid",
            json!({"extensions": {"appid": "https://example.com"}}),
        ),
    );
    assert_eq!(client.result()["ok"], true);
    client.request(
        3,
        "create",
        &create_body_with(b"lb", json!({"extensions": {"largeBlob": {}}})),
    );
    assert_eq!(error_code(&client.result()).1, "NotSupportedError");
}

#[test]
fn get_response_json_has_the_webauthn_shape() {
    let f = Fixture::new(true);
    let server = TestServer::start(f.registry.clone());
    let token = f.bearer(Some("lease"));
    let mut client = server.connect();
    client.hello(&token);
    client.request(1, "get", &get_body(b"shape"));
    let response = response_json(&client.result());
    let id = b64u_encode(&[1u8; 32]);
    assert_eq!(response["id"], id);
    assert_eq!(response["rawId"], id);
    assert_eq!(response["type"], "public-key");
    assert_eq!(response["authenticatorAttachment"], "cross-platform");
    assert_eq!(response["clientExtensionResults"], json!({}));
    let inner = response["response"].as_object().unwrap();
    let mut keys: Vec<&str> = inner.keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(
        keys,
        vec![
            "authenticatorData",
            "clientDataJSON",
            "signature",
            "userHandle"
        ]
    );
    assert_eq!(b64(&response["response"]["userHandle"]), vec![1, 2, 3]);
    let authenticator_data = b64(&response["response"]["authenticatorData"]);
    assert_eq!(&authenticator_data[..32], Sha256::digest(RP_ID).as_slice());
    assert_eq!(authenticator_data[32] & 0x05, 0x05, "UP and UV");
}

#[test]
fn create_response_json_has_the_webauthn_shape_and_its_spki_verifies_a_later_assertion() {
    let f = Fixture::new(false);
    let server = TestServer::start(f.registry.clone());
    let token = f.bearer(Some("lease"));
    let mut client = server.connect();
    client.hello(&token);
    client.request(
        1,
        "create",
        &create_body_with(b"create-shape", json!({"extensions": {"credProps": true}})),
    );
    let response = response_json(&client.result());
    assert_eq!(response["type"], "public-key");
    assert_eq!(response["authenticatorAttachment"], "cross-platform");
    assert_eq!(response["id"], response["rawId"]);
    assert_eq!(
        response["clientExtensionResults"],
        json!({"credProps": {"rk": true}})
    );
    let inner = &response["response"];
    assert_eq!(inner["transports"], json!(["usb"]));
    assert_eq!(inner["publicKeyAlgorithm"], -7);
    let client_data: Value = serde_json::from_slice(&b64(&inner["clientDataJSON"])).unwrap();
    assert_eq!(
        client_data,
        json!({"type": "webauthn.create", "challenge": b64u_encode(b"create-shape"), "origin": ORIGIN})
    );
    // The attestation object is `none` and carries the same authenticator data.
    let attestation: ciborium::Value =
        ciborium::from_reader(b64(&inner["attestationObject"]).as_slice()).unwrap();
    let attestation = attestation.as_map().unwrap();
    let field = |name: &str| {
        attestation
            .iter()
            .find(|(k, _)| k.as_text() == Some(name))
            .map(|(_, v)| v.clone())
            .unwrap()
    };
    assert_eq!(field("fmt").as_text(), Some("none"));
    assert_eq!(
        field("authData").as_bytes().unwrap(),
        &b64(&inner["authenticatorData"])
    );

    // COSE -> SPKI round trip: the SPKI public key verifies an assertion of the new credential.
    let key = VerifyingKey::from_public_key_der(&b64(&inner["publicKey"])).unwrap();
    let id = response["id"].as_str().unwrap().to_string();
    client.request(
        2,
        "get",
        &get_body_with(
            b"after-create",
            json!({"allowCredentials": [{"type": "public-key", "id": id}]}),
        ),
    );
    let assertion = response_json(&client.result());
    assert_eq!(assertion["id"], id);
    assert_eq!(
        b64(&assertion["response"]["userHandle"]),
        b"user-1".to_vec()
    );
    verify_assertion(&assertion, &key);
}

// --- readiness and version skew ------------------------------------------------------------------

#[test]
fn wait_attached_wakes_on_an_attached_hello_and_times_out_otherwise() {
    let f = Fixture::new(false);
    let server = TestServer::start(f.registry.clone());
    let token = f.bearer(None);

    assert!(server.readiness.status(&token).is_none());
    assert!(
        server
            .readiness
            .wait_attached(&token, Duration::from_millis(100))
            .is_none(),
        "no hello yet: the wait times out"
    );

    let readiness = server.readiness.clone();
    let waited_for = token.clone();
    let waiter = thread::spawn(move || readiness.wait_attached(&waited_for, READ_TIMEOUT));
    let mut client = server.connect();
    let ack = client.hello_with(&token, false);
    assert_eq!(ack["type"], "hello");
    thread::sleep(Duration::from_millis(100));
    assert!(
        !waiter.is_finished(),
        "attached = false does not satisfy the wait"
    );
    client.send(json!({
        "type": "hello", "v": 2, "bearer": token, "attached": true,
        "incognito_allowed": true, "build_version": "x", "relay_version": "y",
    }));
    let state = waiter.join().unwrap().expect("woken by the attached hello");
    assert!(state.connected && state.attached && state.incognito_allowed);
    assert_eq!(state.build_version.as_deref(), Some("x"));
    assert_eq!(state.relay_version.as_deref(), Some("y"));
    assert!(state.last_disconnect.is_none());

    drop(client);
    let deadline = Instant::now() + READ_TIMEOUT;
    loop {
        let state = server.readiness.status(&token).unwrap();
        if !state.connected {
            assert!(state.last_disconnect.is_some());
            break;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        server
            .readiness
            .wait_attached(&token, Duration::from_millis(50))
            .is_none(),
        "a disconnected bearer is not ready"
    );
}

#[test]
fn version_skew_is_logged_and_audited_once_per_connection_but_not_fatal() {
    let f = Fixture::new(true);
    let server = TestServer::start(f.registry.clone());
    let token = f.bearer(Some("lease"));
    let skew_records = || {
        f.events()
            .into_iter()
            .filter(|e| e["kind"] == "transport.version_skew")
            .collect::<Vec<_>>()
    };

    let mut client = server.connect();
    let hello = json!({
        "type": "hello", "v": 2, "bearer": token, "attached": true,
        "build_version": "0.0.1+old", "relay_version": build_version(),
    });
    client.send(hello.clone());
    assert_eq!(client.next().unwrap()["type"], "hello");
    client.send(hello);
    client.request(1, "get", &get_body(b"skewed"));
    assert_eq!(client.result()["ok"], true, "skew is not fatal");
    let records = skew_records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["daemon_version"], build_version());
    assert_eq!(records[0]["build_version"], "0.0.1+old");
    assert_eq!(records[0]["relay_version"], build_version());

    let mut matching = server.connect();
    matching.hello(&token);
    assert_eq!(skew_records().len(), 1, "matching versions are not audited");
}

// --- the E2E-20 hold hook ---------------------------------------------------------------------

#[test]
fn the_hold_hook_delays_results_while_keepalives_flow_and_honours_an_abort() {
    assert_eq!(
        hold_result_from(Some("250")),
        Some(Duration::from_millis(250))
    );
    assert_eq!(hold_result_from(Some("0")), None);
    assert_eq!(hold_result_from(Some("soon")), None);
    assert_eq!(hold_result_from(None), None);

    let f = Fixture::new(true);
    let options = TransportOptions {
        keepalive_interval: Duration::from_millis(50),
        hold_result: Some(Duration::from_millis(600)),
        ..TransportOptions::default()
    };
    let server = TestServer::start_with(f.registry.clone(), AgentRequestLimits::default(), options);
    let token = f.bearer(Some("lease"));
    let mut client = server.connect();
    client.hello(&token);

    client.request(1, "get", &get_body(b"held"));
    let mut keepalives = 0;
    let result = loop {
        let frame = read_frame(&mut client.stream).unwrap();
        if frame["type"] == "keepalive" {
            keepalives += 1;
            continue;
        }
        break frame;
    };
    assert_eq!(result["ok"], true);
    assert!(
        keepalives >= 2,
        "keepalives flowed during the hold ({keepalives})"
    );

    client.request(2, "get", &get_body(b"held-aborted"));
    let deadline = Instant::now() + READ_TIMEOUT;
    while f.key_provider.sign_calls() < 2 {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
    client.send(json!({"type": "abort", "id": 2}));
    assert_eq!(error_code(&client.result()), ("aborted", "AbortError"));
}

#[test]
fn an_abort_during_the_request_hold_stops_the_ceremony_before_key_use() {
    let f = Fixture::new(true);
    let options = TransportOptions {
        hold_request: Some(Duration::from_secs(5)),
        ..TransportOptions::default()
    };
    let server = TestServer::start_with(f.registry.clone(), AgentRequestLimits::default(), options);
    let token = f.bearer(Some("lease"));
    let mut client = server.connect();
    client.hello(&token);

    let started = Instant::now();
    client.request(1, "get", &get_body(b"held-before-key-use"));
    thread::sleep(Duration::from_millis(100));
    client.send(json!({"type": "abort", "id": 1}));
    assert_eq!(error_code(&client.result()), ("aborted", "AbortError"));
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "the abort ends the hold"
    );
    assert_eq!(f.key_provider.sign_calls(), 0, "no key use after an abort");
}

// --- unit tests of the parse and the response ---------------------------------------------------

#[test]
fn a_get_body_maps_onto_the_sign_request() {
    let challenge = b"0123456789abcdef";
    let body = get_body_with(
        challenge,
        json!({
            "allowCredentials": [{"type": "public-key", "id": "AQID", "transports": ["usb"]}],
            "userVerification": "required",
            "extensions": {"appid": "https://example.com"},
            "hints": ["security-key"],
        }),
    );
    let ParsedCeremony::Get(request) = webauthn::parse_request_details(Op::Get, &body).unwrap()
    else {
        panic!("expected a get");
    };
    assert_eq!(request.origin, ORIGIN);
    assert_eq!(request.top_origin, None);
    assert!(!request.cross_origin);
    assert_eq!(request.rp_id, RP_ID);
    assert_eq!(request.challenge_b64u, b64u_encode(challenge));
    assert_eq!(request.allow_credentials, vec!["AQID".to_string()]);
    assert!(request.user_verification);
    assert_eq!(request.extensions, vec!["appid".to_string()]);
    assert_eq!(request.timeout_ms, Some(180000));
}

#[test]
fn a_create_body_maps_onto_the_registration_request() {
    let body = create_body_with(
        b"challenge",
        json!({
            "pubKeyCredParams": [
                {"type": "other", "alg": -999},
                {"type": "public-key", "alg": -8},
                {"type": "public-key", "alg": -7},
            ],
            "authenticatorSelection": {"userVerification": "required"},
            "attestation": "direct".repeat(10),
            "excludeCredentials": [{"type": "public-key", "id": "AQID=="}],
            "extensions": {"credProps": true},
            "timeout": 1234.9,
        }),
    );
    let ParsedCeremony::Create {
        request,
        cred_props,
    } = webauthn::parse_request_details(Op::Create, &body).unwrap()
    else {
        panic!("expected a create");
    };
    assert!(cred_props);
    assert_eq!(request.rp_id, RP_ID);
    assert_eq!(request.rp_name.as_deref(), Some("Example"));
    assert_eq!(request.user_id_b64u, b64u_encode(b"user-1"));
    assert_eq!(request.user_name, "alice");
    assert_eq!(request.user_display_name.as_deref(), Some("Alice"));
    assert_eq!(request.pub_key_cred_params, vec![-8, -7]);
    assert!(request.user_verification);
    assert_eq!(request.attestation.as_deref().map(str::len), Some(32));
    assert_eq!(request.exclude_credentials, vec!["AQID".to_string()]);
    assert_eq!(request.extensions, vec!["credProps".to_string()]);
    assert_eq!(request.timeout_ms, Some(1234));
    assert_eq!(request.top_origin, None);

    let defaults = create_body_with(b"c", json!({"pubKeyCredParams": []}));
    let ParsedCeremony::Create { request, .. } =
        webauthn::parse_request_details(Op::Create, &defaults).unwrap()
    else {
        panic!("expected a create");
    };
    assert_eq!(request.pub_key_cred_params, vec![-7, -257]);
}

#[test]
fn malformed_bodies_are_rejected() {
    let missing_override = json!({"challenge": "Y2g", "rpId": RP_ID}).to_string();
    let malformed_override = get_body_with(
        b"c",
        json!({"extensions": {"remoteDesktopClientOverride": {"origin": ORIGIN}}}),
    );
    let no_rp_id = {
        let mut body: Value = serde_json::from_str(&get_body(b"c")).unwrap();
        body.as_object_mut().unwrap().remove("rpId");
        body.to_string()
    };
    for body in [
        "not json".to_string(),
        "[]".to_string(),
        missing_override,
        malformed_override,
        no_rp_id,
        get_body_with(b"c", json!({"challenge": ""})),
        get_body_with(b"c", json!({"challenge": "not base64url!"})),
        get_body_with(
            b"c",
            json!({"allowCredentials": [{"type": "password", "id": "AQID"}]}),
        ),
        get_body_with(b"c", json!({"userVerification": 3})),
    ] {
        assert!(
            webauthn::parse_request_details(Op::Get, &body).is_err(),
            "{body}"
        );
    }
    for body in [
        create_body_with(b"c", json!({"user": {"id": "", "name": "a"}})),
        create_body_with(
            b"c",
            json!({"user": {"id": b64u_encode(&[0u8; 65]), "name": "a"}}),
        ),
        create_body_with(b"c", json!({"rp": {"name": "no id"}})),
        create_body_with(
            b"c",
            json!({"pubKeyCredParams": [{"type": "public-key", "alg": "x"}]}),
        ),
    ] {
        assert!(
            webauthn::parse_request_details(Op::Create, &body).is_err(),
            "{body}"
        );
    }
}

#[test]
fn spki_is_derived_from_es256_and_ed25519_cose_keys() {
    use ciborium::Value as Cbor;
    let int = |n: i64| Cbor::Integer(n.into());
    let generated = SoftwareCredentialKeyProvider.generate(-7).unwrap();
    let point = generated.cose_public_key;
    let es256 = Cbor::Map(vec![
        (int(1), int(2)),
        (int(3), int(-7)),
        (int(-1), int(1)),
        (int(-2), Cbor::Bytes(point[1..33].to_vec())),
        (int(-3), Cbor::Bytes(point[33..65].to_vec())),
    ]);
    let spki = webauthn::spki_from_cose_key(&es256).unwrap();
    let key = VerifyingKey::from_public_key_der(&spki).unwrap();
    assert_eq!(key, VerifyingKey::from_sec1_bytes(&point).unwrap());

    let ed25519 = Cbor::Map(vec![
        (int(1), int(1)),
        (int(3), int(-8)),
        (int(-1), int(6)),
        (int(-2), Cbor::Bytes(vec![7u8; 32])),
    ]);
    let spki = webauthn::spki_from_cose_key(&ed25519).unwrap();
    assert_eq!(spki.len(), 44);
    assert_eq!(&spki[spki.len() - 32..], &[7u8; 32]);

    let unknown = Cbor::Map(vec![(int(1), int(3)), (int(-1), int(0))]);
    assert!(webauthn::spki_from_cose_key(&unknown).is_none());
}

#[test]
fn wire_codes_and_dom_names_of_transport_errors() {
    use crate::agent::sign::dom_exception_name;
    assert_eq!(wire_error_code(ErrorCode::Aborted), "aborted");
    assert_eq!(dom_exception_name(ErrorCode::Aborted), "AbortError");
    assert_eq!(wire_error_code(ErrorCode::Busy), "busy");
    assert_eq!(dom_exception_name(ErrorCode::Busy), "NotAllowedError");
    assert_eq!(wire_error_code(ErrorCode::BadRequest), "bad_request");
    assert_eq!(
        dom_exception_name(ErrorCode::Unauthorized),
        "NotAllowedError"
    );
}

// --- review fixes: hello deadline, peer UID, authenticatorSelection ------------------------------

#[test]
fn the_hello_deadline_is_absolute_so_a_trickling_peer_is_closed() {
    let f = Fixture::new(false);
    let token = f.bearer(Some("lease"));
    let server = TestServer::start_with(
        f.registry.clone(),
        AgentRequestLimits::default(),
        TransportOptions {
            hello_timeout: Duration::from_millis(400),
            ..TransportOptions::default()
        },
    );
    let mut client = server.connect();
    let hello = json!({
        "type": "hello",
        "v": 2,
        "build_version": build_version(),
        "bearer": token,
        "attached": true,
        "incognito_allowed": true,
        "socket": "/unused",
    })
    .to_string();
    let mut frame = (hello.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(hello.as_bytes());
    // One byte every 100 ms for 4 s: each read finishes well within a per-read timeout of
    // 400 ms, so only an absolute deadline closes the connection before the trickle ends.
    let mut writer = client.stream.try_clone().unwrap();
    let trickle = thread::spawn(move || {
        for byte in frame.iter().take(40) {
            if std::io::Write::write_all(&mut writer, &[*byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
    });
    let started = Instant::now();
    assert!(
        client.closed(),
        "the daemon closed the trickling connection"
    );
    let closed_after = started.elapsed();
    trickle.join().unwrap();
    assert!(
        closed_after < Duration::from_millis(2500),
        "closed after {closed_after:?}, not at the 400 ms hello deadline"
    );
    assert!(
        server.readiness.status(&token).is_none(),
        "no hello recorded"
    );
}

#[test]
fn a_hello_from_a_peer_with_another_uid_is_refused_and_audited() {
    let f = Fixture::new(false);
    let own_uid = unsafe { libc::geteuid() };
    let server = TestServer::start_with_peer_uid(f.registry.clone(), Some(own_uid + 1));
    let token = f.bearer(Some("lease"));
    let mut client = server.connect();
    let ack = client.hello_with(&token, true);
    assert_eq!(ack["type"], "error");
    assert_eq!(ack["code"], "unauthorized");
    assert!(client.closed());
    assert!(server.readiness.status(&token).is_none());
    let refused = f
        .events()
        .into_iter()
        .find(|e| e["kind"] == "transport.peer_refused")
        .expect("the refusal is audited");
    assert_eq!(refused["expected_uid"], own_uid);
    assert_eq!(refused["peer_uid"], own_uid + 1);

    // A peer whose UID the kernel did not report is refused too.
    let server = TestServer::start_with_peer_uid(f.registry.clone(), None);
    let mut client = server.connect();
    assert_eq!(client.hello_with(&token, true)["code"], "unauthorized");
}

#[test]
fn a_hello_is_accepted_from_the_bound_browser_uid_only() {
    let f = Fixture::new(false);
    let own_uid = unsafe { libc::geteuid() };
    let browser_uid = own_uid + 7;
    let token = f.bearer_for_browser_uid(Some("lease"), Some(browser_uid));

    // The relay runs as the browser user: accepted, although it is not the daemon's UID.
    let server = TestServer::start_with_peer_uid(f.registry.clone(), Some(browser_uid));
    server.connect().hello(&token);

    // The daemon's own UID is not the browser user: refused.
    let server = TestServer::start_with_peer_uid(f.registry.clone(), Some(own_uid));
    let mut client = server.connect();
    assert_eq!(client.hello_with(&token, true)["code"], "unauthorized");
}

#[test]
fn a_hello_from_the_same_uid_is_accepted_through_so_peercred() {
    let f = Fixture::new(false);
    let token = f.bearer_for_browser_uid(Some("lease"), Some(unsafe { libc::geteuid() }));
    let server = TestServer::start(f.registry.clone());
    server.connect().hello(&token);
}

#[test]
fn a_per_uid_socket_needs_a_root_daemon() {
    if unsafe { libc::geteuid() } == 0 {
        return; // The refusal path only exists for a non-root daemon.
    }
    let dir = tempfile::tempdir().unwrap();
    let mut server = SignTransportServer::bind(
        dir.path().join("sign").join("sock"),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let err = server.add_uid_socket(4242, 4242).unwrap_err();
    assert!(err.contains("not running as root"), "{err}");
    assert!(!dir.path().join("sign").join("4242").exists());
}

#[test]
fn a_platform_attachment_is_not_supported_but_cross_platform_is_fine() {
    let f = Fixture::new(false);
    let server = TestServer::start(f.registry.clone());
    let token = f.bearer(Some("lease"));
    let mut client = server.connect();
    client.hello(&token);
    client.request(
        1,
        "create",
        &create_body_with(
            b"platform",
            json!({"authenticatorSelection": {"authenticatorAttachment": "platform"}}),
        ),
    );
    assert_eq!(
        error_code(&client.result()),
        ("not_supported", "NotSupportedError")
    );
    assert_eq!(f.credential_count(), 0);
    assert!(
        f.has_reason("unsupported_option"),
        "{:?}",
        f.policy_records()
    );

    client.request(
        2,
        "create",
        &create_body_with(
            b"roaming",
            json!({"authenticatorSelection": {
                "authenticatorAttachment": "cross-platform",
                "residentKey": "discouraged",
                "requireResidentKey": false,
            }}),
        ),
    );
    assert_eq!(client.result()["ok"], true);
    assert_eq!(f.credential_count(), 1);
}

#[test]
fn authenticator_selection_members_are_type_checked() {
    let parse = |selection: Value| {
        webauthn::parse_request_details(
            Op::Create,
            &create_body_with(b"c", json!({ "authenticatorSelection": selection })),
        )
    };
    for bad in [
        json!({"authenticatorAttachment": 1}),
        json!({"residentKey": true}),
        json!({"requireResidentKey": "yes"}),
    ] {
        assert!(parse(bad.clone()).is_err(), "{bad}");
    }
    let attachment = |selection: Value| match parse(selection).unwrap() {
        ParsedCeremony::Create { request, .. } => request.authenticator_attachment,
        _ => panic!("expected a create"),
    };
    assert_eq!(
        attachment(json!({"authenticatorAttachment": "platform"})).as_deref(),
        Some("platform")
    );
    assert_eq!(
        attachment(json!({"residentKey": "required", "requireResidentKey": true})),
        None
    );
    // An unknown enum value is carried and ignored by the handler, as WebAuthn requires.
    assert_eq!(
        attachment(json!({"authenticatorAttachment": "hybrid-thing"})).as_deref(),
        Some("hybrid-thing")
    );
}

#[test]
fn the_transport_deadline_follows_chromiums_clamp() {
    let received = Instant::now();
    let three_min = Duration::from_secs(180);
    let twenty_h = Duration::from_secs(20 * 3600);
    assert_eq!(
        super::transport_ceremony_deadline(None, received),
        received + twenty_h,
        "no page timeout: 20 h"
    );
    assert_eq!(
        super::transport_ceremony_deadline(Some(1_000), received),
        received + three_min,
        "a short page timeout is raised to 3 min"
    );
    assert_eq!(
        super::transport_ceremony_deadline(Some(600_000), received),
        received + Duration::from_secs(600)
    );
    assert_eq!(
        super::transport_ceremony_deadline(Some(u64::MAX), received),
        received + twenty_h,
        "a long page timeout is capped at 20 h"
    );
}
