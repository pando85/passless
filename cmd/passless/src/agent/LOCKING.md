# Agent lock order

Every mutex, `RwLock` and condvar in `cmd/passless/src/agent/` (plus the human operation lock in
`main.rs` that same-user profiles share) is listed here with its place in one acquisition order. A
thread may acquire a lock only when every lock it already holds ranks lower. Two locks of the same
rank never nest. This is plan finding V-M1 of `docs/plans/agent-delegation-implementation.md`.

The order is checked in debug builds by `lock_order.rs`: tracked acquisitions declare their
`LockLevel`, and an acquisition that breaks the order panics before the thread blocks. The checks
compile away in release builds. Tests drive the ceremony, reload and launch paths through these
checks (for example `sign_path_follows_the_lock_order`, and the `lock_order` unit tests).

## Rules

1. **Ascending order.** Acquire in the order of the table below. `T` marks locks whose
   acquisitions are tracked by `lock_order.rs`.
2. **Policy locks are leaves.** No policy guard is held across any other acquisition, including
   another policy lock. `PolicyRuntime` helpers that touch several of its maps take them one after
   another and release each before the next (`invalidate_ceremony`, `abandon_pending`,
   `principal_cancel_pending`, `cleanup_expired_pending`, `cancel_pending_for_session`, `reload`).
   The only policy lock held across others is `reload_lock`, which ranks below them.
3. **No lock across a wait on a human, an escalation or a join.** A joined duplicate waits on its
   in-flight slot's condvar holding no other lock. P7's escalation wait must hold no lock either:
   its waiters park on the escalation mutex's condvar, which is a leaf.
4. **The backend operation lock is held only for the bounded key-use section.** In same-user mode
   it is the human authenticator's operation lock (`main.rs`), so agent ceremonies do take it:
   invariant 17 requires counters and credential updates to share the backend lock. They take it
   only after the replay key and budget are claimed, for credential selection, the audit
   reservation, the pre-key-use re-check and key use (`SignHandler::sign_fresh`,
   `RegisterHandler::register_fresh`). They never take it while waiting for a duplicate, an
   escalation, a human or the browser manager, and never while holding a policy, session or
   registry guard. The browser lease is activated after the operation lock is released
   (`BrowserLeaseActivation`), and only until it has succeeded once. The human path recovers a
   poisoned operation lock (`main.rs::lock_operation`), because it guards no data.
5. **The audit gate is a terminal leaf.** `AuditGate::record` may be called with any of the locks
   above held. It never acquires a lock outside the audit gate. Inside it, `append_lock` serializes
   whole records, including segment rotation.
6. **Key-use gates.** From the pre-key-use re-check to the end of key use (the signature, or the
   credential write), a ceremony holds the read side of its session's gate and of the revocation
   epoch gate. `AgentSession::revoke` and `PolicyRuntime::bump_revocation_epoch` take the write
   side. A revocation therefore either happens before the re-check, which then fails, or waits
   for the key use that already passed it. Once a revocation has returned, no operation it
   revoked can use a key. The gates are never held across a join, an escalation wait, a human or
   the browser manager.

## Order

| Rank | Lock | Declared at | Notes |
|---|---|---|---|
| 5 T | `managed_sessions[profile]` slot | `runtime.rs` (`AgentRuntime.managed_sessions`) | Held by `handle_principal` for one whole principal request. It is the outermost runtime lock. |
| 10 T | `ProfileRuntime::lifecycle_lock` | `runtime.rs` (`ProfileRuntime`) | Makes browser launch and delegation single-flight per profile. |
| 20 T | Backend operation lock | `backend.rs` (`CredentialBackendHandle.operation_lock`); the human one in `main.rs` (`ServiceHandler.operation_lock`) | See rule 4. Admin credential handlers take it before storage. |
| 25 | Human `ServiceHandler.service` | `main.rs` | Human CTAP path only: operation lock, then service, then storage. |
| 30 T | `BrowserProcessManager` | `runtime.rs` (`AgentRuntime.browser_manager`) | Launch, status, control, cleanup and the runtime loop. During a ceremony it is taken only by `BrowserLeaseActivation::activate`, after the operation lock is released, and only until the lease is active. |
| 35 | Profile bookkeeping: `endpoint_id`, `active_browser`, `shared_browsers` | `runtime.rs` (`ProfileRuntime`) | Short sections, under `browser_manager` on the launch path. They never nest with each other. |
| 40 T | Backend credential storage, and `pin_storage` | `backend.rs`, `runtime.rs` (`ProfileRuntime.credential_storage`) | The browser launch reads storage under `browser_manager`. Ceremonies release storage before key use (see "Fixed in P5"). |
| 45 T | `AgentRuntime::agent_config` (`RwLock`) | `runtime.rs` | Read for the live profile configuration on launch. A reload holds the write guard across `PolicyRuntime::reload` and releases it before closing browsers. |
| 50 T | `SignContextRegistry` maps: `entries`, `registration_entries`, `revoked_registrations` | `sign.rs` | They never nest. Each guard is released before the next map is locked and before a session is revoked. |
| 55 T | `RequestLimiter::profiles` | `capacity.rs` | Per-profile request counters; a short section with nothing nested. |
| 60 T | `AgentSession::state` (replay table and budget) | `session.rs` | Taken by `claim`, `record_completion` and `operations_used`. Never held across the in-flight slot. |
| 65 T | `InFlight::outcome` and its condvar | `session.rs` | Joined duplicates park here, holding nothing else. The original publishes here first and only then records completion in the session table. |
| 66 T | `AgentSession::key_use` gate (`RwLock`) | `session.rs` | Rule 6. Read by a ceremony from the re-check to the end of key use; write by `AgentSession::revoke` (called after registry guards are released or, in `revoke_all`, under them). |
| 68 T | `PolicyRuntime::reload_lock` | `policy_engine.rs` | Serializes reloads. It is held across the epoch gate and the policy locks of rank 70. |
| 69 T | `PolicyRuntime::key_use_gate` (`RwLock`) | `policy_engine.rs` | Rule 6. Read by a ceremony after its session gate; write by `bump_revocation_epoch` (under `reload_lock` on a reload). |
| 70 T | `PolicyRuntime`: `current` (`RwLock`), `intents`, `grants`, `pending`, `pending_requests` | `policy_engine.rs` | Leaves (rule 2). `grants` may call the audit gate. |
| 72 T | `ReadinessRegistry::entries` and its condvar | `transport/readiness.rs` | A leaf. The hello path records into it and the launch path reads or waits on it (`status`, `wait_attached`), possibly holding `lifecycle_lock` (10) and `browser_manager` (30). Waiters park on its condvar holding nothing else. The hello path never takes the lifecycle lock or the browser manager. |
| 74 T | Sign transport: `Shared::connections` and each `Connection::in_flight` | `transport/mod.rs` | Leaves; they never nest with each other. Short map sections only: a connection to supersede is cloned out before it is closed. |
| 76 T | A transport connection's write mutex (`Connection::writer`) | `transport/mod.rs` | A leaf. Held across one frame write, bounded by the 5 s write timeout. `closed` is set under it, so no frame follows a close. |
| 80 | P7 escalation service mutex (reserved) | — | A leaf. It must never be taken with the operation lock, a policy guard or a session guard held. Waiters use its condvar holding nothing else. |
| 90 | `AuditGate`: `append_lock`, then `sequence`, `last_hash`, `writer`, `current_segment(_name)`, `segment_index`, `anchor`, `anchor_inode`, `segment_file_ino` | `audit.rs` | Terminal leaf (rule 5). |
| — | TPM `Context` mutex | `storage/tpm/portable/provider.rs` | A leaf inside the TPM key provider. It is released before the provider returns. |
| — | `runtime_loop`, `sign_server_handle`, `WorkerTracker.handles`, `completed_sessions` | `runtime.rs` | Join-handle and bookkeeping locks. They never nest with the locks above. A `join()` under them only joins threads that do not take them. |
| — | Relay (`sign-proxy`): `Relay::output`, `Relay::in_flight` | `bin/sign-proxy.rs` | A separate process. The two never nest: an id is retired or drained under `in_flight`, which is released before a frame is written under `output`. |

## Ceremony paths

**Sign** (`SignHandler::sign_with`, the check order of ADR 0014 section 9):

- Steps 1 to 6 (session, origin, grant, resolve, options, replay key and budget) take only leaf
  locks, one at a time: policy (70), session (60) and audit (90).
- A duplicate then joins the in-flight slot (65), holding nothing else.
- A fresh key takes the operation lock (20), then storage (40). Under both it takes policy (70)
  and audit (90) for the reservation. For the pre-key-use re-check it takes the session gate
  (66) and the epoch gate (69), then policy (70) to re-resolve.
- The counter is written, storage is released, and the key provider signs. Then the gates and
  the operation lock are released.
- With no lock held, `BrowserLeaseActivation` takes `browser_manager` (30) until the lease is
  active. The assertion is released only if that succeeds.
- On completion it publishes to the in-flight slot (65) and records the outcome in the session
  (60), one after the other.

**Register** follows the same path without the lease activation; its gates are held until the
credential is written.

**Sign transport** (`transport/mod.rs`). The connection's reader thread authenticates `hello`
through the registry maps (50) and the session and policy reads of the bearer, one at a time;
records the hello in the readiness registry (72); then, if it superseded another connection, takes
the connection table (74) to find it and that connection's write mutex (76) to close it. Each
`request` re-validates the bearer through the registry (50), is admitted by the request limiter
(55), and is tracked in the in-flight table (74); its ceremony then runs on its own thread with no
transport lock held, following the sign or register path above. The result is written under the
write mutex (76) alone. A close sets `closed` under the write mutex, releases it, and only then
takes the in-flight table (74) to cancel every request. The keepalive writer takes only the write
mutex.

**Browser launch** (`handle_ensure_browser`) takes these locks in this order:

1. the `managed_sessions` slot (5);
2. `lifecycle_lock` (10);
3. `browser_manager` (30);
4. while `browser_manager` is held, briefly: bookkeeping (35), `agent_config` (45), storage (40)
   and then registry (50), and policy `grants` (70). Each of these is acquired and released
   separately.
5. while `browser_manager` is held, the wait for the extension worker's attached `hello`
   (`await_interception`, or `await_reattach` for an existing lease): it parks on the readiness
   condvar (72) holding nothing else of rank above 30, and the transport's hello path that wakes
   it takes only the registry maps (50) and the readiness registry (72).

The admin `browser launch` (`handle_launch_browser`) takes `browser_manager` (30) without the
lifecycle lock and then follows steps 4 and 5. The runtime loop reads the readiness registry (72)
under `browser_manager` to find degraded leases (`poll_interception`), then records their audit
events (90).

**Reload** (`handle_reload_policy`) takes these locks in this order:

1. `agent_config` write (45);
2. `reload_lock` (68);
3. each policy lock in turn (70);
4. then everything is released, and `revoke_stale_sessions` takes the registry maps (50);
5. finally browser cleanup takes the bookkeeping locks and `browser_manager`.

## Fixed in P5

- **Storage and browser manager deadlock.** A sign held storage and then took `browser_manager`
  inside `AssertionActivatingKeyProvider`. A browser launch held `browser_manager` and then read
  storage. Signing now releases storage after the counter write and before key use.
- **Audit rotation deadlock.** `AuditGate::record` took `sequence`, `last_hash` and `writer`, while
  segment rotation took the reverse order, so two concurrent records could deadlock. Records are
  now serialized by `append_lock`. This also stops another record from interleaving between
  computing a sequence number and writing it.
- **Human lock held across the browser manager** (P5 review H1). Lease activation moved out of the
  key provider, after the operation lock is released.
- **Revocation between re-check and key use** (P5 review M1). The key-use gates (rule 6).
- **Nested policy locks.** `pending` and `pending_requests` were held while `intents` and `grants`
  were locked. These policy locks are now flat.

## Known bounded waits (not deadlocks)

- `browser_manager` is held across a browser launch (up to the CDP discovery timeout of about
  30 s, then up to `INTERCEPTION_ATTACH_TIMEOUT`, 30 s, for the worker to attach), across the
  bootstrap's wait for a reconnecting worker (at most the 10 s degraded grace period) and across
  `terminate` (up to about 8 s). The first sign of a lease waits for it to
  activate the lease, holding no backend lock, so the human CTAP path is not delayed.
- A revocation waits for a key use that already passed its re-check (rule 6): one signature or
  one credential write.
- The human CTAP path holds the operation lock across a whole CTAP command, including its
  user-presence prompt. Agent ceremonies of same-user profiles queue behind it (rule 4 keeps the
  reverse from happening).
