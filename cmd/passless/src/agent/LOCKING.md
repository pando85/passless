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
   another and release each before the next (`principal_exit`, `reload`).
   The only policy lock held across others is `reload_lock`, which ranks below them.
3. **No lock across a wait on a human, an escalation or a join.** A joined duplicate waits on its
   in-flight slot's condvar holding no other lock, and suspends its request permit for the wait
   (atomic counters, at most four duplicates per slot; `InFlight::join`). An escalation waiter (`Waiter::wait`) holds no
   lock either: it parks on the escalation mutex's condvar, which is a leaf, and wakes at least
   every 250 ms to re-check its cancellation, deadline and session with the mutex released.
4. **The backend operation lock is held only for the bounded key-use section.** In same-user mode
   it is the human authenticator's operation lock (`main.rs`), so agent ceremonies do take it:
   invariant 17 requires counters and credential updates to share the backend lock. They take it
   only after the replay key and budget are claimed, for credential selection, the audit
   reservation, the pre-key-use re-check and key use (`SignHandler::sign_fresh`,
   `RegisterHandler::register_fresh`). They never take it while waiting for a duplicate, an
   escalation, a human or the browser manager, and never while holding a policy, session or
   registry guard. The browser lease is activated after the operation lock is released
   (`BrowserLeaseActivation`), and only until it has succeeded once. The human path recovers a
   poisoned operation lock (`main.rs::lock_operation`), because it guards no data, and a
   poisoned credential storage or PIN storage lock (`storage::lock_shared_storage`,
   `pin_storage::lock_pin_storage`; the soundness argument is on those functions), and the TPM
   context and pass Git-sync state locks inside the backends (see the table). Release builds
   abort on panic, so the code that runs under these locks on the agent side is kept panic-free
   (no `expect`, `unwrap` or fallible indexing; ADR 0014 section 14, invariant 23).
5. **The audit gate is a terminal leaf.** `AuditGate::record` may be called with any of the locks
   above held. It never acquires a lock outside the audit gate. Inside it, `append_lock` serializes
   whole records, including segment rotation. A ceremony's records go through one
   `CeremonyAudit` (`operation_audit.rs`, ADR 0014 section 12): a refusal (`policy.deny`) and the
   reservation (`policy.allow`) are written where the ceremony stands, as before; the terminal
   record (`operation.terminal`) is written once by the ceremony's exit point
   (`SignHandler::sign_parked`, `RegisterHandler::register_parked`) after every lock the ceremony
   took has been released, or by the audit's drop guard if the ceremony unwinds. `CeremonyAudit`
   adds no lock of its own: its state is a `RefCell` touched only by the ceremony's own thread, and
   the epochs it records are atomics. A refusal passes through the session's refusal ledger
   (rank 85, a leaf, `refusal_ledger.rs`) to be coalesced; the ledger only counts under its mutex
   and every record it leads to (the refusal in full, or a summary) is written after the mutex is
   released.
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
| 30 T | `BrowserProcessManager` | `runtime.rs` (`AgentRuntime.browser_manager`) | Launch, status, control, cleanup and the runtime loop. During a ceremony it is taken only by `BrowserLeaseActivation::activate`, after the operation lock is released, and only until the lease is active. `browser-control` (`cdp_round_trip_shared`) takes it only for the request and for slices of at most 50 ms of reading the CDP pipe, and releases it between them: a `Runtime.evaluate` that awaits a WebAuthn ceremony would otherwise hold it while the ceremony waits for it in `activate` (a deadlock until the call's timeout). The lease's `cdp_busy` flag serialises the calls of one lease instead (a second one gets `Busy`). No rank changes. |
| 35 | Profile bookkeeping: `active_browser`, `shared_browsers` | `runtime.rs` (`ProfileRuntime`) | Short sections, under `browser_manager` on the launch path. They never nest with each other. |
| 40 T | Backend credential storage, and `pin_storage` | `backend.rs`, `runtime.rs` (`ProfileRuntime.credential_storage`) | The browser launch reads storage under `browser_manager`. Ceremonies release storage before key use (see "Fixed in P5"). |
| 45 T | `AgentRuntime::agent_config` (`RwLock`) | `runtime.rs` | Read for the live profile configuration on launch. A reload holds the write guard across `PolicyRuntime::reload` and releases it before closing browsers. |
| 50 T | `SignContextRegistry` maps: `entries`, `registration_entries`, `revoked_registrations`, `revoked_signs` | `sign.rs` | They never nest. Each guard is released before the next map is locked and before a session is revoked. |
| 55 T | `RequestLimiter::profiles` | `capacity.rs` | Per-profile request counters; a short section with nothing nested. |
| 60 T | `AgentSession::state` (replay table and budget) | `session.rs` | Taken by `claim`, `record_completion` and `operations_used`. Never held across the in-flight slot. |
| 64 T | `GrantedRulesStore::writers[profile]` | `granted_rules.rs` | One per profile. Held across the store file write, its reload and the view swap (71); released before the grant or revocation epoch is bumped. |
| 65 T | `InFlight::outcome` and its condvar | `session.rs` | Joined duplicates park here, holding nothing else. The original publishes here first and only then records completion in the session table. |
| 66 T | `AgentSession::key_use` gate (`RwLock`) | `session.rs` | Rule 6. Read by a ceremony from the re-check to the end of key use; write by `AgentSession::revoke` (called after registry guards are released or, in `revoke_all`, under them). |
| 68 T | `PolicyRuntime::reload_lock` | `policy_engine.rs` | Serializes reloads. It is held across the epoch gate and the policy locks of rank 70. |
| 69 T | `PolicyRuntime::key_use_gate` (`RwLock`) | `policy_engine.rs` | Rule 6. Read by a ceremony after its session gate; write by `bump_revocation_epoch` (under `reload_lock` on a reload). |
| 70 T | `PolicyRuntime`: `current` (`RwLock`), `grants` | `policy_engine.rs` | Leaves (rule 2). `grants` may call the audit gate. |
| 71 T | `GrantedRulesStore::views` (`RwLock`) | `granted_rules.rs` | A leaf. Read by resolution (after the policy guard of rank 70 is released) and by the admin `grants` handlers; written by a store write under its writer (64). |
| 72 T | `ReadinessRegistry::entries` and its condvar | `transport/readiness.rs` | A leaf. The hello path records into it and the launch path reads or waits on it (`status`, `wait_attached`), possibly holding `lifecycle_lock` (10) and `browser_manager` (30). Waiters park on its condvar holding nothing else. The hello path never takes the lifecycle lock or the browser manager. `browser-control` reads a lease's state here (`interception_state`) under the browser manager, which the order allows (30 then 72); the pipe-mode `EnsureBrowser` path takes exactly the locks of the port-mode one, so the pipe-mode principal browser needs no change of the order. |
| 74 T | Sign transport: `Shared::connections` and each `Connection::in_flight` | `transport/mod.rs` | Leaves; they never nest with each other. Short map sections only: a connection to supersede is cloned out before it is closed. |
| 76 T | A transport connection's write mutex (`Connection::writer`) | `transport/mod.rs` | A leaf. Held across one frame write, bounded by the 5 s write timeout. `closed` is set under it, so no frame follows a close. |
| 80 T | `EscalationService::inner` and its condvar `changed` | `escalation.rs` | A leaf. It must never be taken with the operation lock, a policy guard or a session guard held. Waiters park on its condvar holding nothing else and call their `cancelled`/`still_valid` checks with it released. No audit record, store write, prompt show or withdrawal and no D-Bus call happens under it: state changes are made under it and their effects run after it is released. The registration prompt's passkey count (review L4) is one such effect: the `StoreCounter` takes the storage lock (40) just before the prompt is shown, so `run` must be reached with no lock held. A wildcard registration's cap reservation (review L2) is a pair of atomics, not a lock. |
| 82 T | `NotificationPrompter::drivers` (per-profile driver channels) | `prompt.rs` | A leaf: only a channel send (and, on first use, a thread spawn) happens under it. Called by the escalation service after its mutex is released. A failed driver spawn is reported to the sink only after this lock is dropped, because the sink re-enters the prompter (a withdrawal, the next queued prompt). |
| 85 T | `RefusalLedger::inner` (per session) | `refusal_ledger.rs` | A leaf (final review M2). `CeremonyAudit::deny` counts a refusal under it and releases it before any record is written; the pending summaries it returns (and `AgentSession::revoke`'s flush, and the ledger's drop) are written after it is released. Ranked above the key-use gates (66, 69) and the policy locks because a refusal can be raised with a key-use gate held; below the audit gate. Only the closure that builds a summary template runs under it, and it takes no lock (atomics). The runtime loop also sweeps the ledgers of tombstoned (revoked) sessions about once a second (`SignContextRegistry::flush_due_revoked_refusals`): it copies the ledger handles out under the tombstone maps (50) and then flushes each, so the audit gate is never reached under a registry lock (review L5). |
| 90 | `AuditGate`: `append_lock`, then `sequence`, `last_hash`, `writer`, `current_segment(_name)`, `segment_index`, `anchor`, `anchor_inode`, `segment_file_ino` | `audit.rs` | Terminal leaf (rule 5). |
| — | TPM `Context` mutex | `storage/tpm/portable/provider.rs`, `parent.rs`, `storage/tpm/mod.rs` | A leaf inside the TPM key provider and the TPM storage adapter. It is released before the call returns. A poisoned lock is recovered (`portable::context::lock_context`): the context is reusable after a failed call, the session settings are cleared and any transient objects the unwound call left loaded are flushed. |
| — | `PassGitSync` state | `storage/pass/sync.rs` | A leaf inside the pass backend. Recovered when poisoned. A one-call (implicit) Git-sync operation ends from a drop guard (`ImplicitOperation`), so a panic cannot leave its depth counter raised. |
| — | `runtime_loop`, `sign_server_handle`, `WorkerTracker.handles`, `completed_sessions` | `runtime.rs` | Join-handle and bookkeeping locks. They never nest with the locks above. A `join()` under them only joins threads that do not take them. |
| — | Prompt child: `Inbox::state` | `escalation_prompt.rs` | A separate process (the re-executed prompt child, or the validation probe). A leaf: it guards the stdin line queue and is never held across an await or another lock. |
| — | Relay (`sign-proxy`): `Relay::output`, `Relay::in_flight` | `bin/sign-proxy.rs` | A separate process. The two never nest: an id is retired or drained under `in_flight`, which is released before a frame is written under `output`. |

## Ceremony paths

**Sign** (`SignHandler::sign_with`, the check order of ADR 0014 section 9):

- Steps 1 to 6 (session, origin, grant, resolve, options, replay key and budget) take only leaf
  locks, one at a time: policy (70), granted-rules view (71), session (60) and audit (90).
- A duplicate then joins the in-flight slot (65), holding nothing else. Its request permit is
  suspended while it waits (an original parked on an escalation can take minutes), resumed after.
- **Parked wait** (`request`, ADR 0014 section 8.1). The escalation pre-checks read the
  granted-rules view (71) and take the escalation mutex (80), one at a time, before the replay
  key. The replay key is taken without budget (`claim_key`: session, 60). A fresh key then calls
  `join_or_create` (view 71, escalation 80, audit 90 for `escalation.requested`, one at a time)
  and parks in `Waiter::wait` on the escalation condvar holding **no other lock** (rule 3): no
  operation lock, storage, policy, session, gate or transport lock is held across the wait. The
  ceremony's capacity permit is suspended for the wait and resumed afterwards; it is a set of
  atomic counters, not a lock. Every 250 ms the waiter releases the escalation mutex and checks
  its cancellation, deadline and session validity (an atomic and the epoch). After approval it
  re-resolves (policy 70, view 71), claims the budget (session 60) and continues as a fresh key
  below. `the_human_operation_lock_is_free_while_a_waiter_is_parked` (`sign.rs`) takes the human
  operation lock and storage under the debug lock-order checks while a waiter is parked.
- A fresh key takes the operation lock (20), then storage (40). Under both it reads the RP's own
  credentials (`ByRp`; no other RP's credential is read), reads the granted-rules view (71) for the credentials registration grants pinned, and takes policy (70)
  and audit (90) for the reservation. For the pre-key-use re-check it takes the session gate
  (66) and the epoch gate (69), then policy (70) to re-resolve.
- The counter is written, storage is released, and the key provider signs. Then the gates and
  the operation lock are released.
- With no lock held, `BrowserLeaseActivation` takes `browser_manager` (30) until the lease is
  active. The assertion is released only if that succeeds.
- On completion it publishes to the in-flight slot (65) and records the outcome in the session
  (60), one after the other.

**Register** follows the same path without the lease activation; its gates are held until the
credential is written. A registration escalation parks like an authentication one (it is never
joined). After an approved registration has written its credential and released the operation
lock, storage and the gates, `record_registration_grant` persists the grant with nothing else
held: writer (64), then view (71), then audit (90).

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

**Granted rules** (`GrantedRulesStore::add`, `revoke`, `clear`). The profile's writer (64) is
held across the file write; under it the view is read and then swapped (71), one at a time. The
writer is released before `bump_grant_epoch` (an atomic) or `bump_revocation_epoch` (the epoch
gate, 69). After a revoke or clear the admin handler revokes stale sessions and closes browsers
exactly as a reload does (`revoke_stale_bearers_and_close_browsers`, below). A clear also calls
`EscalationService::cancel_profile`, and a revoke `EscalationService::cancel_rp` for its RP
(escalation mutex 80, then the prompt driver table 82), after the store call has returned, with
no lock held. The writer also guards the revocation generations: a revoke bumps its RP's and a
clear the profile's, under the writer, and `add_unless_revoked` compares an escalation's
`RevokeToken` with them under the same writer before it writes (review M-c, M-d). The lock order
is unchanged.

**Escalation** (`EscalationService`; the ceremony side is the parked wait above). `join_or_create`
reads the granted-rules view (71) through the grant writer, takes the store's writer (64) alone to
capture the RP's `RevokeToken`, and takes the escalation mutex (80) twice, never together: once to
check the cooldown, once to admit the request. The
`escalation.requested` record (90) is written with nothing held. A waiter parks on the escalation
condvar holding nothing else. A prompt report runs on the profile's prompt driver thread, which
holds no lock: the approval takes the escalation mutex to move the entry to `Deciding`, releases
it, records `escalation.approved` and `granted_rule.add` (90, the latter before the store write),
takes the escalation mutex once more only to check that the entry is still `Deciding` (a reload or
a grant clear may have cancelled it; the mutex is released before the write), persists the grant
(`GrantedRulesStore::add`: writer 64, then view 71; the grant epoch is an atomic), and takes the
escalation mutex again to publish the outcome. If the entry was cancelled in between, the grant
is revoked again after the mutex is released (`GrantedRulesStore::revoke_request`: writer 64, then
view 71; the revocation epoch is bumped after the writer is released) and `granted_rule.revoke` is
recorded (90). A panic anywhere in the approval finishes the entry as denied from a drop guard
(escalation mutex, then the audit gate, one at a time). The cooldown and withdrawal maps are
pruned on every insert and capped at 4096 entries each, under the same mutex. The withdrawal map
evicts its oldest entry past the cap; the cooldown map never evicts a live cooldown: admission
refuses a new escalation while live cooldowns plus live escalations fill it (review L1). The count is
also per profile (256 live cooldowns plus live escalations each; review M-e), so a profile at its
quota is refused alone and the global 4096 is only a backstop. Prompt shows and withdrawals take only the driver table (82), after the escalation mutex
is released. A reload that changed the policy calls `cancel_profile` after the configuration
lock (45) and `reload_lock` (68) are released: it takes the escalation mutex (80) and then
withdraws the prompts (82).

**Reload** (`handle_reload_policy`) takes these locks in this order:

1. `agent_config` write (45);
2. `reload_lock` (68);
3. each policy lock in turn (70);
4. then everything is released, and `revoke_stale_sessions` takes the registry maps (50), one at a
   time: it removes the stale sign and registration bearers, records them in the `revoked_*`
   tombstone maps (so a late use is audited as `policy.deny(bearer_revoked)`, bounded per bearer)
   and returns the leases they were bound to;
5. `close_revoked_leases` takes `browser_manager` (30) and revokes, terminates, cleans up and
   audits each returned lease (the audit gate, 90, under the browser manager: rule 5). A lease
   an admin launched lives only in the manager, so it is closed here and not by the bookkeeping;
6. finally browser cleanup takes the bookkeeping locks and `browser_manager`.

The admin `browser launch` (`handle_launch_browser`), holding `browser_manager` (30), asks the
registry (50) whether a live bearer is bound to the lease it found. A live lease with none (a
revocation is closing it) is closed there and a fresh browser launched.

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
  were locked. These policy locks are now flat (`intents` and `pending` were removed with the
  principal intent protocol in P7, and `pending_requests` with the principal delegation
  protocol).

## Shared browser ownership (P10b, L5)

`SharedBrowserLease::owner_session` is the principal session that launched a `browser_scope =
"profile"` browser: the worker's bearer, the session grant and the bearer session behind it are
the owner's. `cleanup_browser_for_session` decides in `detach_session_from_shared`, under the
bookkeeping lock (35) alone, that the owner's exit (or the last session's) closes the browser, then
removes the other sessions' `active_browser` entries for that lease (35 again, not nested), and only
then takes `browser_manager` (30) to terminate it, exactly as the last-session case did. No lock is
held across another, and the order of the table above is unchanged.

## Known bounded waits (not deadlocks)

- `browser_manager` is held across a browser launch and across `terminate` (up to about 8 s). A
  launch runs the containment probe (`bwrap` run once as the browser's user, at most 10 s,
  `containment.rs`), then the spawn, which is handed to the long-lived launcher thread and waited
  for over a channel (`spawn_on_launcher_thread`, defect B1; that thread takes no lock, so the
  hand-off adds no lock edge and the lock order is unchanged), then up to the CDP discovery timeout
  of about 30 s and up to `INTERCEPTION_ATTACH_TIMEOUT`, 30 s, for the worker to attach. It is also
  held across the bootstrap's wait for a reconnecting worker (at most the 10 s degraded grace
  period). The first sign of a lease waits for it to
  activate the lease, holding no backend lock, so the human CTAP path is not delayed.
- The browser launch also runs `<browser> --version` (at most 10 s, `browser_select::run_version`,
  D4/R14) before the spawn, under `browser_manager` on the principal path (`resolve_browser_launch`:
  it reads `agent_config` (45), which ranks above the manager, so the order is unchanged). The admin
  launch runs it before taking the manager.
- A revocation waits for a key use that already passed its re-check (rule 6): one signature or
  one credential write.
- A pipe-mode `browser-control` request is checked and written under `browser_manager` (30)
  (`cdp_begin`). That includes the extension filter's own `Target.getTargetInfo` lookups
  (`cdp_filter.rs`), which the browser answers itself, never through a WebAuthn ceremony, within
  the call's CDP deadline (at most 30 s). The filter's detaches are written under the manager too,
  in `cdp_begin` and in the 50 ms read slices. The filter is plain state on the lease and takes no
  lock.
- The human CTAP path holds the operation lock across a whole CTAP command, including its
  user-presence prompt. Agent ceremonies of same-user profiles queue behind it (rule 4 keeps the
  reverse from happening).
- A same-user sign holds the human operation lock (and storage) while it reads the target RP's
  credentials (`SignHandler::sign_fresh`: one `ByRp` read, then a `ByRp` read per candidate in
  `resolve_credential_id`, as the RP ID is normalized the way the storage indexes key it; review
  M-f). Credentials of other RPs are never read or decrypted. With the `pass` backend that still
  decrypts each of the RP's own credentials (a GPG operation each), so an RP with many credentials
  makes the section longer and a human CTAP command queues behind it (final review M4). Pinning
  `credential_refs` does not skip the `ByRp` read of the RP. `RegisterHandler::register_fresh`
  does not walk the store: it reads only the credential IDs named by `excludeCredentials`, each by
  ID and then within the request's RP. A latency residual, documented in ADR 0014 section 15 and
  `docs/agents/same-user.md`.
