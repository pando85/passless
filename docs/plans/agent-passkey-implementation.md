# Agent authentication implementation plan

- **Status:** Approved for phased implementation
- **Date:** 2026-07-13
- **Owners:** Passless maintainers
- **Covers:** [ADR 0001](../decisions/0001-agent-authentication-security-model.md) and [ADR 0002](../decisions/0002-native-webauthn-agent-architecture.md)
- **Initial platform:** Linux with stock browser WebAuthn and UHID

## Purpose

This plan implements two opt-in agent authentication modes without changing browser behavior:

- `isolated`: persistent, agent-only credentials with independent storage and revocation.
- `delegated-session`: one human-approved assertion using one existing user credential for one RP ID, followed by a short-lived ephemeral browser lease.

The implementation uses separate UHID endpoints to classify human and agent requests. It does not use a browser extension, native messaging host, WebAuthn proxy, injected script, patched browser, raw signing API, or caller-supplied `clientDataHash`.

Each phase has a security exit gate. A phase that depends on an unproven gate does not begin until the gate passes. Failure causes design revision rather than a weaker fallback.

## Outcomes

The implementation is complete when:

1. Existing Passless behavior remains the default and passes its existing tests unchanged.
2. A configured agent profile maps to an authenticated principal and a unique UHID endpoint.
3. Kernel-enforced device permissions prevent human and agent browsers from seeing the wrong endpoint.
4. Isolated credentials cannot cross human or agent-profile boundaries.
5. Delegated mode exposes one exact existing credential for one exact RP assertion without copying key material.
6. Every WebAuthn operation receives fresh, truthful UP and actual UV when required.
7. A delegation grant is consumed by one terminal assertion result and cannot authorize later WebAuthn calls.
8. A delegated browser is terminated at its local monotonic deadline or earlier revocation.
9. Policy, authorization, credential use, browser leases, denial, and cleanup are protected by durable audit.
10. No production path describes a local browser lease as RP-side revocation or continuing user presence.

## Explicit non-outcomes

This work does not deliver:

- Autonomous WebAuthn or automatic UP/UV during an authorization window.
- A new RP-visible agent identity in delegated-session mode.
- Business-action authorization after login.
- Guaranteed invalidation of an RP session when the local browser lease ends.
- Cookie, token, private-key, PIN, raw assertion, or arbitrary signing APIs.
- Browser modification, browser extensions, or WebAuthn proxying.
- Remote agent support or non-Unix isolation in the first release.
- Protection from host root, kernel compromise, or a malicious Passless administrator.
- RP-supported OAuth, workload identity, or service-account provisioning.

## Current repository baseline

The current implementation has one service, backend, and UHID loop per process:

- `passless-core/src/config.rs`: `AppConfig`, backend, security, PIN, CLI, and TOML merging.
- `cmd/passless/src/main.rs`: startup, instance locking, one UHID device, backend dispatch, and `run_with_service()`.
- `cmd/passless/src/authenticator.rs`: `AuthenticatorService`, `PasslessCallbacks`, UP/UV handling, and storage callbacks.
- `cmd/passless/src/storage/`: local, pass, and TPM implementations of `CredentialStorage`.
- `cmd/passless/src/pin_storage/`: PIN state backends.
- `cmd/passless/src/instance_lock.rs`: exclusive backend-state locking.
- `cmd/passless/src/notification.rs`: current presence and verification prompts.
- `cmd/passless/tests/`: human WebAuthn, client, backend, PIN, and instance-lock E2E tests.

Constraints that drive the implementation:

- `run_with_service()` currently owns one `UhidDevice` and one CTAPHID handler.
- `AuthenticatorService::with_pin_storage()` creates its own shared storage owner.
- The transport dependency currently fixes some UHID identity fields.
- The instance lock prevents independent processes from opening the same human backend.
- Existing storage adapters are mutable and depend on one external mutex for iteration and updates.
- Authenticator callbacks receive RP ID but not exact browser origin or process identity.

The design extends these boundaries. It does not bypass the instance lock or open the same human backend through multiple adapters.

## Target structure

The exact split may be adjusted during implementation, but responsibilities remain separate:

```text
passless-core/src/agent/
    config.rs             validated profile configuration
    ids.rs                opaque profile, endpoint, principal, intent, and grant IDs
    policy.rs             immutable policy model and decisions
    protocol.rs           versioned local IPC request and response types

cmd/passless/src/agent/
    audit/                protected writer, verification, rotation, degradation
    authorization.rs      intent and delegated-grant state machines
    browser.rs            ephemeral browser process and lease lifecycle
    device.rs             unique UHID endpoint registry and visibility checks
    launcher.rs           principal authentication and Linux isolation
    policy.rs             loaded policy generation and evaluator
    prompt.rs             agent-specific trusted prompt
    service.rs            endpoint-specific ceremony orchestration
    storage/
        delegated.rs      callback access filter over one human storage owner
        isolated.rs       profile-scoped credential storage ports
    worker.rs             independent CTAPHID endpoint worker

cmd/passless/src/commands/
    agent.rs              principal-safe commands
    agent_admin.rs        human administrative commands

docs/agents/
    README.md
    security-model.md
    configuration.md
    isolated-mode.md
    delegated-session.md
    operations.md
    audit.md
    troubleshooting.md
```

Do not create a separate protocol crate unless two independently versioned binaries need the contract. Initial local protocol types belong in `passless-core` to minimize packages and dependencies.

## Requirement catalog

Requirement IDs are stable across implementation, tests, and review evidence.

| ID | Requirement |
|---|---|
| MODE-01 | Agent support is disabled by default and unknown modes fail validation. |
| MODE-02 | Support only `isolated` and `delegated-session` profiles. |
| MODE-03 | Delegated mode permits one authentication assertion and no registration or credential management. |
| ROUTE-01 | Human and agent requests use distinct UHID endpoints. |
| ROUTE-02 | Every agent endpoint is bound to one authenticated principal, profile, and mode. |
| ROUTE-03 | Human and agent browser identities cannot open each other's hidraw nodes. |
| ROUTE-04 | Endpoint failure never falls back to another Passless credential path. |
| AUTH-01 | Set UP only after a fresh gesture for the exact active CTAP operation. |
| AUTH-02 | Set UV only after actual local user verification for that operation. |
| AUTH-03 | Policy, capabilities, grants, leases, and earlier gestures never produce UP or UV. |
| RP-01 | The stock browser remains responsible for origin-to-RP validation and client-data construction. |
| RP-02 | Passless exactly matches the CTAP RP ID against policy and active authorization. |
| RP-03 | Passless never claims independent visibility of the exact web origin. |
| PRIN-01 | Authenticate a principal with peer identity, launcher identity, sandbox identity, and a protected session capability. |
| PRIN-02 | Secure profiles require a separate Unix identity, container, or equivalent kernel boundary. |
| PRIN-03 | Principals cannot access admin channels, credential roots, audit, browser-profile files, `/dev/uhid`, or unrelated hidraw nodes. |
| ISO-01 | Isolated credentials use profile-specific stores, PIN state, callbacks, and enumeration. |
| ISO-02 | Isolated registration and authentication each require one-shot intents. |
| ISO-03 | Isolated credentials are independently revocable. |
| DEL-01 | A delegated grant binds one principal, endpoint, RP ID, credential, policy generation, login deadline, and maximum session lifetime. |
| DEL-02 | A delegated credential view can read and update only the exact granted credential. |
| DEL-03 | Human and delegated access serialize all mutable credential state. |
| DEL-04 | Every terminal assertion result consumes the grant and removes delegated key access. |
| DEL-05 | The delegated endpoint drains and is destroyed after the CTAP exchange. |
| SESS-01 | Delegated browser leases use daemon-owned monotonic deadlines. |
| SESS-02 | Principals cannot extend leases; exit, revocation, expiry, or isolation failure terminates them. |
| SESS-03 | Ephemeral profiles contain no personal profile data and are never reused after failed cleanup. |
| SESS-04 | Documentation distinguishes local lease expiry from RP-side session expiry. |
| POL-01 | Agent policy is deny-by-default and administered outside the principal. |
| POL-02 | Re-evaluate policy before endpoint creation, request binding, prompt display, and key use. |
| POL-03 | Policy change, profile disablement, or credential revocation cancels affected work immediately. |
| INT-01 | Permit one unbound authorization and one active ceremony per endpoint. |
| INT-02 | Consume bound authorization on success, denial, failure, cancellation, mismatch, or timeout. |
| INT-03 | Use monotonic time for authorization expiry and lose in-memory authorization on restart. |
| STORE-01 | Private keys stay in daemon-owned storage and never cross local protocols. |
| STORE-02 | Human storage remains format-compatible and is opened by one daemon-owned adapter. |
| STORE-03 | Isolated stores use non-overlapping roots and quarantine invalid records. |
| SECRET-01 | Secrets do not appear in CLI, IPC metadata, logs, errors, audit, arguments, or ordinary environment variables. |
| AUDIT-01 | Durably record authorization before credential creation or use. |
| AUDIT-02 | Hash-chain audit records across rotation and protect them from principals. |
| AUDIT-03 | Terminal audit failure enters persistent fail-closed agent degradation. |
| PROTO-01 | Version local admin, principal, and audit contracts and reject incompatible peers. |
| PROTO-02 | Validate message sizes, fields, state transitions, and peer authorization before use. |
| OPS-01 | Agent failure does not stop or weaken the existing human authenticator. |
| OPS-02 | Agent configuration and data can be disabled or removed without migrating human credentials. |
| AUTO-01 | No autonomous mode, delegated UP, cached UV, or repeated passkey use under one browser lease is exposed. |

## Delivery strategy

Implementation proceeds through ten ordered phases. Phase 0 is a hard feasibility gate. Later phases may be split into reviewable pull requests, but no production agent mode is enabled until Phase 9 passes.

Every phase must provide:

- Code and schema changes scoped to that phase.
- Positive, negative, race, and failure tests appropriate to the boundary.
- A requirement-to-test update.
- Documentation of newly accepted residual risk.
- A passing human regression suite.

## Phase 0: Native UHID and isolation feasibility

### Objective

Prove the assumptions that cannot be established from the current single-device implementation.

### Deliverables

- A disposable multi-UHID probe under `tools/agent-uhid-feasibility/`.
- A controlled RP test using stock browser WebAuthn.
- Reproducible Linux device-policy and principal-isolation setup.
- Packet and process evidence for UP, UV, endpoint routing, and teardown.
- `tools/agent-uhid-feasibility/evidence.md` with commands, versions, pass/fail results, and unresolved limitations. The deleted proxy feasibility evidence does not satisfy this replacement gate.

The Phase 0 tools are not linked into production and contain no production credentials.

### Experiments

1. Add the minimum public transport API needed to create devices with deterministic, unique name, `phys`, `uniq`, vendor, and product identity. Prefer an upstream `soft-fido2-transport` change; if unavailable, document and review a minimal pinned fork before proceeding.
2. Run the human endpoint and one agent endpoint concurrently for at least 1,000 create/destroy cycles.
3. Identify each resulting hidraw node without relying on enumeration order.
4. Prove the human browser identity cannot open the agent node.
5. Prove the principal browser identity cannot open the human node or `/dev/uhid`.
6. Launch a stock browser with a fresh profile and complete isolated registration and authentication through only the agent node.
7. Complete delegated authentication with one existing human credential through an exact filtered view while the human endpoint remains responsive.
8. Race simultaneous human and delegated assertions for the same credential and verify serialized counter/state updates without lost writes.
9. Attempt delegated registration, resident enumeration, credential management, deletion, another RP, another credential, and a second assertion; verify terminal rejection.
10. Deny and approve prompts and inspect authenticator flags at packet and RP levels.
11. After successfully submitting the CTAP response, reject later requests before callback dispatch, exercise the transport's kernel acknowledgment or bounded drain procedure, and verify safe endpoint destruction without truncating the browser result.
12. Kill the browser, agent, worker, daemon, and audit path at each state and verify cleanup and fail-closed behavior.
13. Expire and revoke a browser lease; verify browser termination, control-channel closure, profile cleanup, and non-reuse after injected cleanup failure.
14. Run existing human registration, assertion, PIN, client, storage, and instance-lock tests with agent support compiled but disabled.
15. Test representative direct and federated or cross-site login flows from a fresh profile and document which RP patterns are supported; unsupported redirect patterns do not weaken endpoint or credential controls.

### Exit gate

All experiments must pass on the minimum and current supported Linux environments. Device identity must be deterministic, mutual endpoint invisibility must be kernel-enforced, delegated storage must remain single-owner and exact-credential-only, UP/UV must be truthful, and existing human behavior must remain compatible.

Failure of device routing, principal isolation, exact delegated filtering, shared-state synchronization, or endpoint teardown blocks implementation and requires an ADR revision.

## Phase 1: Domain types, configuration, and local contracts

### Objective

Freeze validated configuration and state types before adding runtime authority.

### Changes

- Add `passless-core/src/agent/` behind an `agent` feature.
- Add `agent = []` to `passless-core`, propagate it from `cmd/passless`, and gate module exports in `passless-core/src/lib.rs`.
- Add `AgentConfig`, `AgentProfileConfig`, and `AgentMode` to `AppConfig`.
- Make agent configuration independently cloneable and extract owned or `Arc`-wrapped validated profiles at startup; do not require `AppConfig` itself to implement `Clone`.
- Represent `isolated` and `delegated-session` as a closed enum.
- Add opaque typed IDs for profiles, principal sessions, endpoints, policies, intents, grants, credentials, and browser leases.
- Add validated RP ID, duration, device identity, store reference, browser command, and principal identity types.
- Define versioned admin and principal request/response envelopes with bounded sizes.
- Define stable errors and safe recommended actions.
- Add policy generation and deterministic policy digest types.
- Use Unix `SOCK_SEQPACKET` local sockets with peer credentials for versioned admin and principal contracts.
- Define the policy digest as SHA-256 over RFC 8949 deterministic CBOR for validated policy fields, with fixed golden fixtures; do not rely on a serializer's default map ordering or integer encoding.
- Derive stable non-secret credential references as a full SHA-256 digest over a domain separator and credential ID, reject collisions, and resolve references only inside the daemon-owned credential index.

### Configuration rules

- Existing files with no `[agents]` section retain current behavior.
- `[agents].enabled` defaults to `false`.
- `default` is always `deny` in the first release.
- Profile IDs are unique, normalized, and safe for local path derivation.
- RP IDs are exact normalized DNS names; reject schemes, ports, paths, wildcards, IPs outside explicit test configuration, trailing dots, and public suffixes.
- `delegated-session` requires explicit credential references, `require_uv = true`, positive grant TTL, and positive session TTL.
- `isolated` requires a non-overlapping storage root and explicitly configured registration policy.
- Agent vendor/product/unique device identities cannot collide with the human endpoint or another enabled profile.
- Agent credential, PIN, browser-profile, runtime, and audit paths cannot equal, contain, or be contained by human or other profile roots after canonical and symlink-safe validation.
- Security-sensitive unknown fields fail loading instead of being ignored.
- CLI values override TOML using the existing precedence model without exposing secrets.
- Agent configuration structs derive the existing `ConfigDoc` support so generated TOML documentation remains authoritative. Extend the derive implementation for maps of named profile structs, or generate the `[agents.profiles.*]` section through a reviewed dedicated path if the macro cannot represent it safely.

### Illustrative configuration

```toml
[agents]
enabled = true
default = "deny"
audit_path = "/var/lib/passless-agent/audit/events.jsonl"

[agents.profiles.opencode]
mode = "delegated-session"
principal_user = "passless-opencode"
rp_ids = ["github.com"]
credential_refs = ["user-github"]
max_grant_ttl = "2m"
max_session_ttl = "15m"
require_uv = true

[agents.profiles.release-bot]
mode = "isolated"
principal_user = "passless-release"
rp_ids = ["github.com"]
credential_store = "/var/lib/passless-agent/release-bot/credentials"
pin_store = "/var/lib/passless-agent/release-bot/pin"
registration_allowed = true
require_uv = true
```

### Tests

- Default and backward-compatible configuration snapshots.
- Unknown mode and field rejection.
- RP ID normalization and public-suffix corpus.
- Duration overflow, zero, maximum, and monotonic conversion tests.
- Path overlap, symlink replacement, ownership, and permission tests.
- Device identity collision tests.
- Protocol missing, duplicate, malformed, oversized, and incompatible-version tests.
- Serialization round trips and stable error snapshots.

### Exit gate

Configuration cannot enable an ambiguous or shared route. Existing configuration snapshots remain compatible. No contract contains private material, cookies, raw assertions, or caller-provided signing input.

## Phase 2: Multi-endpoint daemon runtime

### Objective

Refactor the single-device loop into explicit independent endpoint workers while preserving the human service.

### Changes

- Extract a worker around `UhidDevice`, `CtapHidHandler`, command handler, shutdown signal, and cache cleanup.
- Preserve or deliberately simplify the existing `ServiceHandler` command-handler wrapper as part of worker extraction.
- Keep the current human worker construction and behavior as the default path.
- Add an endpoint registry with atomic create, ready, activate, drain, fail, and destroy transitions.
- Parameterize UHID identity using the Phase 0 result.
- Route worker output only to the service injected at endpoint creation.
- Add per-endpoint cancellation and a daemon-wide shutdown coordinator.
- Prevent an agent worker from blocking the human worker while waiting for policy, prompt, audit, or browser state.
- Acquire one existing-style canonical-path lock per human or isolated backend plus one daemon-wide lock for agent audit, sockets, and endpoint state; release all locks on failed startup.
- Clean stale runtime metadata at startup without trusting it as proof that a kernel device still exists.

### Concurrency model

- One worker owns each CTAPHID channel state.
- Human storage remains one `Arc<Mutex<S>>` or an equivalent single-owner abstraction.
- Endpoint registry locks are never held during storage, prompt, audit sync, browser wait, or packet I/O.
- Lock ordering is documented and tested.
- Human requests receive bounded priority when delegated access contends for the human credential store.
- Agent resource limits bound endpoint count, pending packets, message sizes, prompt count, and cleanup work.

### Tests

- Endpoint state-machine property tests.
- Concurrent create, drain, destroy, daemon shutdown, and stale-handle tests.
- Packet routing proving no service can receive another endpoint's frames.
- Lock-order and contention tests with injected delays.
- Worker crash isolation and human-worker continuity.
- Repeated endpoint lifecycle tests under file-descriptor and process pressure.
- Existing human E2E tests with zero configured profiles.

### Exit gate

An endpoint has exactly one service and profile identity for its lifetime. Agent-worker failure leaves the human worker operational. No shared lock is held across user interaction or browser lifecycle waits.

## Phase 3: Principal launcher, device policy, and browser leases

### Objective

Build the enforced boundary that makes an agent endpoint a trustworthy routing signal.

This phase begins only after maintainers review and accept the Phase 0 evidence.

### Changes

- Add the administrative launcher path and per-principal control socket.
- Authenticate admin and principal peers with Unix credentials.
- Generate a 256-bit session capability with the OS CSPRNG and transfer it through an inherited socket or pipe.
- Bind the established principal connection to UID, PID, process start identity, and cgroup, namespace, or container identity.
- Create a separate Unix identity or equivalent container boundary for each secure profile.
- Create a daemon-owned `0700` runtime directory and ephemeral browser profile.
- Durably record browser PID, process start identity, cgroup or transient-scope identity, endpoint, and profile path before exposing the principal session; recover verified orphan scopes on daemon startup.
- Apply `no_new_privs`, resource limits, process limits, filesystem restrictions, device-node policy, and a reviewed syscall policy.
- Start a stock browser without sync, personal profiles, unapproved extensions, saved credentials, or inherited sessions.
- Expose only the profile's hidraw node and approved browser-control channel.
- Add a browser lease manager using monotonic deadlines and explicit revoke, browser-exit, principal-exit, and cleanup states.
- Quarantine profile paths after failed cleanup and require administrative recovery before removal.

### Browser-control assumptions

The implementation documents exactly which automation interface the principal receives. Passless does not return cookies or tokens, but the browser-control interface may expose session state. The security model therefore treats the principal as holding the full RP browser-session authority during the lease.

The launcher navigates first to a configured HTTPS start URL whose host is valid for the profile's RP ID. The start URL is operational configuration, not origin evidence. If the approved browser-control interface allows later arbitrary navigation, documentation and the approval prompt state that explicitly; optional network policy may narrow destinations but does not create RP action scope.

Direct profile filesystem access is denied. Optional network and egress restrictions may reduce exfiltration, but the first release does not claim they create RP-side revocation or business-action scope.

### Tests

- Wrong UID, process, namespace, cgroup, capability, profile, and expired-session rejection.
- Capability absence from command lines, environment, logs, audit, crash output, and proc inspection.
- In-principal attempts to open `/dev/uhid`, human and foreign hidraw nodes, admin socket, stores, audit, and profile paths.
- Browser startup failure, crash, hang, principal exit, daemon restart, revoke, and expiry cleanup.
- Monotonic expiry under wall-clock jumps.
- Symlink, mount replacement, path reuse, and cleanup-race tests.
- Daemon restart recovery that kills only a PID with matching process-start and scope identity, never a recycled PID.
- Resource exhaustion that cannot starve the human authenticator.

### Exit gate

The principal sees exactly one intended agent endpoint and no protected path. Missing kernel controls cause launch failure, not same-user fallback. Browser leases terminate and clean up deterministically under normal and fault-injected paths.

## Phase 4: Credential isolation and delegated views

### Objective

Implement storage boundaries before connecting agent requests to key use.

### Human storage ownership

- Add an `AuthenticatorService` constructor accepting the existing `Arc<Mutex<S>>` storage owner while retaining `with_pin_storage()` for current callers; update human construction only where shared ownership is required.
- Keep one adapter instance for each human backend.
- Serialize reads, signature-counter updates, writes, deletion, iteration, and cache cleanup.
- Do not create another local, pass, or TPM adapter over the same human root.

### Delegated credential view

- Add a non-cloneable, capability-scoped callback access filter bound to grant ID, endpoint ID, RP ID, and credential reference; it is not a second `CredentialStorage` adapter.
- Permit exact credential read and required post-assertion state update only.
- Reject iteration, RP enumeration, registration, create, overwrite, delete, and credential management.
- Recheck active grant state and policy immediately before read and update.
- Hold a per-credential operation lock across the complete read-sign-update sequence and use backend-atomic record replacement; reject conflicting or failed updates before returning an assertion.
- Invalidate the view before endpoint destruction on every terminal result.
- Return mismatch errors without searching for another credential.

### Isolated storage

- Define an agent storage port that requires profile identity on every operation.
- Implement local, pass, and TPM adapters under distinct roots using existing backend formats where safe.
- Keep profile-specific PIN and UV retry state separate.
- Store ownership, RP ID, credential reference, creation time, policy digest, and revocation metadata in a versioned integrity-protected envelope if existing records cannot safely carry them.
- Quarantine corrupt, unknown-version, wrong-owner, and unauthenticated records.
- Expose no cross-profile iterator.

### Tests

- Shared backend conformance for local, pass, and TPM.
- Human, isolated, and delegated enumeration boundaries.
- Exact delegated read/update and every prohibited method.
- Concurrent human/delegated counter update and rollback failures.
- Cross-profile, wrong-RP, wrong-credential, expired-grant, and revoked-credential denial.
- Corruption, truncation, wrong integrity key, symlink, and unknown version.
- Existing human storage fixtures remain byte-for-byte compatible.
- Crash and conflict injection between credential read, signature generation, and counter persistence, with behavior compared to the existing signature-counter policy.

### Exit gate

No API or test can use a human credential through an agent endpoint without one live exact delegated view. Isolated credentials cannot appear through human or other profile paths. Concurrent state updates are serialized and durable.

## Phase 5: Policy, intents, and delegation grants

### Objective

Implement daemon-owned authorization independently from browser and credential callbacks.

### Policy engine

- Parse validated profile policy from the main configuration.
- Assign an in-memory generation and deterministic digest.
- Reload only through the administrative channel in the first release.
- Evaluate profile, mode, principal identity, RP ID, action, credential, registration budget, UV requirement, and requested lifetime.
- Notify endpoint and authorization registries after an atomic successful reload.
- Cancel work affected by disablement, narrowing, credential revocation, or expiry.

### Isolated intents

- Implement one-shot registration and authentication intent states.
- Bind registration to one namespace and budget.
- Bind authentication to one exact credential.
- Enforce one unbound and one active intent per endpoint.
- Support idempotent creation only when the complete payload matches.

### Delegated grants

- Accept a principal request for one configured RP and credential as untrusted input and store it as a pending request with no key-use authority.
- Bind the pending request to an exact CTAP operation before presenting one trusted prompt; prompt approval atomically creates the one-shot grant and supplies UP for that operation.
- Bind grant ID, profile, principal session, endpoint, RP ID, credential, policy generation, login deadline, and requested session TTL.
- Clamp grant and session TTLs to configured maxima.
- Do not start the browser lease until assertion completion.
- Consume the grant on every terminal assertion result.
- Never reactivate credential access during `browser_lease_active`.

### Races and time

- Use monotonic deadlines for decisions and wall time for display and audit.
- Re-evaluate policy at creation, request binding, prompt display, and immediately before credential use.
- Make cancellation idempotent.
- Ensure timeout, cancellation, policy reload, principal exit, endpoint destruction, and credential revocation have one deterministic winning terminal transition.
- Lose all intents and grants on daemon restart.

### Tests

- State-machine model and property tests.
- Replay, duplicate ID, changed idempotency payload, double binding, and double completion.
- Wrong endpoint, principal, RP, credential, action, and mode.
- Expiry at every boundary using a controllable monotonic clock.
- Policy reload and revocation races before prompt and before key use.
- Session TTL clamping and principal extension attempts.
- Registration requests rejected in delegated mode.

### Exit gate

No authorization can bind twice, cross an endpoint or principal, outlive policy, or authorize more than its exact operation. A browser lease contains no live credential capability.

## Phase 6: Protected audit

### Objective

Create an audit subsystem that gates key use and is unavailable to principals.

### Event model

Events cover:

- Daemon and agent subsystem start, stop, and degraded state.
- Principal and endpoint lifecycle.
- Policy load, reload, denial, expiry, and revocation.
- Intent and grant creation, approval, binding, cancellation, consumption, and timeout.
- Prompt display, approval, denial, timeout, and UV result.
- Isolated credential reservation, creation, use, revocation, quarantine, and deletion.
- Delegated credential reservation, use, and state-update result.
- Browser lease start, expiry, revocation, exit, cleanup, quarantine, and recovery.
- Audit rotation, verification, checkpoint, degradation, and acknowledgement.

### Durability and secrecy

- Use owner-only append-oriented files under a non-principal path.
- Serialize one versioned canonical event per record.
- Include sequence, previous hash, event hash, wall timestamp, and monotonic duration fields where useful.
- Synchronize the authorization reservation before credential creation or use.
- Synchronize terminal credential events.
- Chain rotations and optionally publish TPM or remote checkpoints.
- Scan every event type for prohibited secret fields.
- Enter persistent degraded state if an irreversible result cannot be recorded.
- Keep human operations independent from agent audit degradation.

### Tests

- Append, sync, rotation, restart, retention, and chain verification.
- Disk full, read-only path, short write, interrupted write, corrupt tail, and missing rotation file.
- Pre-write failure proving no credential callback runs.
- Terminal-write failure proving later agent operations are denied.
- Principal filesystem denial and symlink replacement.
- Secret-scanning property tests over every event and error variant.

### Exit gate

Audit can block key use, detect corruption, survive restart, and remain inaccessible to the principal. Recovery is explicit and cannot silently discard a discontinuity.

## Phase 7: Agent ceremony services

### Objective

Connect native CTAP requests to endpoint identity, authorization, policy, audit, prompt, and the correct credential view.

### Service construction

- Keep the existing human `AuthenticatorService` construction compatible.
- Create an independent agent service per endpoint with its own callbacks and CTAPHID state.
- Inject mode-specific authorization and storage capabilities.
- Parameterize authenticator AAGUID and options where isolated mode requires a distinct model.
- Compare delegated assertion credential IDs and authenticator-data flags with the human flow for the same credential and verification result; AAGUID is registration attestation data and is not used to characterize delegated assertions.
- Never share callback-local iterators, pending prompts, PIN state, or ceremony state between services.

### Trusted prompt

- Add an `AgentPrompt` interface outside the principal boundary.
- Use a fixed template with distinct trusted and untrusted fields.
- Show profile, mode, exact RP ID, action, credential label, and delegated browser-session maximum.
- Label account names, page URL, page title, and agent reason as untrusted.
- Deliver approval directly to the daemon, never through the principal socket.
- Require explicit distinguishable approve and deny actions.
- Fail closed on unsupported notification servers, timeout, disconnect, rendering failure, or ambiguous action support.
- Keep automatic approval debug-only and impossible in release builds.
- Implement `AgentPrompt` separately from `show_verification_notification`; detect notification servers requiring the current single-action fallback and reject agent prompts on them.
- Use one bound delegated-ceremony template showing trusted RP ID, credential label, grant TTL, session TTL, and clearly labeled untrusted reason. Its distinct affirmative action both creates the one-shot grant and supplies UP for that CTAP operation after a configured minimum review period.

### Isolated registration flow

1. The authenticated principal creates an intent under current policy.
2. The browser starts native `navigator.credentials.create()` through the isolated endpoint.
3. The endpoint service matches action and RP ID and binds the intent.
4. Policy and registration budget are re-evaluated and reserved.
5. Audit reservation is synchronized.
6. The trusted prompt collects fresh UP and configured UV.
7. The isolated service creates the credential in the profile store.
8. Terminal audit is recorded and the response returns to the browser.
9. The intent is consumed on all terminal paths.

### Isolated authentication flow

1. The principal creates an intent naming one exact isolated credential.
2. The browser starts native `navigator.credentials.get()` through the isolated endpoint.
3. The service matches RP ID and exact credential and binds the intent.
4. Policy is re-evaluated and audit reservation is synchronized.
5. The trusted prompt collects fresh UP and configured UV.
6. The isolated view returns only the intended credential.
7. Terminal audit is recorded and the assertion returns.
8. The intent is consumed on all terminal paths.

### Delegated authentication flow

1. The principal creates a pending delegation request for one configured RP, credential, and session maximum.
2. Policy permits creation of the temporary browser and endpoint but no key use.
3. The launcher creates the principal browser and temporary delegated endpoint.
4. The stock browser starts `navigator.credentials.get()`.
5. The endpoint service rejects every command except the expected authentication operation.
6. The service exactly matches RP ID, credential, principal, endpoint, policy generation, and login deadline, then binds the pending request.
7. Policy is re-evaluated and audit reservation is synchronized.
8. One trusted prompt creates the grant and collects fresh UP and required UV for the bound operation.
9. The delegated view reads only the exact user credential and serializes its state update.
10. Terminal audit is recorded and the assertion returns to the browser.
11. The grant and delegated view are consumed, then the endpoint drains and is destroyed.
12. The local browser lease starts at the clamped monotonic deadline.
13. Expiry, revocation, browser exit, principal exit, or daemon shutdown terminates the browser and cleans the profile.

### Tests

- Controlled-RP isolated registration and authentication.
- Controlled-RP delegated authentication with an existing credential.
- RP-side verification of RP hash, signature, counter, UP, and UV.
- Denial, timeout, UV failure, and prompt failure produce no assertion.
- Wrong RP, credential, endpoint, profile, principal, policy generation, action, and mode.
- Delegated registration, second assertion, enumeration, deletion, and management denial.
- Cancellation and policy/revocation races before and during prompt.
- Endpoint draining and destruction only after successful transport submission and the Phase 0-proven drain procedure.
- Packet-level flag fixtures for every prompt and verification result.
- Human and agent requests for the same credential under contention.

### Exit gate

Packet and RP evidence prove truthful UP/UV and exact route selection. Every missing precondition fails terminally without searching another store or endpoint. Existing human E2E tests pass unchanged.

## Phase 8: CLI, documentation, and operations

### Objective

Provide safe administration and principal workflows without exposing credential or session primitives.

### Administrative commands

```text
passless agent-admin profile check|show|list|enable|disable
passless agent-admin policy check|reload|show
passless agent-admin credential list|show|revoke|delete
passless agent-admin delegation show|list|revoke
passless agent-admin session show|list|revoke
passless agent-admin audit status|verify|export
passless agent-admin install [auto|opencode|claude|pi] [--scope user|project] [--force]
```

Authority-changing and destructive commands use only the administrative channel and require trusted human confirmation where applicable.

The skill installer writes the bundled `passless-agent` Agent Skill to the selected tool's native user or project directory. `auto` installs only for detected tools, existing different skills require `--force`, and installation does not enable an agent profile or grant authentication authority.

**Native skill paths by target:**

| Target | User scope | Project scope |
|---|---|---|
| `opencode` | `~/.config/opencode/skills/passless-agent/SKILL.md` | `.opencode/skills/passless-agent/SKILL.md` |
| `claude` | `~/.claude/skills/passless-agent/SKILL.md` | `.claude/skills/passless-agent/SKILL.md` |
| `pi` | `~/.pi/agent/skills/passless-agent/SKILL.md` | `.pi/skills/passless-agent/SKILL.md` |

Pi paths follow the [official Pi skills documentation](https://raw.githubusercontent.com/badlogic/pi-mono/main/packages/coding-agent/docs/skills.md). Detection uses the user config directory (`~/.config/opencode`, `~/.claude`, `~/.pi/agent`), the project directory (`.opencode`, `.claude`, `.pi`), or the presence of the agent command (`opencode`, `claude`, `pi`) in `PATH`.

### Principal commands

```text
passless agent doctor
passless agent capabilities
passless agent instructions
passless agent intent create|show|wait|cancel
passless agent delegation request|show|wait|cancel
passless agent credential list|show
passless agent run --profile <profile> -- <command...>
```

Principal commands:

- Default to versioned JSON inside a principal.
- Never read PINs or confirmation from stdin.
- Never approve policy or delegation.
- Never accept a raw credential ID not already represented by an allowed non-secret reference.
- Never return private material, assertions, cookies, tokens, capabilities, or browser profile paths.
- Return stable errors and one safe recommended action.

### Documentation

Documentation must explain:

- The distinction between isolated credentials and delegated sessions.
- Why every actual WebAuthn operation requires fresh UP and actual UV.
- That the browser enforces origin and Passless sees only RP ID at CTAP.
- That delegated mode presents the same user credential to the RP.
- That local browser expiry is not RP-side revocation.
- That the agent has the full authority of the RP browser session during the lease.
- How principal and device isolation work and how to test them.
- How to provision, approve, launch, audit, revoke, and uninstall.
- Why RP-supported OAuth, service accounts, applications, and workload identity remain preferable for unattended use.

### Operational work

- Generate shell completions through the existing build path.
- Add configuration-reference generation for agent fields.
- Add systemd and udev examples without applying them automatically.
- Add startup diagnostics for device isolation, principal identity, stores, audit, and stale profiles.
- Define browser and kernel support ranges from Phase 0 evidence.
- Define cleanup and revocation runbooks.
- Add `Agent` and `AgentAdmin` variants to `passless_core::config::Commands`, module declarations in `cmd/passless/src/commands/mod.rs`, and dispatch arms in `cmd/passless/src/main.rs`.

### Tests

- CLI JSON and error snapshots.
- Admin commands unavailable inside a principal.
- Principal commands unavailable or limited outside a principal.
- Completion and generated-config documentation tests.
- Documentation links and command examples.
- Release binary has no autonomous mode or automatic WebAuthn approval option.

### Exit gate

An operator can configure, validate, launch, inspect, revoke, audit, and uninstall both modes using documented commands. Principal-facing output contains no authority-changing operation or secret.

## Phase 9: System validation, independent review, and controlled release

### Objective

Validate the complete boundary before enabling opt-in production use.

### Test environments

- Minimum and current supported Linux kernels and distributions.
- Stock browser versions selected by Phase 0.
- Local, pass, and TPM storage backends.
- Human endpoint alone, isolated mode, delegated mode, and concurrent human/agent operation.
- Low disk, file-descriptor pressure, process pressure, clock changes, daemon restart, browser crash, and forced cleanup failure.

### Required suites

| Suite | Coverage |
|---|---|
| Human regression | Existing WebAuthn, client, PIN, storage, credential-management, and instance-lock behavior |
| Endpoint isolation | Unique identity, node discovery, permissions, wrong-browser access, lifecycle, and no fallback |
| Principal isolation | UID, namespace, cgroup, filesystem, socket, device, profile, capability, and resource attacks |
| Policy and authorization | Default deny, exact match, TTL, reload, replay, idempotency, race, cancellation, and revocation |
| Credential isolation | Human/isolated/delegated boundaries, backend conformance, counter serialization, corruption, and quarantine |
| Ceremony semantics | Prompt integrity, RP matching, credential selection, UP, UV, and RP verification |
| Browser lease | Start, clamp, expiry, revoke, crash, principal exit, cleanup, quarantine, and restart |
| Audit | Pre-write gate, terminal failure, degradation, recovery, rotation, verification, and secret absence |
| Resource abuse | Endpoint, request, process, audit, profile, and cleanup flooding |
| Autonomous absence | Unknown mode rejection, no cached approval, and no repeated assertion under one lease |

### Independent security review

Reviewers receive:

- ADRs, threat model, and requirement traceability.
- Endpoint and kernel device-routing design.
- Shared human-storage synchronization analysis.
- Principal, browser-control, and profile-lifecycle design.
- Policy and authorization state machines.
- Prompt and UP/UV evidence.
- Storage and secret-lifetime analysis.
- Audit durability and fault-injection evidence.
- Known limitations, especially RP session authority and local-expiry limits.

Critical and high findings block release. Medium findings require a documented owner and disposition.

### Rollout

1. Ship agent support behind an opt-in compile or experimental runtime feature.
2. Keep `[agents].enabled = false` by default.
3. Require explicit administrator creation of every profile and exact RP policy.
4. Refuse profile startup if any mandatory device, principal, storage, prompt, audit, or cleanup control is unavailable.
5. Leave human startup independent from agent-component failure.
6. Support only documented kernel, distribution, browser, and backend combinations.
7. Remove the experimental label only after at least one stable release without a boundary-breaking issue.

### Rollback

- Disable profile launch and destroy active agent endpoints.
- Revoke active grants, intents, and browser leases.
- Terminate managed ephemeral browsers and quarantine profiles that fail cleanup.
- Revoke isolated credentials locally and instruct operators to remove them at each RP.
- Preserve non-secret metadata and audit for investigation.
- Leave human credentials and configuration untouched.
- For delegated mode, instruct users to revoke RP sessions through RP controls when compromise or session copying is suspected.

### Exit gate

Every requirement has passing evidence, independent review has no unresolved release blocker, installation and rollback are reproducible, and the feature can be disabled without rewriting human credentials or configuration.

## Security test matrix

| Threat | Primary controls | Required evidence |
|---|---|---|
| Another browser consumes an agent authorization | Dedicated UHID node and kernel device policy | Cross-identity hidraw denial and race tests |
| Agent reaches human credentials | Separate endpoint plus exact delegated view or isolated store | Storage and device-boundary tests |
| Delegated mode selects another account | Exact credential reference and no fallback search | Wrong-credential and ambiguous-discoverable tests |
| Agent obtains repeated passkey use during lease | One-shot grant, consumed view, endpoint destruction | Second-assertion and endpoint-lifecycle E2E |
| False UP or UV | Trusted prompt and actual verification gate flags | Packet-level and RP-level flag tests |
| Prompt injection changes RP | Exact CTAP RP match and trusted RP display | Wrong-RP E2E and prompt snapshot review |
| Principal extends local session | Daemon monotonic deadline and kill-on-expiry | Clock jump, extension attempt, and expiry tests |
| Agent retains RP authority after local expiry | Honest limitation, ephemeral profile, restricted control/egress where configured | Documentation review and cleanup tests; no revocation claim |
| Human and agent corrupt credential state | One storage owner and serialized mutation | Concurrent counter/update fault tests |
| Agent changes policy or approval | Admin channel absent from principal | IPC and filesystem adversarial tests |
| Agent suppresses audit | Audit outside principal and durable pre-write | Access-denial and write-failure tests |
| Cleanup leaves reusable profile | Quarantine and no reuse | Fault-injected cleanup and restart tests |
| Autonomous behavior is introduced | Closed modes and fresh-prompt invariant | Config, API, CLI, code-path, and E2E review |

## Requirement traceability

| Requirements | Implemented in | Verified in |
|---|---|---|
| MODE-01 through MODE-03 | Phases 1, 5, and 7 | Config, policy, and delegated negative suites |
| ROUTE-01 through ROUTE-04 | Phases 0, 2, and 3 | Endpoint and principal-isolation suites |
| AUTH-01 through AUTH-03 | Phase 7 | Packet and RP flag tests |
| RP-01 through RP-03 | Phases 1, 5, and 7 | RP validation, mismatch, and documentation review |
| PRIN-01 through PRIN-03 | Phase 3 | Principal-isolation suite |
| ISO-01 through ISO-03 | Phases 4, 5, and 7 | Isolated storage and ceremony suites |
| DEL-01 through DEL-05 | Phases 4, 5, and 7 | Delegated state, storage, and E2E suites |
| SESS-01 through SESS-04 | Phases 3, 5, 7, and 8 | Lease lifecycle and documentation suites |
| POL-01 through POL-03 | Phase 5 | Policy and race suites |
| INT-01 through INT-03 | Phase 5 | State-machine and concurrency suites |
| STORE-01 through STORE-03 | Phase 4 | Backend, compatibility, and corruption suites |
| SECRET-01 | All phases | Secret scans over protocol, CLI, logs, audit, and failures |
| AUDIT-01 through AUDIT-03 | Phase 6 | Audit fault-injection suite |
| PROTO-01 and PROTO-02 | Phases 1 and 3 | Contract and malformed-input suites |
| OPS-01 and OPS-02 | All phases | Human regression, rollback, and release suites |
| AUTO-01 | Phases 1, 5, 7, and 8 | Closed-mode and autonomous-absence suites |

### Requirement-to-source and test mapping

Each requirement maps to specific source modules and test files:

| Requirement | Source modules | Test files |
|---|---|---|
| MODE-01 | `passless-core/src/agent/config.rs`, `passless-core/src/agent/policy.rs` | `passless-core/src/agent/config.rs` (unit tests), `cmd/passless/src/agent/policy_engine.rs` (unit tests) |
| MODE-02 | `passless-core/src/agent/config.rs` | `passless-core/src/agent/config.rs` (unit tests) |
| MODE-03 | `cmd/passless/src/agent/ceremony.rs`, `cmd/passless/src/agent/grant.rs` | `cmd/passless/src/agent/ceremony.rs` (unit tests) |
| ROUTE-01 | `cmd/passless/src/agent/device.rs`, `cmd/passless/src/agent/endpoint_manager.rs` | `tools/agent-uhid-feasibility/` (Phase 0 evidence) |
| ROUTE-02 | `cmd/passless/src/agent/endpoint_manager.rs`, `cmd/passless/src/agent/runtime.rs` | `cmd/passless/src/agent/endpoint_manager.rs` (unit tests) |
| ROUTE-03 | `contrib/udev/70-passless-agent.rules`, `tools/agent-uhid-feasibility/` | Phase 0 evidence (pending privileged checks) |
| ROUTE-04 | `cmd/passless/src/agent/ceremony.rs` | `cmd/passless/src/agent/ceremony.rs` (unit tests) |
| AUTH-01 | `cmd/passless/src/agent/prompt.rs`, `cmd/passless/src/agent/ceremony.rs` | Pending packet-level and RP-level tests |
| AUTH-02 | `cmd/passless/src/agent/prompt.rs`, `cmd/passless/src/agent/ceremony.rs` | Pending packet-level and RP-level tests |
| AUTH-03 | `passless-core/src/agent/policy.rs`, `cmd/passless/src/agent/ceremony.rs` | `cmd/passless/src/agent/ceremony.rs` (unit tests) |
| RP-01 | `cmd/passless/src/agent/ceremony.rs` | Documentation review |
| RP-02 | `cmd/passless/src/agent/ceremony.rs`, `cmd/passless/src/agent/policy_engine.rs` | `cmd/passless/src/agent/ceremony.rs` (unit tests) |
| RP-03 | Documentation | Documentation review |
| PRIN-01 | `cmd/passless/src/agent/launcher.rs`, `cmd/passless/src/agent/ipc.rs` | Pending principal-isolation suite |
| PRIN-02 | `cmd/passless/src/agent/launcher.rs` | Pending principal-isolation suite |
| PRIN-03 | `cmd/passless/src/agent/launcher.rs`, `contrib/udev/70-passless-agent.rules` | Pending principal-isolation suite |
| ISO-01 | `cmd/passless/src/agent/storage.rs`, `cmd/passless/src/agent/storage_factory.rs` | `cmd/passless/src/agent/storage.rs` (unit tests) |
| ISO-02 | `cmd/passless/src/agent/intent.rs`, `cmd/passless/src/agent/ceremony.rs` | `cmd/passless/src/agent/intent.rs` (unit tests) |
| ISO-03 | `cmd/passless/src/agent/storage.rs`, `cmd/passless/src/agent/ceremony.rs` | Pending isolated storage suite |
| DEL-01 | `cmd/passless/src/agent/grant.rs`, `cmd/passless/src/agent/ceremony.rs` | `cmd/passless/src/agent/grant.rs` (unit tests) |
| DEL-02 | `cmd/passless/src/agent/storage.rs` | Pending delegated storage suite |
| DEL-03 | `cmd/passless/src/agent/storage.rs`, `cmd/passless/src/authenticator.rs` | Pending concurrent counter tests |
| DEL-04 | `cmd/passless/src/agent/grant.rs`, `cmd/passless/src/agent/ceremony.rs` | `cmd/passless/src/agent/grant.rs` (unit tests) |
| DEL-05 | `cmd/passless/src/agent/endpoint_manager.rs`, `cmd/passless/src/agent/ceremony.rs` | Pending endpoint lifecycle tests |
| SESS-01 | `cmd/passless/src/agent/browser.rs` | `cmd/passless/src/agent/browser.rs` (unit tests) |
| SESS-02 | `cmd/passless/src/agent/browser.rs` | `cmd/passless/src/agent/browser.rs` (unit tests) |
| SESS-03 | `cmd/passless/src/agent/browser.rs` | `cmd/passless/src/agent/browser.rs` (unit tests) |
| SESS-04 | Documentation | Documentation review |
| POL-01 | `passless-core/src/agent/policy.rs`, `cmd/passless/src/agent/policy_engine.rs` | `passless-core/src/agent/policy.rs` (unit tests) |
| POL-02 | `cmd/passless/src/agent/policy_engine.rs` | `cmd/passless/src/agent/policy_engine.rs` (unit tests) |
| POL-03 | `cmd/passless/src/agent/policy_engine.rs` | Pending policy race suite |
| INT-01 | `cmd/passless/src/agent/intent.rs` | `cmd/passless/src/agent/intent.rs` (unit tests) |
| INT-02 | `cmd/passless/src/agent/intent.rs` | `cmd/passless/src/agent/intent.rs` (unit tests) |
| INT-03 | `cmd/passless/src/agent/intent.rs` | `cmd/passless/src/agent/intent.rs` (unit tests) |
| STORE-01 | `cmd/passless/src/agent/storage.rs`, `cmd/passless/src/authenticator.rs` | Existing human storage tests |
| STORE-02 | `cmd/passless/src/authenticator.rs`, `cmd/passless/src/storage/` | Existing human storage tests |
| STORE-03 | `cmd/passless/src/agent/storage.rs`, `cmd/passless/src/agent/storage_factory.rs` | `cmd/passless/src/agent/storage.rs` (unit tests) |
| SECRET-01 | All agent modules | Pending secret scans over protocol, CLI, logs, audit |
| AUDIT-01 | `cmd/passless/src/agent/audit.rs`, `cmd/passless/src/agent/audit_events.rs` | `cmd/passless/src/agent/audit.rs` (unit tests) |
| AUDIT-02 | `cmd/passless/src/agent/audit.rs` | `cmd/passless/src/agent/audit.rs` (unit tests) |
| AUDIT-03 | `cmd/passless/src/agent/audit.rs` | Pending audit fault-injection suite |
| PROTO-01 | `passless-core/src/agent/protocol.rs` | `passless-core/src/agent/protocol.rs` (unit tests) |
| PROTO-02 | `passless-core/src/agent/protocol.rs` | `passless-core/src/agent/protocol.rs` (unit tests) |
| OPS-01 | `cmd/passless/src/agent/runtime.rs`, `cmd/passless/src/worker.rs` | Existing human E2E tests |
| OPS-02 | `cmd/passless/src/agent/runtime.rs` | Pending rollback suite |
| AUTO-01 | `passless-core/src/agent/config.rs`, `cmd/passless/src/agent/ceremony.rs` | `passless-core/src/agent/config.rs` (unit tests) |

### Phase 0 evidence status

Phase 0 feasibility evidence is documented in `tools/agent-uhid-feasibility/evidence.md`.

**Executed and passed (rootless):**

- UHID module presence and `/dev/uhid` access.
- Deterministic device identity (name, phys, uniq, vendor, product) via CREATE2.
- 1000-cycle create/destroy lifecycle with no leftover devices.
- Concurrent 3-device lifecycle.
- Sysfs-based HID device discovery and hidraw mapping.
- Stock Chromium/Playwright WebAuthn registration and authentication against local Passless UHID endpoint (debug auto-accept UV mode).
- Policy validation (dry-run) for three-tier identity model (uhid-daemon, fido, fido-agent-probe).
- Probe unit tests (15 passed).

**Pending (privileged checks):**

- udev rule installation, reload, and trigger.
- `/dev/uhid` permission enforcement via udev.
- Probe device tagging via udev `ENV{FEASIBILITY_PROBE}`.
- hidraw node permission override for probe devices.
- Module unload safety check.
- Leftover device cleanup via sysfs write.

**Pending (browser/agent pipeline):**

- Agent-mediated UHID device creation from browser.
- Cross-origin isolation headers (COOP/COEP).
- hidraw node access from agent context.
- Privileged cross-identity separation.
- Production UV prompt approval flow (debug auto-accept is not evidence of production prompt).

**Browser and kernel support ranges:**

- Kernel: Linux 7.1.3-1-MANJARO tested. Minimum supported kernel is the oldest distribution kernel providing UHID, hidraw, pidfd/close_range, SOCK_SEQPACKET, namespaces, and cgroups.
- Browser: Stock Chromium (via Playwright) tested with debug auto-accept. Production prompt approval pending.

### Phase 9 validation status

Phase 9 (system validation, independent review, and controlled release) is **not yet executed**.

**Pending:**

- Full test environment matrix (minimum and current supported Linux kernels and distributions).
- Stock browser versions selected by Phase 0 (production UV flow).
- Local, pass, and TPM storage backend conformance for agent mode.
- Human regression suite with agent support compiled but disabled.
- Endpoint isolation suite (unique identity, node discovery, permissions, wrong-browser access, lifecycle, no fallback).
- Principal isolation suite (UID, namespace, cgroup, filesystem, socket, device, profile, capability, resource attacks).
- Policy and authorization suite (default deny, exact match, TTL, reload, replay, idempotency, race, cancellation, revocation).
- Credential isolation suite (human/isolated/delegated boundaries, backend conformance, counter serialization, corruption, quarantine).
- Ceremony semantics suite (prompt integrity, RP matching, credential selection, UP, UV, RP verification).
- Browser lease suite (start, clamp, expiry, revoke, crash, principal exit, cleanup, quarantine, restart).
- Audit suite (pre-write gate, terminal failure, degradation, recovery, rotation, verification, secret absence).
- Resource abuse suite (endpoint, request, process, audit, profile, cleanup flooding).
- Autonomous absence suite (unknown mode rejection, no cached approval, no repeated assertion under one lease).
- Independent security review of ADRs, threat model, endpoint and kernel device-routing design, shared human-storage synchronization, principal and browser-control design, policy and authorization state machines, prompt and UP/UV evidence, storage and secret-lifetime analysis, audit durability and fault-injection evidence, and known limitations.

**Release gates:**

- All phase gates pass in order.
- Every requirement has reviewable passing evidence.
- Independent review has no unresolved critical or high finding.
- Existing human behavior, configuration, and data remain compatible.
- Device and principal isolation are reproducible from documentation.
- Packet-level and RP-level tests prove truthful UP and UV.
- Delegated mode cannot register, enumerate, delete, manage, or perform a second assertion.
- Browser lease expiry and cleanup are tested without claiming RP-side revocation.
- No autonomous or automatic-approval mode exists in config, protocol, CLI, documentation, or runtime.
- Installation, revocation, recovery, rollback, and uninstall are documented and verified.
- Agent support remains opt-in until at least one stable release validates the operating model.

## CI and quality gates

Every implementation change runs:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

Agent changes additionally run:

- Domain and protocol property tests.
- Agent unit and integration tests.
- Existing human E2E tests.
- Controlled-RP native-browser E2E tests where the environment supports UHID.
- Principal and device isolation tests in a privileged CI job.
- Local, pass, and TPM backend conformance where available.
- Secret scanning over protocol fixtures, CLI snapshots, logs, errors, and audit.
- Documentation link and generated configuration checks.

New unsafe code, process execution, namespace or device configuration, peer authorization, filesystem access, and credential handling require focused security ownership.

## Configuration migration

Agent configuration is additive under `[agents]`.

- Existing configuration remains valid and agent support remains disabled.
- Existing human backend paths, records, and instance-lock identity remain valid.
- Human records are never automatically migrated, copied, or relabeled.
- Enabling delegated mode creates references to existing credentials, not duplicate records.
- Removing or disabling a profile prevents new sessions without deleting credentials automatically.
- Unknown security-sensitive fields and modes fail validation.
- Isolated roots cannot overlap human or other profile roots.
- Downgrading to a binary without agent support leaves human operation intact and ignores no active agent process; operators must terminate agent sessions before downgrade.

## Operational lifecycle

### Provisioning isolated mode

1. Install and verify a release supporting agent mode.
2. Create the principal identity and device-isolation policy.
3. Configure a separate credential and PIN root.
4. Configure exact RP policy and registration budget.
5. Run `agent doctor` and the endpoint visibility checks.
6. Launch the profile and perform human-approved native registration.
7. Remove or exhaust registration authority and retain authentication policy.

### Provisioning delegated-session mode

1. Create the principal identity and device-isolation policy.
2. Select an existing credential by non-secret administrative reference.
3. Configure exact RP ID, maximum grant TTL, maximum browser-session TTL, and required UV.
4. Run `agent doctor` and verify the ephemeral browser contains no personal state.
5. Keep policy disabled until the operator is ready to approve individual grants.

### Delegated use

1. The principal requests one RP and credential under current policy.
2. Passless validates policy and launches the ephemeral browser and temporary endpoint without granting key use.
3. The browser starts native WebAuthn and binds the pending request.
4. Passless verifies the exact RP and credential, durably reserves the operation, and presents one prompt for the one-shot grant and current UP/UV.
5. Human approval creates the grant and authorizes that bound assertion.
6. The browser receives one assertion and the credential route is destroyed.
7. The agent uses the RP browser session until local expiry or earlier termination.
8. Passless terminates the browser and cleans or quarantines the profile.

### Revocation

- Disable policy or the profile.
- Cancel pending intents and grants.
- Destroy active agent endpoints.
- Terminate browser leases.
- Revoke isolated credentials locally and at the RP.
- For delegated sessions, use RP account controls to revoke server-side sessions when required.
- Verify audit history and cleanup state.

### Recovery

- Lost isolated store: register a new isolated credential and remove the old RP credential.
- Corrupt human credential: follow existing human recovery; do not bypass delegated filtering.
- Audit corruption: block agent operations, preserve files, verify from the last checkpoint, and require administrative acknowledgement.
- Failed profile cleanup: quarantine the profile, revoke the RP session if possible, and remove it only through the recovery command.
- Compromised principal: terminate, revoke policy and leases, remove isolated RP credentials, revoke delegated RP sessions, and rebuild the principal identity.
- Device-policy failure: disable all agent profiles until routing isolation is restored and independently verified.

## Risk register

| Risk | Impact | Treatment | Release disposition |
|---|---|---|---|
| UHID nodes cannot be isolated deterministically | Wrong browser reaches credential route | Phase 0 identity and kernel-policy proof | Blocks implementation |
| Shared human storage update races | Counter or credential corruption | One owner, serialization, fault tests | Blocks release |
| Agent prompt can be spoofed or auto-accepted | False UP/UV | Trusted prompt boundary and release guard | Blocks release |
| Browser control exposes session material | Session may survive local lease if copied | Honest scope, restricted profile/control/egress, short TTL | Accepted residual risk if documented |
| RP session outlives local lease | Continued server authority | Kill browser, clean profile, RP revocation guidance | Accepted residual risk if documented |
| Fresh profile requires federated or cross-site login | Broader practical session authority or incompatibility | Supported-RP testing and explicit limitations | Block unsupported RP/profile combination |
| Sandbox unavailable | Principal reaches protected resources | Refuse secure profile startup | Supported limitation |
| Synchronous audit adds latency | Ceremony timeout or poor UX | Measure and optimize storage, never weaken pre-write | Must meet documented budget |
| Local backend lacks encryption at rest | Host user can read files | Existing disclosure; recommend pass or TPM | Accepted baseline limitation |
| Multi-endpoint runtime affects human service | Human availability or regression | Independent workers, priority, full regression suite | Blocks release |

## Definition of done

The project is done only when:

- All phase gates pass in order.
- Every requirement has reviewable passing evidence.
- Independent review has no unresolved critical or high finding.
- Existing human behavior, configuration, and data remain compatible.
- Device and principal isolation are reproducible from documentation.
- Packet-level and RP-level tests prove truthful UP and UV.
- Delegated mode cannot register, enumerate, delete, manage, or perform a second assertion.
- Browser lease expiry and cleanup are tested without claiming RP-side revocation.
- No autonomous or automatic-approval mode exists in config, protocol, CLI, documentation, or runtime.
- Installation, revocation, recovery, rollback, and uninstall are documented and verified.
- Agent support remains opt-in until at least one stable release validates the operating model.
