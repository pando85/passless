# Agent passkey implementation plan

- **Status:** Approved plan; implementation not started
- **Date:** 2026-07-13
- **Owners:** Passless maintainers
- **Covers:** [ADR 0001](../decisions/0001-agent-authentication-security-model.md), [ADR 0002](../decisions/0002-managed-browser-interactive-passkeys.md), [ADR 0003](../decisions/0003-autonomous-agent-authentication.md)
- **Initial platform:** Linux and managed Chromium

## Purpose

This plan delivers standards-compliant, interactive passkey authentication for locally launched agents without exposing personal Passless credentials or weakening WebAuthn user-presence semantics.

The plan is complete for the decisions recorded in ADRs 0001 through 0003. It includes feasibility work, repository structure, protocols, policy, principal isolation, credential storage, audit, browser integration, CLI, documentation, tests, migration, packaging, review, and release gates.

Autonomous WebAuthn is not an implementation phase. The plan records controls that prevent it from being added accidentally and defines the separate evidence required for future autonomous work.

## Outcomes

The implementation is complete when:

1. A trusted launcher starts an agent and managed Chromium profile inside a kernel-enforced principal boundary.
2. The browser proxy is active before navigation and cannot fall back to personal authenticators.
3. The agent creates a short-lived intent for one exact origin, RP ID, action, browser session, and credential where applicable.
4. The daemon authenticates the principal and browser request, re-evaluates current policy, and presents a trusted human prompt.
5. Registration or authentication completes only after a ceremony-specific gesture.
6. UP and UV reflect the evidence actually collected.
7. Machine credentials remain in a separate store and never appear through UHID.
8. Durable protected audit records surround every credential creation and use.
9. Existing human Passless behavior and storage formats remain unchanged.
10. No code path provides autonomous WebAuthn or sets UP from prior delegation.

## Explicit non-outcomes

This work does not deliver:

- Unattended browser login.
- Delegated-machine presence.
- OAuth, token exchange, or workload-identity issuance.
- Remote agents.
- Cross-origin iframe, related-origin, or conditional WebAuthn flows.
- Firefox or Safari integration.
- Conversion or delegation of human credentials.
- Authorization of actions after login.
- Protection from host root or kernel compromise.

## Repository baseline

The current workspace contains:

```text
passless-core/          configuration and shared errors
passless-config-doc/    configuration documentation derive macro
cmd/passless/           daemon, UHID authenticator, storage, PIN storage, CLI
cmd/passless/tests/     current human-flow integration and E2E tests
docs/                   project documentation
```

Relevant current code is concentrated in:

- `cmd/passless/src/main.rs`: daemon startup, backend dispatch, and UHID loop.
- `cmd/passless/src/authenticator.rs`: human authenticator service and callbacks.
- `cmd/passless/src/notification.rs`: existing human presence and verification prompts.
- `cmd/passless/src/storage/`: local, pass, and TPM credential backends.
- `cmd/passless/src/pin_storage/`: PIN state backends.
- `cmd/passless/src/instance_lock.rs`: process-level backend locking.
- `passless-core/src/config.rs`: CLI and TOML configuration model.

The current human implementation remains in place during v1. The agent path is additive and feature-gated until release readiness.

## Target repository structure

```text
passless-core/
    src/agent/                 policy and validated domain types

passless-protocol/
    src/admin.rs               versioned administrative contracts
    src/agent.rs               versioned principal and intent contracts
    src/browser.rs             versioned browser proxy contracts
    src/audit.rs               versioned audit event contracts

cmd/passless/
    src/agent/
        audit/                 protected writer, verification, degradation
        browser/               request validation and client-data construction
        intent.rs              in-memory intent registry and state machine
        launcher/              principal lifecycle and sandbox integration
        policy.rs              current-policy evaluator
        service.rs             interactive ceremony orchestration
        storage/               machine credential ports and backend adapters
    src/commands/agent.rs       principal-safe commands
    src/commands/agent_admin.rs human administrative commands
    src/daemon/                admin, agent, and browser Unix sockets

cmd/passless-native-host/
    src/main.rs                Chromium native messaging bridge

browser-extension/
    manifest.json
    background.js              minimal WebAuthenticationProxy integration

docs/agents/                  operator and agent documentation
tools/agent-feasibility/      non-production Phase 0 evidence
```

`passless-protocol` is a new workspace crate with only `serde`, `serde_json`, and `ciborium` dependencies. It contains versioned wire types and deterministic encoders, but no credential operations, policy decisions, filesystem access, process execution, or secrets. Agent implementation initially remains in `cmd/passless` to avoid extracting the stable human engine before the browser design is proven. A later refactor may extract an engine crate without changing protocols.

## Requirement catalog

The identifiers below are used by phase exits, tests, and review evidence.

| ID | Requirement |
|---|---|
| AUTH-01 | Set UP if and only if a fresh gesture authorizes the exact bound ceremony. |
| AUTH-02 | Set UV if and only if actual local user verification occurred for the ceremony. |
| AUTH-03 | Reject unknown or autonomous modes; policy and capabilities expose `interactive` only. |
| SEP-01 | Human and agent requests use structurally separate transports with no fallback. |
| SEP-02 | Human and machine credentials use separate roots, interfaces, and enumeration paths. |
| SEP-03 | Managed browsers cannot access UHID, personal browser profiles, or platform passkeys. |
| PRIN-01 | Authenticate principals with launcher identity, peer credentials, a session capability, and sandbox identity. |
| PRIN-02 | A secure profile requires a separate Unix user, container, or equivalent kernel-enforced boundary. |
| PRIN-03 | Principals cannot access admin sockets, storage roots, audit files, or other principals. |
| BIND-01 | Bind every intent to one exact HTTPS origin, RP ID, action, browser session, and expiry. |
| BIND-02 | Bind authentication to exactly one credential. |
| BIND-03 | Validate that RP ID is allowed for the exact origin under WebAuthn rules. |
| BIND-04 | Canonicalize and digest every security-relevant WebAuthn request field. |
| BIND-05 | Construct `clientDataJSON` in the daemon; reject raw signing and caller-provided hashes. |
| POL-01 | Deny machine access by default and use exact principal/origin/RP/action grants. |
| POL-02 | Re-evaluate policy at intent creation, request binding, and immediately before key use. |
| POL-03 | Cancel affected intents on policy change, expiry, credential revocation, or principal termination. |
| INT-01 | Permit one unbound intent and one active ceremony per principal in v1. |
| INT-02 | Consume a bound intent on success, denial, failure, cancellation, or timeout. |
| INT-03 | Require a new intent for every retry and lose all intents on daemon restart. |
| STORE-01 | Keep private keys in the daemon and never return them through any protocol. |
| STORE-02 | Store each machine credential in a versioned integrity-protected envelope. |
| STORE-03 | Quarantine corrupt and unknown-version records; never reinterpret them as human credentials. |
| STORE-04 | Make revocation immediate and preserve non-secret metadata for audit. |
| SECRET-01 | Keep private keys, PINs, capabilities, cookies, tokens, and raw assertions out of protocols, CLI output, logs, errors, and audit. |
| AUDIT-01 | Require protected-local audit assurance for every secure principal profile. |
| AUDIT-02 | Durably append an authorization-reservation event before credential creation or use. |
| AUDIT-03 | Append a terminal event and enter fail-closed degraded mode if it cannot be recorded. |
| AUDIT-04 | Hash-chain records across rotation without placing secrets in audit data. |
| PROTO-01 | Version every admin, agent, browser, and audit contract and reject incompatible peers. |
| PROTO-02 | Authenticate browser and agent channels and validate every field before use. |
| PROTO-03 | Return stable errors and safe recommended actions without downgrade instructions. |
| OPS-01 | Version and authenticate distribution of the daemon, launcher, extension, and native host. |
| OPS-02 | Preserve existing human configuration, storage, CLI, UHID behavior, and tests. |
| AUTO-01 | Do not implement delegated-machine WebAuthn, autonomous registration, or false UP/UV. |
| AUTO-02 | Document scoped RP-supported credentials as the preferred unattended mechanism. |

## Delivery strategy

Implementation proceeds through ten ordered phases, numbered 0 through 9. A phase can overlap another only when its inputs are stable and its security gate remains independently reviewable.

No production agent feature is enabled by default before Phase 8. Phase 0 may invalidate the browser approach. If it does, implementation stops and ADR 0002 is superseded rather than weakened.

## Phase 0: Managed-browser feasibility

### Objective

Prove that Chromium's proxy API can provide the origin context, response control, failure behavior, and profile isolation required by ADR 0002.

### Deliverables

- `tools/agent-feasibility/extension/`: minimal unpacked Manifest V3 extension using `webAuthenticationProxy`.
- `tools/agent-feasibility/native-host/`: disposable native messaging bridge.
- `tools/agent-feasibility/launch.sh`: reproducible dedicated-profile launcher.
- `tools/agent-feasibility/test-rp/`: controlled HTTPS RP with registration and assertion verification.
- `tools/agent-feasibility/evidence.md`: command transcript, Chromium version, policy, screenshots where useful, network-free reproduction steps, and pass/fail table.
- Browser request and response fixtures for registration, authentication, cancellation, timeout, and proxy failure.
- Provisional cross-component canonicalization vectors sufficient to prove the Phase 0 message path; Phase 1 freezes the final deterministic CBOR schema and vectors before any credential implementation begins.

### Experiments

1. Attach the proxy before the first navigation.
2. Capture the exact top-level origin, RP ID, request identifier, tab, document identity, and WebAuthn options.
3. Determine which context comes from the proxy API and which requires another extension API.
4. Complete one registration and authentication against the controlled RP.
5. Cancel from the page and proxy independently and verify mutual propagation.
6. Kill the extension service worker, native host, and daemon at each ceremony state.
7. Verify that every failure is terminal and the browser never invokes another authenticator.
8. Attempt cross-origin iframe, related-origin, conditional, and concurrent requests and verify rejection.
9. Launch the profile without UHID access and without personal profile directories.
10. Verify behavior across the minimum and latest supported Chromium versions.

### Exit gate

All ADR 0002 feasibility items must pass. Evidence must show trusted exact-origin correlation, complete response construction, deterministic fail-closed behavior, and no path to personal authenticators.

Failure of origin trust, proxy attachment before navigation, or no-fallback behavior stops the project. Convenience fallbacks are prohibited.

## Phase 1: Threat model, protocols, and validated types

### Objective

Freeze trust boundaries and wire contracts before implementing credential operations.

### Changes

- Add `passless-protocol` to the workspace.
- Add `passless-core/src/agent/` for validated origin, RP ID, profile, credential reference, action, policy, and intent types.
- Add `[agents]` configuration under an opt-in `agent` feature.
- Define separate admin, agent, and browser socket addresses and permission models.
- Define schema version negotiation and incompatible-version errors.
- Define canonical CBOR for browser option digests and publish fixed test vectors.
- Define stable request IDs, intent IDs, browser-session IDs, principal-session IDs, and policy versions.
- Define all stable errors listed in ADR 0002 plus structured `agent_action` values.

### Workspace and feature integration

- Add `passless-protocol` to the root workspace members.
- Give `passless-protocol` no default features and only the serialization dependencies listed in the target structure.
- Add an `agent` feature to `passless-core` and `cmd/passless`; it gates agent config, daemon channels, launcher, and agent commands at compile time.
- Keep the existing `tpm` feature independent. `agent,tpm` enables the TPM machine-storage adapter.
- Default builds compile no agent runtime and preserve current behavior.

### RP ID validation

Normalize origins with the URL parser and domain names with IDNA processing before comparison. Apply WebAuthn RP ID rules to the authenticated origin: the RP ID must equal the origin's effective domain or be a registrable-domain suffix of it, must not be a public suffix, and must not include a scheme, port, path, wildcard, or trailing dot. Loopback IP origins are permitted only in the controlled test profile and require exact RP ID matching.

### Security configuration behavior

The agent authenticator inherits current Passless hardening requirements for core-dump prevention and memory handling. It uses the existing signature-counter policy. Presence and verification configuration is evaluated through agent-specific callbacks and cannot disable the mandatory interactive prompt. Existing `user_verification_registration`, `user_verification_authentication`, and `always_uv` settings may require additional verification, but cannot convert policy or launcher authentication into UV. The implementation review must document the exact interaction before Phase 6 exits.

### Canonical browser request

The canonical digest input is an explicitly versioned CBOR map. It includes each field whether present or absent and preserves list ordering. It covers challenge, RP ID, RP entity, user entity, algorithms, allow/exclude credentials, user verification, authenticator selection, extensions, timeout, origin, top origin, action, request ID, document ID, and browser session ID.

JSON field order, optional whitespace, browser object property order, and unrecognized extension fields cannot affect interpretation. Unknown security-relevant fields cause rejection until a new schema supports them.

The native host authenticates the complete message envelope. The daemon recomputes the digest from the decoded request before binding it to an intent.

### Tests

- Origin normalization and rejection tests.
- RP ID validity and public-suffix rejection tests.
- Canonicalization golden vectors shared by Rust and JavaScript.
- Duplicate, missing, unknown, oversized, and malformed field tests.
- Protocol downgrade and incompatible-version tests.
- Property tests for serialization round trips and ID uniqueness.
- Configuration tests proving default deny and interactive-only mode.

### Exit gate

The protocol crate has no credential or filesystem access. Cross-language fixtures produce identical digests. Security review approves the canonical field set and message-size limits.

## Phase 2: Machine policy, intents, and credential storage

### Objective

Implement the daemon-owned authorization state without browser or key-use integration.

### Policy work

- Parse exact profile, origin, RP ID, and action grants.
- Reject wildcard, public-suffix, registrable-domain, and mode values other than `interactive`.
- Require exact credential references for authentication.
- Require registration namespace, expiry, and budget for registration.
- Assign a monotonically changing policy version and stable digest.
- Reload policy atomically and notify the intent registry of changed or removed grants.

Policy is stored in the main Passless TOML file under `[agents]`. It is loaded at daemon startup and reloaded only through `passless agent-admin policy reload`; v1 does not use filesystem watchers. A successful reload increments an in-memory generation and records the deterministic policy digest. Audit identity uses both generation and digest, so a daemon restart can restart the generation without confusing policy content.

### Intent work

- Implement an in-memory registry keyed by authenticated principal session.
- Enforce one unbound intent and one bound ceremony per principal.
- Implement explicit state transitions with no implicit retry.
- Use a monotonic clock for timeout decisions and wall time only for display and audit.
- Re-evaluate policy at creation, binding, and execution.
- Cancel intents on principal termination, daemon shutdown, policy change, credential revocation, browser cancellation, and timeout.
- Support idempotent creation without allowing a changed payload under the same idempotency key.

### Storage work

- Add a `MachineCredentialStorage` trait separate from `CredentialStorage`.
- Implement local, pass, and TPM adapters under distinct configured roots.
- Use one versioned envelope containing the credential and ownership metadata.
- Integrity-protect envelopes with a daemon-held key stored outside the principal boundary.
- Retain the selected backend's confidentiality model: owner-protected local files, GPG-encrypted pass records, or TPM-sealed records.
- Zeroize serialized private material and integrity keys after use.
- Support list, read-exact, write-new, revoke, quarantine, and delete-admin operations.
- Never expose a generic iterator that can cross principals.

`delete-admin` permanently removes already-revoked private material after retention and investigation requirements are satisfied. `revoke` immediately blocks use while preserving the envelope and metadata for audit. Only the administrative channel can delete.

Machine storage configuration uses backend-specific roots that cannot equal, contain, or be contained by a human credential root after canonical path validation:

```text
local: $XDG_DATA_HOME/passless-agent/fido2
pass:  fido2-agent inside the configured password store
tpm:   $XDG_DATA_HOME/passless-agent/fido2-tpm
```

Operators may override these under `[agents.storage]`. The daemon refuses agent startup on overlap, symlink ambiguity, insecure ownership, or insecure permissions.

### Credential envelope fields

```text
schema_version
credential
owner_profile
credential_ref
rp_id
creation_origin
created_at
creation_policy_version
creation_policy_digest
revoked_at
revocation_reason
integrity_algorithm
integrity_tag
```

### Tests

- Shared backend conformance suite for local, pass, and TPM.
- Human-to-machine and machine-to-human enumeration denial.
- Cross-principal read and use denial.
- Corruption, truncation, unknown-version, and wrong-key quarantine.
- Create-only registration behavior; no overwrite.
- Immediate revocation and revocation-during-binding races.
- Policy-reload and expiry cancellation races.
- Daemon restart removes all intents but preserves credentials and policy.

### Exit gate

No test or internal API can use a machine credential without exact profile, RP ID, and credential reference. Existing human storage fixtures remain byte-for-byte compatible.

## Phase 3: Protected audit

### Objective

Create an audit subsystem that can gate key use and cannot be modified by the principal.

### Event model

Events cover:

- Principal session start and end.
- Policy load, change, denial, expiry, and revocation.
- Intent creation, binding, rejection, cancellation, expiry, and consumption.
- Browser connection, protocol mismatch, request, cancellation, and failure.
- Human prompt display, approval, denial, timeout, and verification result.
- Machine credential reservation, creation, use, revocation, quarantine, and deletion.
- Ceremony completion and failure.
- Audit rotation, checkpoint, degradation, recovery, and administrative acknowledgement.

### Durability

- Open the active file with owner-only permissions and append semantics.
- Serialize one complete JSON object per line.
- Assign a sequence number before append.
- Compute the event hash over canonical event bytes and the previous hash.
- Use `fdatasync` after the pre-execution authorization-reservation record.
- Append and synchronize terminal credential events.
- Rotate only between records and chain the first new record to the previous file's final hash.
- Retain rotated files for the configured retention period.

Audit storage is global to the daemon and independent from credential backends. The default active path is `$XDG_STATE_HOME/passless/audit/machine.jsonl`, rotation size is 50 MiB, and retention is 180 days. Configuration lives under `[agents.audit]`. Secure profiles reject `best-effort` assurance and refuse startup if protected-local ownership and permissions cannot be established.

### Failure behavior

- Failure before key use returns `audit_unavailable`; no credential operation occurs.
- Failure after an irreversible RP response sets persistent `audit_degraded` state.
- Degraded state blocks new agent intents and ceremonies.
- Recovery requires an administrator to repair storage, run verification, and acknowledge the discontinuity.
- Human UHID operations are not blocked by agent-audit degradation.

### Tests

- Write, sync, rotation, restart, and chain verification.
- Read-only path, disk-full, short-write, interrupted-write, and corrupt-tail behavior.
- Pre-write failure proving the credential callback is never invoked.
- Terminal-write failure proving later agent operations are denied.
- Principal filesystem tests proving audit files cannot be opened or modified.
- Secret-scanning property tests over every event variant.

### Exit gate

The audit writer can block credential callbacks, survives restart, detects chain corruption, and remains inaccessible from a principal sandbox. Performance measurements document the synchronous-write cost.

## Phase 4: Trusted launcher and principal isolation

### Objective

Implement the secure local principal profile and separate daemon channels.

### Launcher design

- Linux-only in v1.
- Create an ephemeral runtime directory owned by the daemon user.
- Generate a 256-bit random session capability.
- Pass the capability through an inherited pipe or socket file descriptor.
- Place the process tree and browser in a dedicated cgroup and namespace or supported container.
- Run the principal under a distinct Unix identity or equivalent container identity.
- Remove UHID, admin socket, storage, audit, personal home, and unrelated runtime paths from the namespace.
- Mount only required agent files and a dedicated Chromium profile.
- Apply `no_new_privs`, a reviewed seccomp profile, resource limits, and process-count limits.
- Terminate the browser and process tree when either exits unexpectedly or the daemon invalidates the session.

`passless agent run` requests a session through the local administrative launcher path, creates the sandbox, starts the native host and managed browser, and then starts the requested command with inherited stdin, stdout, stderr, and exit status. Browser startup failure terminates the command. Command exit terminates the browser and invalidates the principal session. Signals are forwarded to the command process group before the configured forced-shutdown timeout.

### Session capability

The daemon generates 32 random bytes with the operating-system CSPRNG for each session. It passes the raw capability through an inherited `SOCK_SEQPACKET` socket pair created before entering the sandbox. The capability is session-scoped, is consumed by an authenticated handshake, and is then bound to that connection; it is not sent on every request. The daemon additionally checks peer UID, PID, and cgroup or namespace membership, so possession outside the launched boundary is insufficient. Capability memory is zeroized when the session ends.

The exact sandbox implementation is selected during Phase 0 and documented as a supported dependency. If the required kernel boundary is unavailable, `passless agent run` refuses secure mode rather than degrading to a capability file.

### Daemon channels

- Administrative socket: daemon user only; never mounted in the principal.
- Agent socket: one authenticated principal session; intent and metadata operations only.
- Browser socket: native host only; browser protocol operations only.
- Human UHID loop: unchanged and unaware of agent sockets.

The admin socket is created at daemon startup as `$XDG_RUNTIME_DIR/passless/admin.sock` with mode `0600`. Per-session agent and browser sockets live under `$XDG_RUNTIME_DIR/passless/agent/<session-id>/`, in a daemon-owned `0700` directory selectively mounted or passed into the sandbox. Failure to create the admin socket disables agent support but does not stop the human UHID path. Failure to create a session socket aborts that launch. Shutdown closes and removes all sockets and session directories.

The existing instance lock continues to protect the configured human backend. Agent support adds one daemon-wide lock covering agent policy, machine roots, audit state, and sockets. Multiple principal sessions share that daemon; no second daemon may open the same machine root or audit path.

Human UHID work and agent ceremonies execute on separate workers. Agent storage or prompt waits cannot hold the UHID service mutex. Human requests receive scheduling priority when shared backend resources are contended.

Authentication combines socket peer credentials, capability proof, principal-session ID, and cgroup or namespace membership. A capability copied to a process outside the principal boundary is insufficient.

### Tests

- Agent and browser can connect only to their intended sockets.
- Another UID, PID namespace, cgroup, session, or expired capability is rejected.
- Principal cannot stat or open UHID, admin socket, human store, machine store, audit path, or another browser profile.
- Capability never appears in `/proc/<pid>/cmdline`, environment, logs, crash output, or audit.
- Session termination cancels intents and kills browser descendants.
- Resource limits prevent intent or process flooding from affecting the human authenticator.

### Exit gate

A documented adversarial test from inside the principal fails to reach every protected resource. Sandbox setup failure is terminal. The human daemon remains functional after principal termination.

## Phase 5: Browser extension and native host

### Objective

Build the smallest reviewable browser TCB that forwards proxy requests without making policy decisions.

### Extension

- Manifest V3 with only required permissions.
- Plain JavaScript with no runtime third-party dependencies.
- No content scripts and no page-controlled messaging channel.
- Attach `webAuthenticationProxy` before launcher signals readiness.
- Accept one request at a time.
- Collect trusted tab and document context through approved extension APIs.
- Forward the complete request to the native host.
- Resolve or reject only the matching opaque browser request ID.
- Reject all requests after native-host disconnect or protocol error.

### Native host

- Rust binary in `cmd/passless-native-host`.
- Strict length-prefixed native messaging parser with bounded message size.
- Authenticate to the browser daemon socket using the inherited launcher channel.
- Validate extension identity and protocol version.
- Bind each extension request to one browser session and request ID.
- Never access storage, policy files, private keys, audit files, or the admin socket.
- Never construct assertions or modify WebAuthn options.

`cmd/passless-native-host` is a new workspace binary with `passless-protocol`, `serde`, `serde_json`, `zeroize`, and Unix socket dependencies. It has no default features and must use the same package version as the daemon. Release builds produce a separate signed artifact and native-messaging manifest whose allowed extension ID is generated from the pinned extension package.

### Packaging

- Pin the extension identifier in managed Chromium policy.
- Install the native-host manifest into a launcher-controlled location.
- Record compatible daemon, native-host, extension, and protocol versions.
- Refuse mixed incompatible versions.
- Generate release checksums and sign release artifacts through the existing release process.

The extension has no bundler and no production JavaScript dependencies. Packaging is a deterministic archive of reviewed source files and `manifest.json`. Tests load the unpacked directory; release packaging generates a pinned extension identity and enterprise-policy fixture. Updates require the same signing identity and compatibility tests before the supported-version manifest changes.

### Tests

- Rust parser unit and fuzz tests.
- JavaScript/Rust protocol fixture tests.
- Oversized, duplicated, reordered, canceled, stale, and malformed request tests.
- Service-worker suspension and restart tests.
- Native-host crash, daemon disconnect, and protocol mismatch tests.
- Extension-ID and unmanaged-profile rejection tests.
- Browser integration tests against the controlled RP.

### Exit gate

The extension contains no policy, credential, or fallback logic. Every proxy and host failure rejects the browser request. Packaging pins the expected extension and native-host identity.

## Phase 6: Interactive ceremony engine

### Objective

Connect authenticated browser requests to policy, intent, audit, trusted prompts, and machine credential callbacks.

### Agent authenticator architecture

Create a separate `AgentAuthenticatorService` wrapping an independent `soft_fido2::Authenticator`. It does not reuse the human service instance, callback object, credential store, iterator state, or PIN state. It uses:

- The stable machine AAGUID `50c0c5fa-3b7a-4eee-b906-1b3dd4aed297`.
- `AgentAuthenticatorCallbacks`, which require an already authorized bound ceremony context.
- `MachineCredentialStorage`, which exposes only exact-principal and exact-credential operations.
- Agent-specific PIN/UV state under the machine root if CTAP PIN state is required by `soft-fido2`.
- A shared pure conversion layer for WebAuthn and CTAP types where reuse does not cross policy or storage boundaries.

The service receives no generic human `CredentialStorage` reference. The human and agent services may share immutable cryptographic and serialization code, but never mutable credential, enumeration, prompt, or PIN state.

### Trusted prompt design

V1 uses a dedicated `AgentPrompt` interface implemented outside the principal boundary. The initial Linux implementation may use `notify-rust` only with notification daemons that provide explicit, distinguishable Accept and Deny actions. The existing single-default-action compatibility fallback is prohibited for agent prompts.

The prompt uses a fixed template, escapes all external text, and labels fields as either trusted (`Principal`, `Origin`, `RP ID`, `Action`, `Credential`) or untrusted (`RP account text`, `Agent reason`). Acceptance is delivered directly from the prompt implementation to the daemon and cannot arrive through agent or browser sockets. The principal runs under a separate identity and cannot access the human desktop notification bus used by the daemon. Unsupported daemons, missing action support, disconnect, timeout, and rendering failure deny the ceremony.

Phase 0 must confirm that this mechanism preserves the current Passless assurance baseline. If it cannot distinguish actions and trust labels reliably, Phase 6 requires a small dedicated native dialog helper and a focused security review before proceeding.

### Registration flow

1. The authenticated principal creates an interactive registration intent.
2. The daemon validates exact origin, RP ID, namespace, budget, expiry, and browser session against current policy.
3. The browser begins `navigator.credentials.create()`.
4. The extension and native host submit the authenticated browser request.
5. The daemon validates the complete request, recomputes its digest, and binds the intent.
6. The daemon re-evaluates policy and reserves the registration budget.
7. The daemon durably audits authorization and reservation.
8. A trusted prompt displays principal, origin, RP ID, RP-provided account details, and untrusted reason.
9. Human denial, timeout, cancellation, or policy change releases the reservation and consumes the intent.
10. Human approval supplies UP; actual configured verification supplies UV if performed.
11. The agent authenticator creates the credential directly in the machine store.
12. The daemon records the terminal event and returns the browser response.

Registration never overwrites a credential and never occurs without a prompt. The RP user handle and display data are stored only as required by WebAuthn and are treated as RP-provided values.

### Authentication flow

1. The authenticated principal creates an intent naming one exact credential.
2. The daemon validates exact origin, RP ID, credential ownership, browser session, and current policy.
3. The browser begins `navigator.credentials.get()`.
4. The daemon validates and binds the browser request.
5. The requested `allowCredentials` must permit the exact intended credential; any account ambiguity is rejected.
6. The daemon re-evaluates policy and durably audits authorization and reservation.
7. The trusted prompt shows exact principal, origin, RP ID, credential label, and untrusted reason.
8. Human approval supplies UP; actual local verification supplies UV if performed.
9. The machine store returns only the exact credential to the authenticator callback.
10. The daemon records the terminal event and returns the assertion.

### Prompt implementation

The prompt is outside the principal sandbox and cannot be accepted through the agent socket. It must distinguish trusted fields from RP- and agent-provided text. Unknown notification daemons or action models fail closed. Automated acceptance remains available only in debug E2E builds and cannot be enabled in release builds.

### Daemon restart behavior

Daemon restart closes all session sockets, loses all in-memory intents, rejects pending browser requests, and causes launchers to terminate their managed browsers and process trees. Native hosts do not reconnect an old browser session. After restart, the user must launch a new principal session and the agent must create a new intent. The daemon writes best-effort cancellation records during graceful shutdown; abrupt termination is represented by the next audit startup event and sequence recovery.

### Tests

- Registration and authentication success against the controlled RP.
- UP false on denial and no assertion returned.
- UV set only after the configured verification path succeeds.
- RP requiring UV behaves according to existing Passless configuration without fabricating UV.
- Wrong origin, RP ID, credential, browser, principal, options digest, request ID, or policy version fails.
- Empty or ambiguous `allowCredentials` cannot select another account credential in v1.
- Cancellation and policy/revocation races before and during prompt fail closed.
- No machine credential is visible through existing human client commands or UHID tests.
- No human credential is visible through agent metadata commands.

### Exit gate

Packet-level fixtures prove the authenticator flags match the actual prompt and verification outcome. Negative tests cover every missing precondition. Existing human E2E tests pass unchanged.

## Phase 7: CLI, configuration, and documentation

### Objective

Provide stable human-administrative and agent-safe workflows without exposing security-sensitive primitives.

### Administrative commands

```text
passless agent-admin profile create|show|list|revoke
passless agent-admin policy check|reload|show
passless agent-admin credential list|show|revoke|delete
passless agent-admin audit status|verify|export|recover
```

Administrative commands use only the admin channel. Destructive or authority-changing operations require a trusted human confirmation and cannot be invoked from a principal session.

### Agent commands

```text
passless agent doctor
passless agent capabilities
passless agent instructions
passless agent intent create|show|wait|cancel
passless agent credential list|show
passless agent run --profile <profile> -- <command...>
```

Agent commands:

- Default to versioned JSON when called inside a principal.
- Never read PINs or confirmations from stdin.
- Never grant policy or mutate credential authority.
- Never return private material, assertions, capabilities, cookies, or tokens.
- Return stable error codes and one safe next action.
- Report only `interactive` mode in capabilities.

### Documentation

Create:

```text
docs/agents/README.md
docs/agents/security-model.md
docs/agents/installation.md
docs/agents/principal-setup.md
docs/agents/interactive-registration.md
docs/agents/interactive-authentication.md
docs/agents/browser-integration.md
docs/agents/audit.md
docs/agents/errors.md
docs/agents/troubleshooting.md
docs/agents/alternatives-for-autonomous-access.md
```

`passless agent instructions` embeds version-matched concise instructions generated from these contracts. Documentation prominently states that login grants the RP browser session, Passless does not constrain post-login actions, all processes in a principal share authority, and scoped RP-supported credentials are preferable for unattended work.

### Tests

- CLI JSON snapshots and shell completion generation.
- Agent commands rejected outside an authenticated principal where required.
- Admin commands inaccessible inside a principal.
- Documentation link and embedded-instruction consistency checks.
- Error code and recommended-action exhaustiveness.
- Release binary contains no delegated-mode command, capability, or documentation claim.

### Exit gate

An operator can configure, launch, inspect, revoke, audit, and troubleshoot one principal using only documented commands. An agent can perform only health, instruction, intent, and non-secret metadata operations.

## Phase 8: System validation and independent security review

### Objective

Validate the complete boundary under realistic failures before enabling the feature.

### Test environments

- Minimum supported Linux distribution and Chromium version.
- Latest supported Linux distribution and Chromium stable.
- Local, pass, and TPM storage backends.
- Existing human UHID flow running concurrently with one principal session.
- Low disk, process pressure, daemon restart, browser crash, and extension restart.

### Required validation suites

| Suite | Coverage |
|---|---|
| Human regression | Existing registration, authentication, PIN, credential management, storage, and instance-lock tests |
| Browser protocol | Origin, document, options, cancellation, timeout, malformed message, downgrade, and proxy failure |
| Principal isolation | UID, namespace, cgroup, filesystem, socket, UHID, profile, and capability attacks |
| Policy and intent | Default deny, exact match, reload, expiry, idempotency, reuse, race, cancellation, and revocation |
| Credential isolation | Backend conformance, cross-principal denial, human/machine separation, corruption, and quarantine |
| Ceremony semantics | Trusted prompt, UP, UV, account selection, registration budget, and RP verification |
| Audit | Pre-write gate, terminal failure, degradation, recovery, rotation, chain verification, and secret absence |
| Resource abuse | Request flooding, process flooding, large messages, audit growth, and browser churn |
| Supply and update | Artifact signatures, extension pinning, native-host identity, and incompatible versions |
| Autonomous-mode absence | Unknown mode rejection and no code path setting UP without prompt evidence |

### Independent review

Reviewers receive:

- Current threat model and ADRs.
- TCB inventory and component versions.
- Protocol schemas and canonicalization vectors.
- Sandbox design and adversarial test scripts.
- Storage envelope and key-lifetime analysis.
- Audit durability and failure analysis.
- Coverage report for every requirement ID.
- Known limitations and residual risks.

Critical and high findings block release. Medium findings require a documented disposition and owner.

### Exit gate

Every requirement has passing evidence, the independent review is complete, and no unresolved release blocker remains.

## Phase 9: Controlled release

### Objective

Enable the feature without changing defaults for existing users.

### Rollout

1. Ship as an opt-in build feature or experimental runtime flag with secure-profile checks mandatory.
2. Support only the documented Chromium and Linux combinations.
3. Require explicit operator creation of each principal and exact policy grant.
4. Emit startup diagnostics for proxy, sandbox, socket, storage, and audit health.
5. Refuse to start the agent path if any mandatory control is unavailable.
6. Leave human UHID startup independent from agent-component failure.
7. Collect user-reported compatibility and failure data without telemetry containing RP, user, credential, or browser-session identifiers.
8. Remove the experimental label only after at least one release cycle without a boundary-breaking issue.

### Rollback

- Disable agent listener startup and managed-profile launch.
- Revoke affected machine credentials locally and at each RP.
- Preserve audit and machine metadata for investigation.
- Leave human credential storage untouched.
- Uninstall the managed extension and native-host manifest.
- Document RP-side credential removal because local revocation cannot remove a public credential registered at the RP.

### Exit gate

The feature can be disabled or removed without migrating or rewriting human credentials, config, or UHID behavior.

## Security test matrix

| Threat | Primary controls | Required evidence |
|---|---|---|
| Prompt injection changes destination | Exact origin/RP/credential intent and trusted prompt | Negative E2E for every mismatched field |
| Prompt injection acts after login | Documented limitation and low-privilege account guidance | Documentation review; no false authorization claim |
| Same-user process impersonates agent | Separate identity, peer credentials, capability, sandbox membership | Cross-process and stolen-capability tests |
| Agent reaches personal passkey | Namespace, device, profile, and transport isolation | In-sandbox UHID and profile access tests |
| Proxy detaches and browser falls back | Proxy attached before navigation; terminate on failure | Kill tests at every ceremony state |
| Extension/native host mutates request | Authenticated envelope, canonical digest, strict schema | Cross-language vectors and mutation fuzzing |
| Intent replay or race | One-shot state machine and one active request | Concurrency and replay tests |
| Policy changes during prompt | Re-evaluate before key use and cancel affected intent | Deterministic race test |
| Credential crosses principals | Exact ownership in storage API and envelope | Backend cross-principal conformance test |
| Corrupt metadata becomes human credential | Separate roots/interfaces and quarantine | Corruption corpus test |
| Agent suppresses audit | Audit outside sandbox and durable pre-write | Filesystem denial and write-failure tests |
| Audit terminal write fails | Persistent degraded state | Fault injection and recovery test |
| False UP or UV | Prompt evidence gates flags | Packet-level flag tests and code-path review |
| Autonomous mode is added accidentally | Interactive-only enum/capabilities/policy and unknown-mode rejection | API, config, CLI, and fixture tests |

## Requirement traceability

| Requirement | Implemented in | Verified in |
|---|---|---|
| AUTH-01, AUTH-02 | Phase 6 ceremony engine | Phase 6 flag tests; Phase 8 review |
| AUTH-03, AUTO-01 | Phase 1 types and Phase 7 CLI | Unknown-mode and autonomous-absence suites |
| SEP-01, SEP-03 | Phases 0, 4, 5 | No-fallback and sandbox E2E |
| SEP-02 | Phase 2 storage | Backend and human-regression suites |
| PRIN-01 through PRIN-03 | Phase 4 launcher and sockets | Principal-isolation suite |
| BIND-01 through BIND-05 | Phases 1, 5, 6 | Protocol fixtures, fuzzing, and E2E |
| POL-01 through POL-03 | Phase 2 policy | Policy, race, and revocation suites |
| INT-01 through INT-03 | Phase 2 intent registry | State-machine and concurrency tests |
| STORE-01 through STORE-04 | Phase 2 storage and Phase 6 callbacks | Backend, zeroization, corruption, and revocation tests |
| SECRET-01 | Phases 1, 3, 5, 6, and 7 | Protocol, CLI, log, error, audit, and failure-output secret-scanning suite |
| AUDIT-01 through AUDIT-04 | Phase 3 audit | Audit fault-injection suite |
| PROTO-01 through PROTO-03 | Phases 1 and 5 | Contract, downgrade, malformed-input, and snapshot tests |
| OPS-01 | Phase 5 packaging and Phase 9 release | Artifact and version compatibility checks |
| OPS-02 | All phases | Existing CI and human E2E suite |
| AUTO-02 | Phase 7 documentation | Documentation review |

## CI and quality gates

Every implementation PR must run:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

Agent component PRs additionally run:

- Protocol fixture tests in Rust and JavaScript.
- Browser extension lint with no production dependency installation at runtime.
- Native-host parser fuzz corpus.
- Agent unit and integration suites.
- Existing human E2E tests.
- Controlled-RP browser E2E tests on supported Chromium versions.
- Secret scanning over protocol, logs, audit fixtures, and failure output.
- Documentation link and generated-instruction checks.

Security-critical unsafe code, new process execution, filesystem access, socket authorization, and cryptographic key handling require focused reviewer ownership.

## Configuration migration

Agent configuration is additive under `[agents]`. Existing configuration files remain valid and preserve current defaults.

Rules:

- No agent sockets or browser components start without an enabled secure profile.
- Unknown agent fields fail configuration validation rather than being ignored when security-relevant.
- Unknown modes fail validation. `delegated`, `autonomous`, and equivalent values are not accepted aliases.
- Human backend paths remain unchanged.
- Machine backend roots must not overlap human roots.
- Existing human credential files are never auto-migrated.
- Removing agent configuration disables the agent path without modifying machine records.

## Operational lifecycle

### Provisioning

1. Install matching daemon, native host, extension, and supported Chromium.
2. Verify release signatures and component versions.
3. Create the separate principal identity and sandbox resources.
4. Create dedicated browser profile and machine storage root.
5. Verify protected audit storage.
6. Add exact registration policy with short expiry and budget one.
7. Launch the principal and perform interactive registration.
8. Replace or disable registration policy and add exact credential authentication policy.

### Routine use

1. Launcher authenticates the principal session.
2. Agent checks capabilities and health.
3. Agent creates one exact intent.
4. Browser starts one ceremony.
5. Human reviews and approves or denies the trusted prompt.
6. Agent uses the RP browser session under RP controls.

### Revocation

1. Revoke the policy or principal session immediately.
2. Cancel active intents.
3. Mark the machine credential revoked locally.
4. Review and verify audit history.
5. Remove the credential from the RP through its account controls.
6. Delete local private material only after investigation and retention requirements are satisfied.

Local revocation prevents future Passless use but cannot invalidate an RP session already issued or delete the RP's registered public key.

### Recovery

- Lost machine store: register a new machine credential interactively and remove the old RP credential.
- Lost envelope integrity key: quarantine unreadable records; do not bypass verification.
- Audit corruption: block agent operations, preserve files, verify from the last checkpoint, and require administrative recovery acknowledgement.
- Compromised principal: terminate session, revoke policy and credentials, remove RP sessions and credentials, rotate profile data, and create a new principal identity.
- Compromised extension/native host: disable all agent profiles until signed replacements and a security review are available.

## Documentation acceptance checklist

Before release, documentation must answer:

- What a principal is and why a model name is not identity.
- Which components are trusted and what compromise means.
- Why every ceremony requires a human gesture.
- Why agent credentials are separate from personal credentials.
- What exact origin, RP ID, and credential binding do and do not protect.
- Why Passless cannot constrain actions after login.
- How to install, verify, configure, launch, audit, revoke, recover, and uninstall.
- Which errors are safe to retry and why every retry needs a new intent.
- Why the agent must never bypass the managed browser or request weaker behavior.
- Why OAuth, service accounts, workload identity, and RP-specific credentials are preferable for unattended access when available.
- Why autonomous WebAuthn and delegated UP are not supported.

## Risk register

| Risk | Impact | Treatment | Release disposition |
|---|---|---|---|
| Chromium API lacks trustworthy document context | Cannot bind ceremony safely | Phase 0 prototype | Blocks implementation |
| Browser can fall back after proxy failure | Personal credential exposure | Managed policy, UHID denial, kill-on-detach | Blocks release |
| Sandbox unavailable on target system | Principal can reach protected resources | Refuse secure profile startup | Supported limitation |
| Notification prompt can be spoofed or auto-accepted | False presence | Trusted prompt review and release-build guard | Blocks release if unresolved |
| Larger TCB increases maintenance burden | Boundary compromise | Minimal components, version pinning, independent review | Accepted with controls |
| Synchronous audit writes add latency | Poor UX or timeout | Measure in Phase 3; optimize storage, not semantics | Must meet documented budget |
| RP session has broad authority | Agent can act beyond login intent | Prominent limitation and low-privilege account guidance | Accepted residual risk |
| RP account selection is ambiguous | Wrong account authenticated | Exact credential and `allowCredentials` requirement | Blocks release |
| Chromium update changes proxy behavior | Security or availability regression | Version compatibility tests and pinned support range | Blocks affected version |
| Local backend stores keys without encryption | Host user can read local credential files | Existing backend disclosure; recommend pass or TPM for high value | Accepted baseline limitation |

## Future autonomous-authentication track

Autonomous work begins only through a new ADR satisfying ADR 0003. It is separate from this plan and cannot reuse the interactive UP flag.

A research phase may evaluate:

- Interactive WebAuthn bootstrap into RP-supported OAuth authorization.
- Token exchange with explicit subject and actor identity.
- DPoP- or mTLS-bound, short-lived, audience-restricted tokens.
- TPM-protected agent proof-of-possession keys.
- SPIFFE workload identity for operator-controlled services.
- Cooperating-RP protocols that bind immutable transaction context.

Research artifacts must identify an RP that supports the protocol, show actor visibility and scope enforcement at the RP, and demonstrate independent revocation. A browser-only RP accepting ordinary WebAuthn assertions is not sufficient evidence.

## Definition of done

The project is done only when:

- All ten phase gates pass.
- Every requirement in the traceability table has reviewable evidence.
- The independent security review has no unresolved critical or high finding.
- Existing human Passless behavior and data remain compatible.
- Supported installation and rollback are reproducible from documentation.
- The managed browser cannot reach personal authenticators under any tested failure.
- Packet-level tests prove truthful UP and UV.
- No autonomous or delegated-machine mode is exposed by config, protocol, CLI, documentation, or runtime.
- Operators can revoke local authority and are instructed to revoke RP-side credentials and sessions.
- The feature remains opt-in until one stable release validates the operating model.
