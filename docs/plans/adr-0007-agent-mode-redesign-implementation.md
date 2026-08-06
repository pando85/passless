# ADR 0007 Implementation Plan: Unified Same-User and Isolated Agent Modes

- **Status:** Proposed
- **Date:** 2026-08-06
- **Decision:** [ADR 0007](../decisions/0007-unified-agent-identity-modes.md)
- **Verification matrix:** [ADR 0007 verification matrix](adr-0007-verification-matrix.md)
- **Target branch:** `master`

## Objective

Implement one agent WebAuthn operation pipeline that supports:

1. `same-user`: a fully trusted agent uses the existing human passkeys and backend;
2. `isolated`: an agent uses a separate credential namespace and can be independently revoked;
3. autonomous, supervised, denied, and mixed policies per exact RP and action;
4. autonomous UP and UV through bound agent-session evidence;
5. optional human approval or human PIN/platform verification by configuration;
6. short-lived agent sessions with one-shot, replay-resistant WebAuthn operations;
7. software and portable-TPM backends without exporting credential keys;
8. autonomous authentication and registration through the daemon-backed browser extension.

This plan deliberately refactors the current implementation before exposing `same-user`. Adding another mode directly to the current handlers would preserve incorrect provider wiring, request-derived UV, reusable operation authority, and duplicated authenticator behavior.

## Delivery principles

- Preserve ordinary human WebAuthn behavior throughout the migration.
- Keep agent support and `same-user` disabled by default.
- Make changes in reviewable increments with a working or explicitly gated tree after every PR.
- Convert existing isolated behavior to the unified abstractions before enabling human-backend access.
- Require a durable audit reservation before any credential creation or use.
- Do not treat documentation or unit tests as proof of real browser interoperability; use real-RP E2E gates.
- Do not delete the old path until the replacement has passed equivalent and stronger tests.
- Prefer provider and authenticator primitives already used by the human path over new ad hoc crypto or data builders.

## Current implementation gaps to close

The implementation at commit `06722884` provides useful transport and policy pieces, but the following gaps are blockers for `same-user`:

1. `AgentMode` exposes only `isolated`.
2. `AgentRuntime::start_with_factories` receives human storage, PIN storage, and operation lock but does not use them.
3. `/sign` and `/register` are wired to `profile.credential_storage` and a software provider regardless of the configured human or isolated backend.
4. The sign handler may set UV from the RP request or policy presence rather than a resolved verification result.
5. Session grants can authorize repeated calls until TTL expiry, including replay of the same request.
6. Authentication selects from a grant's credential list before fully resolving request selection semantics.
7. Registration hardcodes ES256 and does not completely honor `pubKeyCredParams`, authenticator selection, extensions, attestation, and UV requirements.
8. Registration and authentication build part of the authenticator response independently of the ordinary authenticator path.
9. Origin validation rejects valid origins with ports and does not implement the complete origin/RP relationship.
10. Cross-origin state is derived from RP/domain comparison rather than same-origin-with-ancestors semantics.
11. The extension does not fully preserve `AbortSignal`, timeout, DOMException, native response methods, or all option fields.
12. Stale delegated-session documentation and implementation terminology conflict with the merged runtime.

Each gap maps to a phase and verification row below.

## Target architecture

```text
Agent launcher
  |
  | creates short-lived AgentSession
  v
Managed browser + Passless MV3 extension
  |
  | one request per navigator.credentials.get/create
  | session capability + operation nonce
  v
Agent HTTP/IPC ingress
  |
  v
WebAuthnOperationService
  |-- validate session and request binding
  |-- validate origin/RP/action policy
  |-- select CredentialBackendHandle
  |-- resolve authorization and UP/UV evidence
  |-- reserve audit
  |-- acquire backend operation lock
  |-- authenticate or register via provider-aware service
  |-- finalize audit and atomically consume operation
  v
CredentialBackendHandle
  |-- Human backend for same-user
  `-- Profile backend for isolated
```

The browser transport, policy, evidence, audit, and operation services are shared. Mode selection occurs only when resolving the backend and credential namespace.

## Proposed module boundaries

The exact file organization may change during implementation, but responsibilities must remain explicit.

### `passless-core/src/agent/config.rs`

- `AgentMode::{SameUser, Isolated}`.
- Canonical evidence enum `Agent | Human | None`.
- Policy aliases `deny`, `autonomous`, and `supervised`.
- Session TTL, maximum operations, credential scope, and credential selection configuration.
- Strict mode-specific validation.
- Compatibility parsing for legacy `policy` evidence if retained.

### `passless-core/src/agent/ids.rs`

- `AgentSessionId`.
- `OperationIntentId`.
- Strong nonce or request token types.
- Avoid interchanging session, operation, grant, and registration identifiers.

### `passless-core/src/agent/protocol.rs`

- Complete request/response types for authentication and registration.
- Origin, top-origin, cross-origin, mediation, timeout, and extension inputs.
- Structured errors that map to DOMException values.
- Protocol versioning so extension and daemon incompatibility fails clearly.

### `cmd/passless/src/agent/backend.rs` (new or equivalent)

- `CredentialBackendHandle` and `CredentialNamespace`.
- Backend capability description.
- Human backend construction adapter.
- Isolated backend construction adapter.
- No handler may independently select storage or key providers.

### `cmd/passless/src/agent/session.rs` (new or evolved from `grant.rs`)

- Session creation, lookup, revocation, expiry, operation limits, and principal binding.
- Capability registry.
- Browser-runtime binding.
- Policy-generation invalidation.

### `cmd/passless/src/agent/operation.rs` (new)

- One-shot `OperationIntent` state machine.
- Canonical request hash.
- Atomic state transitions and replay rejection.
- Audit reservation identity.
- Terminal consumption on success, expected errors, cancellation, panic boundaries, and timeout.

### `cmd/passless/src/agent/evidence.rs` (new)

- `AuthorizationProvider` or policy resolution.
- `AgentSessionEvidenceProvider`.
- `HumanInteractionEvidenceProvider`.
- Resolved evidence object used to derive UP/UV flags.
- No handler-level Boolean shortcuts.

### `cmd/passless/src/agent/webauthn.rs` (new or common service)

- Shared `WebAuthnOperationService`.
- Authentication and registration orchestration.
- Credential selection and discovery.
- RP option and credential-policy validation.
- Provider-aware key generation and signing.
- Authenticator data and client data construction through shared, tested primitives.

### Existing handlers

- `sign.rs` becomes a thin HTTP adapter to the operation service.
- `register.rs` becomes a thin HTTP adapter to the operation service.
- `runtime.rs` constructs sessions, backends, and handlers; it does not own WebAuthn semantics.
- `storage_factory.rs` returns complete backend handles rather than loosely related components.
- `policy_engine.rs` returns normalized authorization/evidence decisions and policy-generation metadata.
- `audit.rs` supports reservation/finalization tied to operation intent.

### Browser extension assets

- `main.js`: Web API interception and response facade only.
- `broker.js`: isolated-world validation, request correlation, cancellation forwarding, and page/extension boundary.
- `worker.js`: trusted sender metadata, session channel, daemon transport, lifecycle handling, and protocol-version checks.

## Phase 0: Baseline, feature gate, and test freeze

### Tasks

1. Add an experimental feature/config gate for the unified pipeline, for example `agents.experimental_unified_webauthn = true`.
2. Record the current isolated authentication and registration behavior in integration tests before refactoring.
3. Add failing regression tests for known blockers:
   - RP-requested UV must not set UV without evidence;
   - replaying one operation request must fail;
   - portable-TPM profile must not receive a software provider;
   - human backend inputs must not be silently discarded in same-user construction;
   - a valid HTTPS origin with an explicit port must pass structural parsing;
   - cross-origin is not equivalent to frame host versus RP ID.
4. Make existing extension and daemon protocol versions explicit.
5. Document exact commands and fixtures for current real-RP software E2E.

### Completion criteria

- The current tree has a reproducible baseline test suite.
- Known incorrect behavior is represented by ignored or expected-failure tests linked to this plan.
- Unified behavior cannot be accidentally enabled in production.

## Phase 1: Configuration and normalized policy model

### Tasks

1. Add `SameUser` to `AgentMode`.
2. Replace or extend evidence naming so `agent`, `human`, and `none` are canonical.
3. Parse aliases:
   - `deny` -> `deny + none + none`;
   - `autonomous` -> `allow + agent + agent`;
   - `supervised` -> `confirm + human + human`.
4. Add:
   - `session_ttl`;
   - `max_operations`;
   - optional launch-time RP narrowing;
   - optional credential refs;
   - `credential_selection = single | first-matching | newest | credential:<ref>`;
   - human verification prompt preference for `preferred` and `discouraged` requests.
5. Enforce mode-specific validation:
   - same-user rejects profile storage, PIN path, and agent-specific backend provider settings;
   - isolated requires complete storage and rejects overlap with human and other profiles;
   - missing RP action policy denies;
   - deny cannot carry evidence;
   - unknown values fail startup.
6. Preserve `isolated` configuration compatibility.
7. Optionally accept `policy` as an alias for `agent` for one release, with a startup warning.
8. Add redacted config rendering and `passless agent doctor` diagnostics for the new fields.

### Tests

- TOML parsing for all canonical and alias forms.
- Validation matrix for both modes.
- Path-overlap regression tests.
- Round-trip/redacted rendering tests.
- Defaults prove support is disabled and same-user is never implied.

### Completion criteria

- Configuration can represent every ADR 0007 policy without runtime behavior changes.
- Invalid or ambiguous configurations fail before starting agent endpoints.

## Phase 2: Complete credential backend abstraction

### Tasks

1. Define `CredentialBackendHandle` with:
   - namespace;
   - credential storage;
   - key provider;
   - local verification provider or PIN service;
   - shared operation lock;
   - capability metadata.
2. Refactor human daemon startup to expose one cloneable human backend handle.
3. Refactor the agent storage factory to return complete isolated backend handles.
4. Update `AgentRuntime::start` and `start_with_factories` to consume the human backend rather than separate ignored arguments.
5. Mode resolution:
   - same-user clones the human backend handle;
   - isolated constructs a profile backend handle.
6. Remove handler construction that hardcodes `SoftwareCredentialKeyProvider`.
7. Ensure portable-TPM provider, sealed metadata, and operation lock travel together.
8. Ensure a backend handle cannot be converted into a storage path or exposed through the agent protocol.
9. Add namespace-aware metrics and diagnostics without exposing credential identifiers.

### Tests

- Pointer/identity test proving human UI and same-user agent use the same operation lock.
- Software backend provider selection.
- Portable-TPM backend provider selection.
- Isolated profile receives a different namespace and lock.
- Same-user cannot start without a human backend.
- Isolated cannot receive a human backend through factory substitution.
- Concurrent signature counter test across human and same-user operations.

### Completion criteria

- Every credential operation receives one complete backend handle.
- No sign/register handler opens storage or chooses a provider.
- Current isolated tests pass through the new abstraction.

## Phase 3: Short-lived sessions and one-shot operation intents

### Tasks

1. Separate reusable task authority from one-shot WebAuthn authority:
   - `AgentSession` for the short browser/agent task;
   - `OperationIntent` for one `get()` or `create()` call.
2. Session fields:
   - profile and mode;
   - principal identity;
   - launcher/browser runtime identity;
   - policy generation;
   - issued/expiry timestamps;
   - operation budget;
   - optional RP narrowing;
   - random capability hash.
3. Bind the extension bearer to one session and extension/runtime instance.
4. Implement operation states and atomic transitions.
5. Generate a cryptographic operation nonce in the extension worker or daemon and bind it to a canonical request hash.
6. Reject duplicate nonces, duplicate completed operation IDs, and mismatched request hashes.
7. Re-evaluate policy before authorization and immediately before key use.
8. Consume on:
   - success;
   - policy denial;
   - RP/credential mismatch;
   - user cancellation;
   - timeout;
   - handler error;
   - audit failure;
   - signing or storage failure.
9. Revoke sessions on browser shutdown, launcher failure, explicit revoke, expiry, policy change, and operation-budget exhaustion.
10. Bound registries and replay caches to prevent memory exhaustion.
11. Replace tests that expect replayed requests to sign again.

### Persistence decision

Sessions and pending operations remain in memory. Audit reservations are durable. Daemon restart invalidates sessions and operations, which is the desired fail-closed behavior.

### Tests

- Session TTL boundaries with a controllable clock.
- Operation-count exhaustion.
- Atomic double-submit: exactly one caller reaches key use.
- Replay after success, failure, cancellation, and timeout.
- Policy-generation invalidation between authorization and key use.
- Browser shutdown and principal death invalidation.
- Registry cleanup and bounded memory tests.

### Completion criteria

- A session can perform multiple newly authorized operations within its limit.
- The same operation can never create or use a credential twice.
- Every terminal path leaves the operation consumed and auditable.

## Phase 4: Evidence-provider architecture

### Tasks

1. Introduce a resolved evidence type, for example:

```rust
pub struct ResolvedEvidence {
    pub user_present: bool,
    pub user_verified: bool,
    pub presence_source: EvidenceSource,
    pub verification_source: EvidenceSource,
    pub verified_at: Option<SystemTime>,
}
```

2. Implement `AgentSessionEvidenceProvider`:
   - verifies active session capability;
   - verifies principal, browser/runtime, profile, policy generation, nonce, and request binding;
   - returns agent UP and/or UV only for fields configured as `agent`;
   - never returns evidence for an expired or replayed operation.
3. Implement `HumanInteractionEvidenceProvider`:
   - invokes existing production approval and PIN/platform-verification paths;
   - binds the result to one operation intent;
   - does not expose PIN or biometric data;
   - supports cancellation and timeout.
4. Resolve authorization separately from evidence.
5. Derive authenticator flags only from `ResolvedEvidence`.
6. Enforce RP `userVerification` and credential-level requirements:
   - required needs successful agent or human UV;
   - preferred follows configured provider and prompt preference;
   - discouraged avoids human prompts unless explicitly `always`;
   - `credProtect` can strengthen required verification.
7. Remove every shortcut equivalent to:
   - `uv = request_requires_uv`;
   - `uv = policy_mentions_uv`;
   - `up = authorization_allowed`.
8. Emit explicit audit fields for authorization, presence source, and verification source.

### Tests

- Complete cross-product of authorization and evidence values.
- Required/preferred/discouraged behavior.
- `credProtect` with agent, human, and none.
- Agent evidence fails after session invalidation.
- Human verification is one-shot and cancellation-safe.
- Audit never labels agent verification as human verification.

### Completion criteria

- UP and UV flags are impossible to construct without a successful provider result.
- Fully autonomous policy succeeds for RP-required UV.
- Human-forwarded UV succeeds without revealing verification secrets.

## Phase 5: Unified authentication service

### Tasks

1. Move authentication semantics from `sign.rs` into `WebAuthnOperationService::authenticate`.
2. Validate request protocol version and complete option structure.
3. Parse and validate:
   - challenge;
   - RP ID;
   - origin/top origin/cross-origin context;
   - allow credentials;
   - userVerification;
   - extensions;
   - timeout and mediation where applicable.
4. Apply exact RP policy before backend credential discovery.
5. Select the mode backend and candidate credentials.
6. Implement deterministic selection from ADR 0007.
7. Enforce credential refs as optional narrowing, not as an alternative storage namespace.
8. Enforce credential policy, including discoverability and `credProtect`.
9. Resolve authorization and evidence.
10. Reserve audit before key use.
11. Acquire backend lock.
12. Re-read credential under lock and revalidate policy/session.
13. Construct canonical client data and authenticator data through shared primitives.
14. Sign through the backend key provider.
15. Update signature counter safely and persist it with defined failure semantics.
16. Finalize audit and consume operation.
17. Return complete response data plus extension outputs.
18. Make `sign.rs` an adapter that maps HTTP and DOM errors.

### Counter failure semantics

Define and test one explicit order. Preferred behavior:

1. reserve audit;
2. lock backend;
3. load credential and next counter;
4. sign response containing next counter;
5. persist counter before returning success;
6. if persistence fails, do not return the assertion and record terminal failure.

Backends that can provide stronger atomicity may do so, but externally visible behavior must remain fail-closed.

### Tests

- Same-user authentication with existing software credential.
- Same-user authentication with portable-TPM credential.
- Isolated software and TPM authentication.
- Exact `allowCredentials` ordering.
- Discoverable single and ambiguous selections.
- Credential ref narrowing.
- Required UV and `credProtect`.
- Counter concurrency, persistence failure, and restart behavior.
- Unsupported extensions fail or are omitted according to documented capability.
- Cryptographic verification of every generated assertion.

### Completion criteria

- Isolated authentication no longer depends on handler-local provider selection.
- Same-user authentication uses the exact human backend.
- Assertions are cryptographically and semantically valid for all supported cases.

## Phase 6: Unified registration service

### Tasks

1. Move registration semantics from `register.rs` into `WebAuthnOperationService::register`.
2. Use the selected mode backend as the registration target.
3. Validate:
   - RP and user entities;
   - challenge;
   - origin context;
   - `pubKeyCredParams`;
   - `excludeCredentials`;
   - authenticator selection;
   - resident-key requirements;
   - userVerification;
   - attestation preference;
   - supported extensions.
4. Select the first RP-preferred algorithm supported by the backend. Do not hardcode ES256.
5. Resolve authorization and evidence before key generation.
6. Reserve audit before generating a key or credential ID.
7. Acquire backend lock and revalidate session/policy.
8. Re-check exclude credentials under lock.
9. Generate the key through the backend provider.
10. Construct credential source, COSE public key, authenticator data, and attestation through shared primitives.
11. Persist the credential only in the mode-selected backend.
12. Define cleanup behavior when provider generation succeeds but storage fails, especially for TPM objects.
13. Return complete registration response and extension outputs.
14. Make `register.rs` a protocol adapter only.

### Supported-capability policy

- `none` attestation is mandatory for initial release.
- Unsupported enterprise or direct-attestation requirements return `NotSupportedError` rather than false claims.
- The initial algorithm set is whatever the backend providers can truthfully implement and advertise.
- Resident/discoverable requirements are honored, not silently ignored.
- Unsupported extensions are explicitly rejected when required for correctness.

### Tests

- Same-user registration writes to human storage and is visible to normal human authentication.
- Isolated registration writes only to profile storage.
- Software and TPM key generation.
- Algorithm preference and no-supported-algorithm failure.
- Exclude credential race under concurrent requests.
- Resident-key and UV requirements.
- Storage failure cleanup.
- Register then authenticate E2E in both modes.

### Completion criteria

- Registration behavior is provider-aware and RP-option-aware.
- No path can create a same-user credential without an explicit exact-RP registration rule.

## Phase 7: Origin, RP, and browser security correctness

### Tasks

1. Replace current structural origin checks with a shared parser and validator implementing supported WebAuthn rules:
   - secure origin requirements;
   - valid explicit ports;
   - RP ID equal to or registrable-domain suffix of the effective domain;
   - public-suffix rejection;
   - IP and localhost behavior documented and tested;
   - canonical host and trailing-dot handling.
2. Trust extension sender metadata as the primary frame URL source and cross-check the MAIN-world report.
3. Derive top origin from trusted browser metadata where possible.
4. Initially allow top-level frames only.
5. Add cross-origin iframe support only after implementing:
   - same-origin-with-ancestors calculation;
   - top-origin client data;
   - Permissions Policy checks for create/get;
   - request and response tests across same-origin and cross-origin frames.
6. Keep session bearer and daemon endpoint details out of page JavaScript.
7. Restrict daemon ingress:
   - loopback only;
   - high-entropy per-session bearer;
   - body and header limits;
   - no permissive CORS;
   - constant-time bearer comparison where applicable;
   - request rate and concurrency bounds;
   - protocol version check.
8. Evaluate native messaging as a future transport, but do not block the redesign on it.

### Tests

- Origin with port.
- Parent/subdomain RP relationships.
- Public suffix rejection.
- Origin spoof mismatch between MAIN and sender metadata.
- Same-origin iframe.
- Cross-origin iframe denied before support.
- Cross-origin allowed only with correct top origin and Permissions Policy after support.
- Local untrusted process without bearer.
- Stolen expired bearer and bearer from another browser session.

### Completion criteria

- The daemon never accepts origin solely because its host equals an RP ID.
- Unsupported frame contexts fail closed.
- Session transport compromise does not bypass exact RP, operation, and policy checks.

## Phase 8: Browser API compatibility and lifecycle

### Tasks

1. Preserve the original Credentials API for non-public-key calls.
2. Serialize all required request fields and binary values.
3. Implement cancellation:
   - listen to `AbortSignal`;
   - send cancel to worker/daemon;
   - consume the operation;
   - reject with `AbortError`.
4. Honor the minimum of RP timeout, configured operation timeout, and session expiry.
5. Return DOM-compatible errors:
   - `NotAllowedError` for denial, timeout, cancellation, or unavailable user interaction where appropriate;
   - `SecurityError` for origin/RP violations;
   - `InvalidStateError` for excluded/duplicate registration state;
   - `NotSupportedError` for unsupported algorithms, attestation, or extensions;
   - `UnknownError` only for genuinely unmapped internal failures.
6. Complete response facades:
   - `id`, `rawId`, `type`;
   - `authenticatorAttachment` where known;
   - `response.clientDataJSON`;
   - authentication and registration response fields;
   - `getClientExtensionResults()`;
   - `toJSON()` compatible with WebAuthn JSON conventions;
   - registration `getTransports()` where representable.
7. Make request correlation frame- and session-specific.
8. Add a compatibility probe and optional `webAuthenticationProxy` adapter only if a target RP requires native object identity. The adapter must preserve trustworthy origin correlation.

### Tests

- Abort before dispatch, during daemon processing, and after completion race.
- RP timeout and daemon timeout.
- Browser/tab shutdown.
- Nested frames and multiple simultaneous requests.
- `toJSON()` and response methods.
- RPs that use field access, JSON serialization, and `instanceof` checks.
- No accidental fallback to native security-key UI.

### Completion criteria

- Supported RPs observe normal promise, cancellation, timeout, error, and response behavior.
- The extension cannot leave an operation reusable after page cancellation.

## Phase 9: CLI, operator UX, and diagnostics

### Tasks

1. Add guided configuration commands, for example:
   - `passless agent profile init --mode same-user`;
   - `passless agent profile init --mode isolated`;
   - `passless agent rule add --rp github.com --authenticate autonomous`.
2. Require an explicit warning acknowledgement for same-user autonomous profiles.
3. Show the effective normalized rule without exposing secrets.
4. Add `doctor` checks for:
   - human backend availability;
   - profile storage isolation;
   - selected key provider;
   - extension/daemon protocol version;
   - browser extension load;
   - audit write and fsync behavior;
   - session TTL and operation limits;
   - stale or contradictory configuration.
5. Add session list/revoke commands for administrators.
6. Add audit rendering that clearly labels:
   - same-user versus isolated;
   - agent versus human UP/UV;
   - successful, denied, cancelled, replayed, and expired operations.
7. Keep the capability token out of normal logs and command output.

### Completion criteria

- An operator can create both common profiles without hand-authoring every nested field.
- The effective trust statement is visible before enabling same-user autonomy.
- Diagnostics identify backend/provider mistakes before the first RP operation.

## Phase 10: Migration and cleanup

### Tasks

1. Route current isolated extension authentication and registration through the unified services.
2. Retain the old path behind a temporary rollback flag until E2E gates pass.
3. Remove handler-local provider construction and duplicated WebAuthn semantics.
4. Replace grant replay semantics with session plus one-shot operation semantics.
5. Update or remove tests that encode repeated-sign behavior.
6. Remove dead human-storage arguments only after they are replaced by the backend handle.
7. Remove stale delegated-session mode references from:
   - agent documentation;
   - examples;
   - installed skills;
   - plan status files;
   - CLI help;
   - comments and tests.
8. Mark ADRs 0001, 0005, and 0006 as superseded or amended by ADR 0007 where appropriate, while preserving their historical findings.
9. Deprecate the legacy `policy` evidence spelling if the alias was shipped.
10. Remove the experimental gate only after release criteria are met.

### Rollback strategy

- Before same-user ships, rollback means disabling the unified gate and using the current isolated path.
- After isolated migrates, keep one release with a hidden compatibility switch if operationally practical.
- Same-user never falls back to path sharing or key export. If its backend resolution fails, startup or the operation fails closed.
- Schema changes remain backward-readable for isolated profiles throughout the migration window.

## Proposed PR sequence

Each implementation PR should be independently reviewable and identify the verification rows it closes.

1. **Config model and experimental gate**
   - mode/evidence enums, aliases, validation, baseline regressions.
2. **Credential backend handle**
   - human and isolated construction, provider/lock wiring, no behavior exposure.
3. **Session and one-shot operation state machine**
   - replay protection and lifecycle tests.
4. **Evidence providers**
   - agent and human evidence, flag derivation, UV regressions.
5. **Unified authentication service**
   - isolated migration first, then same-user behind gate.
6. **Authentication real-RP software gate**
   - same-user and isolated E2E.
7. **Unified registration service**
   - algorithm negotiation, backend target, register/authenticate E2E.
8. **Origin and extension lifecycle correctness**
   - sender metadata, ports, cancellation, timeout, response facade.
9. **Portable-TPM gates**
   - same-user and isolated authentication/registration.
10. **Cross-origin iframe support or explicit permanent limitation**
    - separate review because of browser security complexity.
11. **CLI, doctor, audit UX, and documentation migration**
12. **Remove old path and experimental gate**

Large PRs that mix backend ownership, browser transport, crypto construction, and cleanup should be avoided.

## Verification environments

### Unit and property testing

- Pure config validation.
- Session and operation state machines with deterministic clocks.
- Origin/RP validation with public-suffix fixtures.
- Canonical request hashing.
- Credential selection.
- Authenticator data and client data byte-level checks.
- Cryptographic signature verification.
- Property tests for one-shot state transitions and no terminal-to-active transition.

### Integration testing

- In-memory software backend.
- Filesystem/pass-style backend where supported.
- Portable-TPM provider with simulator or test TPM.
- Concurrent human and same-user operations.
- Extension-to-daemon protocol with a test browser page.
- Audit failure injection and storage failure injection.

### Real-RP E2E

Minimum targets:

- Gitea or Forgejo controlled instance for registration and authentication.
- One external RP with username-first `allowCredentials` flow.
- One discoverable-credential flow.
- One RP requesting `userVerification = required`.
- One page using JSON serialization of the credential response.
- A compatibility fixture that performs `instanceof PublicKeyCredential` to define whether a proxy adapter is required.

Run software E2E in CI where practical. Portable-TPM and selected external-RP gates may be release/manual gates with captured command output and audit evidence.

## Observability

Add metrics with bounded labels:

- active sessions by mode;
- session creation, expiry, revoke, and operation-budget exhaustion;
- operations by action, mode, authorization source, evidence source, and result class;
- replay and request-binding rejection counts;
- backend/provider operation latency;
- human-verification latency and cancellation;
- audit reservation/finalization failures;
- extension protocol-version mismatches.

Do not use RP IDs, origins, credential IDs, user handles, session IDs, or operation IDs as unbounded metric labels. Those belong in protected audit and debug logs with appropriate redaction.

## Performance targets

The redesign is security-driven, but should not make local authentication impractical.

Initial non-normative targets on a local software backend:

- session lookup and operation creation: under 5 ms p95;
- policy/backend/evidence resolution for autonomous operation: under 5 ms p95 excluding audit storage;
- total daemon authentication overhead excluding provider signing and browser transport: under 20 ms p95;
- no global lock across independent isolated backends;
- serialization only on operations sharing the same backend handle.

Human verification and TPM signing have provider-dependent latency and are measured separately.

## Release criteria

`same-user` may leave the experimental gate only when all of the following are true:

1. All mandatory rows in the verification matrix pass.
2. No handler hardcodes a key provider or opens credential storage.
3. RP-requested UV without resolved evidence is covered by a passing regression test.
4. Replaying a completed operation is covered by concurrency and E2E tests.
5. Same-user software authentication passes a real RP with an existing human credential.
6. Same-user required-UV autonomous authentication passes and audit labels UV as agent evidence.
7. Same-user human-UV forwarding passes and audit labels UV as human evidence.
8. Isolated authentication and registration remain green.
9. Same-user registration is either fully gated and tested or explicitly disabled in the first release.
10. Portable-TPM same-user authentication passes before documentation claims TPM support.
11. Origin-with-port, RP suffix, public suffix, and top-level frame tests pass.
12. Abort, timeout, browser shutdown, policy reload, and daemon restart consume or invalidate authority.
13. Audit failure prevents key use.
14. Operator documentation states the same-user trust boundary prominently.
15. Security review finds no path from isolated mode to the human backend.

## Decisions intentionally deferred

These items are outside the first implementation unless a blocker is discovered:

- durable sessions across daemon restart;
- reusable human-verification caches;
- enterprise attestation;
- arbitrary authenticator extensions;
- unrestricted cross-origin iframe support;
- native messaging as the extension transport;
- RP-visible distinction between human and agent UV, which standard WebAuthn flags do not provide;
- business-action authorization after the RP login completes;
- protection against host root, kernel, daemon administrator, or browser-extension compromise.

Deferred items must not be simulated with misleading flags or permissive fallbacks.

## Definition of done

The redesign is complete when an operator can configure:

```toml
[agents.profiles.opencode]
mode = "same-user"

[[agents.profiles.opencode.rules]]
rp_id = "github.com"
authenticate = "autonomous"
register = "deny"
```

and a daemon-launched agent browser can authenticate with an existing human passkey, including an RP-required UV request, without human interaction, while:

- the extension never receives the private key;
- the daemon uses the real human backend and provider;
- the operation is exact-RP, origin-bound, one-shot, short-lived, replay-resistant, and audited;
- audit identifies agent-derived UP/UV;
- a separately configured isolated profile cannot access that human credential;
- changing `user_verification` to `human` forwards verification to the human path rather than silently approving it;
- disabling or revoking the session immediately prevents further credential operations.
