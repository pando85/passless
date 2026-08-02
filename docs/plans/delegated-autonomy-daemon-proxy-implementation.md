# Delegated Autonomy Daemon Proxy Implementation Plan

- **Status:** In progress
- **Date:** 2026-08-02
- **Owners:** Passless maintainers
- **Implements:** [ADR 0005](../decisions/0005-delegated-autonomous-authentication-redesign.md)
- **Verification detail:** [ADR 0005 verification matrix](adr-0005-verification-matrix.md)

## Completion Rule

This plan is complete only when every required phase below passes and ADR 0005 is updated to `Accepted` and `Implemented`. A skipped real-RP, negative-security, isolated-mode, confirm-policy, or portable-TPM gate is incomplete evidence, not a pass.

The final implementation must establish all of these properties:

- Chromium performs autonomous assertion without its native credential dialog.
- An `allow` rule produces no desktop notification.
- The Passless daemon is the only signer and private key material never enters the browser.
- The daemon validates the frame origin, RP ID, active grant, credential reference, policy, and audit gate before key use.
- `confirm` and `deny` rules never use the autonomous signing endpoint.
- Software and portable-TPM credentials use the same `CredentialKeyProvider` path.
- Isolated mode and its human-confirmation ceremony path remain functional.
- The delegated-session ceremony and pre-authorization code made obsolete by the proxy path is removed.
- The real relying party accepts the daemon-built `clientDataJSON`, authenticator data, and signature.

## Fixed Contracts

These contracts are frozen before parallel implementation. A change requires updating the ADR, this plan, both sides of the transport, and their tests.

### Browser interception

1. An MV3 extension installs a `document_start` MAIN-world wrapper around `navigator.credentials.get` on HTTPS frames.
2. The wrapper intercepts only calls containing `options.publicKey`; unrelated Credentials API calls use the original bound implementation.
3. The wrapper reads the calling frame's `location.origin`. The page cannot provide or override the origin sent to the daemon.
4. A supported WebAuthn request that reaches the daemon never falls back to native WebAuthn after an error. It rejects with `NotAllowedError`, preventing a native credential dialog from appearing after a policy denial.
5. A separate isolated-world broker owns the endpoint bearer and performs the localhost request. No bearer or endpoint configuration is written to a MAIN-world global, DOM attribute, page event payload, console, or log.
6. The broker accepts requests only from its own frame, derives the same frame origin independently, applies message size bounds, and correlates one response to one request with an unguessable per-frame channel nonce.

### Daemon request and response

The logical request contains:

```text
origin
rp_id
challenge_b64u
allow_credentials[] = { id_b64u, type }
user_verification
cross_origin
```

The daemon selects the exact credential from the active grant. If `allow_credentials` is non-empty, the selected credential ID must occur in it. The browser does not choose or submit an authoritative credential reference.

The successful response contains:

```text
credential_id_b64u
authenticator_data_b64u
signature_b64u
user_handle_b64u
client_data_json_b64u
```

All binary values use unpadded base64url. Request bodies, collection lengths, strings, and HTTP read time are bounded.

### Client data and signature

The daemon constructs the exact no-whitespace bytes:

```json
{"type":"webauthn.get","challenge":"<base64url-no-pad>","origin":"<origin>"}
```

When cross-origin is true, `,"crossOrigin":true` is appended before the closing brace. The daemon hashes and returns these same bytes.

The signed message is:

```text
authenticatorData || SHA256(clientDataJSON)
```

Authenticator data mirrors soft-fido2 assertion construction:

```text
SHA256(rpId) || flags || signCount.to_be_bytes()
```

Flags include UP, policy-satisfied UV, and the credential backup state. Extensions are initially unsupported and the ED bit is clear.

### Authorization and state

1. The parsed origin must be an HTTPS origin with no username, password, path other than `/`, query, or fragment.
2. The origin must exactly match an origin derived from the configured allowed RP ID. Port handling must be explicit and tested; no suffix or substring matching is allowed.
3. The request RP ID must match the active grant and profile rule.
4. The selected credential reference must match the active grant and profile allowlist.
5. Only `authorization = "allow"` can sign. `confirm` and `deny` fail before key-provider invocation.
6. Audit authorization must succeed before storage mutation or key use.
7. Grant validation, counter read/update, audit transition, and signing are serialized so concurrent requests cannot bypass TTL, reuse one-shot authority, or lose a counter update.
8. Constant-counter mode returns zero and performs no counter write. Otherwise a discoverable credential increments with saturation behavior matching soft-fido2 and persists through the human storage path before signing.
9. Any failed persistence, audit, policy, origin, grant, or credential check returns no assertion.

### Local channel

1. The listener binds only `127.0.0.1` on an ephemeral port.
2. Each browser lease receives a cryptographically random token with at least 256 bits of entropy.
3. The token is compared without early-exit leakage, is never logged, and expires when the lease ends.
4. Endpoint metadata and generated extension files are lease-scoped, mode-restricted, correctly owned, and deleted or quarantined with the browser profile.
5. HTTP accepts only the required method, path, content type, allowed origin, bounded body, and bearer. Error bodies contain stable codes but no credential or token material.
6. The bearer limits accidental localhost access but is not the phishing boundary. Origin, grant, policy, and credential checks remain mandatory.

## Phase 0: Baseline and Contract Tests

### Changes

- Record the pre-change branch, existing test status, configured Chromium version, and available TPM test environment.
- Add protocol round-trip and validation tests before connecting either transport side.
- Add exact fixtures for canonical client data and authenticator data.
- Add a fake key provider that records whether signing was attempted.
- Add test fixtures for allow, confirm, deny, expired grant, wrong RP, wrong origin, wrong credential, and audit failure.

### Verification

```bash
CARGO_TARGET_DIR=/tmp/passless-build cargo build -p passless-rs
CARGO_TARGET_DIR=/tmp/passless-build cargo build -p passless-rs --features agent
CARGO_TARGET_DIR=/tmp/passless-build cargo test -p passless-core agent::protocol
CARGO_TARGET_DIR=/tmp/passless-build cargo test -p passless-rs --features agent agent::
```

### Exit Gate

- Both feature configurations compile before new runtime wiring is enabled.
- Every fixed binary and JSON fixture has a byte-exact expected value.
- Denial fixtures can assert that the fake key provider was not called.

## Phase 1: Daemon Signing Oracle

### Changes

- Add `PrincipalRequest::SignAssertion` and its response for direct integration testing and trusted principal use.
- Implement one core signing operation shared by principal IPC and the localhost adapter.
- Resolve the active grant and its exact credential server-side.
- Reuse or extract policy, credential-reference, grant, and audit checks from the delegated ceremony path.
- Read and update the credential through narrowly scoped storage operations that preserve locking, immutable fields, and monotonic-counter checks.
- Construct canonical client data and authenticator data in the daemon.
- Sign through the configured `CredentialKeyProvider` without matching on software key material.
- Implement lease-scoped localhost listener startup, shutdown, request bounds, bearer validation, and stable error mapping.

### Verification

```bash
CARGO_TARGET_DIR=/tmp/passless-build cargo test -p passless-rs --features agent agent::sign
CARGO_TARGET_DIR=/tmp/passless-build cargo test -p passless-rs --features agent agent::runtime
CARGO_TARGET_DIR=/tmp/passless-build cargo test -p passless-rs --features agent agent::storage
```

Required behavioral cases:

- A known P-256 test key produces a signature verified against the returned client data and authenticator data.
- Authenticator data is byte-identical to the soft-fido2 assertion layout for equivalent inputs.
- Wrong origin, wrong RP, wrong credential, missing/expired grant, confirm policy, deny policy, and audit failure invoke the key provider zero times.
- Missing and incorrect bearer requests are rejected.
- Repeated and concurrent successful calls preserve counter monotonicity.
- Constant-counter mode remains zero and does not write storage.
- Daemon restart does not roll the counter back.

### Exit Gate

- One core handler is used by both front doors.
- All denials happen before signing.
- The HTTP listener is unreachable on non-loopback interfaces and shuts down with its lease.
- Software credentials sign and verify without exposing private material in protocol values or logs.

## Phase 2: Extension and Browser Lease Integration

### Changes

- Package minimal MV3 extension assets with a MAIN-world shim and isolated-world broker.
- Preserve the original Credentials API method for unsupported non-WebAuthn calls.
- Serialize WebAuthn request options without losing ArrayBuffer values.
- Return the Gitea/Forgejo-compatible credential shape with `id`, `rawId`, `type`, `getClientExtensionResults`, and assertion response fields.
- Generate a fresh extension directory inside each browser lease with restrictive permissions.
- Supply endpoint configuration only to the isolated-world broker.
- Launch Chromium with exactly the generated extension directory via `--load-extension`.
- Remove generated files through the existing lease cleanup and quarantine behavior.

### Verification

```bash
node --check cmd/passless/assets/agent-extension/main.js
node --check cmd/passless/assets/agent-extension/broker.js
node -e 'const fs=require("fs"); JSON.parse(fs.readFileSync("cmd/passless/assets/agent-extension/manifest.json"))'
CARGO_TARGET_DIR=/tmp/passless-build cargo test -p passless-rs --features agent agent::browser
```

Browser harness cases:

- Chromium reports the extension loaded without manifest, service-worker, or content-script errors.
- The wrapper exists before RP application JavaScript runs.
- The page cannot read the bearer through globals, DOM, events, stack traces, console messages, or extension resources.
- A valid test-RP request reaches a mock daemon and returns a duck-typed credential with byte-correct ArrayBuffers.
- Missing daemon, malformed response, timeout, and policy denial reject with `NotAllowedError` without invoking native WebAuthn.
- A non-`publicKey` Credentials API call reaches the original bound method.
- Subframes report their own origin and cannot claim their parent origin.
- Lease cleanup removes the extension and token; cleanup failure quarantines them.

### Exit Gate

- No private key enters Chromium.
- No page-visible value contains the endpoint bearer.
- The generated extension is the only unpacked extension enabled by Passless.
- Browser launch and cleanup tests pass for pipe and port CDP modes.

## Phase 3: Deterministic Security Integration

### Changes

- Add an in-process or local controlled RP that emits a known challenge and verifies the complete assertion.
- Add a browser integration harness that drives only navigation and the RP's passkey action.
- Capture daemon audit observations, key-provider calls, sign counter, notification-bus calls, and browser dialog evidence without storing secrets.
- Add concurrency and lease-expiry scenarios.

### Verification

Run the controlled-RP matrix:

| Scenario | Expected result |
|---|---|
| Valid allow grant | Assertion accepted; one sign; allow audit |
| Wrong frame origin | `NotAllowedError`; zero signs; deny audit |
| Wrong RP ID | `NotAllowedError`; zero signs; deny audit |
| Credential absent from `allowCredentials` | `NotAllowedError`; zero signs |
| Expired/revoked grant | `NotAllowedError`; zero signs; deny audit |
| Confirm policy | Autonomous endpoint denies; zero signs |
| Deny policy | Autonomous endpoint denies; zero signs |
| Audit sink failure | Fail closed; zero signs |
| Two concurrent requests | Serialized authority and monotonic counters |
| Browser/endpoint crash | Lease cleanup or quarantine; no reusable token |

```bash
CARGO_TARGET_DIR=/tmp/passless-build cargo test -p passless-rs --features agent --test agent_config_integration
CARGO_TARGET_DIR=/tmp/passless-build cargo test -p passless-rs --features agent
make test-agent-validation
```

### Exit Gate

- The controlled RP independently verifies the assertion signature, RP hash, challenge, origin, flags, and counter.
- Allow produces no notification call and no native credential selection.
- Every negative case proves zero key-provider calls, not merely an HTTP error.
- Evidence contains no bearer, credential ID, user handle, raw assertion, cookie, or key material.

## Phase 4: Real-RP Software Credential Gate

### Prerequisites

- The configured `opencode` delegated-session profile permits only the intended RP and credential.
- The existing software credential remains registered at `https://tea.millaguie.net`.
- A fresh daemon-built debug or release binary includes the extension path.
- CDP virtual-authenticator APIs and credential injection scripts are not used.

### Procedure

1. Start the daemon with debug logging directed to a temporary evidence directory.
2. Start a fresh delegated session and its daemon-managed Chromium lease.
3. Monitor D-Bus notification calls and Chromium dialog/extension errors.
4. Use CDP or Playwright only to navigate and click the RP's passkey action.
5. Confirm arrival at the authenticated dashboard.
6. Decode a sanitized copy of returned client data and confirm the exact challenge and origin.
7. Confirm audit allow, active-grant use, selected credential reference, counter persistence, and key-provider invocation.
8. Repeat with an expired grant and an unallowed origin; both must deny before signing.
9. Restart the daemon and confirm the next successful assertion advances the persisted counter.

### Exit Gate

- The RP accepts the assertion and establishes a session.
- No native credential dialog appears.
- No desktop notification is sent for `allow`.
- Logs prove the daemon signing handler, policy, grant, origin, credential, audit, and storage paths were used.
- No CDP virtual authenticator exists and no key extraction occurs.

## Phase 5: Remove the Bypassed Delegated Ceremony Path

### Changes

- Remove delegated-session UHID endpoint construction and delegated ceremony wrapping made obsolete by the extension path.
- Remove allow-policy interaction-token minting for delegated autonomous assertions.
- Remove `agent_mode` callback auto-approval and constructors used only by that bypassed path.
- Retain shared pieces still required by isolated mode and explicit human-confirmation flows.
- Make unsupported delegated registration behavior explicit rather than silently routing it through assertion autonomy.
- Update capability and instruction output to advertise only implemented behavior.

### Verification

```bash
rg 'with_shared_storage_and_pre_authorization|agent_mode' cmd/passless/src
CARGO_TARGET_DIR=/tmp/passless-build cargo test -p passless-rs --features agent agent::ceremony
CARGO_TARGET_DIR=/tmp/passless-build cargo test -p passless-rs --features agent agent::storage
CARGO_TARGET_DIR=/tmp/passless-build cargo test -p passless-rs --features agent agent::runtime
make test-agent-validation
```

Required regressions:

- Isolated registration, assertion, storage scope, revocation, and cross-profile denial still pass.
- Confirm-policy human approval, denial, timeout, and minimum-review-delay behavior still pass through the native ceremony path.
- Delegated `allow` uses only the extension signing oracle.
- No delegated UHID or hidraw device is created.
- Re-run the complete Phase 4 software-credential E2E after deletion.

### Exit Gate

- Searches and call-graph review show no obsolete delegated-autonomy token or callback bypass remains.
- Isolated and confirm paths have behavioral tests, not only compile coverage.
- Real-RP software login remains green after deletion.

## Phase 6: Portable-TPM End-to-End Gate

### Changes

- Add a test-provider assertion proving the oracle dispatches through the provider abstraction.
- Provision a dedicated per-run swtpm instance without killing or reusing unrelated host TPM processes.
- Create or register a portable-TPM-backed credential for a controlled RP, then exercise the full extension-to-daemon path.
- Exercise the configured real RP with a portable-TPM credential when registration is available.
- Capture TPM command/provider evidence without attempting unreliable process-memory absence proofs.

### Verification

```bash
CARGO_TARGET_DIR=/tmp/passless-build cargo test -p passless-rs --all-features --test tpm_portable -- --test-threads=1 --ignored
CARGO_TARGET_DIR=/tmp/passless-build cargo test -p passless-rs --all-features --test tpm_portable_storage -- --test-threads=1 --ignored
make test-e2e-tpm
```

Required evidence:

- Credential creation produces a portable TPM key reference, not a software scalar.
- The signing oracle invokes the portable TPM provider and the controlled/real RP verifies the ES256 signature.
- No PKCS#8 export, scalar extraction, CDP `addCredential`, native dialog, or desktop notification occurs.
- Wrong-origin, expired-grant, and confirm-policy requests invoke no TPM sign operation.
- swtpm and temporary state are stopped and removed by a per-run cleanup trap.

### Exit Gate

- Controlled-RP portable-TPM E2E passes.
- Real-RP portable-TPM E2E passes; if RP registration is unavailable, ADR 0005 remains incomplete.
- TPM failure and cleanup leave no reusable browser token or active grant.

## Phase 7: Repository-Wide Closure

### Documentation

- Update ADR 0005 to `Accepted` and `Implemented`, with implementation paths and dated verification evidence.
- Mark all phases and verification IDs complete in this plan and its matrix.
- Make the daemon-backed extension path authoritative in the installed agent skill.
- Keep the CDP virtual-authenticator workflow clearly labeled legacy/test-only.
- Update other architecture, security, configuration, and operator documentation that still describes delegated UHID autonomy.

### Final Verification

```bash
cargo fmt --all -- --check
CARGO_TARGET_DIR=/tmp/passless-build cargo build -p passless-rs
CARGO_TARGET_DIR=/tmp/passless-build cargo build -p passless-rs --features agent
CARGO_TARGET_DIR=/tmp/passless-build cargo clippy -p passless-rs --all-targets --features agent -- -D warnings
CARGO_TARGET_DIR=/tmp/passless-build cargo test -p passless-rs --features agent
CARGO_TARGET_DIR=/tmp/passless-build cargo test -p passless-core
make test-agent-validation
pre-commit run --all-files
```

Repeat the Phase 4 and Phase 6 real-RP scenarios against the exact binary to be committed. Record only sanitized pass/fail evidence and environment versions.

### Commit Gate

Before committing:

1. Review `git diff` for secrets, generated profiles, assertions, tokens, credential identifiers, screenshots, and unrelated local evidence.
2. Confirm the worktree contains only ADR 0005 implementation, tests, plans, and related documentation intended for the change.
3. Confirm every required phase has evidence and no required item is skipped.
4. Commit the ADR, implementation plan, verification matrix, code, tests, extension assets, skill, and directly related documentation together.
5. Do not amend or rewrite earlier commits.

Suggested commit subject:

```text
feat(agent): route autonomous assertions through daemon
```

## Failure and Rollback

- Any origin, policy, grant, credential, audit, storage, or provider uncertainty fails closed with no assertion.
- Any extension startup failure disables autonomous assertion for that lease; it does not enable CDP key injection or native fallback.
- Any cleanup failure quarantines the lease directory and revokes the bearer and grant before reporting failure.
- Debug artifacts remain under a mode-0700 temporary evidence directory and are deleted after sanitized results are recorded.
- Rollback removes the extension/oracle path while preserving the existing human and isolated authenticator paths; it must never restore CDP key injection as a production fallback.
