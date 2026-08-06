# ADR 0006: Agent Passkey Registration - Implementation Plan

**Status:** Complete
**Created:** 2026-08-03
**ADR:** [0006-agent-passkey-registration.md](../decisions/0006-agent-passkey-registration.md)

## Overview

This plan implements agent-driven passkey registration via the daemon-backed WebAuthn extension, extending ADR 0005's authentication flow to cover credential creation.

## Phase 1: Protocol Types
**Status:** ✅ COMPLETED 2026-08-03

**Goal:** Add registration request/response types and registration grant ID type.

**Files:**
- `passless-core/src/agent/protocol.rs`
- `passless-core/src/agent/ids.rs`

**Tasks:**
1. Add `RegisterCredentialRequest` struct with fields:
   - `origin: String`
   - `rp_id: String`
   - `challenge_b64u: String`
   - `user_id_b64u: String`
   - `user_name: String`
   - `user_display_name: Option<String>`
   - `rp_name: Option<String>`
   - `exclude_credentials: Vec<String>`
   - `user_verification: bool`
   - `cross_origin: bool`

2. Add `RegisterCredentialResponse` struct with fields:
   - `credential_id_b64u: String`
   - `authenticator_data_b64u: String`
   - `attestation_object_b64u: String`
   - `client_data_json_b64u: String`

3. Add `RegistrationGrantId` opaque ID type in `ids.rs`

4. Add `AdminRequest::RequestRegistration` variant:
   ```rust
   RequestRegistration {
       profile_id: ProfileId,
       rp_id: String,
       max_session_ttl: u64,
       reason: Option<String>,
   }
   ```

5. Add `AdminResponse::RegistrationGranted` variant with `RegistrationGrantId`

**Verification:**
```bash
cargo build -p passless-core
cargo test -p passless-core
```

**Exit Criteria:**
- Protocol types compile
- Serialization/deserialization works
- No breaking changes to existing types

---

## Phase 2: Registration Grant System
**Status:** ✅ COMPLETED 2026-08-03

**Goal:** Implement registration grant lifecycle (request, approve, expire, revoke).

**Files:**
- `cmd/passless/src/agent/grant.rs`
- `cmd/passless/src/agent/policy_engine.rs`
- `cmd/passless/src/agent/runtime.rs`

**Tasks:**
1. Add `RegistrationGrant` struct in `grant.rs`:
   ```rust
   pub struct RegistrationGrant {
       pub id: RegistrationGrantId,
       pub profile_id: ProfileId,
       pub session_id: PrincipalSessionId,
       pub endpoint_id: EndpointId,
       pub principal_digest: [u8; 32],
       pub rp_id: String,
       pub issued_at_mono: u64,
       pub expiry_mono: u64,
       state: AtomicU8,
   }
   ```

2. Add `RegistrationGrantRegistry` to manage registration grants:
   - `request_registration()` - create pending request
   - `approve_registration()` - approve and create grant
   - `resolve_registration_grant()` - validate grant for registration
   - `revoke_registration()` - revoke grant
   - `check_expired()` - clean up expired grants

3. Add `PolicyRuntime::authorize_registration()` method:
   - Check `rule_for_rp(rp_id).register.authorization == Allow`
   - Return `Outcome::Allow` or `Outcome::Deny` with reason

4. Add `handle_request_registration()` in `runtime.rs`:
   - Parse `AdminRequest::RequestRegistration`
   - Call `policy_runtime.authorize_registration()`
   - If allowed, create registration grant
   - Return `AdminResponse::RegistrationGranted`

5. Add registration grant expiration cleanup (reuse existing grant cleanup interval)

**Verification:**
```bash
cargo build --features agent
cargo test --features agent grant::
cargo test --features agent policy_engine::
```

**Exit Criteria:**
- Registration grants can be requested and approved
- Grants expire after TTL
- Policy evaluation works correctly
- Revocation works

---

## Phase 3: Daemon Registration Handler
**Status:** ✅ COMPLETED 2026-08-03

**Goal:** Implement `/register` HTTP endpoint with full validation pipeline.

**Files:**
- `cmd/passless/src/agent/register.rs` (new file)
- `cmd/passless/src/agent/sign.rs` (add to HTTP server)
- `cmd/passless/src/agent/mod.rs`

**Tasks:**
1. Create `RegisterHandler` struct (mirrors `SignHandler`):
   ```rust
   pub struct RegisterHandler {
       pub human_storage: Arc<Mutex<Box<dyn CredentialStorage>>>,
       pub policy_runtime: Arc<PolicyRuntime>,
       pub audit_gate: Arc<AuditGate>,
       pub key_provider: Arc<dyn CredentialKeyProvider + Send + Sync>,
       pub security_config: SecurityConfig,
       pub operation_lock: Arc<Mutex<()>>,
   }
   ```

2. Implement `RegisterHandler::register()` method:
   - Validate bearer token (reuse `SignContextRegistry::lookup_bound()`)
   - Validate origin (reuse `verify_origin_structural()`)
   - Acquire operation lock
   - Resolve registration grant
   - Check RP ID in grant scope
   - Check ceremony policy (`register.authorization == Allow`)
   - Check exclude list against existing credentials
   - Record audit event (`AuditAction::Register`)
   - Generate keypair via `key_provider.generate()`
   - Generate credential ID (random 32 bytes)
   - Build `authenticatorData` with attested credential data:
     - `rpIdHash = SHA-256(rp_id)`
     - `flags = 0x41` (UP + AT)
     - `signCount = 0`
     - `AAGUID` (16 bytes)
     - `credentialIdLength` (2 bytes, big-endian)
     - `credentialId` (variable)
     - `credentialPublicKey` (COSE key)
   - Build `clientDataJSON` with type `"webauthn.create"`
   - Build attestation statement (self-attestation, format "none")
   - Write credential to storage via `CredentialStorage::write()`
   - Return `RegisterCredentialResponse`

3. Add `build_authenticator_data_for_registration()` function:
   - Construct attested credential data
   - Encode COSE public key (P-256 for ES256)

4. Add `build_client_data_json_for_registration()` function:
   - Type: `"webauthn.create"`
   - Challenge: base64url-decode then re-encode
   - Origin: from request
   - Cross-origin: from request

5. Add HTTP endpoint to daemon's HTTP server in `sign.rs`:
   - Route `POST /register` to `RegisterHandler::register()`
   - Reuse bearer token validation from `/sign`
   - Reuse CORS headers

6. Add unit tests:
   - Test validation pipeline (origin, grant, policy, exclude list)
   - Test `authenticatorData` construction
   - Test `clientDataJSON` construction
   - Test storage write
   - Test error cases (invalid origin, expired grant, denied policy)

**Verification:**
```bash
cargo build --features agent
cargo test --features agent register::
cargo test --features agent sign::  # Ensure /sign still works
```

**Exit Criteria:**
- `/register` endpoint accepts valid requests
- Validation pipeline rejects invalid requests
- Credentials are written to storage
- Response matches WebAuthn spec

---

## Phase 4: Extension Registration Override
**Status:** ✅ COMPLETED 2026-08-03

**Goal:** Override `navigator.credentials.create()` in the extension.

**Files:**
- `cmd/passless/assets/agent-extension/main.js`
- `cmd/passless/assets/agent-extension/broker.js`
- `cmd/passless/assets/agent-extension/worker.js`

**Tasks:**
1. Extend `main.js` to override `credentials.create()`:
   - Add `originalCreate = credentials.create.bind(credentials)`
   - Override `credentials.create = function(options) { ... }`
   - Serialize `PublicKeyCredentialCreationOptions`:
     - `rp.id`, `rp.name`
     - `user.id` (base64url), `user.name`, `user.displayName`
     - `challenge` (base64url)
     - `pubKeyCredParams` (array of `{type, alg}`)
     - `excludeCredentials` (array of base64url IDs)
   - Post to broker via `window.postMessage`
   - Wait for response with timeout (30s)
   - Deserialize response into duck-typed `PublicKeyCredential`:
     - `id`: credential ID (base64url)
     - `rawId`: credential ID (ArrayBuffer)
     - `type`: `"public-key"`
     - `response.attestationObject`: base64url-decode
     - `response.clientDataJSON`: base64url-decode
     - `response.getTransports()`: return `["internal"]`
     - `response.getAuthenticatorData()`: extract from attestation object
     - `response.getPublicKey()`: extract from attestation object
     - `response.getPublicKeyAlgorithm()`: return `-7` (ES256)

2. Extend `broker.js` to validate registration requests:
   - Validate `rp.id` is present and valid
   - Validate `user.id` is present
   - Validate `challenge` is present
   - Forward to worker via `chrome.runtime.sendMessage`

3. Extend `worker.js` to handle registration:
   - Extract origin from `sender.url`
   - Construct `RegisterCredentialRequest`
   - POST to `http://127.0.0.1:<port>/register` with bearer token
   - Return response to broker

4. Add input validation:
   - Max challenge length: 1024 bytes
   - Max RP ID length: 253 characters
   - Max credential ID length: 256 bytes
   - Max exclude credentials: 64

**Verification:**
```bash
# Manual test with browser
# 1. Start daemon with agent profile
# 2. Launch browser with extension
# 3. Navigate to test RP registration page
# 4. Trigger registration
# 5. Verify credential is created
```

**Exit Criteria:**
- Extension overrides `credentials.create()`
- Registration request is sent to daemon
- Response is returned to page
- Duck-typed credential is accepted by RP

---

## Phase 5: Testing
**Status:** ✅ COMPLETED 2026-08-03

**Goal:** Comprehensive testing of registration flow.

**Files:**
- `cmd/passless/src/agent/register.rs` (unit tests)
- `cmd/passless/tests/agent_registration_e2e.rs` (new file)

**Tasks:**
1. Unit tests for `RegisterHandler`:
   - Test origin validation (HTTPS only, exact host match)
   - Test grant validation (exists, not expired, RP matches)
   - Test policy validation (register.authorization == Allow)
   - Test exclude list validation
   - Test key generation (software and TPM)
   - Test `authenticatorData` construction (verify against WebAuthn spec)
   - Test `clientDataJSON` construction (verify against WebAuthn spec)
   - Test storage write (credential is persisted)
   - Test error cases (invalid origin, expired grant, denied policy)

2. Integration tests for registration grant lifecycle:
   - Test grant request and approval
   - Test grant expiration
   - Test grant revocation
   - Test policy evaluation

3. E2E tests:
   - Test registration via extension (controlled RP)
   - Test authentication with newly registered credential
   - Test registration with TPM backend
   - Test registration with exclude list
   - Test registration denied by policy

4. Security tests:
   - Test origin spoofing
   - Test replay attacks
   - Test unauthorized registration
   - Test concurrent registration requests

**Verification:**
```bash
cargo test --features agent
make test-e2e
```

**Exit Criteria:**
- All unit tests pass
- All integration tests pass
- E2E tests pass with controlled RP
- Security tests pass

---

## Phase 6: Documentation
**Status:** ✅ COMPLETED 2026-08-04

**Goal:** Update documentation to reflect registration support.

**Files:**
- `docs/decisions/0006-agent-passkey-registration.md` (update status)
- `docs/plans/adr-0006-agent-registration-implementation.md` (update status)
- `cmd/passless/assets/skills/passless-agent/SKILL.md` (add registration examples)
- `docs/AGENT_REGISTRATION.md` (new file, operator guide)

**Tasks:**
1. Update ADR 0006 status to "Accepted" and "Implemented"
2. Update implementation plan with verification evidence
3. Add registration examples to agent skill:
   - How to configure registration policy
   - How to register a credential
   - How to authenticate with registered credential
4. Create operator guide for agent registration:
   - Configuration examples
   - Security considerations
   - Troubleshooting

**Verification:**
```bash
# Review documentation for accuracy
```

**Exit Criteria:**
- Documentation is accurate and complete
- Examples are tested and working

---

## Execution Strategy

**Phase Dependencies:**
- Phase 1 (Protocol) → Phase 2 (Grants) → Phase 3 (Handler) → Phase 4 (Extension) → Phase 5 (Testing) → Phase 6 (Docs)

**Parallelization:**
- Phase 1 and Phase 4 can be done in parallel (protocol types and extension override)
- Phase 5 can start after Phase 3 (unit tests for handler)
- Phase 6 can start after Phase 5 (documentation)

**Subagent Allocation:**
- **Subagent 1:** Phase 1 (Protocol types)
- **Subagent 2:** Phase 2 (Registration grants)
- **Subagent 3:** Phase 3 (Registration handler)
- **Subagent 4:** Phase 4 (Extension override)
- **Subagent 5:** Phase 5 (Testing)
- **Subagent 6:** Phase 6 (Documentation)

**Risk Mitigation:**
- Each phase has clear exit criteria and verification steps
- Phases are incremental (each builds on the previous)
- Unit tests are written alongside implementation
- E2E tests validate the full flow

---

## Success Criteria

1. **Functional:** Agents can register passkeys without human interaction
2. **Security:** Private keys never leave the daemon; origin and policy are enforced
3. **Compatibility:** Works with software and TPM backends
4. **Testability:** All tests pass (unit, integration, E2E, security)
5. **Documentation:** Operators can configure and use agent registration

---

## Timeline

- **Phase 1:** 1 day
- **Phase 2:** 2 days
- **Phase 3:** 3 days
- **Phase 4:** 2 days
- **Phase 5:** 3 days
- **Phase 6:** 1 day
- **Total:** 12 days

---

## Notes

- The implementation follows the same patterns as ADR 0005 (authentication)
- The two-phase grant model (registration → authentication) is a key design decision
- Self-attestation ("none") is used for simplicity and compatibility
- Default-deny policy ensures explicit opt-in for registration
