# ADR 0005 Architecture & Verification Diagrams

## System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Browser Extension (MV3)                         │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  MAIN World (content script)                                         │   │
│  │  - Intercepts navigator.credentials.create/get                       │   │
│  │  - Injects user_verification + allow_credentials                     │   │
│  │  - Unwraps {sign_assertion_result: {...}} response                   │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                              ↓ (window.postMessage)                          │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  ISOLATED World (broker)                                             │   │
│  │  - Validates extension ID, request format                            │   │
│  │  - Forwards to worker via Chrome messaging                           │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                              ↓ (chrome.runtime)                            │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  SERVICE Worker                                                      │   │
│  │  - HTTP POST to http://127.0.0.1:PORT/sign                           │   │
│  │  - Manages grant tokens, credential refs                             │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    ↓ HTTP
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Passless Daemon (agent run)                         │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  HTTP Sign Endpoint (127.0.0.1:PORT/sign)                            │   │
│  │  - Validates grant token (HMAC-SHA256, TTL, origin)                  │   │
│  │  - Checks confirm policy (if required)                               │   │
│  │  - Dispatches to CredentialKeyProvider                               │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                              ↓                                               │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  CredentialKeyProvider (trait)                                       │   │
│  │  - Software: soft_fido2_crypto::ecdsa::sign                          │   │
│  │  - TPM: TpmCredentialKeyProvider → TPM2_Sign                         │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                              ↓                                               │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │  Storage Backend                                                     │   │
│  │  - Local: JSON files in ~/.config/passless/fido2/                    │   │
│  │  - Pass: GPG-encrypted files in ~/.password-store/fido2/             │   │
│  │  - TPM: TPM-sealed blobs in ~/.config/passless/tpm/                  │   │
│  │  - TPM Portable: Portable parent at 0x81000001                       │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Authentication Flow Sequence

```
┌─────────┐      ┌──────────┐      ┌──────────┐      ┌──────────┐      ┌──────────┐
│  RP     │      │ Browser  │      │Extension │      │  Daemon  │      │ Storage  │
│(Gitea)  │      │          │      │(MV3)     │      │(agent)   │      │ Backend  │
└────┬────┘      └────┬─────┘      └────┬─────┘      └────┬─────┘      └────┬─────┘
     │                │                 │                 │                 │
     │ 1. navigator   │                 │                 │                 │
     │   .credentials │                 │                 │                 │
     │   .get()       │                 │                 │                 │
     │───────────────>│                 │                 │                 │
     │                │                 │                 │                 │
     │                │ 2. WebAuthn     │                 │                 │
     │                │   request with  │                 │                 │
     │                │   extension     │                 │                 │
     │                │────────────────>│                 │                 │
     │                │                 │                 │                 │
     │                │                 │ 3. Inject       │                 │
     │                │                 │   user_         │                 │
     │                │                 │   verification  │                 │
     │                │                 │   + allow_      │                 │
     │                │                 │   credentials   │                 │
     │                │                 │                 │                 │
     │                │                 │ 4. HTTP POST    │                 │
     │                │                 │   /sign         │                 │
     │                │                 │────────────────>│                 │
     │                │                 │                 │                 │
     │                │                 │                 │ 5. Validate     │
     │                │                 │                 │   grant token   │
     │                │                 │                 │   (HMAC, TTL)   │
     │                │                 │                 │                 │
     │                │                 │                 │ 6. Check        │
     │                │                 │                 │   confirm       │
     │                │                 │                 │   policy        │
     │                │                 │                 │                 │
     │                │                 │                 │ 7. Load         │
     │                │                 │                 │   credential    │
     │                │                 │                 │────────────────>│
     │                │                 │                 │                 │
     │                │                 │                 │ 8. Return       │
     │                │                 │                 │   credential    │
     │                │                 │                 │<────────────────│
     │                │                 │                 │                 │
     │                │                 │                 │ 9. Sign via     │
     │                │                 │                 │   KeyProvider   │
     │                │                 │                 │   (software/TPM)│
     │                │                 │                 │                 │
     │                │                 │ 10. Response    │                 │
     │                │                 │     {sign_      │                 │
     │                │                 │      assertion  │                 │
     │                │                 │      _result:   │                 │
     │                │                 │      {...}}     │                 │
     │                │                 │<────────────────│                 │
     │                │                 │                 │                 │
     │                │ 11. Unwrap      │                 │                 │
     │                │     envelope    │                 │                 │
     │                │<────────────────│                 │                 │
     │                │                 │                 │                 │
     │ 12. WebAuthn   │                 │                 │                 │
     │     response   │                 │                 │                 │
     │<───────────────│                 │                 │                 │
     │                │                 │                 │                 │
     │ 13. Verify     │                 │                 │                 │
     │     signature  │                 │                 │                 │
     │     (ES256)    │                 │                 │                 │
     │                │                 │                 │                 │
```

## What Was Tested

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           VERIFICATION MATRIX                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ✅ VERIFIED (Automated + Manual)                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  • U1: Extension protocol (user_verification, allow_credentials)    │   │
│  │  • U2: Broker validation (extension ID, request format)             │   │
│  │  • U3: Worker HTTP client (grant token, origin, TTL)                │   │
│  │  • U4.1: Sign handler dispatches to CredentialKeyProvider           │   │
│  │  • U4.2: RecordingKeyProvider records sign calls                    │   │
│  │  • I1-I7: HTTP integration tests (sign, validation, errors)         │   │
│  │  • S1-S13: Security tests (origin, TTL, replay, confirm policy)     │   │
│  │  • A1-A7: Audit/counter tests (increment, persistence)              │   │
│  │  • C1-C5: Confirm policy tests (always, never, conditional)         │   │
│  │  • CR1-CR6: Cancellation cleanup regression tests                   │   │
│  │  • T1: swtpm provisioning                                           │   │
│  │  • T2: Portable credential creation (unit tests)                    │   │
│  │  • T4: Key non-extractable contract (TPM-resident)                  │   │
│  │  • T5: CDP virtual-authenticator cannot replicate                   │   │
│  │  • T8: Portable TPM unit suite (3 tests)                            │   │
│  │  • T9: Portable TPM error handling (8 tests)                        │   │
│  │  • E1-E3: Real-RP software E2E (Gitea login)                        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ⚙️ PARTIALLY VERIFIED (Unit tests pass, E2E deferred)                     │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  • T3: Sign via extension path with TPM key                         │   │
│  │         → Requires credential bootstrap via CTAP registration       │   │
│  │  • T6: Real-RP E2E with TPM                                         │   │
│  │         → Requires credential bootstrap + live environment          │   │
│  │  • T7: TPM E2E existing suite (test_tpm_*)                          │   │
│  │         → Requires swtpm running                                    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ❌ NOT TESTED (Requires live environment)                                 │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  • Full daemon startup with TPM portable backend                    │   │
│  │  • End-to-end extension → daemon → TPM → RP flow                    │   │
│  │  • Multiple concurrent agents with different backends               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Test Coverage by Component

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              TEST COVERAGE                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Extension (MV3)                                                            │
│  ├─ main.js: protocol injection, response unwrapping          ✅ U1        │
│  ├─ broker.js: extension ID validation, request format        ✅ U2        │
│  └─ worker.js: HTTP client, grant token, origin               ✅ U3        │
│                                                                             │
│  Daemon (agent run)                                                         │
│  ├─ HTTP endpoint: sign, validation, errors                   ✅ I1-I7     │
│  ├─ Security: origin, TTL, replay, confirm policy             ✅ S1-S13    │
│  ├─ Audit/counter: increment, persistence                     ✅ A1-A7     │
│  ├─ Confirm policy: always, never, conditional                ✅ C1-C5     │
│  ├─ Cancellation cleanup: CR1-CR6                             ✅ CR1-CR6   │
│  └─ CredentialKeyProvider dispatch                            ✅ U4.1-U4.2 │
│                                                                             │
│  Storage Backend                                                            │
│  ├─ Local: JSON files                                       ✅ Unit tests  │
│  ├─ Pass: GPG-encrypted                                     ✅ Unit tests  │
│  ├─ TPM: TPM-sealed blobs                                   ✅ Unit tests  │
│  └─ TPM Portable: portable parent, sign-only                  ✅ T1-T9     │
│                                                                             │
│  Real-RP E2E                                                                │
│  ├─ Software backend: Gitea login                             ✅ E1-E3     │
│  └─ TPM backend: Gitea login with TPM credential            ⚙️ Deferred   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Credential Storage Comparison

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         STORAGE BACKEND COMPARISON                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Local Backend                                                              │
│  ├─ Storage: ~/.config/passless/fido2/<rp_id>/<credential_id>.json         │
│  ├─ Key material: Software scalar (soft_fido2_crypto)                       │
│  ├─ Extractable: Yes (JSON file)                                            │
│  └─ Security: File permissions only                                         │
│                                                                             │
│  Pass Backend                                                               │
│  ├─ Storage: ~/.password-store/fido2/<rp_id>/<credential_id>.gpg           │
│  ├─ Key material: Software scalar, GPG-encrypted                            │
│  ├─ Extractable: Yes (with GPG passphrase)                                  │
│  └─ Security: GPG encryption + file permissions                             │
│                                                                             │
│  TPM Backend                                                                │
│  ├─ Storage: ~/.config/passless/tpm/<rp_id>/<credential_id>.tpm            │
│  ├─ Key material: TPM-sealed blob (sealed by TPM owner hierarchy)           │
│  ├─ Extractable: No (TPM-resident, requires same TPM to unseal)             │
│  └─ Security: Hardware TPM, non-portable across machines                    │
│                                                                             │
│  TPM Portable Backend                                                       │
│  ├─ Storage: ~/.config/passless/tpm-portable/<rp_id>/<credential_id>.tpm   │
│  ├─ Key material: Portable parent at 0x81000001 (swtpm or hardware)         │
│  ├─ Extractable: No (TPM-resident, portable across machines with same TPM)  │
│  └─ Security: Hardware TPM or swtpm, portable with parent key               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Grant Mechanism Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         GRANT MECHANISM OVERVIEW                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Agent Process                                                              │
│  ├─ 1. Connect via Unix socket IPC                                         │
│  ├─ 2. Send RequestDelegation                                              │
│  │     {                                                                    │
│  │       profile_id: "tpm-test",                                           │
│  │       rp_id: "gitea.example.com",                                       │
│  │       credential_ref: "abc123...",                                      │
│  │       max_session_ttl: 300,                                             │
│  │       reason: "CI/CD pipeline"                                          │
│  │     }                                                                    │
│  ├─ 3. Receive GrantId (opaque ID)                                         │
│  └─ 4. Store grant_id in memory (not sent to browser)                      │
│                                                                             │
│  Daemon (passless agent run)                                                │
│  ├─ 1. Receive RequestDelegation via IPC                                   │
│  ├─ 2. Create grant request (pending approval)                             │
│  ├─ 3. Evaluate policy                                                     │
│  │     - Check confirm_policy                                              │
│  │     - Auto-approve if policy allows                                     │
│  │     - Or wait for admin approval                                        │
│  ├─ 4. Create Grant                                                        │
│  │     {                                                                    │
│  │       id: GrantId,                                                      │
│  │       profile_id: ProfileId,                                            │
│  │       session_id: PrincipalSessionId,                                   │
│  │       principal_digest: [u8; 32],                                       │
│  │       rp_ids: BTreeSet<String>,                                         │
│  │       credentials: CredentialSet,                                       │
│  │       issued_at_mono: u64,                                              │
│  │       expiry_mono: u64,                                                 │
│  │       state: Active                                                     │
│  │     }                                                                    │
│  └─ 5. Return GrantId to agent                                             │
│                                                                             │
│  Grant Validation (during sign)                                             │
│  ├─ Check grant exists in registry                                         │
│  ├─ Check grant not expired (TTL)                                          │
│  ├─ Check grant not revoked                                                │
│  ├─ Check RP matches grant's allowed RPs                                   │
│  ├─ Check credential matches grant's allowed credentials                   │
│  └─ If valid: sign without notification (confirm_policy: "never")          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Agent vs Human Authentication

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    AGENT vs HUMAN AUTHENTICATION                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Agent Authentication                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Authorization: Pre-authorized grant token                          │   │
│  │  User Presence: No notification, no prompt                          │   │
│  │  Confirm Policy: "never" (skip confirmation)                        │   │
│  │  TTL: Short-lived grant (e.g., 5m)                                  │   │
│  │  Process Identity: principal_digest (process hash)                  │   │
│  │  Audit Trail: policy.allow (agent grant)                            │   │
│  │  Communication: Unix socket IPC                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  Human Authentication                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Authorization: Real-time user confirmation                         │   │
│  │  User Presence: Desktop notification + click                        │   │
│  │  Confirm Policy: "always" or "conditional"                          │   │
│  │  TTL: Immediate (no grant needed)                                   │   │
│  │  Process Identity: Browser origin validation                        │   │
│  │  Audit Trail: policy.user_confirmed                                 │   │
│  │  Communication: Browser extension (HTTP)                            │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Security Boundaries

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SECURITY BOUNDARIES                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Extension Boundary                                                         │
│  ├─ MAIN world: Cannot access extension APIs directly                       │
│  ├─ ISOLATED world: Validates extension ID, request format                  │
│  └─ SERVICE worker: HTTP client, grant token management                     │
│                                                                             │
│  Daemon Boundary                                                            │
│  ├─ HTTP endpoint: 127.0.0.1 only (no external access)                      │
│  ├─ Grant token: HMAC-SHA256, TTL, origin binding                           │
│  ├─ Confirm policy: Always/never/conditional user confirmation              │
│  └─ Credential access: Storage backend abstraction                          │
│                                                                             │
│  Storage Boundary                                                           │
│  ├─ Local: File permissions (0600)                                          │
│  ├─ Pass: GPG encryption + file permissions                                 │
│  ├─ TPM: Hardware TPM, non-extractable                                      │
│  └─ TPM Portable: Hardware TPM, portable with parent key                    │
│                                                                             │
│  Attack Mitigations                                                         │
│  ├─ Origin spoofing: Extension validates origin in grant token              │
│  ├─ Replay attacks: Grant token has TTL, one-time use                       │
│  ├─ Unauthorized access: Confirm policy requires user confirmation          │
│  ├─ Key extraction: TPM backend keeps key TPM-resident                      │
│  └─ Credential theft: Storage backends use encryption/TPM sealing           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```
