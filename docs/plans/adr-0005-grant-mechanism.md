# ADR 0005: Grant Mechanism & Authentication Flows

## Overview

This document explains how the agent authentication mechanism works in ADR 0005, including the grant system, the difference between agent and human authentication, and the complete authentication flow.

## Table of Contents

1. [Grant Mechanism](#grant-mechanism)
2. [Agent vs Human Authentication](#agent-vs-human-authentication)
3. [Complete Authentication Flow](#complete-authentication-flow)
4. [Grant Lifecycle](#grant-lifecycle)
5. [Security Properties](#security-properties)
6. [Implementation Details](#implementation-details)

---

## Grant Mechananism

### What is a Grant?

A **grant** is an opaque identifier that the daemon uses to track which agent process is authorized to perform authentication operations. Unlike a signed token (e.g., JWT), a grant is:

- **Not self-contained**: The grant state is managed by the daemon, not embedded in the ID
- **Not cryptographically signed**: No HMAC or signature verification
- **Internally tracked**: The daemon maintains a registry of active grants
- **Session-bound**: Tied to a specific agent session and endpoint

### Grant Structure

```rust
pub struct Grant {
    pub id: GrantId,                    // Opaque ID (e.g., "g_xyz...")
    pub profile_id: ProfileId,          // Which agent profile
    pub session_id: PrincipalSessionId, // Agent session
    pub endpoint_id: EndpointId,        // Which endpoint (browser/agent)
    pub principal_digest: [u8; 32],     // Process identity hash
    pub rp_ids: BTreeSet<String>,       // Allowed relying parties
    pub credentials: CredentialSet,     // Allowed credentials
    pub issued_at_mono: u64,            // When issued (monotonic clock)
    pub expiry_mono: u64,               // When expires (monotonic clock)
    state: AtomicU8,                    // Active/Revoked/Expired
}
```

### Grant States

```rust
pub enum GrantState {
    Active,    // Grant is valid and can be used
    Revoked,   // Grant was explicitly revoked
    Expired,   // Grant TTL has elapsed
}
```

---

## Agent vs Human Authentication

### Agent Authentication Flow

```
Agent Process                          Daemon (passless agent run)
     │                                        │
     │  1. Connect via Unix socket            │
     │     (IPC, not HTTP)                    │
     │───────────────────────────────────────>│
     │                                        │
     │  2. RequestDelegation                  │
     │     {                                  │
     │       profile_id: "tpm-test",          │
     │       rp_id: "gitea.example.com",      │
     │       credential_ref: "abc123...",     │
     │       max_session_ttl: 300,            │
     │       reason: "CI/CD pipeline"         │
     │     }                                  │
     │───────────────────────────────────────>│
     │                                        │
     │                                        │  3. Create grant request
     │                                        │     (pending approval)
     │                                        │
     │                                        │  4. Policy evaluation
     │                                        │     - Check confirm policy
     │                                        │     - Auto-approve if policy allows
     │                                        │     - Or wait for admin approval
     │                                        │
     │  5. GrantId returned                   │
     │     (opaque ID, e.g., "g_xyz...")      │
     │<───────────────────────────────────────│
     │                                        │
     │  6. Store grant_id in memory           │
     │     (not sent to browser)              │
```

### Human Authentication Flow

```
Human User                           Daemon
     │                                   │
     │  1. WebAuthn request              │
     │     (no extension, or             │
     │      user_verification: true)     │
     │──────────────────────────────────>│
     │                                   │
     │  2. Show desktop notification     │
     │     "Allow authentication?"       │
     │<──────────────────────────────────│
     │                                   │
     │  3. User clicks "Allow"           │
     │     (physical presence)           │
     │──────────────────────────────────>│
     │                                   │
     │  4. Sign after confirmation       │
     │<──────────────────────────────────│
```

### Key Differences

| Aspect | Agent | Human |
|--------|-------|-------|
| **Authorization** | Pre-authorized grant | Real-time user confirmation |
| **User Presence** | No notification, no prompt | Desktop notification + click |
| **Confirm Policy** | `"never"` (skip confirmation) | `"always"` or `"conditional"` |
| **TTL** | Short-lived grant (e.g., 5m) | Immediate (no grant needed) |
| **Process Identity** | `principal_digest` (process hash) | Browser origin validation |
| **Audit Trail** | `policy.allow` (agent grant) | `policy.user_confirmed` |
| **Communication** | Unix socket IPC | Browser extension (HTTP) |

---

## Complete Authentication Flow

### Agent Authentication Sequence

```
Agent Process                          Daemon                         Browser
     │                                    │                              │
     │  1. Trigger WebAuthn               │                              │
     │     (e.g., HTTP request to RP)     │                              │
     │──────────────────────────────────────────────────────────────────>│
     │                                    │                              │
     │                                    │  2. Extension intercepts     │
     │                                    │     and adds extension:      │
     │                                    │     {                        │
     │                                    │       user_verification: true│
     │                                    │     }                        │
     │                                    │<─────────────────────────────│
     │                                    │                              │
     │                                    │  3. HTTP POST /sign          │
     │                                    │     {                        │
     │                                    │       grant_id: "g_xyz...",  │
     │                                    │       profile_id: "tpm-test",│
     │                                    │       rp_id: "gitea...",     │
     │                                    │       ...                    │
     │                                    │     }                        │
     │                                    │─────────────────────────────>│
     │                                    │                              │
     │                                    │  4. Validate grant           │
     │                                    │     - Grant exists?          │
     │                                    │     - Not expired?           │
     │                                    │     - Not revoked?           │
     │                                    │     - RP matches?            │
     │                                    │     - Credential matches?    │
     │                                    │                              │
     │                                    │  5. Sign (no notification)   │
     │                                    │     because confirm_policy   │
     │                                    │     is "never" for agents    │
     │                                    │<─────────────────────────────│
     │                                    │                              │
     │                                    │  6. Return assertion         │
     │                                    │<─────────────────────────────│
```

### Important Note

The **grant_id is NOT sent to the browser extension**. The extension only knows about:
- `user_verification: true`
- `allow_credentials: [...]`

The daemon uses the `grant_id` internally to track which agent process is authorized to sign. The browser extension communicates with the daemon via HTTP, but the grant validation happens entirely within the daemon.

---

## Grant Lifecycle

### 1. Grant Request

```rust
pub struct GrantRequestParams {
    pub profile_id: ProfileId,
    pub session_id: PrincipalSessionId,
    pub endpoint_id: EndpointId,
    pub principal_digest: [u8; 32],
    pub rp_ids: Vec<String>,
    pub credentials: Vec<CredentialRef>,
    pub requested_ttl_secs: u64,
}
```

The agent process sends a `RequestDelegation` message via Unix socket IPC:

```rust
AdminRequest::RequestDelegation {
    profile_id: ProfileId,
    rp_id: String,
    credential_ref: CredentialRef,
    max_session_ttl: u64,
    reason: Option<String>,
}
```

### 2. Policy Evaluation

The daemon evaluates the grant request against the configured policy:

- **Auto-approve**: If the policy allows delegation for this profile/RP/credential
- **Pending approval**: If the policy requires admin confirmation
- **Deny**: If the policy does not allow delegation

### 3. Grant Creation

If approved, the daemon creates a grant:

```rust
pub struct Grant {
    pub id: GrantId,
    pub profile_id: ProfileId,
    pub session_id: PrincipalSessionId,
    pub endpoint_id: EndpointId,
    pub principal_digest: [u8; 32],
    pub policy_generation: PolicyGenerationId,
    pub policy_digest: PolicyDigest,
    pub rp_ids: BTreeSet<String>,
    pub credentials: CredentialSet,
    pub issued_at_mono: u64,
    pub expiry_mono: u64,
    state: AtomicU8,
}
```

### 4. Grant Usage

When the agent needs to authenticate:

1. Browser extension intercepts WebAuthn request
2. Extension sends HTTP POST to daemon's `/sign` endpoint
3. Daemon validates the grant:
   - Grant exists in registry
   - Grant is not expired (TTL check)
   - Grant is not revoked
   - RP ID matches grant's allowed RPs
   - Credential ref matches grant's allowed credentials
4. If valid, daemon signs without notification (because `confirm_policy` is `"never"`)
5. Returns assertion to browser

### 5. Grant Expiration

Grants automatically expire when:
- TTL elapses (checked via monotonic clock)
- Agent session terminates
- Admin explicitly revokes the grant

### 6. Grant Revocation

Grants can be revoked via:

```rust
AdminRequest::RevokeDelegation {
    request_id: PendingRequestId,
}
```

Or by grant ID:

```rust
AdminRequest::RevokeGrant {
    grant_id: GrantId,
}
```

---

## Security Properties

### 1. Process Identity Binding

Each grant is bound to a `principal_digest` (SHA-256 hash of the agent process identity). This ensures:
- Only the specific process that requested the grant can use it
- Prevents grant theft by other processes
- Tied to the agent's session and endpoint

### 2. RP and Credential Scoping

Grants are scoped to:
- Specific relying parties (`rp_ids`)
- Specific credentials (`credentials`)

This prevents:
- Using a grant for unauthorized RPs
- Using a grant with unauthorized credentials
- Lateral movement between RPs

### 3. Time-Bounded Access

Grants have a TTL (time-to-live):
- Prevents indefinite access
- Forces re-authorization after expiration
- Limits exposure window if grant is compromised

### 4. No Browser Exposure

The grant_id is **never sent to the browser extension**:
- Browser only sees `user_verification` and `allow_credentials`
- Grant validation happens entirely within the daemon
- Prevents browser-based attacks on the grant mechanism

### 5. Audit Trail

All grant operations are audited:
- Grant creation: `policy.allow` event
- Grant usage: Sign operation with grant context
- Grant revocation: Explicit revocation event
- Grant expiration: Automatic cleanup

---

## Implementation Details

### Grant Registry

The daemon maintains a `GrantRegistry` that tracks all active grants:

```rust
pub struct GrantRegistry {
    grants: HashMap<GrantId, Arc<Grant>>,
    pending_requests: HashMap<GrantRequestId, GrantRequest>,
    // ...
}
```

### Grant Resolution

When validating a grant for signing:

```rust
pub fn resolve_grant_for_sign(
    &self,
    profile_id: &ProfileId,
    grant_id: &GrantId,
) -> Option<GrantSignSnapshot> {
    let mut grants_map = self.grants.lock().unwrap();
    let registry = grants_map.get_mut(profile_id.as_str())?;
    let _ = registry.check_expired();  // Clean up expired grants
    let snap = registry.snapshot_for_sign(grant_id)?;

    // Check if revoked
    let is_revoked = snap.state == super::grant::GrantState::Revoked;

    Some(GrantSignSnapshot {
        grant_id: snap.grant_id,
        profile_id: snap.profile_id,
        rp_ids: snap.rp_ids,
        credential_refs: snap.credential_refs,
        state: snap.state,
        // ...
    })
}
```

### IPC Communication

Agent processes communicate with the daemon via Unix socket IPC:

```rust
// Agent process
let stream = UnixStream::connect("/run/user/1000/passless/agent.sock")?;
let mut client = AgentClient::new(stream);

// Request delegation
let grant_id = client.request_delegation(RequestDelegation {
    profile_id: "tpm-test".into(),
    rp_id: "gitea.example.com".into(),
    credential_ref: "abc123...".into(),
    max_session_ttl: 300,
    reason: Some("CI/CD pipeline".into()),
})?;
```

### Browser Extension Communication

The browser extension communicates with the daemon via HTTP:

```javascript
// Extension worker
const response = await fetch('http://127.0.0.1:PORT/sign', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        grant_id: 'g_xyz...',
        profile_id: 'tpm-test',
        rp_id: 'gitea.example.com',
        credential_ref: 'abc123...',
        client_data_hash: '...',
        // ...
    })
});
```

**Important**: The `grant_id` is managed by the daemon internally. The browser extension does not need to know about grants; it only needs to send the authentication request to the daemon.

---

## Summary

The grant mechanism in ADR 0005 provides a secure way for agent processes to authenticate without human interaction:

1. **Agent requests delegation** via Unix socket IPC
2. **Daemon evaluates policy** and creates a grant if approved
3. **Grant is scoped** to specific RPs, credentials, and TTL
4. **Browser extension** intercepts WebAuthn and sends to daemon
5. **Daemon validates grant** and signs without notification
6. **Audit trail** records all grant operations

This design ensures:
- **Security**: Process identity binding, RP/credential scoping, TTL
- **Usability**: No human interaction required for authorized agents
- **Auditability**: Complete audit trail of grant lifecycle
- **Isolation**: Grant mechanism is internal to daemon, not exposed to browser
