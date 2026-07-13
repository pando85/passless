# ADR 0001: Secure delegated passkey workflows for autonomous agents

- **Status:** Proposed
- **Date:** 2026-07-13
- **Decision owners:** Passless maintainers
- **Related components:** `passless`, `passless-core`, authenticator service, credential storage, PIN storage, user verification, browser integration, audit logging

## Context

Passless currently acts as a software FIDO2 authenticator exposed to the operating system through UHID. A browser initiates a normal WebAuthn registration or authentication ceremony, validates the web origin, sends a CTAP request to Passless, and Passless asks the human user for user presence or user verification before using a credential.

This is appropriate for interactive human use. It is not sufficient for an autonomous coding agent that must register or authenticate while the user is absent or without asking the user to approve every ceremony.

An autonomous agent must not obtain a general signing primitive or unrestricted access to the user's passkeys. It needs a narrower capability:

- The human explicitly delegates a limited set of WebAuthn actions.
- The delegation is scoped to an authenticated agent principal and exact relying-party IDs.
- Autonomous operations use machine-owned credentials rather than personal credentials.
- Each browser ceremony requires a short-lived, one-shot machine intent.
- Browser-origin and ceremony evidence is supplied by a trusted browser mediator, not by the agent.
- Every machine interaction is recorded in a dedicated audit trail.
- Existing human workflows continue unchanged.

A CLI is preferred as the canonical initial agent interface because it is universally available to local agents and scripts. A future MCP server may expose the same operations, but it must remain a thin adapter over the same daemon protocol and security policy.

## Problem statement

Passless needs to let an authorized agent autonomously:

1. Register a dedicated passkey for an allowed RP.
2. Authenticate with a dedicated passkey for an allowed RP.
3. Inspect the status of its own intents and machine credentials.
4. Operate without a per-ceremony user click when the delegation permits it.
5. Produce a complete, reviewable machine audit trail.

It must do so without:

- Exposing private keys.
- Allowing arbitrary signing.
- Trusting an agent-supplied origin or `clientDataHash`.
- Claiming fresh human user verification when none occurred.
- Allowing an agent to use personal credentials by default.
- Allowing a failed machine flow to fall back to an interactive personal flow.
- Weakening normal Passless behaviour for human users.

## Decision drivers

The design must:

- Preserve WebAuthn browser-origin validation.
- Keep the Passless daemon as the sole owner of authenticator and storage state.
- Default to deny for machine access.
- Use exact RP IDs in the first version.
- Separate durable human delegation from per-use machine intent.
- Separate human credentials from machine credentials.
- Bind autonomous ceremonies to a trusted browser-mediated ceremony record.
- Represent user verification truthfully.
- Make all machine intents one-shot and short-lived.
- Fail closed when machine authorization or mandatory auditing is unavailable.
- Provide stable JSON contracts and error codes for agents.
- Provide version-matched documentation that LLM agents can consume.
- Maintain existing human CLI and browser flows.
- Permit a future MCP adapter without duplicating authorization logic.

## Decision

Passless will add a policy-enforced autonomous agent workflow based on five security objects:

1. **Delegation** — persistent, human-configured maximum authority.
2. **Agent principal** — authenticated software identity receiving that authority.
3. **Verified agent session** — optional, time-bounded evidence of recent human user verification.
4. **Intent** — one-shot, short-lived declaration of the next expected machine ceremony.
5. **Ceremony binding** — trusted browser evidence binding the intent to the real WebAuthn operation.

Machine-owned credential metadata and a dedicated append-only audit log complete the model.

The browser remains the WebAuthn client. The agent does not submit arbitrary CTAP commands or caller-constructed WebAuthn assertions to Passless.

## High-level architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│ Human administration                                            │
│                                                                 │
│ passless delegation grant/revoke                                │
│ passless session unlock/lock                                    │
│ passless audit ...                                              │
└─────────────────────────────┬───────────────────────────────────┘
                              │ trusted administrative channel
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Passless daemon                                                 │
│                                                                 │
│ - delegation policy                                             │
│ - principal authentication                                      │
│ - verified agent sessions                                       │
│ - one-shot intent registry                                      │
│ - trusted ceremony bindings                                     │
│ - machine credential ownership                                  │
│ - mandatory machine audit                                       │
│ - AuthenticatorService                                          │
│ - credential and PIN storage                                    │
└───────────────┬──────────────────────────────┬──────────────────┘
                │ local control protocol       │ UHID / CTAP
                │                              │
        ┌───────▼────────┐             ┌───────▼────────────────┐
        │ Agent CLI      │             │ Browser/WebAuthn       │
        │                │             │                        │
        │ intent create  │◄────────────┤ trusted browser       │
        │ intent status  │ ceremony ID │ mediator              │
        └───────┬────────┘             └────────────────────────┘
                │
        ┌───────▼────────┐
        │ Autonomous     │
        │ coding agent   │
        └────────────────┘
```

## Terminology

### RP ID

The WebAuthn relying-party identifier, such as `github.com`.

Machine policies use exact normalized RP IDs. They do not use arbitrary URL patterns or caller-supplied origins.

### Human credential

A credential created for ordinary interactive use. It continues to require the normal Passless user-presence and user-verification flow.

### Machine credential

A credential explicitly created for one agent principal under one delegation. It may be used autonomously only when a valid intent, ceremony binding, delegation, and verification mode all match.

### Delegation

A persistent policy grant created by a human administrator. It defines the maximum authority an agent may exercise. A delegation does not itself describe a particular browser request.

### Principal

An authenticated software identity such as `opencode` or `claude-code`. A display name or CLI flag alone is not an authenticated principal.

### Verified agent session

A short-lived daemon state created after real human user verification. It permits autonomous operations that need the WebAuthn UV result for a bounded period.

### Intent

A one-shot, short-lived machine declaration that the principal expects one registration or authentication ceremony for an exact RP ID and optional credential/account constraint.

An intent is not a delegation and does not independently grant authority.

### Ceremony binding

A record produced by a trusted browser mediator and authenticated to the Passless daemon. It binds the intent to evidence from the real browser ceremony, including the actual origin, RP ID, action, and CTAP `clientDataHash`.

## Security model

The authorization decision is the intersection of:

```text
human delegation
    ∩ authenticated principal
    ∩ active verified session, when required
    ∩ one-shot intent
    ∩ trusted ceremony binding
    ∩ machine credential ownership
    ∩ current policy version
```

If any required component is missing or mismatched, Passless denies the machine flow.

### No arbitrary signing

The agent interface will not expose:

- Raw CTAP submission.
- Caller-provided `clientDataHash`.
- Caller-provided browser origin evidence.
- Arbitrary challenges or payloads to sign.
- Private-key export.
- Raw credential-storage access.
- Assertion or attestation generation outside a browser-mediated ceremony.

### Truthful user verification

Passless will support two machine verification modes.

#### `session`

A human performs real user verification once to unlock a bounded agent session. Autonomous ceremonies during that session may use the verified session state, subject to delegation, intent, and ceremony-binding checks.

The session must:

- Have a short configured lifetime.
- Be scoped to one principal.
- Be held only in daemon memory.
- Be cleared on daemon restart.
- Be cleared on explicit lock.
- Be cleared when an operating-system screen-lock event can be detected.
- Never be extended by an agent operation.

#### `none`

The agent may operate unattended without a verified session, but Passless must not claim that human user verification occurred. The WebAuthn UV result remains unset.

This mode works only with RPs whose policy permits authentication or registration without UV.

Passless will not support a mode that treats possession of an agent capability as human user verification.

### User presence and consent

A machine delegation represents prior human consent for the narrowly defined autonomous action. A valid machine flow therefore does not display the normal per-ceremony approval window.

This applies only to machine-owned credentials and exact delegated actions. Human credentials retain the current per-ceremony interaction.

## Trusted browser correlation

A one-shot intent alone cannot securely prove which local browser or process initiated a CTAP request. The CTAP transport does not provide a reliable agent identity to the authenticator.

Autonomous mode therefore requires a trusted browser mediator.

The mediator may be implemented as a browser extension with native messaging, an agent-browser integration, or another authenticated browser-side component. Its exact implementation is deferred, but it must satisfy this contract:

1. Observe the actual browser origin and top-level origin, where applicable.
2. Observe or derive the WebAuthn action and exact RP ID.
3. Observe the actual `clientDataJSON` or `clientDataHash` produced for the ceremony.
4. Bind the ceremony to an existing Passless intent.
5. Authenticate to Passless as the same agent principal or agent session.
6. Send the binding over a restricted local channel.
7. Never accept origin evidence supplied only by the LLM or CLI.

Example ceremony binding:

```json
{
  "schema_version": "passless.ceremony.v1",
  "intent_id": "intent_01JZ...",
  "principal": "opencode",
  "action": "authenticate",
  "origin": "https://github.com",
  "top_origin": null,
  "rp_id": "github.com",
  "client_data_hash": "sha256:...",
  "created_at": "2026-07-13T10:40:10+02:00",
  "expires_at": "2026-07-13T10:41:10+02:00"
}
```

The incoming CTAP request must contain the same action, RP ID, and `clientDataHash` before Passless considers the intent matched.

If trusted browser correlation is unavailable, autonomous machine flows are disabled. Normal human flows continue to work.

## Human compatibility

Existing human workflows remain the default.

```text
Incoming WebAuthn ceremony
        │
        ├─ Has a trusted binding to an active machine intent
        │       │
        │       ├─ all machine checks succeed
        │       │       → autonomous machine flow
        │       │
        │       └─ any machine check fails
        │               → deny machine flow; no human fallback
        │
        └─ No machine binding exists
                → current interactive human Passless flow
```

A failed machine flow must never fall back to:

- A personal credential.
- The normal human approval prompt.
- A less restrictive verification mode.
- An unbound RP-only match.

This prevents an agent from bypassing policy by deliberately causing its machine authorization to fail.

Existing human-oriented commands remain available. The agent namespace is a separate compatibility and security contract.

## Machine credential ownership

Machine and human credentials are distinct by default.

Conceptually:

```rust
pub enum CredentialOwner {
    Human,
    Agent {
        principal_id: PrincipalId,
        delegation_id: DelegationId,
    },
}
```

Machine metadata includes:

- Opaque credential reference.
- Principal ID.
- Delegation ID.
- Exact RP ID.
- Allowed action set.
- Verification mode.
- Creation timestamp.
- Current policy version or digest.
- Revocation state.

An agent can use only credentials owned by that principal and permitted by the active delegation.

### Storage compatibility

The existing serialized credential format is treated as stable. Agent ownership metadata will not be added directly to the frozen credential record in the first implementation.

Instead, Passless will maintain a separate authenticated metadata index keyed by a stable keyed digest of the credential ID.

If ownership metadata is missing, corrupt, or cannot be authenticated, the credential is treated as human-only and is not available to autonomous flows.

The metadata update and credential write must be atomic from the daemon's perspective. Recovery logic must never expose a partially registered machine credential as autonomous.

Delegating an existing human credential to an agent is out of scope for the first version.

## Delegation model

Delegations are created, modified, and revoked only through a human administrative flow.

Example configuration representation:

```toml
[agents]
default = "deny"

[agents.principals.opencode]
identity = "launcher-capability"

[agents.principals.opencode.rp."github.com"]
allow = ["register", "authenticate", "credential.list"]
credential_scope = "dedicated"
verification = "session"
require_browser_binding = true
intent_ttl = "90s"
max_pending_intents = 1

[agents.principals.opencode.rp."staging.example.com"]
allow = ["register", "authenticate", "credential.list"]
credential_scope = "dedicated"
verification = "none"
require_browser_binding = true
intent_ttl = "90s"
max_pending_intents = 1
```

Policy semantics:

1. Machine access is denied by default.
2. Exact normalized RP IDs are required.
3. Public suffixes are rejected.
4. Wildcard RP rules are not supported initially.
5. Explicit denial overrides grants.
6. Registration and authentication are separate actions.
7. `credential_scope = "dedicated"` is required initially.
8. Verification mode is configured by the human and cannot be downgraded by the agent.
9. Browser correlation is mandatory for autonomous mode.
10. Intents are always one-shot.
11. Agent-requested TTLs may shorten but never extend the configured maximum.
12. Revocation immediately invalidates active sessions, intents, and machine credentials covered by the delegation.
13. Policy is enforced by the daemon, not by the CLI or browser mediator.

## Principal authentication

A principal name passed on the command line is descriptive and is not sufficient authentication.

The preferred initial model is a trusted launcher:

```bash
passless agent run --profile opencode -- opencode
```

The launcher:

1. Creates an ephemeral agent session.
2. Authenticates to the Passless daemon.
3. Passes the agent capability through an inherited file descriptor or equivalent protected channel.
4. Starts the agent and its browser integration under the same constrained identity.
5. Never places capability secrets in command arguments or ordinary environment variables.
6. Revokes the session when the launched process tree ends.

The daemon should combine, where available:

- Unix socket peer credentials.
- A random capability.
- Launcher session identity.
- Process, sandbox, container, or cgroup metadata.

A restricted capability file may be supported as a compatibility fallback, but it provides weaker isolation for processes sharing the same Unix user.

Strong deployments should use a separate Unix user, container, sandbox, or equivalent operating-system boundary for the agent.

## Verified agent sessions

Human-facing commands:

```bash
passless session unlock --principal opencode
passless session status --principal opencode
passless session lock --principal opencode
```

`session unlock` must invoke a trusted Passless or operating-system verification UI. It must not accept a PIN through agent-controlled standard input, command arguments, environment variables, or JSON input.

Example session state:

```json
{
  "schema_version": "passless.session.v1",
  "principal": "opencode",
  "verification": "user_verified",
  "verified_at": "2026-07-13T10:35:00+02:00",
  "expires_at": "2026-07-13T10:40:00+02:00"
}
```

The agent may inspect session state but cannot unlock or extend it.

## One-shot intent model

An agent creates an intent immediately before starting a browser ceremony.

```bash
passless agent intent create \
  --action authenticate \
  --rp-id github.com \
  --credential github-opencode \
  --reason "Authenticate to inspect CI failures"
```

Registration:

```bash
passless agent intent create \
  --action register \
  --rp-id github.com \
  --account pando85 \
  --credential-label github-opencode \
  --reason "Register a dedicated GitHub passkey"
```

The intent command:

- Is non-interactive.
- Does not perform user verification.
- Does not itself sign anything.
- Checks the current delegation and verified-session requirement.
- Creates exactly one short-lived intent.
- Returns a stable intent identifier.
- Emits a mandatory audit event.

Example response:

```json
{
  "schema_version": "passless.agent.v1",
  "ok": true,
  "request_id": "req_01JZ...",
  "result": {
    "intent": {
      "id": "intent_01JZ...",
      "principal": "opencode",
      "action": "authenticate",
      "rp_id": "github.com",
      "credential_ref": "github-opencode",
      "state": "waiting_for_browser_binding",
      "created_at": "2026-07-13T10:40:00+02:00",
      "expires_at": "2026-07-13T10:41:30+02:00"
    }
  }
}
```

### Intent states

```text
created
    │
    └── waiting_for_browser_binding
              │
              ├── waiting_for_ctap
              │       │
              │       ├── reserved
              │       │      ├── completed
              │       │      └── failed
              │       ├── expired
              │       └── cancelled
              ├── rejected
              ├── expired
              └── cancelled
```

Terminal states are:

- `completed`
- `failed`
- `rejected`
- `expired`
- `cancelled`

Only one pending intent per principal is supported initially.

An intent is held only in memory and is lost on daemon restart.

### Intent consumption

A mismatched ceremony does not consume the intent.

Once an exact matching CTAP request has been atomically reserved, the intent is consumed regardless of whether the ceremony succeeds. This prevents retries from reusing authorization unexpectedly.

An agent must create a new intent for every retry.

## Ceremony matching

The daemon matches all of the following:

- Authenticated principal.
- Intent identifier.
- Exact normalized RP ID.
- Registration or authentication action.
- Trusted browser origin evidence.
- CTAP `clientDataHash`.
- Machine credential owner and reference for authentication.
- Delegated credential namespace and account constraints for registration.
- Active policy version.
- Required verified-session state.
- Intent expiry and unused state.

For discoverable authentication, Passless filters eligible credentials to machine credentials owned by the principal. Human credentials are never returned to the machine flow.

## CLI surfaces

### Human administrative commands

```bash
passless delegation grant ...
passless delegation list
passless delegation show <DELEGATION_ID>
passless delegation revoke <DELEGATION_ID>

passless session unlock --principal <PRINCIPAL>
passless session status --principal <PRINCIPAL>
passless session lock --principal <PRINCIPAL>

passless audit list ...
passless audit show ...
passless audit verify
passless audit export ...
```

Administrative commands may require trusted interactive user verification. They are not available through the agent capability.

### Agent commands

```bash
passless agent doctor --output json
passless agent capabilities --output json
passless agent instructions --format markdown
passless agent instructions --format json

passless agent intent create ...
passless agent intent get <INTENT_ID>
passless agent intent wait <INTENT_ID> --timeout 2m
passless agent intent cancel <INTENT_ID>

passless agent credential list --rp-id <RP_ID>
passless agent credential show <CREDENTIAL_REF>
```

Agent credential commands expose only credentials owned by the authenticated principal and only policy-approved metadata.

The first version does not expose agent-driven rename or delete operations. Human administrators revoke or delete machine credentials through the existing or new administrative interface.

### Global agent options

```text
--output json|plain
--idempotency-key <KEY>
--request-id <ID>
--socket <PATH>
--timeout <DURATION>
```

Agent commands default to JSON and never prompt through standard input.

## Stable JSON and errors

Agent commands return a versioned envelope.

Success:

```json
{
  "schema_version": "passless.agent.v1",
  "ok": true,
  "request_id": "req_01JZ...",
  "result": {}
}
```

Error:

```json
{
  "schema_version": "passless.agent.v1",
  "ok": false,
  "request_id": "req_01JZ...",
  "error": {
    "code": "verified_session_required",
    "message": "The opencode delegation requires an active verified session.",
    "retryable": false,
    "agent_action": "request_user_session_unlock",
    "details": {
      "principal": "opencode",
      "rp_id": "github.com"
    }
  }
}
```

Initial error codes include:

```text
invalid_request
invalid_rp_id
principal_unauthenticated
principal_not_delegated
action_not_delegated
verified_session_required
verified_session_expired
browser_binding_required
browser_binding_invalid
intent_not_found
intent_conflict
intent_expired
intent_already_consumed
credential_not_found
credential_not_owned
credential_not_delegated
policy_changed
rate_limited
audit_unavailable
daemon_unavailable
backend_unavailable
internal_error
```

Human-readable messages may evolve. `error.code` and `agent_action` are the stable machine contract.

## Idempotency

Intent creation supports a caller-provided idempotency key.

For a given authenticated principal:

- Repeating the same request with the same key returns the existing intent.
- Reusing a key with different parameters returns `intent_conflict`.
- Idempotency does not extend intent expiry.
- An expired or consumed intent is never recreated implicitly.

## Local control protocol

The Passless daemon exposes a versioned local control protocol over a Unix-domain socket.

Default location:

```text
$XDG_RUNTIME_DIR/passless/control.sock
```

The socket must:

- Be owned by the Passless user.
- Use restrictive filesystem permissions.
- Authenticate agent and administrative clients separately.
- Apply request-size limits and timeouts.
- Reject capability material in ordinary request arguments.
- Never expose private credential material.
- Keep policy enforcement in the daemon.

The CLI must not instantiate a second authenticator or open the same backend directly.

## Dedicated machine audit log

Every machine interaction, including denied attempts, is recorded in a separate structured audit channel.

Default location:

```text
$XDG_STATE_HOME/passless/audit/machine.jsonl
```

Default permissions:

```text
0600
```

The daemon may additionally emit structured events to journald, but the JSONL log is the canonical portable machine audit format.

### Audit events

Delegation lifecycle:

```text
delegation.created
delegation.updated
delegation.revoked
delegation.expired
```

Agent and verified-session lifecycle:

```text
agent_session.started
agent_session.authentication_failed
agent_session.verified
agent_session.locked
agent_session.expired
agent_session.terminated
```

Intent lifecycle:

```text
intent.create_requested
intent.created
intent.rejected
intent.browser_bound
intent.binding_rejected
intent.reserved
intent.consumed
intent.cancelled
intent.expired
```

Ceremony lifecycle:

```text
ceremony.registration.started
ceremony.registration.completed
ceremony.registration.failed
ceremony.authentication.started
ceremony.authentication.completed
ceremony.authentication.failed
```

Credential lifecycle:

```text
credential.machine_registered
credential.machine_used
credential.machine_revoked
credential.machine_deleted
```

Security decisions:

```text
policy.allowed
policy.denied
credential_scope.denied
verification.denied
principal.authentication_failed
rate_limit.exceeded
audit.degraded
```

### Audit schema

Example:

```json
{
  "schema_version": "passless.audit.v1",
  "sequence": 1842,
  "timestamp": "2026-07-13T10:40:31.429+02:00",
  "event": "ceremony.authentication.completed",
  "actor": {
    "kind": "machine",
    "principal": "opencode",
    "agent_session_id": "agent_session_01JZ...",
    "process_ref": "process_7dd3..."
  },
  "request": {
    "request_id": "req_01JZ...",
    "intent_id": "intent_01JZ...",
    "reason": "Authenticate to inspect CI failures"
  },
  "authorization": {
    "delegation_id": "delegation_01JZ...",
    "policy_version": 3,
    "policy_digest": "sha256:...",
    "verification": "verified_session",
    "verified_at": "2026-07-13T10:35:02+02:00"
  },
  "webauthn": {
    "origin": "https://github.com",
    "rp_id": "github.com",
    "action": "authenticate",
    "credential_ref": "credential_github_opencode",
    "credential_owner": "agent:opencode"
  },
  "result": {
    "outcome": "success",
    "error_code": null
  },
  "integrity": {
    "previous_event_hash": "sha256:...",
    "event_hash": "sha256:..."
  }
}
```

Audit records must not contain:

- Private keys.
- PINs.
- Principal capabilities.
- Raw challenges.
- Raw assertions.
- Attestation objects.
- Browser cookies.
- OAuth tokens.
- Full raw credential records.
- Full user handles when an opaque keyed reference is sufficient.

### Audit integrity and fail-closed behaviour

Machine actions require the audit channel.

Before Passless autonomously accepts a ceremony, it must durably append the authorization and reservation event. If that write fails, the ceremony is denied.

After execution, Passless appends a terminal success or failure event. If this terminal append fails after a response has already been emitted, the operation cannot be rolled back. Passless must mark the audit subsystem degraded and reject all subsequent machine operations until audit health is restored.

Audit records use monotonically increasing sequence numbers and a hash chain. Rotation preserves a signed or hashed link to the previous file.

A local hash chain detects corruption and casual modification but cannot fully protect against a malicious process with the same filesystem privileges. Strong deployments may anchor checkpoints using a TPM-backed key or forward audit events to an append-only remote service.

### Audit inspection

```bash
passless audit list --actor machine
passless audit list --principal opencode
passless audit list --rp-id github.com
passless audit list --since 24h
passless audit show --intent <INTENT_ID>
passless audit show --credential <CREDENTIAL_REF>
passless audit verify
passless audit export --format jsonl
passless audit tail --actor machine
```

Audit deletion is not available to an agent principal.

## LLM and agent documentation

Secure operation requires documentation designed for both humans and LLM agents.

The repository will add:

```text
docs/agents/
├── README.md
├── security-model.md
├── installation.md
├── principal-setup.md
├── registration.md
├── authentication.md
├── browser-integration.md
├── session-verification.md
├── audit.md
├── errors.md
└── examples/
    ├── opencode.md
    ├── claude-code.md
    └── browser-automation.md
```

A generic agent skill will be distributed at:

```text
contrib/agent-skills/passless/SKILL.md
```

The installed binary will expose version-matched instructions:

```bash
passless agent instructions --format markdown
passless agent instructions --format json
```

The installed command output is authoritative for the installed version. Website documentation may also expose an `llms.txt` index.

### Agent installation contract

Agent documentation may instruct an agent to:

- Detect whether Passless is installed.
- Run `passless agent doctor --output json`.
- Report missing prerequisites.
- Verify daemon, principal, browser mediator, session, and audit health.

It must instruct the agent not to autonomously:

- Run `sudo`.
- Install or modify udev rules.
- Add users to privileged groups.
- Modify Passless delegation policy.
- Create its own principal capability.
- Unlock a verified session.
- Disable browser correlation.
- Disable auditing.
- Request or handle a Passless PIN.
- Downgrade from `session` verification to `none`.

### Registration algorithm for agents

The LLM-facing registration documentation will specify:

```text
1. Run `passless agent doctor --output json`.
2. Confirm the authenticated principal.
3. Confirm registration is delegated for the exact RP ID.
4. Confirm the required verified session is active.
5. Confirm the trusted browser mediator is healthy.
6. Confirm the machine audit channel is healthy.
7. Create exactly one registration intent.
8. Start the normal browser passkey-registration workflow.
9. Bind the browser ceremony to the intent through the trusted mediator.
10. Wait for the terminal intent result.
11. Verify that the new credential is machine-owned by the expected principal.
12. Report the opaque credential reference.
13. Never reuse an expired, failed, or consumed intent.
```

### Authentication algorithm for agents

```text
1. Run `passless agent doctor --output json` when session state is uncertain.
2. Confirm authentication is delegated for the exact RP ID.
3. Select only a machine credential owned by the principal.
4. Confirm the required verified session is active.
5. Create exactly one authentication intent.
6. Start the normal browser authentication workflow.
7. Bind the browser ceremony through the trusted mediator.
8. Wait for the terminal intent result.
9. Continue using the browser session created by the RP.
10. Never request a personal credential or policy downgrade.
```

### Required agent safety rules

The documentation must prominently teach agents:

- Never request or process Passless PINs.
- Never fabricate origin or UV evidence.
- Never pass raw CTAP or WebAuthn signing requests.
- Never reuse intents.
- Never select human credentials.
- Never continue after an audit failure.
- Never bypass the trusted browser mediator.
- Never modify delegations.
- Stop and request human intervention when policy or verified-session state blocks an operation.

## Agent doctor command

`passless agent doctor --output json` reports:

- Daemon protocol compatibility.
- Authenticated principal.
- Principal capability health.
- Trusted browser mediator health.
- Audit subsystem health.
- Active verified-session state.
- Effective delegated RP IDs and actions, without secrets.
- Pending intent conflicts.
- Machine credential availability.

It does not reveal capability material or private credential information.

## Security invariants

The implementation must maintain these invariants:

1. No autonomous operation without a valid delegation.
2. No autonomous operation without an authenticated principal.
3. No autonomous operation without a one-shot intent.
4. No autonomous operation without trusted browser ceremony correlation.
5. No UV result without a valid verified session.
6. No personal credential in an autonomous flow.
7. No machine credential use by another principal.
8. No policy downgrade controlled by the agent.
9. No fallback from a rejected machine flow to a human flow.
10. No unaudited autonomous operation.
11. No intent reuse after reservation.
12. No secret material in CLI JSON or audit records.

## Threat model

| Threat | Mitigation |
|---|---|
| Prompt injection requests authentication to another site | Exact RP-ID delegation and trusted origin binding |
| Agent fabricates origin or `clientDataHash` | Only trusted browser mediator may provide ceremony evidence |
| Another local browser races an RP-only intent | CTAP hash binding and authenticated mediator session |
| Agent uses a personal passkey | Dedicated machine ownership and credential filtering |
| Agent replays a request | One-shot intents, atomic reservation, short expiry |
| Agent claims another principal name | Authenticated launcher capability and socket peer checks |
| Agent treats its capability as human UV | Explicitly prohibited; session or UV-unset modes only |
| Agent changes policy or unlocks itself | Administrative channel separated from agent capability |
| Agent hides activity | Mandatory separate audit log; pre-execution durable append |
| Audit log is modified | Sequence numbers, hash chain, optional TPM/remote anchoring |
| Daemon restarts with stale authority | Sessions and intents are memory-only and fail closed |
| Machine authorization fails and falls back to human | Explicit no-fallback dispatch rule |
| Agent obtains arbitrary signing capability | No raw CTAP, challenge, or signing interface |

## Internal architecture

Authenticator, policy, intent, browser binding, and audit logic will be extracted into reusable library components.

Suggested structure:

```text
passless-core/
    configuration, errors, stable common types

passless-engine/
    authenticator service
    credential and PIN storage ports
    delegation evaluator
    principal and verified-session state
    one-shot intent registry
    ceremony binding matcher
    machine credential metadata
    audit service

passless-protocol/
    versioned local control contracts

cmd/passless/
    daemon
    human CLI
    agent CLI adapter
```

The exact crate names may change. The mandatory boundary is:

> Delegation, session, intent, ceremony matching, credential ownership, and audit enforcement execute in the same trusted daemon that owns the authenticator and credential storage.

## Implementation sequence

### Phase 1: Typed security model

- Add principal, delegation, verification-mode, intent, ceremony-binding, and credential-owner types.
- Add exact RP-ID normalization and validation.
- Add restricted agent DTOs and stable error codes.
- Add policy evaluation tests.

### Phase 2: Machine credential metadata

- Add separate authenticated ownership metadata.
- Make credential and ownership writes atomic.
- Filter credentials by human or machine owner.
- Implement revocation semantics.

### Phase 3: Principal and session management

- Add trusted launcher capabilities.
- Add agent session lifecycle.
- Add trusted human session unlock and lock.
- Clear verified sessions on restart and lock events.

### Phase 4: Intent registry

- Add in-memory one-shot intents.
- Add short expiry, cancellation, idempotency, and atomic reservation.
- Limit pending intents per principal.

### Phase 5: Trusted browser mediator

- Define the authenticated ceremony-binding protocol.
- Bind actual origin, RP ID, action, and `clientDataHash`.
- Reject autonomous mode without trusted correlation.
- Add cross-origin and top-origin tests where relevant.

### Phase 6: Mandatory audit

- Add machine JSONL audit channel.
- Add sequence numbers, hash chain, rotation, and health state.
- Require durable pre-execution events.
- Block subsequent machine actions after audit degradation.

### Phase 7: CLI and documentation

- Add human delegation and session commands.
- Add agent doctor, instructions, intent, and credential-read commands.
- Add stable JSON fixtures.
- Add `docs/agents/` and the generic agent skill.

### Phase 8: Optional adapters

- Add a thin MCP adapter over the local protocol.
- Add TPM or remote anchoring for audit checkpoints.
- Add stronger OS-specific application identity integrations.

## Testing requirements

The implementation must cover:

- Default-deny delegation behaviour.
- Exact RP-ID normalization and public-suffix rejection.
- Cross-principal access attempts.
- Invalid, missing, and stolen capability scenarios.
- Verified-session creation, expiry, lock, and restart behaviour.
- Truthful UV state for `session` and `none` modes.
- Intent expiry, cancellation, replay, and idempotency conflicts.
- Concurrent intent and ceremony races.
- Browser binding with wrong origin, RP ID, action, or `clientDataHash`.
- CTAP requests without browser bindings.
- Machine credential filtering in discoverable and allow-list flows.
- Rejection of human credentials in machine flows.
- No fallback from failed machine flows to interactive flows.
- Delegation revocation during active sessions and intents.
- Atomic machine credential registration and recovery.
- Mandatory audit pre-write failure.
- Terminal audit-write degradation handling.
- Audit hash-chain and rotation verification.
- Absence of secrets from JSON, logs, and error details.
- Existing human registration and authentication regression tests.
- Local, `pass`, and TPM-backed storage where supported.
- Versioned LLM instruction fixtures.

## Consequences

### Positive

- Agents can autonomously register and authenticate within explicit human delegation.
- The browser continues to validate the real web origin.
- Passless remains the sole holder of private credential material.
- Machine credentials are independently revocable and auditable.
- Human credentials and existing workflows remain unchanged.
- User verification is represented truthfully.
- A future MCP server can reuse the same policy and protocol.
- LLM agents receive version-matched secure operating instructions.
- Machine activity can be inspected after the fact.

### Negative

- A trusted browser mediator is required for secure autonomous operation.
- Passless gains a local control protocol and additional daemon state.
- Principal identity is only as strong as the launcher and OS isolation.
- Machine ownership metadata adds storage and recovery complexity.
- Mandatory auditing can intentionally make machine operations unavailable.
- Verified sessions require lifecycle integration with screen lock and process termination.
- The project must maintain stable JSON, audit, and agent-documentation contracts.

## Alternatives considered

### Keep the existing per-ceremony UV window

Rejected as the autonomous agent design. It remains the human default but prevents unattended operation.

### One-shot CLI preauthorization with a user click

Rejected. It merely moves the interaction earlier and does not provide autonomous operation.

### Durable RP policy with no one-shot intent

Rejected. It would silently authorize any matching browser ceremony for the policy lifetime and provide weak request correlation.

### One-shot intent matched only by RP ID and action

Rejected. A different local browser or process could race the agent during the intent window.

### Treat the agent capability as user verification

Rejected. Software-principal authentication is not human user verification.

### Allow agents to use existing personal passkeys

Rejected for the first version. Dedicated machine credentials provide clearer ownership, revocation, and audit semantics.

### Let agents submit raw WebAuthn or CTAP requests

Rejected. This would increase the trusted surface and risk creating an arbitrary signing interface.

### Make MCP the canonical interface

Rejected initially. MCP may be a thin adapter after the core daemon protocol and CLI are established.

### Store agent ownership in the existing credential serialization

Rejected initially because the existing credential storage format is treated as stable. Separate authenticated metadata avoids an immediate credential migration.

## Deferred decisions

The following remain implementation-level or require later ADRs:

- Exact browser mediator implementation.
- OS-specific screen-lock integration.
- Capability transport on non-Unix platforms.
- TPM-backed or remote audit anchoring.
- Remote agent operation.
- Wildcard or registrable-domain policies.
- Delegating existing human credentials.
- Agent-driven credential deletion or rename.
- MCP tool naming and transport.

## Decision outcome

Passless will support autonomous agent registration and authentication through persistent human delegations, authenticated agent principals, optional verified sessions, one-shot intents, trusted browser ceremony bindings, dedicated machine-owned credentials, and mandatory machine auditing.

Normal browser-initiated human flows remain unchanged.

An agent cannot grant itself authority, unlock its own verified session, fabricate browser evidence, access personal credentials, bypass auditing, or reuse a completed intent.