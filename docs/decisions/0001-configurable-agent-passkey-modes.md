# ADR 0001: Configurable passkey modes for controlled agent workflows

- **Status:** Proposed
- **Date:** 2026-07-13
- **Decision owners:** Passless maintainers
- **Related components:** authenticator service, credential storage, browser integration, local control protocol, agent launcher, audit logging, CLI documentation
- **Supersedes:** the agent workflow design proposed in pull request #308 if this ADR is accepted

## Context

Passless currently behaves as an interactive software FIDO2 authenticator exposed through UHID. A browser initiates a WebAuthn registration or authentication ceremony, the browser validates the web origin and relying-party relationship, and Passless asks the human user for user presence or user verification before using a credential.

This is the correct default for ordinary human use. It is not sufficient for all agent workflows:

- Some users want an agent to initiate a login and then wait for the human to approve the passkey ceremony.
- Some users want a narrowly delegated agent to register or authenticate without a human click for each ceremony.
- Both workflows must remain controlled, isolated from personal credentials, and auditable.

These two workflows do not have identical WebAuthn semantics.

WebAuthn defines an authorization gesture as a physical interaction by a user during a ceremony. The UP flag is set only when a user-presence test was performed, and the UV flag is set only when user verification was performed. A fully autonomous software agent cannot truthfully claim a fresh physical user-presence test for each ceremony.

Passless therefore must not hide the difference between interactive WebAuthn and delegated machine authentication. It must make the mode explicit, configurable, and visible in policy, credential metadata, audit events, and documentation.

The earlier proposal used a shared UHID authenticator and attempted to distinguish human and machine requests through a side-channel browser binding. That design has an unsafe ambiguity: when the binding is absent or fails, the authenticator cannot know whether the CTAP request is an ordinary human request or a failed machine request. It also risks mixing human and machine credentials in the same storage and enumeration path.

## Decision summary

Passless will support two configurable agent passkey modes:

1. **Interactive mode** — standards-strict agent-assisted WebAuthn. Every registration or authentication requires a real per-ceremony human authorization gesture. The agent may continue using the isolated browser session after the ceremony completes.
2. **Delegated mode** — autonomous delegated machine authentication. A human administrator grants narrow prior authority, and matching ceremonies may complete without a per-ceremony click. This mode uses explicit delegated-machine presence semantics and is not represented as equivalent to fresh physical user presence.

Both modes will use the same isolated agent architecture:

- A managed agent browser profile.
- A dedicated browser WebAuthn proxy transport.
- A trusted launcher and authenticated agent principal.
- A separate machine credential store.
- One-shot intents bound to one browser WebAuthn request.
- A mandatory protected machine audit log.

The existing human browser and UHID flow remains unchanged and separate.

The mode is configured per principal, exact RP ID, and action. A policy may allow only interactive mode, only delegated mode, or both. Interactive mode is always the safe default when more than one mode is allowed.

## Goals

The design must:

- Preserve the current Passless human flow without behavioural changes.
- Allow an agent to initiate registration and authentication while requiring a human gesture when configured for interactive mode.
- Allow an agent to operate autonomously when explicitly configured for delegated mode.
- Keep human and machine credentials isolated.
- Prevent a failed agent flow from falling back to a personal authenticator or credential.
- Bind every agent operation to an authenticated principal, exact RP ID, action, browser request, and one-shot intent.
- Keep private credential material inside Passless.
- Avoid exposing arbitrary signing, raw CTAP, raw WebAuthn assertions, or caller-supplied `clientDataHash` operations.
- Audit every machine interaction, including denied and failed attempts.
- Provide stable CLI contracts and version-matched LLM instructions.
- Support future MCP integration only as a thin adapter over the same daemon protocol.

## Non-goals

The design does not attempt to:

- Make autonomous delegated mode semantically identical to physical WebAuthn user presence.
- Restrict what an agent does inside an RP after authentication succeeds.
- Protect against host root or kernel compromise.
- Protect against a malicious Passless administrator.
- Allow agents to use existing personal passkeys in the first version.
- Support arbitrary remote agents in the first version.
- Support browsers without the required managed WebAuthn proxy integration in the first version.
- Treat an LLM model name as a trustworthy application identity.

## Security terminology

### Human credential

A credential belonging to the existing interactive Passless authenticator. It is available only through the human UHID path and always follows the existing human-presence and user-verification behaviour.

### Machine credential

A credential created inside the dedicated agent credential store. It belongs to one authenticated principal and one delegation. It is unavailable to the human UHID path and to other principals.

### Principal

The complete launched agent execution environment, not merely an LLM name. A principal includes the agent process tree, its managed browser profile, browser proxy, native host, and launcher session.

### Delegation

A persistent or bounded human-created policy granting a principal maximum authority for exact RP IDs and actions. A delegation does not identify a particular browser request.

### Intent

A short-lived, one-shot agent declaration that it expects one browser WebAuthn registration or authentication request. An intent narrows and correlates use of a delegation; it does not independently grant authority.

### Browser request

One intercepted `navigator.credentials.create()` or `navigator.credentials.get()` invocation, identified by the managed browser proxy's request identifier.

### Interactive mode

An agent workflow in which Passless collects a real authorization gesture for every browser request before creating or using a machine credential.

### Delegated mode

An agent workflow in which a valid delegation and one-shot intent replace the per-ceremony human gesture. Passless calls this **delegated machine presence**. It must not be documented as physical user presence.

## High-level architecture

```text
Human browser/profile
        │
        │ normal browser WebAuthn
        ▼
Existing Passless UHID authenticator
        │
        ├── human credential store
        ├── current UP/UV UI
        └── existing human audit/logging


Managed agent browser/profile
        │
        │ chrome.webAuthenticationProxy or an equivalent
        │ approved managed-browser integration
        ▼
Passless browser extension
        │
        │ authenticated native messaging
        ▼
Passless agent engine
        │
        ├── authenticated principal
        ├── delegation policy
        ├── one-shot intent registry
        ├── browser request correlation
        ├── interactive or delegated mode decision
        ├── machine-only credential store
        └── protected machine audit writer
```

Machine browser requests never enter the existing human UHID path.

The agent browser must not have access to personal browser profiles, human Passless storage, the human control socket, or physical/platform authenticators that could provide an unintended fallback.

## Trusted computing base

The agent security boundary includes:

- The Passless daemon and agent engine.
- The trusted launcher.
- The managed browser configuration.
- The Passless browser extension.
- The native messaging host.
- The local control protocol.
- The machine credential store.
- The protected audit writer.
- The OS sandbox and identity controls used to isolate the principal.

The following are untrusted:

- The LLM.
- Agent-generated commands and plans.
- Web content.
- Repositories inspected by the agent.
- Browser pages and scripts.
- Agent plugins, subagents, and tools.

Compromise of the browser extension, native host, daemon, or launcher can compromise the agent authentication boundary. These components must be versioned, signed where practical, and updated as security-sensitive software.

## Configurable operating modes

### Interactive mode

Interactive mode is the default and standards-strict agent workflow.

For each registration or authentication:

1. The agent creates a one-shot intent.
2. The managed browser initiates the normal WebAuthn API request.
3. The browser proxy sends the request to Passless.
4. Passless validates the principal, delegation, intent, browser session, origin, RP ID, and action.
5. Passless shows a trusted prompt for this exact ceremony.
6. The user performs a real authorization gesture.
7. Passless sets UP only after successful user presence.
8. Passless sets UV only after actual local user verification when required or performed.
9. Passless returns the `PublicKeyCredential` response through the browser proxy.
10. The agent continues using the resulting isolated browser session.

Interactive mode supports:

- Human-assisted registration.
- Human-assisted authentication.
- Bootstrapping an isolated authenticated browser session that the agent can use afterward.
- RPs requiring user verification.
- High-value accounts for which every login must remain explicitly approved.

Interactive mode does not provide unattended authentication.

### Delegated mode

Delegated mode is an explicit autonomous machine-authenticator workflow.

For each registration or authentication:

1. A human-created delegation already permits delegated mode for the exact principal, RP ID, and action.
2. The agent creates one one-shot intent.
3. The managed browser initiates the WebAuthn API request.
4. The browser proxy sends the request to Passless.
5. Passless validates every delegated-machine condition.
6. Passless completes the request without a per-ceremony prompt.
7. The intent is consumed and the operation is audited.

Delegated mode uses the following semantics in the first version:

- The credential is created under a distinct Passless Agent AAGUID.
- The credential is marked internally as `presence = delegated-machine`.
- Passless sets UP for RP interoperability, while explicitly documenting that the authority comes from prior human delegation rather than a fresh physical presence test.
- Passless does not claim standards-equivalent physical user presence.
- UV is unset in delegated mode v1.
- If the RP requires UV, the operation fails with `user_verification_required`; Passless does not silently change mode.
- A separate future ADR is required before delegated mode may reuse cached or session-scoped UV and set the UV flag.

Because delegated mode intentionally differs from standard physical user-presence semantics, it must require explicit acknowledgement by the administrator when granted.

Delegated mode is appropriate for:

- Dedicated low-privilege agent accounts.
- Test and staging environments.
- RPs that accept UV-unset assertions.
- Workflows where autonomous login is necessary and the delegation risk is understood.

Delegated mode should not be recommended for:

- Personal administrator accounts.
- Financial or regulated accounts requiring physical user presence.
- Accounts where a login grants broad irreversible authority.
- RPs that require UV.

## Mode policy

Mode is configured per principal, exact RP ID, and action.

Example:

```toml
[agents]
default = "deny"

[agents.principals.opencode]
identity = "trusted-launcher"
browser_profile = "opencode"

[agents.principals.opencode.rp."github.com".authenticate]
allowed_modes = ["interactive"]
default_mode = "interactive"
credentials = ["github-opencode"]

[agents.principals.opencode.rp."staging.example.com".register]
allowed_modes = ["interactive", "delegated"]
default_mode = "interactive"
credential_namespace = "opencode-staging"
registration_limit = 1
delegation_expires = "2026-08-13T00:00:00Z"

[agents.principals.opencode.rp."staging.example.com".authenticate]
allowed_modes = ["interactive", "delegated"]
default_mode = "interactive"
credentials = ["staging-opencode"]
```

Policy rules:

1. Machine access is denied by default.
2. Policies use exact normalized RP IDs.
3. Public suffixes are rejected.
4. Wildcard RP policies are not supported initially.
5. Registration and authentication are separate actions.
6. Interactive mode is the default when multiple modes are allowed.
7. An agent may request delegated mode only when the human policy explicitly allows it.
8. An agent may always request interactive mode when it is allowed.
9. The agent cannot change the delegation or add an allowed mode.
10. Delegated mode grants require explicit administrative acknowledgement.
11. Registration grants are bounded by expiry and a registration limit.
12. Authentication grants should name exact machine credentials after registration.
13. Revocation immediately invalidates covered intents and prevents future credential use.
14. Policy is enforced by the daemon, not by the CLI or browser extension.

## Administrative acknowledgement for delegated mode

The CLI must make the semantic difference difficult to miss.

Example:

```bash
passless delegation grant \
  --principal opencode \
  --rp-id staging.example.com \
  --action authenticate \
  --allow-mode delegated \
  --credential staging-opencode \
  --acknowledge-delegated-machine-presence
```

The command must display a trusted warning explaining that:

- No human will approve each delegated ceremony.
- Passless will set UP for interoperability based on prior delegation rather than a fresh physical gesture.
- The agent receives full login authority to the delegated RP account.
- Passless cannot constrain actions performed after login.
- Dedicated low-privilege accounts are strongly recommended.

The acknowledgement must be recorded in the delegation and machine audit log.

An agent capability cannot perform this acknowledgement.

## Managed browser and proxy transport

### Required browser model

The first implementation targets a managed Chromium profile using `chrome.webAuthenticationProxy` or a technically equivalent integration approved by a later implementation review.

When the proxy is attached, regular browser WebAuthn processing is suspended and the extension receives creation and request options with an opaque request identifier. The extension must return the complete serialized `PublicKeyCredential` response or a WebAuthn-compatible error.

The Passless agent launcher owns the browser lifecycle.

The managed browser must:

- Use a dedicated profile per principal.
- Run under the principal sandbox.
- Attach the Passless WebAuthn proxy before agent navigation begins.
- Operate in a fail-closed state when the proxy or native host is unhealthy.
- Terminate or block WebAuthn if the proxy detaches unexpectedly.
- Have no access to the human UHID authenticator, personal platform passkeys, or personal browser profiles.
- Use a separate cookie jar from all human browser profiles.
- Limit concurrent WebAuthn requests in the first version.

### Origin and document binding

The proxy request options do not by themselves constitute a trusted caller-origin record. Passless therefore requires a browser-session record authenticated by the extension and native host.

For v1, the managed browser is restricted to:

- One active top-level tab for a passkey ceremony.
- Top-level same-origin ceremonies.
- No cross-origin iframe ceremonies.
- No related-origin requests.
- No conditional mediation.
- No concurrent WebAuthn requests.

The browser binding includes:

```json
{
  "schema_version": "passless.browser-request.v1",
  "browser_session_id": "browser_session_01JZ...",
  "principal": "opencode",
  "request_id": 42,
  "tab_id": 7,
  "document_id": "document_...",
  "origin": "https://github.com",
  "top_origin": "https://github.com",
  "action": "authenticate",
  "rp_id": "github.com",
  "options_digest": "sha256:...",
  "intent_id": "intent_01JZ...",
  "created_at": "2026-07-13T10:40:10+02:00"
}
```

The native host and daemon must verify:

- The browser session belongs to the same principal as the intent.
- The document is the currently committed top-level document.
- The origin is trustworthy and normalized.
- The RP ID is permitted for the origin under WebAuthn RP-ID rules.
- The action and request options match the intent and policy.
- The request identifier has not already been completed or canceled.
- The request is the only active WebAuthn request for that browser session.

The Passless agent engine constructs the required `clientDataJSON` from trusted browser data and the RP challenge. It does not accept caller-provided raw `clientDataJSON` or `clientDataHash` as an arbitrary signing request.

### Cancellation

Browser cancellation and timeout events must propagate to the intent and agent engine.

A canceled request:

- Stops processing immediately.
- Cannot later be completed.
- Consumes a bound intent.
- Produces a terminal audit event.

## Structural separation from the human authenticator

Agent mode and human mode use different transports and stores.

```text
Human transport   → human policy   → human credentials   → human prompt
Agent transport   → agent policy   → machine credentials → configured mode
```

The daemon must not implement:

```text
binding exists  → machine
binding missing → human
```

A request arriving through the agent transport is always an agent request and fails closed on any missing machine condition.

A request arriving through the human UHID transport is always a human request and cannot see machine credentials.

This structural distinction enforces the no-fallback invariant.

## Principal authentication and launcher

A principal name passed through a CLI flag is not authentication.

The first implementation requires a trusted launcher:

```bash
passless agent run --profile opencode -- opencode
```

The launcher:

1. Creates an ephemeral authenticated principal session.
2. Starts the agent process tree inside a constrained OS sandbox.
3. Starts the managed browser profile inside the same principal boundary.
4. Installs or enables only the approved Passless extension and native host for that profile.
5. Passes capabilities through inherited file descriptors or another protected channel.
6. Never places capability secrets in command arguments or ordinary environment variables.
7. Gives the principal access only to its agent socket and browser session.
8. Denies access to the administrative socket, human credential store, machine audit files, and other principals.
9. Terminates the principal session when the process tree or managed browser ends.

The daemon should combine:

- Unix socket peer credentials.
- A random session capability.
- Launcher session identity.
- Process, cgroup, sandbox, container, or equivalent OS metadata.

The entire process tree receives the principal's authority. Passless does not claim to distinguish the main LLM process from a plugin, subprocess, or subagent within the same sandbox.

Strong deployments should use a separate Unix user, container, or equivalent OS boundary.

A plain capability-file fallback is not part of the secure v1 profile. It may be introduced later with an explicit weaker-assurance label.

## One-shot intent model

The agent creates an intent immediately before starting one browser ceremony.

Example:

```bash
passless agent intent create \
  --action authenticate \
  --rp-id github.com \
  --credential github-opencode \
  --mode interactive \
  --reason "Authenticate to inspect workflow failures"
```

Delegated example:

```bash
passless agent intent create \
  --action authenticate \
  --rp-id staging.example.com \
  --credential staging-opencode \
  --mode delegated \
  --reason "Authenticate to run the staging deployment check"
```

The mode is a request constrained by policy. It is not an agent-controlled policy override.

Intent properties:

- One principal.
- One exact RP ID.
- One action.
- One allowed mode.
- One browser session.
- Zero or one exact credential for authentication.
- Registration namespace and account constraints where applicable.
- One short expiry.
- One browser request binding.
- One terminal result.

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
      "requested_mode": "interactive",
      "effective_mode": "interactive",
      "state": "waiting_for_browser_request",
      "created_at": "2026-07-13T10:40:00+02:00",
      "expires_at": "2026-07-13T10:41:30+02:00"
    }
  }
}
```

Intent states:

```text
created
    │
    └── waiting_for_browser_request
              │
              ├── bound
              │     │
              │     ├── waiting_for_user        interactive only
              │     ├── executing
              │     ├── completed
              │     ├── failed
              │     └── cancelled
              │
              ├── rejected
              ├── expired
              └── cancelled
```

Rules:

- Intents are held only in memory.
- Intents are lost on daemon restart.
- Only one unbound intent per principal is supported initially.
- Once bound to a browser request, an intent cannot bind again.
- A bound intent is consumed on success, failure, cancellation, or timeout.
- A mismatched request does not consume an unbound intent.
- Retries require a new intent.
- Agent-requested expiry may shorten but cannot extend the configured maximum.
- Intent creation supports idempotency keys.

## Machine credential storage

Machine credentials are not stored as human credentials plus a sidecar ownership index.

Passless will use a separate machine credential namespace containing one authenticated envelope per credential.

Conceptual format:

```rust
pub struct MachineCredentialEnvelope {
    pub version: u32,
    pub credential: Credential,
    pub owner_principal: PrincipalId,
    pub delegation_id: DelegationId,
    pub rp_id: RpId,
    pub presence_mode: PresenceMode,
    pub created_mode: AgentMode,
    pub created_at: SystemTime,
    pub revoked_at: Option<SystemTime>,
    pub policy_digest: [u8; 32],
}

pub enum PresenceMode {
    InteractiveHuman,
    DelegatedMachine,
}
```

The credential and ownership metadata are persisted as one authenticated storage object. This avoids cross-record transaction and recovery ambiguity.

Storage rules:

- Human storage is readable only by the human authenticator path.
- Machine storage is readable only by the agent engine.
- A principal can enumerate only its own machine credentials.
- Corrupt, unknown, or unauthenticated machine records are quarantined.
- Revoked machine credentials are unavailable to all flows.
- Machine credentials never become human credentials if metadata is missing.
- Human credentials cannot be converted to machine credentials in v1.
- Each machine credential records whether it was created interactively or under delegated presence.
- Credentials created in interactive mode may later be used in delegated mode only if the human explicitly grants delegated authentication for that exact credential.

The machine namespace may use the same configured storage backend as human credentials, but it must use a distinct namespace, authenticated envelope format, and access path.

## Registration controls

Registration is more dangerous than authentication because it creates new durable authority.

Delegated registration grants must include:

- Exact RP ID.
- Exact principal.
- Allowed mode.
- Expiry.
- Maximum number of credentials that may be created.
- Credential namespace or label constraints.
- Optional expected account identifier or opaque user-handle constraint.

Delegated registration defaults:

- `registration_limit = 1`.
- Short delegation expiry.
- One active registration intent.
- No overwrite or replacement of existing credentials.

After the registration limit is consumed, further registration attempts are denied until a human administrator changes the delegation.

Interactive registration may be less tightly bounded because every ceremony requires a human gesture, but it remains subject to exact RP and principal policy.

## User presence and user verification semantics

### Interactive mode

Interactive mode follows WebAuthn semantics:

- UP is set if and only if Passless collected a real user-presence gesture for the ceremony.
- UV is set if and only if Passless performed actual local user verification for the ceremony.
- The prompt displays the principal, origin, RP ID, action, account or credential, and reason.

### Delegated mode

Delegated mode is a Passless-specific machine delegation:

- No fresh physical user-presence test occurs.
- Prior administrative delegation supplies authority.
- UP is set for RP interoperability under the explicit internal classification `delegated-machine`.
- The credential uses a distinct AAGUID and is auditable as delegated.
- UV remains unset in v1.
- If the RP requests `userVerification = required`, Passless returns an error rather than fabricating UV or switching mode.

The documentation and UI must not describe delegated mode as equivalent to a user touching a security key or approving the current ceremony.

A future cached-UV or verified-session mode requires a separate ADR and standards review before implementation.

## CLI surfaces

### Human administrative commands

```bash
passless delegation grant ...
passless delegation list
passless delegation show <DELEGATION_ID>
passless delegation revoke <DELEGATION_ID>

passless agent profile create ...
passless agent profile show ...
passless agent profile delete ...

passless credential machine list ...
passless credential machine revoke <CREDENTIAL_REF>
passless credential machine delete <CREDENTIAL_REF>

passless audit machine list ...
passless audit machine show ...
passless audit machine verify
passless audit machine export ...
```

Administrative commands:

- Use the administrative daemon channel.
- May require real human verification.
- Are unavailable to an agent principal.
- Record all policy and credential changes in the machine audit log.

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

Agent commands:

- Use only the principal's agent channel.
- Default to stable JSON.
- Never prompt through standard input.
- Never accept PINs, biometric data, raw signing input, or delegation changes.
- Expose only the authenticated principal's machine credential metadata.

## Stable errors

The agent protocol returns stable machine-readable errors.

Initial codes include:

```text
invalid_request
invalid_rp_id
principal_unauthenticated
principal_not_delegated
action_not_delegated
mode_not_allowed
delegated_presence_not_acknowledged
user_verification_required
browser_proxy_unavailable
browser_session_invalid
browser_origin_invalid
browser_request_conflict
browser_request_cancelled
intent_not_found
intent_conflict
intent_expired
intent_already_consumed
credential_not_found
credential_not_owned
credential_revoked
registration_limit_exceeded
policy_changed
rate_limited
audit_unavailable
daemon_unavailable
backend_unavailable
internal_error
```

An error may include an `agent_action` such as:

- `retry_with_new_intent`
- `request_interactive_mode`
- `request_human_delegation`
- `request_human_approval`
- `stop_and_report`

The agent must not interpret an error as permission to weaken mode, change RP ID, select a human credential, or bypass the managed browser.

## Dedicated machine audit

Every interaction through the agent architecture is written to a separate structured audit channel, including denied operations.

Default path:

```text
$XDG_STATE_HOME/passless/audit/machine.jsonl
```

The audit writer runs outside the agent sandbox. The agent principal has no filesystem write or delete access to the audit path.

### Audit assurance levels

```toml
[audit.machine]
required = true
assurance = "protected-local"
hash_chain = true
retention = "180d"
rotate_size = "50MiB"
```

Supported assurance labels:

| Level | Meaning |
|---|---|
| `best-effort` | Same-user operational log; not considered tamper-resistant |
| `protected-local` | Agent sandbox cannot modify the audit storage |
| `tamper-evident` | Protected storage plus signed or TPM-backed checkpoints |
| `remote` | Events are forwarded to an external append-only collector |

Secure agent profiles require at least `protected-local`.

### Required events

Administrative lifecycle:

```text
principal.created
principal.revoked
delegation.created
delegation.updated
delegation.revoked
delegation.expired
delegation.delegated_presence_acknowledged
```

Launcher and browser lifecycle:

```text
agent_session.started
agent_session.authentication_failed
agent_session.terminated
browser_session.started
browser_proxy.attached
browser_proxy.detached
browser_proxy.failed
browser_request.received
browser_request.rejected
browser_request.cancelled
```

Intent lifecycle:

```text
intent.create_requested
intent.created
intent.bound
intent.rejected
intent.reserved
intent.consumed
intent.cancelled
intent.expired
```

Ceremony lifecycle:

```text
ceremony.registration.started
ceremony.registration.user_approved
ceremony.registration.user_denied
ceremony.registration.completed
ceremony.registration.failed
ceremony.authentication.started
ceremony.authentication.user_approved
ceremony.authentication.user_denied
ceremony.authentication.completed
ceremony.authentication.failed
```

Credential lifecycle:

```text
credential.machine_registered
credential.machine_used
credential.machine_revoked
credential.machine_deleted
credential.machine_quarantined
```

Security decisions:

```text
policy.allowed
policy.denied
mode.allowed
mode.denied
origin.denied
credential_scope.denied
registration_limit.denied
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
    "browser_session_id": "browser_session_01JZ...",
    "process_ref": "process_7dd3..."
  },
  "request": {
    "request_id": "req_01JZ...",
    "intent_id": "intent_01JZ...",
    "browser_request_id": 42,
    "reason": "Authenticate to inspect CI failures"
  },
  "authorization": {
    "delegation_id": "delegation_01JZ...",
    "policy_version": 3,
    "policy_digest": "sha256:...",
    "mode": "interactive",
    "presence": "physical-user",
    "user_verification": "performed"
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

Delegated operations record:

```json
{
  "authorization": {
    "mode": "delegated",
    "presence": "delegated-machine",
    "user_verification": "not-performed"
  }
}
```

Audit records must not contain:

- Private keys.
- PINs or biometric material.
- Principal capabilities.
- Raw assertions or attestation objects.
- Browser cookies.
- OAuth tokens.
- Raw credential records.
- Full user handles where an opaque keyed reference is sufficient.

### Fail-closed behaviour

Before Passless creates or uses a machine credential, it must durably append the authorization and reservation events.

If the pre-execution audit write fails, the operation is denied.

After execution, Passless appends a terminal result. If the terminal append fails after the RP response can no longer be rolled back, Passless marks the audit subsystem degraded and rejects all subsequent agent operations until audit health is restored.

A local hash chain detects accidental corruption and truncation only when checkpoints are retained. It does not protect against host root compromise. Strong deployments should use TPM-backed or remote checkpoints.

## Compatibility with existing human flows

The existing human path remains unchanged:

```text
ordinary browser → existing UHID authenticator → human credential store → current prompt
```

Agent policy cannot:

- Change human prompt behaviour.
- Make a human credential autonomous.
- Expose machine credentials to the human authenticator.
- Cause a human request to enter the agent engine.

Agent browser requests use a structurally separate path:

```text
managed agent browser → WebAuthn proxy → agent engine → machine credential store
```

When the managed proxy is unavailable, the agent browser must fail rather than use the human path.

## LLM and agent documentation

The design is incomplete without version-matched instructions that teach agents the safe workflow.

The repository will add:

```text
docs/agents/
├── README.md
├── security-model.md
├── installation.md
├── principal-setup.md
├── mode-selection.md
├── interactive-registration.md
├── interactive-authentication.md
├── delegated-registration.md
├── delegated-authentication.md
├── browser-integration.md
├── audit.md
├── errors.md
└── examples/
    ├── opencode.md
    ├── claude-code.md
    └── browser-automation.md
```

A generic skill will be distributed at:

```text
contrib/agent-skills/passless/SKILL.md
```

The installed binary exposes authoritative version-matched instructions:

```bash
passless agent instructions --format markdown
passless agent instructions --format json
```

### Installation contract

The agent may:

- Detect whether Passless is installed.
- Run `passless agent doctor --output json`.
- Report missing daemon, launcher, browser proxy, policy, storage, or audit prerequisites.
- Explain exact human steps required.

The agent must not autonomously:

- Run `sudo`.
- Install or modify udev rules.
- Add users to privileged groups.
- Install an untrusted browser extension.
- Modify Passless delegations.
- Grant delegated mode.
- Create its own principal capability.
- Disable browser proxying.
- Disable or modify auditing.
- Request or handle a Passless PIN.
- Access personal browser profiles.

### Mode-selection algorithm

The LLM-facing instructions must teach:

1. Inspect effective policy for the exact RP ID and action.
2. Prefer interactive mode unless the task requires unattended operation and delegated mode is explicitly allowed.
3. Never request delegated mode merely to avoid asking the user.
4. If the RP requires UV, use interactive mode.
5. If delegated mode is denied, stop or request a human policy change; do not bypass the restriction.
6. Use only the dedicated machine credential selected by policy.
7. Treat authentication as full login authority to that account.
8. Prefer dedicated low-privilege agent accounts.

### Interactive registration algorithm

```text
1. Run `passless agent doctor --output json`.
2. Confirm the authenticated principal and managed browser health.
3. Confirm interactive registration is delegated for the exact RP ID.
4. Confirm the audit channel is healthy.
5. Create one interactive registration intent.
6. Start the RP's normal passkey registration workflow.
7. Wait while Passless displays the trusted ceremony prompt.
8. The human reviews the principal, origin, RP ID, account, and action.
9. The human approves and performs UV if requested.
10. Wait for the terminal intent result.
11. Confirm the new machine credential belongs to the expected principal.
12. Report the opaque credential reference.
```

### Interactive authentication algorithm

```text
1. Confirm interactive authentication is allowed for the exact RP ID.
2. Select only an owned machine credential.
3. Create one interactive authentication intent.
4. Start the browser login.
5. Wait for the trusted Passless prompt.
6. The human approves and performs UV if required.
7. Wait for completion.
8. Continue using the isolated browser session.
```

### Delegated registration algorithm

```text
1. Confirm delegated registration is explicitly allowed.
2. Confirm the delegation has not expired and has remaining registration capacity.
3. Confirm the managed browser and protected audit channel are healthy.
4. Create one delegated registration intent.
5. Start the normal browser registration flow.
6. Wait for the terminal intent result.
7. Confirm that the credential records `presence = delegated-machine` and `UV = false`.
8. Confirm the registration budget was consumed.
9. Never retry without a new intent.
```

### Delegated authentication algorithm

```text
1. Confirm delegated authentication is explicitly allowed for the RP and credential.
2. Confirm the RP request does not require UV.
3. Create one delegated authentication intent.
4. Start the browser login.
5. Wait for the terminal intent result.
6. Continue using the isolated browser session.
7. Never switch to a personal credential or human browser profile.
```

### Required agent safety rules

Agents must be instructed to:

- Never request or process Passless PINs.
- Never fabricate origin, UP, or UV evidence.
- Never send raw signing or CTAP requests.
- Never reuse an intent.
- Never select human credentials.
- Never continue after an audit failure.
- Never bypass the managed browser proxy.
- Never modify delegations.
- Never silently switch from interactive to delegated mode.
- Never use delegated mode when UV is required.
- Stop and request human intervention when policy blocks the requested workflow.

## Agent doctor

`passless agent doctor --output json` reports:

- Daemon and protocol compatibility.
- Authenticated principal.
- Launcher and sandbox assurance.
- Managed browser profile state.
- WebAuthn proxy attachment and native-host health.
- Audit assurance and health.
- Effective RP/action modes without secrets.
- Pending intent conflicts.
- Owned machine credential availability.
- Whether the current RP request requires UV, when known.

The command does not reveal capability material, private keys, cookies, or raw credential data.

## Security invariants

The implementation must maintain:

1. Human and agent requests use structurally separate transports.
2. Human and machine credentials use separate stores and enumeration paths.
3. No agent operation without an authenticated principal.
4. No agent operation without a valid delegation.
5. No agent operation without a one-shot intent.
6. No agent operation without an authenticated managed-browser request.
7. No mode outside the allowed policy.
8. Interactive UP only after a real ceremony-specific presence gesture.
9. Interactive UV only after actual local user verification.
10. Delegated UV is always unset in v1.
11. Delegated presence is explicitly classified and audited.
12. No personal credential in an agent flow.
13. No machine credential in a human flow.
14. No cross-principal machine credential use.
15. No failed agent flow falling back to the human authenticator.
16. No secret material in CLI JSON or audit records.
17. No unaudited machine credential creation or use.
18. No intent reuse after browser binding.

## Threat model

| Threat | Mitigation | Residual risk |
|---|---|---|
| Prompt injection requests another RP | Exact RP policy and trusted browser-origin validation | Injection can still act within an allowed RP |
| Agent fabricates origin or challenge | Managed browser binding and daemon-constructed client data | Compromise of the extension or native host breaks this boundary |
| Another browser races an intent | Dedicated profile, authenticated browser session, one active request | Host root can still interfere |
| Proxy fails and browser uses personal passkey | Proxy-only managed profile, no human authenticator access, launcher termination | Browser isolation must be implemented correctly |
| Agent uses a personal credential | Separate stores and transport paths | Human administrator can still misconfigure accounts outside Passless |
| Agent replays a ceremony | One-shot intent and browser request identifier | RP session remains valid according to RP policy |
| Agent claims another principal | Trusted launcher, capability, socket peer and sandbox identity | All processes inside a principal share its authority |
| Agent grants itself delegated mode | Separate administrative channel and explicit acknowledgement | Malicious administrator remains trusted |
| Audit log is modified | Agent cannot write audit storage; hash chain and optional checkpoint | Root can modify local state without remote anchoring |
| Machine credential metadata is lost | Single authenticated envelope and quarantine | Backend loss may make the credential unusable |
| Agent acts maliciously after login | Dedicated low-privilege account recommendation | Passless cannot authorize post-login actions |
| Delegated mode is mistaken for physical presence | Distinct mode, AAGUID, warnings, metadata and audit labels | RPs generally do not understand Passless policy semantics |

## Residual risks and honest security claims

The following must be prominently documented:

- Delegated mode is a machine delegation, not fresh human consent.
- Setting UP in delegated mode is an interoperability choice and differs from the WebAuthn physical-presence definition.
- A compromised agent can use every permission granted by its delegation.
- Successful authentication gives the agent the RP account privileges represented by the resulting browser session.
- RP ID restriction does not constrain actions after login.
- A local protected audit log does not protect against host root without external anchoring.
- Browser extension and native-host compromise are equivalent to compromising the agent authentication path.

Where an RP supports scoped OAuth, GitHub Apps, service accounts, workload identity, or another narrowly scoped machine credential, those mechanisms may be safer for long-running automation than granting browser login authority. Passless agent passkeys are intended for workflows where WebAuthn-backed browser authentication is required.

## Internal architecture

Suggested workspace boundaries:

```text
passless-core/
    configuration, errors, RP and policy types

passless-engine/
    existing human authenticator service
    agent policy evaluator
    principal sessions
    intent registry
    browser request processor
    machine authenticator
    machine credential storage port
    audit service

passless-protocol/
    versioned admin, agent, browser, and audit contracts

cmd/passless/
    daemon
    human CLI
    administrative CLI
    agent CLI
    trusted launcher

browser-extension/
    managed WebAuthn proxy
    native messaging integration
```

Mandatory boundaries:

- The daemon owns all credential material and policy decisions.
- The browser extension does not receive private keys.
- The agent CLI does not construct assertions.
- Human and agent credential stores are inaccessible across paths.
- Audit enforcement occurs in the daemon before key use.

## Feasibility gate

This ADR must remain **Proposed** until a security prototype demonstrates the following end to end:

1. Launch a dedicated managed Chromium profile.
2. Attach `chrome.webAuthenticationProxy` before navigation.
3. Capture one top-level registration request with a trustworthy origin record.
4. Construct valid `clientDataJSON` and a valid registration response.
5. Register a dedicated machine credential with a test RP.
6. Capture and complete one authentication request.
7. Prove the human UHID authenticator and personal passkeys are unavailable to the agent profile.
8. Prove proxy or native-host failure produces a hard failure with no fallback.
9. Prove cancellation and timeout propagation.
10. Prove interactive mode sets UP/UV only after the expected human gesture.
11. Prove delegated mode records delegated presence, sets UV false, and succeeds only with an RP that accepts it.
12. Prove a one-shot intent cannot bind twice or cross principals.
13. Prove machine credentials cannot appear in the human flow.
14. Prove protected audit pre-write failure blocks credential creation or use.
15. Document the exact Chromium flags, policies, sandboxing, and extension APIs required.

If the prototype cannot obtain a trustworthy browser origin or cannot guarantee no fallback, delegated mode must not ship through that browser integration.

## Implementation sequence

### Phase 0: Feasibility prototype

- Build the managed Chromium and WebAuthn proxy spike.
- Validate origin correlation and response construction.
- Validate hard-failure behaviour.
- Test one interactive and one delegated ceremony against a test RP.

### Phase 1: Security and policy types

- Add principal, delegation, mode, intent, presence and browser-request types.
- Add exact RP normalization and validation.
- Add stable agent errors and JSON schemas.
- Add policy tests.

### Phase 2: Separate machine credential storage

- Define the authenticated envelope format.
- Add a distinct machine namespace to supported backends.
- Implement quarantine and revocation.
- Add human/machine isolation tests.

### Phase 3: Protected audit

- Add the mandatory machine audit channel.
- Add protected-local assurance checks.
- Add sequence numbers, hash chain, rotation and optional checkpoint interfaces.
- Enforce durable pre-execution writes.

### Phase 4: Principal launcher and sandbox

- Add trusted launcher sessions.
- Add managed browser profile lifecycle.
- Add socket, process and capability authentication.
- Deny agent access to human storage and audit files.

### Phase 5: Interactive agent mode

- Add one-shot intents and browser request binding.
- Add per-ceremony trusted prompts.
- Add machine registration and authentication.
- Validate UP and UV semantics.

### Phase 6: Delegated agent mode

- Add explicit delegated-presence policy and acknowledgement.
- Add distinct AAGUID and credential metadata.
- Add registration budgets and expiry.
- Keep UV unset and reject UV-required ceremonies.

### Phase 7: CLI and documentation

- Add administrative delegation and profile commands.
- Add agent doctor, capabilities, instructions, intent and credential-read commands.
- Add versioned fixtures and error guidance.
- Add `docs/agents/` and the generic skill.

### Phase 8: Optional adapters and assurance

- Add a thin MCP adapter.
- Add TPM or remote audit checkpoints.
- Evaluate additional managed browsers.
- Consider cached-UV sessions through a separate ADR.

## Testing requirements

The implementation must test:

- Existing human registration and authentication regressions.
- Human/machine transport separation.
- Human/machine storage separation.
- Default-deny policy.
- Exact RP normalization and public-suffix rejection.
- Cross-principal access attempts.
- Invalid, missing and stolen capabilities.
- Browser proxy attach, detach, crash and cancellation.
- Wrong active tab, document, origin, RP ID, action and options digest.
- Concurrent browser requests and tab races.
- Interactive approval, denial, timeout and UV failure.
- Delegated mode success with UV-unset-compatible RPs.
- Delegated mode rejection when UV is required.
- Delegated-presence acknowledgement requirements.
- Registration limit and delegation expiry.
- Intent expiry, cancellation, replay and idempotency conflict.
- Credential envelope corruption and quarantine.
- Revocation during active intents.
- No personal credential fallback.
- Mandatory audit pre-write failure.
- Terminal audit degradation behaviour.
- Audit hash-chain and rotation verification.
- Absence of secrets from protocol, logs and errors.
- Agent documentation and instruction fixtures.
- Supported local, `pass`, and TPM-backed storage namespaces where practical.

## Consequences

### Positive

- Users can choose between standards-strict interactive approval and explicit autonomous delegation.
- Human Passless behaviour remains unchanged.
- Agent credentials are isolated, independently revocable and auditable.
- Failed agent requests cannot fall back to personal passkeys.
- The same agent browser and storage architecture supports both modes.
- Mode and presence semantics are visible rather than hidden.
- Agents receive a stable, documented interface.
- MCP can be added without changing the authorization model.

### Negative

- Delegated mode intentionally differs from physical WebAuthn user-presence semantics.
- Chromium-specific browser integration is required initially.
- The browser proxy, native host and launcher become security-critical components.
- Separate credential storage and audit channels increase implementation complexity.
- Agents still receive all RP permissions available after login.
- Delegated mode cannot support RPs requiring UV in v1.
- Secure profiles require meaningful OS sandboxing rather than a simple same-user CLI token.
- The project must maintain stable protocol, audit and LLM-documentation contracts.

## Alternatives considered

### Shared UHID path with an optional machine binding

Rejected. Missing bindings cannot distinguish failed machine flows from ordinary human flows, so no-fallback cannot be guaranteed.

### Use existing personal passkeys for agents

Rejected. It creates weak ownership, revocation and audit boundaries and exposes high-value credentials to autonomous workflows.

### One-shot CLI preauthorization followed by shared UHID

Rejected as the autonomous architecture. It either still requires a click or inherits the shared-transport ambiguity.

### Persistent RP policy without intents

Rejected. Any matching browser request could silently use the delegated credential for the policy lifetime.

### Raw CTAP or signing API

Rejected. It would create an unnecessarily general cryptographic capability and weaken origin-bound WebAuthn properties.

### Delegated mode only

Rejected. Many users and RPs require real per-ceremony presence or UV, and an interactive bootstrap workflow remains valuable.

### Interactive mode only

Rejected as the complete design. It preserves strict WebAuthn but does not meet unattended agent requirements.

### Treat an agent capability as UV

Rejected. Software-principal authentication is not human user verification.

### Cached verified-session UV in delegated mode

Deferred. It requires a separate standards and implementation analysis. Delegated mode v1 always leaves UV unset.

### Make MCP the canonical interface

Rejected initially. The daemon protocol and CLI are simpler universal foundations; MCP may remain a thin adapter.

## Deferred decisions

Separate ADRs or implementation reviews are required for:

- Cached or session-scoped UV in delegated mode.
- Additional browser integrations.
- Remote agent operation.
- Non-Unix capability transport.
- Wildcard or registrable-domain policies.
- Delegating existing human credentials.
- Agent-driven credential deletion or rename.
- TPM-backed or remote audit checkpoints as a mandatory baseline.
- MCP tool naming and transport.

## References

- W3C Web Authentication Level 3: https://www.w3.org/TR/webauthn-3/
- Chrome `webAuthenticationProxy`: https://developer.chrome.com/docs/extensions/reference/api/webAuthenticationProxy
- FIDO Client to Authenticator Protocol 2.2: https://fidoalliance.org/specs/fido-v2.2-rd-20241003/fido-client-to-authenticator-protocol-v2.2-rd-20241003.html

## Decision outcome

Passless will preserve the existing UHID authenticator for human credentials and create a structurally separate agent authenticator path using a managed browser WebAuthn proxy, authenticated principals, one-shot intents, machine-only credential storage and protected auditing.

Agent policy may allow:

- **Interactive mode**, which requires a real authorization gesture for every ceremony and follows standard UP/UV semantics.
- **Delegated mode**, which permits autonomous operation under explicit prior delegation, records delegated-machine presence, sets UV false in v1, and is visibly distinct from physical user presence.

Mode is configurable per principal, exact RP ID and action. Interactive mode is the default. Delegated mode requires explicit acknowledgement and cannot silently replace interactive mode.

The ADR remains Proposed until the managed-browser feasibility gate is demonstrated.