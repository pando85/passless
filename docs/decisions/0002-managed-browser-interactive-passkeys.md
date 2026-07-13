# ADR 0002: Managed-browser interactive passkeys

- **Status:** Superseded by [ADR 0004](0004-reject-webauthn-proxy-origin-binding.md)
- **Date:** 2026-07-13
- **Decision owners:** Passless maintainers
- **Implementation status:** Blocked by the failed Phase 0 origin-binding gate
- **Depends on:** [ADR 0001](0001-agent-authentication-security-model.md)
- **Related decision:** [ADR 0003](0003-autonomous-agent-authentication.md)
- **Implementation plan:** [Agent passkey implementation plan](../plans/agent-passkey-implementation.md)
- **Feasibility evidence:** [Managed-browser feasibility evidence](../../tools/agent-feasibility/evidence.md)

## Context

> **Outcome:** The Phase 0 probe demonstrated valid proxy registration and authentication but could not establish a trustworthy binding between a proxy request and its source origin/document. No implementation phase after Phase 0 may proceed from this design. See ADR 0004.

ADR 0001 permits a standards-compliant interactive agent passkey path while requiring structural separation from the human authenticator. This ADR chooses the browser integration and defines the policy, intent, principal, storage, audit, and protocol boundaries required to implement that path.

The design must preserve the browser's origin context without accepting a generic signing request from the agent. It must also prevent browser or protocol failure from exposing personal credentials.

## Decision summary

The first implementation will use a dedicated managed Chromium profile and `chrome.webAuthenticationProxy`. A technically equivalent browser integration requires a new superseding or browser-specific ADR.

The launcher attaches the proxy before navigation and starts the browser inside an authenticated principal sandbox. The proxy sends one versioned, authenticated browser request to the Passless daemon. The daemon validates policy and a one-shot intent, prompts the human, performs the WebAuthn operation using a machine-only credential store, writes protected audit records, and returns a serialized `PublicKeyCredential` response.

V1 supports interactive registration and interactive authentication only.

## Browser model

The managed browser must:

- Use a dedicated profile and cookie jar for one principal.
- Start inside the principal isolation boundary.
- Load only the approved Passless extension and native host before navigation.
- Attach the WebAuthn proxy before navigation.
- Block WebAuthn and terminate the session if the proxy or native host becomes unhealthy.
- Have no access to the human UHID authenticator, personal platform passkeys, or personal browser profiles.
- Permit only one active top-level passkey ceremony.

V1 permits only:

- One active top-level tab during a ceremony.
- Top-level same-origin ceremonies.
- Exact HTTPS origins, except explicitly configured loopback origins used by tests.
- One active WebAuthn request per browser session.

V1 rejects:

- Cross-origin iframe ceremonies.
- Related-origin requests.
- Conditional mediation.
- Concurrent WebAuthn requests.
- Browser sessions that were not launched by Passless.

## Structural separation

```text
Human transport -> human callbacks -> human credentials -> human prompt
Agent transport -> agent policy    -> machine credentials -> trusted prompt
```

The daemon must not implement:

```text
agent binding exists  -> machine path
agent binding missing -> human path
```

Requests arriving through the agent transport are always agent requests. Missing policy, intent, browser, storage, audit, or principal conditions cause a terminal error.

Requests arriving through UHID are always human requests and cannot enumerate or use machine credentials.

## Principal authentication and isolation

A principal name supplied by the caller is not authentication.

The secure v1 profile requires a trusted launcher that:

1. Creates an ephemeral principal session.
2. Creates an enforced OS isolation boundary for the agent process tree and managed browser.
3. Starts the approved extension and native host inside that boundary.
4. Passes a random session capability through an inherited file descriptor or equivalent protected channel.
5. Never places capabilities in command arguments, ordinary environment variables, files readable by the principal, logs, or audit records.
6. Gives the principal access only to its agent socket and browser session.
7. Denies access to the administrative socket, UHID device, human and machine storage paths, audit files, personal browser data, and other principals.
8. Terminates the browser and invalidates the session when the process tree exits or the security boundary degrades.

The daemon authenticates a principal session using all available secure-v1 signals:

- Unix socket peer credentials.
- The random session capability.
- Launcher session identity.
- Process and cgroup, namespace, container, or equivalent sandbox identity.

A separate Unix user, container, or equivalent kernel-enforced boundary is mandatory for the secure v1 profile. A same-user capability file is not a secure profile and is not supported in v1.

All processes within the boundary share the principal's authority. Subprocess isolation inside one principal is outside v1 scope.

## Browser request contract

The extension and native host use a versioned protocol. The authenticated request envelope includes at least:

```json
{
  "schema_version": "passless.browser-request.v1",
  "browser_session_id": "browser_session_01JZ...",
  "principal_id": "principal_01JZ...",
  "request_id": 42,
  "tab_id": 7,
  "document_id": "document_...",
  "origin": "https://github.com",
  "top_origin": "https://github.com",
  "action": "authenticate",
  "rp_id": "github.com",
  "options_digest": "sha256:...",
  "intent_id": "intent_01JZ...",
  "created_at": "2026-07-13T10:40:10Z"
}
```

The authenticated protocol also carries the complete WebAuthn request options needed by the daemon. The options digest is SHA-256 over a versioned canonical encoding of all security-relevant request data, including:

- Challenge.
- RP ID and RP entity data.
- User entity data for registration.
- `allowCredentials` or `excludeCredentials` in order.
- `userVerification`.
- `authenticatorSelection`.
- Requested algorithms.
- Extensions and timeout.

The canonical encoding is deterministic CBOR defined by `passless.browser-request.v1`, is covered by cross-language test vectors, and cannot change without a schema-version change.

`document_id` is derived from trusted Chromium extension APIs and navigation-commit events. It is never supplied by the page, agent, or an untrusted protocol field. Phase 0 must identify the exact supported API source and prove that a stale document cannot reuse a committed document identifier.

The daemon must verify:

- Protocol versions are compatible.
- The browser session and peer belong to the intent's principal.
- The document is the currently committed top-level document.
- `origin` and `top_origin` exactly match the intent and are normalized.
- The RP ID exactly matches the policy and intent and is valid for the origin under WebAuthn rules.
- The action matches the policy and intent.
- Authentication identifies exactly one permitted credential.
- The options digest matches the canonical request received by the daemon.
- The request identifier has not completed, failed, timed out, or been canceled.
- No other WebAuthn request is active for the browser session.

The daemon constructs `clientDataJSON` from the authenticated browser origin and the RP challenge. The `origin` member comes from the trusted current-document record, not from an agent claim or an unchecked duplicate field in the request. The daemon does not accept caller-provided raw `clientDataJSON`, `clientDataHash`, authenticator data, or signing input.

The extension and native host are part of the trusted computing base. Authentication of their channel prevents untrusted local processes from impersonating them; it does not protect against compromise of those components.

## Policy model

Machine access is denied by default. Policy is administered outside the principal boundary and keyed by:

- Authenticated principal profile.
- Exact normalized origin.
- Exact normalized RP ID.
- Action: `register` or `authenticate`.

Authentication policy names exact machine credentials. Registration policy names one machine namespace and includes an expiry and registration budget. The default registration budget is one credential over the lifetime of the grant. It does not reset automatically; only a human administrative policy change can add a new budget.

V1 policy permits only `interactive` mode. Unknown modes are rejected.

Policy rules:

1. Public suffix, wildcard, and registrable-domain grants are rejected.
2. Registration and authentication are separate actions.
3. The agent cannot create, broaden, renew, or revoke policy.
4. Policy changes take effect immediately.
5. Policy is evaluated at intent creation, browser binding, and immediately before credential use.
6. A changed or revoked policy cancels affected intents.
7. Policy version and digest are recorded in audit events.

Example:

```toml
[agents]
default = "deny"

[agents.profiles.opencode]
identity = "trusted-launcher"
browser_profile = "opencode"

[agents.profiles.opencode.origin."https://github.com".rp."github.com".register]
mode = "interactive"
credential_namespace = "opencode-github"
registration_limit = 1
expires_at = "2026-08-13T00:00:00Z"

[agents.profiles.opencode.origin."https://github.com".rp."github.com".authenticate]
mode = "interactive"
credentials = ["github-opencode"]
```

## One-shot intents

An agent creates an intent immediately before one browser ceremony. An intent is not authority and cannot exceed current policy.

Authentication intents contain:

- One authenticated principal session.
- One exact origin.
- One exact RP ID.
- The `authenticate` action.
- One exact machine credential reference.
- One browser session.
- One short expiry not exceeding the configured maximum.
- One idempotency key.

Registration intents contain:

- One authenticated principal session.
- One exact origin.
- One exact RP ID.
- The `register` action.
- One machine credential namespace.
- The applicable registration budget and policy expiry.
- One browser session.
- One short expiry not exceeding the configured maximum.
- One idempotency key.

Intent descriptions and reasons are untrusted audit annotations. They do not authorize post-login behavior.

Intent states are:

```text
waiting_for_browser_request
    -> bound
        -> waiting_for_user
            -> executing
                -> completed
                -> failed
        -> cancelled
    -> rejected
    -> expired
    -> cancelled
```

Intents are held in memory and lost on daemon restart. Only one unbound intent and one active browser ceremony per principal are permitted in v1. Once bound, an intent is consumed on every terminal result. A retry requires a new intent.

Cancellation and timeout propagate from browser to daemon and from daemon to browser. A canceled request cannot later complete.

## User prompt and ceremony semantics

Before registration or authentication, Passless presents a trusted prompt outside the agent sandbox. The prompt shows:

- Principal profile.
- Exact origin.
- RP ID.
- Registration or authentication action.
- Credential label for authentication.
- RP account name and display name for registration, clearly labeled as RP-provided text.
- Agent-supplied reason, clearly labeled as untrusted text.

Approval applies only to the bound browser request. Denial, timeout, prompt failure, or policy change cancels the operation.

Passless sets UP only after approval for that request. Passless sets UV only after actual local verification. The implementation must not turn a notification display, policy grant, launcher capability, or agent intent into UP or UV.

## Machine credential storage

Machine credentials use a storage interface and namespace inaccessible to the human authenticator. Each record is a single integrity-protected envelope containing at least:

```text
format version
credential record
owner principal profile
exact RP ID
creation origin
creation timestamp
creation policy digest
credential label
optional revocation timestamp and reason
```

The interactive machine authenticator uses the stable AAGUID `50c0c5fa-3b7a-4eee-b906-1b3dd4aed297`. This identifies the Passless interactive agent authenticator model. It does not signal delegation or replace RP evaluation of UP, UV, and attestation.

Storage rules:

- Human storage is readable only by the human path.
- Machine storage is readable only by the agent engine, never by the principal process.
- A principal can enumerate only its own non-secret metadata through the agent API.
- Authentication can use only the exact credential named by policy and intent.
- Revoked credentials are unavailable to every path.
- Corrupt, unknown-version, or unauthenticated records are quarantined and never treated as human credentials.
- Existing human credentials cannot be converted or copied into machine storage.
- The configured local, pass, or TPM backend may be reused only through a distinct root and machine-storage interface.

The envelope integrity key is retained in protected daemon storage outside the principal boundary. Transient copies are zeroized from working memory after each cryptographic operation; the protected retained key remains available to verify existing envelopes. Backend confidentiality remains the same as the selected Passless backend: local storage relies on host access controls, pass storage uses GPG, and TPM storage is machine-bound.

## Protected audit

Every request through the agent architecture produces structured audit events, including denied requests.

The secure v1 profile requires `protected-local` assurance:

- The audit writer runs outside the principal boundary.
- The agent cannot open, modify, truncate, rotate, or delete audit files.
- Every record has a schema version, sequence number, timestamp, previous-record hash, and event hash.
- Rotation preserves the chain and retention policy.
- Optional TPM or remote checkpoints can anchor the chain against host-level rewriting.

Before credential creation or use, the daemon must append and synchronize an authorization-reservation event. If this durable write fails, the operation is denied.

After execution, the daemon appends a terminal event. If the RP response can no longer be rolled back and the terminal append fails, the audit subsystem enters a degraded state and rejects later agent operations until an administrator restores and acknowledges audit health.

Audit records include principal, browser session, intent, policy version, origin, RP ID, action, credential reference, authorization result, UP/UV result, timestamps, and stable error code. They never contain private keys, PINs, capabilities, cookies, OAuth tokens, raw assertions, or raw credential records.

A local hash chain does not protect against host root unless its head is retained in TPM-backed or remote storage.

## Administrative and agent interfaces

The daemon exposes separate Unix sockets with different filesystem permissions:

- Administrative channel: policy, profile, credential revocation, and audit administration.
- Agent channel: capabilities, health, instructions, intent lifecycle, and non-secret credential metadata for the authenticated principal.
- Browser channel: authenticated native-host requests and responses.

The principal cannot access the administrative channel.

Agent commands default to versioned JSON, never prompt on stdin, never accept a PIN, never change policy, and never expose raw signing operations. Human administrative commands may use trusted interactive prompts.

Stable errors include at least:

- `principal_authentication_failed`
- `principal_session_expired`
- `policy_denied`
- `policy_changed`
- `intent_required`
- `intent_conflict`
- `intent_expired`
- `intent_consumed`
- `browser_session_mismatch`
- `browser_request_mismatch`
- `origin_mismatch`
- `rp_id_mismatch`
- `credential_mismatch`
- `proxy_unavailable`
- `user_presence_denied`
- `user_verification_required`
- `credential_revoked`
- `credential_corrupt`
- `audit_unavailable`
- `audit_degraded`
- `protocol_version_mismatch`

Errors provide a stable recommended agent action such as `retry_with_new_intent`, `request_human_approval`, or `stop_and_report`. No error permits weaker fallback behavior.

## Feasibility gate

Production implementation cannot begin beyond isolated prototypes until evidence demonstrates:

1. A dedicated Chromium profile launches with the proxy attached before navigation.
2. The proxy provides enough trustworthy context to bind the current top-level document and exact origin.
3. The extension and native host can authenticate their daemon channel without exposing a reusable capability to the principal.
4. The daemon can construct valid `clientDataJSON` and complete registration and authentication against a controlled test RP.
5. The options canonicalization and digest have cross-component test vectors.
6. The managed profile cannot access UHID, personal platform passkeys, or personal browser profiles.
7. Proxy detach, native-host failure, daemon failure, and protocol mismatch all produce hard failure without fallback.
8. Browser and daemon cancellation and timeout are mutually propagated.
9. One intent cannot bind twice, cross principals, change origin, change RP ID, or change credential.
10. UP and UV flags match the actual ceremony evidence.
11. Machine credentials cannot appear in the human path or another principal.
12. Policy changes and revocation cancel in-flight operations before credential use.
13. Protected audit pre-write failure blocks credential creation and use.
14. The secure sandbox denies the principal access to administrative sockets, credential roots, audit files, UHID, and other principal sessions.
15. Exact Chromium versions, APIs, policies, extension packaging, sandbox dependencies, and failure behavior are documented and reproducible.

Failure to prove trusted origin context, no fallback, credential isolation, truthful UP/UV, or principal isolation blocks the feature and requires a superseding ADR.

## Security review gate

Before release, a review independent of the implementation authors must assess:

- Browser extension and native-host message validation.
- Origin, RP, options, and credential canonicalization.
- Principal authentication and sandbox escape resistance.
- Storage separation and secret lifetime.
- Intent races, cancellation, policy reload, and revocation races.
- Audit durability and degraded-state behavior.
- Human-flow regression risk.
- TCB versioning, packaging, and update integrity.

Unresolved critical or high-severity findings block release.

## Consequences

### Positive

- The browser supplies origin-aware WebAuthn requests without giving the agent a signing API.
- Personal credentials remain structurally unavailable.
- Every key use remains human-authorized and auditable.
- Exact origin and credential binding reduces confused-deputy risk.
- Failures remain inside the agent path.

### Negative

- Chromium-specific integration is required initially.
- The extension, native host, launcher, sandbox, protocols, and audit writer become security-critical.
- A larger code and distribution surface requires independent review and coordinated updates.
- The secure profile depends on Linux isolation facilities and cannot degrade to a same-user token.
- Interactive login does not constrain the agent after the RP issues a session.

## Deferred decisions

Separate ADRs are required for:

- Additional browser integrations.
- Remote principals and non-Unix transports.
- Conditional mediation, iframe, and related-origin support.
- Durable intents.
- Human-credential delegation or conversion.
- Agent-driven credential deletion.
- Mandatory remote or TPM-backed audit checkpoints.
- MCP adapters beyond a thin mapping to the agent protocol.
- Any autonomous authentication mode.

## References

- Chrome `webAuthenticationProxy`: https://developer.chrome.com/docs/extensions/reference/api/webAuthenticationProxy
- W3C Web Authentication Level 3: https://www.w3.org/TR/webauthn-3/
- FIDO Client to Authenticator Protocol 2.2: https://fidoalliance.org/specs/fido-v2.2-rd-20241003/fido-client-to-authenticator-protocol-v2.2-rd-20241003.html
