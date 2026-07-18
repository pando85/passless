# ADR 0001: Configurable agent authentication modes

- **Status:** Accepted
- **Date:** 2026-07-13
- **Decision owners:** Passless maintainers
- **Implementation status:** Implemented, validation pending
- **Related decision:** [ADR 0002](0002-native-webauthn-agent-architecture.md)
- **Implementation plan:** [Agent authentication implementation plan](../plans/agent-passkey-implementation.md)
- **Supersedes:** the earlier agent authentication proposals in this pull request and the workflow proposed in pull request #308

## Context

Passless is an interactive software FIDO2 authenticator exposed through UHID. A stock browser validates the relationship between a web origin and an RP ID, constructs client data, and sends CTAP commands to Passless. Passless retains private keys and asks the human for user presence or user verification before using a credential.

Agents need two different kinds of access:

1. An isolated identity with credentials that can be revoked independently from the user's credentials.
2. Temporary use of an existing user login for one RP, after the human approves a native WebAuthn login.

These cases have different security and relying-party semantics. An isolated credential is a separate credential. A delegated browser session uses the user's existing credential for one login, after which the RP sees the same user and issues its ordinary browser session. Passless cannot make that RP session agent-aware or restrict the actions the RP permits after login.

WebAuthn user presence and user verification describe evidence collected for one authenticator operation. A policy rule, a short authorization window, an authenticated agent process, or an earlier approval is not user presence for a later WebAuthn operation. The design must therefore distinguish the WebAuthn ceremony from the browser session created after it.

The browser will not be modified, patched, proxied, or extended for this feature. Origin validation remains in the stock browser, as it does for the existing Passless human flow.

## Decision

Passless will provide configurable agent profiles with two modes:

| Mode | Credential used | Human interaction | RP-visible identity | Local lifetime |
|---|---|---|---|---|
| `isolated` | Agent-only credential | Fresh UP for every WebAuthn ceremony; UV when required | Separate credential, normally the same account unless the RP maps it differently | Credential persists until revoked; policy may expire |
| `delegated-session` | One explicitly permitted existing user credential | Fresh UP and required UV for exactly one native authentication ceremony | Same user and credential | Agent browser lease expires at a configured deadline |

Agent support is disabled by default. Unknown modes are rejected. There is no autonomous WebAuthn mode.

Both modes use ordinary browser WebAuthn over a dedicated agent UHID endpoint. The endpoint is designed to be visible only to the configured agent browser boundary, contingent on Phase 0 proving deterministic device identity and kernel-enforced mutual invisibility. Human browser traffic continues to use the existing human UHID endpoint. The device that receives a CTAP request is the trusted routing signal; Passless does not infer agent identity from request timing or a caller-provided label.

### Isolated mode

An isolated profile:

- Uses a distinct UHID endpoint and isolated credential namespace.
- Cannot enumerate or use human credentials.
- Cannot expose its credentials through the human endpoint.
- Requires a one-shot intent and trusted human prompt for every registration or authentication ceremony.
- Sets UP only for the ceremony approved by the human.
- Sets UV only when Passless performs actual local user verification.
- Can be revoked locally and at the RP without revoking the user's other credentials.

An isolated profile is suitable when the RP can register another passkey and independent credential revocation is important.

### Delegated-session mode

A delegated-session profile permits exactly one authentication assertion using one configured existing user credential for one exact RP ID. It does not permit registration, credential management, or unrestricted access to the human store.

The lifecycle is:

1. Current policy permits the principal, mode, RP ID, credential reference, and maximum browser-session lifetime.
2. The principal creates a short-lived pending delegation request that has no key-use authority.
3. Passless launches an ephemeral browser profile inside the agent boundary and exposes only a temporary agent UHID endpoint.
4. The browser performs ordinary WebAuthn for the configured RP ID and binds the pending request to one CTAP operation.
5. Passless filters the human credential store to the one requested credential, durably records the authorization reservation, and presents one trusted prompt containing the RP ID, credential, and browser-session lifetime.
6. Human approval creates the one-shot grant and supplies UP for that bound assertion. Actual configured user verification supplies UV.
7. The grant is consumed on every terminal result. The temporary credential route is removed after the CTAP exchange completes.
8. If the RP accepts the assertion, the agent uses the resulting browser session until the local browser lease expires, the user revokes it, the browser exits, or the RP session ends.
9. Passless terminates the browser and removes its ephemeral profile when the local lease ends.

The delegation grant authorizes one passkey login, not all passkey operations during the browser lease. A later WebAuthn operation requires another grant and fresh ceremony evidence.

The local browser lease is not an RP token and does not alter the RP's cookie lifetime. Passless can terminate the browser and remove local profile state, but it cannot prove that an RP invalidated its server-side session. Documentation must distinguish local lease expiry from RP session expiry.

## Browser and origin trust

The stock browser remains responsible for:

- Validating that the calling origin may use the requested RP ID.
- Constructing `clientDataJSON` and `clientDataHash`.
- Enforcing browser-side WebAuthn request rules.
- Applying cookie, origin, and site rules to the resulting browser session.

Passless receives the RP ID and `clientDataHash` through CTAP. It does not receive the exact web origin and must not claim that it independently verified one. Agent policy at the authenticator boundary is therefore keyed by exact RP ID, not exact origin.

An optional configured start URL or network policy can constrain the launched browser operationally, but it is not authenticated WebAuthn origin evidence. Prompts display the exact RP ID as trusted. A requested URL, page title, account label, or agent-supplied reason is displayed only as untrusted context.

## Terminology

### Principal

The complete kernel-isolated execution environment launched for one agent profile. It includes the agent process tree and its ephemeral browser session. A model name, command-line value, PID supplied by a caller, or arbitrary string is not principal authentication.

### Human credential

A credential in the existing Passless credential store. It is normally available only through the human endpoint. Delegated-session mode may expose one exact human credential to one temporary filtered agent route without exporting the credential or making the human store generally available.

### Isolated credential

A credential created in one agent profile's separate store. It is unavailable to human and other agent endpoints.

### Policy

Durable administrator-controlled configuration that defines which principal may use which mode, RP IDs, credentials, storage, and maximum lifetimes. Policy is authority but is not UP or UV.

### Intent

A short-lived, one-shot expectation for one isolated registration or authentication ceremony. It narrows current policy and is consumed by every terminal result.

### Delegation grant

A short-lived, one-shot authorization for one delegated authentication ceremony using one exact user credential and RP ID. It also sets the maximum lifetime of the browser lease that may follow. It is not a reusable passkey authorization and is not RP-visible.

Before the exact CTAP operation is bound and the trusted prompt is approved, the record is only a pending delegation request and has no key-use authority.

### Browser lease

The local period during which Passless keeps the delegated ephemeral browser available to the principal after the approved login. It conveys whatever authority the RP browser session provides. It is not a WebAuthn ceremony, proof of continuing user presence, or guarantee of RP-side expiry.

## Security goals

The implementation must:

- Preserve existing human configuration, credential formats, CLI behavior, UHID behavior, and WebAuthn semantics by default.
- Use only stock browser WebAuthn behavior.
- Map every configured agent profile to a distinct authenticated principal and UHID route.
- Keep private keys inside Passless.
- Keep isolated credentials separate from human and other agent credentials.
- Restrict delegated use to one RP ID, one credential, one assertion, one principal, and one short grant.
- Require truthful, ceremony-specific UP and UV.
- Make local browser-session duration explicit and enforce it with a monotonic deadline.
- Deny access by default and fail closed on missing policy, routing, storage, prompt, audit, or isolation controls.
- Audit grants, credential use, browser-lease lifecycle, denials, failures, and revocation without recording secrets.
- Preserve a path to RP-supported OAuth, service accounts, workload identity, and other agent-aware mechanisms for unattended access.

## Non-goals

The design does not:

- Modify browser WebAuthn behavior or use a browser extension, native messaging host, or WebAuthn proxy.
- Provide autonomous WebAuthn or treat a time window as continuing user presence.
- Let an agent export a private key, PIN, cookie, token, raw assertion, or arbitrary signing result through a Passless API.
- Let an agent register a credential in delegated-session mode.
- Make a delegated session independently revocable at the RP when the RP exposes no revocation API.
- Make the RP distinguish the agent from the human in delegated-session mode.
- Restrict business actions performed after login.
- Guarantee that local lease expiry invalidates copied or independently retained RP session material.
- Protect against host root, kernel compromise, or a malicious Passless administrator.
- Distinguish subprocesses, tools, plugins, or subagents inside one principal.
- Support remote principals or non-Unix isolation in the first implementation.

## Normative security invariants

The implementation must maintain all of the following:

1. Agent support is disabled unless an administrator configures and enables a profile.
2. Human and agent browser requests reach distinct UHID endpoints.
3. An endpoint is bound to one authenticated profile and mode for its lifetime.
4. The agent boundary cannot open the human UHID node, human storage paths, administrative socket, audit files, personal browser profiles, or another agent's resources.
5. The human browser cannot open an agent UHID node.
6. Configuration never acts as a per-request classifier on a shared indistinguishable transport.
7. The browser, not Passless, enforces web origin and RP ID validity.
8. Passless independently matches the exact CTAP RP ID to current policy and the active intent or grant.
9. Isolated credentials use separate roots and enumeration paths.
10. Delegated storage access is a read-only filtered view containing only the exact granted credential.
11. Delegated mode rejects registration, deletion, enumeration, credential management, and any non-authentication operation.
12. A delegated grant can authorize at most one successful assertion and is consumed on success, denial, timeout, cancellation, mismatch, or failure.
13. An isolated intent can authorize at most one ceremony and is consumed on every terminal result.
14. Policy is re-evaluated when an intent or grant is created, when a CTAP request is bound, and immediately before key use.
15. UP is set if and only if a fresh human gesture authorizes that exact authenticator operation.
16. UV is set if and only if Passless performs actual local user verification for that operation.
17. A policy, capability, authorization window, launcher identity, or prior gesture is never converted into UP or UV.
18. Private keys remain in Passless and are never copied into browser profiles or principal-accessible storage.
19. Human and delegated access to one credential serialize state changes, including signature counters.
20. Browser leases use monotonic expiry, cannot be extended by the principal, and terminate on principal exit, revocation, or isolation failure.
21. Browser profile cleanup is attempted on every terminal path; failure is visible to the administrator and blocks profile reuse.
22. No secret appears in CLI output, logs, errors, audit records, process arguments, or ordinary environment variables.
23. No credential creation or use occurs without a durable pre-execution audit reservation.
24. Cancellation, timeout, policy change, revocation, daemon restart, and degraded security controls fail closed for the agent path.
25. Agent-path failure does not alter or weaken human authenticator behavior.

## Threat model

| Threat | Required mitigation | Residual risk |
|---|---|---|
| Prompt injection requests another RP | Exact RP policy and grant matching; trusted prompt | Passless cannot independently display the exact browser origin |
| Another local browser consumes a grant | Agent-specific UHID node visible only inside one principal boundary | Kernel or device-policy failure compromises routing |
| Agent selects another user credential | Exact credential filter over delegated storage | RP account labels may still be misleading |
| Agent requests another assertion during a browser lease | Grant consumed and temporary delegated route removed after one CTAP exchange | A still-valid RP session retains its ordinary authority |
| Agent accesses personal credentials | Device isolation, filtered storage view, no storage path access | Host root remains trusted |
| Human and agent race a credential counter | One daemon-owned store and serialized credential mutation | RP counter policy varies |
| Agent extends its lease | Daemon-owned monotonic deadline and kill-on-expiry | Copied RP session material may outlive local cleanup |
| Agent extracts session state | Daemon-owned profile, restricted browser-control channel, sandbox and egress controls where configured | Browser automation authority may expose session data; local TTL is not cryptographic revocation |
| Agent modifies policy | Administrative channel absent from principal boundary | A malicious administrator remains trusted |
| Audit storage fails | Durable pre-write and fail-closed degraded state | Host root can rewrite local audit without external anchoring |
| Agent acts beyond the login purpose | Short lease, isolated profile, optional network controls, explicit warning | Passless cannot authorize RP business actions |

### Accepted delegated-session confused-deputy risk

Delegated-session mode authorizes authentication but gives the principal the full authority of the browser session returned by the RP. The agent can perform destructive or sensitive RP actions that were not shown in the Passless prompt. A short lease limits duration, not action scope. The initial release accepts this residual risk only with an explicit approval warning, an ephemeral profile, immediate local revocation, and guidance to use a low-privilege account or an RP-supported scoped credential where available.

## Autonomous access

Passless will not set UP based on prior delegation, agent identity, policy, a capability, or an authorization window. It will not set UV based on cached administrative approval or software-principal authentication.

For unattended access, users should prefer an RP-supported mechanism that can express actor, audience, scope, lifetime, and revocation, including:

- Scoped OAuth or OpenID Connect authorization.
- OAuth token exchange with subject and actor identity.
- Sender-constrained tokens using DPoP or mutual TLS.
- Application installations such as GitHub Apps.
- Service accounts and narrowly scoped API credentials.
- Workload identity for operator-controlled services.

A future autonomous feature requires a separate ADR and explicit RP support. It cannot silently reuse WebAuthn UP or UV.

## Configuration semantics

Configuration selects durable limits and real isolation boundaries. It does not pre-approve a ceremony.

Illustrative configuration:

```toml
[agents]
enabled = true
audit_path = "/var/lib/passless-agent/audit/events.jsonl"

[agents.profiles.opencode]
mode = "delegated-session"
principal_user = "passless-opencode"
rp_ids = ["github.com"]
credential_refs = ["9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"]
max_grant_ttl = 120
max_session_ttl = 900
browser_command = ["firefox", "--kiosk"]
start_url = "https://github.com/dashboard"
browser_user = "passless-browser-opencode"
browser_runtime_root = "/var/run/passless-browser/opencode"
require_uv = true

[agents.profiles.opencode.device]
name = "passless-agent-opencode"
phys = "opencode-phys"
uniq = "opencode-uniq"
vendor_id = 4660
product_id = 22136

[agents.profiles.release-bot]
mode = "isolated"
principal_user = "passless-release"
rp_ids = ["github.com"]
registration_allowed = true
require_uv = true

[agents.profiles.release-bot.storage.local]
path = "/var/lib/passless-agent/release-bot/credentials"
pin_path = "/var/lib/passless-agent/release-bot/pin"

[agents.profiles.release-bot.device]
name = "passless-agent-release"
phys = "release-phys"
uniq = "release-uniq"
vendor_id = 4660
product_id = 22137
```

Credential references are non-secret hex SHA-256 digests over credential IDs. TTLs are integer seconds. Unknown fields and invalid modes are rejected at load time. See [configuration reference](../agents/configuration.md) for complete field definitions.

## Honest security claims

Documentation and user interfaces must state:

- Delegated-session mode lets the agent act as the user within the RP browser session.
- The RP cannot distinguish that delegated browser use from ordinary use by the user.
- RP ID restriction applies to the WebAuthn assertion; it does not express business-action scope.
- Passless trusts the stock browser for origin validation and cannot independently report the exact origin from CTAP.
- Local browser-lease expiry is not RP-side session revocation.
- A principal includes all processes inside its isolation boundary.
- Local protected audit does not protect against host root without external anchoring.
- RP-supported agent credentials are preferable for unattended or narrowly scoped automation.

## Consequences

### Positive

- No browser modification or browser-specific proxy is required.
- Existing browser origin enforcement and existing Passless CTAP behavior are reused.
- Users can choose independent agent credentials or temporary reuse of an existing login.
- Delegated use does not export the user's passkey and permits only one approved assertion per grant.
- UP and UV retain their standardized meanings.
- Configuration exposes the security tradeoff instead of hiding it behind one ambiguous mode.

### Negative

- Strong routing depends on Linux device and process isolation.
- Delegated-session mode is not independently identifiable or revocable at the RP.
- The authenticator sees RP ID but not exact origin.
- Browser-session authority is broader than the initial login operation.
- Supporting multiple UHID endpoints and filtered access to one store requires daemon refactoring.
- Secure browser automation and reliable profile cleanup add operational complexity.

## Alternatives considered

### One shared UHID endpoint with a temporary global mode switch

Rejected. CTAP does not identify the calling process. A human browser or another local process could race and consume the temporary authorization.

### Automatically approve WebAuthn during the delegation window

Rejected. A delegation window is policy authority, not ceremony-specific user presence or verification.

### Give the agent a copy of the user credential

Rejected. It exports or duplicates a high-value credential, breaks coordinated state, and removes meaningful custody boundaries.

### Require separate credentials only

Not selected as the only mode. It provides the strongest revocation boundary but excludes RPs or deployments where the user explicitly prefers a short, interactive reuse of existing access.

### Browser proxy, extension, or patched browser

Rejected for this design. Stock browser WebAuthn and UHID provide the required RP validation without adding a browser integration TCB.

## Rollout

Agent support is opt-in and disabled by default. The rollout follows the phased approach in the [implementation plan](../plans/agent-passkey-implementation.md):

1. Ship agent support behind an opt-in compile or experimental runtime feature.
2. Keep `[agents].enabled = false` by default.
3. Require explicit administrator creation of every profile and exact RP policy.
4. Refuse profile startup if any mandatory device, principal, storage, prompt, audit, or cleanup control is unavailable.
5. Leave human startup independent from agent-component failure.
6. Support only documented kernel, distribution, browser, and backend combinations.
7. Remove the experimental label only after at least one stable release without a boundary-breaking issue.

Phase 0 feasibility evidence must pass before runtime implementation begins. Phase 9 system validation and independent security review must pass before production release. See the [implementation plan](../plans/agent-passkey-implementation.md) for complete phase gates and exit criteria.

## Rollback

Agent mode can be disabled without affecting human credentials or configuration:

1. Disable every profile: `passless agent-admin profile disable <profile>`.
2. Revoke all active sessions and delegations.
3. Terminate managed browsers and quarantine profiles that fail cleanup.
4. Set `enabled = false` in configuration or stop the daemon.
5. Revoke isolated credentials locally and instruct operators to remove them at each RP.
6. For delegated mode, instruct users to revoke RP sessions through RP controls when compromise or session copying is suspected.
7. Preserve non-secret metadata and audit for investigation.

Human credentials, configuration, and the human UHID endpoint remain untouched. See [operations: rollback](../agents/operations.md#rollback) for detailed steps.

## References

- W3C Web Authentication Level 3: https://www.w3.org/TR/webauthn-3/
- FIDO Client to Authenticator Protocol 2.2: https://fidoalliance.org/specs/fido-v2.2-rd-20241003/fido-client-to-authenticator-protocol-v2.2-rd-20241003.html
- OAuth 2.0 Token Exchange, RFC 8693: https://www.rfc-editor.org/rfc/rfc8693
- OAuth 2.0 Demonstrating Proof of Possession, RFC 9449: https://www.rfc-editor.org/rfc/rfc9449
- OAuth 2.0 Security Best Current Practice, RFC 9700: https://www.rfc-editor.org/rfc/rfc9700
