# ADR 0007: Unified Same-User and Isolated Agent Identity Modes

- **Status:** Proposed
- **Date:** 2026-08-06
- **Decision owners:** Passless maintainers
- **Implementation status:** Not started
- **Implementation plan:** [ADR 0007 implementation plan](../plans/adr-0007-agent-mode-redesign-implementation.md)
- **Verification matrix:** [ADR 0007 verification matrix](../plans/adr-0007-verification-matrix.md)
- **Related decisions:** [ADR 0001](0001-agent-authentication-security-model.md), [ADR 0002](0002-native-webauthn-agent-architecture.md), [ADR 0003](0003-portable-tpm-credential-keys.md), [ADR 0005](0005-delegated-autonomous-authentication-redesign.md), [ADR 0006](0006-agent-passkey-registration.md)
- **Supersedes:** the credential-ownership, delegated-session, grant-consumption, and agent-evidence portions of ADRs 0001, 0005, and 0006 where they conflict with this decision
- **Retains:** the daemon-backed browser extension transport selected by ADR 0005 and the autonomous registration capability selected by ADR 0006

## Context

Passless needs to support two materially different agent use cases without pretending that they provide the same security boundary.

The first use case is the convenient one: an operator runs a trusted coding or browser agent as the same local user and wants it to authenticate as that user with the user's existing passkeys. The operator does not want a separate RP account, a second set of passkeys, or a human prompt for every WebAuthn ceremony. When explicitly configured for full autonomy, Passless should authorize every matching request, including requests that require user presence or user verification, while retaining short-lived authority, exact RP policy, daemon-side signing, and complete audit.

The second use case is a stronger isolation boundary: an agent receives its own passkeys, storage namespace, key provider, browser state, and revocation lifecycle. Compromise of that agent should not directly expose or exercise the human credential namespace. This mode may also be autonomous, but the identity presented to the RP is an agent identity rather than the human's existing passkey identity.

The current implementation does not provide a coherent version of both use cases:

- `AgentMode` currently exposes only `isolated`.
- The browser extension and `/sign` and `/register` endpoints exist, but production runtime wiring gives those handlers the profile credential store and a software key provider rather than a mode-selected credential backend.
- The daemon receives the human storage, PIN storage, and operation lock, but the agent runtime does not use them.
- The sign path can set the UV bit merely because the RP requested UV or the rule mentioned UV, without first resolving a concrete verification source.
- Session grants are reusable until expiry, while the documentation describes one-shot ceremony authority.
- Registration and authentication duplicate part of the authenticator behavior and do not consistently negotiate algorithms, enforce credential protection, or use the configured key provider.
- Origin, top-origin, cross-origin, abort, timeout, and browser-object compatibility behavior is incomplete.

Restoring the old UHID-based `delegated-session` implementation is not the answer. It reintroduces Chromium's native credential modal, duplicates the agent and human ceremony stacks, and cannot provide a reliable headless path. Sharing the human storage path with an isolated profile is also not the answer: it creates multiple storage objects and locks for the same namespace, makes counter and provider behavior unsafe, and obscures the intended trust boundary.

The design must instead make credential ownership an explicit mode while keeping one operation pipeline.

## Decision summary

Passless will provide two agent identity modes:

| Mode | RP identity | Credential backend | Trust statement |
|---|---|---|---|
| `same-user` | The user's existing passkeys and RP accounts | The daemon's existing human credential backend | The configured agent is fully trusted to act as the user within its RP policy |
| `isolated` | Separate agent passkeys and RP accounts | A profile-specific credential backend | The agent cannot use or enumerate the human credential namespace |

Both modes use the same daemon-backed browser extension, session capability, operation state machine, policy engine, evidence providers, signing and registration service, and audit pipeline.

Autonomy is not a credential mode. It is an operation policy. Either identity mode may be autonomous, supervised, mixed by RP and action, or denied.

## 1. Identity modes

### 1.1 `same-user`

A `same-user` profile uses the already-constructed human `CredentialBackendHandle`. It does not configure or reopen a storage path. The handle contains the exact storage, key provider, PIN or local-verification service, operation lock, counter behavior, and backend metadata used by the ordinary human authenticator.

This mode intentionally means that the agent is trusted as the same authenticator user. A malicious or compromised agent with an active, sufficiently broad profile can authenticate as the human to every RP allowed by that profile. Exact RP rules, short session TTLs, credential selectors, operation binding, and audit limit accidents and authority duration; they do not turn a fully trusted same-user agent into an isolated principal.

The private key remains in the configured backend and signatures remain daemon-mediated. For a portable TPM backend, the agent can exercise the key through the daemon but cannot export it. For an extractable software backend running under the same Unix identity, daemon exclusivity is an architectural and audit property rather than a hard boundary against that Unix user. The mode does not claim otherwise.

A same-user profile:

- has no profile storage path or profile PIN namespace;
- may use existing human credentials matching an exact RP rule;
- may optionally narrow access to explicit credential references;
- may autonomously authenticate with existing credentials;
- may autonomously register new credentials into the human backend when registration is explicitly allowed;
- shares the human operation lock and signature counter state;
- never receives raw keys, PINs, storage handles, or arbitrary-signing access.

### 1.2 `isolated`

An `isolated` profile uses a profile-specific `CredentialBackendHandle` containing separate credential storage, key provider, PIN or verification state, operation lock, and backend metadata.

An isolated profile:

- cannot enumerate, select, register into, or sign with the human backend;
- cannot share a storage or PIN path with the human backend or another profile;
- presents separate credentials to the RP;
- can be revoked at the RP without revoking human credentials;
- can independently choose software or portable-TPM key protection when supported;
- may use the same autonomous or supervised evidence policies as same-user mode.

The existing isolated UHID route may remain as a compatibility transport for non-extension clients, but it is not a second policy or signing implementation. It must delegate to the same backend, operation, evidence, and audit services as the extension path.

## 2. One backend abstraction

Runtime code will construct a `CredentialBackendHandle` for every credential namespace:

```rust
pub struct CredentialBackendHandle {
    pub namespace: CredentialNamespace,
    pub storage: Arc<dyn CredentialStorage>,
    pub key_provider: Arc<dyn CredentialKeyProvider>,
    pub verification: Arc<dyn LocalVerificationProvider>,
    pub operation_lock: Arc<tokio::sync::Mutex<()>>,
    pub capabilities: BackendCapabilities,
}

pub enum CredentialNamespace {
    Human,
    Isolated(ProfileId),
}
```

The precise trait names may follow existing code, but the architectural invariant is normative: storage, key provider, verification state, and operation lock are selected together and cannot be independently substituted by an agent handler.

`same-user` receives a clone of the human backend handle. `isolated` receives a handle created by the agent storage factory. The sign and register services accept only a backend handle selected by the runtime. They must not open paths, infer providers, or hardcode the software provider.

This design makes software, pass-backed, legacy TPM, and portable TPM behavior follow the same provider selection as the human path. It also prevents two independently locked storage objects from updating one credential namespace.

## 3. Session authority and one-shot operations

An agent task runs inside a short-lived `AgentSession`. The session is the reusable authority envelope for one browser or agent task; it is not itself a WebAuthn operation authorization.

A session is bound to at least:

- profile ID and identity mode;
- authenticated local principal and launcher instance;
- browser runtime and extension instance;
- policy generation;
- creation and expiry times;
- maximum operation count;
- optional RP narrowing supplied at launch;
- a random, high-entropy capability known to the extension worker and daemon.

Recommended defaults are a ten-minute TTL and sixteen operations. Deployments may reduce those values. The daemon enforces a hard configured maximum TTL and operation count.

Every intercepted `navigator.credentials.get()` or `create()` call creates a separate one-shot `OperationIntent`. The operation is bound to:

- session ID;
- action (`authenticate` or `register`);
- exact RP ID;
- caller origin, top origin, and cross-origin state;
- a canonical hash of the public-key options and challenge;
- selected credential reference or registration target;
- matched rule and policy generation;
- requested and resolved UP/UV evidence;
- a unique operation nonce.

The normative operation lifecycle is:

```text
Pending -> Authorized -> AuditReserved -> Executing -> Succeeded | Failed -> Consumed
```

Terminal success and failure both consume the operation. Replaying a nonce, request hash, or completed operation fails. A session may authorize a later operation only by creating a new intent and re-evaluating current policy.

Policy reload, session revocation, browser shutdown, principal death, TTL expiry, or operation-count exhaustion invalidates further operations. In-flight operations fail closed when their policy generation or session validity changes before key use.

This preserves the convenience of a short agent task while making every WebAuthn request independently bound, audited, and replay-resistant.

## 4. Authorization and evidence are independent

Each exact RP rule defines `authenticate` and `register` independently. The canonical policy model is:

```text
authorization: deny | confirm | allow
user_presence: agent | human | none
user_verification: agent | human | none
```

The meanings are:

- `authorization = deny`: reject before credential enumeration or key access.
- `authorization = confirm`: require a fresh trusted human approval bound to the operation intent.
- `authorization = allow`: authorize automatically from the current administrator-owned rule.
- `user_presence = agent`: prove that the active, bound agent session initiated this operation and set UP from that agent evidence.
- `user_presence = human`: forward the operation to the human interaction path and set UP only after its bound presence result.
- `user_presence = none`: do not set UP; fail if the operation cannot validly proceed without it.
- `user_verification = agent`: verify the bound agent session as the authenticator user and set UV from that agent evidence.
- `user_verification = human`: invoke the normal human PIN, biometric, or platform-verification path and set UV only after it succeeds.
- `user_verification = none`: do not set UV; fail when the RP, credential policy, or authenticator configuration requires UV.

`agent` is the canonical name for the existing policy-derived evidence concept. A temporary compatibility alias `policy` may be accepted during migration, but audit records and new documentation use `agent`.

### 4.1 Autonomous operation

A fully autonomous action uses:

```text
authorization = allow
user_presence = agent
user_verification = agent
```

This combination is valid in both identity modes and is capable of satisfying RP requests for required UP and UV without involving a human. It does not blindly set flags because the RP requested them. The daemon must first validate the active session capability, principal binding, policy generation, exact rule, operation nonce, audit reservation, and credential scope. That successful authenticator-local agent verification is the evidence source.

This is an explicit trust choice. The RP receives ordinary WebAuthn UP and UV bits and cannot distinguish agent-session verification from human PIN or biometric verification. Audit must distinguish them. Operators enabling this policy accept that the agent is treated as the authenticator user and that RP-required UV no longer implies ceremony-time human participation.

The WebAuthn requirement that UV be set only after authenticator-local user verification still applies. Merely matching an `allow` rule or seeing `userVerification = "required"` is insufficient. An expired, unbound, replayed, or otherwise invalid agent session must not produce UV.

### 4.2 Human-forwarded operation

Human interaction remains available by configuration. Examples include:

- automatic authorization with human UV: `allow + agent presence + human verification`;
- human approval but agent verification: `confirm + human presence + agent verification`;
- fully human ceremony evidence: `confirm + human presence + human verification`.

The human PIN or biometric result is handled inside the daemon's normal verification boundary. PIN values and verification secrets are never returned to the extension, browser page, agent process, audit log, or environment.

A successful human interaction is bound to one operation intent and cannot be reused by a later operation unless a separate future ADR explicitly introduces a bounded human-verification cache.

### 4.3 RP preference handling

For `userVerification`:

- `required`: the configured `agent` or `human` provider must succeed; `none` fails.
- `preferred`: Passless applies the configured provider. `agent` verifies and sets UV. `human` follows the profile's human-prompt preference; by default it prompts and sets UV, while an optional `when-required` setting may omit UV without prompting.
- `discouraged`: `agent` may still set UV when configured; `human` does not prompt unless explicitly configured `always`; `none` omits UV.

Credential-level requirements such as `credProtect` are evaluated in addition to the RP request. A credential that requires UV cannot be used with `user_verification = none`. `agent` satisfies that requirement only after valid agent-session verification; `human` satisfies it only after human verification.

For UP, the resolved evidence provider must produce a successful result whenever the selected authenticator behavior requires UP. The flags are derived exclusively from resolved evidence, never directly from request preferences.

## 5. Policy syntax and ergonomic presets

The normalized table form remains available:

```toml
[[agents.profiles.opencode.rules]]
rp_id = "github.com"
credential_selection = "single"
authenticate = {
  authorization = "allow",
  user_presence = "agent",
  user_verification = "agent"
}
register = {
  authorization = "deny",
  user_presence = "none",
  user_verification = "none"
}
```

For the common cases, the parser may expose exact aliases that normalize before validation:

| Alias | Normalized policy |
|---|---|
| `"deny"` | `deny + none + none` |
| `"autonomous"` | `allow + agent + agent` |
| `"supervised"` | `confirm + human + human` |

Example easy same-user configuration:

```toml
[agents]
enabled = true
audit_path = "/var/lib/passless/agent-audit.jsonl"

[agents.profiles.opencode]
mode = "same-user"
principal_user = "alice"
session_ttl = "10m"
max_operations = 16

[[agents.profiles.opencode.rules]]
rp_id = "github.com"
authenticate = "autonomous"
register = "deny"
credential_selection = "single"
```

Example isolated autonomous configuration:

```toml
[agents.profiles.release-bot]
mode = "isolated"
principal_user = "passless-release"
session_ttl = "5m"
max_operations = 8

[agents.profiles.release-bot.storage.local]
path = "/var/lib/passless-agent/release-bot/credentials"
pin_path = "/var/lib/passless-agent/release-bot/pin"

[[agents.profiles.release-bot.rules]]
rp_id = "gitea.example.com"
authenticate = "autonomous"
register = "autonomous"
credential_selection = "single"
```

Example same-user authentication with human UV:

```toml
[[agents.profiles.finance-assistant.rules]]
rp_id = "bank.example"
authenticate = {
  authorization = "allow",
  user_presence = "agent",
  user_verification = "human"
}
register = "deny"
```

Configuration validation is fail-closed:

- `same-user` rejects profile storage and profile PIN paths.
- `isolated` requires a complete non-overlapping profile backend.
- missing modes, rules, actions, evidence, audit, or selectors deny or fail startup as appropriate;
- `deny` cannot assert evidence;
- unsupported combinations fail configuration rather than silently degrading;
- agent support remains disabled by default.

## 6. Credential discovery and selection

Same-user mode should not require duplicating every human credential reference in configuration. For an exact RP rule, the daemon may consider credentials in the selected backend whose RP ID matches the request and whose IDs satisfy `allowCredentials` when present.

The page and agent never receive an unrestricted credential listing. Discovery and selection happen inside the daemon.

Selection is deterministic:

1. If `allowCredentials` is non-empty, choose the first RP-provided credential ID that exists in the allowed backend scope and satisfies configured credential restrictions.
2. If the rule names an exact credential reference, use only that credential.
3. If discoverable authentication yields exactly one permitted credential, use it.
4. If multiple credentials remain, apply the explicit `credential_selection` rule.
5. Without an explicit ambiguity policy, fail with a credential-selection error rather than selecting an arbitrary human account.

Supported ambiguity policies are:

- `single`: require exactly one candidate; this is the safe default;
- `first-matching`: choose a stable order defined by credential ID, only when the operator explicitly accepts that behavior;
- `newest`: choose the most recently created permitted credential;
- `credential:<ref>`: select one exact configured credential.

This allows a fully autonomous configuration to handle multi-account discoverable flows while ensuring that such selection is deliberate.

## 7. Authentication and registration service

The extension transport calls one daemon `WebAuthnOperationService` with separate authentication and registration methods. The service is responsible for the common pipeline:

1. authenticate the session capability;
2. create and bind the one-shot operation intent;
3. derive and validate origin, top origin, cross-origin state, and exact RP ID;
4. re-evaluate the current exact RP/action rule;
5. resolve the mode-selected backend and credential scope;
6. resolve authorization and UP/UV evidence providers;
7. enforce RP options, credential protection, backend capabilities, and algorithm support;
8. reserve durable audit before credential creation or use;
9. acquire the backend operation lock;
10. perform key generation or signing through the backend key provider;
11. update storage and counters atomically where possible;
12. finalize the audit result and consume the operation intent;
13. return a structured WebAuthn response or a specific DOM-compatible error.

Authentication must honor `allowCredentials`, discoverable credentials, user handles, signature counters, `credProtect`, supported extensions, and the backend's actual key provider.

Registration must honor `pubKeyCredParams` in RP preference order, `excludeCredentials`, resident-key requirements, user-verification requirements, authenticator-selection constraints that Passless can represent, supported extensions, and attestation capability. It must not hardcode ES256 or claim unsupported attestation. Unsupported requirements return `NotSupportedError` before storage mutation.

Registration targets the selected mode's backend. `same-user` writes to the human backend; `isolated` writes to the profile backend. Registration remains denied unless the exact RP rule explicitly allows it.

## 8. Browser extension contract

The daemon-backed MV3 extension remains the primary browser integration for both identity modes.

The extension must:

- intercept both `navigator.credentials.get()` and `create()` at `document_start`;
- preserve non-public-key credential calls by delegating to the original API;
- obtain caller origin from trusted extension sender metadata and cross-check it with the MAIN-world report;
- capture or derive top origin and cross-origin state;
- enforce the WebAuthn RP-ID relationship and supported iframe policy rather than equating origin host with RP ID;
- keep the daemon bearer outside the MAIN world and page JavaScript;
- serialize all relevant WebAuthn options without lossy conversions;
- honor `AbortSignal`, RP timeout, extension timeout, and browser shutdown;
- return appropriate DOMException names and messages;
- expose the expected credential response methods and JSON serialization;
- never fall back to native WebAuthn after an operation has been authorized by the agent path unless policy explicitly selects a supervised native path.

Top-level frames are the minimum shipping requirement. Cross-origin iframe support ships only after origin, top-origin, Permissions Policy, and ancestor validation tests pass. Until then, cross-origin requests fail closed.

A `chrome.webAuthenticationProxy` adapter may be added for RPs that require native `PublicKeyCredential` identity. It must use the same daemon operation service and must not weaken origin binding to solve request correlation.

## 9. Audit model

Audit is mandatory for agent credential operations. Failure to reserve or finalize the required audit record fails the operation.

Each record includes at least:

- session and operation identifiers or non-reversible hashes;
- profile, identity mode, principal, and policy generation;
- action, exact RP ID, origin, top origin, and cross-origin state;
- credential namespace and credential reference when known;
- authorization source;
- requested UP/UV and resolved UP/UV source (`agent`, `human`, or absent);
- credential-selection rule;
- backend and key-provider type without secret material;
- audit reservation, start, terminal result, and failure class;
- signature counter before and after successful authentication when applicable.

Audit must make same-user autonomous use unmistakable. A record that contains UV from agent-session verification must never be labeled or rendered as human PIN or biometric verification.

## 10. Security invariants

1. Agent support is disabled by default.
2. Every profile has exactly one identity mode.
3. Same-user mode uses the existing human backend handle; it never reopens the human storage path.
4. Isolated mode cannot obtain the human backend handle.
5. Storage, key provider, verification provider, and operation lock are selected as one backend unit.
6. The extension, page, and agent never receive private keys, PINs, backend handles, or arbitrary signing APIs.
7. Every operation matches one current exact RP/action rule before credential discovery and again before key use.
8. Every operation is bound to one active session, request hash, challenge, origin context, action, and policy generation.
9. Every operation is one-shot and consumed on all terminal results.
10. Session reuse never implies operation reuse.
11. UP and UV flags derive only from successful evidence-provider results.
12. RP-requested UV alone never sets UV.
13. Agent UV requires a valid bound agent-session verification result.
14. Human UV requires the production human verification path.
15. Credential protection and backend requirements may strengthen, but never weaken, the configured evidence requirement.
16. Every credential creation or use has a durable pre-execution audit reservation.
17. Signature counters and credential updates use the selected backend's shared operation lock.
18. Policy reload, revocation, expiry, principal death, and browser shutdown invalidate outstanding authority.
19. Same-user registration writes only to the human backend and only under an explicit exact-RP registration rule.
20. Isolated registration writes only to its profile backend.
21. Origin and RP validation follow WebAuthn rules; explicit ports are not rejected merely for being present in a valid origin.
22. Unsupported algorithms, attestation, extensions, iframe contexts, or authenticator-selection requirements fail closed.
23. Agent failure cannot disable or weaken the ordinary human authenticator path.

## 11. Threat model and residual risk

| Threat | Mitigation | Residual risk |
|---|---|---|
| Compromised same-user agent authenticates as the human | Explicit mode opt-in, exact RP rules, short sessions, operation limits, credential selectors, audit | This is fundamentally allowed by the mode; the agent is trusted as the user |
| Isolated agent reaches human credentials | Separate backend handle, no path sharing, runtime type and validation boundaries | Host root or daemon compromise remains trusted |
| Page replays an assertion request | One-shot nonce, request hash, atomic consumption, session and policy binding | A new valid request may still be authorized by an autonomous rule |
| Local process calls loopback endpoints | High-entropy session capability, short TTL, profile binding, origin/RP/policy validation, operation replay protection | Same-user local compromise is inside the same-user trust boundary |
| RP requests UV and daemon fabricates it | Evidence-provider result required before setting UV | RP cannot distinguish agent verification from human verification |
| Wrong credential selected for a multi-account RP | Safe `single` default and explicit deterministic selection policies | `first-matching` is intentionally less account-specific |
| Counter races corrupt human credentials | Shared backend handle and operation lock | Backend-specific crash consistency remains |
| Extension reports a false origin | Cross-check trusted sender metadata, validate top origin and RP relationship, fail closed on unsupported frames | Browser or extension compromise is in the trusted computing base |
| Autonomous registration creates unwanted passkeys | Separate registration rule, exact RP, session limits, exclude checks, audit | Broad same-user registration policy intentionally grants broad power |
| Human PIN leaks to agent | Verification occurs inside daemon UI/provider and returns only evidence result | Compromised daemon or host remains trusted |

## 12. Consequences

### Positive

- The convenient configuration actually uses the user's existing passkeys without duplicating storage.
- The stronger configuration retains a genuine credential-ownership boundary.
- Both modes share one implementation, reducing semantic drift and duplicated security bugs.
- Full autonomy can satisfy required UP and UV through explicit agent-session verification.
- Human approval and human UV remain available per RP and action.
- Software and TPM providers are selected correctly through the same backend abstraction.
- Short-lived sessions remain ergonomic while each WebAuthn operation becomes one-shot and replay-resistant.
- Audit accurately distinguishes agent, human, and absent evidence.

### Negative

- Same-user autonomous mode deliberately removes ceremony-time human assurance for allowed RPs.
- The RP cannot tell whether UV came from agent-session or human verification.
- The backend abstraction, evidence providers, and operation state machine require substantial refactoring.
- Correct browser-origin and WebAuthn compatibility behavior adds extension complexity.
- Supporting autonomous registration into the human backend increases the impact of a broad rule.

### Neutral

- Isolated mode remains the recommended mode when the agent should not be equivalent to the human.
- Workload identities, service accounts, scoped OAuth, and RP-native automation credentials remain preferable when available.
- The daemon remains a signer and audit mediator, but same-user mode does not claim to defend the human account from the explicitly trusted agent.

## 13. Alternatives considered

### Restore the old `delegated-session` UHID path

Rejected. Chromium's native modal prevents reliable headless use, the approach duplicates ceremony behavior, and it does not solve provider and storage wiring.

### Point an isolated profile at the human storage path

Rejected. It creates ambiguous ownership, duplicate locks and providers, unsafe counter behavior, and no honest isolation boundary.

### Export human keys into a browser virtual authenticator

Rejected for production. It bypasses daemon policy and audit, leaks keys into the browser process, and cannot support non-extractable TPM keys.

### Require one human verification per agent session

Rejected as the only autonomous model. It is a useful optional policy but does not satisfy the requirement for completely autonomous operation. Human verification remains selectable per action.

### Always claim UV whenever an RP requests it

Rejected. Flags must be based on a resolved evidence provider. Fully autonomous mode uses agent-session verification, not an unchecked request bit.

### Make same-user and isolated separate implementations

Rejected. Identity ownership changes backend selection, not the correctness requirements for origin validation, policy, evidence, audit, registration, signing, and replay protection.

### Give the agent direct storage or key-provider access

Rejected. Even for a fully trusted same-user profile, daemon mediation provides consistent provider support, counter serialization, policy enforcement, revocation, and audit while avoiding a general-purpose signing interface.

## 14. Rollout decision

Implementation ships behind an experimental feature gate until all mandatory verification rows pass. The rollout order is:

1. backend abstraction and one-shot operation model;
2. isolated mode through the unified service, preserving current behavior;
3. same-user authentication with software backend;
4. agent and human evidence providers, including required UV and `credProtect`;
5. same-user registration;
6. portable-TPM coverage for both modes;
7. browser compatibility and approved iframe support;
8. removal or deprecation of contradictory delegated-session documentation and code.

No phase may enable same-user mode by default. The operator must explicitly configure the mode and exact RP rules.

## References

- W3C Web Authentication Level 3: <https://www.w3.org/TR/webauthn-3/>
- Chrome `webAuthenticationProxy` API: <https://developer.chrome.com/docs/extensions/reference/api/webAuthenticationProxy>
- [ADR 0007 implementation plan](../plans/adr-0007-agent-mode-redesign-implementation.md)
- [ADR 0007 verification matrix](../plans/adr-0007-verification-matrix.md)
