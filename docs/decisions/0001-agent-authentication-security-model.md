# ADR 0001: Agent authentication security model and v1 scope

- **Status:** Accepted
- **Date:** 2026-07-13
- **Decision owners:** Passless maintainers
- **Implementation status:** Not implemented
- **Related decisions:** [ADR 0002](0002-managed-browser-interactive-passkeys.md), [ADR 0003](0003-autonomous-agent-authentication.md)
- **Implementation plan:** [Agent passkey implementation plan](../plans/agent-passkey-implementation.md)
- **Supersedes:** the earlier configurable agent passkey modes proposal in this pull request and the agent workflow proposed in pull request #308

## Context

Passless is an interactive software FIDO2 authenticator exposed through UHID. A browser validates the web origin and relying-party relationship, and Passless asks the human user for user presence or user verification before using a credential.

Agents introduce two distinct requirements:

1. An agent may initiate a browser login and wait for the human to authorize the WebAuthn ceremony.
2. An agent may need unattended access to a service.

These requirements are not equivalent. WebAuthn authenticates possession of an RP-scoped credential and reports ceremony-time user presence and verification. It does not express an agent's identity, delegated business authority, or limits on actions performed after login.

WebAuthn Level 3 requires the UP flag to be set if and only if the authenticator performed a test of user presence. It requires the UV flag to be set if and only if the authenticator performed user verification. Prior administrative delegation is neither a ceremony-specific presence test nor user verification.

No standardized WebAuthn or CTAP flag identifies an autonomous agent or communicates delegated machine presence to the relying party. A distinct AAGUID identifies an authenticator model; it does not prove the authorization context of an individual assertion.

## Decision

Passless will support a standards-compliant **interactive agent passkey path** in v1.

Every v1 agent registration and authentication ceremony requires a fresh human authorization gesture for that exact browser request. Passless sets UP only after that gesture. Passless sets UV only after actual local user verification.

Passless will not implement autonomous WebAuthn by setting UP without a ceremony-specific presence test. Autonomous authentication is addressed separately by [ADR 0003](0003-autonomous-agent-authentication.md).

The v1 agent path uses:

- A managed browser profile dedicated to one authenticated principal.
- A browser WebAuthn proxy that is attached before navigation.
- A trusted launcher and enforced OS isolation boundary.
- A transport structurally separate from the human UHID authenticator.
- A machine credential store structurally separate from human credentials.
- Exact origin, RP ID, action, browser request, and credential binding.
- A short-lived one-shot intent for every ceremony.
- A protected audit channel outside the agent sandbox.

The existing human browser, UHID transport, credential store, and behavior remain unchanged.

## Security objective

Interactive agent mode must preserve the ceremony-level security semantics of the existing Passless human flow while preventing the agent from gaining access to personal credentials.

This means:

- Private keys remain inside Passless.
- WebAuthn origin and RP scoping remain enforced.
- A human authorizes every credential creation and use.
- UP and UV remain truthful.
- Agent and human credentials cannot cross paths.
- Failure in the agent path cannot fall back to the human authenticator.

The agent architecture has a larger trusted computing base than the current UHID path. Security equivalence is therefore conditional on the browser proxy, native host, launcher, sandbox, protocol, storage isolation, and audit controls passing the gates in ADR 0002 and the implementation plan.

## Goals

The design must:

- Preserve the existing human Passless flow without behavioral changes.
- Let an agent initiate registration and authentication while requiring a human gesture for every ceremony.
- Keep human and machine credentials isolated and independently revocable.
- Prevent failed agent flows from reaching a personal authenticator or credential.
- Bind every agent operation to an authenticated principal, exact origin, exact RP ID, action, browser request, and one exact credential for authentication.
- Keep private credential material inside Passless.
- Avoid arbitrary signing, raw CTAP, raw assertion, and caller-supplied `clientDataHash` interfaces.
- Deny machine access by default.
- Audit every agent interaction, including denied and failed attempts.
- Provide versioned daemon, browser, CLI, and audit contracts.

## Non-goals

The design does not attempt to:

- Provide unattended WebAuthn in v1.
- Authorize or restrict actions performed after the RP creates a browser session.
- Protect against host root, kernel compromise, or a malicious Passless administrator.
- Distinguish an LLM from its plugins, tools, subprocesses, or subagents inside one principal boundary.
- Allow agents to use or convert existing personal passkeys.
- Support remote agents, non-Unix hosts, arbitrary browsers, related-origin requests, conditional mediation, or cross-origin iframe ceremonies in v1.
- Replace OAuth, service accounts, workload identity, or RP-specific machine credentials.

## Terminology

### Human credential

A credential belonging to the existing Passless UHID authenticator. It is available only through the human path and follows existing Passless presence and verification behavior.

### Machine credential

A credential created through the interactive agent path. It belongs to one authenticated principal and is unavailable to the human UHID path and other principals.

The word "machine" describes credential ownership and isolation. It does not imply autonomous use in v1.

### Principal

The complete launched execution environment that receives authority from Passless. It includes the agent process tree, managed browser profile, browser proxy, native host, and launcher session. A model name or caller-provided string is not an authenticated principal.

### Policy grant

A human-administered rule allowing one principal to perform one action for an exact origin and RP ID. Authentication grants identify one exact machine credential. Registration and authentication are separate grants.

### Intent

A short-lived, one-shot declaration that one browser ceremony is expected. An intent narrows and correlates a policy grant. It does not independently grant authority.

## High-level architecture

```text
Human browser
    |
    v
existing UHID transport -> human authenticator -> human credential store

Managed agent browser
    |
    v
WebAuthn proxy -> authenticated browser channel -> agent engine
                                                   |      |
                                                   |      +-> protected audit
                                                   v
                                          machine credential store
```

The daemon owns all policy decisions and credential material. The extension, native host, and agent CLI never receive private keys and never construct arbitrary signatures.

## Trust model

### Trusted computing base

The agent authentication boundary includes:

- The Passless daemon and agent engine.
- The existing FIDO2 implementation used by the agent engine.
- The trusted launcher.
- The managed browser configuration.
- The Passless browser extension and native messaging host.
- The authenticated local protocols.
- The machine credential storage implementation.
- The protected audit writer.
- The OS mechanisms enforcing principal isolation.

These components are security-sensitive. They must be versioned, distributed through authenticated channels, and fail closed on incompatible versions.

### Untrusted inputs

The design treats the following as untrusted:

- The LLM and its generated commands or plans.
- Web pages, scripts, repositories, documents, and tool output consumed by the agent.
- Agent plugins, tools, subprocesses, and subagents.
- Intent reasons and other descriptive text supplied by the agent.
- RP-provided account display names.

Compromise of the extension, native host, launcher, daemon, or isolation boundary compromises the agent authentication path. It must not expose the separate human path.

## Normative security invariants

The implementation must maintain all of the following:

1. Human and agent requests use structurally separate transports.
2. Human and machine credentials use separate stores and enumeration paths.
3. No agent operation occurs without an authenticated principal.
4. No agent operation occurs without an explicit current policy grant.
5. No agent operation occurs without a one-shot intent.
6. No agent operation occurs without an authenticated managed-browser request.
7. Policy is re-evaluated when an intent is created, bound, and executed.
8. Registration and authentication are distinct policy actions.
9. Authentication binds one exact origin, RP ID, and credential.
10. UP is set if and only if a fresh gesture was collected for that ceremony.
11. UV is set if and only if actual local user verification was performed.
12. No personal credential can appear in an agent flow.
13. No machine credential can appear in the human flow.
14. No cross-principal machine credential access is permitted.
15. No agent failure can fall back to the human authenticator.
16. No private key, PIN, capability, cookie, token, or raw assertion appears in CLI JSON, logs, or audit records.
17. No machine credential creation or use occurs without a durable pre-execution audit record.
18. A bound intent cannot be reused.
19. Cancellation, timeout, policy change, and revocation fail closed.
20. The managed browser cannot access personal profiles, platform passkeys, or the human UHID authenticator.

## Threat model

| Threat | Required mitigation | Residual risk |
|---|---|---|
| Prompt injection requests another RP | Exact origin and RP policy, authenticated browser origin, trusted human prompt | After login, the agent has full same-origin control of the RP browser session |
| Agent substitutes another account | Exact credential binding for authentication; account details shown during registration | RP display data may be misleading |
| Agent fabricates origin or challenge | Authenticated browser binding and daemon-constructed client data | Extension or native-host compromise breaks the agent boundary |
| Another process races an intent | Principal session authentication, one active ceremony, request binding | A process inside the same principal shares authority |
| Proxy failure exposes a personal passkey | Proxy-only profile, OS denial of UHID, no personal profile, hard failure | Browser isolation must be implemented and tested correctly |
| Agent reads a personal credential | Separate transport, store, process permissions, and enumeration interfaces | Host root remains trusted |
| Agent replays a ceremony | One-shot intent, unique browser request, RP challenge | The RP session remains valid under RP policy |
| Agent changes policy | Separate administrative channel unavailable to the principal | A malicious administrator remains trusted |
| Policy changes during a ceremony | Re-evaluation before execution and cancellation on mismatch | An RP session already issued cannot be revoked by Passless |
| Audit storage is unavailable | Durable pre-write and fail-closed degraded state | A terminal RP response may precede a failed terminal audit append |
| Audit history is modified | Agent cannot write audit storage; hash chain and optional external checkpoint | Host root can rewrite local state without external anchoring |
| Agent acts maliciously after login | Dedicated low-privilege account guidance | Passless cannot authorize post-login actions |

## Honest security claims

Documentation and user interfaces must state:

- Interactive agent mode still grants the agent the browser-session authority issued by the RP after the human approves login.
- RP ID and credential restrictions do not restrict actions after login.
- All processes inside one principal boundary share its authority.
- The browser proxy path has a broader trusted computing base than the existing UHID path.
- Local protected audit does not protect against host root without external anchoring.
- OAuth, service accounts, workload identity, and RP-specific scoped credentials are preferable for unattended automation where available.

## Consequences

### Positive

- WebAuthn UP and UV retain their standardized meaning.
- Personal credentials remain unavailable to autonomous software.
- Agent credentials are isolated, independently revocable, and auditable.
- Missing browser correlation cannot fall back to the human authenticator.
- The architecture can support future agent-aware protocols without weakening the human path.

### Negative

- V1 cannot authenticate unattended to browser-only RPs.
- Every registration and authentication ceremony requires a human gesture.
- The browser proxy, native host, launcher, sandbox, protocol, and audit writer increase implementation and maintenance cost.
- Successful login still gives the agent the RP's browser-session authority.
- Secure operation requires meaningful OS isolation, not a same-user bearer token.

## Alternatives considered

### Shared UHID path with an optional machine binding

Rejected. If a side-channel binding is missing, the authenticator cannot distinguish an ordinary human request from a failed agent request. This prevents a reliable no-fallback guarantee and risks credential-store confusion.

### Let agents use personal passkeys

Rejected. It creates weak ownership, revocation, and audit boundaries around high-value credentials.

### Raw CTAP or generic signing API

Rejected. It exposes a more general signing capability and discards browser-origin protections.

### Autonomous WebAuthn with UP set from prior delegation

Rejected. Prior delegation is not a ceremony-specific user-presence test. See [ADR 0003](0003-autonomous-agent-authentication.md).

### Interactive browser login without machine credential isolation

Rejected. Agent credentials must not share storage or enumeration paths with personal credentials.

## References

- W3C Web Authentication Level 3: https://www.w3.org/TR/webauthn-3/
- FIDO Client to Authenticator Protocol 2.2: https://fidoalliance.org/specs/fido-v2.2-rd-20241003/fido-client-to-authenticator-protocol-v2.2-rd-20241003.html
- OAuth 2.0 Token Exchange, RFC 8693: https://www.rfc-editor.org/rfc/rfc8693
- OAuth 2.0 Demonstrating Proof of Possession, RFC 9449: https://www.rfc-editor.org/rfc/rfc9449
- OAuth 2.0 Security Best Current Practice, RFC 9700: https://www.rfc-editor.org/rfc/rfc9700
