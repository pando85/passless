# ADR 0003: Autonomous agent authentication

- **Status:** Accepted
- **Date:** 2026-07-13
- **Decision owners:** Passless maintainers
- **Implementation status:** Autonomous WebAuthn is intentionally not implemented
- **Depends on:** [ADR 0001](0001-agent-authentication-security-model.md)
- **Related decision:** [ADR 0002](0002-managed-browser-interactive-passkeys.md)
- **Implementation plan:** [Agent passkey implementation plan](../plans/agent-passkey-implementation.md)

## Context

Autonomous agents need credentials that can be used without a human gesture for every operation. It is tempting to satisfy this requirement by creating a software passkey and setting WebAuthn UP after an administrator grants prior authority.

That approach preserves RP scoping and keeps the private key inside Passless, but it changes the meaning of the assertion delivered to the relying party.

WebAuthn Level 3 states that UP is set if and only if the authenticator performed a test of user presence. UV is set if and only if the authenticator performed user verification. Administrative policy, agent identity, a launcher capability, and an earlier human gesture do not satisfy those ceremony-time statements.

WebAuthn and CTAP currently have no standardized assertion field for:

- An autonomous software actor.
- Prior human delegation.
- Agent identity or delegation chains.
- Business-action scope.
- Transaction intent.

A distinct AAGUID identifies an authenticator model. It is not a per-assertion authorization signal, may not be attested, and is commonly not used by RPs for authorization.

An unmodified RP that receives an ordinary passkey assertion generally treats it as authentication for the user account. Passless cannot constrain the browser session or the actions available after login.

## Decision

Passless will not implement a delegated-machine WebAuthn mode that sets UP without a fresh ceremony-specific user-presence test.

V1 provides only interactive agent passkeys as defined by ADR 0001 and ADR 0002.

Passless will not:

- Set UP based on policy, prior delegation, agent identity, possession of a capability, or an earlier gesture.
- Set UV based on an agent credential, launcher identity, cached administrative approval, or software-principal authentication.
- Use an AAGUID, local metadata, warnings, or audit labels as justification for an inaccurate RP-visible flag.
- Offer autonomous registration to an ordinary WebAuthn RP.
- Describe a full browser login as scoped authorization.
- Expose personal passkeys to autonomous agents.

## Preferred autonomous patterns

When an RP supports machine or delegated authorization, users should prefer the RP's supported mechanism:

- Scoped OAuth or OpenID Connect authorization.
- OAuth token exchange that preserves the user subject and agent actor.
- Sender-constrained access tokens using DPoP or mutual TLS.
- GitHub Apps or equivalent application installations.
- Service accounts and narrowly scoped API credentials.
- Workload identity for operator-controlled services.
- RP-specific transaction or agent protocols that expose the agent identity and authorized action.

These mechanisms can represent the actor, audience, scope, lifetime, and revocation state. An ordinary WebAuthn assertion cannot.

OAuth is not a drop-in replacement for an arbitrary browser-only RP. It requires support from an authorization server and resource server. If an RP offers only browser WebAuthn, Passless supports interactive login and does not manufacture autonomous user presence.

## Recommended delegated architecture

For an RP that supports standards-based delegation, the preferred shape is:

```text
Human --WebAuthn--> authorization server
                         |
                         +-> short-lived delegated token
                                  subject = user
                                  actor = agent
                                  audience = exact service
                                  scope = required actions
                                  proof-of-possession = agent key
                                           |
                                           v
                                         Agent
```

The human passkey authenticates the human to the authorization server. It is not handed to the agent. The agent receives a short-lived, audience-restricted, least-privilege credential bound to an agent-held key. The service can identify both user and actor and can revoke the delegation without revoking the user's passkey.

For operator-controlled infrastructure, a workload identity such as a SPIFFE ID may authenticate the agent workload, while a separate authorization service records any user delegation.

## Future Passless work

Passless may later assist an autonomous flow without weakening WebAuthn semantics by providing one or more of:

- Interactive passkey authentication that bootstraps an RP-supported authorization grant.
- Non-exportable agent proof-of-possession keys protected by the TPM backend.
- Local policy and audit around token acquisition, without storing bearer tokens in logs.
- A thin adapter to a cooperating RP's explicit agent-authentication protocol.
- Transaction-intent confirmation when the RP includes the exact business action in the authorization protocol.

Such work requires a separate ADR. It is not part of the managed-browser passkey implementation plan.

## Requirements for a future autonomous ADR

A future proposal must demonstrate all of the following before acceptance:

1. **Truthful protocol semantics.** No WebAuthn UP or UV flag is set without the corresponding ceremony evidence.
2. **RP awareness.** The RP or authorization server explicitly supports the agent or delegated credential type.
3. **Actor visibility.** The relying service can distinguish the human subject from the software actor.
4. **Least privilege.** Authority is limited by exact audience, actions or scopes, and time.
5. **Intent binding.** High-risk operations bind authorization to immutable transaction context understood by the RP.
6. **Sender constraint.** Stolen tokens cannot be replayed without an agent-held proof-of-possession key.
7. **Non-exportable custody.** Agent private keys remain in Passless, TPM, HSM, TEE, or another reviewed signing boundary.
8. **Independent revocation.** Agent authority can be revoked without revoking the user's passkey.
9. **No personal credential exposure.** The agent cannot invoke the user's passkey after the interactive bootstrap ceremony.
10. **Short lifetime.** Access credentials are short-lived; persistent refresh authority is separately justified and protected.
11. **Auditability.** Issuance and use identify subject, actor, audience, scope, policy, and result.
12. **Prompt-injection containment.** Compromise of the agent cannot exceed the issued authority.
13. **Recovery.** Compromise and key loss have documented rotation, revocation, and recovery procedures.
14. **Standards review.** The design is checked against current FIDO, WebAuthn, OAuth, and workload-identity standards at implementation time.

## Rejected alternatives

### Set UP and document a different local meaning

Rejected. The RP receives the standardized UP bit, not the local documentation. Internal metadata cannot change the assertion's meaning.

### Use a distinct AAGUID as the delegated signal

Rejected. AAGUID identifies authenticator type at registration and is not a standardized per-ceremony delegation signal. Without trusted attestation and RP policy, it is only self-asserted metadata.

### Leave UP unset and rely on ordinary RPs accepting the assertion

Rejected as a general product path. Most WebAuthn login flows expect user presence, and the RP still would not receive agent identity or scoped authorization. This may be useful only in a cooperating-RP protocol described by a future ADR.

### Treat a launcher capability as UV

Rejected. Authentication of a software principal is not human user verification.

### Cache one UV gesture for autonomous WebAuthn

Rejected for the current architecture. Cached authorization would need explicit protocol support defining lifetime, scope, actor, and RP-visible semantics. It cannot silently reuse the WebAuthn UV flag.

### Give the agent the user's existing passkey

Rejected. It removes independent revocation and exposes a high-value user credential as an authentication oracle to prompt-injected code.

## Consequences

### Positive

- Passless does not misrepresent user presence or verification to RPs.
- The human passkey remains phishing-resistant and unavailable to autonomous code.
- Future autonomous work is directed toward protocols that can express agent identity and scope.
- Revocation and audit can be designed around a distinct actor rather than user impersonation.

### Negative

- Passless cannot provide unattended login to arbitrary browser-only WebAuthn RPs.
- Some agent workflows continue to require a human gesture.
- Standards-aligned autonomous access depends on RP or authorization-server support.
- Users may need dedicated low-privilege accounts or service-specific credentials until agent-aware protocols mature.

## State of the art

As of the decision date, OAuth 2.0 Token Exchange defines delegation and actor representation, but deployment support varies. DPoP and mutual TLS sender-constrain tokens but do not themselves grant authority. OAuth security best current practice requires careful audience, redirect, token, and replay controls. SPIFFE addresses workload identity, not user delegation. FIDO agent-authentication initiatives are emerging; they do not currently define a generally deployed delegated-agent WebAuthn assertion.

The absence of a universal solution is a reason to keep v1 interactive, not a reason to overload WebAuthn flags.

## References

- W3C Web Authentication Level 3: https://www.w3.org/TR/webauthn-3/
- FIDO Client to Authenticator Protocol 2.2: https://fidoalliance.org/specs/fido-v2.2-rd-20241003/fido-client-to-authenticator-protocol-v2.2-rd-20241003.html
- OAuth 2.0 Token Exchange, RFC 8693: https://www.rfc-editor.org/rfc/rfc8693
- OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens, RFC 8705: https://www.rfc-editor.org/rfc/rfc8705
- OAuth 2.0 Demonstrating Proof of Possession, RFC 9449: https://www.rfc-editor.org/rfc/rfc9449
- OAuth 2.0 Security Best Current Practice, RFC 9700: https://www.rfc-editor.org/rfc/rfc9700
- SPIFFE: https://spiffe.io/
