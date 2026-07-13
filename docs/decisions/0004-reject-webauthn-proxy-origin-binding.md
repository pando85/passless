# ADR 0004: Reject WebAuthn proxy origin binding

- **Status:** Accepted
- **Date:** 2026-07-13
- **Decision owners:** Passless maintainers
- **Supersedes:** the managed Chromium transport selected by [ADR 0002](0002-managed-browser-interactive-passkeys.md)
- **Preserves:** [ADR 0001](0001-agent-authentication-security-model.md) and [ADR 0003](0003-autonomous-agent-authentication.md)
- **Evidence:** [Phase 0 managed-browser feasibility evidence](../../tools/agent-feasibility/evidence.md)

## Context

ADR 0002 selected Chrome's `webAuthenticationProxy` API subject to a hard feasibility gate. The gate required Passless to bind every intercepted WebAuthn request to a trustworthy exact origin and current top-level document.

The API suspends ordinary WebAuthn processing and supplies complete serialized creation or request options. However, its create and get events contain only:

```text
requestId
requestDetailsJson
```

They do not contain the source origin, tab ID, frame ID, or document ID.

The Phase 0 probe used a managed profile restricted to one normal window, one tab, one top-level frame, and one request. The extension could query the current frame through `tabs` and `webNavigation`, but those APIs report browser state when queried. They do not prove that the observed document originated the earlier proxy request.

## Decision

Passless will not implement the ADR 0002 agent path using `chrome.webAuthenticationProxy` in its current form.

Phase 0 is a NO-GO. Phases 1 through 9 in the implementation plan are blocked and must not proceed on this transport.

The project will retain:

- The security model and interactive-only requirement from ADR 0001.
- The rejection of false UP, false UV, and autonomous WebAuthn impersonation from ADR 0003.
- The reproducible Phase 0 probe and evidence.

The project will not retain the assumption that current browser state can authenticate the source of a proxy request.

## Reason

Deriving origin after receipt creates an uncloseable request-to-document time-of-check/time-of-use gap:

1. Document A starts WebAuthn.
2. Chrome queues the extension proxy event without source identity.
3. Navigation changes the current document to B.
4. The extension queries tabs and navigation state and may observe B.
5. The extension cannot determine whether A or B originated the queued request.

Navigation listeners do not provide a sound correlation. They may run before the request is placed in an extension pending map, and the request has no tab or document identifier against which to compare a navigation event.

Restricting the profile to one tab and one frame narrows the race but does not add the missing binding or event-ordering guarantee.

## Verified positive results

The failed gate does not invalidate all of ADR 0002's assumptions. The probe confirmed:

- The extension can attach before navigation.
- Attached proxy requests can fail terminally without falling back to another authenticator.
- The proxy can carry valid ES256 registration and authentication responses.
- A controlled RP can verify the resulting assertion signature, RP hash, flags, and client-data origin.
- A navigation observed after a request becomes pending can cancel that request.

These properties are insufficient without trustworthy source identity.

## Requirements for reconsideration

A replacement transport requires a new ADR and must provide one of:

1. A browser API that directly includes authenticated source origin and document identity in each WebAuthn proxy event.
2. A browser-integrated capability that cryptographically binds a request envelope to the source document and cannot be forged by page content.
3. A different architecture in which the trusted browser component constructs and authenticates the complete request before it reaches an untrusted race boundary.

Any replacement must rerun the full feasibility gate. A side channel that merely reports current tab state, page-supplied origin, or an uncorrelated options digest is insufficient.

## Consequences

### Positive

- Passless does not ship an origin-confused credential oracle.
- The approved security invariants remain stronger than implementation momentum.
- Future work starts from explicit browser guarantees rather than timing assumptions.

### Negative

- Interactive agent passkeys remain unimplemented.
- The detailed production phases in the current plan are blocked.
- A browser change, browser-specific integration, or cooperating browser component is required before work can resume.

## Alternatives considered

### Query the only active tab

Rejected. It identifies current state, not the source of the queued request.

### Cancel on every top-level navigation

Rejected. A navigation may commit before the asynchronous request handler records the request, and there is no source identifier for correlation.

### Pair a page or content-script side channel with the proxy request

Rejected without a separate design and proof. Page content is untrusted, isolated-world scripts cannot directly prove the caller, and a missing or mismatched side channel must fail closed. Any proposed authenticated browser envelope requires a new ADR.

### Continue with later phases and repair origin binding afterward

Rejected. Origin binding is the first hard security gate and affects every policy, intent, credential, and audit claim downstream.

## References

- Chrome `webAuthenticationProxy`: https://developer.chrome.com/docs/extensions/reference/api/webAuthenticationProxy
- W3C Web Authentication Level 3: https://www.w3.org/TR/webauthn-3/
