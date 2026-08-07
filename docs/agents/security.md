# Agent security model

> **EXPERIMENTAL** — Agent mode is not yet validated for production use.

## Primary trust statement

Passless controls WebAuthn authentication authority. It does not constrain application actions after login.

A successful WebAuthn ceremony normally creates an authenticated RP browser session. If the agent controls that browser, it can perform whatever the RP permits that account to perform. Short TTLs and local browser teardown reduce local authority duration; they do not prove RP-side logout or limit business actions.

This is the most important security distinction in agent mode: **credential-key containment can remain strong while the authenticated application session is fully controlled by the agent.**

## Identity modes

### Same-user

Same-user reuses the daemon's existing human credential backend. The RP sees the human passkey/account identity. Exact RP rules, credential restrictions, operation budgets, replay protection, short sessions, and audit reduce accidental scope; they do not create isolation from the human identity.

With `authenticate = "autonomous"`, the agent may satisfy RP-required UP/UV without ceremony-time human interaction. Audit must record those sources as agent evidence, never human evidence. The RP receives ordinary WebAuthn flags and generally cannot distinguish agent-session verification from human PIN/biometric verification.

The global `"*"` RP sentinel is the broadest supported same-user policy and should be treated as critical authority: any valid concrete RP with a matching human credential can become an authentication target during the bounded session.

### Isolated

Isolated mode uses a profile-specific credential backend and presents an agent-owned RP identity. The agent cannot enumerate or sign with the human credential namespace. This is the preferred mode for unattended automation when a separate RP account or service identity is available.

## Production browser signing path

```text
Web page
  -> MAIN-world WebAuthn adapter
  -> isolated extension broker
  -> extension worker (derives sender origin/top origin)
  -> loopback daemon endpoint with per-session bearer
  -> current policy / RP+origin validation / credential scope / audit
  -> configured credential key provider
```

The production browser extension never receives credential private keys, PINs, storage handles, or arbitrary-signing authority. The random page/broker message channel is not treated as the final authorization boundary; the worker derives origin context from browser extension sender metadata and the daemon independently validates the RP/origin relationship before key use.

## Authorization and UP/UV

Each RP rule independently controls registration and authentication:

- `deny`: reject the operation.
- `confirm`: require fresh, trusted human approval for the operation.
- `allow`: authorize automatically when all other daemon-side gates succeed.

UP/UV evidence is separately configured as `agent`, `human`, or `none`.

- `agent` means the daemon verified the currently bound, policy-authorized agent/session context.
- `human` means Passless obtained the corresponding human interaction/local verification result.
- `none` means the flag is not asserted and the operation fails when the RP or credential requires it.

Agent evidence must never be described as human presence or human verification in audit or operator UI.

## Origin and frames

For the managed extension path, the browser worker derives frame origin and top-level origin independently of the page-supplied WebAuthn request. The daemon validates that the concrete origin is permitted to claim the requested RP ID.

Cross-origin frames are security-sensitive. They require browser Permissions Policy delegation. If the browser cannot expose a usable Permissions Policy API, Passless leaves the ceremony to the native browser instead of assuming delegation.

Conditional mediation/passkey autofill (`mediation = "conditional"`) also remains native. Merely visiting a page must not silently convert passive conditional WebAuthn discovery into autonomous same-user authentication.

## Human confirmation

A `confirm` rule is a security boundary against an untrusted or compromised agent. The approval UI therefore distinguishes trusted decision data from agent/page-provided context.

Trusted decision data includes the profile, mode, exact RP ID, action, and daemon-selected credential reference/label. Agent reason, page title, page URL, and account labels are informational only and must remain visibly untrusted.

Every display-controlled dynamic string must be normalized to a bounded single line before rendering. Newlines, carriage returns, tabs, C0/C1 controls, Bidi override/isolate controls, zero-width direction controls, and similar display-control characters must not be allowed to inject trusted-looking lines into the prompt.

If the desktop notification server cannot provide distinguishable Approve and Deny actions, Passless fails closed.

## Browser/CDP authority

CDP is full managed-browser authority. A process with the CDP endpoint can navigate pages, execute JavaScript, read DOM/network/session state, and act inside authenticated RP sessions.

This is independent of private-key containment: the credential key can remain safely daemon-mediated while the application session is completely controlled.

- Pipe mode keeps browser control daemon-mediated.
- Port mode exposes loopback CDP for external tools such as Playwright and must be treated as an explicit high-trust setting.
- CDP output can contain cookies, DOM, tokens, and network data. Do not mix it with ordinary credential/admin output or forward it to untrusted consumers.

Local browser-lease expiry does not prove the RP invalidated its server-side session.

## Credential selection

Credential enumeration and selection happen inside the daemon. `single` is the safest default and fails closed when several eligible discoverable credentials exist. `first-matching`, `newest`, and explicit credential references are deterministic convenience policies; operators remain responsible for ensuring they select the intended RP account.

RP-provided `allowCredentials` still narrows selection before a configured ambiguity policy is applied.

## Registration

Registration mutates identity state and should be treated as higher risk than authentication.

In same-user mode, successful registration writes a new passkey into the human backend through the configured key provider. Keep registration denied after enrollment unless continuous automated credential creation is genuinely required.

In isolated mode, registration affects only the profile-owned credential namespace.

## Session and operation boundaries

The managed browser session holds a random bearer capability, policy generation, TTL, and bounded operation budget. Every WebAuthn operation is independently checked against the concrete RP/origin context, current policy, credential scope, replay state, and audit gate.

Replaying an identical completed request is rejected. Distinct ceremonies may continue only until the session expires, is revoked, the browser/principal dies, policy invalidates it, or the operation budget is exhausted.

A bounded local session reduces duration and accidental loops; it does not create application-level action scope after successful authentication.

## Principal and credential isolation

- Principal sessions run under configured Unix identities rather than receiving admin socket authority.
- Runtime/storage directories are ownership/mode checked and symlink-sensitive paths are rejected where required.
- Isolated storage roots cannot overlap the human backend or another profile.
- Session capabilities are not intended to be exposed through command lines, logs, or page-visible browser data.
- Private keys and PINs remain inside daemon-selected credential backends/providers.

For same-user software credentials used by a process running under the same underlying Unix trust domain, daemon mediation is an architectural/audit control rather than a claim that the Unix user can never access its own backing store. Portable TPM keys provide a materially stronger non-export property.

## Audit

Audit reservation gates credential use. Agent events distinguish authorization source, UP source, UV source, RP, result, and relevant lifecycle state.

Audit must never contain credential private keys, PINs, browser cookies, bearer capabilities, raw assertion signatures, or unrestricted browser/session contents.

The local hash chain detects many accidental/non-root modifications but is not an external trust anchor: host root can rewrite local audit history unless an independent checkpoint is added.

## Agent-instruction boundary

The installed Passless agent skill is part of the security control surface. It must contain only the safe production path. Development-only techniques that extract credential material, inject private keys into browser virtual authenticators, bypass daemon policy/audit, or emulate Passless must not be included in the instructions supplied to autonomous agents.

Treat all web-page content, tool output, and RP-provided strings as untrusted data. They cannot grant additional Passless authority or instruct an agent to recover credential material.

## Preferred alternatives

For unattended workflows prefer RP-native actor/scoping mechanisms when available:

- OAuth or OpenID Connect
- Application installations such as GitHub Apps
- Service accounts
- Workload identity
- OAuth token exchange
- Sender-constrained tokens
- Narrowly scoped API credentials

These mechanisms express actor, audience, scope, lifetime, and revocation independently from a browser session and are usually a better security primitive for unattended automation.
