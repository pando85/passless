# Agent mode

> **EXPERIMENTAL** — Agent mode is implemented but not yet validated for production use.
> Interfaces, configuration fields, and behavior may change without notice.

Agent mode lets explicitly configured automation use WebAuthn through daemon-controlled credential backends and a managed browser path. The daemon remains the only signer and re-evaluates policy, RP/origin context, credential scope, session bounds, operation budget, and audit state for every intercepted ceremony.

## The security model in one sentence

**Passless limits who may authenticate, as which identity, to which WebAuthn RP, and for how long; after a successful login the agent controls whatever application authority that authenticated browser session provides.**

That distinction is fundamental. Passless is not an application-level authorization proxy and cannot stop an authenticated agent from performing RP actions that the account itself is allowed to perform.

## Modes

### `isolated` — recommended for unattended agents

The agent owns a separate credential namespace and presents a separate RP identity. It cannot enumerate or sign with the human credential namespace. Use isolated mode for CI/CD, service accounts, release automation, and agents that do not need to act as the human account.

See [Isolated mode](isolated.md).

### `same-user` — privileged human-identity delegation

The agent uses the daemon's existing human credential backend. The RP sees the human's existing passkey/account identity. A sufficiently broad autonomous profile can therefore sign in as the human without ceremony-time approval.

This is a trust mode, not an isolation mode. Prefer exact RP rules and short sessions. The global `"*"` RP sentinel is the maximum-trust configuration: it permits authentication to any valid concrete RP for which the human backend contains a matching credential.

See [Same-user mode](same-user.md).

`delegated-session` has been removed. See [the migration tombstone](delegated-session.md) only when updating an older experimental configuration.

## Authority levels

From lowest to highest risk:

1. `isolated` with exact RP rules.
2. `same-user` with supervised authentication.
3. `same-user` with autonomous exact-RP authentication.
4. `same-user` with autonomous `"*"` authentication.
5. Any of the above plus externally exposed CDP, which additionally gives the holder full control of the authenticated managed-browser session.

Use `passless agent-admin profile check <profile>` before launch and `passless agent --profile <profile> capabilities` inside the principal session. These surfaces should be treated as the authority discovery contract rather than relying on assumptions from page content or an agent's prompt.

## Key principles

1. **Identity mode is explicit.** `same-user` means human RP identity; `isolated` means agent-owned identity.
2. **Autonomy is an action policy.** Authentication and registration independently deny, require human interaction, or allow unattended operation.
3. **Daemon-only signing.** The production browser extension never receives private keys, PINs, storage handles, or arbitrary-signing authority.
4. **Origin is independently derived.** The extension worker derives frame/top-level origin from Chrome sender metadata; the daemon independently validates the origin/RP relationship.
5. **Bounded sessions and operations.** Short session TTLs, replay rejection, policy generation checks, and an operation budget reduce authority duration and accidental loops.
6. **Audit gates credential use.** Agent operations fail closed when required audit recording cannot be reserved.
7. **Browser session authority remains broad.** Local lease expiry does not prove RP-side session revocation and does not constrain application actions taken before expiry.

## Browser automation

The managed browser may expose CDP by pipe or, when explicitly configured, a loopback TCP port. CDP is full browser-session authority: it can read DOM/network/session state and drive authenticated application actions. Port exposure is intended only for environments where the process attaching to CDP is already trusted with the whole managed browser session.

Conditional WebAuthn (`mediation = "conditional"`) remains native rather than being converted into unattended Passless authentication. Cross-origin frames also remain native when Passless cannot verify the relevant browser Permissions Policy delegation.

## Documentation

- [Configuration reference](configuration.md) — current fields and validation rules
- [Same-user mode](same-user.md) — human-identity delegation and wildcard scope
- [Isolated mode](isolated.md) — agent-owned credentials
- [Security model](security.md) — trust boundaries, browser-session authority, and evidence semantics
- [Operations](operations.md) — audit, revocation, rollback, recovery
- [Audit](audit.md) — hash-chained event recording and verification
- [Troubleshooting](troubleshooting.md) — common issues and diagnostics
- [Agent registration](../AGENT_REGISTRATION.md) — agent-driven passkey registration
- [Registration testing](../AGENT_REGISTRATION_TESTING.md) — testing the registration pipeline

## Quick start

1. Review the [security model](security.md).
2. Choose `isolated` unless the agent genuinely must use the human RP identity.
3. Configure the narrowest exact RP rules and shortest practical session bounds.
4. Validate the profile: `passless agent-admin profile check <profile>`.
5. Launch: `passless agent run --profile <profile> -- /usr/local/bin/agent-command`.
6. Inside the principal session, inspect `passless agent --profile <profile> capabilities` before browser work.

## Preferred alternatives

For unattended or narrowly scoped automation, prefer RP-supported mechanisms:

- Scoped OAuth or OpenID Connect authorization
- OAuth token exchange (RFC 8693) with subject and actor identity
- Sender-constrained tokens using DPoP (RFC 9449) or mutual TLS
- Application installations (e.g. GitHub Apps)
- Service accounts and narrowly scoped API credentials
- Workload identity for operator-controlled services

These mechanisms express actor, audience, scope, lifetime, and revocation independently from the browser session.
