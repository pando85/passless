# Agent mode

Agent mode extends Passless with configurable profiles for coding agents and automation tools.
It supports two modes: **isolated** credentials (agent-only, independently revocable) and
**delegated-session** (temporary reuse of one existing human credential for one RP login).

## Status

Agent mode is **implemented** but **not yet validated for production use**. Phase 0 feasibility
evidence is available in `tools/agent-uhid-feasibility/evidence.md`. Full production validation
(Phase 9) is pending.

Delegated-session autonomous authentication is being redesigned under
[ADR 0005](../decisions/0005-delegated-autonomous-authentication-redesign.md) to route assertions
through a daemon-loaded MV3 extension and localhost daemon signing channel. Implementation is
**in progress**; see the
[implementation plan](../plans/delegated-autonomy-daemon-proxy-implementation.md).

## Documentation

- [Configuration reference](configuration.md) — complete field definitions and validation rules
- [Isolated mode](isolated.md) — agent-only credentials, including fully unattended operation
- [Delegated-session mode](delegated-session.md) — temporary reuse of one human credential
- [Security model](security.md) — threat model, UP/UV semantics, browser-control authority
- [Operations](operations.md) — audit, revocation, rollback, recovery
- [Audit](audit.md) — hash-chained event recording and verification
- [Troubleshooting](troubleshooting.md) — common issues and diagnostics

## Design decisions

- [ADR 0001: Agent authentication security model](../decisions/0001-agent-authentication-security-model.md)
- [ADR 0002: Native WebAuthn agent architecture](../decisions/0002-native-webauthn-agent-architecture.md)
- [ADR 0005: Delegated autonomous authentication redesign](../decisions/0005-delegated-autonomous-authentication-redesign.md)
- [Implementation plan](../plans/agent-passkey-implementation.md)
- [Delegated autonomy daemon proxy implementation](../plans/delegated-autonomy-daemon-proxy-implementation.md)

## Key principles

1. **Autonomy is explicit.** Each exact RP/action rule denies, confirms, or allows the ceremony and
   selects human or policy UP/UV evidence. Missing rules deny.
2. **Stock browser for human and isolated paths.** No browser modification, extension, native
   messaging host, or WebAuthn proxy for human or isolated-mode ceremonies. Delegated-session
   autonomous authentication uses a daemon-loaded MV3 extension and localhost signing channel;
   see [ADR 0005](../decisions/0005-delegated-autonomous-authentication-redesign.md).
3. **Exact RP ID matching.** Passless matches the CTAP RP ID exactly against policy. It does not
   receive or validate the exact web origin.
4. **One-shot grants.** Delegated mode permits exactly one authentication assertion per grant.
   The grant is consumed on every terminal result.
5. **Local lease ≠ RP revocation.** Browser-lease expiry terminates the local ephemeral browser
   but does not prove RP-side session invalidation.
6. **Deny by default.** Agent support is disabled unless explicitly configured. Unknown modes and
   fields are rejected.

## Quick start

1. Review the [security model](security.md) and [delegated-session confused-deputy risk](security.md#delegated-session-confused-deputy).
2. Create principal and browser Unix users.
3. Configure a profile in `~/.config/passless/config.toml` (see [configuration reference](configuration.md)).
4. Validate configuration: `passless agent-admin profile check <profile>`.
5. Launch: `passless agent run --profile <profile> -- /usr/local/bin/agent-command`.

## Preferred alternatives

For unattended or narrowly scoped automation, prefer RP-supported mechanisms:

- Scoped OAuth or OpenID Connect authorization
- OAuth token exchange (RFC 8693) with subject and actor identity
- Sender-constrained tokens using DPoP (RFC 9449) or mutual TLS
- Application installations (e.g., GitHub Apps)
- Service accounts and narrowly scoped API credentials
- Workload identity for operator-controlled services

These mechanisms express actor, audience, scope, lifetime, and revocation independently from the
browser session.
