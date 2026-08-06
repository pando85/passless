# Agent mode

> **EXPERIMENTAL** — Agent mode is implemented but not yet validated for production use.
> Interfaces, configuration fields, and behavior may change without notice.

Agent mode extends Passless with configurable profiles for coding agents and automation tools.
It creates isolated virtual FIDO2 authenticator endpoints that agents can use to register and
authenticate passkeys without human interaction (where policy allows).

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Passless Daemon (root)                       │
│                                                                      │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────────┐ │
│  │  Human UHID   │   │ Agent UHID   │   │  Sign HTTP Server        │ │
│  │  Endpoint     │   │ Endpoint(s)  │   │  (127.0.0.1)             │ │
│  │  /dev/uhid    │   │ /dev/hidraw* │   │  /register, /sign        │ │
│  └──────┬───────┘   └──────┬───────┘   └────────────┬─────────────┘ │
│         │                  │                         │               │
│         │           ┌──────┴─────────────────────────┘               │
│         │           │                                                │
│  ┌──────┴───────────┴────────────────────────────────────────────┐  │
│  │                    Authenticator Core                           │  │
│  │  ┌─────────────┐  ┌──────────────┐  ┌───────────────────────┐ │  │
│  │  │ Policy       │  │ Credential   │  │ Audit                 │ │  │
│  │  │ Engine       │  │ Storage      │  │ (hash-chained JSONL)  │ │  │
│  │  │ (deny by     │  │ (local/pass/ │  │                       │ │  │
│  │  │  default)    │  │  TPM)        │  │                       │ │  │
│  │  └─────────────┘  └──────────────┘  └───────────────────────┘ │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │              Principal Session Manager                          │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │  │
│  │  │ Intent       │  │ Grant        │  │ Browser Lease        │ │  │
│  │  │ (one-shot)   │  │ (one-shot)   │  │ (ephemeral profile)  │ │  │
│  │  └──────────────┘  └──────────────┘  └──────────────────────┘ │  │
│  └────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘

     ▲                    ▲                        ▲
     │                    │                        │
     │                    │                        │
┌────┴─────┐    ┌────────┴────────┐    ┌──────────┴──────────┐
│  Human   │    │  Agent Process  │    │  Browser Extension  │
│  Browser │    │  (principal     │    │  (intercepts        │
│          │    │   user)         │    │   WebAuthn calls)   │
└──────────┘    └─────────────────┘    └─────────────────────┘
```

## Modes

Agent mode supports two operating modes:

### Isolated mode

Agent-only credentials with independent storage, PIN state, and revocation. The agent
cannot see or use human credentials. Each isolated profile has its own credential store
(local, pass, or TPM backend) under a non-overlapping root.

Best for: CI/CD pipelines, automated deployments, service accounts.

See [Isolated mode](isolated.md) for details.

### Delegated-session mode

Temporary reuse of one existing human credential for one RP login. The RP sees the same
account context as ordinary use by the human. One grant authorizes exactly one passkey
login; a later WebAuthn operation requires another grant.

Best for: Interactive coding sessions where the agent needs to act as the human user.

See [Delegated-session mode](delegated-session.md) for details.

## Key principles

1. **Autonomy is explicit.** Each exact RP/action rule denies, confirms, or allows the
   ceremony and selects human or policy UP/UV evidence. Missing rules deny.
2. **Stock browser for human and isolated paths.** No browser modification, extension,
   native messaging host, or WebAuthn proxy for human or isolated-mode ceremonies.
   Delegated-session autonomous authentication uses a daemon-loaded MV3 extension and
   localhost signing channel.
3. **Exact RP ID matching.** Passless matches the CTAP RP ID exactly against policy. It
   does not receive or validate the exact web origin.
4. **One-shot grants.** Delegated mode permits exactly one authentication assertion per
   grant. The grant is consumed on every terminal result.
5. **Local lease ≠ RP revocation.** Browser-lease expiry terminates the local ephemeral
   browser but does not prove RP-side session invalidation.
6. **Deny by default.** Agent support is disabled unless explicitly configured. Unknown
   modes and fields are rejected.

## Documentation

- [Configuration reference](configuration.md) — complete field definitions and validation rules
- [Isolated mode](isolated.md) — agent-only credentials, including fully unattended operation
- [Delegated-session mode](delegated-session.md) — temporary reuse of one human credential
- [Security model](security.md) — threat model, UP/UV semantics, browser-control authority
- [Operations](operations.md) — audit, revocation, rollback, recovery
- [Audit](audit.md) — hash-chained event recording and verification
- [Troubleshooting](troubleshooting.md) — common issues and diagnostics
- [Agent registration](../AGENT_REGISTRATION.md) — agent-driven passkey registration
- [Registration testing](../AGENT_REGISTRATION_TESTING.md) — testing the registration pipeline

## Quick start

1. Review the [security model](security.md).
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
