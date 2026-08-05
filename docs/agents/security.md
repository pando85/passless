# Agent security model

> **EXPERIMENTAL** — Agent mode is not yet validated for production use.

## Threat model summary

Agent mode extends the Passless daemon with multiple UHID endpoints, principal sessions,
and browser leases. The security boundary relies on:

- Kernel-enforced device permissions for endpoint routing.
- Separate Unix identities for principal, browser, and daemon.
- One-shot intents and grants consumed on every terminal result.
- Hash-chained audit that gates credential use.
- Deny-by-default policy administered outside every principal.

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Security Boundary                                │
│                                                                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐   │
│  │ Daemon (root) │    │ Principal   │    │ Browser              │   │
│  │              │    │ (separate   │    │ (separate            │   │
│  │ - Policy     │    │  Unix user) │    │  Unix user)          │   │
│  │ - Storage    │◄──►│             │    │                      │   │
│  │ - Audit      │    │ - Intents   │    │ - Ephemeral profile  │   │
│  │ - Signing    │    │ - No admin  │    │ - No personal state  │   │
│  │              │    │   access    │    │                      │   │
│  └──────────────┘    └──────────────┘    └──────────────────────┘   │
│        ▲                                                            │
│        │  kernel-enforced                                           │
│  ┌─────┴──────────────────────────────────────────────────────┐    │
│  │  /dev/uhid, /dev/hidraw* — device permissions per profile  │    │
│  │  Admin socket — daemon-only                                │    │
│  │  Audit path — root-owned, mode 0700                        │    │
│  └────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

## Authorization and UP/UV

Every exact RP rule selects `deny`, `confirm`, or `allow` independently for registration and
authentication. It also selects the source of UP and UV evidence.

- Human UP is set only after a trusted prompt approves the bound CTAP operation.
- Human UV is set only after Passless performs actual local verification.
- Policy UP/UV requires an explicit operator-owned rule and is audited as machine authorization,
  not human interaction or verification.
- Missing rules deny, and browser leases never authorize another ceremony by themselves.
- The prompt shows trusted fields (profile, mode, exact RP ID, action, credential label)
  and clearly labels untrusted fields (account name, page URL, page title, agent reason).
- If the notification server cannot provide distinguishable approve and deny actions,
  agent mode fails closed.

### Unattended operation semantics

An exact action using `authorization = "allow"` and policy UP/UV is fully unattended: current
administrator policy resolves the one-shot operation without displaying a notification. Policy UP
and UV are machine authorization claims, not evidence that a human was present or locally verified.

For delegated-session autonomy, the `allow` path is resolved by the daemon signing oracle via
the MV3 extension and localhost channel. The daemon-loaded MV3 extension reads the frame origin
via a MAIN-world override and forwards the assertion request to the daemon over a localhost bearer
channel. The daemon validates origin, grant, policy, credential ref, and audit before signing.
A `confirm` rule is not auto-signed and remains an explicit human prompt. A `deny` rule fails
closed. Daemon-side origin, grant, policy, credential-ref, audit, and key-provider checks are
load-bearing; the bearer token is defense-in-depth. Implementation is **in progress**.

The RP receives ordinary WebAuthn UP/UV flags and generally cannot distinguish human evidence from
policy evidence. Passless records the selected authorization and evidence sources in its audit log,
so operators must treat the rule itself as authority to make those claims. One-shot binding,
policy re-evaluation, credential scope, audit reservation, and terminal consumption are unchanged.
For a complete setup, see the [fully unattended isolated workflow](isolated.md#fully-unattended-workflow).

## Origin vs RP ID

For human and isolated modes, the stock browser validates that the calling origin may use the
requested RP ID. Passless receives the RP ID and `clientDataHash` through CTAP. It does not
receive the exact web origin. Agent policy is keyed by exact RP ID, not origin.

For delegated-session autonomous authentication, the daemon validates the frame origin read by a
MAIN-world extension override. Daemon-side origin, grant, policy, credential-ref, audit, and
key-provider checks are load-bearing. The per-session localhost bearer token is defense-in-depth.
Implementation is **in progress**.

A configured `start_url` is operational configuration, not origin evidence. Passless never
claims independent visibility of the exact web origin for CTAP-based paths.

## Browser-control authority warning

The `passless agent browser-control` command sends CDP commands to the managed browser.

**WARNING:** CDP is the full browser-session authority interface. CDP commands can access
cookies, DOM, network state, and session data. Output may contain sensitive session
material.

- Do not mix CDP output with credential or admin output.
- Do not log, cache, or forward CDP responses to untrusted consumers.
- The principal holds the full RP browser-session authority during the lease.
- Optional network and egress restrictions may reduce exfiltration risk but do not create
  RP-side revocation or business-action scope.
- **Audit recording:** CDP method and outcome metadata may be recorded in audit events, but
  CDP response bodies are not audit-recorded. Do not assume CDP responses are preserved in
  audit logs.

## Delegated-session confused deputy

Delegated mode authorizes authentication but gives the principal the full authority of the
browser session returned by the RP. The agent can perform destructive or sensitive RP
actions that were not shown in the Passless prompt.

Mitigations:

- Short lease limits duration, not action scope.
- Explicit approval warning in the trusted prompt.
- Ephemeral profile with no personal state.
- Immediate local revocation on expiry or admin action.
- Use a low-privilege RP account where possible.

## Principal isolation

- Each principal runs as a separate Unix user (`principal_user`).
- The browser runs as a different Unix user (`browser_user`, delegated only).
- The daemon runs as root for device creation and principal isolation.
- Principals cannot access `/dev/uhid`, human or foreign hidraw nodes, admin sockets,
  credential stores, audit files, or other principals' runtime directories.
- The session capability is transferred through an inherited protected channel, not
  command lines or environment variables.

## Credential isolation

- Isolated credentials use profile-specific stores and enumeration paths.
- Delegated access is a filtered view over one exact human credential.
- Human and delegated access serialize all mutable credential state.
- Private keys remain in daemon-owned storage and never cross local protocols.

For isolated profiles, `allow` changes ceremony authorization only. It does not grant access to
human credentials, another profile's credentials, daemon-owned storage, policy administration, or
the admin socket.

## Preferred alternatives

For unattended or narrowly scoped automation, prefer RP-supported mechanisms:

- Scoped OAuth or OpenID Connect authorization.
- OAuth token exchange (RFC 8693) with subject and actor identity.
- Sender-constrained tokens using DPoP (RFC 9449) or mutual TLS.
- Application installations (e.g., GitHub Apps).
- Service accounts and narrowly scoped API credentials.
- Workload identity for operator-controlled services.

These mechanisms express actor, audience, scope, lifetime, and revocation independently
from the browser session.

## Port mode threat model

When `browser_cdp_expose = "port"`, the daemon exposes the browser's CDP WebSocket on
`127.0.0.1` instead of mediating CDP through Unix pipes. The trust boundary shifts from
the CDP channel to the authenticated session.

### Trust boundary

The trust boundary is the authenticated session (cookies), not the CDP channel. Any
same-user process with the WebSocket URL can control the browser session. This is an
accepted risk for single-user workstations where the agent and operator share a trust
boundary.

### Credential isolation

The credential private key never leaves the daemon. Passless mediates the WebAuthn
ceremony; the browser only holds the authenticated session (cookies), not the credential
material. Even if the agent exfiltrates the entire browser session, it cannot extract
the private key.

### WebSocket UUID as bearer token

The CDP WebSocket URL includes a UUID path component (e.g.,
`ws://127.0.0.1:9222/devtools/browser/<uuid>`). This UUID acts as a bearer token:
possession of the URL grants access. The URL is written to `<runtime_dir>/cdp-endpoint`
with mode 0600, owned by the principal user. The runtime directory has mode 0700.

### Loopback-only binding

Chromium binds to `127.0.0.1` only. The daemon does not pass `--remote-debugging-address`;
Chromium's default is loopback. This is enforced, not configurable. Remote network access
to the CDP endpoint is not possible.

### Extra args rejection

The daemon rejects `--remote-debugging-port` and `--remote-debugging-address` in
`browser_command` extra args. These flags are set by the daemon in port mode. Attempting
to override them causes configuration load failure.

### Audit trail

Audit records note the exposure mode (`pipe` or `port`) at lease creation. In port mode,
audit records the delegation grant, lease creation, and lease expiry. Per-command CDP
audit is not available; the agent has direct CDP access after the ceremony.

### Comparison to pipe mode

| Property | Pipe mode | Port mode |
|----------|-----------|-----------|
| CDP transport | Unix pipes | TCP 127.0.0.1 |
| Daemon mediation | Every command | Ceremony only |
| External tool attachment | No | Yes |
| `browser_user` isolation | Required | Optional |
| CDP command audit | Per-command | Lease-level |
| CDP command filtering | Yes | No |
| Credential key exposure | Never | Never |
| Session cookie exposure | Daemon-gated | Direct |
| Trust assumption | Agent is untrusted | Agent is trusted |

Use pipe mode for multi-user systems, production environments, or untrusted agents.
Use port mode only for single-user workstations where the operator fully trusts the agent.
