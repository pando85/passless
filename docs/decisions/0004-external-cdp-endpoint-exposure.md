# ADR 0004: Agent Browser Trust Models and CDP Exposure

## Status

Proposed

## Context

Agent mode launches a managed browser with `--remote-debugging-pipe`, making CDP
accessible exclusively through the daemon's pipe-based proxy (`browser-control`).
This prevents external tools (Playwright MCP, Puppeteer, native DevTools clients)
from attaching to the authenticated browser session.

Coding agents need rich browser interaction (accessibility snapshots, element
targeting, auto-waiting) that raw CDP JSON over `browser-control` cannot provide.

The current architecture enforces a single security posture (full isolation).
Operators need a spectrum: from fully isolated multi-user deployments to
single-user workstations where the agent is fully trusted.

## Decision

Define two browser trust models for delegated-session profiles, selectable via
configuration. The credential ceremony (WebAuthn assertion) is always mediated
by passless in both models — the trust boundary is about what happens *after*
authentication.

---

### Trust Model 1: Isolated (default, `browser_cdp_expose = "pipe"`)

The agent interacts with the browser exclusively through the daemon's mediated
CDP proxy. Suitable for multi-user systems, production environments, and
untrusted or partially-trusted agents.

**Properties:**

- `browser_user` must differ from `principal_user` (separate Unix user)
- CDP transport: Unix pipes (fd 3/4), no network endpoint
- Every CDP command passes through the daemon (filtering + audit)
- `browser-control` is the only interface; raw CDP JSON per command
- Agent cannot attach external tools to the browser
- Browser process is sandboxed: `close_range()`, `RLIMIT_NOFILE`, `setsid()`,
  `PR_SET_NO_NEW_PRIVS`, uid/gid drop

**Threat model:**

| Threat | Mitigation |
|--------|-----------|
| Compromised browser accesses credentials | Separate user; no access to pass store or daemon pipes |
| Agent exfiltrates session material | Daemon filters CDP commands; audit trail |
| Remote network access to CDP | No network endpoint exists |
| Cross-user access | Unix user isolation + file permissions |

**Agent workflow:**

```
passless agent delegation request → WebAuthn ceremony → daemon-mediated CDP
```

The agent sends individual CDP commands via `browser-control`. No Playwright,
no Puppeteer, no external DevTools.

---

### Trust Model 2: Trusted (`browser_cdp_expose = "port"`)

The agent connects directly to the browser's CDP WebSocket endpoint using
standard tooling (Playwright MCP, Puppeteer). Suitable for single-user
workstations where the operator fully trusts the agent.

**Properties:**

- `browser_user` may equal `principal_user` or be omitted (same-user mode)
- CDP transport: TCP port on 127.0.0.1 (Chromium `--remote-debugging-port`)
- No daemon mediation of CDP commands after the ceremony
- External tools attach via `connectOverCDP(ws://...)`
- Full Playwright MCP capabilities: snapshots, clicks, typing, navigation
- The WebSocket path UUID acts as a bearer token
- `cdp-endpoint` file (mode 0600) carries the URL

**Threat model:**

| Threat | Mitigation |
|--------|-----------|
| Remote network access | Chromium binds 127.0.0.1 only |
| Cross-user local access | `cdp-endpoint` file mode 0600 + runtime dir 0700 |
| Same-user process access | **Accepted risk.** Same trust boundary as the principal session |
| Credential theft via CDP | Passless still mediates the WebAuthn ceremony; credentials never leave the daemon. The browser only holds the authenticated *session* (cookies), not the credential keys |
| Agent exfiltrates session | **Accepted risk.** Operator trusts the agent. Audit records the delegation grant and lease creation |

**What passless still controls in trusted mode:**

- The WebAuthn assertion (credential private key never leaves passless)
- Delegation grant lifecycle (one-shot, TTL-bounded)
- Lease expiry (browser killed when TTL expires)
- Audit trail (delegation requested, granted, browser launched, lease expired)
- Revocation (operator can revoke delegation or kill lease at any time)

**What the agent gains:**

- Direct CDP access after the ceremony
- Full Playwright MCP integration (snapshots, element refs, auto-waiting)
- No per-command daemon round-trip
- Standard DevTools protocol (any CDP client works)

**Agent workflow:**

```
passless agent delegation request → WebAuthn ceremony → browser launched with port
→ agent reads cdp-endpoint → Playwright connectOverCDP → full browser control
→ lease expires or delegation revoked → browser killed
```

---

### Configuration

```toml
[agents.profiles.<id>]
browser_cdp_expose = "pipe"   # "pipe" (default, isolated) | "port" (trusted)
browser_cdp_port = 0          # port mode only; 0 = ephemeral, or fixed e.g. 9222
```

When `browser_cdp_expose = "port"`:

- `browser_user` may equal `principal_user` or be omitted (defaults to principal)
- `browser_cdp_port` is optional (0 = OS assigns ephemeral port)

When `browser_cdp_expose = "pipe"` (or unset):

- All existing constraints apply (`browser_user` must differ, etc.)

### Behaviour (port mode)

1. Browser launched with `--remote-debugging-port=<port>` instead of
   `--remote-debugging-pipe`. Pipe creation and fd-dup2 are skipped.
2. Chromium binds to `127.0.0.1` only (default; no `--remote-debugging-address`).
3. After spawn, daemon reads `DevToolsActivePort` from the browser profile
   directory to discover the actual port and WebSocket path.
4. Daemon writes the full WebSocket URL to `<runtime_dir>/cdp-endpoint`
   (mode 0600, owned by principal user).
5. `browser-status` response includes a `cdp_endpoint` field with the URL.
6. `browser-control` returns an error directing the caller to use the exposed
   endpoint directly.
7. Audit records note the exposure mode at lease creation.

### Proxy mode (future, `browser_cdp_expose = "proxy"`)

A middle ground for environments that want Playwright but with daemon mediation:

- Keep pipe mode internally
- Expose a Unix domain socket at `<runtime_dir>/cdp.sock` (mode 0600)
- Daemon proxies WebSocket frames to/from the pipe
- CDP command filtering and audit remain active
- Playwright connects via a CDP-over-Unix-socket adapter

Out of scope for this ADR. The config enum accommodates it.

---

### Security comparison

| Property | Isolated (pipe) | Trusted (port) | Proxy (future) |
|----------|----------------|----------------|----------------|
| CDP transport | Unix pipes | TCP 127.0.0.1 | Unix socket |
| Daemon mediation | Every command | Ceremony only | Every command |
| External tool attachment | No | Yes (Playwright, etc.) | Yes (via adapter) |
| browser_user isolation | Required | Optional | Required |
| CDP command audit | Per-command | Lease-level only | Per-command |
| CDP command filtering | Yes | No | Yes |
| Credential key exposure | Never | Never | Never |
| Session cookie exposure | Daemon-gated | Direct | Daemon-gated |
| Trust assumption | Agent is untrusted | Agent is trusted | Agent is partially trusted |

## Consequences

- Port mode is a reduced-security mode: any same-user process with the WebSocket
  URL can control the browser session. This is acceptable for single-user
  workstations where the agent and operator share a trust boundary.
- Pipe mode remains the default and recommended mode for multi-user or
  production environments.
- No new dependencies required for port mode: reading `DevToolsActivePort` is a
  file read; writing `cdp-endpoint` is a file write.
- The `browser-control` command becomes unavailable in port mode (no pipes).
- The credential private key never leaves passless in either model. The trust
  boundary is about the authenticated *session*, not the credential material.
