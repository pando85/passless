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

Define two browser trust models for agent profiles, selectable via
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
passless agent intent/delegation → WebAuthn ceremony → daemon-mediated CDP
```

The agent sends individual CDP commands via `browser-control`. No Playwright,
no Puppeteer, no external DevTools.

---

### Trust Model 2: Trusted (`browser_cdp_expose = "port"`)

The agent connects directly to the browser's CDP WebSocket endpoint using
standard tooling (Playwright MCP, Puppeteer). Suitable for single-user
workstations where the operator fully trusts the agent and other local
processes in the same host trust boundary.

**Properties:**

- `browser_user` may equal `principal_user` or be omitted (same-user mode)
- CDP transport: TCP port on 127.0.0.1 (Chromium `--remote-debugging-port`)
- No daemon mediation of CDP commands after browser provisioning
- External tools attach via `connectOverCDP(...)`
- Full Playwright MCP capabilities: snapshots, clicks, typing, navigation
- The DevTools WebSocket path is discovery data, not an authorization boundary
- `cdp-endpoint` file (mode 0600) is a convenience for endpoint discovery

**Threat model:**

| Threat | Mitigation |
|--------|-----------|
| Remote network access | Chromium is constrained to loopback |
| Cross-user local access | **Accepted risk.** TCP loopback has no Unix-user ACL; a local process that discovers the port can attempt CDP access |
| Same-user process access | **Accepted risk.** Same trust boundary as the principal session |
| Credential theft via CDP | Passless still mediates WebAuthn; credential private keys never leave the daemon. The browser holds authenticated session state, not credential keys |
| Agent exfiltrates session | **Accepted risk.** Operator trusts the agent; audit records browser/delegation lifecycle |

A mode-0600 endpoint file and the randomized DevTools path reduce accidental
disclosure but do not turn a loopback TCP listener into a per-user security
boundary. Do not use trusted port mode as cross-user isolation.

**What passless still controls in trusted mode:**

- The WebAuthn assertion (credential private key never leaves passless)
- Grant/session lifecycle and TTLs
- Browser lease expiry and process cleanup
- Audit trail for lifecycle operations
- Revocation and principal-session teardown

**What the agent gains:**

- Direct CDP access to its managed browser
- Full Playwright MCP integration (snapshots, element refs, auto-waiting)
- No per-command daemon round-trip
- Standard DevTools protocol (any compatible CDP client works)

---

### Configuration

```toml
[agents.profiles.<id>]
browser_cdp_expose = "pipe"   # "pipe" (default, isolated) | "port" (trusted)
browser_cdp_port = 0          # port mode only; 0 = ephemeral, or fixed e.g. 9222
```

When `browser_cdp_expose = "port"`:

- `browser_user` may equal `principal_user` or be omitted (defaults to principal)
- `browser_cdp_port` should normally be 0 so Chromium selects an ephemeral port

When `browser_cdp_expose = "pipe"` (or unset):

- All existing isolation constraints apply

### Behaviour (port mode)

1. Browser is launched with `--remote-debugging-port=<port>` instead of
   `--remote-debugging-pipe`. Pipe creation and fd-dup2 are skipped.
2. Chromium is exposed on loopback only; passless never intentionally publishes
   this listener on a non-loopback interface.
3. After spawn, the daemon reads `DevToolsActivePort` from the browser profile
   directory to discover the actual port and WebSocket path.
4. `browser-status` can return the discovered `cdp_endpoint`.
5. `browser-control` returns an error directing the caller to use the exposed
   endpoint directly.
6. Audit records note direct-CDP authority at the lease/session level.

### Playwright MCP lazy discovery

Playwright MCP uses a small native Passless HTTP bootstrap rather than a CDP
WebSocket relay.

```text
Playwright MCP
    |
    | GET /json/version + ephemeral bearer token
    v
Passless bootstrap (127.0.0.1:<ephemeral>)
    |
    | PrincipalRequest::EnsureBrowser
    v
Passless agent runtime
    |
    | reuse same-session lease or launch trusted-port Chromium
    v
Chromium (127.0.0.1:<ephemeral>)
    ^
    |
    +------------ direct CDP WebSocket ------------ Playwright MCP
```

The bootstrap has deliberately narrow semantics:

- `GET /healthz` is side-effect free.
- `GET /json/version` and `/json/version/` authenticate first, then call the
  principal-scoped `EnsureBrowser` operation.
- `EnsureBrowser` is dispatched only after the normal principal capability,
  peer-credential, process-identity, namespace/cgroup, and ancestry checks.
- `EnsureBrowser` is valid only for profiles explicitly configured with
  `browser_cdp_expose = "port"`.
- Lifecycle is single-flight under the profile lifecycle lock.
- A healthy browser is reused only when it belongs to the requesting principal
  session; an admin/unowned or different-session lease is never adopted.
- The bootstrap returns Chromium's real `webSocketDebuggerUrl`; it never proxies
  WebSocket frames and never rewrites `/json/list` targets.
- The bootstrap bearer token is ephemeral and prevents unauthenticated callers
  from triggering lazy startup through the discovery service. It does **not**
  protect the underlying Chromium CDP listener from a local actor that discovers
  that listener independently.
- The supervised Playwright child does not inherit the Passless principal
  capability file descriptor.

The browser starts on the first authenticated Playwright discovery request, not
when the MCP wrapper starts. The bootstrap server is destroyed when the
supervised MCP process exits; the browser remains governed by the existing
principal-session/lease lifecycle.

This avoids adding a second CDP transport implementation to Passless. In
particular there is no Node relay, WebSocket frame conversion, relay queue,
backpressure state, target-URL rewriting, or detached relay process.

### Proxy mode (future, `browser_cdp_expose = "proxy"`)

A middle ground for environments that want Playwright but with daemon mediation:

- Keep pipe mode internally
- Expose an authenticated streaming endpoint with OS-level access control
- Proxy asynchronous CDP messages/events to and from the browser pipe
- Preserve CDP command filtering and audit
- Define client ownership, multiplexing, cancellation, queue limits, and
  backpressure explicitly

The existing finite `browser-control` request/response operation is not a
streaming transport and must not be used as a frame-by-frame Playwright relay.
This mode remains out of scope for this ADR implementation.

---

### Security comparison

| Property | Isolated (pipe) | Trusted (port) | Proxy (future) |
|----------|----------------|----------------|----------------|
| CDP transport | Unix pipes | TCP 127.0.0.1 | Authenticated local stream |
| Daemon mediation | Every command | Lifecycle/ceremony only | Every command |
| External tool attachment | No | Yes (Playwright, etc.) | Yes (via adapter) |
| browser_user isolation | Required | Not a CDP boundary | Required |
| CDP command audit | Per-command | Lease-level only | Per-command |
| CDP command filtering | Yes | No | Yes |
| Credential key exposure | Never | Never | Never |
| Session cookie exposure | Daemon-gated | Direct | Daemon-gated |
| Trust assumption | Agent/local peers untrusted | Local environment trusted | Agent partially trusted |

## Consequences

- Port mode is a reduced-security mode: local processes able to discover/reach
  Chromium's loopback debugging listener can obtain full browser-session
  authority. This is acceptable only where the local environment is trusted.
- The Playwright bootstrap improves lifecycle and discovery hygiene but is not a
  security wrapper around Chromium's direct CDP port.
- Pipe mode remains the default and recommended mode when local/multi-user
  isolation is required.
- The lazy Playwright integration adds no WebSocket stack to Passless and no
  Node/npm dependency to the Passless package itself.
- The Playwright MCP executable remains an external, operator-managed dependency
  and should be version-pinned by the deployment.
- `browser-control` remains unavailable in port mode.
- The credential private key never leaves passless in either model. The trust
  boundary is about authenticated browser-session authority, not credential
  material.
