# Playwright MCP

Passless can run Playwright MCP against a managed Chromium browser without proxying Chrome DevTools Protocol (CDP) traffic.

This integration is intentionally restricted to the trusted CDP port model. It does **not** weaken the default isolated `pipe` mode and it does not turn the Passless daemon into a WebSocket proxy.

## Trust model

A profile must explicitly opt into direct CDP exposure:

```toml
[agents.profiles.coding]
browser_cdp_expose = "port"
browser_cdp_port = 0
```

Keep `browser_cdp_port = 0` unless a fixed port is operationally required. Chromium then chooses an ephemeral loopback port.

`port` mode gives local processes that can reach/discover the Chromium debugging endpoint full browser-session authority. The bootstrap bearer token protects lazy discovery and startup; it is **not** a substitute for the process isolation provided by `pipe` mode. Use this integration only for profiles whose local execution environment is trusted accordingly.

## Running Playwright MCP

Use an absolute path for the external Playwright MCP executable:

```bash
passless agent playwright-mcp \
  --profile coding \
  -- /usr/bin/npx --yes @playwright/mcp@<pinned-version>
```

Passless deliberately does not install Node.js, npm packages, or `@playwright/mcp`. Pin and manage the Playwright MCP version through the normal software-management mechanism for the host.

The command performs two phases automatically:

1. If it is not already running inside a Passless principal session, Passless launches the same command through the normal `agent run` mechanism for the requested profile.
2. Inside that verified principal session, Passless starts an ephemeral authenticated HTTP bootstrap endpoint and supervises the external Playwright MCP process.

The Playwright process does not inherit the Passless principal capability file descriptor.

## Lazy startup flow

```text
Playwright MCP
    |
    | GET /json/version
    | Authorization: Bearer <ephemeral token>
    v
Passless HTTP bootstrap (127.0.0.1:<ephemeral>)
    |
    | PrincipalRequest::EnsureBrowser
    v
Passless agent runtime
    |
    | reuse this session's healthy lease
    |          or
    | launch managed Chromium in trusted port mode
    v
Chromium (127.0.0.1:<ephemeral>)
    ^
    |
    +---------- direct CDP WebSocket ---------- Playwright MCP
```

The browser is not started when the wrapper starts. It is started on the first authenticated `/json/version` discovery request from Playwright.

`GET /healthz` is side-effect free and never starts a browser.

## Bootstrap behavior

The bootstrap server:

- binds only to IPv4 loopback on an ephemeral port;
- accepts only `GET` requests;
- limits request headers to 16 KiB;
- enforces read and write deadlines;
- limits concurrent request workers;
- requires a random bearer token for `/json/version` and `/json/version/`;
- authenticates before any browser lifecycle operation;
- returns only a loopback `ws://.../devtools/browser/...` endpoint;
- sends `Cache-Control: no-store`;
- does not implement `/json/list`;
- does not accept or relay WebSocket connections.

After discovery, all CDP traffic goes directly between Playwright and Chromium.

## Browser ownership

`EnsureBrowser` is a principal-scoped protocol operation. The runtime verifies the ordinary principal capability, peer credentials, process identity, cgroup/namespace identity, and ancestry before the operation is dispatched.

For a profile, the operation is single-flight under the existing lifecycle lock. It:

- reuses a healthy browser only when that browser belongs to the same principal session;
- refuses to adopt a browser owned by another session or an unowned/admin-launched browser;
- cleans up stale owned leases before replacement;
- binds the new lease to the current principal session;
- requires `browser_cdp_expose = "port"`.

When the principal session terminates or expires, the existing Passless session cleanup path revokes and terminates its browser lease. The HTTP bootstrap itself exists only for the lifetime of the supervised Playwright MCP process.

## Why there is no CDP relay

Playwright accepts an HTTP CDP endpoint and performs browser discovery through `/json/version`. Passless therefore only needs to return Chromium's real `webSocketDebuggerUrl` after lazy browser provisioning.

Keeping Passless out of the WebSocket data path avoids a second CDP transport implementation, frame-type conversion issues, relay buffering/backpressure state, target URL rewriting, and a persistent relay process.

A future Playwright integration for isolated `pipe` mode is a separate security design. It would require a real authenticated streaming CDP proxy with explicit multiplexing, event routing, backpressure, filtering, auditing, cancellation, and client-ownership semantics; the finite `browser-control` request/response API is not such a transport.

## MCP client configuration

For clients that accept a local command, configure the Passless wrapper itself as the MCP command. Example shape:

```json
{
  "mcp": {
    "playwright": {
      "command": "passless",
      "args": [
        "agent",
        "playwright-mcp",
        "--profile",
        "coding",
        "--",
        "/usr/bin/npx",
        "--yes",
        "@playwright/mcp@<pinned-version>"
      ]
    }
  }
}
```

Adapt the `command`/`args` shape to the MCP client in use. The external Playwright executable after `--` must be absolute.

## Troubleshooting

`Playwright browser discovery requires browser_cdp_expose = 'port'` means the profile is using the safer default pipe mode. Do not switch modes merely to silence the error; switch only when direct local browser authority is acceptable for that profile.

`profile browser is owned by another principal session` or `a live browser exists ... but is not owned by this principal session` means Passless intentionally refused ambiguous browser authority. End the old session/browser through normal administrative lifecycle controls before retrying.

`managed browser endpoint unavailable` is intentionally generic on the bootstrap HTTP surface. Inspect Passless logs for the policy, configuration, or browser-launch error that caused it.
