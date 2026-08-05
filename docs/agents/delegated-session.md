# Delegated-session mode

> **EXPERIMENTAL** — Agent mode is not yet validated for production use.
> Autonomous (`allow`) assertions for delegated sessions are being redesigned to use a
> daemon-loaded MV3 extension and localhost daemon signing channel instead of a UHID ceremony.
> The `confirm` path remains an explicit human prompt. Implementation is **in progress**.

Delegated-session mode permits exact-policy authentication using configured human credentials and,
when explicitly selected, registration into the human store. The RP sees the same account context
as ordinary use by the human.

## How delegated-session mode works

```
┌──────────────────────────────────────────────────────────────────┐
│                       Passless Daemon (root)                      │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  Delegated Profile: "opencode"                              │ │
│  │                                                              │ │
│  │  ┌──────────────────┐   ┌────────────────────────────────┐  │ │
│  │  │ Agent UHID        │   │ Human Credential Store         │  │ │
│  │  │ Endpoint          │   │ (filtered view: 1 credential)  │  │ │
│  │  │ /dev/hidraw*      │   │                                │  │ │
│  │  └─────────┬─────────┘   └────────────────────────────────┘  │ │
│  │            │                                                  │ │
│  │  ┌─────────┴──────────────────────────────────────────────┐  │ │
│  │  │  Policy Engine                                          │  │ │
│  │  │  rp_id="github.com"                                     │  │ │
│  │  │  authenticate: allow / policy UP / policy UV            │  │ │
│  │  └─────────────────────────────────────────────────────────┘  │ │
│  │                                                               │ │
│  │  ┌────────────────────┐  ┌─────────────────────────────────┐ │ │
│  │  │ One-shot Grant     │  │ Browser Lease                   │ │ │
│  │  │ (consumed after    │  │ (ephemeral profile,             │ │ │
│  │  │  one assertion)    │  │  auto-destroyed on expiry)      │ │ │
│  │  └────────────────────┘  └─────────────────────────────────┘ │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  Autonomous path (allow):                                   │ │
│  │  MV3 extension → MAIN-world origin read → localhost sign    │ │
│  │  channel → daemon validates origin/grant/policy → sign      │ │
│  └─────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
         ▲                              ▲
         │ CTAP                         │ CDP (pipe or port)
         │                              │
┌────────┴────────┐          ┌──────────┴──────────┐
│  Agent Process  │          │  Ephemeral Browser   │
│  (principal     │          │  (browser user)      │
│   user)         │          │                      │
└─────────────────┘          └──────────────────────┘
```

## Semantics

- The delegated credential is the same user credential. The RP cannot distinguish agent
  use from human use.
- One grant authorizes one passkey login, not all WebAuthn operations during the browser
  lease.
- A later WebAuthn operation requires another grant and fresh ceremony evidence.
- Local browser-lease expiry is not RP-side session revocation.

## Configuration

```toml
[agents.profiles.opencode]
mode = "delegated-session"
principal_user = "passless-opencode"
credential_refs = ["<credential-ref-hex>"]
delegated_registration_storage = "human"
max_grant_ttl = 120
max_session_ttl = 900
browser_command = ["firefox", "--profile", "<daemon-managed>"]
start_url = "https://github.com/dashboard"
browser_user = "passless-browser"
browser_runtime_root = "/var/run/passless-browser"

[[agents.profiles.opencode.rules]]
rp_id = "github.com"
register = { authorization = "confirm", user_presence = "human", user_verification = "human" }
authenticate = { authorization = "allow", user_presence = "policy", user_verification = "policy" }

[agents.profiles.opencode.device]
name = "passless-agent-opencode"
phys = "opencode-phys"
uniq = "opencode-uniq"
vendor_id = 4660
product_id = 22136
```

- `browser_user` must differ from `principal_user`.
- `browser_runtime_root` must be owned by `browser_user` with mode 0700; the principal never sees the filesystem path.
- `credential_refs` are non-secret SHA-256 digests over credential IDs.

## Workflow

1. Operator validates configuration:
   ```bash
   passless agent-admin profile check opencode
   ```
2. Operator launches the principal session:
   ```bash
   passless agent run --profile opencode -- /usr/local/bin/agent-command
   ```

   The `agent run` command requires an absolute executable path owned by root,
   attaches stdio to the principal process, and waits for it to exit. See
   [isolated mode](isolated.md#agent-run-behavior) for details.

3. Inside the session, the principal requests delegation:
   ```bash
   passless agent --profile opencode delegation request \
     --rp github.com --credential <credential-ref-hex> \
     --session-ttl 900 --reason "CI deploy"
   ```
4. The daemon launches an ephemeral browser and evaluates the exact authentication rule.
5. An `allow` rule is resolved autonomously by the daemon's policy check with no desktop
   notification. A `confirm` rule is not auto-signed and remains an explicit human prompt path.
   A `deny` rule fails closed. The configured UP/UV sources are recorded in audit.
   The autonomous path uses a daemon-loaded MV3 extension that reads the frame origin via a
   MAIN-world override and forwards the request to the daemon over a localhost bearer channel;
   the daemon validates origin, grant, policy, credential ref, and audit before signing.
   Implementation is **in progress**.
6. The local browser lease starts at the clamped monotonic deadline.
7. The grant and delegated credential view are consumed after the assertion.

## Local lease vs RP revocation

The local browser lease controls how long Passless keeps the ephemeral browser available.
It does not alter the RP's cookie lifetime or prove that the RP invalidated its server-side
session. If compromise or session copying is suspected, instruct users to revoke RP
sessions through RP controls.

## Browser lease lifecycle

- Starts no earlier than successful CTAP assertion completion.
- Uses a daemon-owned monotonic deadline.
- Terminates on expiry, revocation, browser exit, principal exit, or daemon shutdown.
- The ephemeral profile is removed after browser termination.
- A profile whose cleanup fails is quarantined and never reused.

## Revocation

```bash
passless agent-admin delegation list --profile opencode
passless agent-admin delegation revoke <grant-id> --confirm
passless agent-admin session revoke <session-id> --confirm
```

## Trusted (port) mode

By default, delegated-session mode uses pipe-based CDP transport (`browser_cdp_expose = "pipe"`).
The daemon mediates every CDP command through Unix pipes, and `browser_user` must differ from
`principal_user`.

Setting `browser_cdp_expose = "port"` switches to a trusted trust model where the agent connects
directly to the browser's CDP WebSocket endpoint. This enables external tools like Playwright MCP,
Puppeteer, and native DevTools clients.

### Configuration

```toml
[agents.profiles.opencode]
mode = "delegated-session"
principal_user = "alice"
browser_cdp_expose = "port"
browser_cdp_port = 9222
credential_refs = ["<credential-ref-hex>"]
max_grant_ttl = 120
max_session_ttl = 900
browser_command = ["chromium", "--user-data-dir", "<daemon-managed>"]
start_url = "https://github.com/dashboard"
browser_runtime_root = "/var/run/passless-browser"

[[agents.profiles.opencode.rules]]
rp_id = "github.com"
register = { authorization = "deny", user_presence = "none", user_verification = "none" }
authenticate = { authorization = "allow", user_presence = "policy", user_verification = "policy" }

[agents.profiles.opencode.device]
name = "passless-agent-opencode"
phys = "opencode-phys"
uniq = "opencode-uniq"
vendor_id = 4660
product_id = 22136
```

- `browser_user` is optional; if omitted, defaults to `principal_user`.
- `browser_cdp_port` is optional; 0 (default) lets the OS assign an ephemeral port.
- `browser_command` extra args must not include `--remote-debugging-port` or
  `--remote-debugging-address`; the daemon sets these automatically.

### Workflow

1. Operator configures the profile with `browser_cdp_expose = "port"`.
2. Operator launches the principal session:
   ```bash
   passless agent run --profile opencode -- /usr/local/bin/agent-command
   ```
3. Inside the session, the principal requests delegation:
   ```bash
   passless agent --profile opencode delegation request \
     --rp github.com --credential <credential-ref-hex> \
     --session-ttl 900 --reason "Playwright automation"
   ```
4. The daemon performs the WebAuthn ceremony (confirm-policy human prompt) or, for allow-policy
   assertions, loads an MV3 extension that routes the assertion through the daemon signing
   channel. Chromium is launched with
   `--remote-debugging-port=<N> --remote-debugging-address=127.0.0.1`.
5. The daemon reads Chromium's `DevToolsActivePort` file to discover the WebSocket URL.
6. The daemon writes the full WebSocket URL to `<runtime_dir>/cdp-endpoint`
   (mode 0600, owned by principal user).
7. The agent reads the CDP endpoint and connects with Playwright:
   ```javascript
   const browser = await chromium.connectOverCDP('ws://127.0.0.1:9222/devtools/browser/<uuid>');
   ```
8. The agent has full browser control: snapshots, clicks, typing, navigation.
9. Lease expiry or revocation kills the browser process.

### What changes in port mode

- `browser-control` returns an error directing the caller to use the CDP endpoint directly.
- `browser-status` includes a `cdp_endpoint` field with the WebSocket URL.
- No daemon mediation of CDP commands after the ceremony.
- Audit records the exposure mode at lease creation.
- The credential private key never leaves the daemon; only the authenticated session (cookies)
  is exposed to the agent.

### When to use port mode

- Single-user workstations where the operator fully trusts the agent.
- Automation that requires rich browser interaction (Playwright MCP, accessibility snapshots,
  element targeting, auto-waiting).
- Environments where per-command daemon round-trips are unacceptable.

Do not use port mode for multi-user systems, production environments, or untrusted agents.
Use pipe mode instead. See [security](security.md#port-mode-threat-model) for the full threat model.
