# Agent quick start

> **EXPERIMENTAL.** Agent mode is implemented but not yet validated for production use.

Goal: an AI agent logs in to one site with your passkey, through Playwright MCP, without you
touching the keyboard. About five minutes. Everything below is for the user daemon (`systemctl
--user`) with the `same-user` mode. For an agent with its own identity see [Isolated mode](isolated.md).

**You need:** Linux, a Passless build with agent support, Node.js (for `npx`), bubblewrap (`bwrap`),
a Chromium (Playwright's Chromium, Chrome for Testing or your distribution's `chromium`; see
[Containment and supported browsers](containment.md)) and a passkey for the site already stored in
Passless.

```bash
cargo install --path cmd/passless --features agent   # passless and sign-proxy
```

## 1. Allow one site

Add this to `~/.config/passless/config.toml`. Replace `alice` with your user name and `github.com`
with the site's RP ID (usually its domain). Use absolute paths.

```toml
[agents]
enabled = true
audit_path = "/home/alice/.local/state/passless/agent-audit"

[agents.profiles.coding]
mode = "same-user"
principal_user = "alice"
browser_cdp_expose = "port"
max_session_ttl = 3600

[[agents.profiles.coding.rules]]
rp_id = "github.com"
authenticate = "allow"
register = "deny"
```

```bash
mkdir -p -m 700 ~/.local/state/passless/agent-audit
```

An exact `allow` rule lets the agent sign in to that site with no prompt, and nothing else:
every other site is denied. Prefer `authenticate = "request"` if you want a desktop prompt the
first time instead; see [Rules](rules.md). `browser_cdp_expose = "port"` is what the easy path
uses: it makes the managed browser's debugging port reachable on loopback, which is full control of
that browser for any local process that finds it (see [Containment](containment.md#cdp-port-mode)).

## 2. Restart the daemon and check the host

```bash
systemctl --user restart passless
passless doctor --agents
```

`doctor --agents` should report a browser binary, `containment: required and in place`, the
extension and the native host. A `warn` for the notification bus only matters for `request` rules.

## 3. Add the MCP server to your client

```bash
passless agent mcp --print-config claude-code
```

Paste the printed entry into the client's MCP configuration (for Claude Code, `.mcp.json`; the
command also prints a `claude mcp add-json` one-liner). Other clients: `opencode`, `cursor`,
`vscode`. The entry runs `passless agent mcp playwright --profile coding`, which starts a
Passless-managed Chromium on the first browser tool call and points Playwright MCP at it.

## 4. Use it

Ask the agent to open the site, click its explicit "Sign in with a passkey" button and report what
it sees. The page's WebAuthn call is signed by the daemon; the agent never sees a key. Passkey
autofill (conditional mediation) is unavailable, so the page needs a sign-in button. See the
[agent skill](../../cmd/passless/assets/skills/passless-agent/SKILL.md) for what the agent is told, and
[Browser tools](browser-tools.md) for other clients and tools.

Review what happened with `passless agent-admin audit export --format json` ([Audit](audit.md)).
