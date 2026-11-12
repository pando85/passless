# Agent quick start

> **EXPERIMENTAL.** Agent mode is implemented but not yet validated for production use.

Goal: an AI agent logs in to one site with your passkey, through Playwright MCP, without you
touching the keyboard. About five minutes. Everything below is for the user daemon (`systemctl
--user`) with the `same-user` mode. For an agent with its own identity see [Isolated mode](isolated.md).

**You need:**

- Linux, a Passless build with agent support, and Passless **installed and running as your user
  service**: `systemctl --user enable --now passless.service`, which needs the `uhid` and group setup
  of the README's [First-run setup](../../README.md#first-run-setup). `systemctl --user is-active
  passless` should print `active`.
- Node.js (for `npx`) and network access: the first browser tool call runs `npx --yes
  @playwright/mcp`, which downloads that package if it is not cached.
- bubblewrap (`bwrap`).
- A Chromium (Playwright's Chromium, Chrome for Testing or your distribution's `chromium`; see
  [Containment and supported browsers](containment.md)).
- A passkey for the site, already stored in Passless: see below.

```bash
cargo install --path cmd/passless --features agent   # passless and sign-proxy
```

`cargo install` puts `passless` and `sign-proxy` in `~/.cargo/bin`; keep them in the same directory.

**The passkey.** The profile below sets `register = "deny"`, so the agent cannot create one. Register
the passkey once yourself, as a human: in your normal browser, with Passless running as your
authenticator, add a passkey to the site's account settings and approve the prompt. Passless stores
it in your credential store, and the agent then signs in with it. To let an agent register passkeys on
its own, see [Registration](rules.md#registration) (it is off by default for good reason).

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

## 2. Restart the daemon, then check the host

The daemon reads the config only at start, so a changed config needs a restart:

```bash
systemctl --user restart passless
```

`doctor --agents` checks the host (browser, containment, extension, native host, notification bus,
state directory) from the config file and needs no daemon for those lines. Because agents are
enabled it also pings the daemon's agent socket (`agent_subsystem`) and fails if the daemon is not
running or runs without agents; the log then says `Agent subsystem failed to start` and why.

```bash
passless doctor --agents
```

Expect `ok` for `agent_subsystem`, `browser_binary`, `containment`, `extension` and
`native_host_manifest`. The `containment` line reads `required and in place` only while the daemon's
UHID device exists (the browser's user could open its hidraw node, so the private `/dev` is needed);
otherwise it reads `in place as defence in depth`, which is fine. A `warn` for the notification bus
only matters for `request` rules.

## 3. Add the MCP server to your client

```bash
passless agent mcp --print-config claude-code
```

Paste the printed entry into the client's MCP configuration (for Claude Code, `.mcp.json`; the
command also prints a `claude mcp add-json` one-liner). Other clients: `opencode`, `cursor`,
`vscode`. The entry runs `passless agent mcp playwright --profile coding`, which starts a
Passless-managed Chromium on the first browser tool call and points Playwright MCP at it.

The entry's `command` is the absolute path of the `passless` you ran (for a `cargo install`,
`~/.cargo/bin/passless`), so the client needs nothing on its `PATH`. If you move or reinstall the
binary, print the entry again; if passless cannot tell its own path, the entry says `passless`, which
then has to be on the MCP client's `PATH`.

## 4. Use it

Ask the agent to open the site, click its explicit "Sign in with a passkey" button and report what
it sees. The page's WebAuthn call is signed by the daemon; the agent never sees a key. Passkey
autofill (conditional mediation) is unavailable, so the page needs a sign-in button. See the
[agent skill](../../cmd/passless/assets/skills/passless-agent/SKILL.md) for what the agent is told, and
[Browser tools](browser-tools.md) for other clients and tools.

The first tool call is slow: it runs `npx --yes @playwright/mcp` (Node and network, see above) and
starts the browser. The browser is headless (`--headless=new`) by default. For a visible window set
`browser_command` on the profile to the browser's absolute path with no arguments, for example
`browser_command = ["/usr/bin/chromium"]`, and restart the daemon: a profile's `browser_command` gets
no default flag, so no `--headless=new` is added. The daemon must be able to reach your display for
that. See [Containment](containment.md#supported-browsers).

## 5. Review what happened

```bash
passless agent-admin audit export --format json
```

This prints a JSON envelope, not the entries:
`{"version":"1","status":"ok","data":{"entry_count":N,"format":"json","path":"<audit_path>/audit-export-<unix time>.jsonl"}}`.
The entries are in the file `path` names, under `audit_path`, as JSON Lines: one object per line with
`sequence`, `wall_time_ms`, `monotonic_ms` and `event`. Read it with `jq` or one line at a time. With
`--format csv` the file is `.csv`. See [Audit](audit.md).
