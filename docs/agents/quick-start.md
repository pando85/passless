# Agent quick start

> **EXPERIMENTAL.** Agent mode is implemented but not yet validated for production use.

Goal: an AI agent logs in to one site with your passkey, through Playwright MCP, without you
touching the keyboard. About five minutes. Everything below is for the user daemon (`systemctl
--user`) with the `same-user` mode. For an agent with its own identity see [Isolated mode](isolated.md).

> **What you are granting.** A same-user profile with an `allow` rule lets the agent sign in as you at
> that site with no prompt, and in CDP port mode (the easy path below) it controls the managed browser
> completely. After the login the agent holds your logged-in session there: it can do whatever your
> account can, including creating tokens or SSH keys that outlive the browser and the session.
> Passless limits who signs in, where and for how long, not what happens afterwards. Read the
> [security model](security.md) and [same-user mode](same-user.md) first, and prefer `request`, an
> exact site and a short `max_session_ttl`. New to the terms (RP ID, CDP, principal session, lease)?
> See the [glossary](README.md#glossary).

**You need:**

- Linux, a Passless build with agent support, and Passless **installed and running as your user
  service**: `systemctl --user enable --now passless.service`, which needs the `uhid` and group setup
  of the README's [First-run setup](../../README.md#first-run-setup). `systemctl --user is-active
  passless` should print `active`.
- Agent support in the build. Release tarballs (`make release`) and both AUR packages are built with
  `--all-features`, so they include it; `cargo install` needs `--features agent` (below).
  `passless agent --help` confirms it: a build without agent support rejects the subcommand.
- Node.js (for `npx`) and network access. The first browser tool call runs `npx --yes
  @playwright/mcp`, which downloads that package if it is not cached.
- bubblewrap (`bwrap`).
- A Chromium. The simplest is Playwright's: `npx playwright install chromium` (it downloads a browser,
  so it needs the network too). Chrome for Testing or your distribution's `chromium` also work; branded
  Google Chrome and `chrome-headless-shell` do not. See [Containment and supported
  browsers](containment.md#supported-browsers).
- A desktop notification server, if you use `request` rules (not needed for `allow`): see [which ones
  work](../NOTIFICATIONS.md#supported-notification-servers).
- A passkey for the site, already stored in Passless: see below.

```bash
cargo install --path cmd/passless --features agent   # passless and sign-proxy
```

`cargo install` puts `passless` and `sign-proxy` in `~/.cargo/bin`; keep them in the same directory.

**The passkey.** The profile below sets `register = "deny"`, so the agent cannot create one: you
register the passkey once, as a human, and the agent then signs in with it. Do it in your normal
browser (not the managed one), with Passless running, so the browser talks to Passless over UHID as if
it were a USB security key and Passless stores a discoverable credential (resident key) in your
credential store. For GitHub:

1. Open Settings, then **Password and authentication**, then **Passkeys**, then **Add a passkey**
   (`https://github.com/settings/security`).
2. When the browser offers a choice, pick the USB security key option, not a phone or the browser's
   own passkey store. Approve the prompt Passless shows.

Other sites have the same step under their security or sign-in settings. To check that the passkey is
stored:

```bash
passless client list --domain github.com
```

This talks to the running authenticator over HID (your user needs the `fido` group access of the
first-run setup) and may ask for your PIN or a confirmation. Once step 1 below is in place and the daemon
runs, `passless agent-admin credential list --domain github.com` shows what your profiles can reach at
that site (it lists only RPs a profile has a rule for). To let an agent register passkeys on
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

The profile leaves `browser_cdp_port` unset on purpose: the browser picks a free port and the MCP
wrappers and `agent browser --env` find it, so it cannot collide with another browser you run with
`--remote-debugging-port`. `agent mcp install` and `doctor --agents` note a pinned port.

## 2. Restart the daemon, then check the host

The daemon reads the config only at start, so a changed config needs a restart. Validate it first,
without touching the running service (it checks the file as the daemon would at startup and exits
non-zero on an error):

```bash
passless config check
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
otherwise it reads `in place as defence in depth`, which is fine. The `notification_bus` line is a
`warn` when no usable notification server runs and no rule uses `request` (nothing needs a prompt),
and a `FAIL`, making the report `unhealthy`, when some rule does use `request`: a `request` is denied
at once without a server. See [which servers work](../NOTIFICATIONS.md#supported-notification-servers).
A `FAIL` on `config` means the daemon would refuse this configuration; `passless config check` prints
the reason.

## 3. Add the MCP server to your client

One command adds it to Claude Code for your account, or switches an existing plain Playwright MCP
entry. It is a dry run that prints a diff; `--yes` writes it, after saving a backup:

```bash
passless agent mcp install --client claude-code --user --profile coding            # dry run
passless agent mcp install --client claude-code --user --profile coding --yes      # write
```

For opencode use `--client opencode`; `--skill` also installs the bundled agent skill. With no
Playwright MCP entry in the file, `install` adds a `playwright` server that runs `passless agent mcp
playwright --profile coding` (and creates `~/.claude.json` only if it does not exist at all). With a
plain one it rewrites that entry in place, keeping its name, other keys and package spec (a pin such as
`@playwright/mcp@0.0.83`; `@latest` is a tag, not a pin). Restart your client afterwards. Details:
[Browser tools](browser-tools.md#switching-from-a-plain-playwright-mcp). Two Claude Code accounts, or a
repository that ships its own `.mcp.json`: [Multiple accounts and repo-level MCP
entries](browser-tools.md#multiple-accounts-and-repo-level-mcp-entries).

**Shared repositories.** `--project .` writes the entry into the repository's `.mcp.json`. That file is
usually committed, and the entry holds the absolute path of your `passless` and your profile name,
which are specific to your machine; the backup file (`.mcp.json.passless-backup-<UTC timestamp>`) is
left untracked next to it. Use `--project` only for a repository that is yours alone; otherwise use
`--user`, or a local override (see the section above).

**By hand.** Print the entry and paste it, or use the one-liner it prints. Remove the old entry first,
or you will have two servers:

```bash
passless agent mcp --print-config claude-code      # or opencode, cursor, vscode
passless agent mcp playwright --profile coding --print-config claude-code   # the same
```

The entry runs `passless agent mcp playwright --profile coding`, which starts a Passless-managed
Chromium on the first browser tool call and points Playwright MCP at it. It is named `playwright`, as
`install` names it, so the tools stay `mcp__playwright__*`. A profile that is not in port mode is
refused here, as by `install`.

The entry's `command` is the absolute path of the `passless` you ran (for a `cargo install`,
`~/.cargo/bin/passless`), so the client needs nothing on its `PATH`. If you move or reinstall the
binary, print the entry again; if passless cannot tell its own path, the entry says `passless`, which
then has to be on the MCP client's `PATH`.

Two clients at once (two Claude windows, Claude and opencode) each get their own session and browser,
within the profile's limits: see [Several clients at once](browser-tools.md#several-clients-at-once).

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
