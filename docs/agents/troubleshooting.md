# Agent troubleshooting

> **EXPERIMENTAL.** Agent mode is implemented but not yet validated for production use.

Start with `passless doctor --agents`: it checks the browser binary, containment, extension, native
host, notification bus and state directory from the config file (no daemon needed for those), and,
when agents are enabled, that the daemon's agent subsystem answers (`agent_subsystem`).

## Agent support is disabled, or the profile is not found

```bash
passless agent-admin profile list
```

Check that `[agents].enabled = true`, `audit_path` is set, and the profile exists under
`[agents.profiles.<name>]`. Restart the daemon after editing the config (`systemctl --user restart
passless`) or reload a profile's policy with `passless agent-admin policy reload <profile>`.

`several agent profiles are configured`: pass `--profile <name>` to `passless agent browser` or
`passless agent mcp ...`.

## The daemon runs but the agent subsystem does not

| Symptom | Cause and fix |
|---|---|
| Daemon log: `Agent subsystem failed to start: IPC error: failed to create runtime dir: ... File exists`, `agent-admin` says `no agent socket`, `doctor --agents` fails `agent_subsystem` | Older versions left `$XDG_RUNTIME_DIR/agent` behind after a SIGTERM or a crash, and the next start could not create it. Current versions remove their own directory at a clean shutdown and reclaim a leftover at start: a real directory owned by the daemon's user with mode 0700 whose sockets nobody answers is removed and recreated. Upgrade and restart. Where the start still fails with `cannot reclaim the stale runtime dir`, the log says why: it is a symlink or a file, another user owns it or its mode is not 0700 (so Passless will not remove it; check it and delete it yourself), or a live daemon answers on it (stop that one). With an older build, `systemctl --user stop passless; rm -rf "$XDG_RUNTIME_DIR/agent"; systemctl --user start passless`. |
| `doctor --agents` fails `agent_subsystem` with `nothing answers on the admin socket` | The daemon is not running, or it started without agents (the `Agent subsystem failed to start` line in `journalctl --user -u passless` says why), or `agents.enabled` was set after the daemon started: restart it. |

## Configuration errors

Run `passless agent-admin profile check <profile>`.

| Error | Cause and fix |
|---|---|
| `same-user mode uses the human backend and must not specify storage` | Remove the profile's `storage`. |
| `isolated mode requires storage backend configuration` | Add a local, pass or TPM storage section. |
| `wildcard RP scope '*' is only supported in same-user mode` | Use exact rules in an isolated profile. |
| `global same-user authentication requires explicit operator acknowledgement` | Add the profile to `agents.acknowledge_global_same_user`. |
| `same-user registration ... requires explicit operator acknowledgement` | Add it to `agents.acknowledge_same_user_registration`, or set `register = "deny"`. |
| `wildcard RP scope '*' must have register = "deny"` | A wildcard never permits or requests registration. |
| `register = "request" with authenticate = "deny"` | Approving a registration stores `authenticate = allow`; use `allow` or `request` for `authenticate`. |
| `agent roots ... overlap` | Give audit, state and storage separate directories. |
| invalid RP ID | Use an exact domain such as `github.com`; no scheme, port, path, IP address or public suffix. |
| `unknown field`, or a message about removed profile keys | Misspelled or removed field; see [Configuration](configuration.md) and [Migration](migration.md). |

## The browser does not start

- `... is branded Google Chrome` or `... is chrome-headless-shell`: neither can load the extension.
  Remove `browser_command` and `agents.browser_path` so Passless detects a supported browser, or
  install Playwright's Chromium (`npx playwright install chromium`), Chrome for Testing or your
  distribution's `chromium`. See [Containment](containment.md#supported-browsers).
- Containment refused the launch: the browser's user can open a hidraw device and `bwrap` does not work.
  Install bubblewrap, and check that unprivileged user namespaces are enabled
  (`passless doctor --agents` shows the case).
- The MCP client says `Unexpected status 503 when connecting to http://127.0.0.1:<port>/json/version/`:
  the browser could not be started. The response body names the class
  (`{"error":"managed browser unavailable","class":"runtime_root_invalid",...}`; other classes are
  `launch_failed`, `daemon_unreachable`, `refused` and `unavailable`) and the MCP server's stderr
  (the client's MCP log) has the full text; the daemon's log has the launch error:
  `journalctl --user -u passless`. A pipe-mode profile is refused this way (`class` `refused`); the
  stderr line then reads `Playwright browser discovery requires browser_cdp_expose = 'port' ...`
  (see below).
  - `class` `runtime_root_invalid` (`failed to launch browser: invalid runtime root: ...`): the
    browser runtime root, by default `$XDG_RUNTIME_DIR/passless/browser`, cannot be used. Current
    versions create it (mode 0700, yours) when it is missing; an older build fails with `No such file
    or directory`: `mkdir -p -m 700 "$XDG_RUNTIME_DIR/passless/browser"`. An existing root that is
    a symlink, is not mode 0700 or has the wrong owner is refused, not repaired: fix or remove it.
    For a configured `browser_runtime_root` Passless creates only the last component and only when
    the parent exists and is not writable by others; create parents yourself. With a `browser_user`
    that is not the daemon's user, create the root owned by that user with mode 0700 (the default
    root is only created for the daemon's own user).
  - `class` `daemon_unreachable`: the daemon is not running, or runs without agents (see above).
  - `class` `launch_failed`: see `passless doctor --agents` and the daemon log.
- `browser_cdp_port <port> on 127.0.0.1 is already in use (<process>, pid <pid>)`, or `the CDP endpoint on
  127.0.0.1:<port> does not belong to the launched browser`: another process (often a browser you started
  with `--remote-debugging-port`) holds the profile's fixed port, so whatever answered there would not be
  the managed browser. Remove `browser_cdp_port` to use an ephemeral port (recommended), or choose a free
  one. `passless doctor --agents` warns while the port is held.
- The extension is not intercepting: the launch fails and no endpoint is printed. Check
  `passless doctor --agents` for the extension and native host, and the daemon log.
- `agent browser ... must run inside a principal session`: start your agent with
  `passless agent run --profile <profile> -- <absolute command>`, or use `passless agent mcp ...`.
- `Playwright browser discovery requires browser_cdp_expose = 'port'`: the adapter needs an endpoint,
  which a pipe-mode profile does not have. Set `browser_cdp_expose = "port"` on the profile if direct
  local control of the browser is acceptable ([Containment](containment.md#cdp-port-mode)), or run
  `passless agent browser` and drive the browser with `passless agent browser-control`.
- `browser-control` fails with `the managed browser's WebAuthn interception is degraded`: the extension
  worker is not attached (or not allowed in incognito); retry after a moment, or see
  `passless doctor --agents`. `no browser lease associated with this principal session`: run
  `passless agent browser` first, in the same principal session.
- A browser owned by another session: end it with `passless agent-admin principals revoke <id>
  --confirm`.
- Do not add `--remote-debugging-*` or `--load-extension` flags to `browser_command`: Passless owns
  them.

## The page gets NotAllowedError, or the agent sees nothing happen

`NotAllowedError` is deliberately generic. Look at the audit for the real reason:

```bash
passless agent-admin audit export --format json
```

Common causes:

- **No matching rule**, or `deny`: add an exact rule for the site's RP ID (check the RP ID, not just
  the domain in the address bar).
- **`request` waiting**: the page call stays pending until you answer the desktop notification, for up
  to the page's timeout (3 minutes to 20 hours). The agent should wait, not retry.
- **`request` denied or timed out**: a cooldown (10 minutes by default) denies further requests for
  that RP without a prompt. Wait it out, or change the rule to `allow` and reload the policy.
- **No notification**: `request` is denied at once when no notification server with action support is
  running on the user's bus. `doctor --agents` warns. Run one (dunst, mako, a desktop shell) or use
  `allow`. notify-osd (Ubuntu) works: it shows the prompt as a dialog with "Allow always" and "Deny"
  buttons (see [Desktop notifications](../NOTIFICATIONS.md#notify-osd)).
- **Conditional (autofill) request**: unavailable; the page needs an explicit sign-in button.
- **Cross-origin iframe**: denied. Sign in on the top-level page.
- **Extension not attached yet**: wait for `passless agent browser --wait` or the MCP tool's browser to
  report ready.
- **Registration from a background tab**: bring the page to the front; the daemon may have created
  the credential anyway (see [Browser tools](browser-tools.md#limits)).

## Authentication stops after some requests

`replayed_operation` and `operation_budget_exhausted` are terminal for that operation or session
(identical repeats get the original result for 120 seconds, then are rejected). Start a new session if
the task still needs it; retrying in a loop does not help. A policy reload that changes anything also
revokes sessions.

## Approval does not appear, or a granted rule is missing

See [Rules](rules.md). `passless agent-admin grants list --profile <profile>` shows what was approved;
a store that is malformed or has the wrong owner or mode disables grants for that profile and is
reported by `profile check`. A granted rule is inert if the config rule is `deny`, `allow` or gone;
`profile check` and `doctor --agents` report those as orphaned grants.

## A tool cannot connect to CDP

The endpoint is printed only for an intercepted browser, by `passless agent browser --wait`. Port mode
(`browser_cdp_expose = "port"`) is required; in pipe mode there is no endpoint (use `browser-control`). A tool that launches its own Chromium instead of
attaching gets no passkeys. See [Browser tools](browser-tools.md).

## `doctor --agents` warns that an MCP entry starts its own browser

```text
[warn] mcp_client: claude-code/project/playwright: ... entry 'playwright' starts its own browser
(@playwright/mcp via pnpm dlx): passkeys from this MCP reach your human authenticator, not the agent
policy. Fix: passless agent mcp install --client claude-code --project <DIR> --profile coding --yes
```

The doctor scans the user-level opencode and Claude Code configuration (honouring `XDG_CONFIG_HOME` and
`CLAUDE_CONFIG_DIR`) and `opencode.json` and `.mcp.json` in the current directory. A plain Playwright MCP
or chrome-devtools-mcp entry starts a browser the daemon does not own, so there is no interception and
the agent policy never applies. Run the printed command without `--yes` to preview the diff, then with it
to write; see [Browser tools](browser-tools.md#switching-from-a-plain-playwright-mcp). A wrapped entry
that names a profile which is missing or not in port mode is also a warning. Entries the installer
cannot rewrite (started through a shell or `node` script) are reported too: edit them by hand.

## Other

- **Principal cannot run admin commands**: expected. Run `agent-admin` outside the principal session.
- **Audit `verify` fails**: preserve the files, investigate the gap, and repair storage before more
  agent use ([Operations](operations.md#recovery)).
- **Daemon restart ended the sessions**: expected; start new ones.
- **The site still shows a session after the browser closed**: expected. Use the site's own logout or
  revocation.
- **Credential selection is ambiguous**: `single` fails when several credentials match. Pin one with
  `credential:<ref>` or pick `first-matching` or `newest` knowingly.
- **Host features missing**: see the table in [Operations](operations.md#host-requirements).

Related: [Overview](README.md), [Security](security.md), [Configuration](configuration.md).
