# Containment and supported browsers

> **EXPERIMENTAL.** Agent mode is implemented but not yet validated for production use.

The managed browser must never reach your own authenticator. Passless intercepts every WebAuthn call
of the managed browser and signs it in the daemon. If a call ever went to the browser's native
path, it would reach your real security key (your Passless authenticator, or hardware) and could be
approved by a human prompt the agent did not trigger. Three layers prevent that: the extension is
required and verified, requests the extension does not handle fail closed, and the browser cannot
open the hidraw device nodes at all.

## Supported browsers

Supported: **Chromium** and **Chrome for Testing** (including Playwright's Chromium, which is Chrome
for Testing). Needed: Chrome 116 or newer.

Refused at launch, with an actionable error:

- **Branded Google Chrome.** It ignores `--load-extension`, so it would run without interception.
- **`chrome-headless-shell`.** It loads no extensions. Its `--version` looks like Chrome for Testing,
  so it is recognised by its binary name or install path.

Microsoft Edge and Brave were not probed and are unsupported for now.

Passless picks the browser in this order: the profile's `browser_command`; `agents.browser_path`;
Playwright's Chromium in `~/.cache/ms-playwright`; Chrome for Testing in `~/.cache/puppeteer`; the
distribution's `chromium`. A browser Passless starts uses `--headless=new` unless the profile's
`browser_command` sets its own flags; `passless agent browser --headed` starts a visible one. In a
different-user deployment only a binary owned by root, on a path nobody else can write, is accepted.

The extension is allowed in incognito in the managed browser (Passless seeds the fresh profile's
preferences), which keeps it active in contexts that Playwright's `newContext()`, Playwright MCP
`--isolated` and chrome-devtools-mcp `isolatedContext` create. The extension reports this at start;
if it is not allowed the launch fails and the CDP endpoint is withheld, rather than handing out a
browser whose isolated contexts would go native.

## Private /dev and bubblewrap

The daemon runs the managed browser under `bwrap` (bubblewrap) with a private `/dev` that has no
`hidraw*` and no `uhid`, whenever `bwrap` works for the browser's user (it needs unprivileged user
namespaces). Inside it the browser renders without the GPU (`/dev/dri` is hidden).

Without a working `bwrap`, a launch is refused whenever the browser's user can open any
`/dev/hidraw*`. Install bubblewrap, or run the browser as a user that cannot open hidraw devices
(`browser_user`, with a root daemon).

## Check the host

```bash
passless doctor --agents
```

```text
status: healthy
  [ok] agent_subsystem: the daemon's agent subsystem answers on its admin socket
  [ok] coding: browser_binary: Chrome for Testing ... at ~/.cache/ms-playwright/.../chrome
  [ok] coding: containment: required and in place: bwrap /usr/bin/bwrap; ...
  [ok] extension: the interception extension renders and verifies (id ..., needs Chrome 116)
  [ok] native_host_manifest: the relay .../sign-proxy is installed; ...
  [warn] notification_bus: ... `request` rules are denied until a notification server with action support runs there
  [ok] state_dir: ... the daemon creates it (0700)
  [ok] interaction_mode: the human authenticator's prompts are not auto-approved
```

The host checks need no daemon: the browser binary and what containment applies per profile, the
extension and the native host manifest, the notification bus, the state directory and the
automatic-interaction guard below. `containment` reads `required and in place` while the daemon's
UHID device exists (the browser's user could open its hidraw node) and `in place as defence in depth`
when it does not. With `agents.enabled = true` it also pings the daemon's agent socket
(`agent_subsystem`), so a daemon that is not running, or runs without agents, makes it fail. It exits
1 when a check fails.

## Automatic interaction mode

With `PASSLESS_INTERACTION_MODE=automatic` the human authenticator approves its own prompts. A
request from the managed browser that reached it would be signed silently. Agents therefore refuse to
start, and a reload is rejected, while that mode is set and any `same-user` profile has an `allow` or
`request` rule, unless `agents.allow_automatic_human_path = true`. The human authenticator keeps
working. `doctor --agents` flags this.

## CDP port mode

The easy path needs `browser_cdp_expose = "port"`: the managed Chromium listens on a loopback TCP
port. Nothing in Passless limits who on this machine may connect. Anyone who finds the port gets full
control of the browser and every site in it. The browser removes its `DevToolsActivePort` file after
Passless has the address, and the endpoint is only handed out after interception is confirmed, but a
same-user process can still scan loopback ports. Use port mode only where the local environment is
trusted with the whole browser session. The alternative, `browser_cdp_expose = "pipe"`, keeps CDP
daemon-mediated but external tools cannot attach: the agent starts its browser with
`passless agent browser` and drives it through `passless agent browser-control`
([Operations](operations.md#driving-a-pipe-mode-browser)). Pipe mode separates the browser from the
agent only under a root daemon with a distinct `browser_user`; under a non-root daemon the browser runs
as the daemon user.

Each managed browser starts from a fresh, empty profile (no saved passwords, sync or platform
passkeys). A session lasts at most `max_session_ttl`, then the browser is closed and its profile
removed; that does not log the agent out of the site.

## Same user and different user

Two settings are independent: the credential source (`mode`, `same-user` or `isolated`) and whether
the agent's Unix user is the daemon's (`shared-UID`) or another one (`distinct-UID`, which needs the
root `passless-agent.service`). `passless doctor` and every audit record report both.

- **shared-UID**: there is no operating-system boundary between the agent, the browser and the daemon.
  Passless relies on policy, session limits and audit, like `ssh-agent`. An agent can approve its own
  `request` prompts through your notification server (`dunstctl`, `makoctl`, a replaced server, or
  input to notify-osd's dialog). That includes the prompt for registering a passkey at a site you have
  not listed (`register = "request"` on the `*` rule): with a shared UID it is a convenience and an
  audit point, **not a security boundary**; use a distinct-UID principal where it must be one. An
  `isolated` profile in a shared-UID
  deployment has separate passkeys, but the agent can read your store as the same user; separation is
  administrative only, and startup warns.
- **distinct-UID**: the daemon's storage, config and granted rules are protected by Unix permissions,
  and `agents.notify_user` names the human whose session bus receives prompts. It must differ from
  every `principal_user` and `browser_user`. Here the prompt is a boundary, including the registration
  prompt (the residual is approval by mistake or fatigue, addressed by its distinct wording, the store
  count, the daily limit and the cooldown).

See [ADR 0014 §13](../decisions/0014-agent-delegation.md#13-deployment-axes-and-hardening-scope) for the
hardening scope and the open systemd, namespace and seccomp work.
