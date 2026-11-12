# Agent delegation E2E harness

Real-browser tests for Passless agent delegation (ADR 0014): the daemon, its managed Chromium with the
agent extension, a test relying party that verifies every ceremony, and a scripted notification server.
Everything runs in a hermetic environment (temp `HOME`/`XDG_*`/`PASSLESS_*`, private D-Bus session bus).

## Run

```bash
make test-agent-e2e        # CI subset (scenarios tagged ci: true), Playwright Chromium, headless
make test-agent-e2e-full   # all scenarios, all browsers, headless and headed (Xvfb)
tests/agent-e2e/run.sh E2E-01 E2E-06     # selected scenarios
```

`run.sh` builds the binaries once (`--features agent`, into `target/agent-e2e-bin`, so other builds cannot
replace them), wraps the run in `dbus-run-session` (and `xvfb-run -a` for headed variants), prints a
scenario x variant table, and exits non-zero on any `FAIL` or `XPASS`.

Before the first scenario, `lib/preflight.js` starts a plain browser under bwrap for every selected variant and fails
the run in seconds, with the browser's stderr, when that is impossible.

CI runner setup (Ubuntu 24.04+, `.github/workflows/rust.yml`, job `agent-e2e`): besides
`kernel.apparmor_restrict_unprivileged_userns=0`, the AppArmor profile for `/usr/bin/bwrap`
(`/etc/apparmor.d/bwrap-userns-restrict`) must be unloaded. It denies every capability inside bwrap, which makes
Chromium's own namespace sandbox abort (exit 134) when the browser runs under bwrap.

| Variable | Meaning |
|---|---|
| `AGENT_E2E_MATRIX` | `ci` (default) or `full` |
| `AGENT_E2E_BROWSERS` | comma list: `chromium` (distro), `pw-chromium`, `cft` (Chrome for Testing); negative controls `chrome`, `headless-shell`. Default `pw-chromium` (ci) or `chromium,pw-chromium,cft` (full) |
| `AGENT_E2E_HEADLESS` | `new`, `headed` or `both` (default `new` for ci, `both` for full) |
| `AGENT_E2E_EXPOSE` | the attach-mode axis (CDP exposure): `port`, `pipe` or `all`. Default `port` for ci (unchanged), `all` for full. See "Attach modes" |
| `AGENT_E2E_FILTER` | scenario ids (`E2E-01,6`); overrides the CI selection. Also accepted as `run.sh` arguments |
| `AGENT_E2E_ALLOW_SKIP=1` | a SKIP (missing browser, optional tool) no longer fails the run. Without it any SKIP, zero scenarios, or an unmatched filter id exits 1 |
| `AGENT_E2E_TIMEOUT` | overall limit in whole seconds (default 900 ci, 14400 full); exit 124 when it fires, whole run group stopped (TERM, then KILL after 20 s) |
| `AGENT_E2E_OFFLINE=1` | never download browsers (a missing browser is a SKIP, i.e. a failure unless allowed) |
| `AGENT_E2E_KEEP=1` | keep the temp root; `AGENT_E2E_DEBUG=1` extra logging |
| `AGENT_E2E_PASSLESS_BIN`, `AGENT_E2E_NOTIFY_DOUBLE_BIN`, `AGENT_E2E_NO_BUILD=1` | use prebuilt binaries |

Failure artifacts (daemon log, audit, config, RP state) are kept in `target/agent-e2e-artifacts/`.

## Attach modes (port and pipe)

ADR 0014 section 4.3 makes `browser_cdp_expose = "pipe"` the default and the hardened mode: the browser has no CDP endpoint,
every command goes through `passless agent browser-control` and the daemon's CDP filter, and the MCP adapters and other
`direct_cdp` clients refuse the profile. The matrix therefore has a third axis next to browser and headless/headed.

- A scenario declares the modes it supports: `exposeModes: ['port', 'pipe']` (default `['port']`). It runs once per
  (browser, headless, supported mode). `AGENT_E2E_EXPOSE=port|pipe|all` picks the modes of a run; `pipe` runs only the scenarios
  that support it. Variant names carry the mode whenever the run includes pipe (`[chromium/headless/pipe]`); a port-only run, such
  as the CI subset, keeps its old names and its exact scenario set. `report.js` prints one table per mode.
- `pinsExpose: 'pipe'` marks a scenario that writes its own pipe-mode profiles (E2E-52, 52/strict, 53, 54); it runs once per variant
  whatever the axis says.
- In pipe mode `stack.open(profile, url)` starts a principal session (`passless agent run`) that ensures the browser
  (`agent browser --wait`) and serves `browser-control` requests from a FIFO, and returns the same `b` shape as the port path.
  `b.page` is a `PipePage` (`lib/pipe-driver.js`): `evaluate`, `waitForFunction`, `goto`, `bringToFront`, `waitForLoadState`, built
  from flat sessions on page targets and `Runtime.evaluate`; `b.context.newPage()` is `Target.createTarget`. Nothing else is used:
  no CDP port, no Playwright connection. `b.pipe.control(method, params, sessionId)` is the raw call (E2E-52 uses the same).
  A call has a 30 s cap, so `evaluate` starts the function in the page and polls it with short calls; two tabs can have ceremonies
  in flight at once. The extension worker is hidden from the agent by design, so `assertInterceptionActive` judges the daemon's
  `browser-status` (`interception: attached`, `incognito_allowed`, `cdp_exposure: pipe`) and every scenario still asserts the
  agent-path audit records.
- Pipe-enabled: E2E-01 to 05, 07, 09, 12 (+/audit-rule), 13, 14, 15, 16, 17 (+/after-key-use), 23 to 30, 32 (+/abort), 33, 43, 48, 49,
  50, 51; pipe-only: E2E-52, 52/strict, 53 (adapters refused for a pipe-mode profile, with a port-mode control), 54 (grants revoke ends
  the principal session and its browser). Every other scenario stays port-only with a comment saying why: the Playwright and
  CDP-endpoint tools, and the ones that read or stop the extension worker (hidden in pipe mode), inherently need a port.

## Prerequisites

Node 20+, `npm ci` (done by `run.sh`, again whenever `package-lock.json` changes), `openssl`, `dbus-run-session`, `dbus-send`, `bwrap` (unprivileged user namespaces), `flock`, `xvfb-run` (headed only), a Rust
toolchain, and `/dev/uhid` access (`modprobe uhid`, user in the `fido` group, udev rule from `CLAUDE.md`):
the daemon always creates the human UHID device. Browsers: distro `/usr/bin/chromium`; Playwright Chromium and
Chrome for Testing are downloaded once into `target/agent-e2e-cache/` (never into `~/.cache/ms-playwright`).

## Layout

- `lib/env.js` hermetic env and guards; `lib/daemon.js` config + daemon + product browser launch;
  `lib/browser.js` discovery and matrix; `lib/rp-server.js` + `pages/` test RP; `lib/tls.js` test CA and
  `rp-a.test` ... `rp-j.test` / `evil.test` via `--host-resolver-rules`; `lib/notify-double.js` (Rust tool in
  `tools/notify-double`); `lib/escalation.js` (helpers of the P7 escalation scenarios); `lib/mcp-client.js` minimal MCP client; `lib/scenario.js` matrix, CI tags and xfail.
- `scenarios/e2e-NN-*.test.js` follow the catalogue in `docs/plans/agent-delegation-implementation.md`.
- `lib/helpers.js`: `extensionEndpoint` (bearer, socket and build version from the extension worker), `FramedClient`
  (the daemon's wire protocol v2: `hello`, `request`, `abort`), proxy-shaped request bodies, and the daemon log patterns
  of the sign transport (`TRANSPORT_LOG`) and of the human UHID device (`HUMAN_CTAP_LOG`).
- `stack.open(profile, url)` launches through the product path with `url` as the start URL (opened by the daemon only
  after the worker attached the WebAuthn proxy) and returns the start-URL tab, brought to the front; the browser's
  own `about:blank` tab is `b.blankPages`. `{startUrl: false}` navigates the blank tab instead (RPs the rules do not
  admit as a start URL). `lib/browser.js` `stopExtensionWorker` closes the worker target (`Target.closeTarget`).

## Escalation scenarios (P7)

A `request` rule escalates: the daemon's prompt child shows a notification on the private bus, and the scripted
notification double answers it. Stack options: `notify: {script: [...]}` (step N answers the N-th new notification, calls
beyond the list are `ignore`; `approve[:ms]`, `deny[:ms]`, `close[:ms]`, `ignore`), `notify: false` (no notification server
on the private bus: escalation is denied `escalation_unavailable`), `agents: {escalation_cooldown: 2, escalation_timeout: N,
state_dir: '/abs'}` (raw `[agents]` keys; a 1 s cooldown is accepted by debug builds only), per profile `max_granted_rules`.
`stack.notify.stop()` waits for the double to exit (it owns `org.freedesktop.Notifications`); `stack.restartNotify({script})`
starts a new one with its own log (`notify-2.jsonl`). Approvals must be scripted at `approve:1500` or later: the daemon
accepts "Allow always" only 1000 ms after the notification was shown, and an earlier one is a deny.

Helpers (`lib/helpers.js`): `escalationEvents`, `grantedRuleEvents`, `denyReasons`, `grantsStore` (parsed grant store file).
Quirks: the escalation pre-check runs before the replay key, so a refusal (cooldown, caps, unavailable) consumes neither;
a deny, expiry or abort after the wait started consumes the key, so every retry uses a fresh challenge (the page helpers
fetch new RP options per call). `PASSLESS_INTERACTION_MODE=automatic` has no effect on escalation (E2E-44). After a grant
revocation or clear the daemon terminates the managed browsers (the admin-launched one too) and audits late use of the
old bearer as `bearer_revoked`, so a scenario launches a fresh browser (E2E-31).

CI subset: E2E-23, 24, 25, 27, 28, 29, 31, 48, 50 (about 5 to 15 s each). Full matrix only: E2E-20/escalation (6 min
approval), 21 (3 min timeout), 26, 30, 43, 44, 49. E2E-26 proves sequential prompting in arrival order with four RPs; the queue
bound (1 active + 8 queued) needs several bearer sessions of one profile, which the harness cannot create (admin launch
returns the profile's live lease), so the bound is covered by the coordinator unit tests. E2E-44 sets
`agents.allow_automatic_human_path`; E2E-44/startup-refusal proves agents refuse to start without it (R19).

Containment (P10a): every managed browser runs under `bwrap --dev-bind / / --dev /dev --die-with-parent` (E2E-46 reads its
`/dev` through `/proc/<pid>/root`); E2E-46/refused disables bwrap and expects the launch refusal; E2E-46/session-scope is the
defect B1 regression (`browserScope: 'session'`; every other scenario uses `browser_scope = "profile"`). E2E-45/cdp-context
relies on the incognito seed; E2E-47/unloadable waits out the 30 s attach timeout.

Debug-build daemon hooks (set through `daemonEnv`): `PASSLESS_E2E_HOLD_REQUEST_MS` holds each request before its
ceremony (an abort or disconnect then lands before key use), `PASSLESS_E2E_HOLD_RESULT_MS` holds each successful
result after key use, `PASSLESS_E2E_OMIT_AGENT_EXTENSION` drops the generated extension directory (E2E-47),
`PASSLESS_E2E_UNLOADABLE_AGENT_EXTENSION` writes a service worker that loads but never connects (E2E-47/unloadable; a manifest the browser refuses to load blocks headed Chromium on a modal dialog before it opens its debugging port) and
`PASSLESS_E2E_DISABLE_BWRAP` makes the launcher treat bwrap as unavailable (E2E-46/refused).

## Agent-browser easy path (P10b)

E2E-34/35 (Playwright MCP, `--isolated`), 36 (chrome-devtools-mcp), 37 (`connectOverCDP(PASSLESS_CDP_URL)`) and 41 (refused
browsers) run the real `passless agent mcp ...` / `agent browser` against the scenario's daemon (`lib/adapters.js`). `npx` is
`bin/npx`, a stand-in that runs the copies `package.json` pins (`@playwright/mcp`, `chrome-devtools-mcp`), so no scenario needs
the network. `agent browser` only works inside a principal session, so E2E-37 starts an agent as the product does
(`passless agent run -- /bin/bash <script>`). E2E-41 writes no `browser_command` (`noBrowserCommand`) and sets `agents.browser_path`
to stand-ins for branded Chrome and `chrome-headless-shell` (and to the real ones when installed).

E2E-38 (browser-use) and E2E-39 (agent-browser) are local and optional: without the tool they are recorded `SKIP-OPT`, which never
fails a run (`AGENT_E2E_AGENT_BROWSER`, `AGENT_E2E_BROWSER_USE_PYTHON` name the tools). E2E-42 needs `dunst` and a display (headed
variants under Xvfb). E2E-40 is the matrix itself: `AGENT_E2E_MATRIX=full tests/agent-e2e/run.sh E2E-01 E2E-23 E2E-34` runs the
core flows on every browser, headed and headless.

## Expected failures

```js
scenario({ id: 'E2E-06', title: '...', ci: true, xfailUntil: 'P6', xfailMatch: /expected error text/, xfailReason: 'why' }, async ctx => { ... });
```

A tagged scenario whose failure message matches `xfailMatch` is reported `XFAIL`; any other failure is a `FAIL`; an
unexpected pass is `XPASS` and fails the run, so the tag must be removed when the phase lands. `BASELINE.md` records
the current results.

## Hermeticity

- `run.sh` scrubs the environment (temp `HOME`/`XDG_*`, no `DISPLAY`/`WAYLAND_DISPLAY`/`XAUTHORITY`; only headed
  variants get Xvfb's `DISPLAY`) and starts a private bus from a minimal config with no service directories, so no
  real session service can be activated. `SMOKE-02` and every scenario assert only the bus and notify-double are on it.
  The real bus address is passed as `AGENT_E2E_REAL_BUS` only so the harness can refuse it.
- A path resolving inside the real config/state/data/runtime dirs aborts the run. `lib/guard.js` fingerprints the
  real Passless dirs, native-messaging dirs, `~/.cache/ms-playwright` and the Chromium profile before and after.
- Processes are tracked by process group and process tree; after each scenario any process still mentioning the run's
  temp root fails the scenario.
- Seeding a human credential runs a plain browser under `bwrap` with a private `/dev` containing only this daemon's own
  hidraw node, identified through sysfs. If it cannot be identified unambiguously (e.g. another Passless instance starts
  at the same moment) the scenario fails with a clear message.
- TLS material is per run (`AGENT_E2E_TLS_DIR`); browser and build caches are locked with `flock`.
