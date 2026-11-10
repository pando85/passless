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

| Variable | Meaning |
|---|---|
| `AGENT_E2E_MATRIX` | `ci` (default) or `full` |
| `AGENT_E2E_BROWSERS` | comma list: `chromium` (distro), `pw-chromium`, `cft` (Chrome for Testing); negative controls `chrome`, `headless-shell`. Default `pw-chromium` (ci) or `chromium,pw-chromium,cft` (full) |
| `AGENT_E2E_HEADLESS` | `new`, `headed` or `both` (default `new` for ci, `both` for full) |
| `AGENT_E2E_FILTER` | scenario ids (`E2E-01,6`); overrides the CI selection. Also accepted as `run.sh` arguments |
| `AGENT_E2E_ALLOW_SKIP=1` | a SKIP (missing browser, optional tool) no longer fails the run. Without it any SKIP, zero scenarios, or an unmatched filter id exits 1 |
| `AGENT_E2E_TIMEOUT` | overall limit in seconds (default 900 ci, 2400 full) |
| `AGENT_E2E_OFFLINE=1` | never download browsers (a missing browser is a SKIP, i.e. a failure unless allowed) |
| `AGENT_E2E_KEEP=1` | keep the temp root; `AGENT_E2E_DEBUG=1` extra logging |
| `AGENT_E2E_PASSLESS_BIN`, `AGENT_E2E_NOTIFY_DOUBLE_BIN`, `AGENT_E2E_NO_BUILD=1` | use prebuilt binaries |

Failure artifacts (daemon log, audit, config, RP state) are kept in `target/agent-e2e-artifacts/`.

## Prerequisites

Node 20+, `npm ci` (done by `run.sh`, again whenever `package-lock.json` changes), `openssl`, `dbus-run-session`, `dbus-send`, `bwrap` (unprivileged user namespaces), `flock`, `xvfb-run` (headed only), a Rust
toolchain, and `/dev/uhid` access (`modprobe uhid`, user in the `fido` group, udev rule from `CLAUDE.md`):
the daemon always creates the human UHID device. Browsers: distro `/usr/bin/chromium`; Playwright Chromium and
Chrome for Testing are downloaded once into `target/agent-e2e-cache/` (never into `~/.cache/ms-playwright`).

## Layout

- `lib/env.js` hermetic env and guards; `lib/daemon.js` config + daemon + product browser launch;
  `lib/browser.js` discovery and matrix; `lib/rp-server.js` + `pages/` test RP; `lib/tls.js` test CA and
  `rp-a.test` / `rp-b.test` / `evil.test` via `--host-resolver-rules`; `lib/notify-double.js` (Rust tool in
  `tools/notify-double`); `lib/mcp-client.js` minimal MCP client; `lib/scenario.js` matrix, CI tags and xfail.
- `scenarios/e2e-NN-*.test.js` follow the catalogue in `docs/plans/agent-delegation-implementation.md`.

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
