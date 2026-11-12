# E2E baseline

## Pipe-mode attach axis (ADR 0014 section 4.3), 2026-11-12

Branch `feat/agent-delegation-adr-0014`, on top of `794942d`. Debug build, `--features agent`, no Rust changes. The matrix gained a
third axis, the CDP exposure ("attach mode", `AGENT_E2E_EXPOSE=port|pipe|all`; see `README.md`, "Attach modes"). Until now every
scenario ran with `browser_cdp_expose = "port"`, except E2E-52 and 52/strict; pipe mode, the ADR's default, was never exercised end to
end by the core flows. In pipe mode the harness drives each page through `passless agent browser-control` from a principal session
(`lib/pipe-driver.js`), so every command passes the daemon's CDP filter and is audited per command; there is no CDP port and no
Playwright connection.

- Command: `AGENT_E2E_MATRIX=full AGENT_E2E_EXPOSE=pipe tests/agent-e2e/run.sh <ids>`, in two batches, chromium, pw-chromium and cft,
  headed and headless:
  - E2E-01 to 05, 09, 12 (+/audit-rule), 14, 15, 23, 24, 25, 27, 28, 32 (+/abort), 48, 52, 52/strict, 53, 54: 132 PASS (22 on each of
    the 6 variants), 0 FAIL, 695 s.
  - E2E-07, 13, 16, 17 (+/after-key-use), 26, 29, 30, 33, 43, 49, 50, 51: 78 PASS (13 on each variant), 0 FAIL, 426 s.
  - Total: 210 PASS in pipe mode (35 on each variant), 0 FAIL, 0 SKIP, hermeticity guard clean.
- `make test-agent-e2e` (CI subset, port only): unchanged, PASS=46 on pw-chromium headless, guard clean.
- Per-variant pipe results (all PASS): `chromium/headed`, `chromium/headless`, `pw-chromium/headed`, `pw-chromium/headless`, `cft/headed`,
  `cft/headless`: 35 PASS each.
- Expected added full-matrix runtime: about 1,100 s of measured pipe time (the 12 E2E-52 runs were already in the 6,980 s), so a
  full run of both modes is about 8,100 s; the 14,400 s limit is unchanged.
- Pipe-only scenarios added: E2E-53 (the Playwright MCP and chrome-devtools adapters, which are `direct_cdp` clients, are refused for
  a pipe-mode profile before any browser starts; a port-mode profile of the same daemon and a pipe session of the refused profile are
  the controls) and E2E-54 (`grants revoke` ends the principal session and its browser, `browser-control` is refused afterwards, a new
  session gets a fresh lease and the revoked RP prompts again).
- Port-only scenarios keep a one-line comment with the reason: the Playwright, chrome-devtools, browser-use and agent-browser tools need
  a CDP endpoint, and E2E-06, 11, 18, 19, 20, 31, 45 read or stop the extension worker, which the filter hides in pipe mode (E2E-52).
  Not ported yet (driver is page-level): E2E-08, 10 (frames and popups), 22 (20 tabs), 21 (3 minute timeout).
- Finding, fixed (not a safety issue; the refusal was always enforced): `agent mcp playwright` against a pipe-mode profile fails its
  first tool call with Playwright's `Unexpected status 503 when connecting to .../json/version/ ... does not look like a DevTools
  server`. The wrapper printed nothing: `cdp_bootstrap.rs` logged the full refusal with `log::warn!`, but the `agent` client
  subcommands run before logging is initialised in `main.rs`, so the record was dropped. Fixed: the bootstrap now also writes the
  line ("passless: failed to ensure managed browser for CDP bootstrap (refused): ... requires browser_cdp_expose = 'port' ...; in
  pipe mode run `passless agent browser` ...") to the wrapper's stderr, never stdout (the MCP channel), and the refusal is
  classified `refused` in the 503 body. E2E-53 now asserts the documented text, the `passless agent browser` pointer and the
  `(refused)` class on the Playwright wrapper's stderr, as it already did for `agent mcp chrome-devtools`, which ensures the browser
  up front and exits with the text.

## P12 (final gate), 2026-11-12

Branch `feat/agent-delegation-adr-0014` at `602db70`. Debug build, `--features agent`.

- Command: `make test-agent-e2e-full` (`AGENT_E2E_MATRIX=full`, chromium, pw-chromium and cft, headed and headless): 392 PASS
  (65 on each of the 6 variants and the 2 smoke checks), 0 FAIL, 0 XFAIL, 0 XPASS, 0 SKIP, 6,980 s. `make test-agent-e2e`
  (CI subset): PASS=46, nothing else.
- E2E-52 and the optional-tool and browser scenarios E2E-36 to E2E-39, E2E-41 and E2E-42 pass on every variant; E2E-38 (browser-use 1.0.2) and E2E-39 (agent-browser 0.42.0) ran from the
  harness cache (`target/agent-e2e-cache`) rather than SKIP-OPT.
- The run exited 2 only because the hermeticity guard saw a write to `~/.cache/ms-playwright/b/` at 01:33:20 by an unrelated,
  concurrently running Playwright MCP session outside the repo. No scenario failed.

## P7 (escalation), 2026-11-11

Branch `feat/agent-delegation-adr-0014` at `ccf6c0c` (daemon escalation from `69b5700`, `262fb04`, `dd7da60`, `63153b8`; harness
and scenarios `2eff086`, `ccf6c0c`). Debug build, `--features agent`, no Rust changes in the E2E work.

- Command: `AGENT_E2E_MATRIX=full AGENT_E2E_BROWSERS=chromium,pw-chromium,cft AGENT_E2E_HEADLESS=both AGENT_E2E_TIMEOUT=7200 tests/agent-e2e/run.sh`:
  exit 0, PASS=266 (264 scenario results and the 2 smoke checks), XFAIL=18, FAIL=0. Per variant: 44 PASS, 3 XFAIL.
  `make test-agent-e2e` (CI subset): exit 0, PASS=30, XFAIL=2.
- New in P7: E2E-20/escalation (approval after 6 min) and E2E-21 (3 min timeout, `expired(timeout)`) un-XFAILed; E2E-23 to 31,
  43, 44, 48, 49, 50 added. CI subset: 23, 24, 25, 27, 28, 29, 31, 48, 50. Full only: 20/escalation (about 6 min per variant),
  21 (about 3 min), 26, 30, 43, 44, 49.
- E2E-09 and E2E-13 now run with `notify: false` (no notification server: `escalation_unavailable`); E2E-12 uses `deny:500` and
  asserts `escalation.requested` with `rule = "*"`.
- Remaining XFAILs (all variants): E2E-12/audit-rule (P8, no `rule` in `policy.*` audit events), E2E-44/startup-refusal
  (P10, R19: the daemon starts agents in automatic interaction mode), E2E-45/cdp-context (P10).
- Gaps: E2E-26 proves sequential, in-order prompting with four RPs; the queue bound (1 active + 8 queued) needs several bearer
  sessions of one profile, which the harness cannot create (admin launch returns the profile's live lease; session-scoped browsers
  are killed after launch, B1), so the bound is covered by the coordinator unit tests.
- Fixed (review): `agent-admin grants revoke|clear` now terminates the managed browsers (the admin-launched one too),
  `browser launch` then gives a fresh browser with the start-URL tab, and a request on the old bearer is refused and audited
  `policy.deny(bearer_revoked)`. E2E-31 asserts all three (not yet re-run on the matrix).
- E2E-20/escalation, filter id with a slash: `AGENT_E2E_FILTER=E2E-20/escalation` runs the scenario but `report.js` reports
  "matched no scenario" (exit 1); filter by `E2E-20` instead.

| Scenario | chromium headed | chromium headless | pw-chromium headed | pw-chromium headless | cft headed | cft headless |
|---|---|---|---|---|---|---|
| E2E-01 to E2E-22 (as in P6 below; E2E-09, 12, 13 reworked, 20/escalation and 21 now PASS) | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-12/audit-rule (until P8) | XFAIL | XFAIL | XFAIL | XFAIL | XFAIL | XFAIL |
| E2E-23 grant, no second prompt | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-24 deny, cooldown | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-25 two tabs, one prompt | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-26 queued prompts in order | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-27 registration escalation | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-28 daemon-only notification text | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-29 spoofed ActionInvoked | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-30 no notification server | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-31 grants CLI, damaged store | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-43 human ceremony during escalation | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-44 automatic mode never auto-approves | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-44/startup-refusal (until P10) | XFAIL | XFAIL | XFAIL | XFAIL | XFAIL | XFAIL |
| E2E-45/cdp-context (until P10) | XFAIL | XFAIL | XFAIL | XFAIL | XFAIL | XFAIL |
| E2E-48 waiter cap, other profile unaffected | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-49 notification server lost | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-50 three aborts, cooldown | PASS | PASS | PASS | PASS | PASS | PASS |

## P6 (interception and transport), 2026-11-11

Branch `feat/agent-delegation-adr-0014` at HEAD `db0e03c` plus the uncommitted P6 working tree (proxy-only extension,
framed relay, daemon transport, attach-gated launch). Debug build, `--features agent`.

- Command: `AGENT_E2E_MATRIX=full AGENT_E2E_BROWSERS=chromium,pw-chromium,cft AGENT_E2E_HEADLESS=both AGENT_E2E_TIMEOUT=6600 tests/agent-e2e/run.sh`.
  First full run: 169 PASS, 24 XFAIL, 1 FAIL (E2E-22 on chromium/headed: the harness posted concurrent assertions
  to the RP out of counter order, which SimpleWebAuthn rejects; fixed in the scenario, which now verifies them in
  counter order). E2E-22 and E2E-51 were then re-run on all six variants: 12 PASS, exit 0. The table shows the
  final state. `make test-agent-e2e` (CI subset): exit 0, 21 PASS, 2 XFAIL.
- Browsers: distro Chromium 156.0.8078.79; Playwright Chromium (Chrome for Testing 156.0.8078.4, harness cache);
  Chrome for Testing 157.0.8103.50. Headed variants under Xvfb, headless with `--headless=new`.
- E2E-20 takes about 5.5 minutes per variant (the daemon holds the result for 330 s), so it is not in the CI subset.

| Scenario | chromium headed | chromium headless | pw-chromium headed | pw-chromium headless | cft headed | cft headless |
|---|---|---|---|---|---|---|
| E2E-01 same-user allow (SimpleWebAuthn) | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-02 isolated allow, register then authenticate | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-03 deny rule | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-04 unlisted RP | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-05 raw page, allowCredentials | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-06 `http://localhost` RP | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-07 credential selection | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-08 popup, same-origin iframe, blank/srcdoc/blob frames | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-09 request rule acts as deny | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-10 cross-origin iframe denied | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-11 old bearer after exit refused (wire protocol) | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-12 exact beats wildcard | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-12/audit-rule (until P8) | XFAIL | XFAIL | XFAIL | XFAIL | XFAIL | XFAIL |
| E2E-13 legacy config (4 parts) | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-14 replay, identical options | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-15 budget flood | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-16 native PublicKeyCredential, no shim | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-17 abort before key use | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-17/after-key-use | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-18 worker stopped between requests | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-19 worker killed mid-request | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-20 long wait (330 s hold) | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-20/escalation (until P7) | XFAIL | XFAIL | XFAIL | XFAIL | XFAIL | XFAIL |
| E2E-21 escalation timeout (until P7) | XFAIL | XFAIL | XFAIL | XFAIL | XFAIL | XFAIL |
| E2E-22 20 concurrent tabs | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-45 never native (before attach, conditional, worker stopped) | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-45/cdp-context (until P10) | XFAIL | XFAIL | XFAIL | XFAIL | XFAIL | XFAIL |
| E2E-47 missing extension | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-51 unfocused create, orphan cleanup | PASS | PASS | PASS | PASS | PASS | PASS |

Per variant: 28 PASS, 4 XFAIL. Smoke checks SMOKE-01/02 pass.

### Observations (identical on every variant)

- **Worker killed mid-request (E2E-19).** Chromium does not fail the pending proxy request when the worker dies; the
  page stays pending. The daemon cancels on the connection EOF (no key use, `policy.deny reason=aborted`). The page
  gets `NotAllowedError` only once a new worker instance starts and fails the leftover ids from
  `chrome.storage.session`; the scenario wakes it with `isUserVerifyingPlatformAuthenticatorAvailable()` from another
  tab. Without a wake-up the page would wait for its own timeout (at least 3 min, Chromium's clamp).
- **Keepalive (E2E-20).** With Playwright disconnected, a request held 330 s completes: one hello, no connection close,
  no degraded interception. The open native port with 20 s keepalives keeps the worker past the MV3 5-minute limit.
- **Worker restart (E2E-18, E2E-45).** `Target.closeTarget` stops the worker; the next request wakes it, it says hello
  on a new connection and the request succeeds. Chromium reuses the worker's CDP target ID across the restart.
- **Tabs.** The browser starts on `about:blank`; the daemon opens the start URL in a second tab after the attached
  hello, so Playwright sees both. `stack.open` selects the start-URL tab and brings it to the front.
- **Focus (E2E-51).** `create()` from a background tab fails with `NotAllowedError` ("does not have focus") after the
  daemon registered the credential; `get()` is not affected (E2E-22 runs 20 background-tab gets).
- **One pending request per tab.** A second concurrent `get()` in the same tab fails in Chromium with
  `OperationError: A request is already pending` before reaching the proxy; E2E-14 uses two tabs for its concurrent
  duplicate.
- **CDP-created contexts (E2E-45/cdp-context).** Not intercepted until incognito seeding (P10):
  `isConditionalMediationAvailable()` is true there. The scenario stops at that probe and never sends a ceremony, which
  would go to the native path, that is, to every FIDO hidraw device the user can open.

## P1 baseline

Scenarios E2E-01 to E2E-08 against the code at branch `feat/agent-delegation-adr-0014` (HEAD `3658ac5`, no product
changes), run on 2026-11-11.

- Command: `AGENT_E2E_MATRIX=full AGENT_E2E_BROWSERS=chromium,pw-chromium,cft AGENT_E2E_HEADLESS=both tests/agent-e2e/run.sh`
  (exit 0: 38 PASS, 12 XFAIL across 6 variants, plus the two harness smoke checks). `make test-agent-e2e` (CI subset) exits 0.
- Browsers: distro Chromium 156.0.8078.79; Playwright Chromium (Chrome for Testing build 156.0.8078.4, harness cache);
  Chrome for Testing 157.0.8103.50.
- Headed variants run under Xvfb, headless variants use `--headless=new`. Debug build, `--features agent`. Seeding
  runs under bwrap with only the run's own hidraw node.

### Results

| Scenario | chromium headed | chromium headless | pw-chromium headed | pw-chromium headless | cft headed | cft headless |
|---|---|---|---|---|---|---|
| E2E-01 same-user allow, authenticate (SimpleWebAuthn) | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-02 isolated allow, register then authenticate | XFAIL | XFAIL | XFAIL | XFAIL | XFAIL | XFAIL |
| E2E-03 deny rule | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-04 unlisted RP | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-05 raw page, allowCredentials | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-06 `http://localhost` RP | XFAIL | XFAIL | XFAIL | XFAIL | XFAIL | XFAIL |
| E2E-07 single / newest / credential:ref | PASS | PASS | PASS | PASS | PASS | PASS |
| E2E-08 popup and same-origin iframe | PASS | PASS | PASS | PASS | PASS | PASS |

Failures are identical across browsers and modes; each XFAIL is pinned to its expected error text (`xfailMatch`). Passing scenarios assert more than the page result: RP-side
verification (signature, flags, counter, origin, RP ID hash), `policy.allow`/`policy.deny` audit records, an unchanged
human store where no key use is expected, and no notification.

### Why the two XFAILs fail (tagged `xfailUntil: 'P6'`)

**E2E-06** fails before any browser work: the daemon exits with
`Configuration error: RP ID must have at least two labels: 'localhost'` (`validate_rp_id`, R15). The extension manifest
(`https://*/*` only, R12) is therefore not reached; once config accepts `localhost`, the same scenario will start
failing at the injection assertion until the matches are widened. Expected, as stated in the plan.

**E2E-02** fails in three independent places:

1. Registration needs an operator-minted one-shot enrollment grant even with `register = allow`
   (audit: `policy.deny reason=grant_not_found`). Removed in P3.
2. The daemon's `/register` returns the bare credential, but `worker.js` requires `create_attestation_result`, so the page
   gets `NotAllowedError` (broker reply `invalid_daemon_response`) although the daemon stored the credential. Not
   named in the plan; P6 rewrites the transport.
3. The registration authenticator data carries the raw 65-byte EC point instead of a COSE key. A real RP
   (SimpleWebAuthn) rejects it: "Leftover bytes detected while parsing authenticator data". **Not in the plan.**

### Other baseline findings the plan does not mention

- **Browser dies right after launch with the default `browser_scope = "session"`.** The browser is spawned with
  `PR_SET_PDEATHSIG` from the short-lived IPC handler thread, and Linux delivers it when that thread exits. The harness
  sets `browser_scope = "profile"`. (`agent-admin browser launch` and, likely, `EnsureBrowser`.)
- **The `--url`/`start_url` page is not intercepted.** Chromium navigates before the extension is active, so a WebAuthn call
  on that first page reaches the native/HID path (the human authenticator). The harness launches without a start URL and
  waits for the extension worker before navigating (P6 "interception always ready").
- **A profile whose rules are all `deny` does not start** (`invalid policy: allowed_actions must not be empty`; the whole agent
  subsystem fails and the human path continues). E2E-03 therefore denies rp-a next to an allowed unrelated RP.
- `max_session_ttl` above the default `max_grant_ttl` (300 s) logs `failed to request grant` and leaves the browser without a
  sign context; every same-user profile also needs its own unique `[device]` identity.
- Isolated profiles reject `browser_runtime_root` (default is `$XDG_RUNTIME_DIR/passless/browser`).
- An un-intercepted ceremony reaches every FIDO hidraw device the user can open (other Passless instances included).
  Human credentials are therefore seeded with a plain browser ceremony and verified against this run's own store.
