# E2E baseline

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
