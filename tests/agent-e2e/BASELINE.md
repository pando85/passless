# E2E baseline (P1)

Scenarios E2E-01 to E2E-08 against the code at branch `feat/agent-delegation-adr-0014` (HEAD `3658ac5`, no product
changes), run on 2026-11-11.

- Command: `AGENT_E2E_MATRIX=full AGENT_E2E_BROWSERS=chromium,pw-chromium,cft AGENT_E2E_HEADLESS=both tests/agent-e2e/run.sh`
  (exit 0: 38 PASS, 12 XFAIL across 6 variants, plus the two harness smoke checks). `make test-agent-e2e` (CI subset) exits 0.
- Browsers: distro Chromium 156.0.8078.79; Playwright Chromium (Chrome for Testing build 156.0.8078.4, harness cache);
  Chrome for Testing 157.0.8103.50.
- Headed variants run under Xvfb, headless variants use `--headless=new`. Debug build, `--features agent`. Seeding
  runs under bwrap with only the run's own hidraw node.

## Results

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

## Why the two XFAILs fail (tagged `xfailUntil: 'P6'`)

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

## Other baseline findings the plan does not mention

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
