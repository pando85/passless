# P0a spike results: `chrome.webAuthenticationProxy` (Q1, Q1b, Q2, Q3, Q6)

Browsers: `/usr/bin/chromium` 156.0.8078.79 and Playwright's Chromium (playwright-core 1.64.0 pins
build 1248 = Chrome for Testing 156.0.8078.4), each headed (Xvfb) and `--headless=new`.
Every claim below was observed identically on all four combinations unless a difference is stated
(outputs were diffed after masking request IDs, challenges and millisecond timings).

Test hosts: `http://rp-a.localhost:18731`, `evil.localhost`, `sub.rp-a.localhost` (`*.localhost`
is a secure context over plain http, so no TLS was needed; `--host-resolver-rules` maps `*.localhost`
and `*.test` to 127.0.0.1). Extension: unpacked MV3, `webAuthenticationProxy` permission, stable ID
from the manifest `key`, one control server (`lib.js`) that logs worker events and tells the worker
what to answer.

## Reproduce

```bash
cd tests/agent-e2e/spikes && npm install        # playwright-core 1.64.0 (pinned)
# Playwright Chromium (if ~/.cache/ms-playwright is missing):
PLAYWRIGHT_BROWSERS_PATH=$PWD/pw node node_modules/playwright-core/cli.js install chromium
export TMPDIR=<fresh scratch dir> PW_BROWSERS_PATH=$PWD/pw   # profiles/HOME are created under $TMPDIR
cd proxy
./run.sh q1-proxy-basic.js        # also: q1b-origin.js q1c-errors.js q1d-focus-stress.js
./run.sh q2-worker-lifecycle.js   # q2b-idle-and-reload.js (about 70 s per browser)
./run.sh q3-incognito.js
./run.sh q6-uvpaa-conditional.js  # UNATTACHED=1 for the native contrast run
# ONLY=chromium:headed,pw-chromium:headless-new restricts the matrix; SPIKE_PORT changes the control port
```

`run.sh` wraps each script in `dbus-run-session -- xvfb-run`; every browser launch gets a fresh
`HOME`, `XDG_*` and `--user-data-dir` under `$TMPDIR`. No real profile, bus or Passless store is touched.

## Summary

| Q | Answer |
|---|---|
| Q1 attach/create/get | YES. `attach()` ok, `onCreateRequest`/`onGetRequest` fire, page gets a native `PublicKeyCredential`. |
| Q1 cancel | YES. Page `AbortController.abort()` fires `onRequestCanceled(requestId)` for create and get. |
| Q1b origin supplied by browser | YES, as `extensions.remoteDesktopClientOverride.origin` and `.sameOriginWithAncestors` inside `requestDetailsJson`. There is no other origin field on the event. |
| Q1b who builds `clientDataJSON` | THE EXTENSION. Chrome does not validate it: a wrong origin, a wrong challenge and a missing `clientDataJSON` were all handed to the page. |
| Q1b page can forge the origin | NO. A page-supplied `remoteDesktopClientOverride` is overwritten by the browser's values (also from a cross-origin iframe). |
| Q1b `sameOriginWithAncestors` / top origin | `sameOriginWithAncestors` boolean: YES (false for a cross-origin frame). Top origin: NO, not provided. |
| Q1b RP ID checked before the event | YES. Mismatching/invalid `rpId` gives `SecurityError` and no proxy event. Permissions Policy is enforced before the event too. |
| Q2 attachment survives worker stop | YES (forced stop and natural idle stop). |
| Q2 request while worker stopped | The event WAKES the worker and is delivered; it does not go native. |
| Q2 second `attach()` | Does NOT throw (returns ok), also after `detach()`. |
| Q3a primary OTR, no seeding | NO (extension not loaded in OTR, requests go native). |
| Q3 seeding `incognito:true` in `Preferences` | YES, works without any UI, with stale or removed MACs, and even for a never-launched profile. |
| Q3b `Target.createBrowserContext` | Same as Q3a: NO unseeded, YES once seeded. Content script and proxy both apply when seeded. |
| Q6 | Attached: `isConditionalMediationAvailable()` = false; `isUVPAA()` is whatever the extension answers (`onIsUvpaaRequest` fires); conditional `get()` rejects immediately with `NotAllowedError`. |

## Q1: create, get, cancel (`q1-proxy-basic.js`)

```
attach result: ok
CREATE page result: {"ok":{"ctor":"PublicKeyCredential","isPKC":true,"respCtor":"AuthenticatorAttestationResponse","attachment":"cross-platform","hasToJSON":true,"transports":["usb"], ...}}
CREATE event payload: {"requestDetailsJson":"{\"attestation\":\"none\",\"authenticatorSelection\":{...},\"challenge\":\"...\",\"excludeCredentials\":[],\"extensions\":{\"remoteDesktopClientOverride\":{\"origin\":\"http://rp-a.localhost:18731\",\"sameOriginWithAncestors\":true}},\"pubKeyCredParams\":[...],\"rp\":{\"id\":\"rp-a.localhost\",\"name\":\"rp\"},\"timeout\":180000,\"user\":{...}}","requestId":1463185824}
GET event payload:    {"requestDetailsJson":"{\"allowCredentials\":[],\"challenge\":\"...\",\"extensions\":{\"remoteDesktopClientOverride\":{...}},\"rpId\":\"rp-a.localhost\",\"timeout\":180000,\"userVerification\":\"preferred\"}","requestId":-1381853939}
CANCEL create page result: {"err":"AbortError: signal is aborted without reason"}
onRequestCanceled after create abort: [{"requestId":349374270}]   (same requestId as the create event)
CANCEL get page result: {"err":"AbortError: ..."}  ->  onRequestCanceled [{"requestId":1282494559}]
```

- The create response was a real ES256 key (WebCrypto) with a `none` attestationObject (hand-built CBOR);
  the page got `PublicKeyCredential` with `AuthenticatorAttestationResponse`.
- The event has exactly two top-level fields, `requestDetailsJson` and `requestId`.
- Page `timeout: 120000` arrived as `timeout: 180000` (Chrome clamps to 3 min minimum).
- `q1c-errors.js`: `completeCreateRequest/GetRequest({error:{name}})` surfaces to the page as a
  `DOMException` with that exact name for every name tried (NotAllowedError, AbortError,
  InvalidStateError, SecurityError, NotSupportedError, ConstraintError, UnknownError, TypeError,
  NetworkError, TimeoutError, even an invented `WhateverError`). A `responseJson` that is not a valid
  credential (`{"x":1}`) leaves the page request hanging (get) / pending (next create gets
  `OperationError: A request is already pending`). `complete*` with an unknown id gives
  `lastError: Invalid requestId`.

### Focus rule (`q1d-focus-stress.js`), surprise

```
single tab x40:                         {"create:credential":20,"get:credential":20}
two tabs (older tab in front of new):   {"create:NotAllowedError: ...page does not have focus":20,"get:credential":20}
new tab, bringToFront x40:              {"create:credential":20,"get:credential":20}
```

`create()` from a tab that is not the active tab is rejected with `NotAllowedError ... does not have
focus` even though the proxy event fired and the extension answered (the extension had already
completed the request). `get()` is not affected. Same on all four browser/mode combinations
(headless included). A daemon that creates a credential on `onCreateRequest` can therefore end up
with an orphan credential the RP never receives.

## Q1b: origin provenance (`q1b-origin.js`)

Baseline (page on `http://rp-a.localhost:18731`), what the extension saw:

```
ext saw: {"rpId":"rp-a.localhost","ext":{"remoteDesktopClientOverride":{"origin":"http://rp-a.localhost:18731","sameOriginWithAncestors":true}}, ...}
```

**clientDataJSON ownership.** The extension builds it; the browser passes it through unchecked:

```
2a wrong clientData.origin (create)  -> page got cd.origin "https://evil.test"   (credential returned)
2a wrong clientData.origin (get)     -> page got cd.origin "https://evil.test"
2b wrong clientData.challenge (both) -> page got cd.challenge "AAAA..."          (credential returned)
2c clientDataJSON omitted (both)     -> credential returned with an EMPTY clientDataJSON (Chrome does not build one)
```

So the trust anchor is `remoteDesktopClientOverride.origin` in the event plus the extension (or daemon)
building `clientDataJSON` itself; nothing in Chrome checks the result.

**Forgery from the page** (`extensions: {remoteDesktopClientOverride: {origin: "https://evil.test", sameOriginWithAncestors: ...}}`):

```
3a forged (get)    -> ext saw origin http://rp-a.localhost:18731, sameOriginWithAncestors true
3b forged (create) -> ext saw origin http://rp-a.localhost:18731, sameOriginWithAncestors true
3c forged with sameOriginWithAncestors=false -> ext saw the real values (true)
5y cross-origin frame forges {origin: top, sameOriginWithAncestors:true} -> ext saw {"origin":"http://evil.localhost:18731","sameOriginWithAncestors":false}
```

The page value is not merged or passed through; the browser's own object replaces it.

**Frames.** Same-origin iframe (no `allow`): works, `sameOriginWithAncestors:true`. Cross-origin iframe with
`allow="publickey-credentials-get *; publickey-credentials-create *"`: event fires with
`origin` = the frame's origin and `sameOriginWithAncestors:false`. Without `allow`: `NotAllowedError: The
'publickey-credentials-get' feature is not enabled in this document` and NO proxy event. The top-level origin is
not exposed anywhere in the event (a cross-origin frame asking for the top page's rpId gets `SecurityError`
and no event).

**RP ID validation order.** All of these returned `SecurityError` with no proxy event (get and create):

```
page rp-a   -> rpId evil.localhost        SecurityError: The relying party ID is not a registrable domain suffix of, nor equal to the current domain. Subsequently, an attempt to fetch the .well-known/webauthn resource of the claimed RP ID failed.
page evil   -> rpId rp-a.localhost        same
page rp-a   -> rpId localhost / sub.rp-a.localhost / "rp-a.localhost:18731" / "https://rp-a.localhost"   same (the last two without the .well-known sentence)
page sub.rp-a.localhost -> rpId rp-a.localhost   OK, event fires, origin http://sub.rp-a.localhost:18731
```

The `.well-known/webauthn` sentence shows Chrome tries related-origin validation before rejecting. That
path needs https and was not exercised (see unknowns): with a related origin the event could carry an RP
ID that is not a suffix of the origin, so the daemon must keep its own origin/RP ID check.

## Q2: worker lifecycle (`q2-worker-lifecycle.js`, `q2b-idle-and-reload.js`)

```
(a) attach() again while attached: ok
(a) detach()+attach(): detach=ok attach=ok
(b) stop worker via CDP Target.closeTarget: stopped
(b) get while worker stopped -> credential (proxy handled it) | 1 workerStart, attach=ok, 1 onGetRequest
(c) stop worker (restart will skip attach()) ... get -> credential (attachment persisted) | 1 workerStart, 1 onGetRequest
(e) idle attached worker: stopped after ~30s of idleness
(e) get after natural idle stop (restart skips attach()) -> credential (attachment persisted, event woke worker)
```

- The attachment is browser-side state and outlives the worker. Event listeners registered
  synchronously at worker top level wake the stopped worker, which then receives the event.
  Re-running `attach()` on every worker start is harmless (no throw), but not required.
- `q2b` runs WITHOUT Playwright: Playwright's `connectOverCDP` auto-attaches to service workers (like an
  open DevTools) and keeps them alive; with it the worker never idle-stopped in 60 s.
- Request in flight when the worker dies: not tested (requests were answered promptly).

Extension reload:

```
(f) worker target after chrome.runtime.reload(): false
(f) manifest probe BEFORE reload: chrome-extension: { "manifest_version": 3, ...
(f) manifest probe AFTER reload:  chrome-error: <id> is blocked
(f) get after reload, attach() NOT re-run -> {"err":"TimeoutError: signal timed out"} | 0 workerStart, 0 onGetRequest
```

`chrome.runtime.reload()` on a `--load-extension` extension left the extension unloaded (blocked, no worker)
in all four builds. The page request then reached no extension: no event, and it stayed pending until aborted,
which is consistent with the native path (not directly observable here). So when the extension instance is gone, requests are NOT answered by the proxy and
fall through to Chrome's own authenticator handling (D6 containment has to cover that).

## Q3: incognito without user interaction (`q3-incognito.js`)

Switch search: `strings` on the Chromium binary shows no command-line switch that enables an extension in
incognito (only unrelated CSS variables and `enforce-incognito-isolation`). No policy was tried (needs a root-owned
policy dir).

Seeding works: write `{"extensions":{"settings":{"<id>":{"incognito":true}}}}` into `<profile>/Default/Preferences`.
In this build the unpacked extension's settings live in `Preferences` (not `Secure Preferences`) with
`protection.macs`; the MACs are not enforced.

```
[unseeded] normal launch:   isAllowedIncognitoAccess=false
   default page:                         content-script ran: true  | get -> credential via proxy | onGetRequest: 1
   (b) createBrowserContext page:        content-script ran: false | get -> timeout (no event)    | onGetRequest: 0
[unseeded] --incognito:
   (a) primary OTR window page:          content-script ran: false | get -> timeout (no event)    | onGetRequest: 0
   (b) createBrowserContext page:        content-script ran: false | get -> timeout (no event)    | onGetRequest: 0
[seeded: edit Preferences of an existing profile, MACs stale]            -> isAllowedIncognitoAccess=true
   (a) primary OTR (--incognito):        content-script ran: true  | get -> credential via proxy | onGetRequest: 1
   (b) createBrowserContext page:        content-script ran: true  | get -> credential via proxy | onGetRequest: 1
[seeded: protection block deleted]                                       -> same results
[seeded BEFORE FIRST LAUNCH: Preferences containing only that one key]   -> same results, seed kept on relaunch
```

- The proxy attachment is profile-level and, once incognito access is granted, covers the OTR profile and
  the CDP-created contexts with the same single `attach()`. Until then OTR traffic is not intercepted and is
  not blocked either (it goes native).
- Seeding is a file write the daemon can do before launching a fresh profile; no second launch needed.
- Caveat: relies on this (Chromium/CfT) build not enforcing preference MACs. Branded Chrome was excluded by the brief.

## Q6: conditional mediation and UVPAA (`q6-uvpaa-conditional.js`)

```
ATTACHED   isConditionalMediationAvailable -> false     (native, not attached: true)
ATTACHED   isUserVerifyingPlatformAuthenticatorAvailable -> true when the extension answers true, false when it answers false
           onIsUvpaaRequest events: 2 per round (presumably isUVPAA() and getClientCapabilities(); isConditionalMediationAvailable fired none), completeIsUvpaaRequest -> ok
ATTACHED   extension never answers -> isUVPAA() and getClientCapabilities() hang (isConditionalMediationAvailable still false, immediate)
ATTACHED   conditional get -> NotAllowedError after ~0 ms, no onGetRequest, no onRequestCanceled; a modal get afterwards works
UNATTACHED isConditionalMediationAvailable -> true, isUVPAA -> false, no events; conditional get stays pending until aborted
```

`getClientCapabilities()` reports `conditionalGet:false` while attached (`true` natively).

## Unknowns

- Related-origin requests (RP ID that is not a suffix of the origin, `.well-known/webauthn`) need https and
  were not tested; the daemon must not rely on a suffix rule alone being enforced by Chrome.
- Nested frames (cross-origin frame inside a cross-origin top), `onRequestCanceled` on navigation or tab close,
  and a worker dying with a request in flight were not tested.
- Whether a native request while detached would reach a real HID device was not probed (no readable
  `/dev/hidraw*` on this machine, no Passless daemon running); only "no proxy event, request pending" was observed.
- Preference MAC enforcement may differ on other builds (branded Chrome, Edge, Brave).
