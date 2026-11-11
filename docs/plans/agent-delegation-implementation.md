# Agent delegation implementation plan (ADR 0014)

- **Status:** Active
- **Branch:** `feat/agent-delegation-adr-0014`, based on `master` at `130eaa5`
- **Design:** [ADR 0014](../decisions/0014-agent-delegation.md). This plan carries its §19 gap list
  to completion.
- **Execution model:** the main session orchestrates and verifies. Subagents implement, test and
  review. Phases run one after another because they share files and the build.
- **Done when:** every row in the [traceability matrix](#traceability-matrix) has a merged
  implementation and a passing test, and the [final gate](#final-gate) passes.

## Resume here after compaction

1. Read this file, ADR 0014, and `git log --oneline master..HEAD`.
2. Find the first phase in the [progress log](#progress-log) that is not ✅. Continue from its
   checklist.
3. Follow [How each phase is executed](#how-each-phase-is-executed). Do not skip verification.

## Decisions

### Maintainer decisions (2026-11-10)

- Ceremonies are autonomous only. Rules are `deny | allow | request`. Escalation goes through a
  trusted notification, and approval persists into a granted-rules store.
- Approval is persistent for `authenticate`. A registration approval is one-shot and then
  persists `authenticate = allow` for that RP. `register = "allow"` is the separate autonomous
  setting.
- Escalation waits up to Chromium's own ceremony timeout: clamp(page timeout, 3 min, 20 h),
  defaulting to 20 h.
- Grants are permanent until revoked. Cooldown is 10 min. `max_granted_rules` is 64.
- The wildcard is kept but constrained. The bearer-session replay model replaces ADR 0007's
  state machine. Mode and UID relationship are separate axes.
- Removed: CLI-minted enrollment grants (#411), the isolated UHID route, `confirm`, `supervised`
  and human evidence.
- All agent ADRs are consolidated into ADR 0014, and the old files are deleted.
- The Playwright MCP integration may be reworked freely. Goal: an easy way for agents to use
  Passless with a browser, integrated with the most common agent-browsing tools.
- Designs must be validated by at least one Opus reviewer before implementation (see
  [Design validation](#design-validation)).

### Pending maintainer answers

Defaults are applied until answered.

| # | Question | Default applied |
|---|---|---|
| M1 | Commit each verified phase locally on the branch? | Yes: local Conventional Commits, no push, no PR |
| M2 | Run E2E tests against a public RP (webauthn.io) with throwaway users? | No: local RP only |
| M3 | Switch the maintainer's opencode/Claude Code Playwright MCP config and delete the stale `~/.local/bin/playwright-mcp-passless`? | No: document only |
| M4 | Version bump or release? | None. Legacy config is accepted with a warning until the release after next (R8). |

### Orchestrator resolutions

These resolve the open implementation questions. The maintainer may override any of them.
Rows marked *amended* were applied to the ADR in phase P0b.

| # | Topic | Resolution | ADR |
|---|---|---|---|
| R1 | Kanidm resubmits an identical request (`sign.rs:300-308`) | An identical replay key never causes a second signature. While the first request is in flight, the duplicate joins it. After completion, the duplicate receives the original result for 120 s, in the same session only. Any other repeat is rejected. | amended §9 |
| R2 | Notification bus for the root (distinct-UID) daemon | `agents.notify_user` names the human whose session bus receives escalation prompts. The user unit uses its own bus. If no bus can be resolved, escalation is unavailable: deny and audit. | amended §8.2 |
| R3 | Granted-rules location | `agents.state_dir`. The user unit defaults to `$XDG_STATE_HOME/passless/agent`. The system unit defaults to `/var/lib/passless-agent` (systemd `StateDirectory=`). | amended §8.4 |
| R4 | Claim timing (revised by V-H2) | Order: origin/RP check → resolve → (if `request`) cooldown, grant cap, bus and queue checks → replay key → wait → budget claimed after approval. For `allow`: replay key, then budget, before audit. Rejected requests never consume budget. | amended §9 |
| R5 | Several ceremonies waiting on one `register` escalation | **Superseded by V-M3.** Registration escalations are not joinable. The one-use token is bound to the creating ceremony, and a concurrent duplicate is denied. | amended §8.3 (V-M3) |
| R6 | Legacy isolated `device` key and agent udev rule | Warn and ignore for one release. Remove the agent UHID udev and systemd device access. | — |
| R7 | CLI naming collision | Granted rules use `passless agent-admin grants`. The existing session-grant commands move to `passless agent sessions`, with a hidden alias for one release. | amended §8.4 |
| R8 | Deprecation channel | A startup warning plus a `passless doctor` warning. Legacy parsing is removed in the release after next. | — |
| R9 | Aborted escalation audit | `escalation_expired` with `reason = timeout or aborted`. `escalation_revoked` is only for operator revocation. | amended §12 |
| R10 | Pinned `credential_refs` and a registration grant | The credential ref of a registration-kind grant joins the pinned set for that RP. | amended §8.3 |
| R11 | Sign-server capacity | No silent drops. Use per-connection and global caps on concurrent requests. Overflow returns an explicit `busy` error. | — |
| R12 | Interception mechanism | **Resolved (P0a):** `chrome.webAuthenticationProxy` is the primary path and the only one. The MAIN-world override is removed. See D1. | amended §4.4, §11 |
| R13 | Extension in CDP-created (incognito-like) contexts | **Resolved (P0a):** enable the managed extension in incognito by seeding `extensions.settings.<id>.incognito = true` into the fresh profile's `Default/Preferences`. Adapters need not forbid isolated contexts. See D4. | amended §4.2 |
| R14 | Supported browsers | Chromium, and Chrome for Testing. Branded Google Chrome and `chrome-headless-shell` are rejected at launch with a clear error. Edge and Brave were not probed in P0a and are unsupported for now. Detection must not match "Google Chrome for Testing". In distinct-UID deployments, only root-owned, principal-unwritable binaries are accepted. | amended §4.2 |
| R15 | `localhost` RP | `rp_id = "localhost"` and `http://localhost[:port]` origins are valid for exact rules only, never through the wildcard. `validate_rp_id` and `parse_origin` are extended accordingly. | amended §6.1 |
| R16 | Policy epochs (V-H3) | Split the revocation epoch (bumped by reload, grant revocation and config change; revokes sessions) from the grant epoch (bumped when a grant is added; does not revoke). Ceremonies resolve against the live config plus grants, never against the frozen `ctx.profile_config`. The pre-key-use check compares the revocation epoch and re-resolves the rule. | amended §6.4, §8.4, §9 |
| R17 | Managed browser must never reach the human authenticator (V-C1) | See D6. Requests the extension does not handle fail closed instead of reaching the native path. | amended §7, add invariant 25 |
| R18 | Self-approval by a same-UID agent (V-H4) | A shared-UID agent can drive the user's notification server (`dunstctl`, `makoctl`, a replaced server). This cannot be prevented and is documented as residual risk. In distinct-UID deployments (root daemon) `notify_user` must differ from every `principal_user`/`browser_user`; in the shared-UID user unit it is the same user by design and the residual risk applies. The root daemon talks to the user bus only through a dedicated per-prompt child that lives as long as the prompt and drops to `notify_user`; the daemon can kill it to withdraw the prompt. | amended §8.2, §13, §15 |
| R19 | Automatic interaction mode with agents (V-C1) | If `PASSLESS_INTERACTION_MODE=automatic` is set and any same-user profile has `allow` or `request`, the daemon refuses to start agents unless `agents.allow_automatic_human_path = true`, and `doctor` flags it. | amended §7 |

## Investigation facts this plan relies on

### Code facts (at `130eaa5`)

- The operation lock is taken before policy resolution (`sign.rs:1276`, `register.rs:73`). In
  same-user mode this is the human authenticator's lock. **Nothing may wait on a human while
  holding it.**
- The daemon is thread-per-connection. tokio is a dev-dependency only. The sign server caps
  connections at 8 and drops silently (`sign.rs:721`, `765`).
- `PolicyRuntime::reload` replaces the session-grant registries and so wipes every session
  (`policy_engine.rs:1086`). Granted rules must use a separate additive path.
- `prompt.rs` subscribes to D-Bus signals after showing the notification (`793-805`), so an early
  click is lost. It also clamps the timeout to 300 s (`l.20`) and renders `untrusted_*` text
  (`250-262`, `381-399`).
- Extension (`cmd/passless/assets/agent-extension/`):
  - the manifest matches only `https://*/*`;
  - `main.js` caps the timeout at 120 s and handles abort only locally;
  - `worker.js:126` uses `sendNativeMessage`;
  - `sign-proxy.rs` has a 10 s socket timeout.
- Tests:
  - about 1,300 Rust unit tests in agent modules;
  - no JS tests for the extension, apart from `cmd/passless/tests/agent_extension_behavioral.js`,
    which runs from `browser.rs:6765`;
  - no real-browser test with the extension loaded;
  - the live validation stages launch Chromium with `--disable-extensions`;
  - CI never starts a browser.

### Browser facts (spike in `scratchpad/spike`; research cited in the session)

| Browser / mode | Extension loads | Default ctx | `newContext()` ctx | Popup / iframes |
|---|---|---|---|---|
| Chromium 156, headed (Xvfb) and `--headless=new` | yes | override ✅ | native ❌ | ✅ |
| Playwright chromium 155, headed and `--headless=new` | yes | ✅ | ❌ | ✅ |
| Google Chrome 157, branded | **no** (`--load-extension` ignored) | ❌ | ❌ | ❌ |
| `chrome-headless-shell` | **no** | ❌ | ❌ | ❌ |
| any browser, `http://localhost` page | loaded but not injected (manifest is https-only) | ❌ | ❌ | ❌ |

P0a answered the open items below; see the [proxy](../../tests/agent-e2e/spikes/RESULTS-proxy.md)
and [environment](../../tests/agent-e2e/spikes/RESULTS-env.md) results and the P0a checklist.

- Playwright MCP 0.0.85 with `--cdp-endpoint` uses `contexts()[0]` and works. Adding `--isolated`
  calls `newContext()` and breaks. Its `browser_tabs` `isolatedContext` also creates an OTR
  context.
- chrome-devtools-mcp: `--browserUrl` / `--wsEndpoint` attach and work. Its `isolatedContext`
  creates an OTR context and breaks. Launching its own browser defaults to branded Chrome and
  breaks.
- browser-use (`cdp_url`), agent-browser (`--cdp`, and native `--extension` support), Stagehand
  (`executablePath`) and Playwright `connectOverCDP` can all attach. Their own launches default to
  branded Chrome or `--disable-extensions` and break.
- `chrome.webAuthenticationProxy`:
  - it is MV3 stable on Linux, the browser routes create/get/isUVPAA to the extension, and the
    origin is browser-supplied;
  - pages receive a native `PublicKeyCredential`;
  - spanning extensions with incognito access also cover OTR profiles;
  - conditional mediation is rejected while attached, an active virtual authenticator takes
    precedence, and `attach()` must be re-run when the worker restarts;
  - unverified with an unpacked extension and in new headless (P0a: verified on both).
- Chromium WebAuthn timeout is clamp(page timeout, 3 min, 20 h), or 20 h when unset
  (`AdjustTimeout()`, `fido_constants.cc`, verified). Under MV3, `sendNativeMessage` and events
  are limited to 5 min and `fetch` to 30 s. A `connectNative` port keeps the worker alive.

### Defects found by the P1 baseline

| # | Defect | Fixed in |
|---|---|---|
| B1 | With `browser_scope = "session"`, `PR_SET_PDEATHSIG` fires when the short-lived IPC handler thread that spawned the browser exits, so the managed browser is killed right after launch | P10 (P10a: browsers are forked on a long-lived launcher thread) |
| B2 | A launch `--url` page loads before the extension worker has attached, so a ceremony on it reaches the native path | P6 (readiness: navigate only after the worker's `hello` reports `attached`) |
| B3 | Registration `authenticatorData` carries a raw EC point instead of a COSE_Key, so real RPs reject the attestation | P3 |
| B4 | A profile whose rules are all `deny` fails to start (`allowed_actions must not be empty`) | P4 |
| B5 | `max_session_ttl` above 300 s breaks session grant creation | P5 |
| B6 | Every profile needs a unique `[device]` | P3 (UHID route removal) |
| B7 | Isolated profiles reject `browser_runtime_root` | P10 |

## Designs

### D1 Interception

`chrome.webAuthenticationProxy` in the service worker is the only interception path (P0a gate
passed, see the [proxy results](../../tests/agent-e2e/spikes/RESULTS-proxy.md)). The MAIN-world
`navigator.credentials` override is removed.

- **Worker.**
  - `attach()` runs on every worker start; a repeated call is idempotent.
  - Listeners are registered synchronously at the top level, so a request wakes a stopped worker.
    The attachment persists across worker stops.
  - The worker never calls `chrome.runtime.reload()`. An unloaded extension sends requests to the
    native path, which is another reason for D6.
- **Requests.**
  - `onCreateRequest` / `onGetRequest` forward `requestDetailsJson` verbatim to the daemon.
  - The reply goes through `completeCreateRequest` / `completeGetRequest` with the daemon's
    `responseJson` verbatim, or an error name that the page sees as a DOMException.
  - `onRequestCanceled` sends `abort` to the daemon.
- **UVPAA.** The worker answers every `onIsUvpaaRequest` with `false` (V-L2); an unanswered request
  hangs the page.
- **Origin.**
  - The origin comes only from the browser-supplied `extensions.remoteDesktopClientOverride.origin`
    inside `requestDetailsJson`. A page cannot forge it: the browser overwrites a page-supplied
    value, also from a cross-origin frame.
  - `sameOriginWithAncestors` comes from the same object.
  - The top origin is not available on this path, so the audit records `top_origin = null` plus
    `cross_origin`.
  - A request with `sameOriginWithAncestors = false` is denied (cross-origin fails closed).
- **`clientDataJSON`.** Chrome does not validate what the extension returns. The daemon alone
  builds it (type, challenge, origin, `crossOrigin`) from the validated request and signs over its
  hash. The extension forwards daemon output verbatim and never constructs or edits it.
- **RP ID.** Chrome validates the RP ID against the origin, and the iframe Permissions Policy,
  before the event fires. The daemon still runs its own origin and RP-ID check (defence in depth;
  related origins were not tested).
- **Conditional mediation.** While attached, `isConditionalMediationAvailable()` returns false and a
  conditional `get()` rejects with `NotAllowedError`. Passkey autofill UI is unsupported for agents
  and documented as such.
- **Focus caveat.** `create()` from a tab without focus is rejected by Chrome even after the
  extension completed the request, so a registration can complete in the daemon while the page gets
  `NotAllowedError`, leaving an orphan credential in the isolated profile store. This is a known
  limitation: the audit records the registration and the operator can delete the credential.
  Adapters bring the target page to the front before ceremonies where they can (E2E-51).
- **Not tested in P0a:** related-origin requests (need https), nested cross-origin frames,
  `onRequestCanceled` on navigation or tab close, and a worker dying with a request in flight.

### D2 Transport

- **One port per browser.** The service worker lazily opens one long-lived
  `chrome.runtime.connectNative("rs.passless.sign_proxy")` port.
- **Relay.** `sign-proxy` becomes a two-thread relay between the native-messaging frames (4-byte
  LE length + JSON) and one persistent Unix-socket connection that uses the same framing.
- **Frames:**
  - `hello{v:2, build_version, bearer, attached, incognito_allowed}`, where `incognito_allowed` is
    the result of `chrome.extension.isAllowedIncognitoAccess()` (D4, D6.1)
  - `request{id, op, timeout_ms, origin, cross_origin, body}`, where `body` carries
    `requestDetailsJson` verbatim
  - `abort{id}`
  - `result{id, ok, body | error{code, dom}}`
  - `keepalive`
- **Daemon side:**
  - one reader thread per connection;
  - a bounded worker pool for requests;
  - a write mutex;
  - per-connection and global caps (R11);
  - a keepalive at most 20 s apart while anything is pending.
- **Failure handling:**
  - EOF cancels every in-flight request on that connection;
  - the worker's `onDisconnect` rejects outstanding requests with `NotAllowedError`, with no
    resume (replay keys are consumed);
  - a version mismatch in `hello` fails closed.
- **Removed:** the HTTP `/sign` and `/register` endpoints.
- **Request identity and origin:**
  - Wire IDs are allocated by the worker and map to the proxy `requestId`. In-flight requests are
    keyed by the proxy `requestId`, scoped to the connection. The event carries no tab or frame, so
    there is no `(tabId, frameId)` key.
  - `origin` and `cross_origin` are `remoteDesktopClientOverride.origin` and
    `sameOriginWithAncestors` (as `cross_origin = !sameOriginWithAncestors`), copied by the worker
    out of `requestDetailsJson` unmodified. There is no `top_origin` on the wire.
  - The daemon re-parses `requestDetailsJson` itself and never trusts the worker-extracted copy.

### D3 Escalation

The daemon is threaded, not async. `EscalationService` (new `escalation.rs`) owns a single mutex
over:

- pending entries keyed by `(profile, rp, action)`, each with a condvar, waiter count, origin,
  notification ticket and state;
- a cooldown map;
- per profile, one active prompt and a bounded queue.

There is one prompt thread per profile.

**Ceremony flow:**

1. Authenticate the bearer.
2. Validate origin and RP.
3. Resolve the rule to `request`.
4. Deny if in cooldown, at the grant cap, with no notification bus, or if the queue is full.
5. Check the replay key (R1). A duplicate of an in-flight request joins it.
6. Join or create the escalation. The creator writes `escalation_requested`. Authenticate
   escalations are joinable; registration escalations are not (V-M3).
7. Wait in a timed loop on the condvar, checking the cancel token and the deadline.

Budget is claimed only after approval (R4 as revised by V-H2). A rejected, denied, expired or
aborted escalation never consumes budget.

Approval is accepted only from the verified D-Bus sender, and only while the entry is still
Pending. On approval:

1. Write `escalation_approved`.
2. Persist the grant under the per-profile store mutex.
3. Call `bump_generation_additive()`, which does not revoke sessions.
4. Wake the waiters.
5. Each waiter claims budget, re-resolves to `Granted`, then takes the operation lock, re-checks
   the revocation epoch, reserves audit and executes.

Registration approval issues a one-use token bound to the creating ceremony (V-M3). Its `authenticate` grant is persisted only
after the credential is created.

On deny or timeout: audit the outcome, set the cooldown, and fail the waiters.

On abort: decrement the waiter count. When it reaches 0, the entry becomes Withdrawn, the
notification is closed, and a late click does nothing.

A config reload cancels the profile's pending escalations.

**Lock order:** escalation state → policy `RwLock` → sign registry → operation lock. No audit
I/O, D-Bus call or store I/O happens while holding the escalation mutex. No human wait happens
under the operation or storage lock.

**`prompt.rs` changes:**

- subscribe before `Notify`;
- `expire_timeout = 0`;
- actions limited to **Allow always** and **Deny**;
- daemon-derived fields only;
- withdraw with `CloseNotification`.

### D4 Agent-browser integration ("easy path")

**One entry point.** `passless agent browser [--profile P]` (idempotent):

- ensures the managed browser for the calling principal;
- prints the CDP HTTP endpoint (the existing bootstrap `GET /json/version`, made stable per
  principal session);
- `--json`, `--env` (prints `PASSLESS_CDP_URL=…`) and `--wait` (blocks until the browser is
  ready).

**Browser selection.** Auto-detect, in this order:

1. an explicit `agents.browser_path`;
2. Playwright's Chromium in `~/.cache/ms-playwright`;
3. Chrome for Testing;
4. distro `chromium`.

Detection and rejection (R14):

- Supported: Chromium and Chrome for Testing. Chrome for Testing is detected from the `--version`
  output ("Google Chrome for Testing …"); the user agent does not distinguish it. The branded-Chrome
  check must not match that string.
- Rejected with an actionable error: branded Google Chrome (ignores `--load-extension`) and
  `chrome-headless-shell` (loads no extensions). `chrome-headless-shell` is recognised by its binary
  name or install path: P10b confirmed that its `--version` prints `Google Chrome for Testing <version>`,
  the same as the full binary.
- Edge and Brave were not probed and are unsupported for now.
- In distinct-UID deployments only root-owned, principal-unwritable binaries are accepted (V-H7).

The default is `--headless=new`; `--headed` is optional.

**Contexts.**

- **Seeding (R13).** The launcher writes `Default/Preferences` into the fresh `--user-data-dir`
  before the first launch, containing `{"extensions":{"settings":{"<id>":{"incognito":true}}}}`.
  `<id>` is the stable extension ID derived from the manifest `key`; the manifest has no `key` today,
  so P10 adds one. P0a verified that this works without UI, with a profile that was never launched,
  and with stale or absent preference MACs, on Chromium 156 and Chrome for Testing 156. The
  extension and the proxy then apply in the primary off-the-record profile and in
  `Target.createBrowserContext` contexts, which is what Playwright `newContext()`, Playwright MCP
  `--isolated` and chrome-devtools-mcp `isolatedContext` use. Without the seed those contexts go
  native.
- **Fail-closed verification.** The worker calls `chrome.extension.isAllowedIncognitoAccess()` and
  includes the result in `hello` (D6.1). The bootstrap withholds the endpoint, and the launch fails,
  unless it is `true`. A seed that did not take effect is a launch error, never a browser whose
  isolated contexts go native.
- **Caveat.** The seed relies on Chromium and Chrome for Testing not enforcing preference MACs for
  this key; P10 re-checks it for each supported browser version.

**Adapters** (stdio MCP launchers that resolve the endpoint lazily on first tool use):

- `passless agent mcp playwright [-- <extra @playwright/mcp args>]` runs
  `npx @playwright/mcp --cdp-endpoint <url>`. This replaces the current
  `passless agent playwright-mcp` supervisor, with a hidden alias kept for one release.
- `passless agent mcp chrome-devtools` runs `npx chrome-devtools-mcp --browserUrl <url>`.

**Generic recipes,** documented and E2E-tested where noted:

- Playwright library `connectOverCDP` (tested);
- browser-use `cdp_url` (tested locally);
- agent-browser `--cdp` (tested locally);
- Stagehand with `cdpUrl` / `executablePath` (documented).

**Supporting changes:**

- **Config snippets:** `passless agent mcp --print-config {claude-code|opencode|cursor|vscode}`
  emits a ready-to-paste MCP server entry.
- **Doctor:** `passless doctor --agents` checks for a supported browser binary, extension load,
  native-host manifest install, notification bus, and state dir permissions.
- **Skill:** the `passless-agent` skill and `docs/agents/` are rewritten around these commands.

### D6 Native-path containment (V-C1)

A WebAuthn request from the managed browser must never reach the human authenticator (ADR
invariant 25). P0a showed that no command-line switch or feature flag disables CTAP over HID (plain
Chromium created a credential through the UHID device with every candidate flag), and that the
binary's policy list contains no policy that does (enterprise policy installation was not tested).
Containment is therefore mandatory and based on the filesystem and the UID. There
are four layers.

1. **Interception always ready.**
   - The worker opens the native port on startup and keeps it open, with keepalive in both
     directions, not only while a request is pending.
   - `attach()` runs before the worker reports `hello{attached:true, incognito_allowed:true}`
     (D4: `chrome.extension.isAllowedIncognitoAccess()`).
   - `passless agent browser --wait` and the CDP bootstrap do not return an endpoint until that
     hello arrives.
   - If the port drops, or `attach()` fails or is lost, the daemon marks the lease degraded and
     the bootstrap stops handing out the endpoint until the worker re-attaches.
   - The worker never calls `chrome.runtime.reload()`: an unloaded extension sends requests to the
     native path (P0a), so no code path may unload it.
2. **Launch fails closed.**
   - A missing or unloadable extension directory is a launch error, never `--disable-extensions`
     (`browser.rs:2040-2044`).
   - Browsers that cannot load the extension are rejected (R14, D4).
   - A failed incognito seed (D4) is a launch error.
3. **No device access.** The managed browser gets no access to any `/dev/hidraw*`.
   - **Private `/dev` through `bwrap`** (verified on distro Chromium 156, headed and
     `--headless=new`; P10a verified Playwright Chromium and Chrome for Testing too, in port and
     pipe mode):

     ```text
     bwrap --dev-bind / / --dev /dev --die-with-parent <browser> <browser args>
     ```

     The private `/dev` contains `core fd full null ptmx pts random shm stderr stdin stdout tty
     urandom zero`: no `hidraw*` and no `uhid`. Chromium's own sandbox keeps working inside it, with
     no `--no-sandbox` (browser `NoNewPrivs=1`, renderers in their own user and pid namespaces with
     seccomp). Side effects: the UID is unchanged and supplementary groups are not dropped (an
     unprivileged user namespace shows them as the overflow GID 65534, but they stay effective for
     permission checks, so the `fido` group still applies to whatever the browser can reach; the
     private `/dev` is what removes the nodes); `/sys/class/hidraw` stays visible but the nodes do
     not exist;
     the host `/dev/shm` is hidden, so something shared through it needs `--bind /dev/shm /dev/shm`,
     which does not expose hidraw; headed mode needs the X socket, which `--dev-bind / /` keeps
     visible.
   - **When it applies.** The launcher always runs the managed browser in the private `/dev` when
     `bwrap` and unprivileged user namespaces are available, as defence in depth.
   - **Launcher refusal.** The private `/dev` is required when the browser's UID, with its groups,
     could open any `/dev/hidraw*` (a `faccessat2(AT_EACCESS, R_OK|W_OK)`, ACLs included, evaluated
     as that UID; the check runs in the child that will exec the browser, after the credential
     drop, lists `/dev` itself and fails closed when it cannot decide). If it is required and unavailable (`bwrap` not installed, or no unprivileged user
     namespaces), the launcher refuses to start the browser with an actionable error.
   - **Distinct-UID where the browser user cannot open any hidraw node:** the private `/dev` is not
     required. `doctor` reports which case applies: required and in place, in place as defence in
     depth, not required, or refused.
   - A hidraw node that appears after launch is not seen by the launch-time check; under `bwrap`
     it never appears in the private `/dev`.
4. **Human path guard (R19).** If `PASSLESS_INTERACTION_MODE=automatic` is set and any same-user
   profile has an `allow` or `request` rule, the daemon refuses to start agents unless
   `agents.allow_automatic_human_path = true`, and `doctor` flags it.

E2E: E2E-45 to E2E-47.

### D5 E2E harness

- **Location:** `tests/agent-e2e/` (Node 20+, `node --test`, `playwright-core` pinned).
- **Runner:** `make test-agent-e2e`, a wrapper script that creates a hermetic environment:
  - temporary `HOME` and `XDG_*`;
  - `dbus-run-session`;
  - `xvfb-run` for the headed variants.
- **Daemon under test:** the debug build, with local backend storage in the temp dir and
  generated agent config per scenario.
- **Notification double:** a scripted `org.freedesktop.Notifications` server (`notify-double`,
  a small Rust test binary using zbus). It records every `Notify`/`CloseNotification` and fires
  `ActionInvoked`/`NotificationClosed` according to a per-scenario script (approve, deny,
  ignore, delay N). One scenario uses real `dunst` plus `dunstctl action` to prove real-server
  compatibility.
- **Test RP:** a Node server using `@simplewebauthn/server`, with pages using
  `@simplewebauthn/browser` plus a raw `navigator.credentials` page.
  - Origins: `http://localhost:<port>`, plus `https://rp-a.test`, `https://rp-b.test` and
    `https://evil.test` via `--host-resolver-rules`. Multi-origin scenarios use these TLS `.test`
    origins, not `*.localhost`: R15 allows only the exact `localhost` RP and origin.
  - TLS: a self-signed certificate trusted through `--ignore-certificate-errors-spki-list`
    (verified in P0a Q4, headed and new headless; no NSS db is needed).
  - The server verifies every assertion and attestation for real: signature, counter, flags,
    origin and RP ID hash.
- **Browsers:** Chromium (distro), Playwright Chromium, and Chrome for Testing (downloaded and
  cached by the harness). Negative controls: Google Chrome and `chrome-headless-shell`.
- **Tools:**
  - driven programmatically: Playwright `connectOverCDP`, and Playwright MCP and
    chrome-devtools-mcp (both through a minimal MCP stdio client in the harness);
  - local-only and optional (skipped with a reported reason when missing, never silently):
    browser-use, agent-browser.
- **CI:** a new `agent-e2e` job on ubuntu with Chromium, Xvfb and dbus, covering the core
  scenarios on Playwright Chromium. The full matrix runs locally with `make test-agent-e2e-full`.
  The daemon still creates the human UHID device at startup (`main.rs:531`), so the CI job runs
  `modprobe uhid` and installs a udev rule first (V-H6).

## Phases

Each phase leaves the branch green: fmt, clippy `-D warnings`, `cargo test --all-features`,
`make test-agent-validation`, plus every E2E scenario listed for it. Model routing follows the
global orchestration rules.

| Phase | Scope | ADR | Model | Review | Size |
|---|---|---|---|---|---|
| P0a | Spikes (gate for D1 and D4): webAuthenticationProxy with an unpacked extension (headed, new headless, incognito access, cancel event, worker restart); pre-enabling incognito in a fresh profile; `--ignore-certificate-errors-spki-list` with WebAuthn; Chrome for Testing extension loading; Edge and Brave probe | §4, §11 | sonnet | — | S |
| P0b | ADR amendments R1–R4, R7, R9, R10, R12–R19, V-M3 (non-joinable registration) and V-H2 (waiter caps), using P0a results; doc link check | — | sonnet | orchestrator | S |
| P1 | E2E harness foundation (D5): runner, notification double, test RP, browser discovery, MCP client; baseline scenarios against current code (failures recorded, not fixed) | §19 | sonnet | sonnet | L |
| P2 | Remove native fallback; cross-origin fails closed; `confirm` acts as `deny` until P7; missing extension is a launch error (D6.2) | §7, §11 | sonnet | sonnet | S |
| P3 | Remove the UHID agent route (B) and the minted enrollment grants (A); lease-bound registration bearers | §5, §9, §10.3 | sonnet | sonnet | L |
| P4 | Policy schema and resolution: `RuleAction`, legacy mapping and warnings, validation, digest, `resolve()` with `MatchedRule`, numeric generation, pinning before `allowCredentials` | §6, §10.1 | sonnet | opus | L |
| P5 | Sessions and replay: check order, replay key with coalescing (R1), principal digest, reload revocation, `NotSupportedError`, DOMException names, capacity caps (R11) | §9, §10.2, §10.3 | opus | opus | M |
| P6 | Interception and transport: D1 (proxy), D2 (connectNative relay, framing, keepalive, abort, reconnect) and D6.1 (always-attached readiness, degraded lease); removal of the HTTP endpoints | §4.4, §11 | opus | opus | L |
| P7 | Escalation (D3), granted-rules store, `passless agent-admin grants`, `agent sessions` rename, `prompt.rs` fixes, `notify_user` and `state_dir` | §8 | opus | opus | L |
| P8 | Audit: §12 fields, terminal records, escalation events, schema bump | §12 | sonnet | sonnet | M |
| P9 | Deployment axes: `PrincipalRelationship` in doctor and audit, shared-UID `isolated` warning, doctor test rework | §13 | sonnet | sonnet | S |
| P10 | Agent-browser integration (D4) and containment (D6.3, D6.4): `agent browser`, browser detection and rejection, incognito enablement, bwrap hidraw hiding, automatic-mode guard, MCP adapters, `--print-config`, `doctor --agents` | §4.2, §7 | sonnet | opus | L |
| P11 | Docs: `docs/agents/*`, `AGENT_REGISTRATION*`, `PERMISSIONS.md`, `FURTHER_ANALYSIS.md` status, the skill, the ADR §19 table set to Done | — | sonnet | haiku link check | M |
| P12 | Final gate: full E2E matrix, security review, traceability audit | all | opus | — | M |

### Phase checklists

**P0a.**

- One spike script per question, kept under `tests/agent-e2e/spikes/`.
- Each question gets a yes/no answer with evidence.
- **Questions** (all answered; details in the
  [proxy results](../../tests/agent-e2e/spikes/RESULTS-proxy.md) for Q1, Q1b, Q2, Q3 and Q6, and the
  [environment results](../../tests/agent-e2e/spikes/RESULTS-env.md) for Q4, Q5 and Q7 to Q9):
  - **Q1. Yes.** Proxy create/get/cancel work with an unpacked extension, headed and new headless, on
    Chromium 156 and Chrome for Testing 156.
  - **Q1b. Yes.** The origin is browser-supplied, a page-forged `remoteDesktopClientOverride` is
    overwritten, and `sameOriginWithAncestors` is present; the top origin is not available. Chrome
    does not validate `clientDataJSON`, so the daemon builds it.
  - **Q2. Yes.** `attach()` survives a worker stop, a request wakes the stopped worker (it does not
    go native), and a second `attach()` does not throw. After `chrome.runtime.reload()` the extension
    stays unloaded and requests reach no extension (native path).
  - **Q3. Yes.** Seeding `extensions.settings.<id>.incognito = true` into `Default/Preferences` works
    without UI and covers the primary OTR profile and `Target.createBrowserContext` contexts;
    unseeded, both go native.
  - **Q4. Yes.** `--ignore-certificate-errors-spki-list` allows WebAuthn on `https://rp-a.test`.
  - **Q5. Partly.** Chrome for Testing 157 loads the extension (headed and new headless). Branded
    Chrome ignores `--load-extension` and `chrome-headless-shell` loads no extensions. Edge and Brave
    were not installed and are unprobed.
  - **Q6. Answered.** While attached, `isConditionalMediationAvailable()` is false and a conditional
    `get()` is rejected; the extension must answer `onIsUvpaaRequest`. Whether RPs still offer a
    passkey sign-in when the answer is `false` (V-L2) was not tested.
  - **Q7. No.** No Chromium switch or feature flag disables the HID transport, and no such policy
    appears in the binary's policy list (policy files could not be installed without root, so none
    was tried).
  - **Q8. Yes.** `bwrap --dev-bind / / --dev /dev --die-with-parent` hides hidraw; Chromium runs
    headed and in new headless with its own sandbox intact.
  - **Q9. Yes, with a real UID drop.** EXTERNAL auth needs the peer UID to equal the bus owner, so a
    root process must drop to the user in a child before connecting. The user's `dbus-broker` policy
    for UID 0 and a run as real root were not checked.
- **Gate (passed).**
  - D1 uses the proxy: create, get, cancel and worker restart work on Chromium and Chrome for
    Testing, headed and new headless.
  - D4 relies on incognito enablement: it works without user interaction.

**P1.** Scenarios E2E-01 to E2E-08 run against the current code. Record the baseline pass/fail
in the progress log. The harness itself is reviewed for hermeticity: it must not touch the real
`$HOME`, the real bus or the real credential store.

**P2.** Unit tests:

- `confirm` returns 403;
- a cross-origin request is denied;
- the extension never calls the original `get`/`create` after the daemon fails.

E2E-09 and E2E-10.

Recorded decision (P2): a subframe that was not delegated WebAuthn (no `allow="publickey-credentials-*"`) is
rejected by the extension with `NotAllowedError` before any daemon call, so it leaves no audit record. This is
acceptable because Chromium itself refuses WebAuthn in undelegated frames. Delegated cross-origin frames reach the
daemon, which denies and audits them (`cross_origin_denied`, E2E-10).

**P3.**

- Delete `endpoint_manager.rs`, `ceremony.rs`, `ceremony_observer.rs`, `device.rs`, the UHID
  parts of `runtime.rs`, `authenticator.rs:202-240`, `interaction.rs`, the doctor UHID check and
  the udev/systemd agent device access.
- Delete `RegistrationGrantRegistry`, the `RequestRegistration` admin request, the CLI command
  and its runtime handler.
- Registration bearers are bound to the lease and revoked by `revoke_by_lease`.

Tests: registration after lease revocation is refused; registration under the wildcard is
denied. E2E-11.

- Fix B3 and B6 (see Defects found by the P1 baseline) with a regression test.

**P4.** Unit tests:

- the legacy mapping table;
- digest sensitivity to every field;
- resolution precedence (exact > granted > wildcard), including the orphaned-grant case;
- the `register = "request"` validation rules.

Migrate the fixtures in `config.rs` tests (1449-1758), `policy.rs` tests (1019-1063),
`agent_config_integration.rs` and `policy_integration.rs`. E2E-12 and E2E-13.

- Fix B4 (see Defects found by the P1 baseline) with a regression test.

**P5.** Unit tests:

- budget is not consumed when origin validation fails;
- a duplicate is coalesced, never signed twice;
- a failure consumes the key;
- a principal digest mismatch is denied;
- reload revokes bearers;
- reload re-reads the config from disk (and validates it) before compiling a new generation
  (P4 left `handle_reload_policy` recompiling the in-memory config, so a config file change does not
  reach the runtime yet);
- re-resolve the rule and compare the revocation epoch immediately before key use (invariant 13;
  P4 resolves once per request, before the audit reservation and key use).

Replace the `sign.rs` replay tests (2091-2258). E2E-14 and E2E-15.

- Fix B5 (see Defects found by the P1 baseline) with a regression test.

**P6.**

- JS unit tests for the worker and relay: framing, multiplexing, abort and reconnect.
- Rust tests for the relay and the connection handler.
- Rewrite `agent_extension_behavioral.js`.
- E2E-16 to E2E-22.
- Fix B2 (see Defects found by the P1 baseline) with a regression test.
- Un-XFAIL E2E-02 (closes B3 against a real RP).

P6 notes:

- Removed `passless agent-admin install-native-messaging` and the cleanup that deleted
  `rs.passless.sign_proxy.json` from the user's own browser configuration
  (`~/.config/{chromium,google-chrome,google-chrome-beta}/NativeMessagingHosts`). The launcher writes
  the native host manifest only into the lease's profile; the command wrote one into the personal
  browser configuration, admitting the extension ID that the committed manifest `key` makes
  reproducible.
- A browser that runs as another user gets its own sign socket, `<sign dir>/<uid>/sock`, which
  needs a root daemon; a non-root daemon refuses such a launch up front and `doctor` reports it.
  The `hello` checks the peer's `SO_PEERCRED` UID against the lease's browser UID. A real
  cross-UID run needs root and is left to P12 (manual).

**P7.** Unit tests:

- join and coalesce;
- cooldown;
- queue overflow;
- grant cap;
- store round trip, corruption, wrong owner and wrong mode;
- a late approval after withdrawal is ignored;
- the automatic interaction mode does not affect escalation;
- the human operation lock is not held during the wait (a test that runs a human CTAP operation
  concurrently).

E2E-23 to E2E-31.

- Remove the principal intent protocol (`CreateIntent`/`ShowIntent`/`WaitIntent`/`CancelIntent`,
  `intent.rs`) unless reused by escalation.

**P8.** Every reservation has a terminal record. The field-presence test is driven by a §12 field
list. The schema version is bumped. E2E-32.

**P9.** Doctor and audit report both axes. The shared-UID `isolated` warning is emitted. Rework
`test_same_uid_is_fatal`. E2E-33.

**P10.** E2E-34 to E2E-42 across the browser and tool matrix. Also:

- Verify the `bwrap` private `/dev` with Playwright Chromium and Chrome for Testing, headed and
  new headless (P0a Q8 covered distro Chromium 156 only), before they are supported under
  containment.
- Add the manifest `key`; implement the incognito seed and its `isAllowedIncognitoAccess`
  verification (D4); confirm `chrome-headless-shell` detection (D4).
- Re-check preference MAC behaviour for each supported browser version (D4).
- In port mode, withholding the CDP endpoint of a degraded lease is advisory until the containment
  lands: the browser's `DevToolsActivePort` in the profile stays readable by a same-UID agent.
  Hide it from the agent, or document the residual risk.
- Fix B1 and B7 (see Defects found by the P1 baseline) with a regression test.
- `HardenedChildSetup::apply` (`launcher.rs`) sets `PR_SET_PDEATHSIG` before `setuid`, and a
  credential change clears the parent-death signal, so a root-launched browser loses it. Set it
  after the credential drop and re-check the parent, as `apply_prompt_child` already does. Related
  to B1; found in P7.
- Profile-scoped shared browser: a second principal's bearer must not depend on the first
  principal's grant; on first-principal exit, rebind or close (P5 review L5).

**P11.**

- `make check-doc-links` passes.
- No document mentions `confirm`, `supervised`, `delegated-session` or `registration_allowed`,
  except migration notes.
- The `docs/agents` quick start is followed verbatim by a subagent in the hermetic environment,
  and works.
- Move agent-validation assets out of `tools/agent-uhid-feasibility`, then delete it and the
  agent-only parts of `passless-uhid` if the human path does not need them.

**P12.** See [Final gate](#final-gate).

## E2E scenario catalogue

These run in the hermetic harness. **C** marks a scenario that runs in CI. Any other scenario is
local-full only.

| ID | Scenario | Asserts |
|---|---|---|
| E2E-01 C | Same-user `allow`: authenticate at `rp-a` (SimpleWebAuthn) | RP verifies signature, UP=1, UV=1, counter increments; audit `agent` evidence |
| E2E-02 C | Isolated `allow`: register then authenticate | Credential lands in the profile store, not the human store |
| E2E-03 C | `deny` rule | `NotAllowedError`; no prompt; no key use; audit deny |
| E2E-04 C | Unlisted RP, no wildcard | `NotAllowedError`, no prompt |
| E2E-05 | Raw `navigator.credentials` page with `allowCredentials` | Correct credential selected |
| E2E-06 C | `http://localhost` RP | Works (today fails: https-only manifest) |
| E2E-07 | Multi-account RP with `single` / `newest` / `credential:<ref>` | Deterministic selection; `single` errors on ambiguity |
| E2E-08 | Popup and same-origin iframe | Works |
| E2E-09 C | `request` rule (legacy `confirm` maps to it) without a notification server | Denied; native `get` is never invoked (CDP `WebAuthn` virtual authenticator attached as a canary must stay unused) |
| E2E-10 C | Cross-origin iframe to `rp-b` inside `rp-a` | Denied |
| E2E-11 C | Registration after browser exit using the old bearer | Refused |
| E2E-12 C | Wildcard `request` plus exact `allow` | Exact wins; wildcard path audited `rule="*"` |
| E2E-13 | Legacy config | Warns and maps; `allow + human` fails startup |
| E2E-14 C | Replay: page resubmits identical options (Kanidm pattern) | One signature; duplicate receives the same result |
| E2E-15 C | Budget: `evil.test` floods denied requests | Budget intact for `rp-a` |
| E2E-16 C | Page receives a credential passing `instanceof PublicKeyCredential` and `toJSON()` | A native `PublicKeyCredential` only; no MAIN-world shim is present |
| E2E-17 C | Abort via `AbortSignal` mid-request | Daemon receives abort; no signature; audit aborted |
| E2E-18 | Service worker stopped (CDP `ServiceWorker.stopWorker`) between requests | Next request reconnects and succeeds |
| E2E-19 | Worker killed during a pending request | Page gets `NotAllowedError`; daemon cancels; no orphaned escalation |
| E2E-20 | Long wait: escalation approved after 6 min (local-full only: it takes 6 min per variant, so it is not in the CI subset) | Ceremony completes (proves past the 5-min MV3 limit) |
| E2E-21 | Page `timeout` 3 min with no approval | Fails at about 3 min; notification withdrawn |
| E2E-22 | 20 concurrent ceremonies across tabs | No silent drops; caps return explicit `busy` |
| E2E-23 C | `request` approved | Ceremony continues; grant persisted; next ceremony needs no prompt |
| E2E-24 C | `request` denied | `NotAllowedError`; cooldown blocks a re-prompt for 10 min (clock-injected) |
| E2E-25 C | Two tabs request the same RP concurrently | One notification; both complete after one approval |
| E2E-26 | Different RPs concurrently | One prompt at a time; the others queue; overflow denied (E2E proves the sequential, in-order prompting with four RPs; the queue bound needs several bearer sessions of one profile and is covered by the coordinator unit tests) |
| E2E-27 C | `register = "request"` approved | One registration; `authenticate = allow` persisted with `kind=registration`; second registration prompts again |
| E2E-28 C | Notification shows only daemon fields | Notify body and actions inspected via the double; page-controlled strings absent |
| E2E-29 C | Spoofed `ActionInvoked` from a non-server bus name | Ignored |
| E2E-30 | No notification server on the bus | Immediate deny, audited |
| E2E-31 C | `grants list`, `revoke`, `clear` | Revocation invalidates sessions; ceremony prompts again; malformed store fails closed |
| E2E-32 C | Audit content for allow, deny, escalation and abort | All §12 fields present; terminal record for every reservation |
| E2E-33 | Distinct-UID principal (if a second local user is available, else unit-level) | Axes reported; shared-UID isolated warning |
| E2E-34 C | Playwright MCP via `passless agent mcp playwright`: navigate, log in with passkey | Success |
| E2E-35 C | Playwright MCP with `--isolated` | Works (extension enabled in incognito by preference seeding) |
| E2E-36 | chrome-devtools-mcp via adapter, including `isolatedContext` | Works, as above |
| E2E-37 C | Playwright library `connectOverCDP(PASSLESS_CDP_URL)` | Success |
| E2E-38 | browser-use with `cdp_url` | Success (local, optional) |
| E2E-39 | agent-browser `--cdp` | Success (local, optional) |
| E2E-40 | Headed (Xvfb) and `--headless=new` × Chromium, PW Chromium, Chrome for Testing | Core flows E2E-01, 23, 34 pass on every combination |
| E2E-41 C | `agents.browser_path` set to Google Chrome or headless-shell | Launch refused with an actionable error |
| E2E-42 | Real `dunst` with `dunstctl action` approval | Approval works with a real notification server (local, optional: SKIP-OPT when `dunst` is not installed) |
| E2E-43 | Human authenticator concurrently in use (same-user) during a pending escalation | Human CTAP operation is not blocked |
| E2E-44 | `PASSLESS_INTERACTION_MODE=automatic` with a `request` rule | Escalation still prompts or denies; never auto-approved. Agents refuse to start without `allow_automatic_human_path` (R19). |
| E2E-45 C | Request while the extension worker is stopped or before attach; conditional-mediation request; request from a CDP-created context | Never reaches the human device: the human authenticator records no CTAP request, and the page gets `NotAllowedError` or no-op |
| E2E-46 C | Managed browser process | Cannot open any `/dev/hidraw*` (probe inside the browser sandbox namespace), or `doctor` warns on hosts without userns |
| E2E-47 C | Extension directory missing or unloadable | Launch fails with an actionable error; no browser without interception |
| E2E-48 C | Escalation waiters beyond the per-session or per-profile cap; `allow` ceremonies of another profile run concurrently | Caps enforced; other profiles unaffected; no pool exhaustion |
| E2E-49 | Notification server restarts while a prompt is pending | Pending entry expires cleanly; next request prompts on the new server |
| E2E-50 C | Repeated abort at the last second | Rate limit then cooldown (V-M2) |
| E2E-51 | `create()` from an unfocused tab (an older tab in front of the new one) | The page gets `NotAllowedError`; the audit shows the registration; the documented cleanup (the operator deletes the orphan credential) removes it |
| E2E-52 C | Pipe mode: `browser-control` tries to reach the extension worker (target list, auto-attach, extension and `chrome:` URLs, `Extensions`, `exposeDevToolsProtocol`, stopping workers) | The worker is never listed or handed out, every attempt is refused and audited as denied, and a `get()` driven through `browser-control` is still intercepted (review M3). XFAIL until a principal can launch a pipe-mode browser (`EnsureBrowser` is port-only) |

**E2E-45, extension unloaded after attach: not testable end to end, by decision.** The original
catalogue line asked for a request after the extension is unloaded (for example by
`chrome.runtime.reload()`). No product path unloads the extension (the worker never calls
`chrome.runtime.reload()`, D1), the harness has no supported way to unload it from outside (the
harness's CDP access to the extension's targets is being closed off), and a debug-only hook in the
daemon that unloads it would be product code that no release build runs and no review gate
exercises. The case is covered at the layers that decide its outcome instead: a worker that goes
away drops its sign-transport connection, the lease's interception degrades, and the CDP endpoint
is withheld after the grace period (`test_interception_degrades_after_the_grace_period_and_is_reported_once`,
`bootstrap_refuses_a_degraded_lease_until_it_re_attaches`, ADR 0014 section 7); a launch without the
extension never happens (E2E-47, `E2E-47/unloadable`); and whatever the browser then does natively
cannot reach the human device (E2E-46, D6 layer 3). Traceability: item E-12 and invariant 25 in
the [traceability audit](agent-delegation-traceability.md).

## Traceability matrix

Every ADR 0014 decision maps to the phase that implements it and the tests that prove it. The
P12 audit fills in the Verified column.

| ADR | Decision | Phase | Tests | Verified |
|---|---|---|---|---|
| §4.2 | Managed browser; supported binaries; contexts | P10 | E2E-35, 36, 40, 41 | |
| §4.4 / §11 | Interception (D1), origin and `clientDataJSON` ownership, connectNative transport, keepalive, abort, focus limitation | P6 | E2E-16 to 22, 51 | |
| §5 | Identity modes; no UHID agent transport | P3 | E2E-01, 02; unit | |
| §6.1–6.2 | deny/allow/request; resolution precedence | P4 | E2E-03, 04, 12; unit | |
| §6.3 | Constrained wildcard | P4 | E2E-12; unit | |
| §6.4 | Validation and legacy migration; digest coverage | P4 | E2E-13; unit | |
| §7 | No human in ceremonies; no native fallback; agent evidence | P2, P5 | E2E-01, 09, 44 | |
| §8.1 | Escalation flow and Chromium timeout | P7 | E2E-20, 21, 23, 24 | |
| §8.2 | Verified sender, daemon-only text, headless deny, queueing | P7 | E2E-26, 28, 29, 30 | |
| §8.3 | Registration escalation (one-shot, persists authenticate) | P7 | E2E-27 | |
| §8.4 | Granted-rules store, CLI, permanence, additive generation, cap | P7 | E2E-31; unit | |
| §9 | Bearer session, check order, replay key, revocation | P3, P5 | E2E-11, 14, 15; unit | |
| §10.1 | Selection; pin before `allowCredentials`; wildcard `single` | P4 | E2E-07 | |
| §10.2–10.3 | Operation service; registration authority; `NotSupportedError` | P3, P5 | E2E-02, 27; unit | |
| §12 | Audit fields and events | P8 | E2E-32 | |
| §13 | Two axes; hardening scope | P9 | E2E-33; unit | |
| §7 (inv. 25, R17) | Managed browser never reaches the human authenticator; automatic-mode guard | P2, P6, P10 | E2E-44 to 47 | |
| §6.1 (R15) | `localhost` RP for exact rules | P4 | E2E-06 | |
| §8.2 (V-H2, V-M2) | Waiter caps; abort rate limit | P7 | E2E-48, 50 | |
| §14 | Invariants 1–25 | P12 | Security review maps each invariant to evidence | |

## How each phase is executed

1. **Brief.** One implementation subagent receives:
   - the phase row and checklist;
   - the relevant ADR sections and code file:line references;
   - the constraints (import formatting rules in CLAUDE.md, Conventional Commits, no `sudo`, no
     real `$HOME`, bus or store);
   - the acceptance criteria;
   - the expected report: diff summary, test evidence, unknowns.
2. **Implement.** The subagent implements the phase and its tests, then runs fmt, clippy,
   targeted tests and the phase's E2E scenarios.
3. **Verify.** The orchestrator, through a verification subagent, runs:
   - `cargo fmt --check`;
   - `cargo clippy --all-targets --all-features -- -D warnings`;
   - `cargo test --all-features`;
   - `make test-agent-validation`;
   - the phase's E2E scenarios.

   It checks exit codes and reads the diff stat plus the security-relevant hunks.
4. **Review.** The reviewer named in the phase table receives the diff and the ADR, not the
   implementer's conclusions. It reports findings ranked by severity. Critical and high findings
   go back to an implementation subagent.
5. **Commit (M1).** A Conventional Commit on the branch, then update the progress log.

## Design validation

Before P1, an Opus reviewer validates D1–D5 and R1–R14 against the code and ADR 0014. It looks
for deadlocks, lock-order violations, starvation, races, trust-boundary bypasses, invariant
violations and untestable claims. Its findings are folded into this plan. Rejected findings are
recorded here with reasons.

### Validation results (Opus review, 2026-11-10)

Findings are prefixed `V-`. All are accepted unless marked otherwise.

| ID | Finding | Resolution |
|---|---|---|
| V-C1 | The managed browser reaches the human UHID device whenever interception is missing (idle worker, page loaded before attach, OTR context, missing extension); automatic mode then signs silently | D6, R17, R19; P0a Q7–Q8; E2E-45 to 47 |
| V-H1 | Origin source on the proxy path unproven; a page might forge `remoteDesktopClientOverride`; no top origin or frame | P0a gate Q1b: forged override must be ignored, origin must come from the browser. Define `cross_origin` from `sameOriginWithAncestors`; top origin is unavailable on the proxy path, so the audit records `top_origin = null` with `cross_origin`. **Resolved (P0a Q1b):** the browser overwrites a forged value, so D1 uses the proxy. |
| V-H2 | Escalation waiters exhaust pool threads; budget drained in cooldown | Waiters are parked continuations in `EscalationService`, holding no thread. The decision dispatches completion to the pool. Waiters are capped per session (4) and per profile (16). R4 revised. Applied to ADR §8.2 and §9 in P0b. |
| V-H3 | Re-resolution after approval impossible with a frozen `ctx.profile_config` and digest-based generation | R16 |
| V-H4 | Agent can self-approve on the user's bus; root on user bus | R18; ADR residual-risk amendment |
| V-H5 | Prompt thread can wedge forever on `join()` | P7: cancellable inner thread through a channel; `CloseNotification` before join; `NameOwnerChanged` watch expires pending entries and re-resolves the server name |
| V-H6 | The daemon needs UHID to start (`main.rs:531`); `localhost` RP rejected | The harness and CI set up `/dev/uhid` (CI step: `modprobe uhid` plus a udev rule on the runner, which is root there). Local runs accept that a transient human device exists, and its storage is the temp dir. R15 for localhost. |
| V-H7 | Auto-detection runs a principal-writable binary under the root daemon; easy path is port-mode only | R14 amended; `agent browser` fails with a clear message in pipe mode, and documents it |
| V-M1 | Lock order incomplete and contradictory | P5 inventories every lock into a documented order in `agent/LOCKING.md`. The escalation mutex is a leaf. No policy guard is held across another acquisition. The check order follows §9: audit reservation, then epoch re-check, then key use. |
| V-M2 | Abort dodges cooldown; an ignored prompt blocks the slot | Withdrawn escalations are rate-limited (3 per key per 10 min, then cooldown). A queued entry is dequeued when its last waiter leaves. An active prompt with zero waiters is withdrawn immediately. |
| V-M3 | Registration token goes to the wrong waiter | Registration escalations are not joinable. The token is bound to the creating ceremony. Concurrent duplicates are denied. **Supersedes R5.** Applied to ADR §8.3 in P0b. |
| V-M4 | A restarted worker leaves proxied requests hanging | Pending ids are kept in `chrome.storage.session` and failed with `NotAllowedError` on worker restart |
| V-M5 | D2 lacks back-pressure and re-authentication | Write timeout (5 s) closes the connection. The bearer is re-validated on every request against the revocation epoch. Wire ids are worker-allocated. Frames are capped at 1 MiB before allocation. |
| V-M6 | Phases not green as written | The harness supports phase-tagged expected failures (`xfail-until: Pn`). `request` denies with audit until P7. P2 text fixed to "until P7". P3 updates `test-device-matrix.sh`. E2E-09's canary is replaced by a hidraw-access probe (D6) and native-call instrumentation. E2E-12 asserts `rule="*"` only from P8. |
| V-L1 | R1 join uses a 30 s wait; a duplicate's abort cancels the original | The join waits until the ceremony deadline; a duplicate abort only detaches that duplicate |
| V-L2 | isUVPAA `true` causes upsell noise | Answer `false`, matching the native headless Linux value. P0a confirms RPs still offer a passkey sign-in. |
| V-L3 | Grant keys, punycode, scope wording | Grant keys use `validate_rp_id` output. The notification shows the punycode RP ID and "any page under this site". |
| V-L4 | R13 must test `Target.createBrowserContext` contexts | Added to P0a Q3 |
| V-L5 | Sign-proxy and daemon version skew | `doctor` compares versions; `hello` carries the build version |
| V-L6 | Test mechanics: stopWorker, cooldown clock, hidraw | E2E-18 uses `Target.closeTarget` on the worker target. Cooldown is configurable, `agents.escalation_cooldown`, with a minimum of 1 s in debug builds only. hidraw is hidden through D6. |

**Not verified by the reviewer.** These were carried into P0a and are answered there (the proxy
origin source, attach persistence, conditional mediation, SPKI-list TLS and root access to a user
session bus); the zbus `MessageStream` lifetime was not covered by P0a and stays open for P7:

- the proxy origin source;
- whether `attach()` persists while the worker is stopped;
- `isConditionalMediationAvailable` under the proxy;
- `--ignore-certificate-errors-spki-list` with WebAuthn;
- root access to a user session bus;
- zbus `MessageStream` lifetime.

## Final gate

- Every row of the traceability matrix is Verified with links to test names. The audit artifact is
  [agent-delegation-traceability.md](agent-delegation-traceability.md).
- Full local E2E matrix (`make test-agent-e2e-full`): all scenarios pass. The only allowed skips
  are optional tools that are not installed, and each one must be reported.
- CI-equivalent run: fmt, clippy, `cargo test --all-features` on x86_64, `make
  test-agent-validation`, `make test-agent-e2e`, fuzz smoke, `make check-doc-links`, pre-commit.
- An independent Opus security review of the whole branch diff, with each §14 invariant mapped to
  code and test evidence. No open critical or high findings.
- Human-path regression: `make test-e2e`, with agents compiled and disabled, plus a manual check
  that the restored `passless.service` works. The maintainer restarts it.
- The ADR §19 table is updated to all Done, and its status line reflects that. Two rows are
  accepted residuals, not open work, and stay marked as such: *Unfocused-tab registration* (a
  documented limitation, ADR §11) and the *evaluated* directives of *Distinct-UID systemd baseline*
  (an open hardening backlog, ADR §13). "All Done" means every other row; these two are the
  documented limitations the final status line names.

## Progress log

| Phase | State | Commit | Notes |
|---|---|---|---|
| ADR consolidation | ✅ staged | — | ADR 0014 written; 11 ADRs and 14 plans removed |
| Design validation | ✅ | — | Opus review: 1 critical, 7 high, 6 medium, 6 low. All accepted (see Validation results) |
| P0a | ✅ | — | proxy gate passed; incognito via Preferences seeding; no HID-disable switch → bwrap mandatory; TLS via spki list OK; CfT 157 loads extensions |
| P0b | ✅ | — | ADR 0014 amended (R1–R4, R7, R9, R10, R12–R19, V-M3, V-H2, P0a outcomes; invariant 25; §19 rows); plan R, D1, D4, D6, P0a, E2E updated |
| P1 | ✅ | — | Baseline: 24 PASS, 8 XFAIL (E2E-02, 06 until P6) on Chromium and PW Chromium headed/headless; CfT 12 PASS/4 XFAIL; defects B1–B7 recorded |
| P2 | ✅ | — | Native fallback removed; cross-origin and `confirm` deny with audit; launch refuses invalid extension; interim MAIN-world hardening (prototype, single read, about:blank/srcdoc/blob frames). E2E-09, 10, 47 pass; E2E-02, 06 XFAIL until P6 |
| P3 | ✅ | — | UHID route and minted grants removed; registration bearers lease-bound; B3 (COSE_Key) and B6 fixed. E2E-11 pass; E2E-02 XFAIL until P6 (extension `/register` response shape only) |
| P4 | ✅ | — | `RuleAction`/`PolicyAction`, legacy mapping with warnings (doctor shows them; unmappable legacy values are reported by `validate`, so a disabled `[agents]` section never breaks the human config load), validation (wildcard, `register = request`, `localhost` exact only, at most 32 RP rules without a `*` rule), `resolve_rules`/`MatchedRule`/`GrantSource` hook, ceremonies resolve per request through `PolicyRuntime::resolve` against the compiled in-memory generation (not a copy in the session context), numeric generation (serialized reloads), digest v4, pinning before `allowCredentials`, B4 fixed, launch-URL check by most specific rule. E2E-12, 13 added; E2E-03 uses an all-deny profile. Not yet real: config changes do not reach the runtime (reload re-recompiles the in-memory config; P5 re-reads the file) and there is no re-resolve before key use (P5/invariant 13). Also frozen: `max_operations` in the sign/register contexts (P5); audit `rule` identity (E2E-12/audit-rule XFAIL until P8) |
| P5 | ✅ | — | Bearer sessions with length-prefixed replay key (join, 120 s outcome cache, never sign twice); budget only for key use; revocation/grant epochs with key-use gates; reload re-reads config; per-global/profile/session caps with explicit busy; LOCKING.md with debug lock-order checks; two deadlocks fixed; B5 fixed. E2E-14, 15 pass |
| P6 | ✅ | — | Proxy-only worker, framed relay and daemon transport, attach-gated launch (B2 fixed). E2E-02 (B3 closed against SimpleWebAuthn) and E2E-06 un-XFAILed; E2E-16 to 22, 45, 51 added: full matrix (3 browsers x headed/headless) 28 PASS, 4 XFAIL per variant (E2E-20/escalation, 21 until P7; E2E-45/cdp-context until P10; E2E-12/audit-rule until P8). Fixed along the way: admin-launched leases were never activated (browser killed at the 300 s login deadline) and `agent-admin credential delete` could not delete an isolated-store credential (orphan cleanup, E2E-51). Worker death mid-request leaves the page pending until the next worker start fails it |
| P7 | ✅ | — | Escalation: persistent granted-rules store and `agent-admin grants` CLI (69b5700); escalation coordinator and privilege-dropping notification prompt child (262fb04); escalation wired into sign and register ceremonies (dd7da60); ADR section 19 rows, transport deadline test (63153b8); E2E harness teardown fix, escalation scenarios and docs (2eff086, ccf6c0c, 944fa23). E2E-20/escalation and 21 un-XFAILed; E2E-23 to 31, 43, 44, 48 to 50 added; E2E-09, 12, 13 reworked. Full matrix (3 browsers x headed/headless): 44 PASS, 3 XFAIL per variant, exit 0 (remaining XFAILs: E2E-12/audit-rule until P8, E2E-44/startup-refusal and E2E-45/cdp-context until P10). Gap: the queue bound is covered by unit tests only (E2E-26 proves in-order sequential prompting; several bearer sessions of one profile need B1 fixed). Observed: a grant revocation leaves the managed browser running with a revoked bearer. Fix round (77129fc, 6e151fc, 6b47575, 32ed724) verified at 32ed724: fmt, clippy, cargo test, agent validation green; full matrix 44 PASS, 3 XFAIL per variant, 0 FAIL (harness exit 2 only from a hermeticity trip caused by an external write to ~/.cache/ms-playwright; targeted rerun clean) |
| P8 | ⏳ | — | Code and unit tests done; E2E pending orchestrator run. Audit schema version 3: every operation record (`policy.allow` reservation, `policy.deny`, `policy.replay_served`, new `operation.terminal`) carries the §12 field set (`OperationRecord`), keys always present; one `CeremonyAudit` per ceremony (`operation_audit.rs`) writes them, and its single exit point (plus a drop guard for panics) closes every reservation with exactly one terminal record, so a failure after the reservation is the terminal record's `failure_class`, not a second `policy.deny`. Escalation records gain `origin` and `rule`, session grant records `principal`, RP scope and TTL; older records still parse. Field-presence tests run every record type against the canonical `SECTION_12_*` lists in `audit_events.rs`. E2E-12/audit-rule un-XFAILed; E2E-32 and E2E-32/abort added (they read the same lists from the Rust source). `rule` is `exact` or `*` (as in the grants store), with `grant_source` (`config` or `granted`). `backend` is the real storage kind (`local`, `pass`, `tpm`), the human backend's for a same-user profile |
| P9 | ⏳ | — | Code and unit tests done; E2E pending orchestrator run. `PrincipalRelationship` and `DeploymentAxes` (`deployment.rs`) are the one derivation of the relationship, used by the audit `principal_relationship` field (string values unchanged) and by doctor: a `deployment_axes` check (mode and relationship, plus what the §13 matrix cell means) per profile in `agent-admin profile check` and `agent doctor`, and per profile in the start-up diagnostics. The shared-UID `isolated` warning is a passing `isolated_shared_uid` check (`warning:` message) and a `log::warn!` at daemon start (`StartupDiagnosticResult.warnings`). `test_same_uid_is_fatal` asserted that a failing `principal_vs_daemon` uid check is fatal, which contradicts §13 (shared-UID is a supported deployment): reworked into `test_same_uid_is_reported_and_not_fatal` (both modes), `test_distinct_uid_reports_the_axes_without_a_warning` and `test_principal_root_is_still_fatal`; the `principal_vs_daemon` uid check and its dead duplicate in `runtime.rs` are removed. Unit tests cover all four mode x relationship cells. E2E-33 covers the shared-UID column (same-user and isolated: doctor, audit field, start-up warning); the distinct-UID column is unit-level because a second local user needs root |
| P10 | ⏳ P10a and P10b code done; E2E pending orchestrator run | — | P10a (containment core) code, unit tests and E2E scenarios done; E2E pending orchestrator run. Done: the managed browser always runs under `bwrap --dev-bind / / --dev /dev --die-with-parent` when bwrap works for the browser's user (`containment.rs`); otherwise the dropped child's `faccessat(AT_EACCESS, R_OK\|W_OK)` hidraw check refuses the launch with an actionable error; `containment::assess` reports the case for doctor (P10b wires `doctor --agents`). `HardenedChildSetup::apply` arms `PR_SET_PDEATHSIG` after the credential drop and re-checks the parent, and marks inherited descriptors close-on-exec so pre-exec failures reach `spawn`. B1 fixed: browsers are forked on a long-lived launcher thread (`spawn_on_launcher_thread`), every scope sets the parent-death signal; lock order unchanged (LOCKING.md bounded waits). Incognito seed in `Default/Preferences` for the manifest-key ID; launch fails and the endpoint is withheld unless the worker reports `isAllowedIncognitoAccess()` true. Port mode removes `DevToolsActivePort` after discovery (residual documented in ADR §7). Security review fixes (H1, M1, M2, L1, L2, L4 to L6): daemon writes into lease and sign-socket directories go through pinned directory handles (`safe_fs.rs`), with the lease and extension directories kept the daemon's and only the profile handed to the browser user; the hidraw check uses `faccessat2` on a `getdents64` listing in the child and fails closed; distinct-UID browser rlimits fit Chromium; no CDP endpoint in the browser-control error; same-user hardened children inherit no descriptor; `bwrap` must live on a path no other user can write. R19: agents refuse to start, and reloads are rejected, under `PASSLESS_INTERACTION_MODE=automatic` with a same-user `allow`/`request` rule unless `agents.allow_automatic_human_path = true`. E2E-44/startup-refusal and E2E-45/cdp-context un-XFAILed; E2E-46, 46/refused, 46/session-scope (B1) and 47/unloadable added. Probe: Chromium 156, PW Chromium (CfT 155) and CfT 157, headed and `--headless=new`, run under the private `/dev` with Chromium's sandbox on, the proxy attached, the seed honoured and a CDP-created context intercepted. **P10b** (agent-browser easy path), code and unit tests done, E2E pending orchestrator run. Step 0 review leftovers: EPERM from `faccessat2` is unverifiable and refuses the launch; the extension manifest and worker are read through the pinned directory (regular file, owner, size bound: a planted `/dev/zero` symlink or FIFO is refused); the sign directory and the `/tmp/passless-agent-<uid>` fallback are created without following symlinks and a pre-existing directory the daemon does not own is refused (`Dir::open_or_create_path`); safe_fs tests for an intermediate-component symlink and the `create_dir` owner check. P10b: `passless agent browser` (inside a principal session), `agent mcp playwright|chrome-devtools` with `--package`/`--npx`, `agent mcp --print-config {claude-code|opencode|cursor|vscode}`, hidden `agent playwright-mcp` alias, `agents.browser_path` and `browser_select.rs` (detection order, R14 rejection of branded Chrome and `chrome-headless-shell`, V-H7), `passless doctor --agents` (`doctor_agents.rs`), B7 fixed (isolated profiles accept `browser_runtime_root`), L5 (a shared browser closes when its owner session exits; no lock-order change), the harness (`tests/agent-e2e/bin/npx` shim, `lib/adapters.js`, pinned `chrome-devtools-mcp` 1.12.0, `SKIP-OPT`). Findings: `chrome-headless-shell --version` prints `Google Chrome for Testing <version>` like the full binary, so it is recognised by name; the Chrome for Testing string must not match the branded check; puppeteer cannot send the bootstrap's bearer header, so `agent mcp chrome-devtools` ensures the browser at start (not lazily). E2E-34 and E2E-35 pass (Playwright Chromium 156.0.8078.4, headless); E2E-36, 37, 38 to 42, the E2E-40 matrix and the preference-MAC re-check per browser version are pending the orchestrator's full-matrix run |
| P11 | ⏳ Code and docs done; the subagent quick-start run (hermetic environment) is pending the orchestrator | — | Docs rewritten around the easy path from the current CLI help: `docs/agents/quick-start.md` (config with an exact `allow` rule, restart, `agent mcp --print-config claude-code`), `browser-tools.md` (Playwright MCP with `--isolated`, chrome-devtools-mcp, `connectOverCDP` with `agent run` and `agent browser --env`, browser-use, agent-browser, Stagehand, each marked tested or documented), `rules.md` (deny/allow/request, escalation, `agent-admin grants`, `register = "allow"`, the `*` rule), `containment.md` (supported browsers, bwrap, `doctor --agents`, CDP port mode, same-UID residual), `migration.md` (the only page that names the legacy vocabulary), and updated `configuration`, `same-user`, `isolated`, `security`, `operations`, `audit`, `troubleshooting`, `README`; `playwright-mcp.md` is folded into `browser-tools.md`. `AGENT_REGISTRATION*.md`, the agent section of `PERMISSIONS.md` and `FURTHER_ANALYSIS.md` (a status per item and per plan row) match the code; the stale `tests/e2e/test_agent_registration.sh` (HTTP `/register`) is deleted. The bundled `passless-agent` skill is rewritten around `agent mcp playwright`, the passkey-button flow and the pending/denied behaviour. ADR 0014 section 19 has every row Done except the unfocused-tab adapter behaviour and the evaluated systemd, namespace and seccomp directives (reasons in the table); the status line says P12 is pending. Cleanup: the controlled RP, lab udev policy and permission probes moved to `tools/agent-validation`; `tools/agent-uhid-feasibility` and the `passless-uhid` crate (used only by it) are deleted; `make test-agent-validation` passes. Stale code comments and two error strings that named the removed delegated mode were updated. Remaining legacy hits are the config parser and its tests, the `--confirm` flag, the `registration_allowed` capabilities field and the unused `InteractionRequired` error code |
| P12 | ⏳ | — | |
