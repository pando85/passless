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
| M4 | Version bump or release? | None. Legacy config is accepted with a warning for one minor release. |

### Orchestrator resolutions

These resolve the open implementation questions. The maintainer may override any of them.
Rows marked **ADR amend** change ADR text in phase P0b.

| # | Topic | Resolution | ADR |
|---|---|---|---|
| R1 | Kanidm resubmits an identical request (`sign.rs:300-308`) | An identical replay key never causes a second signature. While the first request is in flight, the duplicate joins it. After completion, the duplicate receives the original result for 120 s, in the same session only. Any other repeat is rejected. | **amend §9** |
| R2 | Notification bus for the root (distinct-UID) daemon | `agents.notify_user` names the human whose session bus receives escalation prompts. The user unit uses its own bus. If no bus can be resolved, escalation is unavailable: deny and audit. | **amend §8.2** |
| R3 | Granted-rules location | `agents.state_dir`. The user unit defaults to `$XDG_STATE_HOME/passless/agent`. The system unit defaults to `/var/lib/passless-agent` (systemd `StateDirectory=`). | **amend §8.4** |
| R4 | Claim timing (revised by V-H2) | Order: origin/RP check → resolve → (if `request`) cooldown, grant cap, bus and queue checks → replay key → wait → budget claimed after approval. For `allow`: replay key, then budget, before audit. Rejected requests never consume budget. | **amend §9** |
| R5 | Several ceremonies waiting on one `register` escalation | The first waiter to resume receives the one-use registration token. The others fail with `NotAllowedError`. | **amend §8.3** |
| R6 | Legacy isolated `device` key and agent udev rule | Warn and ignore for one release. Remove the agent UHID udev and systemd device access. | — |
| R7 | CLI naming collision | Granted rules use `passless agent grants`. The existing session-grant commands move to `passless agent sessions`, with a hidden alias for one release. | **amend §8.4** |
| R8 | Deprecation channel | A startup warning plus a `passless doctor` warning. Legacy parsing is removed in the release after next. | — |
| R9 | Aborted escalation audit | `escalation_expired` with `reason = timeout or aborted`. `escalation_revoked` is only for operator revocation. | **amend §12** |
| R10 | Pinned `credential_refs` and a registration grant | The credential ref of a registration-kind grant joins the pinned set for that RP. | **amend §8.3** |
| R11 | Sign-server capacity | No silent drops. Use per-connection and global caps on concurrent requests. Overflow returns an explicit `busy` error. | — |
| R12 | Interception mechanism | `chrome.webAuthenticationProxy` is the primary path, if the P0a spike passes. Otherwise keep the MAIN-world override and widen the matches to `http://localhost/*`. See D1. | **amend §4.4, §11** |
| R13 | Extension in CDP-created (incognito-like) contexts | Enable the managed extension in incognito. If P0a proves that cannot be done reliably, adapters must forbid isolated contexts. See D4. | **amend §4.2** |
| R14 | Supported browsers | Chromium, and Chrome for Testing. Branded Google Chrome and `chrome-headless-shell` are rejected at launch with a clear error. Edge and Brave are best effort, decided after the P0a probe. Detection must not match "Google Chrome for Testing". In distinct-UID deployments, only root-owned, principal-unwritable binaries are accepted. | **amend §4.2** |
| R15 | `localhost` RP | `rp_id = "localhost"` and `http://localhost[:port]` origins are valid for exact rules only, never through the wildcard. `validate_rp_id` and `parse_origin` are extended accordingly. | **amend §6.1** |
| R16 | Policy epochs (V-H3) | Split the revocation epoch (bumped by reload, grant revocation and config change; revokes sessions) from the grant epoch (bumped when a grant is added; does not revoke). Ceremonies resolve against the live config plus grants, never against the frozen `ctx.profile_config`. The pre-key-use check compares the revocation epoch and re-resolves the rule. | **amend §6.4, §8.4, §9** |
| R17 | Managed browser must never reach the human authenticator (V-C1) | See D6. Requests the extension does not handle fail closed instead of reaching the native path. | **amend §7, add invariant 25** |
| R18 | Self-approval by a same-UID agent (V-H4) | A shared-UID agent can drive the user's notification server (`dunstctl`, `makoctl`, a replaced server). This cannot be prevented and is documented as residual risk. `notify_user` must differ from every `principal_user`/`browser_user`. The root daemon talks to the user bus only through a helper that drops to `notify_user`. | **amend §8.2, §13, §15** |
| R19 | Automatic interaction mode with agents (V-C1) | If `PASSLESS_INTERACTION_MODE=automatic` is set and any same-user profile has `allow` or `request`, the daemon refuses to start agents unless `agents.allow_automatic_human_path = true`, and `doctor` flags it. | **amend §7** |

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
  - unverified with an unpacked extension and in new headless.
- Chromium WebAuthn timeout is clamp(page timeout, 3 min, 20 h), or 20 h when unset
  (`AdjustTimeout()`, `fido_constants.cc`, verified). Under MV3, `sendNativeMessage` and events
  are limited to 5 min and `fetch` to 30 s. A `connectNative` port keeps the worker alive.

## Designs

### D1 Interception

**Primary path (subject to the P0a gate):** `chrome.webAuthenticationProxy` in the service
worker.

- `attach()` on worker start and on every wake.
- `onCreateRequest` / `onGetRequest` forward `requestDetailsJson` plus the browser-supplied origin
  to the daemon. The reply goes through `completeCreateRequest` / `completeGetRequest` with
  `responseJson`, or a DOMException name.
- `onRequestCanceled` sends `abort` to the daemon.
- `onIsUvpaaRequest` answers `true` when the profile has any `allow` or `request` rule.
- No MAIN-world script, so the page receives a genuine `PublicKeyCredential`. The browser enforces
  the origin and RP-ID relationship and the iframe Permissions Policy before the extension sees
  the request.
- The daemon still validates the origin against the RP ID, and still rejects cross-origin frames.
- Conditional mediation is rejected by Chromium while attached. This is equivalent to today,
  where conditional requests are already left native and unhandled.

**Fallback (only if P0a fails):** keep the MAIN-world override, but:

- matches `https://*/*`, `http://localhost/*` and `http://127.0.0.1/*`;
- trusted origin taken from the broker's `sender` metadata;
- full `PublicKeyCredential`-compatible shape: `getClientExtensionResults`, `toJSON`,
  `getTransports`, `getPublicKey*`, `getAuthenticatorData`;
- static `PublicKeyCredential` methods patched consistently.

The ADR is amended to record whichever path ships.

### D2 Transport

- **One port per browser.** The service worker lazily opens one long-lived
  `chrome.runtime.connectNative("rs.passless.sign_proxy")` port.
- **Relay.** `sign-proxy` becomes a two-thread relay between the native-messaging frames (4-byte
  LE length + JSON) and one persistent Unix-socket connection that uses the same framing.
- **Frames:**
  - `hello{v:2, bearer}`
  - `request{id, op, timeout_ms, origin, top_origin?, cross_origin, body}`
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
- **Request cache:** the worker's request cache key is `(tabId, frameId, origin, requestId)`.

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
4. Claim budget and replay key.
5. Deny if in cooldown, at the grant cap, or with no notification bus.
6. Join or create the escalation. The creator writes `escalation_requested`.
7. Wait in a timed loop on the condvar, checking the cancel token and the deadline.

Approval is accepted only from the verified D-Bus sender, and only while the entry is still
Pending. On approval:

1. Write `escalation_approved`.
2. Persist the grant under the per-profile store mutex.
3. Call `bump_generation_additive()`, which does not revoke sessions.
4. Wake the waiters.
5. Each waiter re-resolves to `Granted`, then takes the operation lock, re-checks the generation,
   reserves audit and executes.

Registration approval issues a one-use token (R5). Its `authenticate` grant is persisted only
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

Branded Google Chrome and `chrome-headless-shell` are rejected with a clear error (R14). The
default is `--headless=new`; `--headed` is optional.

**Contexts.**

- The managed profile pre-enables the extension in incognito (R13), so `--isolated` and
  `newContext()` contexts are covered.
- If that is impossible, the MCP adapters strip `--isolated` and the docs warn against
  `newContext()`.

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

A WebAuthn request from the managed browser must never reach the human authenticator. There are
four layers.

1. **Interception always ready.**
   - The worker opens the native port on startup and keeps it open, with keepalive in both
     directions, not only while a request is pending.
   - On the proxy path, `attach()` runs before the worker reports `hello{attached:true}`.
   - `passless agent browser --wait` and the CDP bootstrap do not return an endpoint until that
     hello arrives.
   - If the port drops, or `attach()` fails or is lost, the daemon marks the lease degraded and
     the bootstrap stops handing out the endpoint until the worker re-attaches.
2. **Launch fails closed.**
   - A missing or unloadable extension directory is a launch error, never `--disable-extensions`
     (`browser.rs:2040-2044`).
   - Browsers that cannot load the extension are rejected (R14).
3. **No device access.** The managed browser gets no hidraw access to the human device.
   - **Unprivileged-userns hosts:** launch it under `bwrap`, with a private `/dev` that omits
     `hidraw*` and `uhid`.
   - **Distinct-UID:** the browser user is not in the `fido` group (`doctor` checks this).
   - **Shared-UID with no userns:** fall back to the Chromium policy file
     `SecurityKeyPermitAttestation`, which is not sufficient, so instead `doctor` warns. P0a must
     find a Chromium switch or policy that disables the HID transport. Candidates:
     `--disable-features=WebAuthenticationHid…`, and a managed-policy file in a per-profile policy
     dir via `--policy-dir`/`CHROME_POLICY`, which is unverified.
4. **Human path guard (R19).** Agents refuse to start when automatic mode would silently approve
   the human path.

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
    `https://evil.test` via `--host-resolver-rules`.
  - TLS: a test CA trusted through `--ignore-certificate-errors-spki-list` (verified in P0a; the
    fallback is an NSS db).
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
| P6 | Interception and transport: D1 (proxy or hardened fallback), D2 (connectNative relay, framing, keepalive, abort, reconnect) and D6.1 (always-attached readiness, degraded lease); removal of the HTTP endpoints | §4.4, §11 | opus | opus | L |
| P7 | Escalation (D3), granted-rules store, `passless agent grants`, `agent sessions` rename, `prompt.rs` fixes, `notify_user` and `state_dir` | §8 | opus | opus | L |
| P8 | Audit: §12 fields, terminal records, escalation events, schema bump | §12 | sonnet | sonnet | M |
| P9 | Deployment axes: `PrincipalRelationship` in doctor and audit, shared-UID `isolated` warning, doctor test rework | §13 | sonnet | sonnet | S |
| P10 | Agent-browser integration (D4) and containment (D6.3, D6.4): `agent browser`, browser detection and rejection, incognito enablement, bwrap hidraw hiding, automatic-mode guard, MCP adapters, `--print-config`, `doctor --agents` | §4.2, §7 | sonnet | opus | L |
| P11 | Docs: `docs/agents/*`, `AGENT_REGISTRATION*`, `PERMISSIONS.md`, `FURTHER_ANALYSIS.md` status, the skill, the ADR §19 table set to Done | — | sonnet | haiku link check | M |
| P12 | Final gate: full E2E matrix, security review, traceability audit | all | opus | — | M |

### Phase checklists

**P0a.**

- One spike script per question, kept under `tests/agent-e2e/spikes/`.
- Each question gets a yes/no answer with evidence.
- **Questions:**
  - **Q1.** Proxy create/get/cancel work with an unpacked extension, both headed and in new
    headless.
  - **Q1b.** The origin is browser-supplied, a page-forged `remoteDesktopClientOverride` is
    ignored, and `sameOriginWithAncestors` is present.
  - **Q2.** `attach()` survives a worker stop and restart, or is re-run on wake. Requests that
    arrive while the worker is detached: which path do they take?
  - **Q3.** The extension is enabled in incognito without user interaction, covering the primary
    OTR profile and `Target.createBrowserContext` contexts.
  - **Q4.** `--ignore-certificate-errors-spki-list` allows WebAuthn on `https://rp-a.test`.
  - **Q5.** Chrome for Testing loads the extension; Edge and Brave probe.
  - **Q6.** `isConditionalMediationAvailable` and the isUVPAA behaviour under the proxy.
  - **Q7.** A Chromium switch or managed policy that disables the HID/USB security-key transport.
  - **Q8.** `bwrap` with a private `/dev` (no hidraw) runs Chromium headed and in new headless.
  - **Q9.** A root process can connect to a user session bus after dropping to that user (helper
    design for R18).
- **Gate:**
  - D1 uses the proxy only if create, get, cancel and worker-restart all work on Chromium and
    Chrome for Testing, both headed and new headless.
  - D4 relies on incognito enablement only if it works without user interaction.

**P1.** Scenarios E2E-01 to E2E-08 run against the current code. Record the baseline pass/fail
in the progress log. The harness itself is reviewed for hermeticity: it must not touch the real
`$HOME`, the real bus or the real credential store.

**P2.** Unit tests:

- `confirm` returns 403;
- a cross-origin request is denied;
- the extension never calls the original `get`/`create` after the daemon fails.

E2E-09 and E2E-10.

**P3.**

- Delete `endpoint_manager.rs`, `ceremony.rs`, `ceremony_observer.rs`, `device.rs`, the UHID
  parts of `runtime.rs`, `authenticator.rs:202-240`, `interaction.rs`, the doctor UHID check and
  the udev/systemd agent device access.
- Delete `RegistrationGrantRegistry`, the `RequestRegistration` admin request, the CLI command
  and its runtime handler.
- Registration bearers are bound to the lease and revoked by `revoke_by_lease`.

Tests: registration after lease revocation is refused; registration under the wildcard is
denied. E2E-11.

**P4.** Unit tests:

- the legacy mapping table;
- digest sensitivity to every field;
- resolution precedence (exact > granted > wildcard), including the orphaned-grant case;
- the `register = "request"` validation rules.

Migrate the fixtures in `config.rs` tests (1449-1758), `policy.rs` tests (1019-1063),
`agent_config_integration.rs` and `policy_integration.rs`. E2E-12 and E2E-13.

**P5.** Unit tests:

- budget is not consumed when origin validation fails;
- a duplicate is coalesced, never signed twice;
- a failure consumes the key;
- a principal digest mismatch is denied;
- reload revokes bearers.

Replace the `sign.rs` replay tests (2091-2258). E2E-14 and E2E-15.

**P6.**

- JS unit tests for the worker and relay: framing, multiplexing, abort and reconnect.
- Rust tests for the relay and the connection handler.
- Rewrite `agent_extension_behavioral.js`.
- E2E-16 to E2E-22.

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

**P8.** Every reservation has a terminal record. The field-presence test is driven by a §12 field
list. The schema version is bumped. E2E-32.

**P9.** Doctor and audit report both axes. The shared-UID `isolated` warning is emitted. Rework
`test_same_uid_is_fatal`. E2E-33.

**P10.** E2E-34 to E2E-42 across the browser and tool matrix.

**P11.**

- `make check-doc-links` passes.
- No document mentions `confirm`, `supervised`, `delegated-session` or `registration_allowed`,
  except migration notes.
- The `docs/agents` quick start is followed verbatim by a subagent in the hermetic environment,
  and works.

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
| E2E-09 C | `confirm` legacy rule before P7 | Denied; native `get` is never invoked (CDP `WebAuthn` virtual authenticator attached as a canary must stay unused) |
| E2E-10 C | Cross-origin iframe to `rp-b` inside `rp-a` | Denied |
| E2E-11 C | Registration after browser exit using the old bearer | Refused |
| E2E-12 C | Wildcard `request` plus exact `allow` | Exact wins; wildcard path audited `rule="*"` |
| E2E-13 | Legacy config | Warns and maps; `allow + human` fails startup |
| E2E-14 C | Replay: page resubmits identical options (Kanidm pattern) | One signature; duplicate receives the same result |
| E2E-15 C | Budget: `evil.test` floods denied requests | Budget intact for `rp-a` |
| E2E-16 C | Page receives a credential passing `instanceof PublicKeyCredential` and `toJSON()` | Native object (proxy) or a compatible shape (fallback) |
| E2E-17 C | Abort via `AbortSignal` mid-request | Daemon receives abort; no signature; audit aborted |
| E2E-18 | Service worker stopped (CDP `ServiceWorker.stopWorker`) between requests | Next request reconnects and succeeds |
| E2E-19 | Worker killed during a pending request | Page gets `NotAllowedError`; daemon cancels; no orphaned escalation |
| E2E-20 C | Long wait: escalation approved after 6 min | Ceremony completes (proves past the 5-min MV3 limit) |
| E2E-21 | Page `timeout` 3 min with no approval | Fails at about 3 min; notification withdrawn |
| E2E-22 | 20 concurrent ceremonies across tabs | No silent drops; caps return explicit `busy` |
| E2E-23 C | `request` approved | Ceremony continues; grant persisted; next ceremony needs no prompt |
| E2E-24 C | `request` denied | `NotAllowedError`; cooldown blocks a re-prompt for 10 min (clock-injected) |
| E2E-25 C | Two tabs request the same RP concurrently | One notification; both complete after one approval |
| E2E-26 | Different RPs concurrently | One prompt at a time; the others queue; overflow denied |
| E2E-27 C | `register = "request"` approved | One registration; `authenticate = allow` persisted with `kind=registration`; second registration prompts again |
| E2E-28 C | Notification shows only daemon fields | Notify body and actions inspected via the double; page-controlled strings absent |
| E2E-29 C | Spoofed `ActionInvoked` from a non-server bus name | Ignored |
| E2E-30 | No notification server on the bus | Immediate deny, audited |
| E2E-31 C | `grants list`, `revoke`, `clear` | Revocation invalidates sessions; ceremony prompts again; malformed store fails closed |
| E2E-32 C | Audit content for allow, deny, escalation and abort | All §12 fields present; terminal record for every reservation |
| E2E-33 | Distinct-UID principal (if a second local user is available, else unit-level) | Axes reported; shared-UID isolated warning |
| E2E-34 C | Playwright MCP via `passless agent mcp playwright`: navigate, log in with passkey | Success |
| E2E-35 C | Playwright MCP with `--isolated` | Works (incognito enabled) or rejected with a clear message (per P0a) |
| E2E-36 | chrome-devtools-mcp via adapter, including `isolatedContext` | Same as above |
| E2E-37 C | Playwright library `connectOverCDP(PASSLESS_CDP_URL)` | Success |
| E2E-38 | browser-use with `cdp_url` | Success (local, optional) |
| E2E-39 | agent-browser `--cdp` | Success (local, optional) |
| E2E-40 | Headed (Xvfb) and `--headless=new` × Chromium, PW Chromium, Chrome for Testing | Core flows E2E-01, 23, 34 pass on every combination |
| E2E-41 C | `agents.browser_path` set to Google Chrome or headless-shell | Launch refused with an actionable error |
| E2E-42 | Real `dunst` with `dunstctl action` approval | Approval works with a real notification server |
| E2E-43 | Human authenticator concurrently in use (same-user) during a pending escalation | Human CTAP operation is not blocked |
| E2E-44 | `PASSLESS_INTERACTION_MODE=automatic` with a `request` rule | Escalation still prompts or denies; never auto-approved. Agents refuse to start without `allow_automatic_human_path` (R19). |
| E2E-45 C | Request while the extension worker is stopped or before attach; conditional-mediation request; request from a CDP-created context | Never reaches the human device: the human authenticator records no CTAP request, and the page gets `NotAllowedError` or no-op |
| E2E-46 C | Managed browser process | Cannot open any `/dev/hidraw*` (probe inside the browser sandbox namespace), or `doctor` warns on hosts without userns |
| E2E-47 C | Extension directory missing or unloadable | Launch fails with an actionable error; no browser without interception |
| E2E-48 C | Escalation waiters beyond the per-session or per-profile cap; `allow` ceremonies of another profile run concurrently | Caps enforced; other profiles unaffected; no pool exhaustion |
| E2E-49 | Notification server restarts while a prompt is pending | Pending entry expires cleanly; next request prompts on the new server |
| E2E-50 C | Repeated abort at the last second | Rate limit then cooldown (V-M2) |

## Traceability matrix

Every ADR 0014 decision maps to the phase that implements it and the tests that prove it. The
P12 audit fills in the Verified column.

| ADR | Decision | Phase | Tests | Verified |
|---|---|---|---|---|
| §4.2 | Managed browser; supported binaries; contexts | P10 | E2E-35, 36, 40, 41 | |
| §4.4 / §11 | Interception (D1), connectNative transport, keepalive, abort | P6 | E2E-16 to 22 | |
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
| V-H1 | Origin source on the proxy path unproven; a page might forge `remoteDesktopClientOverride`; no top origin or frame | P0a gate Q1b: forged override must be ignored, origin must come from the browser. Define `cross_origin` from `sameOriginWithAncestors`; top origin is unavailable on the proxy path, so the audit records `top_origin = null` with `cross_origin`. If forging is possible, D1 falls back. |
| V-H2 | Escalation waiters exhaust pool threads; budget drained in cooldown | Waiters are parked continuations in `EscalationService`, holding no thread. The decision dispatches completion to the pool. Waiters are capped per session (4) and per profile (16). R4 revised. |
| V-H3 | Re-resolution after approval impossible with a frozen `ctx.profile_config` and digest-based generation | R16 |
| V-H4 | Agent can self-approve on the user's bus; root on user bus | R18; ADR residual-risk amendment |
| V-H5 | Prompt thread can wedge forever on `join()` | P7: cancellable inner thread through a channel; `CloseNotification` before join; `NameOwnerChanged` watch expires pending entries and re-resolves the server name |
| V-H6 | The daemon needs UHID to start (`main.rs:531`); `localhost` RP rejected | The harness and CI set up `/dev/uhid` (CI step: `modprobe uhid` plus a udev rule on the runner, which is root there). Local runs accept that a transient human device exists, and its storage is the temp dir. R15 for localhost. |
| V-H7 | Auto-detection runs a principal-writable binary under the root daemon; easy path is port-mode only | R14 amended; `agent browser` fails with a clear message in pipe mode, and documents it |
| V-M1 | Lock order incomplete and contradictory | P5 inventories every lock into a documented order in `agent/LOCKING.md`. The escalation mutex is a leaf. No policy guard is held across another acquisition. The check order follows §9: audit reservation, then epoch re-check, then key use. |
| V-M2 | Abort dodges cooldown; an ignored prompt blocks the slot | Withdrawn escalations are rate-limited (3 per key per 10 min, then cooldown). A queued entry is dequeued when its last waiter leaves. An active prompt with zero waiters is withdrawn immediately. |
| V-M3 | Registration token goes to the wrong waiter | Registration escalations are not joinable. The token is bound to the creating ceremony. Concurrent duplicates are denied. R5 superseded. |
| V-M4 | A restarted worker leaves proxied requests hanging | Pending ids are kept in `chrome.storage.session` and failed with `NotAllowedError` on worker restart |
| V-M5 | D2 lacks back-pressure and re-authentication | Write timeout (5 s) closes the connection. The bearer is re-validated on every request against the revocation epoch. Wire ids are worker-allocated. Frames are capped at 1 MiB before allocation. |
| V-M6 | Phases not green as written | The harness supports phase-tagged expected failures (`xfail-until: Pn`). `request` denies with audit until P7. P2 text fixed to "until P7". P3 updates `test-device-matrix.sh`. E2E-09's canary is replaced by a hidraw-access probe (D6) and native-call instrumentation. E2E-12 asserts `rule="*"` only from P8. |
| V-L1 | R1 join uses a 30 s wait; a duplicate's abort cancels the original | The join waits until the ceremony deadline; a duplicate abort only detaches that duplicate |
| V-L2 | isUVPAA `true` causes upsell noise | Answer `false`, matching the native headless Linux value. P0a confirms RPs still offer a passkey sign-in. |
| V-L3 | Grant keys, punycode, scope wording | Grant keys use `validate_rp_id` output. The notification shows the punycode RP ID and "any page under this site". |
| V-L4 | R13 must test `Target.createBrowserContext` contexts | Added to P0a Q3 |
| V-L5 | Sign-proxy and daemon version skew | `doctor` compares versions; `hello` carries the build version |
| V-L6 | Test mechanics: stopWorker, cooldown clock, hidraw | E2E-18 uses `Target.closeTarget` on the worker target. Cooldown is configurable, `agents.escalation_cooldown`, with a minimum of 1 s in debug builds only. hidraw is hidden through D6. |

**Not verified by the reviewer.** These are carried into P0a:

- the proxy origin source;
- whether `attach()` persists while the worker is stopped;
- `isConditionalMediationAvailable` under the proxy;
- `--ignore-certificate-errors-spki-list` with WebAuthn;
- root access to a user session bus;
- zbus `MessageStream` lifetime.

## Final gate

- Every row of the traceability matrix is Verified with links to test names.
- Full local E2E matrix (`make test-agent-e2e-full`): all scenarios pass. The only allowed skips
  are optional tools that are not installed, and each one must be reported.
- CI-equivalent run: fmt, clippy, `cargo test --all-features` on x86_64, `make
  test-agent-validation`, `make test-agent-e2e`, fuzz smoke, `make check-doc-links`, pre-commit.
- An independent Opus security review of the whole branch diff, with each §14 invariant mapped to
  code and test evidence. No open critical or high findings.
- Human-path regression: `make test-e2e`, with agents compiled and disabled, plus a manual check
  that the restored `passless.service` works. The maintainer restarts it.
- The ADR §19 table is updated to all Done, and its status line reflects that.

## Progress log

| Phase | State | Commit | Notes |
|---|---|---|---|
| ADR consolidation | ✅ staged | — | ADR 0014 written; 11 ADRs and 14 plans removed |
| Design validation | ✅ | — | Opus review: 1 critical, 7 high, 6 medium, 6 low. All accepted (see Validation results) |
| P0a | ⏳ | — | |
| P0b | ⏳ | — | |
| P1 | ⏳ | — | |
| P2 | ⏳ | — | |
| P3 | ⏳ | — | |
| P4 | ⏳ | — | |
| P5 | ⏳ | — | |
| P6 | ⏳ | — | |
| P7 | ⏳ | — | |
| P8 | ⏳ | — | |
| P9 | ⏳ | — | |
| P10 | ⏳ | — | |
| P11 | ⏳ | — | |
| P12 | ⏳ | — | |
