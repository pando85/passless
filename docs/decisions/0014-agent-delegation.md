# ADR 0014: Agent delegation

- **Status:** Accepted
- **Date:** 2026-11-10
- **Decision owners:** Passless maintainers
- **Implementation status:** Implemented on branch `feat/agent-delegation-adr-0014` (P2 to P12); the final verification gate (P12) passed at commit 602db70 on 2026-11-12, and its full E2E matrix was re-run clean across both attach modes (port and pipe) at 5b0bace. The two accepted residuals (unfocused-tab registration; the evaluated systemd directives) remain marked as such in [Implementation status](#19-implementation-status)
- **Amended:** 2026-11-11, with maintainer-resolved decisions and the results of the browser and
  environment spikes (see [History](#20-history))

This ADR is the single source of truth for letting AI and browser agents authenticate with
passkeys through the Passless daemon. It replaces ADRs 0001, 0002 and 0004–0012 and the agent
implementation plans; see [History](#20-history). ADR 0003 (portable TPM keys) and ADR 0013
(credentialsd) remain separate.

## 1. Context and scope

Passless is a software FIDO2 authenticator. Its human path is an ordinary CTAP device over UHID.
Agents need passkey authentication too, but stock Chromium on Linux offers no transport that is
at once headless, signed by an external daemon, and key-never-in-browser:

- a UHID authenticator always triggers Chromium's native, non-DOM credential modal, which CDP
  cannot dismiss;
- the CDP virtual authenticator is headless but signs inside the browser, so the key must be
  injected, policy and audit are bypassed, and non-extractable TPM keys cannot work;
- a D-Bus platform authenticator (`libwebauthn`, credentialsd) shows portal UI and lacks a
  trusted origin binding for agents (ADR 0013 §3).

Passless therefore loads a daemon-backed MV3 extension into a daemon-managed browser. The
extension intercepts WebAuthn calls and forwards them to the daemon, which applies policy, signs
with the configured key provider and audits the result.

A review in November 2026 found that the human-policy path (`confirm`, human UP/UV) fell back to
native WebAuthn with no binding to the agent operation and could be auto-approved by
`PASSLESS_INTERACTION_MODE=automatic`; that "one-shot" meant a replay set plus a budget on a
reusable bearer session; and that `same-user` mixed two separate properties. This ADR resolves
those findings.

**Product goal.** Agents act autonomously within an administrator-owned policy. They never put a
human into a WebAuthn ceremony. When they need more authority, they ask, a human approves once,
and the approval becomes policy.

Scope: Linux, the agent path only. The human CTAP path is unchanged except where noted.

## 2. Goals and non-goals

Goals:

- keep agent support disabled by default and leave the human authenticator path unaffected by
  any agent configuration or failure;
- keep private keys inside daemon-owned storage or the TPM; the daemon is the only signer;
- authorize every operation from administrator-owned policy, re-checked immediately before key
  use;
- keep agent-owned credentials separable from human credentials when the operator wants that;
- audit every credential creation or use durably before key use, and label agent evidence
  unmistakably;
- fail closed on missing policy, routing, storage, audit, or isolation controls.

Non-goals:

- exporting private keys, PINs, cookies, tokens, raw assertions or arbitrary signatures to an
  agent;
- per-ceremony human approval or human UV for agents (use a human browser instead);
- restricting business actions an agent performs after login, or revoking RP sessions;
- making a same-user agent independently identifiable at the RP;
- claiming agent UP/UV is ceremony-time human interaction;
- protecting against host root, kernel compromise or a malicious Passless administrator;
- distinguishing subprocesses inside one authenticated principal boundary.

RP-native workload identity, service accounts and scoped OAuth remain preferable where they
exist.

## 3. Trust model and principals

| Principal | Trust |
|---|---|
| Operator (administrator) | Trusted. Owns the config file, profiles and rules. |
| Human user | Trusted. Approves escalations through the notification server. |
| Daemon | Trusted computing base: storage, key providers, policy, audit, notification prompt. |
| Agent principal | Untrusted beyond its policy. Requests operations; never sets policy or approves escalations. |
| Managed browser and extension | Inside the session's TCB for origin reporting; never holds keys or the daemon bearer in the page. The agent holds CDP authority over the browser: pipe mode keeps it away from the extension (§4.3); port mode does not, so there the extension's origin report is only as trustworthy as the CDP client (§11, §15). |
| Web page | Untrusted. Supplies options, challenges and display text. |

Trust boundaries:

- **Daemon ↔ principal.** Principal authentication combines a 256-bit launcher capability with
  peer credentials, process identity, namespace and cgroup checks, and process ancestry. A copied
  capability outside the expected boundary is insufficient.
- **Daemon ↔ extension.** A per-session bearer, held only in the extension service worker.
- **Agent ↔ human.** Only escalation crosses it, through the verified notification sender (§8).
- **UID boundary.** Whether the principal shares the daemon UID decides which OS controls are
  meaningful (§13).

## 4. Architecture

```text
agent principal ── IPC (capability) ──▶ daemon ◀── UHID ── human browser
      │                                   │
      │ CDP (pipe or port)                ├─ policy engine + granted-rules store
      ▼                                   ├─ operation service (sign / register)
managed browser (private /dev)            ├─ backend handles (human, isolated/<profile>)
  webAuthenticationProxy ─▶ worker        ├─ notification prompt (D-Bus)
                              │           └─ audit writer
                              └─ native messaging ─▶ sign-proxy ─▶ Unix socket ─┘
```

### 4.1 Daemon

One daemon owns every credential backend, the policy engine, the notification prompt and the
audit writer. Agent processes and browsers receive no storage path, key handle, raw assertion API
or generic signing API. Running agent services in a separate process is rejected (§17).

The daemon exposes separate interfaces: an administrative interface (profiles, credential and
lease revocation, audit, grants); a principal interface (health, browser lifecycle, status,
cancellation, non-secret isolated credential metadata); and the extension's sign socket.
Principals cannot use the administrative interface.

Before launching a browser the daemon durably records a runtime manifest (session, lease, PID,
process start identity, cgroup, profile path; no secrets). Startup recovery kills an orphan only
after confirming start identity and cgroup ownership, and quarantines its profile.

### 4.2 Principal sessions and managed browser

A trusted launcher creates one principal session per launch. `PrincipalSessionId` is generated by
Passless, never derived from a harness label. A profile defines authority; a principal session
defines runtime isolation.

- `max_concurrent_sessions` (default 1) bounds live principals per profile.
- With `browser_scope = "session"` (default) each principal session owns at most one browser
  lease. A lease is reused only by its owning session; matching profile, UID, CDP port or
  harness label never suffices.
- Each lease has its own runtime directory and `--user-data-dir`, with no sync, saved passwords,
  platform passkeys or copied user profile.
- Session end, expiry or revocation revokes its lease and sign bearer, terminates Chromium and
  cleans the profile. A profile that fails cleanup is quarantined and never reused.
- Killing the browser does not revoke RP sessions or material the principal copied.
- **Supported browsers.** Chromium and Chrome for Testing. Chrome for Testing is detected from the
  `--version` output (`Google Chrome for Testing …`); the user agent does not distinguish it from
  branded Chrome, so detection never relies on it, and the check for branded Google Chrome must not
  match this string. Branded Google Chrome (it ignores `--load-extension`) and `chrome-headless-shell`
  (it loads no extensions) are rejected at launch with an actionable error. `chrome-headless-shell`
  cannot be told from Chrome for Testing by `--version`: both print `Google Chrome for Testing
  <version>` (probed on Playwright's `chrome-headless-shell` and `chrome`, 155.0.8059.12 and
  156.0.8078.4), so it is recognised by binary name or install path (a path component containing
  `headless-shell` or `headless_shell`, the symlink target included). Edge and Brave were not probed
  and are unsupported. In a distinct-UID deployment only root-owned binaries that the principal
  cannot write are accepted (the binary and every directory above it owned by root, not writable by
  group or others). The binary is the profile's `browser_command`, else `agents.browser_path`, else
  the first supported one found: Playwright Chromium in `~/.cache/ms-playwright`, Chrome for Testing
  in `~/.cache/puppeteer`, the distribution's `chromium` (`browser_select.rs`).
- **Incognito and CDP-created contexts.** The extension, and with it the proxy (§4.4), applies in an
  off-the-record context only if the extension is allowed in incognito. The launcher therefore
  seeds the managed browser's fresh profile before its first launch: `Default/Preferences` contains
  `extensions.settings.<id>.incognito = true`, where `<id>` is the stable extension ID derived from
  the manifest `key`. Verified on Chromium 156 and Chrome for Testing 156: with the seed, the
  extension and the proxy apply in the primary off-the-record profile and in
  `Target.createBrowserContext` contexts, which is what Playwright `newContext()`, Playwright MCP
  `--isolated` and chrome-devtools-mcp `isolatedContext` create. Without the seed those contexts use
  the native path. The seed relies on these browsers not enforcing the preference MAC for this key.
  The launcher must verify at startup that the seeding took effect and fail closed if it did not.
  Re-checked in P10a (Chromium 156.0.8078.79, Playwright Chromium (Chrome for Testing 155) and Chrome for Testing 157, headed
  and `--headless=new`) and in P10b on Playwright Chromium 156.0.8078.4 (`--headless=new`: Playwright
  MCP `--isolated` and a CDP-created context are intercepted, E2E-35, E2E-45/cdp-context); the full
  browser x headed/headless matrix is the E2E-40 run.

### 4.3 Browser control and CDP exposure

| | `browser_cdp_expose = "pipe"` (default) | `"port"` |
|---|---|---|
| Transport | `--remote-debugging-pipe` (fds 3/4) | `--remote-debugging-port` on 127.0.0.1 |
| Mediation | Every command via `browser-control` | None after provisioning |
| `browser_user` | Must differ from `principal_user` | May equal it |
| Command audit | Per command | Lease level |
| Trust assumption | Agent and local peers untrusted | Local environment trusted |

Port mode is a reduced-security mode. A loopback TCP listener has no Unix-user ACL; the
randomized DevTools path and the 0600 `cdp-endpoint` file are discovery hygiene, not a boundary.
With `browser_scope = "session"` and `max_concurrent_sessions > 1`, `browser_cdp_port` must be 0:
each session gets its own browser and two of them cannot bind one fixed port. With
`browser_scope = "profile"` there is a single shared browser per profile, so a fixed port is
allowed whatever `max_concurrent_sessions` is. `browser-control` is unavailable in port mode.

Playwright MCP uses a Passless HTTP bootstrap on an ephemeral loopback port: `GET /json/version`
authenticates an ephemeral bearer, runs the principal-scoped `EnsureBrowser` after full principal
checks, and returns Chromium's real `webSocketDebuggerUrl`. It never relays WebSocket frames. The
bearer gates lazy startup only; it does not protect Chromium's listener.

In both modes the WebAuthn ceremony is mediated by the daemon; CDP exposure decides only who holds
authenticated browser-session authority.

**Principal launch path (pipe mode).** A principal in a principal session ensures its browser with
the same `EnsureBrowser` request as in port mode (`passless agent browser`). In pipe mode the
daemon starts the browser with `--remote-debugging-pipe`, keeps the pipes, and answers with no
endpoint and `cdp_exposure = "pipe"`; the principal then drives the browser with `browser-control`.
Everything else is the port path: the principal checks of the principal interface, the readiness
gate (no answer before the worker attached with incognito access allowed), the lease's containment,
the session grant and bearers bound to the session and lease, the B1 lifetime (the browser is
forked on the launcher thread and ends with its session, revocation or expiry), and the lease
audit records (`browser_lease.launch` with `cdp_expose = "pipe"`, then `revoke` and `cleanup`).
`browser-control` acts on the lease its session owns and is refused, with a `denied` record,
while the lease's interception is degraded (the same condition under which the port-mode
bootstrap withholds its endpoint); a worker that is reconnecting within its grace period is
served. A caller that can only use an endpoint (the Playwright bootstrap, the chrome-devtools
adapter) sends `direct_cdp = true` and a pipe-mode profile refuses it before anything starts.
`browser-control` does not hold the browser manager while it waits for the browser's answer (it
takes it for the request and for 50 ms reading steps): a `Runtime.evaluate` with `awaitPromise`
that waits for a WebAuthn ceremony would otherwise block the ceremony's own lease activation, which
needs the manager, until the call timed out. One call per lease runs at a time; a second gets a
`Busy` error. With `browser_scope = "profile"` the sessions of a profile share one browser and its
pipe, so they see each other's targets and events.

`browser_user` must differ from `principal_user` (and from the daemon user, and must not be
root) only under a root daemon, where the browser is a separate Unix user that the principal
cannot reach (`runtime/gates.rs`, checked at startup). A non-root daemon cannot switch users: the
principal, the daemon and the browser are then one UID, the browser runs as the daemon user, and
what pipe mode adds is mediation and audit of every CDP command and the extension filter, not
isolation of the browser process from the principal (who can then read its profile and signal it).
Treat that deployment as the shared-UID case of §13.

**Extension filter (pipe mode).** CDP can attach to any target, the extension's service worker
included: a session on it could read the daemon bearer, send requests with a forged
`remoteDesktopClientOverride.origin` or `sameOriginWithAncestors`, or call
`webAuthenticationProxy.detach()`. In pipe mode `browser-control` filters the agent's commands
against the fixed extension ID (`cdp_filter.rs`, review M3):

- it refuses the `Extensions` domain, `Target.exposeDevToolsProtocol` (it would give page script an
  unfiltered CDP channel), `Target.sendMessageToTarget` and `Target.attachToBrowserTarget` (the
  agent already holds the browser session), `Target.openDevTools` (a `devtools://` page on any
  page), `Target.setRemoteLocations` (a browser-side listener that connects out and exposes what it
  finds as targets) and `Browser.executeBrowserCommand` (the browser's own UI commands), and
  `ServiceWorker.inspectWorker`, `stopWorker` and `stopAllWorkers`, which name workers by version
  and cannot be attributed without tracking every registration. The rest of `Target.*` and
  `Browser.*` was reviewed: what remains neither opens browser UI nor creates a target the filter
  does not see (`createTarget` takes a URL, which is checked; `getDevToolsTarget` only names a
  target, which is hidden and refused like any other);
- it allows only flat sessions: `Target.attachToTarget` and `Target.setAutoAttach` must say
  `flatten: true` (as Playwright and Puppeteer do). A non-flat session tunnels its commands
  through a JSON string in `Target.sendMessageToTarget`, whose escapes a check of the outer request
  never decodes (review H1); its inbound counterpart, `Target.receivedMessageFromTarget`, is
  dropped;
- it refuses a command whose `targetId` is a hostile target, or that runs on a session of one.
  The filter maps every session to its target (from `Target.attachedToTarget` events and
  `Target.attachToTarget` responses), refuses a session it never saw created, and before it
  forwards a command that names a target or runs on a session it asks the browser what that
  target is now, with its own `Target.getTargetInfo` (no answer in time refuses the command). A
  target found to be hostile, by a lookup, a target event or a target list, has every session on
  it refused and detached (review H2). A target is hostile when it is the extension's (its URL
  holds the extension ID), when its `type` is browser chrome (`browser`, `browser_ui`,
  `background_page`, `app`, `webview`) or when its URL, normalized as below, is on an internal
  scheme (the list in the next bullet, any `chrome-extension:` page, also behind `view-source:`).
  Without this, `Target.getTargets` listed the browser's pre-existing `browser_ui` targets and
  `Target.openDevTools` returned a `devtools://` page, neither of which carries the extension ID.
  Web content stays visible: `page`, `iframe`, `worker`, `shared_worker`, `service_worker`, `tab`
  and `other` are judged by their URL only. **`chrome-error:` is not internal for a target:**
  Chromium reports `chrome-error://chromewebdata/` as the URL of a page whose navigation failed,
  and an agent that retries after a network error does so on that very page, so detaching it would
  break retries; it is a renderer error page, not a WebUI page with browser privileges. A request
  that names `chrome-error:` is still refused, as no legitimate command needs to;
- it refuses a command whose parameters name an extension (`chrome-extension:`, the extension ID)
  or a browser-internal page (`chrome:`, `chrome-untrusted:`, `chrome-search:`, `devtools:`,
  `chrome-devtools:`, `chrome-error:`, and `about:` other than `about:blank` and `about:srcdoc`, because Chromium
  maps `about:inspect` and the like to `chrome://` pages; review M-a), after URL-style
  normalization (tabs and newlines dropped, `\uXXXX`/`\xHH` and percent escapes decoded once,
  lowercase). A string that is itself JSON is parsed and searched as well;
- it hides hostile targets (the extension's and browser-internal ones): every response's
  `targetInfos` lose them and a `targetInfo` of one becomes an error, whatever command the
  response answers, and their target events are dropped. An auto-attach that reaches the worker or
  an internal page is not shown; the daemon resumes the target if it waits for a debugger and
  detaches that session, and the client never learns of it. The daemon logs `hid extension target`
  for the extension's own targets only (the E2E harness reads the worker's ID there) and `hid
  browser-internal target` for the others;
- it forwards the request it checked, re-serialized, never the agent's raw text, so the browser's
  JSON parser cannot read something else (duplicate keys, escapes; review M-b); it reserves
  request IDs from 2000000000 for the daemon, swallows the answers to its own commands and drops a
  browser message it cannot parse.

A refusal is a `Forbidden` error, audited as a `denied` browser-control record. Every command on
a session costs one extra pipe round trip for the lookup. The filter's view is updated only while a
`browser-control` call reads the pipe, so a worker that restarts under an
auto-attach with `waitForDebuggerOnStart` stays paused until the next call (availability of the
agent's own ceremonies only). The filter does not restrict `file:` URLs, so the agent can read what
the browser user can read, the extension's `worker.js` and its bearer included; the bearer alone
does not pass the sign socket's peer-UID check when the browser runs as another user (§4.4), and in
a shared-UID deployment the agent can read that file directly anyway. The filter is tested against a scripted
browser pipe (`browser.rs`, `cdp_filter.rs`) and against a real browser by E2E-52, which also
attacks the worker by its target ID. Port mode has no such filter:
Chromium's listener is reached directly and the bootstrap never relays frames (§7, §15).

### 4.4 Extension and transport

The daemon loads an MV3 extension (`cmd/passless/assets/agent-extension/`) with
`--load-extension`. `chrome.webAuthenticationProxy` is the interception mechanism. The extension is a
service worker only: it has no content script, and the MAIN-world override of
`navigator.credentials` is removed. The page therefore receives a genuine `PublicKeyCredential`,
and the browser, not the extension, applies the RP-ID and Permissions Policy checks before the
extension sees a request (§11).

The worker:

- calls `chrome.webAuthenticationProxy.attach()` on every start; a repeated call is idempotent;
- handles `onCreateRequest` and `onGetRequest` by forwarding the request details to the daemon and
  completing the request with `completeCreateRequest` or `completeGetRequest`, passing the daemon's
  output through verbatim or, on failure, a DOMException name;
- handles `onRequestCanceled` by sending an abort to the daemon;
- answers every `onIsUvpaaRequest` with `false`;
- holds the daemon bearer and talks to the daemon (below).

As implemented (P6), the worker keeps one `chrome.runtime.connectNative` port open to the native
host `rs.passless.sign_proxy` (`cmd/passless/src/bin/sign-proxy.rs`), a stdio relay that holds one
connection to the daemon's Unix socket. Both hops carry length-prefixed JSON frames (`hello`,
`request`, `abort`, `result`, `keepalive`); requests are multiplexed by a worker-allocated id, and
both sides send a keepalive at least every 20 seconds, so an escalation wait is not bounded by
MV3's `sendNativeMessage` and `fetch` limits. There is no HTTP. The daemon-UID socket is
`$XDG_RUNTIME_DIR/agent/sign/sock` (mode 0600 in a 0700 directory); a browser that runs as another
user gets `<sign dir>/<uid>/sock`, in a 0700 directory owned by that user, which needs a root
daemon. The `hello` authenticates the bearer and the peer: its `SO_PEERCRED` UID must be the
lease's browser UID. The native host manifest is written only into the lease's profile and admits
only the extension ID fixed by the committed manifest `key`.

## 5. Identity modes and backend

| `mode` | RP identity | Backend | Trust statement |
|---|---|---|---|
| `same-user` | The user's existing passkeys and RP accounts | The human backend handle | The agent is trusted to act as the user within its policy |
| `isolated` | Separate agent passkeys and RP accounts | A profile-specific backend handle | The agent cannot use or enumerate the human namespace |

Autonomy is a policy, not a mode.

**`same-user`** clones the already-constructed human `CredentialBackendHandle`. It never reopens
the human storage path and has no profile storage or PIN path. It shares the human operation lock
and counters, may narrow access with `credential_refs`, and registers into the human backend only
under an explicit registration rule. For a portable TPM backend the agent can exercise but not
export keys; for an extractable backend under a shared UID, daemon exclusivity is an architectural
and audit property, not a hard boundary.

**`isolated`** uses a profile handle with separate storage, key provider, PIN state and lock. It
cannot enumerate, select, register into or sign with the human backend, cannot share a path with
the human backend or another profile, and is revocable at the RP without touching human
credentials. Software or portable-TPM keys are chosen per profile. `isolated` means credential
isolation, not OS namespace isolation.

**Transport.** Agents use only the extension path (§4.4). Isolated profiles have no per-profile
UHID or hidraw device, and the daemon runs no CTAP endpoint for agents. Non-browser agent clients
(libfido2, ssh) are out of scope until requested. The human authenticator's own UHID device is
unaffected.

**Backend handle.** Storage, key provider, verification state and operation lock are selected
together (`CredentialBackendHandle`, `CredentialNamespace::{Human, Isolated(ProfileId)}`). The
sign and register services accept only a runtime-selected handle; they never open paths, infer
providers or hardcode the software provider.

## 6. Policy

### 6.1 Schema

```toml
[agents]
enabled = true
audit_path = "/var/lib/passless/agent-audit.jsonl"
acknowledge_global_same_user = ["opencode"]

[agents.profiles.opencode]
mode = "same-user"            # credential source: same-user | isolated
principal_user = "alice"
session_ttl = "10m"
max_operations = 16
credential_selection = "single"

[[agents.profiles.opencode.rules]]
rp_id = "github.com"
authenticate = "allow"
register = "deny"

[[agents.profiles.opencode.rules]]
rp_id = "*"                   # requires acknowledge_global_same_user
authenticate = "request"
register = "deny"
```

| Action value | Meaning |
|---|---|
| `deny` | Reject before credential enumeration or key access. Never prompts. |
| `allow` | Authorize autonomously. UP and UV come from agent-session evidence (§7). |
| `request` | Not authorized yet. The ceremony raises an escalation (§8). For `authenticate`, approval persists `allow` for that exact RP. For `register`, approval permits one registration (§8.3). |

`register` and `authenticate` are independent per rule. Per-rule `credential_selection` overrides
the profile value (§10.1). Policy is owned by the operator; a principal cannot add, broaden,
reload or revoke it, and cannot choose an evidence source at request time.

RP IDs are normalized exact DNS names: no scheme, port, path, trailing dot, IP address or public
suffix. The only pattern is the constrained `*` (§6.3). The one exception to the public-suffix rule
is `localhost`: `rp_id = "localhost"` and origins `http://localhost[:port]` are valid for exact
rules only and never match through the wildcard.

### 6.2 Resolution

The effective action for `(profile, rp_id, action)` is:

1. an exact config rule with `deny` gives `deny`;
2. an exact config rule with `allow` gives `allow`;
3. an exact or wildcard rule with `request` gives `allow` if the granted-rules store has a
   matching exact entry, otherwise `request`;
4. a wildcard rule with `allow` gives `allow`;
5. otherwise `deny`.

The granted-rules store can only upgrade `request` to `allow`. When the operator changes a config
rule to `deny` or removes the `request` rule, matching granted entries become inert, and
`passless doctor` reports them as orphaned.

### 6.3 Wildcard

`rp_id = "*"` is valid only when the profile is `same-user`, the profile is listed in
`acknowledge_global_same_user`, `register = "deny"`, and the rule has no `credential_refs` and no
`credential:<ref>`. Selection under a wildcard is always `single`; a wildcard never chooses
between several human accounts. Exact rules always take precedence. Every operation resolves
through exactly one rule, and a wildcard match is audited as `rule = "*"`.

### 6.4 Validation

- Unknown fields and enum values fail startup. Missing profiles, rules or actions deny.
- `same-user` rejects profile storage and PIN paths; `isolated` requires a complete,
  non-overlapping profile backend.
- Same-user registration (`register = "allow"` or `"request"`) requires an exact RP and the
  profile listed in `acknowledge_same_user_registration`.
- The legacy evidence tables `{authorization, user_presence, user_verification}` and presets
  parse with a deprecation warning until the release after next (plan R8, then removed):
  `deny` → `deny`; `autonomous` and
  `allow+agent+agent` (or the `policy` alias) → `allow`; `supervised` and `confirm+*` →
  `request`. Any other combination, including `allow` with human or `none` evidence, fails
  startup with a migration message.
- The legacy profile fields `rp_ids`, `registration_allowed`, `require_uv` and
  `human_verification_prompt` are removed; a config using them fails with a migration message.
- The policy digest covers every rule field, profile-level `credential_selection` and every
  acknowledgement. It does not cover the granted-rules store, which has its own `grants_digest`
  (§8.4).
- A ceremony resolves against the live configuration plus the granted-rules store, never against a
  copy of the profile configuration frozen into the session. Change is tracked by two monotonic
  counters: the *revocation epoch*, bumped by a config reload, a grant revocation and a config
  change, which revokes sessions; and the *grant epoch*, bumped when a grant is added, which does
  not revoke sessions (§8.4, §9).

## 7. Ceremonies and evidence

An agent ceremony never invokes the notification prompt, the PIN path or native WebAuthn. The
extension never falls back to a native authenticator for a request it has routed to the daemon. A
`deny`, a rejected or timed-out escalation, and every policy failure return `NotAllowedError` to
the page. Non-public-key credential calls (passwords, federated credentials) are not WebAuthn and
never reach an authenticator.

**The managed browser never reaches the human authenticator (invariant 25).** While attached, the
proxy routes every WebAuthn create and get from the managed browser to the extension, and a request
the extension cannot handle fails closed. Conditional mediation is unavailable while attached (§11).
The remaining gaps are an unloaded extension, a request before the first attach, and a context in
which the extension is not enabled (§4.2): each would be handled by the browser itself, through
CTAP over HID, and so could reach the human's UHID device. No command-line switch or feature flag
disables CTAP over HID (verified: plain Chromium created a credential through the UHID device with
every candidate flag), and the binary's policy list contains no policy that does (enterprise policy
installation was not tested). The CDP virtual authenticator is not a substitute, because it signs
inside the browser and any CDP client can remove it. Containment is therefore mandatory and is based
on the filesystem and the UID:

- Whenever `bwrap` and unprivileged user namespaces are available, the managed browser runs in a
  private `/dev` that has no `hidraw*` and no `uhid`, as defence in depth:
  `bwrap --dev-bind / / --dev /dev --die-with-parent <browser> …`. Chromium's own sandbox keeps
  working inside it (verified on distro Chromium 156, with no `--no-sandbox`; Playwright Chromium
  and Chrome for Testing are verified before they are supported under containment).
- The private `/dev` is required, and the launcher refuses to start the browser without it, when
  the browser's UID could open any `/dev/hidraw*` (no `bwrap`, or no unprivileged user namespaces,
  means refusal). The check is `faccessat2(AT_EACCESS, R_OK | W_OK)` over every `/dev/hidraw*`
  (ACLs count), run in the child that would exec the browser, after its credential drop, so it is
  evaluated as the browser's UID and groups; the child lists `/dev` itself. It fails closed: an
  unreadable `/dev`, a kernel without `faccessat2` or any error other than "cannot open" refuses the
  launch. Whether `bwrap` works is probed as the browser's user too, and a `bwrap` whose binary or
  any directory on its path another user could write is not used. Supplementary groups are not
  dropped inside `bwrap`'s user namespace (they show as the overflow GID 65534 but stay effective),
  which is why the private `/dev`, not the groups, keeps hidraw out. The browser is forked
  on a long-lived launcher thread: its parent-death signal, and `bwrap --die-with-parent`, follow
  the forking thread, so a browser forked on a request thread would die when the request returned.
- In a distinct-UID deployment where the browser user cannot open any hidraw node, containment is
  not required. `passless doctor` reports which case applies: required and in place, in place as
  defence in depth, not required, or refused.
- A missing or unloadable extension is a launch error, never a launch without the extension. The
  CDP endpoint is not handed out until the worker has attached the proxy, and is withheld again
  while the daemon cannot confirm the attachment: the lease is degraded when its worker has been
  disconnected, or has reported `attached = false`, for longer than a 10-second grace period.
  Degraded does not mean that requests go native: the attachment is browser-side state, and while
  the extension stays loaded a request wakes the worker (§11). Only a lost or failed attachment
  leaves the native path, which the private `/dev` contains. A worker that is not allowed in
  incognito (§4.2) counts as not attached: the launch fails and the endpoint is withheld. In port
  mode the withholding is discovery hygiene, not a boundary: the launcher removes the browser's
  `DevToolsActivePort` once it has read the endpoint, but a same-UID agent can still find the
  loopback listener (socket tables and its own processes' descriptors) and read the WebSocket URL
  from DevTools' `/json/version`. Port mode already trusts the local environment (§4.3); the
  private `/dev` bounds what a request that bypasses the extension can reach. A port-mode CDP client
  can also attach to the extension's service worker and evaluate code there: read the bearer, send
  requests with a forged origin, or detach the proxy. That bypasses no policy (the daemon still
  checks the origin against the RP ID, the rules, the budget and replay, and a detached proxy leaves
  only the contained native path), but the extension's origin report is then only as trustworthy
  as the CDP client. Pipe mode filters CDP access to the extension (§4.3) and is the hardened
  option.
- The daemon's writes into a lease never follow a path the browser user controls (the runtime
  root belongs to that user): the lease directory and the extension directory stay the daemon's,
  every write goes through directory handles opened without following symlinks, files are created
  exclusively (`O_EXCL | O_NOFOLLOW`) and rewritten by unlink and create, and only the profile is
  handed to the browser user, after the daemon's writes into it and before the browser starts.

`PASSLESS_INTERACTION_MODE=automatic` (PR #505) affects only the human CTAP path and never approves
an escalation. Because it would let a request that reaches the native path be signed silently, the
daemon refuses to start agents when it is set and any same-user profile has an `allow` or `request`
rule, unless `agents.allow_automatic_human_path = true`. `passless doctor` flags the combination.
Isolated and deny-only profiles do not trigger it: in a shared-UID deployment their managed browser
still runs as the human's UID, and what keeps its native requests from the automatically approving
human authenticator is the containment above, not this guard.

For an `allow` decision the daemon sets UP=1 and UV=1 only after validating that:

- the bearer session is active, unexpired and within its operation budget;
- the session is bound to the profile, the principal digest and the browser lease;
- the operation passes origin and RP validation;
- the revocation epoch is unchanged and the rule, re-resolved against the live configuration and
  grants, still resolves to `allow` immediately before key use;
- the replay key is fresh;
- the durable audit reservation has succeeded.

This is authenticator-local verification of the agent as the authenticator user. The RP cannot
tell agent UV from human UV; the audit always labels the evidence `agent`. Rules carry no evidence
fields, and an RP's `userVerification` request never sets UV by itself. Credential `credProtect`
is evaluated against this evidence (level 2 needs UV unless the request names the credential in
`allowCredentials`; level 3 always needs UV); agent UV satisfies them only because the operator
chose `allow`.

## 8. Escalation and granted rules

### 8.1 Flow

1. A ceremony resolves to `request`.
2. The daemon creates or joins a pending escalation keyed by `(profile, rp_id, action)`. One is
   pending per key; concurrent `authenticate` ceremonies wait on it. Registration escalations are
   not joinable (§8.3).
3. The daemon writes an `escalation_requested` audit record; if the write fails, the ceremony
   fails.
4. The daemon shows a notification built only from daemon-derived fields: profile, identity
   mode, principal, action, RP ID, origin, and whether the grant would be persistent. It shows no
   page- or agent-supplied text. The only actions are **Allow always** and **Deny**.
5. The WebAuthn call stays open until a decision or the ceremony's effective timeout. The waiting
   ceremony is parked in the escalation service; it holds no lock (no operation, storage, policy
   or session lock) and no request-cap slot, while its request thread sleeps on the escalation
   condvar (§8.2; amended in P7). The timeout
   matches Chromium: the page's `timeout` clamped to 3 minutes–20 hours, or 20 hours when unset
   (`AdjustTimeout()` in `content/browser/webauth/authenticator_common_impl.cc`;
   `kMinRequestTimeout`/`kMaxRequestTimeout` in `device/fido/public/fido_constants.cc`). The
   optional `agents.escalation_timeout` (unset by default) sets a shorter cap. The notification
   has no expiry and is withdrawn when the ceremony ends, aborts or times out. The transport
   requirement is in §4.4.
6. On approval the daemon writes `escalation_approved`, atomically persists the granted rule,
   bumps the grant epoch, then re-resolves and continues the original ceremony as `allow`.
7. On denial or timeout it writes `escalation_denied` or `escalation_expired`, fails the
   ceremony, and starts a cooldown for that key (default 10 minutes) during which new requests
   are denied without prompting. When a waiting ceremony is aborted it stops waiting; when the last
   waiter of an escalation has left, the escalation is withdrawn, its notification is closed, a
   late click has no effect, and `escalation_expired` with `reason = aborted` is recorded (§12).
   Withdrawn or aborted escalations are rate-limited: after 3 per key within 10 minutes, the
   cooldown applies to that key. A queued entry is dequeued when its last waiter leaves, and an
   active prompt with zero waiters is withdrawn immediately.

### 8.2 Integrity and abuse limits

- Approval comes only from the notification server's verified D-Bus sender: the prompt
  subscribes to `ActionInvoked` with zbus and rejects signals whose sender is not the server's
  unique bus name. No API, CLI or extension message can approve an escalation; operators who want
  a rule without a prompt edit the config.
- The notification-server capability gate fails closed on servers without distinct actions.
  `min_review_delay_ms` is a timing heuristic, not authentication.
- `agents.notify_user` names the human whose session bus receives escalation prompts. The user
  unit uses its own bus. If no bus can be resolved, escalation is unavailable: the request is denied
  immediately and audited. Headless hosts use explicit `allow` rules.
- A root daemon (distinct-UID deployment) reaches the `notify_user` session bus only through a
  dedicated per-prompt child process that lives exactly as long as that prompt: it owns the bus
  connection, emits the notification, waits for the action or close signal, and exits. The daemon
  can kill it to withdraw the prompt. The child drops privileges (`setgroups`, `setresgid`,
  `setresuid`, `PR_SET_NO_NEW_PRIVS`, no capabilities) and connects to
  `unix:path=/run/user/<uid>/bus` before it does anything else, and reports the result to the
  daemon. The daemon never changes its own credentials. D-Bus EXTERNAL authentication requires the peer UID to
  equal the bus owner's UID (verified), so a root process connecting as itself is rejected, and the
  drop is process-wide and irreversible, which rules out doing it in the daemon.
- Each profile shows at most one escalation prompt at a time. Other keys queue in a bounded
  queue; overflow is denied.
- Waiting ceremonies are parked: they hold no lock and no request-cap slot (the transport permit
  is suspended for the wait), only their sleeping request thread (amended in P7). At most 4
  escalation waiters exist per session and 16 per profile; a ceremony beyond a cap is denied and
  audited, and other profiles are unaffected (a profile at its cap never uses up another's). A
  global bound of 1024 waiters is a safety limit on parked threads only: it is 64 times the
  profile cap, so it is reached only if 64 profiles are saturated at once and cannot be used to
  starve one profile through another (final security review L3).
- The cooldown table (default 10 minutes per denied key) holds at most 4096 keys and never evicts
  a live cooldown, so a broad `request` rule cannot push out the cooldown that a human's deny just
  set. Live cooldowns plus live escalations count against it, per profile and globally: a profile
  may hold at most 256, and when it is at that quota its new escalations are refused
  (`policy.deny`, `escalation_tracking_full`, result `busy`) until one of its entries expires
  (reviews L1 and M-e). The quota is per profile, so a hostile page behind a broad `request` rule
  can fill only its own profile's share and other profiles still escalate. The global 4096 (16
  times the quota) is a backstop that is reached only if 16 profiles are saturated at once. The
  withdrawal counter table is bounded separately and evicts its oldest entry; that only resets a
  rate-limit count.
- The budget claim happens only after origin and policy validation, and for a `request` rule only
  after approval (§9).
- A same-UID agent can drive the user's notification server (`dunstctl`, `makoctl`, or a replaced
  server) and so approve its own escalation. This cannot be prevented. Escalation integrity holds
  only for distinct-UID principals (§13, §15). In a distinct-UID deployment (root daemon)
  `notify_user` must differ from every `principal_user` and `browser_user`. In the shared-UID user
  unit the notification user is the same user by design, and the residual risk applies.

### 8.3 Registration escalation

Autonomous registration is the explicit setting `register = "allow"`; it is never obtained
through escalation. `register = "request"` is valid only where `register = "allow"` would be
valid, and invalid when the same rule has `authenticate = "deny"`.

Registration escalations are not joinable. Each registration ceremony that resolves to `request`
raises its own escalation, and a concurrent duplicate for the same `(profile, rp_id)` is denied.
Approving a registration escalation issues a one-use token that is bound to the creating ceremony;
no other waiter can claim it. It permits exactly one registration, for exactly that RP, within that
ceremony. The approval binds to that ceremony's session and is not a separate transferable
credential. It does not persist `register = allow`. On successful creation it persists
`authenticate = allow` for that exact RP with `kind = "registration"` and the new credential
reference, and that credential reference joins the pinned set for the RP (§10.1). If registration
fails after approval, nothing is persisted.

### 8.4 Granted-rules store

- **Location:** `<agents.state_dir>/granted-rules/<profile>.toml`, owned by the daemon user, mode
  0600, in a 0700 directory. `agents.state_dir` defaults to `$XDG_STATE_HOME/passless/agent` in the
  user unit and to `/var/lib/passless-agent` (systemd `StateDirectory=`) in the system unit. The
  daemon never writes the operator's config file.
- **Entry:** `rp_id` (exact), `action` (`authenticate`), `kind` (`escalation` or
  `registration`), `granted_at`, approving `request_id`, origin at request time, and the
  permitting config rule (`exact` or `*`).
- **Write:** temporary file, fsync, rename, fsync directory. A failed write fails the approval and
  the ceremony is denied. The store directory is opened once as a pinned handle (`safe_fs::Dir`:
  `openat` with `O_NOFOLLOW` below its parent, owner and mode checked on the descriptor), and the
  exclusive temporary file, the `renameat`, the fsync and the reload all go through it, so a
  symlink planted in its place is refused and a path swap cannot redirect a write (review L4). The
  state directory above it is the operator's and is resolved once.
- **Read:** loaded at startup and after every write. A malformed or wrongly owned store disables
  grants for that profile (fail closed) and is reported by `passless doctor` (`agent-admin
  profile check`). The store has its own `grants_digest`, reported next to the policy digest;
  the policy digest covers the configuration only, so a reload's no-op comparison is unaffected
  by grants (amended in P7).
- **Administration** (amended in P7): `passless agent` is the principal CLI, so the operator
  commands live under `passless agent-admin`: `grants list [--profile P]`,
  `grants revoke --profile P --rp R [--action A] --confirm` and
  `grants clear --profile P --confirm`, over the admin socket. Revocation is audited
  (`granted_rule.revoke`). Both cancel the pending escalations they cover (a revoke those of its
  RP, of any action; a clear those of the profile), so an approval in flight cannot persist the
  grant again: it is compensated and recorded as `escalation.revoked`. The cancel runs after the
  store call, so the store closes the window between them itself: an escalation captures its RP's
  revocation generation when it is raised, a revoke bumps the RP's generation and a clear the
  profile's (under the store's per-profile writer, also when nothing was stored), and the
  approval's grant write is refused if the generation moved. The authenticate approval then ends as
  `escalation.revoked`; an approved registration keeps its credential and persists no grant (§8.3). Session grants (§9) are administered with `agent-admin sessions …` and
  principal sessions with `agent-admin principals …`; their former spellings `delegation` and
  `session` remain hidden aliases for one release.
- **Lifetime:** permanent until revoked or made inert by a config change (§6.2); no TTL.
- **Epochs:** adding a grant bumps the grant epoch without invalidating active sessions, because it
  only widens authority the human just approved. Revoking a grant, reloading the configuration or
  changing the config bumps the revocation epoch and invalidates active sessions (§6.4). The
  revocation epoch is global (amended in P7): a revocation invalidates the sessions of every
  profile, not only the affected one, which errs on the safe side.
- **Locking** (amended in P7): `cmd/passless/src/agent/LOCKING.md` is normative where it differs
  from the plan's D3. The escalation mutex is a leaf, the store's per-profile write lock ranks
  below the policy locks and its loaded view is a leaf, and no wait holds a lock. D3's
  `bump_generation_additive` is `bump_grant_epoch`.
- **Cap:** `max_granted_rules` per profile, default 64; above it requests are denied.

In shared-UID deployments the agent can write this file as it can write the config; that is inside
the shared-UID trust boundary (§13). In distinct-UID deployments it must not be writable by the
principal.

## 9. Sessions and replay

The normative model is a bearer session, not a per-operation state machine.

- **Binding.** Profile, identity mode, principal digest, browser lease, revocation epoch at
  creation, TTL and `max_operations` (recommended 10 minutes and 16; the daemon enforces
  configured maxima).
- **Self-issued.** A principal obtains its session itself within policy. This is the `allow`
  model, not a bypass; the `AdminAuthority` seal is cosmetic. Session (grant) request and approval
  are audited.
- **Order of checks.** Authenticate the bearer; validate origin and RP; resolve policy. For `allow`:
  check the replay key, claim budget, reserve audit. For `request`: check the cooldown, the grant
  cap, the notification bus and the queue; check the replay key; wait for the decision; claim
  budget only after approval; reserve audit. Then re-check the revocation epoch, re-resolve the rule
  against the live configuration and grants, and use the key. A rejected request never consumes
  budget. The bearer is validated against the revocation epoch on every request.
- **Replay key.** `SHA-256(action ‖ rp_id ‖ origin ‖ top_origin ‖ challenge)`, held per session
  until expiry (`top_origin` is null on the proxy path, §11). An identical key never causes a second
  signature or credential creation. While the first request is in flight, a duplicate joins it and
  waits until the ceremony's deadline; a duplicate's abort detaches only that duplicate. After
  completion the duplicate receives the original result for 120 seconds, in the same session only.
  Any other repeat is rejected. Failures consume the key. This accommodates relying parties that
  resubmit an identical request (Kanidm).
- **Bounded table.** Entries live for the session, so the table is capped at 8192 keys (twice the
  largest `max_operations`, 4096, because every signed key claims budget). When a fresh key finds
  it full, the daemon forgets the oldest completed entries that are older than the 120 second
  outcome window and never reached key use, together with their challenges. It never forgets an
  entry that is in flight, inside the outcome window, or that used a key, so a request that was
  signed once is never signed again, however long the session lives. If nothing can be forgotten
  the request is refused with `busy` and recommended action `retry_with_backoff`, audited as
  `policy.deny` with reason `replay_table_full` (result `busy`). It consumes no budget and does
  not consume its replay key (review M2). Without the cap an allowed RP with no matching
  credential left one permanent entry per fresh challenge.
- **Revocation.** Browser exit, lease revocation, principal death, TTL expiry, config reload and
  grant revocation revoke both sign and registration bearers. Registration authority on the
  extension path is the session bearer itself; there is no separate registration grant (§10.3).
  A registration escalation binds to the waiting ceremony's session.
- **In flight.** An operation whose session or generation is no longer valid fails before key
  use. An additive grant (§8.4) does not count as a change.

## 10. Credential selection and registration

### 10.1 Selection

Discovery and selection happen inside the daemon; the page and agent never receive an
unrestricted listing.

1. `credential:<ref>` and `credential_refs` narrow the candidate set first.
2. A non-empty `allowCredentials` chooses within that pinned set.
3. If exactly one permitted credential remains, use it.
4. Otherwise apply `credential_selection`: `single` (default; exactly one candidate),
   `first-matching` (stable order by credential ID), `newest`, or `credential:<ref>`.
5. With no applicable policy, fail with a selection error rather than pick an arbitrary account.

Precedence of the selector is exact-rule override, then wildcard rule (always `single`), then
profile default.

### 10.2 Operation service

The extension calls one daemon operation service with authentication and registration methods.
After the checks of §9 it resolves the mode-selected backend and credential scope; enforces RP
options, `credProtect`, backend capabilities and algorithms; acquires the backend operation lock;
signs or generates through the backend key provider; updates storage and counters atomically where
possible; finalizes audit; and returns a WebAuthn response or a specific DOMException. A
per-credential lock spans read-sign-update so the human and agent paths cannot race a counter.

Authentication honors `allowCredentials`, discoverable credentials, user handles, counters,
`credProtect`, supported extensions and the backend's real key provider. The daemon builds the
`clientDataJSON` of type `webauthn.get` as it does for registration (§11). The proxy's
`remoteDesktopClientOverride` entry in the request extensions is supplied by the browser (§11) and
is not an unsupported extension.

### 10.3 Registration

Registration targets the mode's backend: `same-user` writes to the human backend, `isolated` to the
profile backend. It is denied unless the exact rule says `allow` (or an escalation approves it,
§8.3). The daemon:

- honors `pubKeyCredParams` in RP order, `excludeCredentials` (a match rejects), user-verification
  and authenticator-selection constraints it can represent;
- generates the key through `CredentialKeyProvider::generate()` (TPM keys are generated and
  sealed in one step) and a random credential ID;
- builds `authenticatorData` with attested credential data and `clientDataJSON` of type
  `webauthn.create`, from the validated request (§11), with attestation format `none`;
- writes the credential before returning.

Unsupported requirements (enterprise attestation, extensions, a `platform` authenticator
attachment, no common algorithm) return `NotSupportedError` before storage mutation instead of
being dropped. `authenticatorSelection.residentKey` and `requireResidentKey` are type-checked and
then accepted at every value, because every agent credential is discoverable and so satisfies all
of them.

**Authority.** Same-user `register = "allow"` requires only an exact RP rule plus the profile
listed in `acknowledge_same_user_registration`. Passless has no operator-minted, one-shot
enrollment grant and no CLI to mint one. A human-approved single registration is
`register = "request"` through the notification (§8.3). Registration authority on the extension
path is the session bearer (§9).

## 11. Browser extension contract

Interception uses `chrome.webAuthenticationProxy` (§4.4); the MAIN-world override of
`navigator.credentials` is removed. The facts below were verified on Chromium 156 and Chrome for
Testing 156, each headed and with `--headless=new`
([results](../../tests/agent-e2e/spikes/RESULTS-proxy.md)). The extension must:

- attach the proxy on every worker start and register its event listeners synchronously at the top
  level of the worker, so that a request wakes a stopped worker;
- forward `onCreateRequest` and `onGetRequest` to the daemon with the request details verbatim, and
  complete them with the daemon's output verbatim; it never constructs or edits `clientDataJSON` or
  any other part of a response;
- answer every `onIsUvpaaRequest` with `false`, because an unanswered request hangs the page;
- treat `onRequestCanceled` as an abort, propagating it to the daemon, which cancels any pending
  escalation wait for that ceremony; honor the RP timeout and browser shutdown;
- keep the daemon bearer in the service worker; it is never visible to page JavaScript (a CDP
  client is another matter: see "Who can forge it" below);
- return correct DOMException names (the page receives the name given to `complete*Request`);
- track in-flight requests by the browser-supplied request ID (the event carries no tab or frame
  identifier), record the pending request IDs in `chrome.storage.session`, and fail them with
  `NotAllowedError` when the worker restarts;
- never fall back to native WebAuthn for a request routed to the daemon (§7);
- never call `chrome.runtime.reload()`: an unloaded extension sends requests to the native path
  (§7).

**Origin.** The origin comes only from the browser-supplied
`extensions.remoteDesktopClientOverride.origin` inside `requestDetailsJson`. A page cannot forge it
(verified: the browser overwrites a page-supplied value, also from a cross-origin frame).
`sameOriginWithAncestors` comes from the same object. The worker may copy both out of the request
details unmodified, but the daemon re-parses the request details itself and does not rely on a
worker-extracted copy. The top origin is not available on this path,
so the audit records `top_origin = null` together with `cross_origin` (§12). A request with
`sameOriginWithAncestors = false` is denied: cross-origin frames fail closed. The daemon treats
`remoteDesktopClientOverride` as browser metadata, not as an RP-supplied extension.

**Who can forge it.** A page cannot; a CDP client that reaches the extension's worker can (it can
evaluate code there and call the sign transport with any request details). In pipe mode the daemon
filters CDP so that the agent cannot reach the worker or any other extension or browser-internal
page (§4.3): it allows only flat sessions, ties every session to its target and re-checks that
target before each command on it, and forwards only the request it checked. The filter is the
boundary here, so it fails closed: an unknown session, an unanswered lookup, an unparsable message
or a full tracking table is a refusal. In port mode it cannot, so there the origin report is only as trustworthy as the CDP
client, and it is the daemon's own checks that hold: the origin is validated against the RP ID,
the rules, the budget and the replay key apply, and a proxy the client detaches leaves only the
contained native path (§7). A forged origin therefore gives no more than the agent could obtain by
navigating the browser to that origin, which CDP already allows.

**`clientDataJSON`.** Chrome does not validate the `clientDataJSON` the extension returns (verified:
a wrong origin, a wrong challenge and an absent value were all handed to the page). The daemon alone
builds it (type, challenge, origin, `crossOrigin`) from the validated request and signs over its
hash. The extension forwards the result verbatim and never constructs or edits it.

**RP ID.** Chrome validates the RP ID against the origin, and enforces the iframe Permissions
Policy, before the event fires. The daemon still performs its own origin and RP ID check as defence
in depth; related-origin requests can carry an RP ID that is not a suffix of the origin, so the daemon
does not rely on a suffix rule being enforced by the browser. Explicit ports are valid (§14).

**Conditional mediation and UVPAA.** While the proxy is attached,
`PublicKeyCredential.isConditionalMediationAvailable()` returns false and a conditional `get()` is
rejected with `NotAllowedError`. Passkey autofill UI is therefore not supported for agents. Pages
that call `isUserVerifyingPlatformAuthenticatorAvailable()` or `getClientCapabilities()` trigger
`onIsUvpaaRequest`; the extension answers `false`.

**Worker lifecycle.** The attachment is browser-side state and persists across service-worker
stops. A request arriving while the worker is stopped wakes it and is delivered; it does not go
native. `attach()` on every start is idempotent.

**Known limitation: focus.** Chrome rejects `create()` from a tab that does not have focus with
`NotAllowedError`, even after the extension has completed the request. A registration can therefore
complete in the daemon while the page receives `NotAllowedError`, leaving an orphan credential in the
isolated profile's store. The audit records the registration, and the operator can delete the
credential. The adapters are stdio launchers and never drive a page, so they cannot raise a tab: the
guidance tells the agent to bring the page to the front before `create()`, and an adapter that does it
itself (a CDP client or a tool-level option) is future work outside this ADR. `get()` is not affected.

## 12. Audit

Audit is mandatory. The daemon durably appends and fsyncs a reservation before any credential
creation or use; failure blocks key use, and a terminal record follows every reservation.

Storage is outside the principal boundary (in distinct-UID deployments), owner-only,
append-oriented and hash-chained. A terminal write failure puts agent support into a degraded
state until an administrator repairs it; the human path stays available. Records never contain
private keys, PINs, capabilities, bearers, cookies, tokens, raw assertions, client-data hashes,
credential records or browser profile contents.

Each operation record carries at least: session ID hash and request or escalation ID; profile,
mode, principal relationship and the real revocation and grant epochs; action, RP ID, origin, top
origin (null on the proxy path) and cross-origin flag; matched rule (`exact` or `*`; `rp_id` names an
exact rule's RP) and the grant source (`config`, or `granted` when a granted rule upgraded a `request`);
decision and evidence source (`agent` or absent); credential reference and selection rule; backend
and key-provider type; counter before and after; terminal result and failure class.

Implementation (P8, schema version 3). The operation records are `policy.allow` (the reservation),
`policy.deny` and `policy.replay_served` (refusals and served duplicates, which hold no
reservation) and `operation.terminal`. They all carry the same keys, always present and null when
they do not apply yet: `session_id_hash`, `request_id`, `escalation_id`, `profile_id`, `mode`,
`principal_relationship`, `revocation_epoch`, `grant_epoch`, `action`, `rp_id`, `origin`,
`top_origin`, `cross_origin`, `rule`, `grant_source`, `decision`, `evidence_source`,
`credential_ref`, `selection_rule`, `backend`, `key_provider`, `counter_before`, `counter_after`,
`result` and `failure_class`. A reservation and its terminal record share `request_id`. Exactly one
`operation.terminal` follows every `policy.allow`, on every exit path: the ceremony's single exit
point writes it, and a drop guard writes it (`failure_class = abandoned`) if the ceremony unwinds.
After the reservation a failure is the terminal record's `failure_class`, not a second
`policy.deny`. `result` is `success`, `replay_served`, `denied`, `aborted`, `revoked`, `timeout`,
`busy` or `error`. The test list `SECTION_12_OPERATION_FIELDS` in `audit_events.rs` is the
canonical field list that the record types are tested against.

**Coalesced refusals** (final security review M2). Every record is fsynced, and a page can loop a
refused request, so refusals are coalesced per `(session, RP ID, action, reason)` rather than
written one for one. The first 16 of a key in a 60 second window are written in full, as above.
Later ones are counted, not written. The count is written as one `policy.deny` summary whose
`suppressed` field is the number of refusals it stands for (the field is present on every
`policy.deny` and `policy.replay_served` record, null on all but a summary):

- when the window has ended and the key is refused again (the next window then starts with 16 full
  records again);
- when the pending count reaches 1024, inside the window;
- when the session is revoked, and, at the latest, when it is dropped (a clean daemon exit).

A summary is a `policy.deny` record with the same operation fields as the refusals it summarizes
(`request_id` and the epochs are those of the latest one), `origin`, `top_origin` and
`cross_origin` null (a summary may span several origins), and the same `reason` and `result`. A
session tracks at most 64 keys; refusals beyond that share one overflow key per `(action,
reason)`, whose summary names `rp_id = "unknown"`, so rotating RP IDs does not defeat the bound.
No refusal is lost: it is either a record or part of a `suppressed` count. The one gap is a daemon
killed while a count is pending (fewer than 1024 refusals per key). A served duplicate
(`policy.replay_served`) keeps its own cap of 16 per replay key and is not a refusal. A late use
of a revoked bearer is a refusal of that bearer's session and is coalesced the same way. A revoked
session's ledger is flushed when it is revoked, but the tombstone keeps the session alive to audit
later use, so refusals counted after that flush are written by a sweep: the runtime loop writes the
pending count of every tombstoned session about once a second, once the key's window (60 seconds)
has ended, without needing another refusal (review L5). The residual is a daemon killed within
that window plus one sweep interval of such a refusal; a bearer's tombstone that is evicted from
the ring, or a clean exit, writes its count as well. The refusal ledger's lock is a leaf below the
audit gate (`LOCKING.md`).

Exceptions and recovery:

- **A killed daemon.** A daemon exit or SIGKILL between a reservation and its terminal record
  leaves an open reservation. At the next start, before the new run writes anything, the daemon
  scans the newest two audit segments for `policy.allow` records without an `operation.terminal`
  of the same `request_id` and closes each with one (`result = error`, `failure_class =
  abandoned`, the reservation's fields copied). An orphan in an older segment is not recovered; it
  stays visible as a reservation without a terminal record.
- **A durable but unacknowledged reservation.** If the frame is written and fsynced but the
  directory fsync or the anchor update then fails, the gate reports `DurableUnacknowledged` and
  breaks its circuit. Key use is blocked, the ceremony still owes (and attempts) its terminal
  record, which the broken circuit will normally refuse, and the next start's recovery closes the
  reservation. A write that failed before the frame was synced is not a reservation.
- **A duplicate whose own deadline passes** while it waits for the identical in-flight request is
  a refusal: `policy.deny` with `failure_class = join_timeout` (`result = timeout`).
- **Transport-level busy refusals** (the global, per-profile and per-session request caps) are answered before any ceremony
  exists and write no operation record; they are not audited.

Also recorded: session (grant) request and approval with profile, principal, RP scope and TTL;
escalations as `requested`, `approved`, `denied`, `expired` and `revoked`; and browser-lease
creation, expiry, revocation, exit and cleanup. An escalation that ends by timeout or by abort is
recorded as `expired` with `reason = timeout` or `reason = aborted`. An escalation whose notification
server went away while the prompt was shown is `expired` with `reason = server_lost` (no cooldown,
but it counts toward the V-M2 withdrawal limit). `revoked` is used only when policy changes under a
pending escalation, with `reason = policy_reload` (a configuration reload, or revoking or clearing
granted rules); it is never written for a timeout or an abort.

## 13. Deployment axes and hardening scope

Two independent axes:

- `mode` (configured): `same-user` uses the human backend; `isolated` uses a profile backend.
- Principal relationship (derived from the principal UID vs the daemon UID): **shared-UID** or
  **distinct-UID**.

| | shared-UID | distinct-UID |
|---|---|---|
| `same-user` | The agent is fully the user. No process boundary. Hardening below is not required. | The agent uses human passkeys only through the daemon. A Unix boundary protects the backend, config and granted-rules store. Hardening applies. |
| `isolated` | Separate passkeys, but the agent can read the human store as the same UID; separation is administrative only. Startup warns. | Full isolation, the recommended strong mode. Hardening applies. |

`passless doctor` and every audit record report both axes.

**Shared-UID.** Linux has no kernel boundary between same-UID processes: a same-UID browser or agent
can ptrace the daemon, read its memory and descriptors, and reach the sign socket. Passless does not
attempt OS isolation here; the boundary is policy, session limits and audit, like ssh-agent or
gpg-agent. Omitting `PR_SET_NO_NEW_PRIVS` in the same-UID port-mode spawn is intentional (it would
break Chromium's sandbox helper). Spawn hygiene is reliability, not security: the same-UID spawn
marks inherited daemon descriptors close-on-exec and sets `PR_SET_PDEATHSIG` from the long-lived
launcher thread, so the browser dies with the daemon and not with the request that launched it;
rlimits are optional. The user unit's
`systemd-analyze security` score is accepted. Namespace and seccomp work does not apply. The
human/agent boundary still applies, so escalation integrity (§8.2) is in scope, with one residual
risk: a same-UID agent can drive the user's notification server and approve its own escalation
(§8.2, §15). Escalation integrity holds only for distinct-UID principals. In the same-UID port-mode
spawn the browser has the daemon's UID, so the containment of §7 (private `/dev`) is required
whenever that UID can open a hidraw node.

**Distinct-UID.** The root system unit (`passless-agent.service`) needs root continuously for
cross-user `setuid`/`setgid` spawns. It never changes its own credentials to reach a user's
notification bus: it uses the privilege-dropping child of §8.2, and `notify_user` differs from every
`principal_user` and `browser_user`. The containment of §7 is not required when the browser user
cannot open any hidraw node, but is still applied when `bwrap` is available; `passless doctor`
reports which case applies.
A browser that runs as another user gets resource limits Chromium can live with (no
address-space limit, 4096 processes for that user, 8192 descriptors, no core dumps); the
principal's tighter defaults would stop Chromium from starting.
The distinct-UID and root-daemon paths (`notify_user`, the prompt child, the `browser_user` gates,
the cross-user rlimits, the `bwrap` path checks) are verified at unit level (`deployment.rs`,
`doctor.rs` and `runtime.rs` tests), because the E2E harness runs the daemon and its principals as
the invoking user and cannot create a second user without root; real-browser E2E covers the
shared-UID case.

- *Systemd baseline (enabled):* `ProtectHostname`, `ProtectClock`, `ProtectKernelLogs`,
  `LockPersonality`, `RestrictRealtime`, plus `ProtectKernelTunables`, `ProtectControlGroups`,
  `ProtectKernelModules`, `RestrictSUIDSGID`. Deliberately kept: `NoNewPrivileges=false`
  (child setuid).
- *To evaluate against managed Chromium:* `PrivateDevices` (the original reason for
  `PrivateDevices=false`, per-profile hidraw nodes, no longer exists; browser device needs such as
  GPU and `/dev/dri` must be checked first, and the daemon still needs `/dev/uhid` for the human
  authenticator), `RestrictAddressFamilies`, `RestrictNamespaces`, `ProtectProc`/`ProcSubset`,
  `MemoryDenyWriteExecute`; `CapabilityBoundingSet` and `SystemCallFilter` after a privilege and
  syscall inventory.
- *Namespaces:* mount namespace first, with a bind-mount allowlist (profile and runtime
  directories, display sockets, fonts, themes); PID namespace as a stretch goal; network
  namespace only in pipe mode, since port mode needs shared loopback.
- *seccomp:* principal process first (deny-list such as ptrace, mount, bpf, init_module,
  kexec_load, perf_event_open); the browser process later, after per-version syscall profiling.
  Renderer and GPU seccomp remain Chromium's.

## 14. Security invariants

1. Agent support is disabled by default.
2. Every profile has exactly one identity mode.
3. Same-user mode uses the existing human backend handle; it never reopens the human storage path.
4. Isolated mode cannot obtain the human backend handle.
5. Storage, key provider, verification provider and operation lock are selected as one backend
   unit.
6. The extension, page and agent never receive private keys, PINs, backend handles or arbitrary
   signing APIs. The sign transport is not one: every request on it is validated (origin against
   RP ID, rules, budget, replay) whoever presents the bearer. In pipe mode the agent cannot reach
   the extension worker (§4.3); in port mode it can (§11, §15).
7. No agent ceremony involves human interaction or native WebAuthn fallback.
8. UP and UV are set only from validated agent-session evidence under an `allow` decision.
9. Every operation resolves through exactly one rule. Exact rules beat granted rules, which beat
   wildcard rules.
10. Only an explicit `request` rule can escalate. `deny` and unlisted RPs never prompt.
11. Escalations are approved only through the verified notification sender, never by the agent,
    extension, page, API or automatic interaction mode.
12. Granted rules are exact-RP, additive only, persisted atomically, included in the digest, and
    revocable.
13. The revocation epoch and the resolved rule, against the live configuration and grants, are
    re-checked immediately before key use.
14. Replay keys bind action, RP, origin context and challenge, and are consumed on every result.
15. Credential protection and backend requirements may strengthen, but never weaken, the
    configured evidence requirement.
16. Every credential creation or use has a durable pre-execution audit reservation.
17. Signature counters and credential updates use the selected backend's shared operation lock.
18. Policy reload, revocation, expiry, principal death and browser shutdown invalidate outstanding
    authority. An additive grant is not a policy change.
19. Same-user registration writes only to the human backend and only under an explicit exact-RP
    registration rule.
20. Isolated registration writes only to its profile backend.
21. Origin and RP validation follow WebAuthn rules; explicit ports are not rejected merely for
    being present in a valid origin.
22. Unsupported algorithms, attestation, extensions, iframe contexts or authenticator-selection
    requirements fail closed.
23. Agent failure cannot disable or weaken the ordinary human authenticator path.
24. Agents have no CTAP/UHID transport; the extension path is the only agent transport.
25. The managed browser never reaches the human authenticator: a request the extension does not
    handle fails closed instead of reaching the native path, and the browser has either a private
    `/dev` without `hidraw*` and `uhid` or a UID that cannot open any hidraw node.

Invariants 1–6 and 15–23 were ADR 0007 §10 items 1–6 and 15–23; 7–14 replace its items 7–14;
24 and 25 are new.

**Invariant 23 and panics.** Same-user ceremonies hold the human operation lock and the shared
credential storage for their key-use section (LOCKING.md rule 4). Release builds keep
`panic = "abort"`, so a panic anywhere in the daemon ends the process, human path included. The
invariant therefore rests on two measures. The agent code that runs under the shared locks is
panic-free: it returns errors instead of calling `expect` or `unwrap` (credential IDs come from
`getrandom(2)` through a fallible call, CBOR encoding and the audit gate's state locks fail as
errors, the TPM nonce length is checked). And the human path recovers a poisoned operation,
storage or PIN storage lock instead of failing every later command, which is what makes an
unwinding agent panic harmless in debug and test builds and in any future unwind build
(`an_agent_panic_under_the_shared_locks_leaves_the_human_path_working`). Switching release
builds to `panic = "unwind"` with `catch_unwind` around ceremonies was considered and not
adopted: a panic is a bug that should stay loud, the human path cannot use `catch_unwind`
itself, and recovered locks are sound without it. The soundness of a recovered lock rests on the
backends writing a credential atomically: `local` and `tpm` rename a complete temporary file, and
`pass` has GnuPG encrypt to a temporary file in the same directory that is fsynced and renamed over
the target (GnuPG's own `--output <target>` truncates in place and is not used on the target), so
a panic leaves either the previous file or the complete new one. The `local` backend has no
credential cache; `pass` and `tpm` cache decrypted credentials for a bounded time, so a panic after
a write can leave a stale cached copy until it expires. The TPM context lock and the `pass`
Git-sync lock are recovered the same way (the TPM recovery also flushes transient objects the
unwound call left loaded), and a one-call Git-sync operation ends from a drop guard, so a panic
cannot stop Git sync. The residual is a panic inside a dependency
(`soft_fido2`, `serde_json`, `ciborium`), which still ends the daemon until systemd restarts it;
it is an availability failure, never a weakened check, and startup recovery closes any open audit
reservation (§12).

## 15. Threats and residual risk

| Threat | Mitigation | Residual |
|---|---|---|
| Compromised same-user agent acts as the human | Explicit mode, exact rules, short sessions, budgets, selectors, audit | Allowed by design within policy |
| Isolated agent reaches human credentials | Separate backend handle, no shared paths | Host root or daemon compromise; shared-UID deployments |
| Malicious page drives the agent to request many RPs | Only `request` rules escalate; one prompt per profile; bounded queue; cooldown; grant cap | Prompt fatigue can still widen policy permanently |
| Notification click-jacking or spoofed approval | Verified D-Bus sender; daemon-derived text only | A same-UID agent can drive the user's notification server (`dunstctl`, `makoctl`, a replaced server) and approve its own prompt; integrity holds only for distinct-UID principals |
| Agent tampers with granted rules or config | Daemon-owned store, owner/mode checks, digest | Shared-UID agents can tamper |
| Supervised policy silently auto-approved | No `confirm`; no native fallback; automatic mode excluded; agents refuse to start under automatic mode with `allow` or `request` rules unless acknowledged | None on the agent path |
| Browser request reaches the human authenticator (unloaded extension, unattached worker, context without the extension) | Proxy interception; launch fails closed; private `/dev` without hidraw, or a UID that cannot open it (§7) | A hidraw node that appears after launch, where containment is not applied |
| Page replays a request | Replay key per session, consumed on every result | A new valid request is authorized by `allow` |
| Page burns the operation budget | Budget claimed after origin and policy validation | — |
| Local process calls the sign socket | Bearer, short TTL, profile binding, origin/RP/policy checks | Inside the boundary for shared-UID |
| RP-requested UV is fabricated | UV only from validated agent evidence | RP cannot distinguish agent from human UV |
| Wildcard or ambiguity picks the wrong account | Pinning before `allowCredentials`; forced `single` under `*` | `first-matching` is deliberately less specific |
| Counter races corrupt human credentials | Shared handle and operation lock | Backend-specific crash consistency |
| Agent ceremony panics while holding the human locks | Panic-free agent code under the shared locks; the human path recovers poisoned operation, storage and PIN locks (§14, invariant 23) | Release builds abort: a panic in a dependency restarts the daemon (systemd `Restart=on-failure`) |
| Same-user ceremonies delay the human path | The operation lock is held only for the bounded key-use section, never across a wait on a human, an escalation or the browser | A same-user sign holds the human operation lock while it reads the target RP's credentials (selection, reservation, key use); credentials of other RPs are never read, and a registration reads only the IDs in its exclude list. With the `pass` backend that decrypts each of the RP's own credentials, so an RP with many passkeys makes each ceremony slower and a human request waits behind it; pinning does not skip the read. A latency residual, not a confidentiality one; `isolated` profiles have their own lock and store (`docs/agents/same-user.md`) |
| Page floods the audit log or the replay table | Refusal records are coalesced per session, RP, action and reason with a `suppressed` count (§12); the replay table is capped and refuses with `busy` rather than evicting an entry that protects "never sign twice" (§9) | A page can fill its own session's replay table for 120 seconds, so that session's new requests get `busy` until old entries leave the outcome window; other sessions are unaffected |
| Extension reports a false origin | Origin taken only from the browser-supplied `remoteDesktopClientOverride`, which a page cannot forge; the daemon builds `clientDataJSON`; cross-origin frames fail closed | Browser and extension are in the TCB; the top origin is not available |
| Agent drives the extension worker over CDP (reads the bearer, forges the origin, detaches the proxy) | Pipe mode: `browser-control` allows only flat sessions, maps each session to its target and looks the target up before every command on it, refuses attaching to, messaging, closing or inspecting extension targets, hides them from target lists and auto-attach, hides and refuses browser-internal targets (browser UI, `devtools://` and `chrome://` pages), refuses `Target.openDevTools`, `setRemoteLocations` and `Browser.executeBrowserCommand`, refuses extension and browser-internal URLs (`about:` aliases and nested JSON included), and forwards only the request it checked, re-serialized (§4.3); in both modes the daemon validates the origin against the RP ID, rules, budget and replay, and containment covers a detached proxy | Port mode: unfiltered, so the origin report is as trustworthy as the CDP client (§7, §11); pipe mode: a worker paused by an auto-attach waits for the next `browser-control` call, and `file:` navigations can read the extension's files (the bearer alone does not pass the sign socket's peer-UID check of a distinct-UID browser) |
| Registration completes but the page gets `NotAllowedError` (unfocused tab) | The audit records the registration; the operator deletes the orphan credential; adapters bring the page to the front | An orphan credential can remain until deleted |
| Stale registration authority | Registration bearers revoked with the lease; escalation bound to the waiting ceremony's session | — |
| Unwanted autonomous registration | Separate rule, exact RP, acknowledgement, exclude checks, audit | A broad registration rule grants broad power |
| Port-mode CDP reached by another local user | Loopback only; pipe mode for untrusted peers | Accepted in port mode |
| Agent copies browser session material | CDP pipe mediation; short leases | Lease expiry is not RP-side revocation |
| Agent suppresses audit | Audit outside principal; durable pre-write gate | Host root can rewrite local audit |

## 16. Consequences

- **Positive:** one coherent model of autonomous ceremonies plus durable, auditable policy growth;
  the native-fallback gap is removed rather than patched; the schema shrinks; one daemon pipeline
  serves both modes and both key providers, including non-extractable TPM keys.
- **Negative:** per-ceremony human approval and human UV for agents are no longer available;
  approved escalations persist until revoked, so policy can grow through clicks; agent UP/UV is
  indistinguishable from human UP/UV at the RP; the extension adds a TCB component;
  passkey autofill (conditional mediation) is unavailable to agents while the proxy is attached;
  containment of the managed browser needs `bwrap` with unprivileged user namespaces or a UID that
  cannot open hidraw nodes; only Chromium and Chrome for Testing are supported browsers.
- **Migration:** `supervised` and `confirm` rules become `request`; existing configs keep working
  with warnings until the release after next (plan R8; §6.4).

## 17. Alternatives considered

| Alternative | Outcome |
|---|---|
| Per-ceremony human confirmation or human UP/UV, via native fallback or a supervised preset | Rejected. Unbound to the agent operation, auto-approvable, and contrary to the autonomy goal; humans act through escalation instead. |
| One human verification per agent session | Rejected; same reason. |
| `allow` without UP/UV | Rejected. Many RPs require the flags. |
| Always set UV when the RP requests it | Rejected. Flags come from validated evidence. |
| Autonomy as a third identity mode | Rejected. Credential ownership and policy are independent axes. |
| Separate implementations for `same-user` and `isolated` | Rejected. Ownership changes backend selection only. |
| Formal per-operation state machine | Dropped. The bearer session with replay key and budget is adequate once its gaps are closed. |
| Suffix or unconstrained wildcard RP rules | Rejected. Only the constrained same-user `*` exists. |
| Approving escalations through CLI, API or extension | Rejected. Operators edit config; humans approve through the notification. |
| UHID agent endpoint (former `delegated-session`), with or without modal dismissal | Rejected. Chromium's native modal cannot be dismissed headlessly. |
| Isolated UHID compatibility transport alongside the extension | Rejected. Duplicates the policy pipeline, needs a per-ceremony human prompt that contradicts autonomous-only ceremonies, and is unreachable once native fallback is removed. |
| Operator-minted one-shot enrollment grants (#411) | Replaced by `register = "request"` (human approval) and `register = "allow"` plus acknowledgement (§10.3). |
| CDP virtual authenticator with injected key | Rejected for production; test only. Leaks keys, bypasses policy, cannot use TPM keys. |
| MAIN-world override of `navigator.credentials` | Removed. `chrome.webAuthenticationProxy` replaces it: the origin is browser-supplied and the page receives a native `PublicKeyCredential` (§4.4, §11). |
| `chrome.webAuthenticationProxy` as the interception mechanism | Chosen (§4.4, §11). The request carries a browser-supplied origin and `sameOriginWithAncestors`; the page receives a native `PublicKeyCredential`. |
| `remoteDesktopClientOverride` as a way for a page or agent to set the origin | Rejected. The browser overwrites a page-supplied value; only the browser-supplied value is read (§11). |
| A Chromium switch or feature flag that disables CTAP over HID | Not available; no policy was found either (§7). Containment by a private `/dev` or a UID boundary replaces it. |
| D-Bus platform authenticator / credentialsd for agents | Rejected. Portal UI, no trusted origin binding (ADR 0013). |
| Shared CTAP endpoint classified per request | Rejected. CTAP carries no caller identity. |
| Separate daemon process for agents | Rejected. Duplicates the storage TCB and counter synchronization. |
| Copy human credentials into agent storage, or point an isolated profile at the human path | Rejected. Breaks counters, exports keys, duplicates locks. |
| Direct storage or key-provider access for trusted agents | Rejected. Mediation keeps provider support, counters, policy and audit consistent. |
| OS isolation for shared-UID deployments | Rejected. No kernel boundary exists between same-UID processes. |

**Deferred:** a daemon-mediated streaming CDP proxy mode; running the root daemon with a bounded
capability set or a small privileged helper; attestation formats beyond `none`; resumable browser
sessions; external audit checkpoints; RP-integrated session revocation; remote principals.

## 18. Code map

- Daemon agent runtime: `cmd/passless/src/agent/` (`runtime.rs`, `sign.rs`, `register.rs`,
  `policy_engine.rs`, `grant.rs`, `prompt.rs`, `audit.rs`, `audit_events.rs`, `backend.rs`,
  `browser.rs`, `launcher.rs`, `cdp_bootstrap.rs`, `cdp_filter.rs` for the pipe-mode extension
  filter).
- Granted-rules store: `cmd/passless/src/agent/granted_rules.rs`; principal identity and the
  admin authority token: `agent/identity.rs`.
- Configuration and policy digest: `passless-core/src/agent/config.rs`, `policy.rs`.
- Extension: `cmd/passless/assets/agent-extension/`; native host: `cmd/passless/src/bin/sign-proxy.rs`.
- Systemd units: `contrib/systemd/passless-agent.service`, `contrib/systemd/passless.service`.
- Removed (P6, §4.4): the MAIN-world override and its broker (`main.js`, `broker.js`).
- Removed (P3, P7, §5, §10.3): the isolated UHID route (`agent/endpoint_manager.rs`; the per-ceremony
  confirm prompt in `agent/ceremony.rs:1426-1479`; endpoint wiring in `runtime.rs`; `/dev/uhid`
  probing for agents in `launcher.rs` and `doctor.rs`, which must then cover only the human
  daemon) and operator-minted enrollment grants (`request_registration_grant` and its registry in
  `policy_engine.rs`/`grant.rs`; the `RequestRegistration` admin request in `passless-core`
  `protocol.rs` and `runtime.rs`; the CLI in `commands/agent_admin.rs`).

## 19. Implementation status

References are `file:line` at commit `130eaa5`.

| Item | Current | Target |
|---|---|---|
| Native fallback for `confirm`/human rules | **Done (P2, P6).** The daemon no longer returns `human_interaction_required` for a rule; the worker has no `fallback` flag and the page never replays natively; a request the extension does not handle fails closed (§7, §11) | — |
| Human/confirm evidence in schema | **Done (P4).** `RuleAction` (`deny`, `allow`, `request`) replaces `AgentAuthorization` and the human/agent UP and UV sources; rules carry no evidence fields; `allow` sets UP=1 and UV=1 from session evidence; `request` escalates (P7, §8) | — |
| Legacy fields and `policy` alias | **Done (P4).** The legacy evidence tables and presets map (`autonomous`/`allow+agent+agent` to `allow`, `supervised`/`confirm+*` to `request`, `deny+none+none` to `deny`) with one warning per mapped field, logged once per load and shown by `passless agent-admin profile check`; any other combination (including `allow` with human or `none` evidence) and the removed profile keys `rp_ids`, `registration_allowed`, `require_uv`, `human_verification_prompt` fail startup with a migration message. Legacy parsing is removed in the release after next (R8) | — |
| Cross-origin frames | **Done (P2, P6).** `sameOriginWithAncestors = false` from the browser-supplied override is denied and audited with `top_origin = null` (§11) | — |
| `localhost` RP | **Done in the daemon (P4).** `validate_rp_id`, `parse_origin` and the launch URL check accept `localhost` and `http://localhost[:port]` for exact rules only; resolution never matches `localhost` through the wildcard; `*.localhost` and other `http` hosts are rejected. **Done (P6)** in the extension: the origin comes from the browser-supplied override, which the daemon re-parses | — |
| `credential:<ref>` vs `allowCredentials` | **Done (P4).** `narrow_candidates` pins first (`credential:<ref>`), `allowCredentials` then chooses within the pinned set, and the wildcard always selects `single` (§10.1) | — |
| Epochs and live resolution | **Done (P5).** A revocation epoch (bumped by a reload that changes the digest; P7 bumps it on grant revocation) and a grant epoch (P7 bumps it when a grant is added; never revokes). Sessions record the revocation epoch at creation and are checked against it on every request and again immediately before key use, together with a live re-resolve (invariant 13). Reload re-reads and validates the configuration file; an invalid file or a restart-only change keeps the old generation and returns an error; an unchanged digest revokes nothing. `max_operations` is read from the live policy | — |
| Budget claim order | **Done (P5).** Origin and RP validation, session grant and principal binding, resolve, unsupported options, then replay key, then budget; rejected requests never claim budget. `request` (P7) runs the escalation pre-checks, takes the replay key without budget, and claims the budget only after approval (`AgentSession::claim_key`, `ClaimGuard::claim_budget`) | — |
| Replay | **Done (P5).** `SHA-256(action ‖ rp_id ‖ origin ‖ top_origin ‖ challenge)` with length-prefixed fields and a presence tag for `top_origin` (`session.rs`); per bearer session; a duplicate joins the in-flight request until its own deadline (an aborted duplicate detaches alone) or gets the original outcome for 120 s; a reused challenge under another key is rejected; failures consume the key | — |
| Registration bearers | **Done (P3).** Bound to the browser lease and revoked by `revoke_by_lease`; a late use is refused with `401 invalid_bearer` and audited as `policy.deny(reason=bearer_revoked)` (the first 16 per window in full, the rest as a `suppressed` count, §12) | — |
| Operator-minted enrollment grants (#411) | **Done (P3).** `RegistrationGrantRegistry`, the `RequestRegistration` admin request, its CLI and handler are removed; registration authority is the exact-RP `register = "allow"` rule, or one human-approved registration through `register = "request"` (§8.3, P7); a wildcard rule never permits registration | — |
| Isolated UHID route | **Done (P3).** `endpoint_manager.rs`, `ceremony.rs`, `ceremony_observer.rs`, `device.rs`, `interaction.rs`, the endpoint wiring in `runtime.rs`, the agent UHID doctor check and the agent udev rule are removed; a legacy `[device]` key is warned about and ignored (R6). `agent/storage.rs` (ceremony-scoped storage views) is removed too. The `passless-uhid` crate and `tools/agent-uhid-feasibility` were removed in P11: the controlled RP, the lab udev policy and the permission probes moved to `tools/agent-validation`. The principal intent protocol was removed in P7. A cleanup after P11 removed the leftovers: `passless agent endpoint-status` and the `endpoint_id` plumbing (grants, leases, the browser manifest, the profile report), the principal delegation protocol (`passless agent delegation`, the `RequestDelegation`, `ShowDelegation`, `WaitDelegation`, `CancelDelegation` and `SignAssertion` principal requests, the pending-request registry in `policy_engine.rs`), `ErrorCode::InteractionRequired` and the legacy `Capabilities` principal request with its `registration_allowed` field (`passless agent capabilities` prints the `Authority` response, which carries each RP's `authenticate` and `register` rule). The `endpoint.*` and `intent.*` audit record kinds stay readable for old logs | — |
| Principal digest at signing | **Done (P5).** The session records the principal digest; sign and registration deny `principal_mismatch` when it differs from the session grant's | — |
| Policy digest | **Done (P4, P7).** Version 5 covers every rule field, profile and rule `credential_selection`, both acknowledgements, the operation and concurrency limits, the browser fields, `max_granted_rules` and the escalation timeout and cooldown; a profile whose rules are all `deny` loads (B4). Granted rules have a separate `grants_digest` (§8.4) | — |
| Audit content | **Done (P8).** Every operation record carries the §12 fields (`OperationRecord`, schema version 3), including `top_origin = null` with `cross_origin`, the matched `rule` (`exact` or `*`) and `grant_source`, the live epochs, `backend`, `key_provider` and the counters; every reservation has exactly one `operation.terminal` record (`operation_audit.rs`). `backend` is the storage kind (`local`, `pass` or `tpm`): the human backend's kind for a same-user profile (passed from `main.rs` to the runtime), the profile's own storage for an isolated one; `daemon.start` now reports the human backend's kind too. Browser-lease records: `browser_lease.launch` is written once the lease is spawned and recorded (`audit_launch`, `runtime.rs`); every teardown goes through `close_lease_audited` (one `browser_lease.revoke` with a `reason`, then one `cleanup`), and a lease that ends on its own through `retire_dead_lease_audited` (`crash` with the exit code, or `expire`, then `cleanup`), also for an admin-launched lease that no profile tracks; a lease already gone writes nothing, so each event is audited once | — |
| Escalation audit events | **Done (P7, P8).** `escalation.requested`, `approved`, `denied`, `expired` (`reason` = `timeout`, `aborted` or `server_lost`) and `revoked` (`reason = policy_reload`), plus `granted_rule.add` and `granted_rule.revoke`; a failed `requested` write fails the ceremony. P8: every escalation record carries `origin` and `rule`, `grant.request` and `grant.approve` carry `principal`, the RP scope and the TTL, and the schema version is 3 | — |
| Interception mechanism | **Done (P6).** Worker-only extension on `chrome.webAuthenticationProxy`; no content script; `main.js` and `broker.js` removed; manifest `key` fixes the extension ID; launch waits for the worker's attached `hello` and opens the start URL only then (B2) | — |
| Origin source and `clientDataJSON` | **Done (P6).** Origin and `sameOriginWithAncestors` from `remoteDesktopClientOverride`, re-parsed by the daemon; the daemon builds `clientDataJSON` and the response JSON; the worker forwards it verbatim (§11) | — |
| Conditional mediation and UVPAA | **Done (P6).** Unavailable while attached; `onIsUvpaaRequest` answered `false`; passkey autofill unsupported (§11) | — |
| Worker lifecycle | **Done (P6).** `attach()` on every worker start; never `chrome.runtime.reload()`; readiness per bearer and degraded leases (§7, §11) | — |
| Abort | **Done (P6).** `onRequestCanceled` and a closed connection cancel the request before key use (§11) | — |
| Extension cache | **Done (P6).** In-flight requests tracked by the browser-supplied request ID (§11) | — |
| Unsupported options | **Done (P5).** Unsupported extensions, enterprise attestation and no supported algorithm return `NotSupportedError` before budget or storage; `excludeCredentials` matches return `InvalidStateError`; origin failures `SecurityError`; daemon errors carry the DOMException name and `busy` (R11 caps) maps to `NotAllowedError` | — |
| Transport | **Done (P6).** `connectNative` port, framed relay, one multiplexed connection per worker with keepalive both ways; per-browser-UID sockets and a `SO_PEERCRED` check at `hello` (§4.4) | — |
| Unfocused-tab registration | **Accepted residual: a documented limitation (P6, P11), not open work for this ADR.** Orphan credential; the audit records it and `agent-admin credential delete` removes it. The adapters are stdio launchers that start Playwright MCP or chrome-devtools-mcp and never drive a page, so they cannot raise a tab. The mitigation is guidance: `docs/agents/browser-tools.md` and the `passless-agent` skill tell the agent to bring the page to the front before `create()` | Adapters bring the page to the front (§11): future work outside this ADR, needs a CDP client in the adapter or a tool-level option |
| Escalation, granted-rules store, grants CLI | **Done (P7).** `agent/granted_rules.rs` (fail-closed load, atomic write, epochs), installed as the policy runtime's grant source; `agent-admin grants list/revoke/clear`. `agent/escalation.rs` coordinates escalations (join, per-profile prompt and FIFO of 8, cooldown, V-M2 rate limit, waiter caps); `sign.rs`/`register.rs` pre-check, take the replay key, park with no lock held, then re-resolve to a granted `allow` and claim the budget; a reload that changes the policy cancels pending escalations (§8.1) | — |
| Registration escalation | **Done (P7).** Not joinable (`escalation_busy`); the one-use `RegistrationApproval` is bound to the creating ceremony and required by its pre-key-use re-check; after the credential write `authenticate = allow` is persisted with `kind = registration` and the credential reference, which joins the configured pinned set; a failed grant write keeps the credential and is audited (§8.3) | — |
| Abort handling and in-flight tracking | **Done (P6)** for the worker: pending request IDs kept in `chrome.storage.session` and failed with `NotAllowedError` on worker restart (§11). **Done (P7):** withdrawn or aborted escalations are rate-limited, 3 per key per 10 minutes, then cooldown; an abort within 2 s of the deadline counts as a timeout (§8.1) | — |
| Escalation waiters | **Done (P7).** Parked waiters hold no lock and no request-cap slot (the transport permit is suspended); caps of 4 per session, 16 per profile and 64 in all; the wait ends at the earliest of the Chromium-clamped page timeout (3 min–20 h), `agents.escalation_timeout` and the session TTL (§8.1, §8.2) | — |
| Notification bus for a root daemon | **Done (P7).** `agents.notify_user`; a dedicated per-prompt child (`__agent-escalation-prompt`) drops privileges, connects to the user's bus, and is killed to withdraw; no bus means deny and audit (`escalation_unavailable`) (§8.2) | — |
| Granted-rules location | **Done (P7).** `agents.state_dir` with unit-specific defaults; `agents.notify_user` validated (§8.2, §8.4) | — |
| CLI naming | **Done (P7).** Granted rules under `passless agent-admin grants`; session grants under `agent-admin sessions` and principal sessions under `agent-admin principals`, with the old `delegation` and `session` names as hidden aliases for one release (§8.4) | — |
| Same-UID self-approval | **Done (P7, P11).** `agents.notify_user` is validated against every principal and browser user (P7); the residual risk is documented for operators in `docs/agents/rules.md`, `containment.md` and `security.md` (P11) next to §8.2, §13 and §15 | — |
| Supported browsers | **Done (P2, P10b):** a missing or unloadable extension is a launch error (`verify_extension_dir`, which reads the manifest and worker through the pinned directory: regular files owned by the daemon or browser user, bounded; E2E-47, and E2E-47/unloadable since P10a). `browser_select.rs` (P10b) picks the binary (`browser_command`, `agents.browser_path`, Playwright Chromium, Chrome for Testing, distro `chromium`) and refuses branded Google Chrome and `chrome-headless-shell` (by name or path, and by `--version` for branded Chrome; the headless shell prints the Chrome for Testing string) with an actionable error on the admin and principal launch paths; a distinct-UID principal only gets a root-owned binary on a path nobody else can write (V-H7); E2E-41, unit tests. P10a verified Chromium 156, Playwright Chromium (Chrome for Testing 155) and Chrome for Testing 157, headed and `--headless=new`, under the private `/dev` (Chromium's own sandbox on, extension and proxy attach, incognito seed honoured) | — |
| Incognito and CDP-created contexts | **Done (P10a).** The launcher seeds the fresh profile's `Default/Preferences` with `extensions.settings.<id>.incognito = true` for the manifest-key extension ID (`seed_incognito_access`, `browser.rs`); the worker reports `isAllowedIncognitoAccess()` in its hello; a worker that is attached but not allowed in incognito is not intercepting (`BearerReadiness::intercepting`, `transport/readiness.rs`), so the launch fails (`LaunchError::IncognitoNotAllowed`) and the bootstrap withholds the endpoint (E2E-45/cdp-context) | — |
| Native-path containment | **Done (P10a)** for the launcher: the browser runs under `bwrap --dev-bind / / --dev /dev --die-with-parent` whenever `bwrap` works for the browser's user (`ContainmentPlan`, `containment.rs`; `/dev/shm` is bound through only when a path the browser needs lives there); otherwise the child refuses to exec when `faccessat2(AT_EACCESS, R_OK \| W_OK)` finds an openable `/dev/hidraw*`, or cannot tell, after the credential drop (`LaunchError::ContainmentRefused`; the child lists `/dev` with `getdents64`); `containment::assess` reports the case. Port mode removes `DevToolsActivePort` after discovery. Review fixes: daemon writes into lease and sign-socket directories go through pinned directory handles (`safe_fs.rs`; lease and extension directories stay the daemon's, only the profile is handed over), a distinct-UID browser gets Chromium-sized rlimits, and `bwrap` must live on a path no other user can write. E2E-45, 46, 46/refused, 47 | — (`passless doctor --agents` reports the case per profile, P10b) |
| Automatic interaction mode with agents | **Done (P10a).** Agents refuse to start, and a reload is rejected, when `PASSLESS_INTERACTION_MODE=automatic` and a same-user profile has an `allow` or `request` rule, unless `agents.allow_automatic_human_path = true` (`AgentConfig::validate_human_path_interaction`); the human path stays up (E2E-44/startup-refusal) | — (`passless doctor --agents` flags it, P10b) |
| Agent browser CLI | **Done (P10b).** `passless agent browser [--json] [--env] [--wait] [--headed] [--url]` runs inside a principal session (the browser belongs to the session and closes with it; from a plain shell it explains this instead of starting a browser that would die at once). It sends `EnsureBrowser` (idempotent per session, shared per profile with `browser_scope = "profile"`), whose endpoint is already withheld until the worker attached and incognito access is confirmed (`--wait` re-checks `BrowserStatus`), and prints the loopback HTTP endpoint (`http://127.0.0.1:<port>`) or `PASSLESS_CDP_URL=...`. The default browser flag is `--headless=new` unless the profile's `browser_command` sets its own; `--headed` omits it. Needs `browser_cdp_expose = "port"` for an endpoint; in pipe mode (the default) it ensures the same session-bound browser and prints how to drive it (`passless agent browser-control`, `--json` has `endpoint = null` and `control_command`, `--env` is an error). E2E-37 (port), E2E-52 (pipe) | — |
| Pipe-mode principal browser | **Done.** `EnsureBrowser` serves both CDP modes (`runtime/browser_ensure.rs`): pipe mode returns no endpoint and `cdp_exposure = "pipe"`, with the same gates, session binding, B1 lifetime and lease audit as port mode; `browser-control` additionally refuses a degraded lease (`gates::check_control_interception`); the MCP adapters send `direct_cdp` and keep requiring port mode (§4.3). Supersedes the V-H7 "port-mode only" easy path: its binary-selection concern is covered by `resolve_browser_launch`, which both modes share. E2E-52 | — |
| MCP adapters and client config | **Done (P10b).** `passless agent mcp playwright [-- args]` runs `npx --yes @playwright/mcp --cdp-endpoint <bootstrap>`, the bootstrap bearer going in `PLAYWRIGHT_MCP_CDP_HEADERS` (never in argv), with the browser started lazily on the first discovery request (the existing authenticated loopback bootstrap); `agent mcp chrome-devtools` runs `npx --yes chrome-devtools-mcp --browserUrl <endpoint>` and ensures the browser when it starts, because puppeteer requests `<browserUrl>/json/version` at the URL's root and cannot send the bearer header (an unauthenticated lazy endpoint would let any local process start the browser). Both resolve `npx` in the caller's `PATH` and re-run themselves in a principal session; `--package` pins the npm package, `--npx` names npx. `agent playwright-mcp` stays as a hidden alias for one release. `agent mcp --print-config {claude-code,opencode,cursor,vscode}` prints a ready entry (formats checked against each client's documentation: `mcpServers` for Claude Code `.mcp.json` and Cursor `.cursor/mcp.json`, `servers` for VS Code `.vscode/mcp.json`, `mcp.servers.<name>` with a `command` array for opencode's current schema; older opencode releases keep the name directly under `mcp`). E2E-34, 35, 36 | **Done (P11)** for the docs: `docs/agents/browser-tools.md` documents Stagehand `cdpUrl` (untested), browser-use and agent-browser. Their scenarios (E2E-38, E2E-39) are local and optional and skip when the tool is absent; they have not been run |
| `passless doctor --agents` | **Done (P10b).** Host checks with no daemon: per profile the browser binary (kind, version, source, the extension's minimum Chrome) and the containment case (`containment::assess`); once the extension and native host manifest (rendered into a scratch directory and verified), the notification bus (the prompt child's bus: name owner and `actions`), the state directory (private, the daemon user's) and the automatic-interaction guard (R19). Exits 1 when a check fails. E2E-41 | — |
| Shared browser ownership (P5 review L5) | **Done (P10b).** A `browser_scope = "profile"` browser records its owner session; when the owner exits the browser closes even if other sessions are attached (the worker's bearer, grant and bearer session are the owner's), and the others launch their own on their next `EnsureBrowser`. Rebinding the worker's baked-in bearer to another principal is not possible. While the owner lives, the sessions that attach later ride on its grant (`runtime.rs`, LOCKING.md) | — |
| Isolated `browser_runtime_root` (B7) | **Done (P10b).** An isolated profile may set `browser_runtime_root` | — |
| Principal relationship | **Done (P9).** One `PrincipalRelationship` type (`deployment.rs`) derives `shared-uid` or `distinct-uid` from the principal UID against the daemon UID; audit records (`principal_relationship`, next to `mode`) and `passless doctor` (`deployment_axes` check per profile) use it. The shared-UID `isolated` warning is a passing `isolated_shared_uid` doctor check and a `warn` log line at daemon start. A shared-UID principal is no longer a fatal start-up check: only a root principal is (`principal_not_root`). The distinct-UID column, the root-daemon paths (`notify_user`, the prompt child, the `browser_user` gates, the cross-user rlimits, the `bwrap` path checks) and the no-warning cells are verified at unit level (`deployment.rs`, `doctor.rs`, `runtime.rs` tests; E2E-33 covers the shared-UID column), because the harness cannot create a second user without root | — |
| User guides | **Done (P11).** `docs/agents/` is rewritten around the easy path (`quick-start.md`, `browser-tools.md`, `rules.md`, `containment.md`, `migration.md`), `docs/AGENT_REGISTRATION*.md`, `docs/PERMISSIONS.md` and `docs/security/FURTHER_ANALYSIS.md` (a status per item) match the code, and the bundled `passless-agent` skill is rewritten around `agent mcp playwright`. The legacy rule vocabulary appears only in `docs/agents/migration.md` | — |
| Backend separation | **Done (before ADR 0014).** `CredentialBackendHandle`, `CredentialNamespace` (`backend.rs:18-73`) | — |
| Audit before key use | **Done (before ADR 0014).** Fsynced, hash-chained append (`audit.rs:163-164`, `audit.rs:1258`); allow record gates signing (`sign.rs:1516`) | — |
| `credProtect` | **Done (P5; levels corrected in the verification gate).** `cred_protect::satisfied` (`cmd/passless/src/agent/cred_protect.rs`) is evaluated in the sign path after the credential is read and before key use: level 3 needs UV, level 2 needs UV unless `allowCredentials` names the credential, level 1 and no level need none, an unknown level is treated as 3. Agent evidence is UV = true under `allow`, so every level is satisfied on the agent path and only the operator's choice of `allow` satisfies level 3 (§7); the check keeps that true if evidence ever carried no UV (invariant 15). Before the gate only level 3 was checked. Unit tests cover levels 1 to 3 with and without `allowCredentials`. Agent registration creates credentials without a `credProtect` level (the extension is not offered, §10.3), so the check protects credentials created elsewhere that a same-user profile can read | — |
| Agents off by default | **Done (before ADR 0014).** `AgentConfig.enabled` defaults to false (`config.rs:989`) | — |
| D-Bus sender validation | **Done (before ADR 0014; P7).** zbus match on server unique name, others rejected; since P7 in the prompt child (`escalation_prompt.rs`) | — |
| Session (grant) audit events | **Done (before ADR 0014).** Request and approve recorded (`grant.rs:571`, `grant.rs:639`) | — |
| Shared-UID spawn hygiene | **Done.** Inherited descriptors marked close-on-exec and `PR_SET_PDEATHSIG` armed after any credential drop, with a parent re-check (`HardenedChildSetup::apply`, `launcher.rs`); browsers forked on the long-lived launcher thread (`spawn_on_launcher_thread`), so a `browser_scope = "session"` browser no longer dies with the IPC thread that launched it (defect B1, P10a; E2E-46/session-scope) | — |
| Distinct-UID systemd baseline | **Done** for the baseline directives (the "additive controls" block of `contrib/systemd/passless-agent.service`, asserted by `cmd/passless/tests/systemd_unit_baseline.rs`). **Accepted residual, not open work for this ADR:** every directive §13 lists as to evaluate (`PrivateDevices`, `RestrictAddressFamilies`, `RestrictNamespaces`, `ProtectProc`/`ProcSubset`, `MemoryDenyWriteExecute`, `CapabilityBoundingSet`, `SystemCallFilter`); none is enabled, and `PrivateDevices=false` is set explicitly | Evaluated directives including `PrivateDevices`, namespaces, seccomp and the rest of that list (§13): open backlog in `docs/security/FURTHER_ANALYSIS.md` (C-2, H-2, H-3); a hardening backlog for the root multi-principal unit, not a blocker for the agent path |

## 20. History

This ADR consolidates the records below. Each was removed in the commit that introduced this
file; `130eaa5` is the last commit containing all of them (`git show 130eaa5:docs/decisions/<file>`).

| ADR | Title | Date | Decision | Last changed |
|---|---|---|---|---|
| 0001 | Configurable agent authentication policy | 2026-07-19 | Exact-RP `deny/confirm/allow` rules with human/policy evidence; `isolated` and `delegated-session` modes | `23d04ff` |
| 0002 | Native WebAuthn agent architecture | 2026-07-13 | One daemon, per-agent UHID endpoints, launcher boundary, audit gate | `0672288` |
| 0004 | Agent browser trust models and CDP exposure | 2026-07-25 | CDP pipe (default) vs loopback port; Playwright bootstrap | `620a0b7` |
| 0005 | Delegated autonomous authentication via a daemon-backed extension | 2026-08-02 | MV3 MAIN-world override plus daemon signing replaces UHID delegation | `0672288` |
| 0006 | Agent-driven passkey registration | 2026-08-03 | Extension overrides `create()`; daemon `/register` | `0672288` |
| 0007 | Unified same-user and isolated identity modes | 2026-08-06 | `same-user`/`isolated` over one backend handle and operation service | `a6facff` |
| 0008 | Same-user trust boundary and browser hardening scope | 2026-08-27 | No OS isolation between same-UID browser and daemon | `d371a21` |
| 0009 | Daemon hardening scope | 2026-08-27 | Systemd hardening for the root multi-principal unit only | `02d6a15` |
| 0010 | OS namespace isolation scope | 2026-08-27 | Namespaces for cross-user deployments, mount first | `d371a21` |
| 0011 | seccomp-BPF scope | 2026-08-27 | seccomp for cross-user deployments, principal first | `d371a21` |
| 0012 | Grant audit and notification approval integrity | 2026-08-27 | Audit grant events; verify D-Bus `ActionInvoked` sender | `d371a21` |

The agent implementation plans and verification matrices in `docs/plans/` and the
`docs/agents/delegated-session.md` migration notice were removed at the same time.

On 2026-11-11 the ADR was amended with maintainer-resolved decisions (replay coalescing, claim
order, notification bus and state directory, `localhost`, epochs, containment, supported browsers,
incognito seeding, non-joinable registration escalations, waiter caps) and with the results of the
spikes that settled the interception mechanism and the environment questions:
[proxy results](../../tests/agent-e2e/spikes/RESULTS-proxy.md) and
[environment results](../../tests/agent-e2e/spikes/RESULTS-env.md).

| PR | Change |
|---|---|
| #309 | Secure native agent authentication: UHID agent endpoints, policy, audit |
| #396 | Autonomous agent authentication through the daemon-backed extension |
| #402 | Unified `same-user` and `isolated` modes |
| #407 | Same-user catch-all (`*`) RP authentication |
| #410 | Dangerous-profile acknowledgements |
| #411 | Ephemeral (one-shot) same-user enrollment grants |
| #450 | Sign hardening: Unix-socket server, native-messaging sign-proxy, replay dedup, grant audit, D-Bus sender validation |
| #505 | Explicit automatic interaction mode for the human path |
