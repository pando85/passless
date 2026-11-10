# ADR 0014: Agent delegation

- **Status:** Accepted
- **Date:** 2026-11-10
- **Decision owners:** Passless maintainers
- **Implementation status:** Partially implemented; see [Implementation status](#19-implementation-status)
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
| Managed browser and extension | Inside the session's TCB for origin reporting; never holds keys or the daemon bearer in the page. |
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
  (it loads no extensions) are rejected at launch with an actionable error. Edge and Brave were not
  probed and are unsupported. In a distinct-UID deployment only root-owned binaries that the
  principal cannot write are accepted.
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
With `max_concurrent_sessions > 1`, `browser_cdp_port` must be 0. `browser-control` is unavailable
in port mode.

Playwright MCP uses a Passless HTTP bootstrap on an ephemeral loopback port: `GET /json/version`
authenticates an ephemeral bearer, runs the principal-scoped `EnsureBrowser` after full principal
checks, and returns Chromium's real `webSocketDebuggerUrl`. It never relays WebSocket frames. The
bearer gates lazy startup only; it does not protect Chromium's listener.

In both modes the WebAuthn ceremony is mediated by the daemon; CDP exposure decides only who holds
authenticated browser-session authority.

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

As implemented (PR #450), the worker calls `chrome.runtime.sendNativeMessage` to the native host
`rs.passless.sign_proxy` (`cmd/passless/src/bin/sign-proxy.rs`), which forwards an HTTP request
with the bearer to the daemon's Unix socket (`$XDG_RUNTIME_DIR/agent/sign/sock`, endpoints
`/sign` and `/register`).

**Required change.** Escalation waits can last minutes or hours, but MV3 bounds `sendNativeMessage`
and `fetch` by the service worker's 5-minute and 30-second limits, and the sign-proxy has a
10-second socket timeout. The extension therefore carries agent requests over a
`chrome.runtime.connectNative` port, and the daemon sends a keepalive on that port at least every
20 seconds while a request is pending.

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
  parse for one minor release with a deprecation warning: `deny` → `deny`; `autonomous` and
  `allow+agent+agent` (or the `policy` alias) → `allow`; `supervised` and `confirm+*` →
  `request`. Any other combination, including `allow` with human or `none` evidence, fails
  startup with a migration message.
- The legacy profile fields `rp_ids`, `registration_allowed`, `require_uv` and
  `human_verification_prompt` are removed; a config using them fails with a migration message.
- The policy digest covers every rule field, profile-level `credential_selection`, every
  acknowledgement, and the granted-rules store content (§8.4).
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
  means refusal).
- In a distinct-UID deployment where the browser user cannot open any hidraw node, containment is
  not required. `passless doctor` reports which case applies: required and in place, in place as
  defence in depth, not required, or refused.
- A missing or unloadable extension is a launch error, never a launch without the extension. The
  CDP endpoint is not handed out until the worker has attached the proxy, and is withheld again if
  the attachment is lost.

`PASSLESS_INTERACTION_MODE=automatic` (PR #505) affects only the human CTAP path and never approves
an escalation. Because it would let a request that reaches the native path be signed silently, the
daemon refuses to start agents when it is set and any same-user profile has an `allow` or `request`
rule, unless `agents.allow_automatic_human_path = true`. `passless doctor` flags the combination.

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
is evaluated against this evidence; agent UV satisfies level 3 only because the operator chose
`allow`.

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
   ceremony is a parked continuation in the escalation service; it holds no thread, no operation
   lock and no storage lock (§8.2). The timeout
   matches Chromium: the page's `timeout` clamped to 3 minutes–20 hours, or 20 hours when unset
   (`AdjustTimeout()` in `content/browser/webauth/authenticator_common_impl.cc`;
   `kMinRequestTimeout`/`kMaxRequestTimeout` in `device/fido/public/fido_constants.cc`). The
   optional `agents.escalation_timeout` (unset by default) sets a shorter cap. The notification
   has no expiry and is withdrawn when the ceremony ends, aborts or times out. The transport
   requirement is in §4.4.
6. On approval the daemon writes `escalation_approved`, atomically persists the granted rule,
   bumps the policy generation, then re-resolves and continues the original ceremony as `allow`.
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
- Waiting ceremonies are parked continuations that hold no thread. At most 4 escalation waiters
  exist per session and 16 per profile; a ceremony beyond either cap is denied and audited, and
  other profiles are unaffected.
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
  the ceremony is denied.
- **Read:** loaded at startup and after every write; included in the policy digest. A malformed
  or wrongly owned store disables grants for that profile (fail closed) and is reported by
  `passless doctor`.
- **Administration:** `passless agent grants list [--profile P]`,
  `passless agent grants revoke --profile P --rp R [--action A]`,
  `passless agent grants clear --profile P`. Revocation is audited. The commands that administer
  session grants (§9) are `passless agent sessions …`; their former spelling under
  `passless agent grants` remains a hidden alias for one release.
- **Lifetime:** permanent until revoked or made inert by a config change (§6.2); no TTL.
- **Epochs:** adding a grant bumps the grant epoch without invalidating active sessions, because it
  only widens authority the human just approved. Revoking a grant, reloading the configuration or
  changing the config bumps the revocation epoch and invalidates the active sessions of the affected
  profile (§6.4).
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

Unsupported requirements (resident-key, attestation, extensions) return `NotSupportedError` before
storage mutation instead of being dropped.

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
- keep the daemon bearer in the service worker; it is never visible to page JavaScript;
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
credential. Adapters bring the target page to the front before a ceremony where they can. `get()` is
not affected.

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
origin (null on the proxy path) and cross-origin flag; matched rule (`exact`, `*` or `granted`); decision and evidence source (`agent`
or absent); credential reference and selection rule; backend and key-provider type; counter before
and after; terminal result and failure class.

Also recorded: session (grant) request and approval with profile, principal, RP scope and TTL;
escalations as `requested`, `approved`, `denied`, `expired` and `revoked`; and browser-lease
creation, expiry, revocation, exit and cleanup. An escalation that ends by timeout or by abort is
recorded as `expired` with `reason = timeout` or `reason = aborted`; `revoked` is used only for
operator revocation.

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
closes inherited daemon descriptors and sets `PR_SET_PDEATHSIG`; rlimits are optional. The user unit's
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
   signing APIs.
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
| Extension reports a false origin | Origin taken only from the browser-supplied `remoteDesktopClientOverride`, which a page cannot forge; the daemon builds `clientDataJSON`; cross-origin frames fail closed | Browser and extension are in the TCB; the top origin is not available |
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
  with warnings for one minor release (§6.4).

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
  `browser.rs`, `launcher.rs`, `cdp_bootstrap.rs`).
- Configuration and policy digest: `passless-core/src/agent/config.rs`, `policy.rs`.
- Extension: `cmd/passless/assets/agent-extension/`; native host: `cmd/passless/src/bin/sign-proxy.rs`.
- Systemd units: `contrib/systemd/passless-agent.service`, `contrib/systemd/passless.service`.
- To be removed (§4.4): the MAIN-world override and its broker (`main.js`, `broker.js`).
- To be removed (§5, §10.3): the isolated UHID route (`agent/endpoint_manager.rs`; the per-ceremony
  confirm prompt in `agent/ceremony.rs:1426-1479`; endpoint wiring in `runtime.rs`; `/dev/uhid`
  probing for agents in `launcher.rs` and `doctor.rs`, which must then cover only the human
  daemon) and operator-minted enrollment grants (`request_registration_grant` and its registry in
  `policy_engine.rs`/`grant.rs`; the `RequestRegistration` admin request in `passless-core`
  `protocol.rs` and `runtime.rs`; the CLI in `commands/agent_admin.rs`).

## 19. Implementation status

References are `file:line` at commit `130eaa5`.

| Item | Current | Target |
|---|---|---|
| Native fallback for `confirm`/human rules | Daemon returns `human_interaction_required` (`sign.rs:1383-1414`); worker flags `fallback` (`worker.js:140`); page replays natively (`main.js:282`) | Planned (P2): removed (§7) |
| Human/confirm evidence in schema | `AgentAuthorization::Confirm`, human UP/UV sources (`passless-core/src/agent/config.rs:198-320`) | Planned (P4): `deny`, `allow` and `request` only (§6) |
| Legacy fields and `policy` alias | Accepted without warning (`config.rs:218`, `654-684`) | Planned (P4): warn for one release, then fail (§6.4) |
| Cross-origin frames | Accepted with any parseable top origin (`sign.rs:208`) | Planned (P2, P6): fail closed; `sameOriginWithAncestors = false` denied (§11) |
| `localhost` RP | `localhost` RP and `http://localhost` origins rejected by `validate_rp_id` and `parse_origin` | Planned (P4): valid for exact rules only, never through the wildcard (§6.1) |
| `credential:<ref>` vs `allowCredentials` | `allowCredentials` match returns before pinning (`sign.rs:1633-1642`) | Planned (P4): pin first (§10.1) |
| Epochs and live resolution | Reload replaces the session-grant registries and wipes every session (`policy_engine.rs:1086`); ceremonies use a frozen profile config; digest-based generation | Planned (P4, P5, P7): revocation and grant epochs; live resolution (§6.4, §8.4, §9) |
| Budget claim order | Claimed at `sign.rs:1080`, before origin check at `sign.rs:1256` | Planned (P5): after origin and policy; for `request`, after approval (§9) |
| Replay | Raw body hash; identical body gets a 120 s cached response (`sign.rs:298-345`) | Planned (P5): replay key; a duplicate joins the in-flight request or gets the original result for 120 s in the same session; other repeats rejected (§9) |
| Registration bearers | Not revoked with the lease (`revoke_by_lease`, `sign.rs:644-663`) | Planned (P3): revoked (§9) |
| Operator-minted enrollment grants (#411) | `request_registration_grant` with placeholder session, endpoint and zero principal digest (`policy_engine.rs:870-892`); CLI `commands/agent_admin.rs:658`, IPC `AdminRequest::RequestRegistration` (`protocol.rs:378`) | Planned (P3): removed (§10.3) |
| Isolated UHID route | Per-profile UHID endpoints (`endpoint_manager.rs`, `runtime.rs:1425`, `runtime.rs:1516`); in-daemon confirm prompt (`ceremony.rs:1426-1479`); agent UHID probing (`launcher.rs:1259`, `doctor.rs:251`) | Planned (P3): removed (§5) |
| Principal digest at signing | Not checked | Planned (P5): checked (§7) |
| Policy digest | Omits `credential_selection` and `human_verification_prompt` (`passless-core/src/agent/policy.rs:497-518`) | Planned (P4): covers all fields and grants (§6.4) |
| Audit content | No session, operation, origin, credential or result in `PolicyAllowMeta` (`audit_events.rs:659-666`); "generation" is an ID length (`runtime.rs:4079`) | Planned (P8): fields of §12, including `top_origin = null` with `cross_origin` |
| Escalation audit events | Not implemented | Planned (P8): timeout or abort recorded as `escalation_expired` with a reason; `escalation_revoked` only for operator revocation (§12) |
| Interception mechanism | Page-controlled MAIN-world override, duck-typed credential, manifest matches only `https://*/*` (`main.js`, `broker.js`, `manifest.json`) | Planned (P6): `chrome.webAuthenticationProxy` only; MAIN-world override removed (§4.4, §11) |
| Origin source and `clientDataJSON` | Origin reported by the MAIN-world script; response built by the override | Planned (P6): origin from the browser-supplied `remoteDesktopClientOverride`; the daemon builds `clientDataJSON`; the extension forwards it verbatim (§11) |
| Conditional mediation and UVPAA | Conditional requests left native and unhandled | Planned (P6): unavailable while attached; `onIsUvpaaRequest` answered `false`; passkey autofill unsupported (§11) |
| Worker lifecycle | No proxy attachment | Planned (P6): `attach()` on every worker start; never `chrome.runtime.reload()` (§11) |
| Abort | Local reject only (`main.js:320-325`) | Planned (P6): propagated to daemon (§11) |
| Extension cache | Keyed by `request_id` only (`worker.js:84-117`) | Planned (P6): in-flight requests tracked by the browser-supplied request ID (§11) |
| Unsupported options | Silently dropped | Planned (P5): `NotSupportedError` (§10.3) |
| Transport | `sendNativeMessage` (`worker.js:126`); sign-proxy 10 s socket timeout | Planned (P6): `connectNative` with keepalive (§4.4) |
| Unfocused-tab registration | Not handled | Planned (P6, P10): documented limitation (orphan credential, audit records it); adapters bring the page to the front (§11) |
| Escalation, granted-rules store, `passless agent grants` | Not implemented | Planned (P7): §8 |
| Registration escalation | Not implemented | Planned (P7): not joinable; one-use token bound to the creating ceremony; the credential reference joins the pinned set (§8.3) |
| Abort handling and in-flight tracking | Not implemented | Planned (P6, P7): withdrawn or aborted escalations rate-limited, 3 per key per 10 minutes, then cooldown (§8.1); pending request IDs kept in `chrome.storage.session` and failed with `NotAllowedError` on worker restart (§11) |
| Escalation waiters | Not implemented | Planned (P7): parked continuations holding no thread; caps of 4 per session and 16 per profile (§8.2) |
| Notification bus for a root daemon | Prompt uses the daemon's own session bus | Planned (P7): `agents.notify_user`; dedicated per-prompt privilege-dropping child; no bus means deny and audit (§8.2) |
| Granted-rules location | Not implemented | Planned (P7): `agents.state_dir` with unit-specific defaults (§8.4) |
| CLI naming | Session-grant commands use the name `grants` (`commands/agent_admin.rs`) | Planned (P7): granted rules under `passless agent grants`; session commands under `passless agent sessions` with a hidden alias for one release (§8.4) |
| Same-UID self-approval | Not documented | Planned (P11): documented residual risk; `notify_user` differs from every principal and browser user (§8.2, §13, §15) |
| Supported browsers | No detection; the launcher can start with `--disable-extensions` (`browser.rs:2040-2044`) | Planned (P2, P10): launch error without the extension; Chromium and Chrome for Testing accepted; branded Chrome and `chrome-headless-shell` rejected; root-owned binaries only in distinct-UID deployments (§4.2) |
| Incognito and CDP-created contexts | The extension is not active in them; requests go native | Planned (P10): `Default/Preferences` seeded with `incognito = true` for the manifest-key extension ID; startup verification fails closed (§4.2) |
| Native-path containment | A request the extension does not handle can reach the human UHID device | Planned (P2, P6, P10): fail closed; private `/dev` through `bwrap` whenever available, required (launcher refusal) when the browser UID can open hidraw; invariant 25 (§7) |
| Automatic interaction mode with agents | Not guarded | Planned (P10): agents refuse to start unless `agents.allow_automatic_human_path = true`; `doctor` flags it (§7) |
| Principal relationship | Used only for browser spawn (`browser.rs:2224`); not in doctor or audit; no shared-UID `isolated` warning | Planned (P9): both axes reported; startup warning (§13) |
| User guides | Describe `confirm`, presets, `registration_allowed` | Planned (P11): rewrite when the code lands |
| Backend separation | **Done.** `CredentialBackendHandle`, `CredentialNamespace` (`backend.rs:18-73`) | — |
| Audit before key use | **Done.** Fsynced, hash-chained append (`audit.rs:163-164`, `audit.rs:1258`); allow record gates signing (`sign.rs:1516`) | — |
| `credProtect` | **Done.** Levels 2 and 3 enforced (`sign.rs:1468`, `sign.rs:1531`) | — |
| Agents off by default | **Done.** `AgentConfig.enabled` defaults to false (`config.rs:989`) | — |
| D-Bus sender validation | **Done.** zbus match on server unique name, others rejected (`prompt.rs:565-613`) | — |
| Session (grant) audit events | **Done.** Request and approve recorded (`grant.rs:571`, `grant.rs:639`) | — |
| Shared-UID spawn hygiene | **Done.** FD closure and `PR_SET_PDEATHSIG` (`browser.rs:2248-2257`) | — |
| Distinct-UID systemd baseline | **Done.** Baseline directives (`contrib/systemd/passless-agent.service:64-71`) | Evaluated directives including `PrivateDevices`, namespaces, seccomp (§13) |

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
