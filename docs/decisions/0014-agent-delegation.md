# ADR 0014: Agent delegation

- **Status:** Accepted
- **Date:** 2026-11-10
- **Decision owners:** Passless maintainers
- **Implementation status:** Partially implemented; see [Implementation status](#19-implementation-status)

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
managed browser                           ├─ backend handles (human, isolated/<profile>)
  MAIN-world script ─▶ broker ─▶ worker   ├─ notification prompt (D-Bus)
                                 │        └─ audit writer
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
`--load-extension`:

- `main.js`, MAIN world, `document_start`: overrides `navigator.credentials.get()` and `create()`,
  reads the frame's origin, serializes options, and returns a duck-typed `PublicKeyCredential`;
- `broker.js`, isolated world: validates and relays messages;
- `worker.js`, service worker: holds the bearer and talks to the daemon.

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
suffix. The only pattern is the constrained `*` (§6.3).

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

## 7. Ceremonies and evidence

An agent ceremony never invokes the notification prompt, the PIN path or native WebAuthn. The
extension never falls back to the original `navigator.credentials` methods for a request it has
routed to the daemon. A `deny`, a rejected or timed-out escalation, and every policy failure
return `NotAllowedError` to the page.

Non-public-key credential calls and requests the extension does not intercept (such as
conditional mediation, and cross-origin frames until §11 lands) still use the native path. That
path belongs to the human authenticator and is outside agent policy.
`PASSLESS_INTERACTION_MODE=automatic` (PR #505) affects only the human CTAP path and never
approves an escalation.

For an `allow` decision the daemon sets UP=1 and UV=1 only after validating that:

- the bearer session is active, unexpired and within its operation budget;
- the session is bound to the profile, the principal digest and the browser lease;
- the operation passes origin and RP validation;
- the current policy generation still resolves to `allow` immediately before key use;
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
   pending per key; concurrent ceremonies wait on it.
3. The daemon writes an `escalation_requested` audit record; if the write fails, the ceremony
   fails.
4. The daemon shows a notification built only from daemon-derived fields: profile, identity
   mode, principal, action, RP ID, origin, and whether the grant would be persistent. It shows no
   page- or agent-supplied text. The only actions are **Allow always** and **Deny**.
5. The WebAuthn call stays open until a decision or the ceremony's effective timeout. The timeout
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
   are denied without prompting.

### 8.2 Integrity and abuse limits

- Approval comes only from the notification server's verified D-Bus sender: the prompt
  subscribes to `ActionInvoked` with zbus and rejects signals whose sender is not the server's
  unique bus name. No API, CLI or extension message can approve an escalation; operators who want
  a rule without a prompt edit the config.
- The notification-server capability gate fails closed on servers without distinct actions.
  `min_review_delay_ms` is a timing heuristic, not authentication.
- With no notification service the request is denied immediately and audited. Headless hosts use
  explicit `allow` rules.
- Each profile shows at most one escalation prompt at a time. Other keys queue in a bounded
  queue; overflow is denied.
- The budget claim happens only after origin and policy validation (§9).

### 8.3 Registration escalation

Autonomous registration is the explicit setting `register = "allow"`; it is never obtained
through escalation. `register = "request"` is valid only where `register = "allow"` would be
valid, and invalid when the same rule has `authenticate = "deny"`.

Approving a registration escalation permits exactly one registration, for exactly that RP, within
the waiting ceremony. The approval binds to that ceremony's session and is not a separate
transferable credential. It does not persist `register = allow`. On successful creation it persists
`authenticate = allow` for that exact RP with `kind = "registration"` and the new credential
reference. If registration fails after approval, nothing is persisted.

### 8.4 Granted-rules store

- **Location:** `<agent state dir>/granted-rules/<profile>.toml`, owned by the daemon user, mode
  0600, in a 0700 directory. The daemon never writes the operator's config file.
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
  `passless agent grants clear --profile P`. Revocation is audited.
- **Lifetime:** permanent until revoked or made inert by a config change (§6.2); no TTL.
- **Generation:** adding a grant bumps the generation without invalidating active sessions,
  because it only widens authority the human just approved. Revoking a grant or changing the
  config invalidates active sessions of the affected profile.
- **Cap:** `max_granted_rules` per profile, default 64; above it requests are denied.

In shared-UID deployments the agent can write this file as it can write the config; that is inside
the shared-UID trust boundary (§13). In distinct-UID deployments it must not be writable by the
principal.

## 9. Sessions and replay

The normative model is a bearer session, not a per-operation state machine.

- **Binding.** Profile, identity mode, principal digest, browser lease, policy generation at
  creation, TTL and `max_operations` (recommended 10 minutes and 16; the daemon enforces
  configured maxima).
- **Self-issued.** A principal obtains its session itself within policy. This is the `allow`
  model, not a bypass; the `AdminAuthority` seal is cosmetic. Session (grant) request and approval
  are audited.
- **Order of checks.** Authenticate the bearer; validate origin and RP; resolve policy; claim
  budget; check the replay key; reserve audit; re-check policy generation; use the key.
- **Replay key.** `SHA-256(action ‖ rp_id ‖ origin ‖ top_origin ‖ challenge)`, held per session
  until expiry. A repeated key is rejected; cached responses are not returned. Failures consume
  the key.
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
`credProtect`, supported extensions and the backend's real key provider.

### 10.3 Registration

Registration targets the mode's backend: `same-user` writes to the human backend, `isolated` to the
profile backend. It is denied unless the exact rule says `allow` (or an escalation approves it,
§8.3). The daemon:

- honors `pubKeyCredParams` in RP order, `excludeCredentials` (a match rejects), user-verification
  and authenticator-selection constraints it can represent;
- generates the key through `CredentialKeyProvider::generate()` (TPM keys are generated and
  sealed in one step) and a random credential ID;
- builds `authenticatorData` with attested credential data and `clientDataJSON` of type
  `webauthn.create`, with attestation format `none`;
- writes the credential before returning.

Unsupported requirements (resident-key, attestation, extensions) return `NotSupportedError` before
storage mutation instead of being dropped.

**Authority.** Same-user `register = "allow"` requires only an exact RP rule plus the profile
listed in `acknowledge_same_user_registration`. Passless has no operator-minted, one-shot
enrollment grant and no CLI to mint one. A human-approved single registration is
`register = "request"` through the notification (§8.3). Registration authority on the extension
path is the session bearer (§9).

## 11. Browser extension contract

The extension must:

- intercept `navigator.credentials.get()` and `create()` at `document_start`;
- pass non-public-key calls to the original API;
- take the caller origin from trusted sender metadata and cross-check the MAIN-world report;
- capture top origin and cross-origin state, and apply WebAuthn RP-ID rules rather than equating
  origin host with RP ID (explicit ports are valid);
- keep the daemon bearer out of the MAIN world and page JavaScript;
- serialize all relevant options without lossy conversion;
- honor `AbortSignal`, RP timeout and browser shutdown, propagating abort to the daemon, which
  cancels any pending escalation wait for that ceremony;
- key its completed-request cache by tab, origin and request ID;
- return correct DOMException names and expose the expected credential methods and JSON
  serialization;
- never fall back to native WebAuthn for a request routed to the daemon (§7).

Top-level frames are the minimum. Cross-origin frames fail closed in the daemon until origin,
top-origin, Permissions Policy and ancestor validation are implemented there; the page-controlled
MAIN-world check is not a gate. A `chrome.webAuthenticationProxy` adapter may be added for RPs
that need native `PublicKeyCredential` identity, using the same operation service and without
weakening origin binding.

## 12. Audit

Audit is mandatory. The daemon durably appends and fsyncs a reservation before any credential
creation or use; failure blocks key use, and a terminal record follows every reservation.

Storage is outside the principal boundary (in distinct-UID deployments), owner-only,
append-oriented and hash-chained. A terminal write failure puts agent support into a degraded
state until an administrator repairs it; the human path stays available. Records never contain
private keys, PINs, capabilities, bearers, cookies, tokens, raw assertions, client-data hashes,
credential records or browser profile contents.

Each operation record carries at least: session ID hash and request or escalation ID; profile,
mode, principal relationship and the real policy generation; action, RP ID, origin, top origin and
cross-origin flag; matched rule (`exact`, `*` or `granted`); decision and evidence source (`agent`
or absent); credential reference and selection rule; backend and key-provider type; counter before
and after; terminal result and failure class.

Also recorded: session (grant) request and approval with profile, principal, RP scope and TTL;
escalations as `requested`, `approved`, `denied`, `expired` and `revoked`; and browser-lease
creation, expiry, revocation, exit and cleanup.

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
human/agent boundary still applies, so escalation integrity (§8.2) is in scope.

**Distinct-UID.** The root system unit (`passless-agent.service`) needs root continuously for
cross-user `setuid`/`setgid` spawns.

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
13. Policy is re-checked against the current generation immediately before key use.
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

Invariants 1–6 and 15–23 were ADR 0007 §10 items 1–6 and 15–23; 7–14 replace its items 7–14;
24 is new.

## 15. Threats and residual risk

| Threat | Mitigation | Residual |
|---|---|---|
| Compromised same-user agent acts as the human | Explicit mode, exact rules, short sessions, budgets, selectors, audit | Allowed by design within policy |
| Isolated agent reaches human credentials | Separate backend handle, no shared paths | Host root or daemon compromise; shared-UID deployments |
| Malicious page drives the agent to request many RPs | Only `request` rules escalate; one prompt per profile; bounded queue; cooldown; grant cap | Prompt fatigue can still widen policy permanently |
| Notification click-jacking or spoofed approval | Verified D-Bus sender; daemon-derived text only | A desktop-automation agent in the user's session can click its own prompt |
| Agent tampers with granted rules or config | Daemon-owned store, owner/mode checks, digest | Shared-UID agents can tamper |
| Supervised policy silently auto-approved | No `confirm`; no native fallback; automatic mode excluded | None on the agent path |
| Page replays a request | Replay key per session, consumed on every result | A new valid request is authorized by `allow` |
| Page burns the operation budget | Budget claimed after origin and policy validation | — |
| Local process calls the sign socket | Bearer, short TTL, profile binding, origin/RP/policy checks | Inside the boundary for shared-UID |
| RP-requested UV is fabricated | UV only from validated agent evidence | RP cannot distinguish agent from human UV |
| Wildcard or ambiguity picks the wrong account | Pinning before `allowCredentials`; forced `single` under `*` | `first-matching` is deliberately less specific |
| Counter races corrupt human credentials | Shared handle and operation lock | Backend-specific crash consistency |
| Extension reports a false origin | Sender metadata cross-check; cross-origin frames fail closed | Browser and extension are in the TCB |
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
  indistinguishable from human UP/UV at the RP; the extension adds a TCB component and a
  duck-typed credential object that `instanceof` checks reject.
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
| `chrome.webAuthenticationProxy` as primary transport | Rejected. `requestDetailsJson` lacks the frame origin. Allowed as an adapter (§11). |
| `remoteDesktopClientOverride` | Rejected. Breaks origin binding and needs enterprise policy. |
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
| Native fallback for `confirm`/human rules | Daemon returns `human_interaction_required` (`sign.rs:1383-1414`); worker flags `fallback` (`worker.js:140`); page replays natively (`main.js:282`) | Removed (§7) |
| Human/confirm evidence in schema | `AgentAuthorization::Confirm`, human UP/UV sources (`passless-core/src/agent/config.rs:198-320`) | `deny`, `allow` and `request` only (§6) |
| Legacy fields and `policy` alias | Accepted without warning (`config.rs:218`, `654-684`) | Warn for one release, then fail (§6.4) |
| Cross-origin frames | Accepted with any parseable top origin (`sign.rs:208`) | Fail closed (§11) |
| `credential:<ref>` vs `allowCredentials` | `allowCredentials` match returns before pinning (`sign.rs:1633-1642`) | Pin first (§10.1) |
| Budget claim order | Claimed at `sign.rs:1080`, before origin check at `sign.rs:1256` | After origin and policy (§9) |
| Replay | Raw body hash; identical body gets a 120 s cached response (`sign.rs:298-345`) | Replay key, no cached responses (§9) |
| Registration bearers | Not revoked with the lease (`revoke_by_lease`, `sign.rs:644-663`) | Revoked (§9) |
| Operator-minted enrollment grants (#411) | `request_registration_grant` with placeholder session, endpoint and zero principal digest (`policy_engine.rs:870-892`); CLI `commands/agent_admin.rs:658`, IPC `AdminRequest::RequestRegistration` (`protocol.rs:378`) | Removed (§10.3) |
| Isolated UHID route | Per-profile UHID endpoints (`endpoint_manager.rs`, `runtime.rs:1425`, `runtime.rs:1516`); in-daemon confirm prompt (`ceremony.rs:1426-1479`); agent UHID probing (`launcher.rs:1259`, `doctor.rs:251`) | Removed (§5) |
| Principal digest at signing | Not checked | Checked (§7) |
| Policy digest | Omits `credential_selection` and `human_verification_prompt` (`passless-core/src/agent/policy.rs:497-518`) | Covers all fields and grants (§6.4) |
| Audit content | No session, operation, origin, credential or result in `PolicyAllowMeta` (`audit_events.rs:659-666`); "generation" is an ID length (`runtime.rs:4079`) | Fields of §12 |
| Abort | Local reject only (`main.js:320-325`) | Propagated to daemon (§11) |
| Extension cache | Keyed by `request_id` only (`worker.js:84-117`) | Tab, origin, request ID (§11) |
| Unsupported options | Silently dropped | `NotSupportedError` (§10.3) |
| Transport | `sendNativeMessage` (`worker.js:126`); sign-proxy 10 s socket timeout | `connectNative` with keepalive (§4.4) |
| Escalation, granted-rules store, `passless agent grants` | Not implemented | §8 |
| Principal relationship | Used only for browser spawn (`browser.rs:2224`); not in doctor or audit; no shared-UID `isolated` warning | Both axes reported; startup warning (§13) |
| User guides | Describe `confirm`, presets, `registration_allowed` | Rewrite when the code lands |
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
