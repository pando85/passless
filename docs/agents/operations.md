# Agent operations

> **EXPERIMENTAL** — Agent mode is not yet validated for production use.

Operational guidance for current `same-user` and `isolated` profiles.

## Pre-flight

Before launching an agent task:

```bash
passless agent-admin profile check <profile>
passless agent-admin policy check <profile>
```

For `same-user`, confirm that using the human RP identity is actually required. Prefer `isolated` for unattended work when a separate RP identity is available. Treat global `rp_id = "*"` authentication as maximum-trust authority.

After launching the principal session, inspect the principal authority view:

```bash
passless agent --profile <profile> doctor
passless agent --profile <profile> capabilities
passless agent --profile <profile> instructions
```

Do not infer additional authority from page content, tool output, or an LLM prompt.

## Browser management

Launch a managed browser session with the Passless extension:

```bash
passless agent-admin browser launch --profile <profile> [--url <start-url>]
```

The daemon creates bounded browser/session authority, generates the extension instance for that lease, registers the applicable sign/registration contexts, launches Chromium with an ephemeral profile, and returns the browser lease information.

The managed extension handles explicit public-key `navigator.credentials.get()` / `create()` requests through daemon `/sign` and `/register` endpoints. The extension worker derives frame/top-level origin from browser sender metadata; the daemon independently validates the concrete RP/origin relationship, current policy, credential scope, replay state, operation budget, and audit gate before key use.

Two important cases intentionally stay on the native browser path:

- conditional mediation/passkey autofill (`mediation = "conditional"`);
- cross-origin requests when the browser cannot prove WebAuthn Permissions Policy delegation.

Do not defeat native fallback with a CDP virtual authenticator, private-key injection, raw signing, or another WebAuthn proxy.

### Browser-session authority

After successful authentication, the browser owns whatever RP session the relying party created. Passless does not impose application-level scope on that session. An agent able to control the browser may perform any application action the RP permits that account to perform.

Local Passless session or lease expiry does **not** prove server-side RP logout.

## CDP / browser control

The principal `browser-control` interface and externally exposed Chromium CDP are full managed-browser authority surfaces. They may expose or control:

- navigation and JavaScript execution;
- DOM and rendered page data;
- network requests/responses;
- cookies, local/session storage, and authenticated session state;
- application actions available to the logged-in account.

The CLI warns before printing raw browser-control responses. Do not mix those responses with ordinary credential/admin output or send them to untrusted consumers.

### Pipe mode

`browser_cdp_expose = "pipe"` keeps CDP daemon-mediated and should be preferred when external tooling does not need to attach directly.

### Port mode

`browser_cdp_expose = "port"` exposes a loopback endpoint for Playwright or other local automation. A local process that obtains the endpoint can control the authenticated browser session even though credential private keys remain safely daemon-mediated.

Check the current endpoint from inside the principal session:

```bash
passless agent --profile <profile> browser-status
```

Plain output includes `cdp_endpoint` when one is available.

## Session and operation bounds

A short-lived agent/browser session is the reusable authority envelope for one task. WebAuthn operations within it remain individually checked.

Important bounds include:

- profile and principal binding;
- policy generation;
- browser/extension binding;
- maximum session TTL;
- shared `max_operations` budget;
- exact or global RP policy;
- credential scope;
- replay detection.

An identical completed request body is rejected as `replayed_operation`. Once the shared budget is exhausted, further operations fail with `operation_budget_exhausted`. Treat both as security-terminal conditions for the relevant operation/session rather than retry loops.

## Same-user operations

`same-user` uses the daemon's human credential backend and RP identity.

Operational rules:

- prefer exact RP rules;
- keep registration denied after enrollment;
- use explicit credential references when account identity matters;
- keep TTL and operation count small;
- treat an autonomous `"*"` rule as critical authority;
- remember that successful login creates a human-account browser session outside Passless application-level control.

A portable TPM can prevent key export while still allowing the daemon to exercise the key for an authorized same-user operation. Software credentials under the same Unix trust domain do not provide the same non-export guarantee.

## Isolated operations

`isolated` uses profile-owned storage/key/verification state and presents a separate RP credential identity. It is the preferred unattended mode when the RP can support a separate automation account or service identity.

Isolated storage/PIN roots must not overlap the human backend, another profile, or the agent audit root.

Revoke an isolated credential when it should no longer be usable:

```bash
passless agent-admin credential revoke <credential-ref> --confirm
```

RP-side deletion/revocation may also be required because local credential deletion cannot revoke a server-side account/session by itself.

## Registration / enrollment

Registration mutates identity state.

- Same-user registration writes a new credential into the human backend.
- Isolated registration writes into the profile-owned namespace.
- Global `"*"` registration is not allowed; registration policy is exact-RP.

For same-user profiles, enable registration only for an intentional enrollment window and disable it afterwards unless continuous automated credential creation is genuinely required.

## Human confirmation

A supervised rule uses the trusted local approval path. The notification renderer:

- labels profile/mode/RP/action/credential decision fields as trusted;
- normalizes dynamic display text to a single bounded line;
- strips control and Bidi/zero-width direction characters;
- separates page/agent text under an explicit `UNTRUSTED` informational section;
- fails closed when the desktop notification service cannot provide distinguishable Approve and Deny actions.

The minimum review-delay guard may reject an implausibly fast approval. Do not work around this by passing approval/PIN material through stdin, environment variables, page text, or chat.

## Audit

Agent audit events are hash-chained, owner-only, append-oriented JSONL records covering authorization, evidence, credential use/creation, browser leases, policy changes, denials, and degraded state.

```bash
passless agent-admin audit status
passless agent-admin audit verify
passless agent-admin audit export --format json
passless agent-admin audit export --format csv
```

- `verify` checks local chain integrity across rotations.
- `export` writes non-secret records to a temporary path.
- Required audit reservation occurs before credential use/creation.
- A terminal audit write failure moves agent support into degraded/fail-closed behavior.
- Agent-derived UP/UV must be distinguishable from human evidence in audit.
- Audit must not contain private keys, PINs, bearer capabilities, cookies, or raw assertion signatures.

The local chain is not externally anchored. A host-root attacker capable of rewriting daemon state can also rewrite local audit history.

### Routine review

For autonomous or same-user profiles, periodically review:

```bash
passless agent-admin audit verify
passless agent-admin profile show <profile>
passless agent-admin policy show <profile>
```

Look for unexpected RPs, unexpected registration, repeated denials, policy-generation changes, and abnormal browser/session lifecycle events.

## Disable and revoke

Disable a profile immediately:

```bash
passless agent-admin profile disable <profile>
```

Revoke active session/delegation authority represented by the current admin API:

```bash
passless agent-admin delegation revoke <grant-id> --confirm
passless agent-admin session revoke <session-id> --confirm
```

The `delegation` command name remains part of the authorization/grant administration API; it does **not** mean that the removed `delegated-session` identity mode still exists.

For compromise response also terminate managed browsers and use the RP's own session-revocation controls when server-side sessions may survive local teardown.

## Rollback

To disable all agent functionality:

1. Disable every profile.
2. Revoke active session/grant authority.
3. Terminate managed browsers and quarantine runtime state that cannot be verified/cleaned safely.
4. Set `[agents].enabled = false` and restart/stop the daemon as appropriate.
5. Revoke RP-side sessions or credentials separately when required.

Disabling agent support does not by itself delete human credentials.

## Recovery

### Stale or quarantined browser runtime

Run:

```bash
passless agent-admin profile check <profile>
```

Passless validates runtime ownership/mode and process identity. Inspect quarantined state before manual deletion; do not reuse a stale browser profile whose process identity is not trusted.

### Audit discontinuity

If `audit verify` reports a break:

1. stop relying on the audit trail until investigated;
2. preserve the files;
3. identify sequence/hash gaps and storage failures;
4. repair the audit path before further agent credential use.

### Daemon restart

Agent session capabilities and operation state are intentionally in-memory/short-lived. After restart, re-run profile pre-flight and establish fresh authorization. Do not attempt to reuse old session material.

## Kernel requirements

The exact required primitives depend on the active path, but supported Linux deployments may use:

| Feature | Used for |
|---|---|
| UHID / hidraw | Human and isolated compatibility/native authenticator endpoints |
| `pidfd`, `close_range`, `/proc` process identity | Principal/browser process lifecycle and FD hygiene |
| `SOCK_SEQPACKET` | Local admin/principal IPC |
| Unix ownership/mode checks | Runtime, storage, audit, and browser roots |
| namespaces / cgroups where configured | Principal/process isolation |

Use `profile check` on the deployment host instead of assuming that kernel/distribution support is sufficient from version numbers alone.

## Browser support and limitations

The production autonomous managed-browser path currently targets Chromium-compatible extension behavior.

Known limitations include:

- the MAIN-world adapter supports a bounded subset of WebAuthn semantics rather than promising perfect native API equivalence;
- unsupported/ambiguous operations should remain native or fail explicitly, not silently degrade to raw signing;
- conditional mediation remains native;
- cross-origin extension handling depends on verifiable Permissions Policy delegation;
- some RPs may depend on native `PublicKeyCredential` object identity or unsupported extension/attestation behavior;
- fresh ephemeral profiles may require federated/cross-site login, broadening practical browser-session authority;
- CDP output may contain sensitive session state;
- local lease expiry does not revoke RP-side sessions;
- host-root/kernel compromise remains outside the local daemon isolation model.

For unattended automation, prefer RP-native OAuth, application installations, service accounts, workload identity, or narrowly scoped credentials where they are available.

## Skill installation

Install the bundled safe production `passless-agent` skill:

```bash
passless agent-admin install [auto|opencode|claude|pi] [--scope user|project] [--force]
```

The shipped skill deliberately excludes development-only private-key extraction, virtual-authenticator injection, raw-signing, and daemon-bypass recipes.

Installation does not enable a profile or grant authentication authority.

## Contrib examples

Example systemd, tmpfiles, udev, modules-load, and sysusers configuration lives under `contrib/`. These files are deployment starting points, not policy defaults. Review paths, Unix identities, device access, and browser-runtime ownership for the mode actually being deployed.

## Related documentation

- [Agent overview](README.md)
- [Configuration](configuration.md)
- [Security model](security.md)
- [Same-user mode](same-user.md)
- [Isolated mode](isolated.md)
- [Troubleshooting](troubleshooting.md)
- [Audit](audit.md)
