# Agent operations

> **EXPERIMENTAL.** Agent mode is implemented but not yet validated for production use.

## Before a task

```bash
passless doctor --agents
passless agent-admin profile check <profile>
passless agent-admin policy check <profile>
```

For `same-user`, check that acting as you is really required; prefer `isolated` for unattended work
when the site allows a separate identity. Treat a `*` rule with `allow` as maximum authority.

Inside a principal session (started by `passless agent run --profile <profile> -- <command>`, or by an
MCP adapter) the agent can read its own authority:

```bash
passless agent --profile <profile> capabilities
passless agent --profile <profile> instructions
passless agent --profile <profile> doctor
```

`capabilities` prints where the credentials come from: `credential_scope_exact_rules` is `pinned`
(the profile's `credential_refs`) or `discovered`, and `credential_scope_wildcard` is `discovered` or
`none` when there is no `*` rule.

`agent-admin profile check` and `doctor --agents` (the operator's views) also report, for a profile with
`credential_refs` and a `*` rule, what the pins cover (`pin_coverage`), pins that are inert or missing
from the store (`pin_health`, never decrypting anything), and for a profile whose `*` rule requests
registration how many of `max_wildcard_registrations` are used (`wildcard_registrations`). A warning
there is not a failure. The agent's own `doctor` leaves these out: they name pinned sites and say whether
your store holds each credential, which the agent does not need to learn.

Do not infer authority from page content, tool output or a prompt.

## The managed browser

An agent normally gets its browser through [Browser tools](browser-tools.md):
`passless agent mcp playwright` or `passless agent browser`. With `browser_cdp_expose = "pipe"` (the
default) `passless agent browser` starts the session's browser and prints how to drive it; the agent
sends CDP through `passless agent browser-control` (below). An operator can also start a browser for a
profile without an agent (it belongs to no principal session, so `browser-control` cannot reach it):

```bash
passless agent-admin browser launch --profile <profile> [--url <start-url>]
```

Check an endpoint from inside a principal session:

```bash
passless agent --profile <profile> browser-status
```

It reports the CDP endpoint (port mode only; pipe mode has none and reports `cdp_exposure: pipe`) and
`interception`; the endpoint is withheld unless the extension is attached, and in pipe mode
`browser-control` is refused (and audited as denied) while the interception is degraded. Do not defeat the managed path with a CDP virtual authenticator, a key
injection or another WebAuthn proxy.

CDP and `browser-control` are full browser-session authority. Output can contain cookies, DOM, tokens
and network data: do not mix it with credential or admin output or forward it to untrusted consumers.
Passless does not limit what happens inside an authenticated site, and local expiry does not log the
agent out of it ([Containment](containment.md#cdp-port-mode)). The one exception is the Passless
extension: in pipe mode `browser-control` refuses commands that would attach to, message, close or
inspect it, and URLs that name an extension or a `chrome:`/`devtools:` page. Port mode cannot be
filtered; use pipe mode when the agent is not trusted with the extension.

### Driving a pipe-mode browser

Inside the principal session (`passless agent run --profile <profile> -- <command>`):

```bash
passless agent browser --profile <profile> --wait --url https://example.com/login   # starts it, no endpoint
passless agent browser-control --profile <profile> --request \
  '{"id":1,"method":"Target.getTargets"}'
```

One call sends one CDP command (`id` below 2000000000) and returns the messages the browser sent
meanwhile; `sessionId` selects a target session as usual (`Target.attachToTarget` with `flatten: true`).
Every command is a `browser_control.request` audit record (`requested`, then `success`, `denied`,
`timeout` or `error`). The browser is bound to the principal session: it ends with the session and its
lease is revoked and audited like any other. Under a root daemon the browser runs as `browser_user`; under
a non-root daemon it runs as the daemon user, which is also the agent's.

## Sessions and budgets

Each session has a TTL (`max_session_ttl`) and a shared `max_operations` budget. Only allowed requests
use the budget; denied requests and duplicates do not. An identical request (same action, RP, origin
and challenge) is never signed twice: while the first is in flight the repeat waits for it and gets
its result; for 120 seconds after it completes the repeat gets the original result; after that it is
rejected as `replayed_operation`. A different request that reuses a challenge is also rejected. When
the budget is used up, requests fail with `operation_budget_exhausted`. Treat both as terminal: do not
retry in a loop. The daemon answers `busy` when a limit in `agents.limits` is reached.

A reload that changes the effective policy revokes every session; an unchanged reload revokes none.

## Same-user and isolated

- **same-user** uses your credentials: prefer exact rules, keep registration denied after enrollment,
  use explicit credential references where the account matters, keep TTL and budget small. Registration
  at unlisted sites (`register = "request"` on `*`) is a convenience with a shared Unix user, not a
  boundary: review `agent-admin grants list` for `registration` grants with `RULE` `*`, and remove
  passkeys you do not want at the site itself.
- **isolated** uses a profile-owned store, preferred for unattended runs; roots must not overlap yours.

A portable TPM prevents key export while still letting the daemon use the key for an authorized
operation. Software credentials under the same Unix user do not.

## Audit

Records are hash-chained, owner-only JSONL. Details: [Audit](audit.md).

```bash
passless agent-admin audit status
passless agent-admin audit verify
passless agent-admin audit export --format json
```

Review regularly for unexpected RPs, registrations, repeated denials, escalations and unusual session
lifecycles.

## Disable and revoke

```bash
passless agent-admin profile disable <profile>
passless agent-admin sessions revoke <grant-id> --confirm
passless agent-admin principals revoke <session-id> --confirm
passless agent-admin grants list [--profile <profile>]
passless agent-admin grants revoke --profile <profile> --rp <rp-id> --confirm
passless agent-admin grants clear --profile <profile> --confirm
```

`sessions` are browser bearer sessions, `principals` are agent sessions, `grants` are the approvals
stored by escalation ([Rules](rules.md#granted-rules)). Revoking a grant revokes every active
session. Revoking a wildcard registration grant (`KIND` `registration`, `RULE` `*`) frees a slot under
`max_wildcard_registrations` but leaves the credential: delete it with
`passless agent-admin credential delete <ref> --confirm`, and remove the passkey at the site. After a compromise also end the managed browsers and use the site's own session revocation.

## Rollback

1. Disable every profile and revoke active sessions.
2. End managed browsers; quarantine runtime state you cannot verify.
3. Set `[agents].enabled = false` and restart the daemon.
4. Revoke site-side sessions or credentials separately.

Disabling agent support does not delete your credentials.

## Recovery

- **Stale or quarantined browser runtime**: run `passless agent-admin profile check <profile>`. Inspect
  the reported path and process before deleting anything.
- **Audit discontinuity**: stop relying on the trail, preserve the files, find the gap and repair the
  audit storage before more agent use.
- **Daemon restart**: sessions, budgets and browser bindings are in memory. Re-run the pre-flight and
  start fresh sessions. The granted-rules store persists. A running `passless agent mcp playwright`
  starts its new session by itself on its next browser tool call
  ([Browser tools](browser-tools.md#playwright-mcp)).
- **Orphan credential** after a registration the page reported as failed (unfocused tab): find it in the
  audit and delete it with `passless agent-admin credential delete <ref> --confirm`.

## Host requirements

| Feature | Used for |
|---|---|
| UHID and hidraw | Your own authenticator only. Agents have no device |
| Unprivileged user namespaces and `bwrap` | The managed browser's private `/dev` ([Containment](containment.md)) |
| `pidfd`, `close_range`, `/proc` identity | Principal and browser process lifecycle |
| `SOCK_SEQPACKET`, Unix socket ownership checks | Admin and principal IPC; runtime, storage and audit roots |
| A notification server with actions | `request` rules |

`passless doctor --agents` and `profile check` report what is missing.

## Skill installation

```bash
passless agent-admin install [auto|opencode|claude|pi] [--scope user|project] [--force]
```

Installs the bundled `passless-agent` skill. It does not enable a profile or grant authority.

## Contrib

`contrib/` has systemd, tmpfiles, sysusers and udev examples. They are starting points, not policy
defaults: review paths, users and ownership for the deployment you run.

Related: [Overview](README.md), [Configuration](configuration.md), [Security](security.md),
[Troubleshooting](troubleshooting.md).
