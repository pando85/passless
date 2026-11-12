# Agent configuration reference

> **EXPERIMENTAL.** Agent mode is implemented but not yet validated for production use. Fields and
> validation rules may change.

Agent support is off by default. All configuration lives under `[agents]` in the main TOML file
(`~/.config/passless/config.toml`, or `PASSLESS_CONFIG`). Unknown fields and invalid values are
rejected when the config loads. For a minimal working file see the [Quick start](quick-start.md).

## `[agents]`

```toml
[agents]
enabled = true
audit_path = "/home/alice/.local/state/passless/agent-audit"
```

| Field | Meaning |
|---|---|
| `enabled` | Master switch (default `false`). |
| `audit_path` | Required when enabled. Owner-only directory for audit records; must not overlap any storage root. |
| `browser_path` | Browser binary for profiles that set no `browser_command`. Unset, Passless detects one ([Containment](containment.md#supported-browsers)). |
| `notify_user` | The user whose session bus receives escalation prompts. A root daemon needs it for `request` rules and it must differ from every `principal_user` and `browser_user`; a non-root daemon may only name its own user. Restart-only. |
| `state_dir` | Absolute path for persistent agent state, such as granted rules. Default `$XDG_STATE_HOME/passless/agent`, or `/var/lib/passless-agent` for a root daemon. Restart-only. |
| `escalation_timeout` | Seconds (1 to 72000) capping how long a request waits for a decision. Unset, the page's own timeout applies. |
| `escalation_cooldown` | Seconds (60 to 86400, default 600) during which a denied or expired escalation is denied without a prompt. |
| `allow_automatic_human_path` | Default `false`. See [Containment](containment.md#automatic-interaction-mode). |
| `acknowledge_global_same_user` | Profile names allowed to use a `*` rule. |
| `acknowledge_same_user_registration` | Profile names allowed to register into the human store. |

An acknowledgement names a profile and grants nothing by itself; the rules stay the authority.
Acknowledging an unknown profile is an error, so stale names cannot survive a rename.

`[agents.limits]` sets the concurrency caps of the request server, read at start. A request over a cap
is answered `busy` (the page sees `NotAllowedError`), never dropped: `max_concurrent_requests`
(default 32), `max_requests_per_profile` (16), `max_requests_per_session` (8),
`max_requests_per_connection` (8), each 1 to 1024.

## Profiles

```toml
[agents.profiles.coding]
mode = "same-user"          # or "isolated"
principal_user = "alice"
browser_cdp_expose = "port"
max_session_ttl = 3600
max_operations = 32
credential_selection = "single"
```

| Field | Meaning |
|---|---|
| `mode` | `same-user` uses your credential store; `isolated` uses the profile's own. |
| `principal_user` | Unix user the agent runs as. |
| `rules` | Per-RP rules, see [Rules](rules.md). Missing rules deny. |
| `credential_refs` | Optional list restricting the credentials the profile may use. |
| `credential_selection` | `single` (default), `first-matching`, `newest` or `credential:<ref>`. A rule may override it. |
| `max_session_ttl` | Seconds of authority per session (1 to a year). It caps each principal session and its browser lease. `passless agent mcp playwright` renews an expired session on its next browser tool call, through the admin socket with every check applied again; a revoked session, or one whose profile was disabled, is final. |
| `max_operations` | Shared budget of allowed ceremonies per session, 1 to 4096 (default 64). Only allowed requests count. |
| `max_concurrent_sessions` | Live principal sessions per profile: 1 to 64 (default 64). `0` means unlimited and is only valid with `browser_scope = "profile"`. A new session over the limit is refused with `profile '<name>' reached max_concurrent_sessions (<n>)`. Each MCP client process is one session: see [Several clients at once](browser-tools.md#several-clients-at-once). |
| `max_granted_rules` | Granted rules per profile (default 64, 1 to 256). |
| `browser_scope` | `session` (default; each session owns its browser) or `profile` (sessions share one; it closes when its owner session ends, and the others start their own on their next browser call). |
| `browser_command` | Browser executable and arguments. Optional: see `browser_path`. |
| `browser_user` | Unix user for the browser (needs a root daemon). Not allowed for `isolated`. In pipe mode under a root daemon it must differ from `principal_user` and the daemon user and must not be root. A non-root daemon cannot switch users, so there the browser runs as the daemon user (which is also the principal's): pipe mode then mediates and audits CDP but does not separate the browser from the agent. |
| `browser_runtime_root` | Runtime root for the browser; mode 0700, owned by the browser user. Unset, it is `$XDG_RUNTIME_DIR/passless/browser`, which the daemon creates when missing (only when the browser runs as the daemon's own user). A configured root is created by the daemon only as its last component, and only when its parent exists and is not writable by others; an existing one with the wrong owner or mode, or a symlink, is refused, never repaired. |
| `browser_cdp_expose` | `pipe` (default) or `port`. Pipe: the browser has no endpoint and the agent drives it through `passless agent browser-control` (every command audited, extension filtered; start it with `passless agent browser`). Port: a loopback endpoint for the [easy path](browser-tools.md) tools (Playwright, chrome-devtools-mcp, `connectOverCDP`), which need `port`. |
| `browser_cdp_port` | Loopback port for port mode; `0` (default) lets Chromium choose. Leave it unset unless a tool needs that exact port: the MCP wrappers and `passless agent browser --env` (`PASSLESS_CDP_URL`) find the endpoint themselves. `passless agent mcp install` and `passless doctor --agents` print a note when a profile pins one. A launch is refused while another process (a browser you started with `--remote-debugging-port`, for example) holds the port on 127.0.0.1. Must be 0 when `browser_scope` is `session` and `max_concurrent_sessions` is above 1 (a shared `profile` browser may use a fixed port). |
| `start_url` | Optional `http` or `https` URL opened at start. |

`max_grant_ttl` is a compatibility bound on session grants. The daemon rejects Chromium
remote-debugging flags in `browser_command`: it owns them.

### Same-user and isolated storage

A `same-user` profile uses the daemon's human backend and must not set `storage`. Registration writes
into your own store, so keep it denied after enrollment.

An `isolated` profile requires its own storage; roots must not overlap the human backend, another
profile, the audit path or the granted-rules directory:

```toml
[agents.profiles.release]
mode = "isolated"
principal_user = "passless-release"
max_session_ttl = 300
max_operations = 8

[agents.profiles.release.storage.local]
path = "/var/lib/passless-agent/release/credentials"
pin_path = "/var/lib/passless-agent/release/pin"

[[agents.profiles.release.rules]]
rp_id = "git.example.com"
authenticate = "allow"
register = "deny"
```

Other backends: `storage.pass` (`store_path`, `path`, `gpg_backend`, `pin_path`, `git_sync`,
`git_auto_push`) and `storage.tpm` (`path`, `tcti`, `pin_path`, `portable`) when built with TPM
support. For an isolated `pass` profile `git_sync` and `git_auto_push` default to `true` and are
independent of the top-level `[pass]` settings; a `same-user` profile follows the global ones. If the
human and an isolated backend share one Git repository, a push from either can publish the other's
commits: use separate repositories.

## Validation

Important fail-closed checks:

- `agents.enabled = true` requires `audit_path`; storage and audit roots must not overlap.
- `same-user` rejects `storage`; `isolated` requires it.
- A `*` rule requires `same-user`, the acknowledgement, no `credential_refs`, `register = "deny"` and
  `single` selection.
- Same-user registration (`register` other than `deny`) needs an exact RP and the registration
  acknowledgement. `register = "request"` with `authenticate = "deny"` is invalid.
- RP IDs are exact DNS names: partial wildcards, IP addresses, public suffixes, schemes, ports and
  paths are rejected. `localhost` is allowed for exact rules only.
- A profile may have at most 32 RP rules unless it has a `*` rule.
- Duplicate RP rules and unknown fields fail.
- A profile whose rules are all `deny` is valid.

Older spellings: see [Migration](migration.md).

### Validate before restarting the service

```bash
passless config check                              # PASSLESS_CONFIG, else ~/.config/passless/config.toml
passless config check --config-path ./candidate.toml
```

`config check` loads the file the way the daemon does and runs the same validation (the `[agents]`
table, every profile rule, the acknowledgements, root overlaps, the backend and the audit directory),
prints the deprecation warnings and ends with `ok`, or prints the error and exits non-zero. It needs no
running daemon, D-Bus or UHID, so run it before `systemctl --user restart passless`: a daemon that
refuses the file does not start. `passless doctor --agents` reports a rejected configuration as a
`FAIL` on its `config` check. With `agents.enabled = false` the profiles are not validated, as at
startup, and `config check` says so.

## Policy reload

`passless agent-admin policy reload <profile>` re-reads and validates the config file the daemon started from.

- An **invalid** file is rejected and the current policy stays in force.
- A change that needs a restart (`enabled`, `audit_path`, `limits`, `notify_user`, `state_dir`, the
  set of profiles, or a profile's `mode`, `principal_user`, `browser_user`, `storage`, `browser_scope`
  or `max_concurrent_sessions`) is rejected the same way.
- An **unchanged** effective policy changes nothing and live sessions continue.
- A **changed** policy revokes every session, closes the managed browsers, and cancels pending
  escalations. Operations in flight fail before key use.

## Pre-flight

```bash
passless doctor --agents
passless agent-admin profile check coding
passless agent-admin policy check coding
```

Inside a principal session, `passless agent --profile coding capabilities` shows the authority the
profile actually has, including each RP's `authenticate` and `register` rule. Treat it, not a page
or a prompt, as the authority contract.
