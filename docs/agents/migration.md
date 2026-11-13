# Migrating older agent configuration

> **Migration notes.** This page is the only place in the agent documentation that names removed
> vocabulary. New configuration must use the current spelling in [Rules](rules.md). The legacy
> spellings below are accepted for one release with a warning and then removed (the warning says
> "removed in the release after next").

Validate before restarting the service: `passless config check` loads the file as the daemon does and
prints every deprecation warning below, or the error that would stop the daemon, with no daemon
running (see [Configuration](configuration.md#validate-before-restarting-the-service)).

## Rule actions

Rules used to carry three values: an authorization (`deny`, `confirm`, `allow`) and the source of user
presence and user verification (`human`, `agent`, `none`). Agent ceremonies no longer involve a
human UP or UV step, so the evidence fields are gone. Old rules are mapped when the config loads, and
every mapped field logs a warning (also shown by `passless agent-admin profile check` and
`passless doctor`):

| Legacy spelling | Now |
|---|---|
| `"deny"`, or a table `deny` with `none` and `none` | `deny` |
| `"autonomous"`, or a table `allow` with `agent` and `agent` (`policy` is an alias of `agent`) | `allow` |
| `"supervised"`, or a table with authorization `confirm` | `request` |
| A table `allow` with human or `none` evidence | **Startup fails** with a migration message. Choose `allow` (autonomous) or `request` (human approves) |
| A table `deny` with any evidence | **Startup fails**: write `deny` |

`request` is not a renamed `confirm`. A `confirm` rule used to prompt for each ceremony and could fall
back to the browser's native path; `request` prompts once per RP through a notification, and
approving it stores a granted rule ([Rules](rules.md#request-escalation)). Re-check every mapped rule
and decide whether you want `request` or `allow`.

## Removed profile fields

`rp_ids`, `registration_allowed`, `require_uv` and `human_verification_prompt` are removed. A config
that still has them fails to start. Replace them with explicit `[[agents.profiles.<name>.rules]]`
entries (`rp_id`, `authenticate`, `register`), and delete `human_verification_prompt`.
`registration_allowed = true` plus a registration rule becomes `register = "allow"` on the exact RP
(a same-user profile also needs `acknowledge_same_user_registration`).

## Removed modes and features

- The `delegated-session` mode no longer exists. Use `same-user` and review the trust model; it is
  not a rename.
- Agents no longer have a UHID or hidraw device. A leftover `[agents.profiles.<name>.device]` table
  is ignored with a warning, and the agent udev rule is gone.
- There are no operator-minted enrollment grants and no principal intent commands.
- The `agent-admin delegation` and `agent-admin session` commands are now `agent-admin sessions` and
  `agent-admin principals` (the old names are hidden aliases for one release). `agent playwright-mcp`
  is a hidden alias of `agent mcp playwright`.
- Conditional mediation no longer "stays native". It is unavailable in the managed browser, and
  cross-origin frames are denied.

## Upgrading to agent pre-requests

Agents can now ask for passkey access before they navigate (`passless agent request-access`, the opt-in
`passless_request_access` MCP tool; [Asking in advance](rules.md#asking-in-advance)). Nothing changes
for a profile until you list `pre_request_actions` in it. What changes on upgrade regardless, and what to
tell your users:

- **The policy digest goes from version 6 to 7.** It now covers `pre_request_actions`, so the first
  policy compile of the new binary has a new digest for every profile and **revokes sessions once**: a
  daemon restarted into the new version ends its sessions anyway, and an unchanged `policy reload` after
  that revokes nothing. Running `agent mcp playwright` wrappers start a new principal session on their
  next browser tool call.
- **The granted-rules store moves to version 2 only once a pre-request grant exists.** A grant an agent
  asked for in advance has no origin and says `source = "pre_request"` (and a registration that used a
  pre-approval has `source = "pre_request"` with its origin), which version 1 cannot represent. The
  daemon writes the lowest version that fits its entries: a store with only page-raised grants stays
  version 1 and downgrades cleanly. **An older daemon that finds a version 2 file disables that
  profile's grants (fail closed) and `passless doctor` reports it.** Before downgrading, run
  `agent-admin grants revoke` for each `pre_request` grant, or `grants clear --profile <p> --confirm`; the
  next write returns the file to version 1. `grants list` shows each grant's `SOURCE` and prints an empty
  origin as `-`; the JSON has the same `source` and `origin` values.
- **The agent protocol goes to 1.3** (`PrincipalRequest::RequestAccess`). An older client against the new
  daemon, or the reverse, negotiates down and simply lacks the command. The MCP wrapper's own link to its
  principal session is broker protocol 2: a wrapper started by an older `passless` refuses a new broker
  (and the reverse) with a message that says to restart the MCP server.
- **The audit schema goes to version 5.** Operation records carry `approval_source`; escalation records
  carry `source`, `principal_session_id_hash` and `agent_note`, and `origin` may be null; there are new
  kinds (`pre_approval.issued`, `consumed`, `expired`) and `policy.deny` reasons (`not_requestable`,
  `pre_request_rate_limited`, `pre_request_not_enabled`). Readers of older records are unaffected: fields
  added later read as absent. The audit export marks agent-supplied text (`agent_supplied` in the JSON
  rows, a last `agent_supplied` column in the CSV). See [Audit](audit.md).
- `passless agent-admin sessions list`, `show` and `revoke` work again (they ended in "unexpected
  response").

## From a plain Playwright MCP

Before agent mode, an MCP client started its own browser (`npx @playwright/mcp`, `pnpm dlx
@playwright/mcp@<pin>`, `chrome-devtools-mcp`). That still works, but its passkey prompts reach your
human authenticator, not an agent profile's rules. Rewrite the entries to the wrapper:

```bash
passless agent mcp install --client claude-code --user --profile coding        # dry run
passless agent mcp install --client claude-code --user --profile coding --yes  # write
```

Use `--client opencode --user` for `~/.config/opencode/opencode.json`, and `--project <DIR>` only for a
repository that is yours alone (it writes your `passless` path and profile into a committed file).
`--user` also rewrites the entries `claude mcp add` keeps per project (local scope). The entry keeps its
name, other keys and package spec; compatible flags (`--isolated`, `--viewport-size`, ...) pass through, and flags
that choose or attach a browser (`--browser`, `--headless`, `--user-data-dir`, ...) are dropped with a
note. The profile needs `browser_cdp_expose = "port"`. Details: [Browser
tools](browser-tools.md#switching-from-a-plain-playwright-mcp).

The design record is [ADR 0014](../decisions/0014-agent-delegation.md#6-policy).
