# Migrating older agent configuration

> **Migration notes.** This page is the only place in the agent documentation that names removed
> vocabulary. New configuration must use the current spelling in [Rules](rules.md). The legacy
> spellings below are accepted for one release with a warning and then removed (the warning says
> "removed in the release after next").

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

## From a plain Playwright MCP

Before agent mode, an MCP client started its own browser (`npx @playwright/mcp`, `pnpm dlx
@playwright/mcp@<pin>`, `chrome-devtools-mcp`). That still works, but its passkey prompts reach your
human authenticator, not an agent profile's rules. Rewrite the entries to the wrapper:

```bash
passless agent mcp install --client claude-code --project <DIR> --profile coding        # dry run
passless agent mcp install --client claude-code --project <DIR> --profile coding --yes  # write
```

Use `--client opencode --user` for `~/.config/opencode/opencode.json`. The entry keeps its name, other
keys and version pin; compatible flags (`--isolated`, `--viewport-size`, ...) pass through, and flags
that choose or attach a browser (`--browser`, `--headless`, `--user-data-dir`, ...) are dropped with a
note. The profile needs `browser_cdp_expose = "port"`. Details: [Browser
tools](browser-tools.md#switching-from-a-plain-playwright-mcp).

The design record is [ADR 0014](../decisions/0014-agent-delegation.md#6-policy).
