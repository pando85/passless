# Rules, escalation and grants

> **EXPERIMENTAL.** Agent mode is implemented but not yet validated for production use.

A profile lists rules, one per relying party (RP). A rule sets two independent actions: `authenticate`
(sign in) and `register` (create a passkey). Each is `deny`, `allow` or `request`. A missing action is
`deny`.

```toml
[[agents.profiles.coding.rules]]
rp_id = "github.com"        # exact RP ID: a domain, no scheme, port, path or IP address
authenticate = "allow"
register = "deny"
```

| Action | What happens |
|---|---|
| `deny` | The request is refused before any credential is looked up. Never prompts. |
| `allow` | The daemon signs with no human step, once its other checks pass (origin, session, budget, audit). |
| `request` | The request waits for you. A desktop notification asks, and your answer decides. |

The agent cannot choose, widen or skip a rule. Only you, by editing the config file, can. There is no
human user presence or verification in an agent ceremony: `allow` supplies it from the validated
session, and the audit records the source as `agent`.

## Request: escalation

A `request` rule raises an escalation when the agent makes a request:

1. The daemon shows a notification with daemon-derived text only: profile, mode, principal, action, RP
   ID, origin and whether the approval is persistent. Nothing the page or the agent wrote is shown.
2. The notification has two actions: **Allow always** and **Deny**. Only a click on the real
   notification server counts; no API, CLI or extension message can approve.
3. The web page's WebAuthn call stays pending while you decide. The wait lasts up to the page's own
   timeout (Chromium clamps it to between 3 minutes and 20 hours; 20 hours when the page sets none).
   `agents.escalation_timeout` sets a shorter cap.
4. **Allow always** stores a granted rule and the request continues. Later requests for that RP need
   no prompt.
5. **Deny**, or running out the clock, fails the request with `NotAllowedError` and starts a cooldown
   (10 minutes by default, `agents.escalation_cooldown`) during which requests for that RP are
   denied without a prompt.

Other limits: one prompt per profile at a time, a bounded queue behind it, and a cap on waiting
requests (4 per session and 16 per profile; one profile at its limit does not affect another, and a
global bound of 1024 only protects the daemon's threads). A request over a limit is denied and
audited. When a profile's share of the cooldown table (256 entries) is full, that profile's new
escalations are refused instead of evicting a cooldown; other profiles are unaffected. If
no notification server with action support is running, a `request` is denied immediately and audited;
`passless doctor --agents` warns about this. Headless hosts should use explicit `allow` rules.

Approval of a `register = "request"` rule permits exactly one registration, by the ceremony that
asked. It does not make registration permanent: when the credential is created, Passless stores
`authenticate = allow` for that RP, and the next registration prompts again. A rule with
`register = "request"` needs `authenticate` to be `allow` or `request`.

**An agent that shares your Unix user can drive your notification server** (`dunstctl`, `makoctl`) and
approve its own prompt. Passless cannot prevent this. The approval is only an integrity boundary when
the agent runs as a different user from the one who owns the notification bus. See
[Containment](containment.md#same-user-and-different-user).

## Granted rules

An approved escalation is kept in `<agents.state_dir>/granted-rules/<profile>.toml` (by default
`$XDG_STATE_HOME/passless/agent`). The daemon owns the file; it is never your config. A granted rule
only ever turns `request` into `allow` for one exact RP. It is permanent until you revoke it, and it
becomes inert if you change the config rule to `deny` or remove it. A profile holds at most
`max_granted_rules` of them (default 64, 1 to 256).

```bash
passless agent-admin grants list [--profile coding]
passless agent-admin grants revoke --profile coding --rp github.com --confirm
passless agent-admin grants clear --profile coding --confirm
```

Revoking a grant revokes every active agent session (the next request prompts again), the same as a
policy change. Adding a grant does not. Use the RP's own controls too: revoking locally does not log
the agent out of the site. A store that is malformed or has the wrong owner or mode disables grants
for that profile and `passless doctor` reports it. A grant is inert, never consulted, when no rule
reaches its RP, its rule is now `deny`, or its rule is now `allow`; `passless doctor --agents` and
`agent-admin profile check` list those as orphaned (a warning), and `doctor --agents` also lists the
stores of profiles that no longer exist. (`--confirm` is the real flag of the
destructive admin commands; without it they refuse.)

## Registration

`register = "allow"` is the autonomous setting: the agent may create a passkey at that exact RP with
no prompt. It is never obtained through escalation and never by a wildcard. In `same-user` mode the
new passkey is written into your own credential store, so the profile must also be listed in
`acknowledge_same_user_registration`. In `isolated` mode it lands in the profile's own store. Keep
`register = "deny"` once enrollment is done.

## The wildcard rule

```toml
[agents]
acknowledge_global_same_user = ["coding"]

[[agents.profiles.coding.rules]]
rp_id = "*"
authenticate = "request"
register = "deny"
```

`rp_id = "*"` matches every site. It is only valid in a `same-user` profile listed in
`acknowledge_global_same_user`, must have `register = "deny"`, and cannot use `credential_refs` or a
pinned `credential:<ref>`. Selection is always `single`: when several accounts match, the request
fails rather than choosing one. Every request still carries its concrete RP and origin and only that
RP's credentials are considered. Exact rules win over `*`; a request that matches through `*` is
audited as `rule = "*"`. `localhost` is never matched through the wildcard.

`*` with `allow` is the broadest authority Passless offers: the agent can sign in as you to any site
where you hold exactly one passkey. Prefer `request` on the wildcard and exact `allow` rules for the
sites you trust.

## Resolution order

For one request, the first match wins: exact `deny`; exact `allow`; exact or `*` `request` (upgraded
to `allow` if a granted rule exists for the RP); `*` `allow`; otherwise `deny`. `localhost` and
`http://localhost[:port]` origins are valid for exact rules only.

## Credential selection

`credential_selection` (profile or rule) is `single` (default: fail if several credentials match),
`first-matching`, `newest` or `credential:<ref>`. A pin (`credential:<ref>`) is applied before the
site's `allowCredentials` list, which then chooses within the pinned set. A credential created by an
approved registration joins the pinned set of its RP.

Migrating from older rule spellings: see [Migration](migration.md).
