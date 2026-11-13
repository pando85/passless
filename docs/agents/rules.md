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
2. The notification has two actions: **Allow always** and **Deny**. A registration prompt has
   **Register once** and **Deny** instead (see [Registration](#registration)). Only a click on the
   real notification server counts; no API, CLI or extension message can approve.
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
[Containment](containment.md#same-user-and-different-user). Registration at unlisted sites (below) is
affected the same way: with a shared UID it is a convenience and an audit point, not a security
boundary.

## Granted rules

An approved escalation is kept in `<agents.state_dir>/granted-rules/<profile>.toml` (by default
`$XDG_STATE_HOME/passless/agent`). The daemon owns the file; it is never your config. A granted rule
only ever turns `request` into `allow` for one exact RP, and only for the rule it was approved
through: a grant made under the `*` rule turns the wildcard's `authenticate = "request"` into `allow`
for that one RP and does nothing for an exact rule you add for the same RP later (that rule asks
again). It is permanent until you revoke it, and it becomes inert if you change the config rule to
`deny` or remove it. A profile holds at most
`max_granted_rules` of them (default 64, 1 to 256).

```bash
passless agent-admin grants list [--profile coding]
passless agent-admin grants revoke --profile coding --rp github.com --confirm
passless agent-admin grants clear --profile coding --confirm
```

`grants list` prints one table per profile with a header. `KIND` is `escalation` (an approved
sign-in) or `registration` (a credential the agent created, shown in `CREDENTIAL`), and `RULE` is the
configured rule that permitted it: `exact`, or `*` for a grant under the wildcard rule. Wildcard
registration grants count against `max_wildcard_registrations`; revoking one frees a slot (the
credential stays until `agent-admin credential delete`).

```text
coding: 2 rule(s), digest 5c1f...
  RP_ID            ACTION        KIND          RULE   GRANTED_AT            REQUEST   ORIGIN                   CREDENTIAL
  github.com       authenticate  escalation    exact  2026-11-12T10:00:00Z  esc-0a1f  https://github.com       -
  new.example.org  authenticate  registration  *      2026-11-12T10:05:00Z  esc-77aa  https://new.example.org  3b9c...
```

Revoking a grant revokes every active agent session (the next request prompts again), the same as a
policy change. Adding a grant does not. Use the RP's own controls too: revoking locally does not log
the agent out of the site. A store that is malformed or has the wrong owner or mode disables grants
for that profile and `passless doctor` reports it. A grant is inert, never consulted, when no rule
reaches its RP, its rule is now `deny` or `allow`, or a different rule reaches the RP now (a `*`
grant at an RP with an exact rule); `passless doctor --agents` and
`agent-admin profile check` list those as orphaned (a warning), and `doctor --agents` also lists the
stores of profiles that no longer exist. The destructive admin commands (`revoke`, `clear`) refuse to
run without `--confirm`.

## Registration

`register = "allow"` is the autonomous setting: the agent may create a passkey at that exact RP with
no prompt, and it is never valid on the wildcard or stored by an escalation (an approved escalation
only ever permits the one registration that asked, see `register = "request"` above). In `same-user`
mode the new passkey is written into your own credential store, so the profile must also be listed in
`acknowledge_same_user_registration`. In `isolated` mode it lands in the profile's own store. Keep
`register = "deny"` once enrollment is done.

A same-user profile that may register at one site (`"request"` asks you first; `"allow"` does not):

```toml
[agents]
enabled = true
audit_path = "/home/alice/.local/state/passless/agent-audit"
acknowledge_same_user_registration = ["coding"]

[agents.profiles.coding]
mode = "same-user"
principal_user = "alice"
browser_cdp_expose = "port"

[[agents.profiles.coding.rules]]
rp_id = "github.com"
authenticate = "allow"
register = "request"
```

Without the acknowledgement the daemon refuses to start (`passless config check` shows the error).

Every registration prompt, for an exact rule or for `*`, is built to be hard to mistake for a
sign-in. The summary is "CREATE A NEW PASSKEY? (not a sign-in)", and the actions are **Register
once** and **Deny** (not "Allow always": one approval is one registration). The body names whose
store receives the passkey, whether the site is on your list, and how many passkeys that store
already holds for the site when the backend can count them without decrypting anything:

```text
Action: create a new passkey and register it at this site
Site: new.example.org (NOT on your list; matched by the * rule)
Origin: https://new.example.org
Stored in: YOUR passkey store (same-user profile "coding"), which already holds 1 passkey for this site
Approving allows this one registration, then lets the agent sign in here without asking.
Requested by: a page now, principal user alice
```

### Registration at unlisted sites

An exact rule is how you list a site. To let the agent also create a passkey at a site that has no
rule, give the `*` rule `register = "request"`. The profile must be `same-user` and listed in three
acknowledgements, one per risk: `acknowledge_global_same_user` (sign-in anywhere),
`acknowledge_same_user_registration` (writes to your own store) and
`acknowledge_global_registration` (creation at sites you have not listed). `register = "allow"` on
`*` is invalid: nothing lets the agent create passkeys anywhere with no human step.

```toml
[agents]
acknowledge_global_same_user = ["coding"]
acknowledge_same_user_registration = ["coding"]
acknowledge_global_registration = ["coding"]

[agents.profiles.coding]
mode = "same-user"
principal_user = "alice"
max_wildcard_registrations = 4                  # optional, 1 to 32, default 4
wildcard_registration_prompts_per_day = 3       # optional, 1 to 24, default 3

[[agents.profiles.coding.rules]]
rp_id = "*"
authenticate = "request"
register = "request"
```

What bounds it:

- **One approval, one registration.** The approval is not joinable and is bound to the page that asked.
  Afterwards Passless stores `authenticate = allow` for that one RP (`kind = registration`, `rule = *`),
  so the agent signs in there without asking, **with the passkey it created only**, never with one you
  already had at that site. The grant belongs to the `*` rule: it does not create an exact rule, and it
  becomes inert if the `*` rule's `authenticate` is set to `deny`, or if you later add an exact rule for
  that site (which then asks again; `doctor` lists the grant as inert).
- **A hard cap.** At `max_wildcard_registrations` stored wildcard registration grants, a new request is
  refused without a prompt (audit reason `wildcard_registration_cap`). `agent-admin grants revoke`
  frees a slot.
- **A daily limit.** After `wildcard_registration_prompts_per_day` such prompts in a rolling 24 hours,
  further requests are refused without a prompt (`wildcard_registration_rate`). The count is in memory
  and restarts with the daemon. Registrations at exact rules do not count.
- **A profile-wide cooldown.** A deny, a timeout or the third withdrawal within 10 minutes starts the
  usual per-site cooldown and a cooldown for every wildcard registration of the profile
  (`agents.escalation_cooldown`, 10 minutes by default; audit reason `wildcard_registration_cooldown`),
  so a page that rotates through site names cannot make you click again and again.
- **Never `localhost`.** The wildcard does not match it; a `localhost` registration needs an exact rule.

**This is a convenience, not a security boundary, when the agent shares your Unix user.** The agent
could approve its own prompt (`dunstctl`, `makoctl`, a replaced server, input to notify-osd's dialog)
or edit the config. The prompt, the cap, the daily limit and the cooldown protect against a confused or
prompt-injected agent that works through the browser and its tools, and against accidents. Where
registration at unlisted sites must be a boundary, run the agent as a different Unix user from the one
who owns the notification bus ([Containment](containment.md#same-user-and-different-user)).

Residuals: a passkey added to a real account at the site stays there after you revoke it locally, so
remove it at the site too. With the `pass` backend, Git history keeps the credential file and its site
name. The prompt cannot show which account at the site the passkey is for.

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
`acknowledge_global_same_user`. `register` is `deny` (the default) or `request` (see
[Registration at unlisted sites](#registration-at-unlisted-sites)); `register = "allow"` is invalid.
Selection is always `single`: when several accounts match, the request fails rather than choosing one.
Every request still carries its concrete RP and origin and only that RP's credentials are considered.
Exact rules win over `*`; a request that matches through `*` is audited as `rule = "*"`. `localhost` is
never matched through the wildcard.

`*` with `allow` is the broadest authority Passless offers: the agent can sign in as you to any site
where you hold exactly one passkey. Prefer `request` on the wildcard and exact `allow` rules for the
sites you trust.

### Pins and the wildcard

The profile's `credential_refs` can be set together with `*`. The list **pins the exact rules only**:
an operation at a site with its own rule uses only the listed credentials (plus any the agent
registered there), and fails if none is usable, without ever falling through to `*`. An operation
that matches through `*` ignores the list and finds the credentials of that site, or only the ones the
agent registered there once it has registered one. A pin belongs to one site, so it only means
something at its own site. To pin a site, give it an exact rule; that rule can carry the same actions
as the wildcard (`authenticate = "request"`), so pinning never forces more autonomy.

```toml
[agents.profiles.coding]
credential_refs = ["<ref-for-github>", "<ref-for-gitlab>"]   # constrain github.com and gitlab.com

[[agents.profiles.coding.rules]]
rp_id = "github.com"
authenticate = "allow"

[[agents.profiles.coding.rules]]
rp_id = "gitlab.com"
authenticate = "allow"

[[agents.profiles.coding.rules]]
rp_id = "*"                       # every other site: discovery, one prompt per site
authenticate = "request"
```

Do not read the list as "the agent may only ever use these credentials". `passless agent-admin
profile check` and `passless doctor --agents` say what it covers:

```text
[ok]   pin_coverage: credential_refs (2) constrain the 2 exact rule(s); RPs matched by `*` use discovery
[warn] pin_health: warning: pin 689b6f6e0e41 belongs to new.example.org, which has no exact rule: inert (the `*` rule uses discovery, never the pins)
```

They also warn about a pin whose credential is no longer in the store (the exact rules fail closed
until it is restored or the pin is removed) and about an exact rule with no pinned credential in the
store. Pins are located from the store's file names, never by decrypting anything.

## Resolution order

For `authenticate`, the first match wins: exact `deny`; exact `allow`; exact or `*` `request` (upgraded
to `allow` if a granted rule exists for the RP that was approved through that same rule); `*` `allow`;
otherwise `deny`. When the upgrade rests on registration grants only (a "Register once" approval), the
agent may sign in with the credential(s) it created there and no other.

For `register`: exact `deny`; exact `allow`; exact `request`; `*` `request` (only in a profile with the
acknowledgements above); otherwise `deny`. `*` with `register = "allow"` is invalid and would resolve
to `deny` anyway.

`localhost` and `http://localhost[:port]` origins are valid for exact rules only, for both actions.

## Credential selection

`credential_selection` (profile or rule) is `single` (default: fail if several credentials match),
`first-matching`, `newest` or `credential:<ref>`. Which credentials are candidates depends on the rule
that matched:

| Matched rule | `credential_refs` | Candidates |
|---|---|---|
| exact | set | the listed credentials plus those registered at that site |
| exact | not set | every credential of the site |
| `*` | either | every credential of the site, or only those the agent registered there when it has registered any |

A pin (`credential:<ref>`) is applied next, then the site's `allowCredentials` list chooses within the
set, and the selector (`single`, `newest`, ...) breaks any remaining tie. A credential created by an
approved registration joins the candidates of its site. The audit records where the candidates came
from as `credential_scope`: `pinned`, `discovered` or `registration_pinned`.

Migrating from older rule spellings: see [Migration](migration.md).
