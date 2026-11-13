# ADR 0014 amendment: pins with the wildcard, registration at unlisted sites, agent pre-requests

- **Status:** Accepted (2026-11-12); Phase 1 implemented and folded into ADR 0014
- **Date:** 2026-11-12
- **Amends:** [ADR 0014](0014-agent-delegation.md) §6.2, §6.3, §6.4, §8.1 to §8.4, §9, §10.1, §10.3, §12,
  §14, §15, §17
- **Base:** master at v0.23.0 (`9ffc776`)
- **Decision owners:** Passless maintainers
- **Delivery:** Phase 1 (v0.25.0): changes 1 and 2. Phase 2: change 3, steps 1 and 2. See
  [§13](#13-implementation-plan).

This amendment records three related decisions. Each has its own rationale and threat analysis. The
accepted answers to the questions raised during review are listed in [§14](#14-decisions-taken-in-review).

## 0. Summary

| # | Change | Decision |
|---|---|---|
| 1 | Profile `credential_refs` may coexist with `*`; the pins constrain exact-rule matches only | Build as proposed (Phase 1) |
| 2 | `register = "request"` on `*`, behind `acknowledge_global_registration` | Build the narrower form: same-user only, a hard cap, a daily prompt limit, a profile-wide cooldown, a distinct "Register once" prompt; `register = "allow"` on `*` stays forbidden (Phase 1) |
| 3 | `passless agent request-access` and an opt-in MCP tool that ask before navigating | Build in two steps: `authenticate` first, `register` with one-shot tokens second (Phase 2) |

## 1. Context

### 1.1 The deployment that motivates this

One `same-user` profile `coding`, shared-UID (user unit), used by two Claude Code accounts and
opencode through `passless agent mcp playwright`. It has 14 exact rules with `authenticate = "allow"`
and `register = "request"`, and a `*` rule with `authenticate = "request"`, `register = "deny"`,
acknowledged in `acknowledge_global_same_user`. The notification server is notify-osd 1.0 (fallback
dialog, no `actions` capability, shared id 0, nonced keys per §8.2 of the ADR).

Three problems:

1. Adding `*` forced the operator to drop a 19-entry profile `credential_refs` pin list, because
   `AgentProfileConfig::validate` rejects `credential_refs` whenever a `*` rule exists
   (`passless-core/src/agent/config.rs:1084`). The exact RPs lost their pins.
2. The agent cannot register a passkey at a site that has no exact rule. The only path is for the
   operator to add an exact rule and reload, which revokes every session.
3. Escalation happens only at ceremony time. The agent learns that it needs approval when the page's
   WebAuthn call is already pending, and the login stalls while the human finds the prompt.

### 1.2 Where ADR 0014 forbids wildcard registration, and why

Every place that says a wildcard never permits or requests registration:

- §6.3: `*` is valid only with `register = "deny"`.
- §6.4: same-user registration requires an exact RP and `acknowledge_same_user_registration`.
- §8.3: `register = "request"` is valid only where `register = "allow"` would be valid. Since
  `allow` on `*` is invalid, `request` on `*` is invalid too.
- §10.3: registration "is denied unless the exact rule says `allow`" or an escalation approves it.
- Invariant 19: same-user registration writes to the human backend only under an explicit exact-RP
  registration rule.
- §19, row "Operator-minted enrollment grants": "a wildcard rule never permits registration".
- Code: `config.rs:1090` (the validation error says "a wildcard never permits or requests
  registration"); `resolve.rs:148` (the wildcard is consulted only for `Authenticate`);
  `register.rs:237` and `register.rs:329` (comments); `test_register_under_wildcard_is_always_denied`.
- Docs: `docs/agents/rules.md` (Registration, The wildcard rule), `docs/agents/security.md`
  (Registration), `docs/agents/configuration.md:111`.

The reasons, from §8.2, §13, §15 and the review history:

- **Self-approval.** A same-UID agent can drive the user's notification server and approve its own
  prompt (§8.2, §15). On dunst and mako this is one command. On notify-osd there is no control CLI,
  but a same-UID process can synthesize input to the dialog or replace the server and own
  `org.freedesktop.Notifications`, which makes it the "verified sender". The prompt is a boundary
  only for distinct-UID principals.
- **Real-store pollution.** Same-user registration writes into the human's own credential store
  (and, with the `pass` backend, commits and pushes to the user's Git remote).
- **Identity at arbitrary sites.** A credential created under the user's identity at any site the
  agent reaches, with a persisted autonomous sign-in afterwards.
- **The "`request` is a deferred `allow`" principle (§8.3).** A human is asked to approve only what
  the operator could have written in config.

### 1.3 Why `credential_refs` was forbidden with `*`

The pin list is profile-wide. The sign path builds its candidate set from the session grant's frozen
`credential_refs` when it is non-empty, and from per-RP discovery only when it is empty
(`cmd/passless/src/agent/sign.rs:1823`). Every candidate is then resolved within the request's RP
(`resolve_credential_id`). With pins present, every RP reached through `*` would therefore have an
empty candidate set and fail. The session grant is also built by walking the store for credentials
whose RP is in the grant's RP scope (`runtime.rs:4217`, `runtime/browser_ensure.rs:362`); with `*`
the scope is `["*"]`, no credential matches it, and with pins configured the grant would not be
created at all (`dynamic_credential_scope || !credential_refs.is_empty()`). The rejection was the
simple way to keep both paths consistent, not a security property of its own.

## 2. Decisions

### 2.1 Change 1: profile pins coexist with `*`

**Decision.** Profile `credential_refs` is valid together with a `*` rule. Its meaning becomes, in
every profile: *the pin list constrains operations that resolve through an exact rule; it never
applies to an operation that resolves through `*`.* In a profile without `*` every match is exact, so
the meaning of every configuration that is valid today is unchanged.

Candidate set for one ceremony, by matched rule (replaces the first step of §10.1):

| Matched rule | Profile `credential_refs` | Candidate set |
|---|---|---|
| exact, upgraded by registration grants only | either | the credentials those grants recorded, never discovery or the pins (review M1) |
| exact | set | profile pins ∪ registration-granted refs for this RP (as today) |
| exact | unset | discovery within this RP (as today) |
| `*` | either | discovery within this RP, **unless** the RP has registration-granted refs, then those refs only (new, §2.2 item 3) |

Then, as today: `credential:<ref>` narrows, a non-empty `allowCredentials` chooses within the set,
and the selector applies (`*` is always `single`).

- **A profile pin does not constrain wildcard-matched RPs.** A credential belongs to exactly one RP
  ID, so a pin is meaningful only for its own RP. Making the pin list constrain wildcard RPs "where it
  contains a credential of that RP" was rejected (§10): whether an RP is pinned would depend on
  storage contents, and deleting a pinned credential would silently turn its RP from pinned into
  discovered (fail open). An operator who wants an RP pinned lists it with an exact rule, which can
  carry the same actions as the wildcard (`authenticate = "request"`), so pinning never forces more
  autonomy on an RP.
- **A registered credential joins the pin set** as today for exact rules: the
  `kind = "registration"` granted rule carries `credential_ref`, and the sign path adds the
  registration-granted refs of the RP to the configured pins, live. The daemon never writes the
  config. Wildcard matches: §2.2 item 3.
- **Backward compatibility.** Configs valid today keep their meaning. Configs rejected today
  (pins with `*`) become valid. An older daemon rejects such a config at startup (fail closed). The
  policy digest already covers `credential_refs`.

**Implementation requirements.**

- The sign path chooses the candidate source by `MatchedRule::rule`, not by whether the session
  grant's `credential_refs` is empty.
- Pins are read from the live `PolicySnapshot`, not from a copy frozen in the session grant. A pin
  change is a config change that bumps the revocation epoch, so the result is the same, but the code
  no longer depends on the store walk that cannot see RPs reached through `*`.
- Session-grant creation no longer requires a non-empty filtered ref list when pins are configured;
  the grant's `credentials` field stays for audit and `agent-admin sessions show` only.
- `EffectiveAuthority.credentials` (`runtime.rs:2027`, `AuthorityCredentialScope` in
  `passless-core/src/agent/protocol.rs`) replaces `dynamic_per_rp: bool` with
  `exact_rules: "pinned" | "discovered"` and `wildcard: "discovered" | null`.

**Why relaxing this is safe.** Compared with the configuration the operator is forced into today
(`*` without pins), every exact RP gets strictly fewer usable credentials and every wildcard RP is
unchanged. Compared with pins without `*`, the wildcard's extra reach is the wildcard's own authority,
which already needs `acknowledge_global_same_user`. Exact rules always resolve before `*` (§6.2), so
an operation at a pinned RP can never fall through to discovery. A pin at `login.example.com` does
not restrict a page that asks for RP ID `example.com`; that is a different RP with different
credentials, and it resolves through `*` like any unlisted RP. The one real risk is an operator who
reads the pin list as "the agent may only ever use these credentials". `agent-admin profile check`
and `passless doctor --agents` therefore print, for a profile with both: "credential_refs constrain
the N exact rules; RPs matched by `*` use discovery", and warn about pins whose credential belongs to
an RP that has no exact rule (inert pins).

### 2.2 Change 2: registration at unlisted sites through escalation

**Decision (narrower form).** `register = "request"` becomes valid on the `*` rule of a **same-user**
profile, with all of the following. `register = "allow"` on `*` stays invalid, and resolution maps a
wildcard `register = "allow"` to `deny` as defence in depth. `*` stays same-user only; an isolated
form is future work (§15).

1. **Separate acknowledgement.** The profile is listed in the new
   `agents.acknowledge_global_registration`, in addition to `acknowledge_global_same_user` (already
   required by `*`) and `acknowledge_same_user_registration` (already required by any same-user
   `register` other than `deny`). Three acknowledgements for three separate risks: global sign-in,
   writes to the human store, and creation at unlisted sites.
2. **One approval, one registration.** §8.3 semantics are unchanged: not joinable, a one-use
   `RegistrationApproval` bound to the creating ceremony's session, exactly one registration at
   exactly that RP. After the credential is written the daemon persists `authenticate = allow` for
   that RP with `kind = "registration"`, `rule = "*"` and the credential ref. That grant upgrades the
   `*` rule's `authenticate = "request"` and no other rule's: grants match by the identity of the rule
   they were approved through (`rule = "*"` or `exact`), so if the operator later adds an exact rule
   for the RP, the grant is inert there (`doctor` reports it) and the exact rule asks again. It does
   not create an exact rule, and it becomes inert if the `*` rule's `authenticate` is set to `deny`,
   the rule is removed, or an exact rule takes over the RP (§6.2).
3. **The agent signs in only with its own passkey there.** For an RP matched through `*` that holds
   registration-granted refs, the candidate set is those refs only (table in §2.1), selected with
   `single`. Without this, discovery would find the new credential next to any credential the human
   already has at that RP, and `single` would fail every later sign-in. After the agent registers a
   passkey at an unlisted site, it signs in there only with that passkey, never with one the human
   created. The same holds for an exact rule whose `request` is upgraded by registration grants
   alone ("Register once" at an exact `register = "request"` rule, or an exact rule added later
   next to a grant made through that exact rule): the candidates are the recorded credentials only,
   never discovery and never the pins, because the prompt promised only the new passkey. An exact
   rule that is not upgraded by a registration grant is unchanged: with pins, the refs of grants
   approved through that exact rule join the pins; without pins, discovery. An approved sign-in
   escalation ("Allow always") keeps discovery for its own rule.
4. **Hard cap.** `max_wildcard_registrations` (profile key, default 4) counts the profile's persisted
   granted rules with `kind = "registration"` and `rule = "*"`. At the cap a wildcard registration is
   refused without a prompt (`policy.deny`, `wildcard_registration_cap`). Revoking such a grant frees
   a slot (the credential stays until `agent-admin credential delete`). These entries also count
   against `max_granted_rules`. Pending escalations and approved ceremonies whose grant is not
   written yet hold a slot too (an RAII reservation from approval until the grant write returns or
   the ceremony ends, review L2); otherwise a second registration would be prompted in the gap.
5. **Daily prompt limit.** `wildcard_registration_prompts_per_day` (profile key, default 3): wildcard
   registration prompts per profile in any rolling 24 hours, counted when a prompt is shown. Beyond
   it the request is refused without a prompt (`wildcard_registration_rate`). Exact-rule registration
   prompts do not count. The window is in memory and restarts with the daemon; in a shared-UID
   deployment the agent could restart the daemon anyway, so this is a fatigue limit, not a boundary.
6. **Profile-wide cooldown.** A deny, a timeout, or the third withdrawal within 10 minutes of a
   wildcard registration escalation starts the usual per-key cooldown **and** a profile-wide
   wildcard-registration cooldown of `agents.escalation_cooldown` (default 10 minutes). During it
   every wildcard registration of the profile is refused without a prompt
   (`wildcard_registration_cooldown`). Without it, a page or agent that rotates RP IDs gets a fresh
   prompt for each one.
7. **`localhost` excluded.** The wildcard never matches `localhost` for any action. A `localhost`
   registration needs an exact rule.
8. **Distinct prompt.** §5. "Register once" replaces "Allow always" on every registration prompt,
   exact or `*`, and the prompt shows how many passkeys the store already holds for the site when the
   backend can count them without decrypting (§5.2).

**Where the credential lands.** The human backend, which is the user's real store, through the
shared backend handle and under the human operation lock, exactly as exact-rule same-user
registration does today. With `pass` this includes the automatic Git commit and push, and the RP ID
is part of the committed path. The human's own browser will offer the passkey at that site.

**`register = "allow"` on `*` remains forbidden.** It would let the agent create credentials in the
human store at any site with no human step, bounded only by the cap. Nothing in the motivating use
case needs it, and every reason in §1.2 applies to it at full strength.

**Weighing against the original reasons.**

- *Self-approval.* Unchanged and not fixable. In a shared-UID deployment, such as the motivating
  one, an agent that tries can approve its own prompt on any server, notify-osd included, and can
  also edit the config and reload. **In shared-UID deployments this feature is a convenience, not a
  security boundary.** The prompt, cap, daily limit and cooldown work against a confused or
  prompt-injected agent that uses the browser and its tools rather than attacking the desktop, and
  against accidents. For that threat the prompt is a real control: today an injected agent's
  `create()` at an unlisted site is refused outright; with this change the human must actively click
  "Register once" on a prompt that says the site is not on the list. With a distinct-UID principal the
  prompt is a boundary.
- *Real-store pollution.* Reduced, not removed: at most `max_wildcard_registrations` approved
  credentials per profile, each audited, listed by `agent-admin grants list` with `rule = "*"`, and
  removable. With `pass`, pushed history keeps them.
- *Identity at arbitrary sites.* The important case is not a junk site: a passkey created there is
  useless elsewhere, and its key never leaves the daemon. It is a real site where the agent already
  holds a logged-in session (through a password or cookie) and adds a passkey to the user's real
  account. That converts a session-bound foothold into a persistent one that survives browser
  teardown and local revocation, until the user removes the passkey at the site. A same-user `*`
  `authenticate = "request"` approval already grants persistent sign-in where the user holds a
  passkey; registration extends that to sites where the user does not. The prompt says this (§5.1).
- *`request` is a deferred `allow`.* Each approved outcome (one registration at RP X, then
  `authenticate = allow` at X) is expressible in config as an exact rule for X. What is new is that
  the set of RPs is not enumerated in advance, which is exactly the trade the wildcard
  `authenticate = "request"` already makes. §8.3's sentence becomes: "`register = "request"` is valid
  where `register = "allow"` would be valid, and on the `*` rule of a same-user profile listed in
  `acknowledge_global_registration`."

### 2.3 Change 3: agent-initiated pre-request

**Decision.** A principal may ask for an escalation before it navigates. A pre-request can only lead
to an outcome that a ceremony-time `request` for the same `(profile, rp_id, action)` could lead to,
and only where the live configuration resolves that key to `request`. It never widens policy, never
approves anything, and never reveals whether the user holds a credential. It is built in two steps:
step 1 `authenticate`, step 2 `register` with one-shot tokens and the MCP relay.

**Opt-in.** Per profile, `pre_request_actions` (default `[]`). It changes who can raise a prompt (an
agent with no page) and how cheaply, so the operator turns it on.

**Entry point and authentication.** A new principal-interface request,
`PrincipalRequest::RequestAccess`, authenticated exactly like every principal request: the launcher
capability plus peer credentials, process identity, namespace, cgroup and ancestry (§3 of the ADR).
No bearer, no admin socket. The daemon identifies the requester's `PrincipalSessionId` from that
connection.

- `authenticate` (step 1): allowed from any principal session of the profile. The outcome, a
  persistent per-RP grant, is not session-bound.
- `register` (step 2): allowed only from a principal session that owns a browser lease or will own
  the next one (`browser_scope = "session"`, or the owner under `"profile"`). The token binds to that
  principal session, so a request from a session that cannot run the ceremony is refused
  (`not_requestable`, with a message), not issued.

Surfaces:

- **CLI (step 1, extended in step 2):**
  `passless agent request-access <rp_id> [--register] [--note <text>] [--wait <secs>] [--json]`.
  Inside a principal session (`agent run`) it uses that session. Outside one it re-runs itself in a
  fresh principal session, like the MCP adapters, for `authenticate`; `--register` outside a session
  is an error explaining that the token must belong to the session that owns the browser.
- **MCP tool (step 2), opt-in:** `passless agent mcp playwright --with-access-tool`. The broker
  (inside the browser's principal session) gains one request, `RequestAccess`, next to `Ensure`
  (broker protocol 2), and the wrapper relays the client's stdio to expose one extra tool (§6).
  Without the flag the wrapper behaves exactly as today: Playwright MCP inherits the stdio and no
  tool is added. Since the broker owns the browser's session, `register` tokens issued this way are
  consumable by that browser's ceremonies. Each of the motivating user's three agents has its own
  wrapper and principal session, so tokens never cross between them. Whether the flag becomes the
  default is a later decision.
- No standalone MCP server: it would be a different principal session from the browser's, so it
  could only ever do `authenticate`, which the CLI already covers for agents with a shell.

**Semantics.**

- *Resolution first.* The daemon resolves `(profile, rp_id, action)` against the live config and
  grants. `allow` returns `already_allowed` with no prompt. `deny` or no rule returns
  `not_requestable` with no prompt (audited, coalesced like any refusal). Only `request` continues.
  `rp_id` goes through `validate_rp_id` (normalized, punycode, no IP, no public suffix); `localhost`
  only through an exact rule.
- *Same pipeline.* Then the ceremony-time pre-checks in the same order: cooldown (shared key),
  the wildcard-registration cap, daily limit and profile-wide cooldown (§2.2), grant cap and store,
  bus, queue, waiter caps. A pre-request occupies one waiter slot of its principal session.
- *Authenticate (step 1).* Creates or joins the escalation for the key. Ceremonies that arrive
  while it is pending join it as usual. Approval persists the same grant a ceremony-time approval
  would, with `source = "pre_request"` and no origin. Deny or expiry starts the same per-key cooldown.
- *Register (step 2).* Raises a non-joinable escalation bound to `(profile, rp_id, principal
  session)`. While it is pending, the first registration ceremony of a bearer session owned by that
  principal session at that RP **adopts** it and waits on it as its creating ceremony; any other
  registration ceremony for the key gets `escalation_busy`, as today. If it is approved before a
  ceremony adopts it, the approval becomes a **pre-approval token**.
- *Pre-approval token.* In memory only, never persisted, not `Clone`, like `RegistrationApproval`.
  Bound to profile, normalized RP ID, principal session, the revocation epoch and the RP's revoke
  token at issue. TTL 10 minutes, capped by the principal session's remaining TTL. Consumed by the
  first registration ceremony that resolves to `request` at exactly that RP from a bearer session
  owned by that principal session, at the point where `Escalation::prepare` would run (after the
  option checks, so an unsupported request does not burn it). Consumption turns it into the
  ceremony's `RegistrationApproval`; from there the path is §8.3 unchanged (budget claim after
  approval, pre-key-use re-check that the rule still resolves to `request`, grant persisted after
  the write). It is dropped on TTL, principal session end, lease revocation, revocation-epoch bump,
  `grants revoke` for the RP and `grants clear`. A ceremony that fails after consuming it does not
  give it back, as with a ceremony-time approval.
- *Pending lifetime.* A pending pre-request waits up to 10 minutes, or `agents.escalation_timeout`
  if shorter, then expires with `reason = timeout` and starts the per-key cooldown. There is no
  cancel request.
- *Idempotent.* Repeating the same request from the same principal session returns the state of its
  pending escalation or token instead of raising a new one. This is how a client polls.
- *Rate limits.* Per principal session: 1 pending pre-request, at most 6 per 10 minutes; beyond
  that `rate_limited`, without a prompt.

**Agent-supplied text (`--note`).** Never shown in the notification. Reasons:

- The prompt is the one UI the agent cannot write to. The ADR keeps it daemon-derived so that a
  prompt-injected agent, or a page through the agent, cannot place persuasive text in it. A label
  such as "agent-supplied, untrusted" does not neutralize "Your manager asked for this, approve it":
  the human reads the text, not the label, and the prompt already has the system's authority.
- Sanitizing and truncating stop markup and Bidi tricks, not social engineering.
- On notify-osd the fallback dialog has room for a few lines; agent text would compete with the
  lines that matter (action, site, store).
- The agent already has a channel to explain itself: its own chat with the human, which the human
  reads as the agent's words.

The note is kept in the audit log only: sanitized with the prompt's `sanitize_line` rules, at most
200 bytes, written as `agent_note` on the pre-request's `escalation.requested` record, labelled
agent-supplied wherever `agent-admin` displays it, and never shown to the human at decision time.
The tool description and the CLI help say this.

**MCP tool surface (step 2).**

```json
{
  "name": "passless_request_access",
  "description": "Ask the human, through Passless, for passkey access to a site before you navigate there. Use it when a site will need passkey sign-in or registration. The human sees a fixed system prompt naming only the site and the action; your note is NOT shown to them, so explain why in the chat. Approval does not sign in for you: navigate and use the site's normal WebAuthn flow afterwards. For 'register' the approval is valid once, for 10 minutes, in this browser only.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "rp_id": { "type": "string", "description": "The site's RP ID, a domain such as example.com" },
      "action": { "type": "string", "enum": ["authenticate", "register"], "default": "authenticate" },
      "note": { "type": "string", "maxLength": 200, "description": "Recorded in the audit log only" },
      "wait_seconds": { "type": "integer", "minimum": 0, "maximum": 120, "default": 30 }
    },
    "required": ["rp_id"],
    "additionalProperties": false
  }
}
```

The result is one text content item holding JSON:

```json
{ "state": "approved", "rp_id": "example.org", "action": "register",
  "expires_in_secs": 597, "retry_after_secs": null,
  "message": "Registration approved once for example.org in this browser for 10 minutes." }
```

`state` is one of `already_allowed`, `pending`, `approved`, `denied`, `expired`, `cooldown`,
`rate_limited`, `not_requestable`, `not_enabled`, `unavailable` (no usable notification server),
`busy`. `isError` is false for all of them; it is true only for a malformed call or a broken broker
link. `pending` means "call again later with the same arguments". The CLI's `--json` output is the
same object.

## 3. Config schema changes

```toml
[agents]
enabled = true
audit_path = "/home/alice/.local/state/passless/agent-audit"
acknowledge_global_same_user = ["coding"]
acknowledge_same_user_registration = ["coding"]
acknowledge_global_registration = ["coding"]           # Phase 1 (change 2)

[agents.profiles.coding]
mode = "same-user"
principal_user = "alice"
credential_selection = "single"
credential_refs = ["<ref-01>", "<ref-02>", "<ref-19>"]  # Phase 1: now valid with `*` (change 1)
max_wildcard_registrations = 4                           # Phase 1 (change 2): 1..=32, default 4
wildcard_registration_prompts_per_day = 3                # Phase 1 (change 2): 1..=24, default 3
pre_request_actions = ["authenticate", "register"]       # Phase 2 (change 3): default []

[[agents.profiles.coding.rules]]
rp_id = "github.com"
authenticate = "allow"
register = "request"

[[agents.profiles.coding.rules]]
rp_id = "*"
authenticate = "request"
register = "request"                                     # Phase 1: needs acknowledge_global_registration
```

| Key | Where | Type, range | Default | Phase |
|---|---|---|---|---|
| `acknowledge_global_registration` | `[agents]` | list of profile IDs | `[]` | 1 |
| `max_wildcard_registrations` | profile | integer, 1 to 32 | 4 | 1 |
| `wildcard_registration_prompts_per_day` | profile | integer, 1 to 24 | 3 | 1 |
| `pre_request_actions` | profile | list of `"authenticate"`, `"register"`, no duplicates | `[]` | 2 (`authenticate` in step 1, `register` accepted from step 2) |

Validation (§6.4 additions):

- `credential_refs` with `*`: valid. `credential_selection = "credential:<ref>"` (profile or exact
  rule) must still be in `credential_refs` when it is set.
- `*` with `register = "request"`: the profile is `same-user` and listed in
  `acknowledge_global_registration`, `acknowledge_global_same_user` and
  `acknowledge_same_user_registration`; `authenticate` is `request` or `allow`; the rule's
  `credential_selection`, if set, is `single`. A missing acknowledgement fails startup with a message
  naming it.
- `*` with `register = "allow"`: invalid, with a message pointing to `request`.
- `*` in an isolated profile: still invalid (unchanged).
- `acknowledge_global_registration` naming an unknown profile: invalid, like the other
  acknowledgements. Naming a profile with no `*` `register = "request"` rule: a warning (stale
  acknowledgement).
- `max_wildcard_registrations` outside 1..=32, or `wildcard_registration_prompts_per_day` outside
  1..=24: invalid. Either key set on a profile without a `*` `register = "request"` rule: a warning
  (no effect). A `max_wildcard_registrations` below the number of wildcard registration grants
  already stored is valid; new wildcard registrations are refused until grants are revoked.
- `pre_request_actions` with an unknown value or a duplicate: invalid. Before step 2 ships,
  `"register"` is invalid with a message saying it is not supported yet. `"register"` with no rule
  that has `register = "request"`: a warning.
- The policy digest covers every new key: version 5 to 6 in Phase 1
  (`acknowledge_global_registration`, `max_wildcard_registrations`,
  `wildcard_registration_prompts_per_day`), 6 to 7 in Phase 2 (`pre_request_actions`). Each upgrade
  revokes sessions once.

## 4. Resolution-order changes

`authenticate` (§6.2) is unchanged:

1. exact `deny` gives `deny`;
2. exact `allow` gives `allow`;
3. exact or `*` `request` gives `allow` with a matching granted entry, else `request`;
4. `*` `allow` gives `allow`;
5. otherwise `deny`.

`localhost` never matches `*` (unchanged).

`register` (new; today the wildcard is never consulted):

1. exact `deny` gives `deny`;
2. exact `allow` gives `allow`;
3. exact `request` gives `request`;
4. `*` `request` gives `request` (`rule = "*"`); `*` `allow` gives `deny` (invalid config, defence in
   depth); `localhost` never reaches this step;
5. otherwise `deny`.

The cap, the daily limit and the profile-wide cooldown are escalation pre-checks, not resolution: a
profile at its cap still resolves to `request`, and the pre-check refuses it, so the audit says why.

Credential scope after resolution: the table in §2.1. Invariant 9 gains "a wildcard match never uses
the profile pin list; an exact match always does when one is configured".

## 5. Prompt text

All fields are daemon-derived and rendered by `render_prompt` with the existing sanitizing. The body
stays at seven lines or fewer for notify-osd's fallback dialog.

### 5.1 Registration (Phase 1; any rule; replaces the current registration text)

- Summary: `Passless: CREATE A NEW PASSKEY? (not a sign-in)`
- Body:

```text
Action: create a new passkey and register it at this site
Site: example.org (NOT on your list; matched by the * rule)
Origin: https://www.example.org
Stored in: YOUR passkey store (same-user profile "coding"), which already holds 1 passkey for this site
Approving allows this one registration, then lets the agent sign in here without asking.
Requested by: a page now, principal user alice
```

- Variants:
  - exact rule: `Site: github.com (your rule for this site)`;
  - isolated profile (exact rules only): `Stored in: the agent's own store (isolated profile "release")`;
  - the store count (§5.2): `which already holds N passkeys for this site` for N ≥ 2,
    `which already holds 1 passkey for this site`, `which holds no passkey for this site yet` for 0,
    and the clause omitted entirely when the backend cannot count without decrypting;
  - pre-request (Phase 2): `Origin: none yet` and
    `Requested by: the agent in advance (no page is waiting), principal user alice`.
- Actions: **Register once** and **Deny**. Keys `register_once:<nonce>` and `deny:<nonce>`, with the
  same fresh 128-bit nonce rules as today.

### 5.2 The store count: investigation and outcome

The question was whether the number of passkeys the target store holds for the RP can be obtained
without decrypting any credential. Findings, from `cmd/passless/src/storage/`:

- **Layout, all three backends.** A credential is a file at
  `<root>/<rp_id>/<hex(credential_id)>.<ext>` (`index.rs`, `get_credential_path`). The RP ID is a
  plaintext directory name, validated as a single path component (`rp_id.rs`,
  `ValidatedRpId`). Each adapter builds `CredentialIndexes` at startup with
  `load_credential_paths`, which lists directories and file names only; it keeps `id`, `rp`
  (RP ID to credential IDs) and `rp_hash` maps, and `update_indexes_on_write` and
  `update_indexes_on_delete` keep them current. `CredentialFilter::ByRp` is resolved from that index.
- **local** (`storage/local/mod.rs`, extension `bin`): the index is built from paths; counting is
  `indexes.rp[rp_id].len()`, no file is read.
- **pass** (`storage/pass/mod.rs`, extension `gpg`, under `<store>/<pass_path>/`, default `fido2`):
  the same path layout inside the password store; the RP ID is in the plaintext path (and in Git
  history). The refreshing wrapper (`storage/pass_refresh.rs`) rebuilds the index after an external
  Git change by rescanning paths "without decrypting them", using the HEAD and a metadata
  fingerprint. Counting needs no GPG operation.
- **tpm** (`storage/tpm/mod.rs`, extension `tpm`): the same layout and index; counting needs no
  unseal.
- `CredentialStorage::count_credentials` already counts from the index; the default
  `list_relying_parties` decrypts every credential and must not be used for this.

**Outcome.** The count is cheap for every backend, so every registration prompt shows it. A new
trait method `CredentialStorage::count_for_rp(&self, rp_id: &str) -> Option<usize>` returns the
index count; its default is `None`, and a backend that returns `None` (none today, but a future one
might) gets no count clause at all, never a "0". The pass wrapper runs its cheap refresh check before
counting. The count is read in the register path before the escalation is raised, holding only the
storage lock (level 40), briefly, never the operation lock and never across the wait (LOCKING.md).
It counts files, so it includes a credential file that would fail to decrypt; the wording says
"holds", which is accurate for that. The count is shown to the human only and never returned to the
agent or the page.

### 5.3 Sign-in

- Ceremony-time: unchanged (`Passless: agent sign-in request`, **Allow always** and **Deny**).
- Pre-request (Phase 2): the body adds `Requested by: the agent in advance (no page is waiting)` and
  `Origin: none yet`.

### 5.4 Prompt protocol version 2 (Phase 1)

`PromptRequest.actions` must equal one of two fixed sets,
`[["allow_always","Allow always"],["deny","Deny"]]` or
`[["register_once","Register once"],["deny","Deny"]]`; the child still validates the set and never
shows anything else. The daemon accepts a `decision` of `register_once` only for a registration
prompt, and `allow_always` only for a sign-in prompt; the other is a deny. The protocol version goes
from 1 to 2 (the child is the daemon's own binary, so both sides change together). The minimum
review delay applies to both.

## 6. MCP wrapper relay (Phase 2, step 2, opt-in)

Without `--with-access-tool` nothing changes: Playwright MCP inherits the client's stdio. With it,
the wrapper relays:

- MCP stdio carries newline-delimited JSON-RPC. The wrapper forwards every message in both
  directions byte for byte, except:
  - a response whose `id` answers a client `tools/list` request without a `cursor`: the wrapper
    appends its tool to `result.tools` (later pages are untouched, so pagination still works);
  - a client `tools/call` whose `params.name` is `passless_request_access`: answered by the wrapper
    with the client's own `id`, never forwarded.
- The wrapper never originates requests to either side, so request IDs cannot collide.
  `notifications/tools/list_changed` passes through; the client's re-list gets the tool again.
- A line that does not parse as JSON is forwarded unchanged. A line over 4 MiB is forwarded
  unchanged and never inspected.
- The tool is listed even before a session exists (sessions start lazily); a call on a profile
  without `pre_request_actions` answers `not_enabled`.
- The relay holds no capability or bearer; it only talks to its broker. It is not part of the trust
  boundary, but a bug in it can break the MCP connection, which is why it is opt-in and has its own
  tests.
- `passless agent mcp --print-config` and `agent mcp install` gain the flag only when asked
  (`--with-access-tool` passed through).

`agent mcp chrome-devtools` does not get the tool; agents using it call the CLI.

## 7. Persistence: granted-rules store

**Phase 1: no format change.** A wildcard registration grant is already representable in version 1:
`kind = "registration"`, `rule = "*"`, `origin` and `credential_ref` set. The cap counts those
entries.

**Phase 2: version 2** (`<state_dir>/granted-rules/<profile>.toml`):

```toml
version = 2
profile = "coding"

[[grant]]
rp_id = "example.org"
action = "authenticate"
kind = "registration"
granted_at = "2026-11-12T10:00:00Z"
request_id = "esc-0f3c..."
origin = "https://www.example.org"
rule = "*"
credential_ref = "<hex>"
source = "pre_request"          # new: "ceremony" (default) or "pre_request"

[[grant]]
rp_id = "docs.example.net"
action = "authenticate"
kind = "escalation"
granted_at = "2026-11-12T10:05:00Z"
request_id = "esc-77aa..."
rule = "*"
source = "pre_request"          # an authenticate pre-request has no origin: `origin` is omitted
```

Changes: `origin` becomes optional (absent only for an `authenticate` pre-request); `source` is new
with default `ceremony`. Everything else, including the fail-closed load, the pinned directory handle
and the atomic write, is unchanged. Pre-approval tokens are never persisted.

Migration:

- A version 1 file loads as version 2 with `source = "ceremony"`.
- The writer writes the lowest version that represents its entries: version 1 while every entry has
  an origin and `source = "ceremony"`, version 2 otherwise. A store is rewritten as version 2 only
  once a pre-request grant exists, so a downgrade works until then.
- An older daemon that meets a version 2 file disables grants for that profile (unknown version,
  fail closed) and `passless doctor` reports it. The release notes say so.
- `grants_digest` covers the new field.

## 8. Audit schema

Readers already accept every version, and fields added later default when absent
(`audit_events.rs`, `AUDIT_SCHEMA_VERSION`). Each phase therefore ships its own version.

**Phase 1: version 4.** Operation records (`policy.allow`, `policy.deny`, `policy.replay_served`,
`operation.terminal`) add `credential_scope`, always present: `pinned`, `discovered`,
`registration_pinned`, or null before selection. `SECTION_12_OPERATION_FIELDS` gains it. New
`policy.deny` reasons: `wildcard_registration_cap`, `wildcard_registration_rate`,
`wildcard_registration_cooldown`. Escalation records for a wildcard registration already carry
`rule = "*"` and `action = "register"`.

**Phase 2: version 5.**

- Operation records add `approval_source`: `ceremony` or `pre_request` for an operation that ran on
  an escalation approval or a pre-approval token, null otherwise.
- Escalation records (`escalation.requested`, `approved`, `denied`, `expired`, `revoked`) add
  `source` (`ceremony` or `pre_request`), `principal_session_id_hash`, and `agent_note` (sanitized,
  at most 200 bytes, only on a pre-request's `requested`, null elsewhere); `origin` may be null for a
  pre-request.
- New record kinds: `pre_approval.issued`, `pre_approval.consumed` (with the consuming `request_id`)
  and `pre_approval.expired` (`reason`: `ttl`, `session_end`, `lease_revoked`, `policy_reload`,
  `grant_revoked`).
- New `policy.deny` reasons: `not_requestable`, `pre_request_rate_limited`,
  `pre_request_not_enabled`. They are coalesced like every refusal.

The hash chain is unaffected by either version.

## 9. Threat analysis

What an attacker who controls the agent, or steers it through page content, can newly do.

### 9.1 Change 1

| Deployment | New capability | Notes |
|---|---|---|
| any | None compared with `*` without pins; fewer credentials at exact RPs | The alternative the operator has today is weaker |
| any | An exact RP whose pins are stale fails closed (`credential_not_match`) | It never falls through to `*` |
| any | The operator misreads the pin list as global | Doctor and `profile check` say what it covers |

### 9.2 Change 2

| Deployment | New capability | Bound |
|---|---|---|
| same-user, shared-UID (the motivating one) | Create passkeys in the user's real store at unlisted sites, then sign in there autonomously. **Convenience, not a security boundary:** a hostile agent can self-approve on any notification server, notify-osd included, or simply edit the config, as before | Against a confused or injected agent: the prompt, the cap, the daily limit and the profile-wide cooldown. Against a hostile one: nothing it could not already get by editing the config |
| same-user, distinct-UID | Ask the human to approve a passkey in the user's store at an unlisted site | The prompt is a boundary. Residual: approval by mistake or fatigue, addressed by the distinct wording, the store count, the daily limit and the cooldown |
| isolated | None: `*` stays same-user only | Isolated `*` is future work (§15) |

Residuals common to all: a passkey added to a real account at the RP persists there after local
revocation (RP-side cleanup needed); with `pass`, Git history keeps the credential file and its RP ID
path; the prompt cannot show which account at the site the passkey is for (that is page-supplied
text).

### 9.3 Change 3

| Deployment | New capability | Bound |
|---|---|---|
| any | Raise prompts without a page or navigation, so faster and cheaper | Opt-in per profile; 1 pending and 6 per 10 minutes per session; shared per-key cooldown; one prompt per profile; queue and waiter caps; the change 2 limits for wildcard registration |
| any | Time a prompt to coincide with one the human expects (confusion) | The prompt says "requested in advance, no page is waiting" and names the site; minimum review delay |
| any | Learn whether an RP is already allowed (`already_allowed`) | Rules are already visible through `Authority`; granted state is new but low value. No credential-existence oracle: the store count is shown to the human only, and the pre-request never reports it |
| any | Put text in front of the human | Not possible: the note goes to the audit only |
| any | Hold a registration approval for later | One use, 10 minutes, its own principal session only, in memory, revoked with the session, lease or policy |
| shared-UID | Self-approve a pre-request | Same as ceremony-time; nothing new. A convenience, not a boundary |
| distinct-UID | Nothing beyond the rows above; principal authentication is unchanged | |

## 10. Rejected alternatives

| Alternative | Why rejected |
|---|---|
| Pins constrain a wildcard RP when the pin list contains one of its credentials | Depends on storage contents; deleting a pinned credential turns the RP from pinned to discovered (fail open); needs a storage walk at policy time |
| Per-rule `credential_refs` on exact rules | Equivalent in effect, since a credential belongs to one RP; a second way to say the same thing. Can be added later if wanted |
| Keep forbidding pins with `*` | Forces the weaker configuration the motivating user ended up with |
| `register = "allow"` on `*` | Autonomous creation anywhere; every §1.2 reason at full strength |
| Reuse "Allow always" for registration | It is not "always": one registration. Misleading on the prompt that matters most |
| Registration through `*` without a cap or profile-wide cooldown | Rotating RP IDs gives a fresh prompt each time |
| Same-user wildcard registration only for distinct-UID principals | Removes the feature from the motivating deployment while not protecting it against anything the agent could not already do there; shared-UID use is documented as a convenience instead |
| A store count obtained by decrypting (`list_relying_parties`) | One GPG decryption or TPM unseal per credential under the storage lock, before every prompt; the index makes it unnecessary |
| Show the agent's reason in the prompt, labelled untrusted | The label does not neutralize persuasion; the trusted prompt is the one surface the agent must not write to |
| Pre-approval token bound to the profile only | Transferable between the agents that share a profile; breaks the ADR's "bound to the creating ceremony's session" property |
| Persist pre-approval tokens across restarts | They are short-lived and session-bound; sessions do not survive a restart either |
| Pre-request persists `register = allow` | Contradicts one approval, one registration |
| Pre-request checks whether the user holds a credential at the RP first | A credential-existence oracle for the agent |
| A standalone MCP server for the tool | Its own principal session cannot run the browser's ceremonies, so it could never do `register` |
| The relay on by default | It changes the stdio path of every `agent mcp playwright` user; opt-in until it has field use |
| Approving pre-requests by CLI or API | Already rejected by the ADR (§17); unchanged |

## 11. Test plan

### 11.1 Unit

Phase 1:

- `passless-core` config: the validation matrix for pins with `*`; each acknowledgement missing;
  `*` `register = "allow"` rejected; isolated `*` still rejected; bounds and warnings of
  `max_wildcard_registrations` and `wildcard_registration_prompts_per_day`; digest version 6 covers
  the new keys.
- `resolve.rs`: the register order of §4; `*` `register = "allow"` resolves to `deny`; `localhost`
  never through `*` for either action.
- `sign.rs`: candidate set per matched rule (exact pinned, exact discovered, `*` discovered, `*`
  registration-pinned); a stale pin at an exact RP fails closed and does not consult `*`; pins read
  from the live snapshot; `credential_scope` recorded.
- `register.rs`: wildcard registration end to end with a scripted prompter; cap, daily-limit and
  profile-wide cooldown refusals with their audit reasons; the grant has `rule = "*"`; replace
  `test_register_under_wildcard_is_always_denied` with tests that a wildcard registration without
  the acknowledgement cannot be configured and that `allow` resolves to `deny`; the store count is
  read without the operation lock.
- `escalation.rs`: the profile-wide wildcard cooldown and the 24-hour window, both refusing
  without a prompt and leaving exact-rule registrations unaffected.
- `escalation_prompt.rs` and `prompt.rs`: the two action sets, labels and nonce keys; a mismatched
  decision is a deny; registration text names the store, "NOT on your list" and the count clause in
  its three forms, and omits it for `None`.
- `storage`: `count_for_rp` for local, pass (including after a refresh) and tpm matches the index and
  never decrypts (a pass fixture with a `gpg` that fails if called); the `Box<dyn CredentialStorage>`
  forwarding impl forwards it.
- `granted_rules.rs`: the wildcard-registration count helper.
- `audit_events.rs`: `SECTION_12_OPERATION_FIELDS` for version 4; new deny reasons.

Phase 2:

- `protocol.rs`: `RequestAccess` and `AccessRequestStatus` round trip with `deny_unknown_fields`.
- `escalation.rs`: pre-request lifecycle (join by ceremonies for `authenticate`; adoption by exactly
  one ceremony of the bound principal session for `register`; `escalation_busy` for others); token
  issue, consumption, TTL expiry and every revocation path; idempotent repeat; per-session limits;
  the shared cooldown in both directions.
- `granted_rules.rs`: version 1 loads; the writer keeps version 1 until a pre-request entry exists;
  version 2 round trip; an unknown version disables the profile.
- `escalation_prompt.rs`: pre-request lines; the body never contains agent text (property test with
  hostile notes).
- `audit_events.rs`: version 5 fields, `pre_approval.*` kinds, `agent_note` sanitizing and its
  200-byte bound.
- `mcp_session.rs`: relay framing (`tools/list` first page appended, later pages untouched, the
  tool's `tools/call` answered with the client's `id`, everything else byte-identical, oversized and
  non-JSON lines forwarded); without `--with-access-tool` the stdio is inherited; broker protocol 2
  refuses a version 1 broker cleanly.

### 11.2 Deterministic validation suite (`tools/agent-validation/test-deterministic.sh`)

- The new unit tests run in its cargo phase; no new skips.
- Phase 1: `tests/test-real-notifications.sh` and `stages/real-notifications.sh` cover a
  registration prompt with "Register once" on the private-bus dunst run; a policy fixture set for the
  new validation errors and warnings, run through `passless agent-admin profile check`.
- Phase 2: the same notification run checks that a pre-request body contains no text supplied as a
  note; `tests/test-secret-scanning.sh` gets a fixture `agent_note` holding a token-shaped string,
  flagged in the audit scan, to document that the note is stored.

### 11.3 E2E (`tests/agent-e2e`, new IDs after E2E-57)

| ID | Phase | Scenario |
|---|---|---|
| E2E-58 | 1 | Pins with `*`: an exact RP signs only with its pinned credential; an unlisted RP discovers through `*`; an exact RP whose pin is gone fails with no fallthrough |
| E2E-59 | 1 | Same-user wildcard registration approved: summary, buttons and store count in the prompt, credential in the human store, grant `kind = registration`, `rule = "*"`, next sign-in without a prompt and with the new credential although the human already had one there |
| E2E-59/deny | 1 | Deny starts the per-key and the profile-wide cooldown: a second unlisted RP is refused without a prompt |
| E2E-60 | 1 | Cap and daily limit with non-default values of both keys: the refusal comes without a prompt; revoking one grant frees a cap slot |
| E2E-61 | 1 | Config refusals: `*` `register = "allow"`, missing `acknowledge_global_registration`, isolated `*`; `localhost` never registers through `*` |
| E2E-62 | 1 | Audit version 4 content for E2E-58 to E2E-61 |
| E2E-27 (updated) | 1 | The existing exact-rule registration escalation now shows "Register once" |
| E2E-42/register (local, optional) | 1 | Real dunst: a registration prompt approved through "Register once" |
| E2E-63 | 2, step 1 | `agent request-access` for `authenticate`: approved, then sign-in with no prompt; denied, then the ceremony is in cooldown; `already_allowed` and `not_requestable` without a prompt; `not_enabled` without `pre_request_actions` |
| E2E-64 | 2, step 2 | `--register` token: consumed by the next registration in the same session; refused for another session of the profile; expires after its TTL; dropped when the session ends |
| E2E-65 | 2, step 2 | `agent mcp playwright --with-access-tool`: `tools/list` has Playwright's tools plus `passless_request_access`; a call works; Playwright tools are unaffected; it still survives a daemon restart (E2E-57 harness). Without the flag the tool is absent |
| E2E-66 | 2 | Audit version 5 content for E2E-63 to E2E-65 |

notify-osd 1.0 (the motivating server) cannot run in CI. A manual check on it is part of the Phase 1
release checklist: the fallback dialog shows "Register once" and "Deny", the body fits, and only the
nonced key from it decides.

## 12. Docs to update

Phase 1:

- `docs/decisions/0014-agent-delegation.md`: fold the accepted parts into §6.3, §6.4, §8.2, §8.3,
  §10.1, §10.3, §12, invariants 9 and 19 (new wording: "or a human-approved single registration
  through the acknowledged same-user `*` rule"), a new invariant ("a wildcard match never uses the
  profile pins"), §15, §17, §19 and §20.
- `docs/agents/rules.md` (wildcard, registration, resolution order, credential selection),
  `same-user.md`, `security.md` and `containment.md`: state plainly that in a shared-UID deployment
  registration at unlisted sites is a convenience and an audit point, **not a security boundary**,
  because the agent can approve its own prompt; recommend a distinct-UID principal where it must be
  a boundary.
- `docs/agents/configuration.md` (the new keys and the line at 111), `audit.md` (version 4),
  `operations.md` and `troubleshooting.md` (new refusal reasons), `docs/NOTIFICATIONS.md`
  (the registration prompt, its buttons and the count), `docs/AGENT_REGISTRATION.md`.
- `tests/agent-e2e/README.md`: catalogue entries E2E-58 to E2E-62.

Phase 2:

- ADR 0014: §8.1 (pre-requests), §8.4 (store version 2), §9, §12 (version 5), invariant 10 and new
  invariants ("a pre-request never yields an outcome a ceremony-time request could not"; "no
  agent-supplied text is shown in a prompt").
- `docs/agents/rules.md`: an "Asking in advance" section; `browser-tools.md`: the CLI and
  `--with-access-tool`; `audit.md` (version 5); `configuration.md` (`pre_request_actions`).
- `cmd/passless/assets/skills/passless-agent/SKILL.md`: when to call `passless_request_access` or
  `passless agent request-access`, that the note is not shown, and to explain in chat.
- `tests/agent-e2e/README.md`: E2E-63 to E2E-66.

## 13. Implementation plan

Each phase has a trust-boundary core for an Opus implementer and a CLI, docs, tests and E2E part for
a Sonnet implementer. The core lands first within a phase; Opus reviews the Sonnet part where it
touches the relay or the broker.

### 13.1 Phase 1 (v0.25.0): changes 1 and 2

**Trust-boundary core (Opus).**

- `passless-core/src/agent/config.rs`: `AgentConfig.acknowledge_global_registration` and its checks
  in `AgentConfig::validate` (next to the existing acknowledgement loop and the
  `global_same_user` and `human_backend_registration` checks); `AgentProfileConfig` and
  `AgentProfileConfigRepr` (and `From`) gain `max_wildcard_registrations` and
  `wildcard_registration_prompts_per_day`; `AgentProfileConfig::validate`: remove the
  `credential_refs` rejection in the wildcard block, accept `register = "request"` on `*` under the
  conditions of §3, keep `allow` rejected.
- `passless-core/src/agent/resolve.rs`: `resolve_rules` consults the wildcard for `Register`
  (`request` only; `allow` gives `deny`); module docs.
- `passless-core/src/agent/policy.rs`: `PolicyParams` and the digest, version 6.
- `passless-core/src/agent/protocol.rs`: `AuthorityCredentialScope` (`exact_rules`, `wildcard`).
- `cmd/passless/src/agent/policy_engine.rs`: `compile_snapshot` and `PolicySnapshot` (pins and the
  new limits), `EscalationProfile` (cap, daily limit, wildcard acknowledgement).
- `cmd/passless/src/agent/sign.rs`: the candidate-scope block of `sign_fresh` chooses by
  `MatchedRule::rule` and reads pins from the live snapshot; `*` with registration-granted refs uses
  those only; `credential_scope` to the audit.
- `cmd/passless/src/agent/runtime.rs` (session-grant creation near line 4217; `EffectiveAuthority`
  near 2027) and `runtime/browser_ensure.rs` (near 362): grants with pins and `*`.
- `cmd/passless/src/agent/register.rs`: `register_audited` step 3 for `*`; the store count read
  (storage lock only) before `Escalation::prepare`; the wildcard pre-checks; the grant with
  `rule = "*"` from `register_escalated`.
- `cmd/passless/src/agent/escalation.rs`: wildcard registration cap, 24-hour window and
  profile-wide cooldown in the service's inner state, consulted by `precheck` and `join_or_create`,
  started on deny, timeout and the V-M2 withdrawal limit; new `EscalationRefusal` variants;
  `EscalationRequest` carries the store count and the matched-rule kind into `prompt_fields`.
- `cmd/passless/src/agent/escalation_prompt.rs`: `PromptFields` (rule kind, store, count),
  `render_prompt`, `PROTOCOL_VERSION = 2`, `ACTION_REGISTER_ONCE` and `LABEL_REGISTER_ONCE`,
  `allowed_actions` per verb, `PromptRequest::new` and `validate`, `PromptKeys`.
- `cmd/passless/src/agent/prompt.rs`: decision mapping per verb (the `ACTION_ALLOW_ALWAYS` match).
- `cmd/passless/src/agent/granted_rules.rs`: the wildcard-registration count helper (no format
  change).
- `cmd/passless/src/storage/mod.rs`: `CredentialStorage::count_for_rp` (default `None`) and its
  forwarding in the boxed impl; implementations in `storage/local/mod.rs`, `storage/pass/mod.rs`,
  `storage/pass_refresh.rs` (refresh check first) and `storage/tpm/mod.rs`, from `CredentialIndexes.rp`.
- `cmd/passless/src/agent/audit_events.rs`: version 4, `credential_scope`, the new
  `PolicyDenyReason` variants, `SECTION_12_OPERATION_FIELDS`.

**CLI, docs, tests and E2E (Sonnet).**

- `cmd/passless/src/commands/agent_admin.rs` (`profile check`, `grants list` showing `rule`) and
  `cmd/passless/src/agent/doctor_agents.rs`: the pin-coverage note, inert pins, stale
  acknowledgements, the wildcard registration count against the cap.
- `passless agent capabilities` output for the new `AuthorityCredentialScope`.
- Unit tests outside the core list; the validation-suite additions of §11.2.
- E2E-58, E2E-59, E2E-59/deny, E2E-60, E2E-61, E2E-62, the E2E-27 update and E2E-42/register; the
  harness's notify double accepts the `register_once` key.
- Phase 1 docs (§12) and the notify-osd manual check in the release checklist.

### 13.2 Phase 2: change 3

**Step 1, `authenticate` pre-requests.**

Core (Opus):

- `passless-core/src/agent/protocol.rs`: `PrincipalRequest::RequestAccess { rp_id, action, note,
  wait_ms }`, `PrincipalResponse::AccessRequest(AccessRequestStatus)`.
- `passless-core/src/agent/config.rs` and `policy.rs`: `pre_request_actions` (step 1 accepts
  `authenticate` only), digest version 7.
- `cmd/passless/src/agent/runtime.rs` (`handle_principal`): dispatch, requester identity, resolution
  first, the per-session limits.
- `cmd/passless/src/agent/escalation.rs`: a pre-request waiter (deadline, idempotent repeat, waiter
  slot), joinable by ceremonies; deny and expiry into the shared cooldown.
- `cmd/passless/src/agent/granted_rules.rs`: version 2 (`source`, optional `origin`) and the
  lowest-version writer.
- `cmd/passless/src/agent/escalation_prompt.rs`: the pre-request lines.
- `cmd/passless/src/agent/audit_events.rs`: version 5 fields for `source`,
  `principal_session_id_hash`, `agent_note`, nullable `origin`, `approval_source`; new deny reasons.

Sonnet:

- `cmd/passless/src/commands/agent.rs`: `passless agent request-access` (in-session use, re-run in a
  fresh principal session outside one, `--note`, `--wait`, `--json`).
- `agent-admin grants list` shows `source`; audit display labels `agent_note` as agent-supplied.
- E2E-63 and the step 1 part of E2E-66; step 1 docs and the skill.

**Step 2, `register` pre-approval tokens and the MCP tool.**

Core (Opus):

- `cmd/passless/src/agent/escalation.rs`: the non-joinable pre-register escalation bound to the
  principal session, adoption by one ceremony, the `PreApprovalToken` (issue, TTL, every revocation
  path), conversion into `RegistrationApproval`.
- `cmd/passless/src/agent/register.rs`: token lookup and adoption at the `Escalation::prepare`
  point; `approval_matches` by principal session.
- `cmd/passless/src/agent/session.rs` and `grant.rs`: the owning `PrincipalSessionId` of a bearer
  session, through its session grant.
- `runtime.rs` (`handle_principal`): the lease-ownership check for `register`.
- `audit_events.rs`: `pre_approval.issued`, `consumed`, `expired`.
- `config.rs`: `pre_request_actions` accepts `register`.
- Review of the broker protocol 2 handler (the broker's single new request).

Sonnet:

- `cmd/passless/src/commands/mcp_session.rs`: broker protocol 2 (`BrokerRequest::RequestAccess`,
  its `BrokerMessage`), the stdio relay, the tool definition and result mapping.
- `cmd/passless/src/commands/playwright_mcp.rs` and the `agent mcp` CLI: `--with-access-tool`,
  pass-through in `--print-config` and `agent mcp install`.
- The CLI's `--register`.
- E2E-64, E2E-65 and the step 2 part of E2E-66; step 2 docs and the skill.

## 14. Decisions taken in review

- **Change 1:** build as proposed (Phase 1).
- **Change 2:** build the narrower form (Phase 1).
- **Change 3:** build in two steps, `authenticate` first, `register` with one-shot tokens second
  (Phase 2).
- **Isolated `*`:** deferred; recorded as future work (§15). `*` stays same-user only.
- **Shared-UID same-user registration at unlisted sites:** allowed, and documented plainly as a
  convenience, not a security boundary (§2.2, §9.2, §12).
- **Defaults and keys:** cap 4 (`max_wildcard_registrations`, 1 to 32), 3 prompts per rolling 24
  hours (`wildcard_registration_prompts_per_day`, 1 to 24), 10 minutes for both the pre-approval
  token and the pending pre-request (constants).
- **Store count in the registration prompt:** shown, because all three backends can count from
  their path index without decrypting (§5.2); a backend that cannot gets no clause, never a "0".
- **After an unlisted-site registration** the agent signs in at that site only with the passkey it
  created; exact rules are unchanged (§2.2 item 3).
- **Agent-supplied note:** audit only, sanitized, at most 200 bytes, never shown in the prompt.
- **MCP relay:** opt-in with `--with-access-tool`; making it the default is a later decision.

## 15. Future work

- **Isolated `*`.** An isolated profile could have a `*` rule in one form only:
  `register = "request"` with `authenticate = "request"`, acknowledged in
  `acknowledge_global_registration`, where an `authenticate` ceremony at an RP without a
  registration grant is denied without a prompt (the isolated store can hold a credential for an
  unlisted RP only through such a registration). The credential and the account would be the
  agent's own, with no human-store pollution, which makes it the safer home for agents that create
  accounts. It lifts the "`*` is same-user only" rule of §6.3, so it needs its own amendment.
- **The relay as the default** for `agent mcp playwright`, after field use.
- **The access tool for `agent mcp chrome-devtools`**, if a relay there proves worth it.
