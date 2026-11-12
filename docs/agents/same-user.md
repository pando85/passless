# Same-user mode

> **EXPERIMENTAL.** Same-user mode deliberately gives the agent bounded authority to act as you for
> the sites its rules name.

A `same-user` profile signs with the daemon's own credential store: your passkeys. The site sees your
existing account. Passless does not copy or export a key; the daemon does the signing, through the
same storage, key provider, counters and locks as your authenticator.

This is a trust mode, not an isolation mode. After a successful login the managed browser holds your
session at that site, and Passless does not limit what the agent does there: which repository,
purchase, message or settings change. Exact rules, short sessions, operation budgets and audit bound
how long and where the agent can sign in, not what it does afterwards.

## Minimal profile

```toml
[agents]
enabled = true
audit_path = "/home/alice/.local/state/passless/agent-audit"

[agents.profiles.coding]
mode = "same-user"
principal_user = "alice"
browser_cdp_expose = "port"
max_session_ttl = 600
max_operations = 16
credential_selection = "single"

[[agents.profiles.coding.rules]]
rp_id = "github.com"
authenticate = "allow"
register = "deny"
```

Rules, prompts and the wildcard are described in [Rules](rules.md). Start from the
[Quick start](quick-start.md).

## Credential scope

Without `credential_refs` the daemon finds your credentials for the concrete site. Narrow that to
specific credentials when practical:

```toml
credential_refs = ["<credential-ref-hex>"]
credential_selection = "credential:<credential-ref-hex>"
```

`single` fails when more than one credential matches, which is the safest default when you have
several accounts at a site.

`credential_refs` pins the sites that have an exact rule. It can be set together with a `*` rule, and
it never applies to a site that matches through `*` (those discover the site's credentials). A pin
belongs to one site, so list a site with an exact rule to pin it. `agent-admin profile check` and
`passless doctor --agents` print what the list covers and warn about inert or missing pins
([Rules](rules.md#pins-and-the-wildcard)).

## Registration

Registration writes the new passkey into your own store. It needs an exact-RP rule with
`register = "allow"` (or `"request"`), and the profile listed in `acknowledge_same_user_registration`.
Keep `register = "deny"` after enrollment. A `*` rule can also have `register = "request"`, so that the
agent can ask to create a passkey at a site you have not listed; that needs a further acknowledgement
and is bounded by a cap, a daily limit and a cooldown. See [Rules](rules.md#registration) and
[Registration at unlisted sites](rules.md#registration-at-unlisted-sites).

## Latency

A same-user ceremony holds your authenticator's operation lock while it looks for the credential:
a sign reads the credentials stored for the site's RP ID before it signs, and no other site's
credentials. With the `pass` backend that read decrypts each of the site's own credentials (one GPG
operation each), so a site with many passkeys makes each agent ceremony slower, and a request made
through your own authenticator (the physical path) waits behind it for that time. `local` and `tpm`
stores are much cheaper. Pinning `credential_refs` does not skip that read. A registration reads
only the credential IDs in its exclude list. Keep the number of passkeys per site small, or use an
`isolated` profile with its own store, when ceremony latency matters. This is a latency residual,
not a security one; see the ADR's
[threat table](../decisions/0014-agent-delegation.md#15-threats-and-residual-risk).

## Who approves prompts

The agent runs as your Unix user, so it can drive your notification server and approve its own
`request` prompts. A `request` rule in a same-user, same-Unix-user deployment is a convenience and an
audit point, not a security boundary against a hostile agent. That includes registration at unlisted
sites (`register = "request"` on `*`): a convenience, not a security boundary, because the agent can
approve its own prompt. Use a distinct-UID principal where it must be a boundary. See
[Containment](containment.md#same-user-and-different-user).

Operations, audit and recovery: [Operations](operations.md), [Audit](audit.md). Threat model:
[Security](security.md).
