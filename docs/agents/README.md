# Agent mode

> **EXPERIMENTAL.** Agent mode is implemented but not yet validated for production use. Interfaces,
> configuration fields and behavior may change without notice.

Agent mode lets AI and browser agents sign in with your passkeys, under rules you write. The agent
drives a Passless-managed Chromium. Passless intercepts the page's WebAuthn calls, applies your policy,
signs in the daemon and records an audit trail. The agent never sees a key.

**Passless limits who may authenticate, as which identity, to which site, and for how long. After a
successful login the agent controls whatever the authenticated browser session allows.** It is not an
application-level authorization proxy.

## Start here

1. [Quick start](quick-start.md): one rule, one command, five minutes.
2. [Browser tools](browser-tools.md): Playwright MCP, chrome-devtools-mcp, the Playwright library,
   browser-use, agent-browser, Stagehand.
3. [Rules](rules.md): `deny`, `allow`, `request`, escalation prompts, granted rules, registration and
   the wildcard.

## Reference

- [Configuration](configuration.md): every field and validation rule.
- [Containment and supported browsers](containment.md): supported browsers, bubblewrap, CDP port mode,
  `passless doctor --agents`.
- [Same-user mode](same-user.md) and [isolated mode](isolated.md): whose passkeys the agent uses.
- [Security model](security.md), [operations](operations.md), [audit](audit.md),
  [troubleshooting](troubleshooting.md).
- [Migration](migration.md): older configuration spellings and their mapping.
- [Agent registration](../AGENT_REGISTRATION.md) and
  [registration testing](../AGENT_REGISTRATION_TESTING.md).
- [ADR 0014](../decisions/0014-agent-delegation.md): the design and its security invariants.

## Two identity modes

- **`same-user`** signs with your own passkeys. The site sees your account. A broad `allow` rule means
  the agent can sign in as you without asking. Prefer exact sites.
- **`isolated`** signs with the profile's own store, as an identity of its own. Recommended for
  unattended automation where the site allows a separate account.

## Prefer these where available

For unattended or narrowly scoped automation, RP-native mechanisms are usually better: scoped OAuth or
OpenID Connect, OAuth token exchange (RFC 8693), sender-constrained tokens (DPoP, RFC 9449, or mutual
TLS), application installations such as GitHub Apps, service accounts and workload identity. They
express actor, audience, scope, lifetime and revocation independently of a browser session.

## Glossary

- **RP ID**: the relying party's identifier in WebAuthn, usually the site's domain (`github.com`). Rules
  match it exactly; it is not the URL in the address bar.
- **CDP**: the Chrome DevTools Protocol, how a tool (Playwright, chrome-devtools-mcp) controls a
  browser. `browser_cdp_expose = "port"` opens a loopback endpoint for it; the default `pipe` has none.
- **Principal session**: the daemon's record of one agent client and its limits (`max_session_ttl`,
  `max_operations`). Each MCP client process that runs `passless agent mcp ...` has one.
- **Lease**: the managed browser a session holds. It closes when its session ends (with
  `browser_scope = "profile"`, when the session that owns it ends).
- **Escalation**: a `request` rule asking you, through a desktop notification, to allow one RP.
  Approving it stores a **granted rule**: a permanent `allow` for that exact RP until you revoke it.
- **UHID / hidraw**: how Passless appears as a USB security key. UHID is the kernel interface the daemon
  uses to create the virtual device; hidraw is the device node clients and browsers open to talk to it.
  Agents get neither: they reach the daemon through the managed browser.
