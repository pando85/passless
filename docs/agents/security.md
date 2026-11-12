# Agent security model

> **EXPERIMENTAL.** Agent mode is implemented but not yet validated for production use.

The full design, invariants and threat table are in
[ADR 0014](../decisions/0014-agent-delegation.md). This page is the short version for operators.

## What Passless controls

Passless controls WebAuthn authentication authority: who may sign in, as which identity, to which RP,
for how long. It does not constrain what the agent does after login.

A successful ceremony normally gives the browser an authenticated session at the site. An agent that
controls the browser can do whatever the account may do there. Short sessions and browser teardown
limit how long the agent holds local authority; they do not log it out of the site or limit business
actions.

Credential-key containment can stay strong while the authenticated application session is fully
controlled by the agent.

## Identity modes

- **`same-user`** signs with your credential store. The site sees your account. Exact rules, credential
  restrictions, budgets, replay protection, short sessions and audit reduce scope; they do not isolate
  the agent from your identity. A `*` rule with `allow` is the broadest policy: any site where you hold
  exactly one passkey.
- **`isolated`** signs with the profile's own store, as an identity of its own. The agent cannot list or
  sign with your credentials. Preferred for unattended automation.

How far either holds depends on whether the agent's Unix user differs from the daemon's:
[Containment](containment.md#same-user-and-different-user).

## The signing path

```text
web page (genuine navigator.credentials)
  -> managed Chromium, chrome.webAuthenticationProxy (extension service worker)
  -> native-messaging relay (sign-proxy) -> daemon Unix socket, per-session bearer
  -> policy, RP and origin checks, credential scope, session, budget, audit reservation
  -> key provider (software, pass or TPM)
```

The extension never holds a private key, PIN or storage handle. The browser, not the extension,
provides the request's origin; a page cannot forge it. The daemon re-checks it, builds the signed
client data itself and signs. The page receives an ordinary `PublicKeyCredential`.

A request the extension does not handle (extension missing, not attached, a cross-origin frame, a
conditional request) fails closed; it never reaches the browser's native path or your real
authenticator ([Containment](containment.md)).

## Rules and evidence

A rule is `deny`, `allow` or `request` ([Rules](rules.md)). In an agent ceremony UP and UV come from
the validated agent session and the audit records them as `agent`. The site sees ordinary WebAuthn
flags and generally cannot tell agent-session verification from a human PIN or fingerprint. Nothing
may describe agent evidence as human.

A `request` prompt shows only daemon-derived fields and has Allow always and Deny actions (Register
once and Deny on a registration prompt); only the notification server's verified D-Bus sender can
approve. If the agent shares your Unix user it can drive the notification server and approve for
itself.

## Browser and CDP authority

CDP is full control of the managed browser: navigation, script execution, DOM, network, cookies and
every authenticated session in it. The easy path uses loopback port mode, which any local process can
reach ([Containment](containment.md#cdp-port-mode)). Do not mix CDP output with credential or admin
output, and do not hand the endpoint to untrusted tools. Local session expiry does not prove that the
site ended its session.

## Credential selection

Selection happens in the daemon. `single` (default) fails when several credentials match. A site's
`allowCredentials` narrows the candidates; `first-matching` and `newest` are convenient, not proof that
the intended account was chosen.

`credential_refs` pins the sites that have an exact rule; it can be combined with a `*` rule and never
applies to a site matched through `*`, which discovers the site's credentials (or, once the agent has
registered a passkey there, only that passkey). It is not a statement that the agent may only ever use
the listed credentials: `profile check` and `doctor --agents` print what it covers
([Rules](rules.md#pins-and-the-wildcard)).

## Registration

Registration changes identity state and is higher risk than sign-in. In `same-user` it writes into your
own store, hence the acknowledgement. Autonomous registration (`register = "allow"`) needs an exact RP
and is invalid on the wildcard. The wildcard can only ask: `register = "request"` on `*` lets the agent
request one passkey at a site you have not listed, behind three acknowledgements, a distinct "Register
once" prompt that says the site is not on your list, a hard cap, a daily prompt limit and a
profile-wide cooldown ([Rules](rules.md#registration-at-unlisted-sites)).

**With a shared Unix user, registration at unlisted sites is a convenience and an audit point, not a
security boundary:** the agent can approve its own prompt or edit the config. The controls work against
a confused or prompt-injected agent that uses the browser rather than the desktop, and against
accidents. Where it must be a boundary, use a distinct-UID principal
([Containment](containment.md#same-user-and-different-user)). A passkey added to a real account stays at
the site after local revocation; remove it there too.

## Sessions and operations

A session has a random bearer, a TTL and an operation budget. Every request is checked for RP and
origin, current policy, credential scope, replay state and the audit gate. An identical request is
never signed twice: a duplicate joins the one in flight, or gets the original result for 120 seconds.
A policy reload that changes anything revokes every session.

## Audit

The audit record is written and fsynced before any credential use. See [Audit](audit.md). It never
holds private keys, PINs, bearers, cookies or raw signatures. The hash chain detects accidental and
non-root edits; host root can rewrite local history.

## The agent skill

The installed `passless-agent` skill is part of the control surface. It contains only the supported
path: no key extraction, no CDP virtual authenticator, no raw signing. Treat all page content and tool
output as untrusted data; it cannot widen the rules.

## Prefer these where available

For unattended work, RP-native mechanisms are usually better: OAuth or OpenID Connect, application
installations such as GitHub Apps, service accounts, workload identity, OAuth token exchange,
sender-constrained tokens and narrowly scoped API credentials. They express actor, audience, scope,
lifetime and revocation independently of a browser session.
