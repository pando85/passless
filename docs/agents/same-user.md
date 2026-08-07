# Same-user mode

> **EXPERIMENTAL** — Same-user mode deliberately gives the configured agent bounded authority to act as the human user for exact relying parties. Review the policy and verification evidence before enabling it.

`same-user` uses the daemon's existing human credential backend. It does not copy, reopen, or export passkey material. Registration and authentication are performed by the daemon through the same storage, key provider, operation lock, signature counters, and local-verification services used by the human authenticator.

This is a trust mode, not an isolation mode. An autonomous same-user agent can authenticate as the human account to every RP and credential permitted by its profile while its session is active. Exact RP rules, credential selectors, TTLs, operation budgets, replay protection, and audit bound that authority; they do not turn the agent into a separate identity.

## Minimal autonomous profile

```toml
[agents]
enabled = true
audit_path = "/var/lib/passless-agent/audit/events.jsonl"

[agents.profiles.opencode]
mode = "same-user"
principal_user = "passless-opencode"
browser_command = ["chromium"]
browser_runtime_root = "/run/passless-agent/opencode"
max_session_ttl = 600
max_operations = 16
credential_selection = "single"

[[agents.profiles.opencode.rules]]
rp_id = "github.com"
authenticate = "autonomous"
register = "deny"
```

The aliases normalize as follows:

- `"deny"`: deny authorization, no UP, no UV.
- `"autonomous"`: automatic authorization with agent-derived UP and UV.
- `"supervised"`: human confirmation with human-derived UP and UV.

The expanded table form remains available:

```toml
authenticate = {
  authorization = "allow",
  user_presence = "agent",
  user_verification = "agent"
}
```

## Credential scope

Omitting `credential_refs` permits discovery of human credentials matching an allowed RP. Narrow the profile to explicit non-secret credential references when practical:

```toml
credential_refs = ["<credential-ref-hex>"]
credential_selection = "credential:<credential-ref-hex>"
```

Other selection policies are `single`, `first-matching`, and `newest`. `single` fails closed when more than one eligible credential exists.

## Registration

Registration is denied unless the exact RP rule explicitly permits it. Autonomous same-user registration writes the new passkey into the human backend through its configured key provider. A newly registered credential is immediately eligible for later authentication in the same bounded browser session, subject to the rule and optional credential scope.

```toml
[[agents.profiles.bootstrap.rules]]
rp_id = "git.example.com"
register = "autonomous"
authenticate = "autonomous"
```

Disable autonomous registration after enrollment when it is no longer needed.

## Session and operation bounds

A browser session receives a random bearer capability, a TTL, and a shared `max_operations` budget covering both registration and authentication. Every WebAuthn request is independently validated against the current policy, exact RP, caller origin, top origin, credential scope, and replay digest. Repeating the same operation body is rejected; distinct operations may continue until the shared budget or session expires.

Human verification can be required by using `user_verification = "human"`. `human_verification_prompt = "always"` prompts whenever that provider is selected; `"when-required"` prompts only when the RP or credential requires UV. Human-derived evidence is never synthesized from an agent rule.

## Browser path

The daemon launches a stock browser with the Passless MV3 extension. A MAIN-world script intercepts `navigator.credentials.create()` and `navigator.credentials.get()`, while the service worker forwards a bounded request to the loopback daemon. The daemon validates and signs; the extension never receives private keys, PINs, storage handles, or arbitrary-signing authority.

## Operational checks

```bash
passless agent-admin profile check opencode
passless agent-admin policy check opencode
passless agent run --profile opencode -- <agent-command>
```

Inside the principal session:

```bash
passless agent --profile opencode doctor
passless agent --profile opencode capabilities
```

Review [security.md](security.md), [operations.md](operations.md), and [audit.md](audit.md) before deployment.
