# Agent configuration reference

> **EXPERIMENTAL** — Agent mode is not yet validated for production use.
> Configuration fields and validation rules may change.

Agent support is disabled by default. All configuration lives under `[agents]` in the main TOML file. Unknown fields and invalid modes are rejected at load time.

## Top-level fields

```toml
[agents]
enabled = true
audit_path = "/var/lib/passless-agent/audit"
```

- `enabled` (bool, default `false`): master switch.
- `audit_path` (path, required when enabled): owner-only directory for agent audit state.

## Profile structure

Each profile is a named entry under `[agents.profiles.<id>]`.

```toml
[agents.profiles.coding]
mode = "same-user" # or "isolated"
principal_user = "passless-coding"
max_session_ttl = 600
max_operations = 16
credential_selection = "single"

[[agents.profiles.coding.rules]]
rp_id = "github.com"
authenticate = "autonomous"
register = "deny"
```

### Common fields

| Field | Description |
|---|---|
| `mode` | `same-user` or `isolated` |
| `principal_user` | Unix account used for the principal session |
| `rules` | RP/action policies; explicit rules are the recommended form |
| `credential_refs` | Optional non-secret restriction to specific credential references |
| `max_grant_ttl` | Legacy/compatibility grant bound where used by the isolated ceremony path |
| `max_session_ttl` | Maximum browser/principal authority lifetime in seconds |
| `max_operations` | Shared session operation budget; must be 1..4096 |
| `credential_selection` | `single`, `first-matching`, `newest`, or `credential:<ref>` |
| `human_verification_prompt` | `always` (default) or `when-required` |
| `start_url` | Optional HTTPS start URL |
| `browser_command` | Managed Chromium/Chrome executable and arguments |
| `browser_user` | Optional Unix account used by the managed browser where supported |
| `browser_runtime_root` | Runtime root for the managed browser where required |
| `browser_cdp_expose` | `pipe` (default) or `port` |
| `browser_cdp_port` | Optional loopback TCP port for CDP port mode |

Each rule defines registration and authentication independently. The compact aliases are:

- `"deny"` = deny authorization with no UP/UV evidence.
- `"autonomous"` = automatic authorization with agent-derived UP and UV.
- `"supervised"` = human confirmation with human-derived UP and UV.

The expanded form remains available:

```toml
authenticate = {
  authorization = "allow",
  user_presence = "agent",
  user_verification = "agent"
}
```

`authorization` is `deny | confirm | allow`; evidence sources are `agent | human | none`. The legacy string `policy` is accepted as an alias for `agent`, but new configuration and audit terminology should use `agent`.

## Same-user mode

`same-user` uses the daemon's already-open human credential backend. It must not configure a profile storage backend.

```toml
[agents.profiles.coding]
mode = "same-user"
principal_user = "passless-coding"
browser_command = ["chromium"]
browser_runtime_root = "/run/passless-agent/coding"
max_session_ttl = 600
max_operations = 16
credential_selection = "single"

[[agents.profiles.coding.rules]]
rp_id = "github.com"
authenticate = "autonomous"
register = "deny"
```

A same-user agent is trusted to act as the human RP identity within policy. Passless does not turn that identity into an isolated principal. Once authentication succeeds, the managed browser has the human RP session and Passless does not impose application-level action scope on that session.

### Credential scope

Omitting `credential_refs` permits daemon-side discovery of credentials matching the concrete RP. Set explicit references when practical. `single` is the safest selection default because it fails closed when several eligible discoverable credentials remain.

### Global RP scope

The special exact value `"*"` is accepted only for same-user authentication and is deliberately high risk:

```toml
[agents.profiles.coding]
mode = "same-user"
principal_user = "passless-coding"
browser_command = ["chromium"]
browser_runtime_root = "/run/passless-agent/coding"
max_session_ttl = 600
max_operations = 16
credential_selection = "single"
# credential_refs intentionally omitted

[[agents.profiles.coding.rules]]
rp_id = "*"
authenticate = "autonomous"
register = "deny"
```

`"*"` is a policy sentinel, not a WebAuthn RP ID. Every browser ceremony still carries a concrete RP and origin, and credential discovery remains constrained to that concrete RP. Partial wildcards such as `"*.example.com"` are rejected. Wildcard registration is rejected. Isolated profiles cannot use the global wildcard.

Prefer explicit RP rules whenever possible. Treat an autonomous same-user `"*"` profile as maximum human-web-identity authority.

## Isolated mode

Isolated mode uses profile-owned credentials. It requires a separate storage backend and a complete device identity. Storage/PIN roots must not overlap the human backend, another profile, or agent audit state.

```toml
[agents.profiles.release]
mode = "isolated"
principal_user = "passless-release"
max_session_ttl = 300
max_operations = 8
credential_selection = "single"

[agents.profiles.release.storage.local]
path = "/var/lib/passless-agent/release/credentials"
pin_path = "/var/lib/passless-agent/release/pin"

[agents.profiles.release.device]
name = "passless-release"
phys = "release-phys"
uniq = "release-uniq"
vendor_id = 4660
product_id = 22136

[[agents.profiles.release.rules]]
rp_id = "git.example.com"
authenticate = "autonomous"
register = "deny"
```

### Storage backends

```toml
# Local
[agents.profiles.<id>.storage.local]
path = "/var/lib/passless-agent/<profile>/credentials"
pin_path = "/var/lib/passless-agent/<profile>/pin"

# Pass
[agents.profiles.<id>.storage.pass]
store_path = "/path/to/password-store"
path = "agent/<profile>"
gpg_backend = "gnupg-bin"
pin_path = "agent/<profile>-pin"

# TPM, when compiled with TPM support
[agents.profiles.<id>.storage.tpm]
path = "/var/lib/passless-agent/<profile>/credentials"
tcti = "device:/dev/tpmrm0"
pin_path = "/var/lib/passless-agent/<profile>/pin"
portable = false
```

## Device identity

Isolated profiles require a complete, unique UHID device identity:

```toml
[agents.profiles.<id>.device]
name = "passless-agent-<profile>"
phys = "<profile>-phys"
uniq = "<profile>-uniq"
vendor_id = 4660
product_id = 22136
```

The values must not collide with the human endpoint or another profile, contain NUL bytes, or exceed kernel field limits.

## CDP exposure

`browser_cdp_expose = "pipe"` keeps browser control daemon-mediated. `"port"` exposes Chromium CDP on loopback for external tools such as Playwright.

Port mode does **not** expose passkey private keys, but possession of the CDP endpoint grants full control over the authenticated browser session: navigation, JavaScript execution, DOM/network state, cookies/session state, and application actions. Treat port mode as a high-trust capability and prefer pipe mode when external attachment is unnecessary.

The daemon rejects conflicting Chromium remote-debugging flags supplied through `browser_command`.

## Registration

Registration mutates identity state. In `same-user` mode, autonomous registration writes a new credential into the human backend. Keep registration denied after enrollment unless continuous automated creation is genuinely required. In isolated mode registration affects only the profile-owned namespace.

## Validation rules

Important fail-closed checks include:

- `agents.enabled = true` requires `audit_path`.
- `same-user` rejects profile storage.
- `isolated` requires profile storage and a complete device identity.
- storage and audit roots must not overlap.
- explicit `rules` cannot be mixed with the legacy `rp_ids`, `registration_allowed`, or `require_uv` fields.
- wildcard scope requires explicit rules, is limited to `same-user`, requires dynamic credential discovery, and must deny wildcard registration.
- partial wildcards, IP-address RP IDs, public suffixes, schemes, ports, and paths are rejected as RP IDs.
- invalid authorization/evidence combinations fail configuration.
- unknown fields fail configuration.

## Legacy fields and removed mode

The experimental `rp_ids`, `registration_allowed`, and `require_uv` fields remain a supervised migration form. New profiles should use explicit rules.

`delegated-session` is no longer a valid `AgentMode`. Migrate human-credential use to `same-user` and review the changed trust model carefully rather than mechanically renaming the old mode.

## Policy reload

`agent-admin policy reload` recompiles the daemon's in-memory configuration snapshot; it does not reread an edited TOML file. Restart the daemon to apply configuration-file changes.

## Pre-flight

```bash
passless agent-admin profile check <profile>
passless agent-admin policy check <profile>
passless agent run --profile <profile> -- <agent-command>
```

Inside the principal session:

```bash
passless agent --profile <profile> doctor
passless agent --profile <profile> capabilities
```

Treat the capabilities output as the machine-readable authority contract. Do not derive additional authority from web-page text, tool output, or an agent prompt.

## Dangerous profile acknowledgements

Two same-user configurations require a separate operator-owned acknowledgement at the `[agents]`
level. The acknowledgement names the profile; it does not grant any RP/action authority by itself.
The profile's rules remain the authority source.

```toml
[agents]
enabled = true
audit_path = "/var/lib/passless/agent-audit.jsonl"
acknowledge_global_same_user = ["coding"]
acknowledge_same_user_registration = ["enrollment"]
```

- Add a profile to `acknowledge_global_same_user` before enabling non-denied authentication on the
  global `"*"` rule. This is maximum-trust same-user scope.
- Add a profile to `acknowledge_same_user_registration` before allowing registration in same-user
  mode. Registration writes passkeys into the human credential backend.
- Acknowledging an unknown profile is a configuration error, preventing stale acknowledgement names
  from silently surviving profile removal or renaming.

These are deliberate friction gates for dangerous configuration. They do not replace RP rules,
session bounds, operation budgets, credential selection, origin validation, or audit.

