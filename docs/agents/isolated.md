# Isolated mode

> **EXPERIMENTAL.** Agent mode is implemented but not yet validated for production use.

An `isolated` profile has its own credential store, PIN state and key provider. The agent
authenticates as an identity of its own, not as you, and cannot list or sign with your passkeys. Use
it for unattended automation where the site supports a separate automation account or service
identity.

```text
Passless daemon
  |- your credential store           (not available to an isolated profile)
  `- isolated profile "release"
       |- its own credential store, PIN state and key provider (local, pass or TPM)
       |- exact-RP rules
       `- audit
```

## Example

```toml
[agents]
enabled = true
audit_path = "/var/lib/passless-agent/audit"

[agents.profiles.release]
mode = "isolated"
principal_user = "passless-release"
max_session_ttl = 300
max_operations = 8
browser_cdp_expose = "port"

[agents.profiles.release.storage.local]
path = "/var/lib/passless-agent/release/credentials"
pin_path = "/var/lib/passless-agent/release/pin"

[[agents.profiles.release.rules]]
rp_id = "git.example.com"
authenticate = "allow"
register = "allow"
```

Storage roots must not overlap your backend, another profile, the audit path or the granted-rules
directory ([Configuration](configuration.md#same-user-and-isolated-storage)). For a portable TPM
credential the TPM stays the signer; agent mode never substitutes a software key.

An isolated profile does not take `browser_user`. Whether its agent also runs as a different Unix user
decides how real the separation is: with the same Unix user as the daemon the agent can read your
store, the separation is administrative only and startup warns. See
[Containment](containment.md#same-user-and-different-user).

## Enrolling and unattended use

1. Create the Unix user and storage directories (mode 0700).
2. Set the narrowest exact rules. Enrol with `register = "allow"`, then change it to `deny` and
   reload the policy.
3. Check: `passless doctor --agents` and `passless agent-admin profile check release`.
4. Run the agent: `passless agent run --profile release -- <absolute command>`, or use the MCP adapter
   from [Browser tools](browser-tools.md).
5. Review the [audit](audit.md) and the account's state at the site after enrollment or sensitive work.

Isolated registration affects only the profile's own store. `credential_selection = "single"` is the
safest default.

## Revocation

```bash
passless agent-admin credential list [--domain git.example.com]
passless agent-admin credential revoke <credential-ref> --confirm
passless agent-admin credential delete <credential-ref> --confirm
passless agent-admin profile disable release
```

Revoking or deleting a credential locally does not remove it from the site's account or end a
session the site has already started; use the site's own controls too.

The shared threat model is in [Security](security.md); audit and recovery in [Operations](operations.md).
