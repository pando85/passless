# Isolated mode

Isolated profiles use agent-only credentials with independent storage, PIN state, and
revocation. They cannot see or use human credentials.

An isolated profile can be fully unattended. Setting an exact RP action to `allow` with policy
UP/UV removes the human prompt, but does not make the authenticator unrestricted. Every operation
still requires a one-shot intent and passes the normal endpoint, policy, storage, and audit gates.

## Credential store

Each isolated profile has its own storage backend (local, pass, or TPM) under a
non-overlapping root. Credentials created in one profile are invisible to the human
endpoint and to other profiles.

```toml
[agents]
enabled = true
audit_path = "/var/lib/passless-agent/audit/events.jsonl"

[agents.profiles.release-bot]
mode = "isolated"
principal_user = "passless-release"

[[agents.profiles.release-bot.rules]]
rp_id = "github.com"
register = { authorization = "allow", user_presence = "policy", user_verification = "policy" }
authenticate = { authorization = "allow", user_presence = "policy", user_verification = "policy" }

[agents.profiles.release-bot.storage.local]
path = "/var/lib/passless-agent/release-bot/credentials"
pin_path = "/var/lib/passless-agent/release-bot/pin"

[agents.profiles.release-bot.device]
name = "passless-agent-release"
phys = "release-phys"
uniq = "release-uniq"
vendor_id = 4660
product_id = 22137
```

This profile can register and authenticate at `github.com` without a notification. Policy UP/UV
means that the operator-owned rule authorizes the WebAuthn flags; it does not represent a human
being present or locally verified. See [unattended operation semantics](security.md#unattended-operation-semantics).

## One-shot intents

Every registration and authentication ceremony requires a one-shot intent.

### Registration

```bash
passless agent --profile release-bot intent create register \
  --rp github.com --reason "CI release signing"
```

The intent binds to the first matching CTAP `makeCredential` request. A `confirm` rule displays
the trusted prompt; an `allow` rule resolves it from policy without a notification. The credential
is stored in the profile's isolated store. The intent is consumed on every terminal result.

The principal creates the intent immediately before starting WebAuthn registration. An `allow`
rule does not require an administrator to approve that individual intent.

### Authentication

```bash
passless agent --profile release-bot intent create authenticate \
  --rp github.com --credential <credential-ref-hex> --reason "release push"
```

The intent binds to the exact credential and RP ID. UP and UV use the sources configured in the
exact action rule. The intent is consumed on every terminal result.

## Fully unattended workflow

1. Create the principal Unix user and daemon-owned storage described in
   [configuration](configuration.md#setup).
2. Configure one exact RP rule with `register` and `authenticate` set to `allow`, as shown above.
3. Restart the daemon, then validate the loaded profile and policy:
   ```bash
   passless agent-admin profile check release-bot
   passless agent-admin policy check release-bot
   ```
4. Launch the automation under the configured principal identity:
   ```bash
   passless agent run --profile release-bot -- /usr/local/bin/agent-command
   ```
5. Inside that session, create one registration intent immediately before initiating the matching
   WebAuthn registration:
   ```bash
   passless agent --profile release-bot intent create register \
     --rp github.com --reason "Initial unattended enrollment"
   ```
6. List the resulting isolated credential and retain its non-secret reference:
   ```bash
   passless agent --profile release-bot credential list
   ```
7. For each authentication, create a fresh intent immediately before initiating WebAuthn:
   ```bash
   passless agent --profile release-bot intent create authenticate \
     --rp github.com --credential <credential-ref-hex> --reason "CI release"
   ```

Creating an intent does not itself perform WebAuthn. The following browser or client request must
arrive on the profile's endpoint and match the intent. Each terminal result consumes the intent, so
retries require a new one.

### Boundaries retained without prompts

- Only normalized exact RP IDs with explicit rules are eligible; missing or suffix-only rules deny.
- Each request remains bound to its principal session, endpoint, process identity, policy
  generation, action, RP ID, and credential reference where applicable.
- Credentials and PIN state remain separate from human credentials and every other profile.
- A durable audit reservation is still required before credential creation or use.
- Policy reload, daemon restart, timeout, cancellation, denial, success, and failure invalidate or
  consume the relevant one-shot state.
- The principal cannot modify policy, access daemon-owned storage, or use another endpoint.

## Launch and workflow

```bash
passless agent-admin profile check release-bot
passless agent run --profile release-bot -- /usr/local/bin/agent-command
```

Principal commands (`intent`, `capabilities`, `doctor`, `credential`) run inside the
launched session. The operator launches; the principal requests ceremonies.

### `agent run` behavior

The `agent run` command:

- Requires the daemon to be running as root.
- Requires an absolute executable path (no PATH lookup).
- Attaches stdin/stdout/stderr to the principal process.
- Waits for the principal process to exit and propagates its exit code.
- On Ctrl+C, sends a termination request to the daemon and waits for graceful shutdown.
- The principal process runs as the configured `principal_user` with device policy
  enforced by the daemon.

The command path must be absolute and owned by root to prevent PATH injection or
symlink attacks from the principal user.

## Revocation

```bash
passless agent-admin credential list -d github.com
passless agent-admin credential revoke <credential-ref> --confirm
passless agent-admin credential delete <credential-ref> --confirm
```

Revocation is local. Remove the credential at each RP separately.

## Registration budget

Use `register.authorization = "allow"` only where unattended enrollment is intended. Change it to
`"confirm"` for supervised enrollment or replace the registration policy with an all-`none`
`"deny"` rule after enrollment, then restart the daemon:

```bash
# Edit the exact RP registration rule
sudo systemctl restart passless-agent
```

For example, retain unattended authentication while closing registration:

```toml
[[agents.profiles.release-bot.rules]]
rp_id = "github.com"
register = { authorization = "deny", user_presence = "none", user_verification = "none" }
authenticate = { authorization = "allow", user_presence = "policy", user_verification = "policy" }
```

The daemon loads the updated configuration on restart and recompiles policy. Existing isolated
credentials remain usable for authentication; subsequent registration requests deny. The
`agent-admin policy reload` command recompiles policy from the daemon's in-memory
configuration snapshot and does not read from disk. See
[configuration: policy reload](configuration.md#policy-reload-behavior) for details.
