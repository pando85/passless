# Isolated mode

Isolated profiles use agent-only credentials with independent storage, PIN state, and
revocation. They cannot see or use human credentials.

## Credential store

Each isolated profile has its own storage backend (local, pass, or TPM) under a
non-overlapping root. Credentials created in one profile are invisible to the human
endpoint and to other profiles.

```toml
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

### Authentication

```bash
passless agent --profile release-bot intent create authenticate \
  --rp github.com --credential <credential-ref-hex> --reason "release push"
```

The intent binds to the exact credential and RP ID. UP and UV use the sources configured in the
exact action rule. The intent is consumed on every terminal result.

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

The daemon loads the updated configuration on restart and recompiles policy. The
`agent-admin policy reload` command recompiles policy from the daemon's in-memory
configuration snapshot and does not read from disk. See
[configuration: policy reload](configuration.md#policy-reload-behavior) for details.
