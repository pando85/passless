# Agent configuration reference

Agent support is disabled by default. All configuration lives under `[agents]` in the main
TOML file. Unknown fields and invalid modes are rejected at load time.

## Top-level fields

```toml
[agents]
enabled = true
audit_path = "/var/lib/passless-agent/audit/events.jsonl"
```

- `enabled` (bool, default `false`): master switch. When false, no agent endpoints are created.
- `audit_path` (path, required when enabled): owner-only directory for hash-chained audit events.

## Profile structure

Each profile is a named entry under `[agents.profiles.<id>]`.

```toml
[agents.profiles.<profile-id>]
mode = "isolated" | "delegated-session"
principal_user = "<unix-user>"
device = { name, phys, uniq, vendor_id, product_id }

[[agents.profiles.<profile-id>.rules]]
rp_id = "<exact-dns-name>"
register = { authorization = "deny", user_presence = "none", user_verification = "none" }
authenticate = { authorization = "allow", user_presence = "policy", user_verification = "policy" }
```

### Fields common to both modes

| Field | Required | Description |
|---|---|---|
| `mode` | yes | `isolated` or `delegated-session` |
| `principal_user` | yes | Separate Unix user that owns the principal session |
| `rules` | no | Exact RP registration and authentication policies; missing rules deny |
| `device` | yes | Unique UHID identity; must not collide with human endpoint or other profiles |
| `start_url` | delegated only | HTTPS URL whose host matches exactly one rule |

Each action sets `authorization = "deny" | "confirm" | "allow"`,
`user_presence = "human" | "policy" | "none"`, and
`user_verification = "human" | "policy" | "none"`. `allow` cannot require human UP, and a
denied action must use `none` for both evidence sources.

### Delegated-session fields

| Field | Required | Description |
|---|---|---|
| `credential_refs` | yes | Non-secret hex references to existing human credentials |
| `max_grant_ttl` | yes | Maximum seconds for the one-shot login grant (1..31536000) |
| `max_session_ttl` | yes | Maximum seconds for the browser lease after assertion |
| `browser_command` | yes | Stock browser executable and arguments |
| `browser_user` | yes | Separate Unix user for the ephemeral browser; must differ from `principal_user` |
| `browser_runtime_root` | yes | Absolute path for ephemeral browser profile state; owned by `browser_user` with mode 0700 |
| `delegated_registration_storage` | for registration | Must be `"human"`; omission denies delegated registration |

### Isolated fields

| Field | Required | Description |
|---|---|---|
| `storage` | yes | Backend configuration with non-overlapping root paths |
| `rules[].register` | no | Exact-RP registration decision and evidence sources |

Isolated mode must not set `browser_user` or `browser_runtime_root`.

For fully unattended isolated operation, an exact action may use `authorization = "allow"` with
policy UP/UV. After enrollment, change registration to an all-`none` `deny` rule unless unattended
credential creation must remain available. See the [fully unattended isolated workflow](isolated.md#fully-unattended-workflow).

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

# TPM (requires agent feature)
[agents.profiles.<id>.storage.tpm]
path = "/var/lib/passless-agent/<profile>/credentials"
tcti = "device:/dev/tpmrm0"
pin_path = "/var/lib/passless-agent/<profile>/pin"
```

All storage roots must be non-overlapping with each other, with the human backend, and with the
audit path after canonical and symlink-safe validation.

### Device identity

```toml
[agents.profiles.<id>.device]
name = "passless-agent-<profile>"
phys = "<profile>-phys"
uniq = "<profile>-uniq"
vendor_id = 4660
product_id = 22136
```

- Each field must not contain NUL bytes.
- Length limits reserve 1 byte for the kernel NUL terminator:
  name <= 127, phys <= 63, uniq <= 63.
- The combination must not collide with the human endpoint
  (`virtual-fido` / `0x15d9:0x0a37`) or another profile.

## Validation rules

- `enabled = true` requires `audit_path`.
- `delegated-session` requires non-empty `credential_refs` for authentication, positive
  `max_grant_ttl` and `max_session_ttl`, `browser_command`, `browser_user`, and
  `browser_runtime_root`.
- `isolated` requires `storage` and must not set `browser_user` or `browser_runtime_root`.
- `browser_user` must differ from `principal_user`.
- `browser_runtime_root` must be absolute and contain no NUL bytes.
- `start_url` must use HTTPS and its host must match exactly one rule.
- The legacy experimental `rp_ids`, `registration_allowed`, and `require_uv` fields remain a
  supervised migration form. They cannot be mixed with explicit `rules`.
- Unknown fields in any section cause load failure.

## Migrating legacy profiles

The experimental legacy fields describe one supervised policy for every listed RP:

```toml
rp_ids = ["github.com"]
registration_allowed = true
require_uv = true
```

Replace them with an explicit rule before enabling autonomous behavior:

```toml
[[agents.profiles.<id>.rules]]
rp_id = "github.com"
register = { authorization = "confirm", user_presence = "human", user_verification = "human" }
authenticate = { authorization = "confirm", user_presence = "human", user_verification = "human" }
```

Create one rule per legacy RP ID. Set `register` to an all-`none` `deny` rule when
`registration_allowed` was false, and set `user_verification = "none"` when `require_uv` was false.
Do not keep legacy fields alongside `rules`; mixed forms fail configuration. Change `confirm` to
`allow` and select policy evidence only after reviewing the [security model](security.md#authorization-and-upuv).

## Policy reload behavior

The `agent-admin policy reload` command recompiles policy from the daemon's in-memory
configuration snapshot, not from disk. It cannot apply an edited TOML file. To apply configuration
file changes:

1. Edit the TOML configuration file.
2. Restart the daemon (`systemctl restart passless-agent` or equivalent).
3. The daemon loads the updated configuration and recompiles policy.

The reload command invalidates all active browser leases and pending intents across
all profiles. Use it after configuration changes that affect policy evaluation, not
for routine configuration edits.

## Setup

1. Create the principal Unix user:
   ```bash
   sudo useradd -r -s /usr/sbin/nologin passless-<profile>
   ```
2. Create the browser Unix user (delegated only):
   ```bash
   sudo useradd -r -s /usr/sbin/nologin passless-browser-<profile>
   ```
3. Create daemon-owned storage directories with mode `0700`:
   ```bash
   sudo mkdir -p /var/lib/passless-agent/<profile>
   sudo chown root:root /var/lib/passless-agent/<profile>
   sudo chmod 0700 /var/lib/passless-agent/<profile>
   ```
4. Create the audit directory:
   ```bash
   sudo mkdir -p /var/lib/passless-agent/audit
   sudo chown root:root /var/lib/passless-agent/audit
   sudo chmod 0700 /var/lib/passless-agent/audit
   ```
5. Create the browser runtime directory (delegated only) owned by the browser user:
   ```bash
   sudo mkdir -p /var/run/passless-browser/<profile>
   sudo chown passless-browser-<profile>:passless-browser-<profile> /var/run/passless-browser/<profile>
   sudo chmod 0700 /var/run/passless-browser/<profile>
   ```
6. Validate configuration:
   ```bash
   passless agent-admin profile check <profile>
   passless agent-admin policy check <profile>
   ```
7. Launch the daemon as root (required for principal isolation):
   ```bash
   sudo passless
   ```

See [contrib/](../../contrib/) for systemd, tmpfiles, and udev examples.
