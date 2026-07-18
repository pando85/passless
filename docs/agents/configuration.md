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
rp_ids = ["<exact-dns-name>"]
require_uv = true | false
device = { name, phys, uniq, vendor_id, product_id }
```

### Fields common to both modes

| Field | Required | Description |
|---|---|---|
| `mode` | yes | `isolated` or `delegated-session` |
| `principal_user` | yes | Separate Unix user that owns the principal session |
| `rp_ids` | no | Exact DNS names; no scheme, port, path, wildcard, trailing dot, IP, or public suffix |
| `require_uv` | yes for delegated | Must be `true` for `delegated-session` |
| `device` | yes | Unique UHID identity; must not collide with human endpoint or other profiles |
| `start_url` | delegated only | HTTPS URL whose host matches exactly one `rp_ids` entry |

### Delegated-session fields

| Field | Required | Description |
|---|---|---|
| `credential_refs` | yes | Non-secret hex references to existing human credentials |
| `max_grant_ttl` | yes | Maximum seconds for the one-shot login grant (1..31536000) |
| `max_session_ttl` | yes | Maximum seconds for the browser lease after assertion |
| `browser_command` | yes | Stock browser executable and arguments |
| `browser_user` | yes | Separate Unix user for the ephemeral browser; must differ from `principal_user` |
| `browser_runtime_root` | yes | Absolute path for ephemeral browser profile state; owned by `browser_user` with mode 0700 |

### Isolated fields

| Field | Required | Description |
|---|---|---|
| `storage` | yes | Backend configuration with non-overlapping root paths |
| `registration_allowed` | no | Whether the profile may create new credentials |

Isolated mode must not set `browser_user` or `browser_runtime_root`.

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
- `delegated-session` requires `require_uv = true`, non-empty `credential_refs`,
  positive `max_grant_ttl` and `max_session_ttl`, `browser_command`, `browser_user`,
  and `browser_runtime_root`.
- `isolated` requires `storage` and must not set `browser_user` or `browser_runtime_root`.
- `browser_user` must differ from `principal_user`.
- `browser_runtime_root` must be absolute and contain no NUL bytes.
- `start_url` must use HTTPS and its host must match exactly one `rp_ids` entry.
- Unknown fields in any section cause load failure.

## Policy reload behavior

The `agent-admin policy reload` command recompiles policy from the daemon's in-memory
configuration snapshot, not from disk. To apply configuration file changes:

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
