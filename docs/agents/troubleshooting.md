# Agent troubleshooting

Common issues and diagnostics for agent mode.

## Agent support is disabled

**Symptom:** `passless agent run` or `passless agent-admin` commands fail with "agent support is disabled" or similar.

**Diagnosis:**

```bash
passless agent-admin profile list
# Check if [agents].enabled = true in config
```

**Fix:** Set `enabled = true` in the `[agents]` section of your configuration file and restart the daemon.

## Profile not found

**Symptom:** `passless agent run --profile <name>` fails with "profile not found".

**Diagnosis:**

```bash
passless agent-admin profile list
# Verify the profile exists and is enabled
```

**Fix:** Ensure the profile is defined under `[agents.profiles.<name>]` and `enabled = true` (or the profile-level enabled flag is not false).

## Configuration validation errors

**Symptom:** Daemon fails to start or `passless agent-admin profile check` reports errors.

**Common errors:**

| Error | Cause | Fix |
|-------|-------|-----|
| `delegated-session requires require_uv = true` | Delegated mode must enforce UV | Set `require_uv = true` |
| `delegated-session requires credential_refs` | No credential references configured | Add `credential_refs = ["<hex>"]` |
| `delegated-session requires browser_command` | No browser command configured | Add `browser_command = ["firefox"]` |
| `delegated-session requires browser_user` | No browser user configured | Add `browser_user = "passless-browser-<profile>"` |
| `delegated-session requires browser_runtime_root` | No browser runtime root configured | Add `browser_runtime_root = "/var/run/passless-browser/<profile>"` |
| `isolated mode requires storage backend configuration` | No storage configured | Add `[agents.profiles.<name>.storage.local]` or similar |
| `isolated mode must not specify browser_user` | Isolated mode cannot have browser_user | Remove `browser_user` |
| `device identity collides with the human authenticator` | Device identity matches human endpoint | Change device name/phys/uniq/vendor_id/product_id |
| `agent profile '<name>': storage paths overlap` | Credential and PIN paths overlap | Use non-overlapping paths |
| `unknown field` | Invalid or unsupported field | Remove the field; check configuration reference |

**Diagnosis:**

```bash
passless agent-admin profile check <profile>
passless agent-admin policy check <profile>
```

## Permission denied on agent hidraw node

**Symptom:** Browser cannot access the agent hidraw node; WebAuthn requests fail.

**Diagnosis:**

```bash
ls -l /dev/hidraw*
# Check ownership and permissions of the agent hidraw node
id
# Check if the browser user is in the correct group
```

**Fix:** Ensure the udev rule in `contrib/udev/70-passless-agent.rules` is installed and configured for your profile's device identity. Reload udev rules:

```bash
sudo cp contrib/udev/70-passless-agent.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
```

Verify the browser user matches the `OWNER` or `GROUP` in the udev rule.

## Browser fails to start

**Symptom:** `passless agent run` fails with "browser failed to start" or similar.

**Diagnosis:**

```bash
# Check if the browser command is correct
which firefox
# Check if the browser user exists
id passless-browser-<profile>
# Check journal for errors
journalctl -u passless-agent -n 50
```

**Fix:**

- Ensure `browser_command` is an absolute path or a command in PATH.
- Ensure the browser user exists and has access to the browser binary.
- Ensure `browser_runtime_root` is owned by the browser user with mode `0700`.

## Principal cannot access admin commands

**Symptom:** `passless agent-admin` commands fail when run inside a principal session.

**Diagnosis:** This is expected behavior. Principal sessions cannot access admin commands.

**Fix:** Run admin commands outside the principal session, as the daemon administrator (typically root).

## Audit verification fails

**Symptom:** `passless agent-admin audit verify` reports hash-chain discontinuity.

**Diagnosis:**

```bash
passless agent-admin audit verify
# Review the output for sequence gaps or hash mismatches
```

**Fix:**

1. Do not acknowledge the discontinuity until the cause is known.
2. Preserve the existing audit files.
3. Investigate the gap using wall-clock timestamps and event sequence numbers.
4. After resolution, the daemon continues appending from the last valid record.

## Quarantined browser profile

**Symptom:** Browser profile cleanup failed; profile is quarantined.

**Diagnosis:**

```bash
sudo ls -la /var/run/passless-browser/
# Look for profiles with .quarantined suffix or unusual ownership
```

**Fix:**

```bash
sudo rm -rf /var/run/passless-browser/<quarantined-profile>
```

The administrator must inspect and remove quarantined profiles manually. Do not reuse a quarantined profile.

## Daemon restart loses active sessions

**Symptom:** After daemon restart, all active agent sessions are terminated.

**Diagnosis:** This is expected behavior. Intents, grants, and browser leases are in-memory and lost on restart.

**Fix:** Re-launch the principal session and request new authorization. The daemon terminates verified orphan browser scopes on startup.

## Delegated mode: RP session outlives local lease

**Symptom:** Local browser lease expires, but the RP session remains active.

**Diagnosis:** This is expected behavior. Local lease expiry does not guarantee RP-side session invalidation.

**Fix:** Instruct users to revoke RP sessions through RP controls (e.g., GitHub Settings > Sessions) when compromise or session copying is suspected.

## Isolated mode: credential not found

**Symptom:** `passless agent intent create authenticate --credential <ref>` fails with "credential not found".

**Diagnosis:**

```bash
passless agent-admin credential list --profile <profile>
# Verify the credential reference matches
```

**Fix:** Ensure the credential reference is the correct hex SHA-256 digest. Credential references are non-secret and can be listed without exposing private keys.

## Kernel or distribution not supported

**Symptom:** Agent mode fails with kernel-related errors or missing features.

**Diagnosis:** Check kernel requirements in [operations.md](operations.md#kernel-requirements).

**Fix:** Use a supported kernel and distribution. See Phase 0 evidence in `tools/agent-uhid-feasibility/evidence.md` for tested combinations.

## Further help

- Review the [security model](security.md) for threat model and design rationale.
- Check the [implementation plan](../plans/agent-passkey-implementation.md) for phase status.
- Consult [ADR 0001](../decisions/0001-agent-authentication-security-model.md) and [ADR 0002](../decisions/0002-native-webauthn-agent-architecture.md) for design decisions.
