# Operations

## Audit

Audit events are hash-chained, owner-only, append-oriented JSONL records. They cover
authorization, credential use, browser leases, denials, policy changes, and degradation.

```bash
passless agent-admin audit status
passless agent-admin audit verify
passless agent-admin audit export --format json
passless agent-admin audit export --format csv
```

- `verify` checks hash-chain integrity across rotations.
- `export` writes non-secret events to a temporary path and reports the location.
- A terminal audit write failure puts agent support in persistent degraded mode until
  an administrator repairs and acknowledges it.
- Human operations remain available during agent audit degradation.

## Disable and revoke

Disable a profile without deleting credentials:

```bash
passless agent-admin profile disable <profile>
```

Revoke an isolated credential:

```bash
passless agent-admin credential revoke <credential-ref> --confirm
```

Revoke an active delegation or session:

```bash
passless agent-admin delegation revoke <grant-id> --confirm
passless agent-admin session revoke <session-id> --confirm
```

## Rollback

To disable all agent functionality:

1. Disable every profile:
   ```bash
   passless agent-admin profile disable <profile>
   ```
2. Revoke all active sessions and delegations.
3. Terminate managed browsers and quarantine profiles that fail cleanup.
4. Set `enabled = false` in configuration or stop the daemon.

Human credentials and configuration are not affected.

## Uninstall

1. Stop the daemon and disable the systemd service.
2. Remove agent configuration from the TOML file.
3. Remove agent storage roots, audit path, and runtime directories.
4. Remove udev rules and tmpfiles configuration.
5. Remove principal and browser Unix users.

Agent data and human data are fully independent. Removing agent data does not require
migrating human credentials.

## Recovery

### Quarantined browser profiles

A profile whose cleanup did not complete is quarantined. The administrator must inspect
and remove it manually:

```bash
sudo ls -la /var/run/passless-browser/
sudo rm -rf /var/run/passless-browser/<quarantined-profile>
```

### Audit discontinuity

If `audit verify` reports a hash-chain break:

1. Do not acknowledge the discontinuity until the cause is known.
2. Preserve the existing audit files.
3. Investigate the gap using wall-clock timestamps and event sequence numbers.
4. After resolution, the daemon continues appending from the last valid record.

### Daemon restart

On restart, the daemon:

- Recovers daemon-owned runtime manifests.
- Terminates verified orphan browser scopes (PID plus process-start identity match).
- Destroys all agent endpoints.
- Loses all in-memory intents and grants.
- Requires new authorization for all subsequent operations.

## Kernel requirements

| Feature | Required for | Notes |
|---|---|---|
| UHID (`uhid` module) | All agent modes | Virtual HID device creation |
| hidraw | Browser access to agent endpoints | Per-profile group policy via udev |
| pidfd / `close_range` | Principal session management | Clean process tree teardown |
| `SOCK_SEQPACKET` | Admin and principal IPC | Versioned local contracts |
| Namespaces / cgroups | Principal isolation | Separate UID, device policy, filesystem policy |

**Supported kernel range:** Linux 7.1.3-1-MANJARO tested. Minimum supported kernel is the oldest distribution kernel providing all of the above. See Phase 0 evidence in `tools/agent-uhid-feasibility/evidence.md` for tested combinations.

## Browser support

**Supported browser range:** Stock Chromium (via Playwright) tested with debug auto-accept UV. Production prompt approval flow is pending validation.

**Browser requirements:**

- Stock browser with WebAuthn support (no modifications, extensions, or native messaging hosts).
- Ability to access hidraw nodes via udev group policy.
- Ephemeral profile support (no personal sync, extensions, or saved state).

**Known limitations:**

- Fresh ephemeral profiles may require federated or cross-site login for some RPs, which broadens practical session authority.
- Browser-control (CDP) output may contain session state; treat it as full-session authority.
- Local lease expiry does not guarantee RP-side session invalidation.

See Phase 0 evidence in `tools/agent-uhid-feasibility/evidence.md` for tested browser versions and RP patterns.

## Browser and endpoint status

Check the status of a profile's endpoint and browser lease:

```bash
passless agent-admin profile check <profile>
passless agent-admin profile show <profile>
```

The `profile check` command reports:

- `endpoint_state`: the current endpoint lifecycle state (`creating`, `ready`, `active`, `draining`, `destroyed`, `failed`).
- `browser_lease_state`: the current browser lease state (if active), including remaining lifetime.
- `policy_generation`: the current policy generation number.
- `audit_gate_healthy`: whether the audit subsystem is operational.
- Per-check diagnostics for enabled state, device identity, storage, and principal isolation.

The `profile show` command reports:

- Active grants, active sessions, and pending intents.
- Policy generation and mode.

Use these commands to verify endpoint readiness before launching a principal session and to diagnose browser lease or endpoint lifecycle issues.

## Skill installation

Install the bundled `passless-agent` Agent Skill for coding agents:

```bash
passless agent-admin install [auto|opencode|claude|pi] [--scope user|project] [--force]
```

**Native skill paths by target:**

| Target | User scope | Project scope |
|---|---|---|
| `opencode` | `~/.config/opencode/skills/passless-agent/SKILL.md` | `.opencode/skills/passless-agent/SKILL.md` |
| `claude` | `~/.claude/skills/passless-agent/SKILL.md` | `.claude/skills/passless-agent/SKILL.md` |
| `pi` | `~/.pi/agent/skills/passless-agent/SKILL.md` | `.pi/skills/passless-agent/SKILL.md` |

Pi paths follow the [official Pi skills documentation](https://raw.githubusercontent.com/badlogic/pi-mono/main/packages/coding-agent/docs/skills.md).

- `auto` detects installed agents by checking user config directories, project directories, and `PATH`.
- `--scope user` installs to the user's home directory; `--scope project` installs to the project root.
- `--force` replaces an existing different skill.
- Installation does not enable an agent profile or grant authentication authority.

## Contrib examples

Example systemd, tmpfiles, udev, and sysusers configurations are provided in `contrib/`:

- `contrib/systemd/passless-agent.service` — systemd service for the agent daemon (runs as root).
- `contrib/systemd/passless.service` — systemd user service for the human authenticator.
- `contrib/tmpfiles/passless-agent.conf` — tmpfiles configuration for agent runtime directories.
- `contrib/udev/70-passless-agent.rules` — udev rules for agent hidraw node permissions (per-profile browser UID).
- `contrib/udev/90-passless.rules` — udev rule for human `/dev/uhid` access (fido group).
- `contrib/modules-load.d/fido.conf` — kernel module autoload for `uhid`.
- `contrib/sysusers.d/passless.conf` — sysusers configuration for the `fido` group.

**Important:** These are examples. Review and adapt them for your distribution and security policy before use. The agent udev rule (`70-passless-agent.rules`) requires placeholder replacement with your profile's device identity and browser UID.

## Known limitations

- Linux only. No remote principals or non-Unix isolation in the first release.
- Delegated mode does not create a new RP-visible agent identity.
- Local lease expiry does not guarantee RP-side session invalidation.
- Passless sees the CTAP RP ID but not the exact web origin.
- Browser-control (CDP) output may contain session state; treat it as full-session authority.
- Host root and kernel compromise are outside the threat model.
- RP-supported OAuth, workload identity, and service accounts are preferred for unattended use.
