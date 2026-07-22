# Runtime Permissions and Hardened Setup

Passless runs as a regular unprivileged user. Root is neither required nor recommended. This
document describes the minimum permissions needed for the core runtime, optional backend-specific
access, and how to harden the service.

## Core Requirements

### UHID Device Access

Passless communicates with the kernel through `/dev/uhid`. The device must exist and the user must
have read/write access.

**Load the kernel module:**

```bash
sudo modprobe uhid
```

**Make it persistent across reboot:**

```bash
sudo cp contrib/modules-load.d/fido.conf /etc/modules-load.d/
```

This installs a `modules-load.d` snippet containing `uhid` so the module is loaded automatically at
boot.

### Least-Privilege udev Rule

The packaged udev rule grants group-based access to `/dev/uhid`:

```udev
KERNEL=="uhid", GROUP="fido", MODE="0660"
```

**Install the rule:**

```bash
sudo cp contrib/udev/90-passless.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
```

### The `fido` Group

Create the group and add your user:

```bash
# Using systemd-sysusers (recommended on systemd-based systems):
sudo cp contrib/sysusers.d/passless.conf /usr/lib/sysusers.d/
sudo systemd-sysusers

# Or manually:
sudo groupadd fido 2>/dev/null || true
```

Add your user to the group:

```bash
sudo usermod -a -G fido $USER
```

### Verify Access

Log out and back in so the group membership takes effect, then verify:

```bash
# Confirm group membership
id | grep fido

# Confirm device permissions
ls -l /dev/uhid
# Expected: crw-rw---- 1 root fido ... /dev/uhid

# Test read/write access
test -r /dev/uhid && test -w /dev/uhid && echo "access ok"
```

## Daemon vs Client Access

Passless daemon access to `/dev/uhid` is not the same as client access to the virtual FIDO HID
device.

```
Passless requires:         /dev/uhid access (to create virtual authenticator)
WebAuthn client requires:  access to the generated FIDO HID/hidraw device (to send CTAP2 requests)
Brokered setup may use:    credentialsd/portal API instead of direct client HID access
```

- **Passless daemon** opens `/dev/uhid` to register a virtual FIDO2 authenticator with the kernel.
- **WebAuthn client** (browser, Electron app, etc.) opens the generated `/dev/hidraw*` device to
  perform CTAP2 operations.
- **credentialsd** can broker access, allowing confined applications to use Passless without direct
  HID device access.

If Passless starts successfully but a browser or application cannot complete a WebAuthn ceremony,
the issue is likely in the client layer (device permissions, WebAuthn implementation, or package
confinement), not in Passless itself.

See [docs/CLIENT_COMPATIBILITY.md](CLIENT_COMPATIBILITY.md) for application-side troubleshooting,
compatibility boundaries, and diagnostic procedures.

## Optional Backend-Specific Access

### Configuration File

Passless reads its configuration from `~/.config/passless/config.toml`. No special permissions are
needed beyond standard user read access to the file.

### Pass Backend

When using the `pass` storage backend, Passless requires:

- Read/write access to `~/.password-store` (or the path configured in `PASSWORD_STORE_DIR`)
- A valid `.gpg-id` file in the password store directory
- A running GPG agent (`gpg-agent`) with access to the decryption key
- Git access if automatic synchronization is enabled (the store has a git remote)

Verify:

```bash
gpg --list-secret-keys   # confirm the GPG key is available
pass ls                  # confirm password-store is accessible
```

### TPM Backend

When using the TPM 2.0 storage backend, Passless requires:

- Read/write access to `/dev/tpmrm0` (the TPM resource manager device)
- The `tpm2-tss` libraries installed

Typically, the `tss` or `tss2` group owns the TPM device:

```bash
sudo usermod -a -G tss $USER    # or tss2, depending on distribution
```

For software TPM (swtpm) during testing, no special device permissions are needed; access to the
Unix socket or TCP port is sufficient.

### Desktop Notifications

When user verification is performed via desktop notifications, Passless requires access to the user
D-Bus session bus. This is available by default in graphical sessions. When running under a systemd
user service, the `DBUS_SESSION_BUS_ADDRESS` environment variable is typically inherited
automatically.

If notifications fail in a service context, ensure the service unit includes:

```ini
[Service]
# Inherit the D-Bus session bus address from the user session
Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%U/bus
```

## Memory Locking and CAP_IPC_LOCK

Passless locks credential memory with `mlock()` to prevent sensitive data from being swapped to
disk. By default, unprivileged users have a limited `RLIMIT_MEMLOCK` (often 64 KiB), which may be
insufficient.

### Option 1: Increase LimitMEMLOCK in the systemd Service

The packaged systemd service sets `LimitMEMLOCK=2M`. Adjust this value if you see mlock failures:

```ini
[Service]
LimitMEMLOCK=16M
```

### Option 2: Grant CAP_IPC_LOCK to the Binary

Granting `CAP_IPC_LOCK` allows the process to lock unlimited memory without running as root:

```bash
sudo setcap cap_ipc_lock=+ep $(which passless)
```

Verify:

```bash
getcap $(which passless)
# Expected: /path/to/passless cap_ipc_lock=ep
```

> **Note:** File capabilities are cleared when the binary is replaced (e.g., during upgrades).
> Re-run the `setcap` command after each update.

### Option 3: Run with Sufficient MEMLOCK Limit

If neither systemd hardening nor file capabilities are used, ensure the user session has a
sufficient `LimitMEMLOCK`. Check the current limit:

```bash
ulimit -l
```

Set it permanently in `/etc/security/limits.d/`:

```
*    hard    memlock    16384
*    soft    memlock    16384
```

## Hardened Service Example

The following systemd user service applies defense-in-depth hardening. It extends the packaged
`contrib/systemd/passless.service` with additional isolation directives and can be used as a
reference for further lockdown.

```ini
[Unit]
Description=Passless FIDO2 Software Authenticator
Documentation=https://github.com/pando85/passless
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=passless
Restart=on-failure
RestartSec=5s

# Filesystem isolation: read-only system, writable only where needed
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%h/.password-store %h/.config/passless

# Device access: only /dev/uhid (and /dev/tpmrm0 if using TPM backend)
# DeviceAllow is managed by udev; the fido group already restricts access.

# Process isolation
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true

# Network: not required for core operation, but needed for pass git sync
# PrivateNetwork=true    # uncomment only if git sync is not used

# Memory locking: allow mlock for credential protection
LimitMEMLOCK=16M

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=passless

[Install]
WantedBy=default.target
```

Key directives:

| Directive | Purpose |
|-----------|---------|
| `NoNewPrivileges=true` | Prevent privilege escalation via `execve()` |
| `ProtectSystem=strict` | Mount `/usr`, `/boot`, `/efi` read-only |
| `ProtectHome=read-only` | Prevent writes to home directories (except `ReadWritePaths`) |
| `ReadWritePaths` | Allow writes only to the password store and config directory |
| `LimitMEMLOCK` | Allow sufficient memory locking for credential protection |
| `ProtectKernelTunables` | Prevent access to `/proc/sys`, `/sys`, etc. |
| `RestrictSUIDSGID` | Ignore SUID/SGID bits on executed binaries |

Adjust `ReadWritePaths` based on your backend:

- **Pass backend:** `%h/.password-store %h/.config/passless %h/.gnupg`
- **TPM backend:** `%h/.config/passless` (and ensure TPM device access via group)
- **Local backend:** `%h/.config/passless /path/to/local/store`

## Troubleshooting

### Permission denied on /dev/uhid

```
Error: Permission denied (os error 13)
```

**Diagnosis:**

```bash
ls -l /dev/uhid          # check ownership and mode
id | grep fido           # check group membership
```

**Fix:**

1. Ensure the udev rule is installed and reloaded (see [udev rule](#least-privilege-udev-rule)).
2. Ensure you are in the `fido` group: `sudo usermod -a -G fido $USER`.
3. Log out and back in for group changes to take effect.
4. Verify with `test -r /dev/uhid && test -w /dev/uhid && echo "access ok"`.

### No such device: /dev/uhid

```
Error: No such file or directory (os error 2)
```

**Diagnosis:**

```bash
lsmod | grep uhid        # check if module is loaded
```

**Fix:**

```bash
sudo modprobe uhid
# Make persistent:
sudo cp contrib/modules-load.d/fido.conf /etc/modules-load.d/
```

### mlock failed / memory locking unavailable

```
Warning: mlock capability probe failed - memory locking may not be available
```

This is a warning, not a fatal error. Credentials will still work but may be swapped to disk.

**Fix:** See [Memory Locking and CAP_IPC_LOCK](#memory-locking-and-cap_ipc_lock).

### GPG decryption failed (pass backend)

```
Error: GPG agent not available / decryption failed
```

**Diagnosis:**

```bash
gpg --list-secret-keys              # check keys
gpg-connect-agent /bye              # check agent
pass ls                             # test pass directly
```

**Fix:**

1. Ensure `gpg-agent` is running: `gpg-connect-agent /bye`.
2. Verify the GPG key referenced in `.gpg-id` exists.
3. If running under systemd, ensure the service can access the D-Bus session and GPG agent socket.
   You may need:

   ```ini
   [Service]
   Environment=GNUPGHOME=%h/.gnupg
   ```

### TPM device not accessible

```
Error: TPM2 error / device not found
```

**Diagnosis:**

```bash
ls -l /dev/tpmrm0       # check device exists and permissions
id | grep tss            # check group membership
```

**Fix:**

```bash
sudo usermod -a -G tss $USER    # or tss2
# Log out and back in
```

### Desktop notifications not shown

**Diagnosis:**

```bash
echo $DBUS_SESSION_BUS_ADDRESS   # check D-Bus session
```

**Fix:**

If running under systemd, ensure the service inherits the session bus address:

```ini
[Service]
Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%U/bus
```

### Service fails to start with ProtectSystem=strict

If the service fails after enabling strict filesystem isolation, check the journal for denied
access:

```bash
journalctl --user -u passless -n 50
```

Add any required paths to `ReadWritePaths` in the service unit. Common additions:

- `%h/.gnupg` for GPG agent socket access (pass backend)
- `%h/.local/share/passless` if using an alternative data directory

### Another Passless instance is already running

```
Error: another Passless instance is already using backend state:
  /home/user/.password-store/fido2
```

Passless enforces single-instance ownership per backend state directory. A second daemon targeting
the same state is rejected immediately to prevent concurrent read/modify/write corruption.

### Built-in UV stopped working (retry exhaustion)

If authentication silently fails with a notification timeout instead of prompting for UV,
built-in UV retries may be exhausted.

**Diagnosis:**

```bash
systemctl --user status passless
pgrep -a passless
journalctl --user -u passless -n 20
```

**Fix:**

1. Stop the existing instance: `systemctl --user stop passless` (or kill the manual process).
2. If a manually started process and a systemd service are both running, disable one:
   `systemctl --user disable --now passless`.
3. Multiple daemons are supported only when each uses a different backend state path.

Lock files are stored in `$XDG_RUNTIME_DIR/passless/` (or `/tmp/passless-<uid>/passless/` as
fallback). Stale lock files from crashed processes do not block restarts because lock ownership is
attached to the file descriptor, not the file itself.

### Built-in UV stopped working (retry exhaustion)

**Diagnosis:**

```bash
journalctl --user -u passless -n 50 | grep -i "uv"
```

Look for these log messages:

| Message | Meaning |
|---------|---------|
| `UV retry limit is almost exhausted: 1 attempt remaining` | One UV attempt left |
| `UV retries exhausted; built-in user verification is blocked` | UV is blocked (0 retries) |
| `Built-in UV is blocked; falling back to notification-based verification` | Notification fallback active |

**Fix:**

Reset UV retries with an authenticated command:

```bash
passless client pin uv-reset
```

This requires PIN authentication and restores UV retries to the configured maximum
(`pin.max_uv_retries` in config, default 8).

**How `pin.enforcement` affects UV fallback:**

| `pin.enforcement` | `always_uv` | Behavior when UV blocked |
|-------------------|-------------|--------------------------|
| `required` | any | Built-in UV denied; PIN required |
| `optional` | `true` | Built-in UV denied; PIN required |
| `optional` | `false` | Falls back to notification-based UV |
| `never` | any | Falls back to notification-based UV |

## Agent Mode Permissions

Agent mode extends Passless with multiple UHID endpoints, principal sessions, and browser leases.
It requires additional permissions and a different security model than the human authenticator.

### Daemon runs as root

The agent daemon **must run as root** to:

- Create UHID endpoints with deterministic device identity.
- Enforce principal isolation (separate UIDs, namespaces, device policy).
- Manage browser leases and ephemeral profiles.
- Write audit events to owner-only paths.

**Do not** add `User=` or `Group=` directives to the agent systemd service.

### Principal and browser users

Each agent profile requires:

- **Principal user:** A separate Unix user that owns the principal session (configured as `principal_user`).
- **Browser user:** A separate Unix user for the ephemeral browser (configured as `browser_user`, delegated-session only). Must differ from `principal_user`.

Create these users as system users with no login shell:

```bash
sudo useradd -r -s /usr/sbin/nologin passless-<profile>
sudo useradd -r -s /usr/sbin/nologin passless-browser-<profile>
```

### Device permissions

Agent hidraw nodes require per-profile udev rules to grant access **only** to the configured browser user.

**Install the agent udev rule:**

```bash
sudo cp contrib/udev/70-passless-agent.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
```

**Important:** The example rule contains placeholders. Replace `ATTRS{phys}` and `OWNER`/`GROUP` with your profile's device identity and browser user. See `contrib/udev/70-passless-agent.rules` for instructions.

**Do not** grant human users or principals access to `/dev/uhid`. The daemon accesses `/dev/uhid` as root.

### Storage and audit paths

Agent storage and audit paths must be:

- Owned by root with mode `0700`.
- Non-overlapping with each other, with the human backend, and with browser runtime roots.
- Outside every principal boundary.

```bash
sudo mkdir -p /var/lib/passless-agent/<profile>
sudo chown root:root /var/lib/passless-agent/<profile>
sudo chmod 0700 /var/lib/passless-agent/<profile>

sudo mkdir -p /var/lib/passless-agent/audit
sudo chown root:root /var/lib/passless-agent/audit
sudo chmod 0700 /var/lib/passless-agent/audit
```

### Browser runtime root

The browser runtime root (delegated-session only) must be:

- Owned by the configured `browser_user` with mode `0700`.
- Absolute and contain no NUL bytes.
- Non-overlapping with other paths.

```bash
sudo mkdir -p /var/run/passless-browser/<profile>
sudo chown passless-browser-<profile>:passless-browser-<profile> /var/run/passless-browser/<profile>
sudo chmod 0700 /var/run/passless-browser/<profile>
```

### Systemd service

Use the provided `contrib/systemd/passless-agent.service` as a starting point. Key directives:

- `NoNewPrivileges=false` — required because the daemon uses setuid to launch principal and browser processes.
- `ProtectSystem=strict` — read-only system mounts.
- `ProtectHome=read-only` — prevent writes to home directories.
- `ReadWritePaths=/var/lib/passless-agent /var/run/passless-agent` — daemon-owned storage and runtime.
- `LimitMEMLOCK=64M` — sufficient memory locking for agent operations.

### Troubleshooting

See [docs/agents/troubleshooting.md](agents/troubleshooting.md) for common agent mode issues.
