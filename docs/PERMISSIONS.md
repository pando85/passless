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
