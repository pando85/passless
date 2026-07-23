<h1 align="center">
  <br>
  <img src="https://raw.githubusercontent.com/pando85/passless/master/assets/logo.svg" alt="logo" width="200">
  <br>
  passless
  <br>
  <br>
</h1>

![Build status](https://img.shields.io/github/actions/workflow/status/pando85/passless/rust.yml?branch=master)
![passless license](https://img.shields.io/github/license/pando85/passless)

Passless is a software FIDO2 authenticator that emulates hardware security keys. Built with
[soft-fido2](https://github.com/pando85/soft-fido2), it runs as a virtual UHID device on Linux.

It also includes client capabilities for interacting with any FIDO2 authenticator.

> [!IMPORTANT]
>
> **Client compatibility:** Sandboxed environments (Flatpak, Snap) and some Electron applications
> may not be able to communicate with the authenticator out of the box. The
> [Credentials for Linux](https://github.com/linux-credentials/credentialsd) project is developing
> a system credential service and browser integrations that may provide a portal-style path for
> confined applications. Current integrations are experimental and do not automatically enable
> arbitrary Electron, Flatpak, or Snap applications. See
> [docs/CLIENT_COMPATIBILITY.md](docs/CLIENT_COMPATIBILITY.md) for details on compatibility
> boundaries, troubleshooting, and credentialsd integration.

## ⚠️ Security Warning <!-- omit in toc -->

**Passless is a software FIDO2 authenticator and does not provide the same hardware-backed isolation
as dedicated security keys.** While Passless applies multiple hardening measures (GPG encryption,
memory protection, core dump prevention), credentials stored in software remain more exposed to
system-level compromise than non-exportable keys protected by secure hardware.

For many users, this trade-off is acceptable in exchange for better availability, usability, and
Linux-native integration. However, hardware FIDO2 authenticators offer stronger guarantees against
credential exfiltration and OS-level compromise, and remain the recommended option for high-value
accounts or stricter threat models.

Users should choose the solution that best fits their own security and practicality requirements.

- [Features](#features)
- [Android](#android)
- [Configuration](#configuration)
- [Installation](#installation)
  - [Cargo](#cargo)
  - [Arch Linux](#arch-linux)
- [Permissions and Hardening](#permissions-and-hardening)
- [Acknowledgements](#acknowledgements)

## Features

- FIDO2/WebAuthn authentication without hardware tokens
- Passkey support (resident credentials)
- User verification via desktop notifications or PIN
- PIN support with configurable enforcement policies
- Storage backends:
  - [pass](https://www.passwordstore.org/) (encrypted, git-synced)
  - TPM 2.0 (Experimental), including a [portable TPM backend](docs/TPM_PORTABLE.md)
    with TPM-resident non-exportable keys syncable across devices via a recovery seed
  - Local filesystem (testing only)
- Security hardening (memory locking, core dump prevention)
- Credential management via CTAP commands

## Android

For passkey support on Android, use
[Password Store (Passkey Edition)](https://github.com/pando85/Android-Password-Store). It is a
`pass`-compatible manager that also registers as an Android WebAuthn/passkey Credential Provider,
and reads from the same git-synced `pass` store used by passless — giving you a unified,
cross-platform passkey setup.

## PIN Support

Passless supports optional PIN-based user verification. When a PIN is set, the authenticator
requires PIN verification for WebAuthn operations based on the configured enforcement policy.

### PIN Enforcement Policies

| Policy | `always_uv=false` | `always_uv=true` |
|--------|-------------------|------------------|
| `never` | Notification | Notification |
| `optional` | Notification | **PIN required** |
| `required` | **PIN required** | **PIN required** |

**Default:** `enforcement=optional`, `always_uv=true`

### Behavior Matrix

| PIN Set | `enforcement` | `always_uv` | User Verification Method |
|---------|---------------|-------------|--------------------------|
| No | any | any | Desktop notification |
| Yes | `never` | `false` | Desktop notification |
| Yes | `never` | `true` | Desktop notification |
| Yes | `optional` | `false` | Desktop notification |
| Yes | `optional` | `true` | PIN required |
| Yes | `required` | `false` | PIN required |
| Yes | `required` | `true` | PIN required |

### Setting a PIN

```bash
# Set a new PIN
passless client pin set 1234

# Change existing PIN
passless client pin change 1234 5678
```

### Configuration

```toml
[pin]
# PIN enforcement policy: "never", "optional", "required"
enforcement = "optional"

# Minimum PIN length (4-63 characters)
min_length = 4

# Maximum PIN retry attempts before lockout
max_retries = 8

# Maximum user verification retry attempts before UV is blocked
# Use `passless client pin uv-reset` to restore after authentication
max_uv_retries = 8
```

Note: For enhanced security with hardware-backed protection, consider using the TPM backend
which seals credentials to the TPM hardware. The experimental
[portable TPM backend](docs/TPM_PORTABLE.md) goes further: signing keys are generated inside
the TPM and never exposed to host memory, and credential blobs can be synchronized across
multiple TPMs provisioned from the same recovery seed.

## Configuration

Passless can be configured using a TOML configuration file. By default, the configuration file is
located at `~/.config/passless/config.toml`.

To generate a default configuration file:

```bash
mkdir -p ~/.config/passless
passless config print > ~/.config/passless/config.toml
```

You can then edit this file to customize the storage backend, security settings, and other options.
Command-line arguments will override settings from the configuration file.

## Installation

### Cargo

Install from source with full system integration. See [DEVELOPMENT.md](DEVELOPMENT.md#prerequisites)
for required dependencies.

```bash
# Clone the repository
git clone https://github.com/pando85/passless.git
cd passless

# Install everything (binary, systemd service, udev rules, sysusers config)
make install

# Follow the post-install instructions to:
# 1. Add yourself to the fido group
# 2. Load the uhid kernel module
# 3. Log out and back in
# 4. Enable the systemd service
```

### Arch Linux

```bash
yay -S passless
```

or the binary from AUR:

```bash
yay -S passless-bin
```

## Permissions and Hardening

Passless runs as an unprivileged user and requires only regular-user read/write access to
`/dev/uhid`. Root is neither required nor recommended.

For detailed setup instructions, backend-specific permissions, hardened systemd service examples,
and troubleshooting, see [docs/PERMISSIONS.md](docs/PERMISSIONS.md).

## Single-Instance Enforcement

Only one Passless daemon may own a given backend state directory at a time. Starting a second
daemon against the same backend fails immediately with a clear error. Multiple daemons are
supported only when each uses a different backend state path.

Client commands (`passless client ...`, `passless config print`) do not acquire the daemon lock
and work normally while the authenticator is running.

## Acknowledgements

A big thank you to the [PassKeeZ](https://github.com/Zig-Sec/PassKeeZ) project for being such a
great source of inspiration. Their work on a FIDO2 / Passkey-compatible Linux authenticator gave
this project both motivation and direction.
