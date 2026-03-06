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
> Browsers running in sandboxed environments (for example, installed via the Ubuntu App Center) may
> not be able to communicate with the authenticator out of the box. To enable this, you can use the
> `credentialsd` service provided by the
> ["Credentials for Linux" project](https://github.com/linux-credentials/credentialsd) to allow
> sandboxed apps — including browsers — to access FIDO2 / WebAuthn credentials on Linux.

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
- [Configuration](#configuration)
- [Installation](#installation)
  - [Cargo](#cargo)
  - [Arch Linux](#arch-linux)
- [Acknowledgements](#acknowledgements)

## Features

- FIDO2/WebAuthn authentication without hardware tokens
- Passkey support (resident credentials)
- User verification via desktop notifications
- Storage backends:
  - [pass](https://www.passwordstore.org/) (encrypted, git-synced)
  - TPM 2.0 (Experimental)
  - Local filesystem (testing only)
- **Intel SGX support via Gramine** (hardware memory isolation)
- Security hardening (memory locking, core dump prevention)
- Credential management via CTAP commands

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

### Gramine/Intel SGX

For enhanced security with hardware memory isolation, Passless can run in an Intel SGX enclave using Gramine.

**Requirements:**
- Intel SGX-capable CPU (6th gen or newer)
- SGX enabled in BIOS
- Linux kernel 5.11+

**Quick start:**
```bash
# Build and run with SGX
make gramine-build
make gramine-run
```

See [Gramine Integration Guide](docs/GRAMINE_INTEGRATION.md) for detailed setup instructions.

## Acknowledgements

A big thank you to the [PassKeeZ](https://github.com/Zig-Sec/PassKeeZ) project for being such a
great source of inspiration. Their work on a FIDO2 / Passkey-compatible Linux authenticator gave
this project both motivation and direction.
