<h1 align="center">
  <br>
  <img src="https://raw.githubusercontent.com/pando85/passless/master/assets/logo.svg" alt="logo" width="200">
  <br>
  passless
  <br>
  <br>
</h1>

![Build status](https://img.shields.io/github/actions/workflow/status/pando85/passless/rust.yml?branch=main)
![passless license](https://img.shields.io/github/license/pando85/passless)

Software FIDO2 authenticator that emulates a hardware security key. Built with
[rust-keylib](https://github.com/linux-china/rust-keylib) and runs as a virtual UHID device on
Linux.

## ⚠️ Security Disclaimer <!-- omit in toc -->

**Software authenticators lack the physical isolation of dedicated hardware security keys.** While
Passless uses GPG encryption, memory protection, and prevents core dumps to minimize exposure,
credentials stored in software are inherently more vulnerable to system-level compromise than
hardware-isolated keys.

For most use cases, Passless provides a reasonable security model. However, for highly sensitive
accounts or threat models requiring protection against local attackers with elevated privileges,
dedicated hardware security keys remain the recommended option.

- [Features](#features)
- [Configuration](#configuration)
- [Installation](#installation)
  - [Cargo](#cargo)
  - [Arch Linux](#arch-linux)

## Features

- FIDO2/WebAuthn authentication without hardware tokens
- Passkey support (resident credentials)
- User verification via desktop notifications
- Storage backends:
  - Local filesystem (JSON)
  - [pass](https://www.passwordstore.org/) (encrypted, git-synced)
  - TPM 2.0
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

Install from source with full system integration:

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
