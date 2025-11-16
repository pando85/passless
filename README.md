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

TODO

- [Features](#features)
- [Installation](#installation)
  - [Cargo](#cargo)
  - [Arch Linux](#arch-linux)

## Features

TODO

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
