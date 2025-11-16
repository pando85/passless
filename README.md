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
- [Configuration](#configuration)
- [Installation](#installation)
  - [Cargo](#cargo)
  - [Arch Linux](#arch-linux)
  - [Binaries](#binaries)

## Features

TODO

## Configuration

Passless can be configured using a TOML configuration file. By default, the configuration file is located at `~/.config/passless/config.toml`.

To generate a default configuration file:

```bash
passless config print > ~/.config/passless/config.toml
```

You can then edit this file to customize the storage backend, security settings, and other options. Command-line arguments will override settings from the configuration file.

## Installation

### Cargo

```bash
cargo install passless-cli
```

### Arch Linux

```bash
yay -S passless-rs
```

or the binary from AUR:

```bash
yay -S passless-rs-bin
```

### Binaries

Binaries are made available each release for the Linux and MacOS operating systems.

You can download a prebuilt binary from our
[Releases](https://github.com/pando85/passless/releases).

```bash
curl -s https://api.github.com/repos/pando85/passless/releases/latest \
  | grep browser_download_url \
  | grep -v sha256 \
  | grep $(uname -m) \
  | grep linux \
  | cut -d '"' -f 4 \
  | xargs curl -L \
  | tar xvz
sudo mv passless /usr/local/bin
```
