# Development Guide

## Building from Source

### Prerequisites

**Required:**

- Rust and Cargo (install via [rustup](https://rustup.rs/))

**System Dependencies:**

- `libudev-dev` - Required for UHID device access
- `libtss2-dev` - TPM 2.0 TSS libraries (includes tss2-esys, tss2-tctildr, tss2-mu)

**Ubuntu/Debian:**

```bash
sudo apt install libudev-dev libtss2-dev
```

**Arch Linux:**

```bash
sudo pacman -S systemd-libs tpm2-tss
```

### Build Commands

```bash
# Clone the repository
git clone https://github.com/arunanshub/passless.git
cd passless

# Standard debug build
cargo build

# Optimized release build
cargo build --release

# Run directly
cargo run

# Run with verbose logging
cargo run -- --verbose
```

## Testing the TPM Backend (swtpm)

Quick steps to run a software TPM for local testing.

### Prerequisites

- Install the `swtpm` package from your distribution

**Ubuntu/Debian:**

```bash
sudo apt install swtpm
```

**Arch Linux:**

```bash
sudo pacman -S swtpm
```

### Setup and Run

Create runtime directories and start the software TPM:

```bash
rm -rf /tmp/swtpm-state /tmp/tpm-store
mkdir -p /tmp/swtpm-state /tmp/tpm-store

# Start the software TPM and attach it to the char device:
swtpm socket \
  --tpm2 \
  --tpmstate dir=/tmp/swtpm-state \
  --server type=tcp,port=2321 \
  --ctrl type=tcp,port=2322 \
  --flags not-need-init,startup-clear \
  --log level=20
```

In another terminal, run passless with the TPM backend:

```bash
cargo run -- --backend-type tpm --tpm-tcti "swtpm:host=localhost,port=2321" --tpm-path /tmp/tpm-store -v
```

### TCTI Configuration Examples

The `--tpm-tcti` flag accepts various TCTI (TPM Command Transmission Interface) specifications:

- `device:/dev/tpm0` - Hardware TPM character device
- `device:/dev/tpmrm0` - TPM resource manager
- `swtpm:host=localhost,port=2321` - Software TPM over TCP
- `swtpm:path=/path/to/socket` - Software TPM over Unix socket
- `tabrmd:` - TPM2 Access Broker & Resource Manager

For more details, see [docs/TPM_SETUP.md](docs/TPM_SETUP.md) and
[docs/SWTPM_QUICK_START.md](docs/SWTPM_QUICK_START.md).
