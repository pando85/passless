# Gramine Quick Start Guide

This guide gets you running Passless with Intel SGX in under 10 minutes.

## Prerequisites Check

```bash
# 1. Check for Intel SGX CPU
grep -q 'sgx' /proc/cpuinfo && echo "✓ SGX CPU found" || echo "✗ No SGX CPU"

# 2. Check for SGX device
ls /dev/sgx_enclave /dev/sgx/enclave 2>/dev/null && echo "✓ SGX driver loaded" || echo "✗ SGX driver missing"

# 3. Check for Gramine
command -v gramine-sgx &>/dev/null && echo "✓ Gramine installed" || echo "✗ Gramine not installed"
```

## Quick Install

### Ubuntu 22.04+

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y gramine cargo

# Setup UHID
sudo modprobe uhid
sudo groupadd fido 2>/dev/null || true
sudo usermod -a -G fido $USER
echo 'KERNEL=="uhid", GROUP="fido", MODE="0660"' | sudo tee /etc/udev/rules.d/90-uinput.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

### Ubuntu 20.04

```bash
# Add Gramine repository
wget -O - https://packages.gramineproject.io/gramine-keyring.gpg | \
    sudo gpg --dearmor -o /usr/share/keyrings/gramine-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] \
    https://packages.gramineproject.io/$(lsb_release -sc) $(lsb_release -sc) main" | \
    sudo tee /etc/apt/sources.list.d/gramine.list

sudo apt-get update
sudo apt-get install -y gramine cargo

# Setup UHID (same as above)
```

## Build and Run

```bash
# Clone and build
git clone https://github.com/pando85/passless.git
cd passless

# Build Passless
cargo build --release
sudo install -m 755 target/release/passless /usr/bin/passless

# Build Gramine manifest
cd gramine
./build.sh

# Run Passless in SGX enclave
./run.sh
```

## Verify It Works

```bash
# In another terminal, test WebAuthn registration
# Use any WebAuthn demo site like https://webauthn.io/
# The authenticator should appear and register successfully
```

## Common Issues

### "SGX device not found"
- Ensure your CPU supports Intel SGX (6th gen or newer)
- Enable SGX in BIOS settings
- Load kernel driver: `sudo modprobe intel_sgx`

### "Permission denied on /dev/uhid"
- Add user to fido group: `sudo usermod -a -G fido $USER`
- Log out and back in
- Or run with sudo for testing

### "No such file: *.manifest.sgx"
- Run `./gramine/build.sh` to generate manifests

## Next Steps

- Read the full [Gramine Integration Guide](../docs/GRAMINE_INTEGRATION.md) for detailed configuration
- Learn about [SGX Sealed Storage](../docs/GRAMINE_INTEGRATION.md#storage-modes)
- Configure [Docker deployment](../docs/GRAMINE_INTEGRATION.md#dockergsc-deployment)