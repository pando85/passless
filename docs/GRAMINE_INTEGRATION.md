# Gramine Integration for Passless

This document provides comprehensive instructions for running Passless in an Intel SGX enclave using Gramine.

## Overview

Gramine (formerly Graphene) is a Library OS that enables running unmodified applications in Intel SGX enclaves. This provides hardware-based memory encryption and isolation for Passless, protecting credentials and cryptographic keys even from a compromised operating system.

### Security Benefits

- **Memory Encryption**: All enclave memory is encrypted by the CPU
- **Hardware Isolation**: Enclave code and data are isolated from the host OS
- **Sealed Storage**: Optional hardware-bound credential storage
- **Attestation**: Capability for remote attestation (future enhancement)

### Architecture

```
┌────────────────────────────────────────────────────────┐
│                    Untrusted Host                       │
│  ┌──────────────────────────────────────────────────┐  │
│  │              Gramine Runtime                      │  │
│  │  ┌────────────────────────────────────────────┐  │  │
│  │  │          Intel SGX Enclave                  │  │  │
│  │  │  ┌────────────────────────────────────────┐│  │  │
│  │  │  │        Passless Process                ││  │  │
│  │  │  │  ┌──────────────┐  ┌────────────────┐ ││  │  │
│  │  │  │  │ CTAP Handler │  │ Credential     │ ││  │  │
│  │  │  │  │ (soft-fido2) │  │ Storage        │ ││  │  │
│  │  │  │  └──────────────┘  └────────────────┘ ││  │  │
│  │  │  │         Sealed Storage (Optional)      ││  │  │
│  │  │  └────────────────────────────────────────┘│  │  │
│  │  └────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────┘  │
│                          │                              │
│  ┌──────────────────────┐                              │
│  │    UHID Device       │                              │
│  └──────────────────────┘                              │
└────────────────────────────────────────────────────────┘
```

## Hardware Requirements

### Intel SGX Capable CPU

| Generation | Support Level |
|------------|---------------|
| Intel 6th Gen (Skylake) | SGX1 (basic) |
| Intel 7th Gen (Kaby Lake) | SGX1 |
| Intel 8th Gen (Coffee Lake) | SGX2 (recommended) |
| Intel 10th Gen+ (Ice Lake, etc.) | SGX2 with larger EPC |
| AMD CPUs | Not supported |
| ARM CPUs | Not supported |

### BIOS Configuration

1. Enter BIOS/UEFI settings
2. Navigate to Security or CPU Configuration
3. Enable "Intel SGX" or "Software Guard Extensions"
4. Set SGX ownership to "Enabled" (not "Software Controlled")

### Linux Kernel Requirements

- **Kernel 5.11+**: Native SGX driver (recommended)
- **Kernel 5.4-5.10**: May require DCAP driver

Check SGX support:
```bash
# Check for SGX device
ls -la /dev/sgx_enclave /dev/sgx/enclave

# Check CPU flags
grep -E 'sgx|sgxlc' /proc/cpuinfo
```

## Installation

### 1. Install Gramine

**Ubuntu 22.04+:**
```bash
sudo apt-get update
sudo apt-get install -y gramine
```

**Ubuntu 20.04:**
```bash
sudo apt-get install -y wget gnupg
wget -O - https://packages.gramineproject.io/gramine-keyring.gpg | \
    sudo gpg --dearmor -o /usr/share/keyrings/gramine-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] \
    https://packages.gramineproject.io/$(lsb_release -sc) $(lsb_release -sc) main" | \
    sudo tee /etc/apt/sources.list.d/gramine.list
sudo apt-get update
sudo apt-get install -y gramine
```

**From Source:**
```bash
git clone https://github.com/gramineproject/gramine.git
cd gramine
meson setup build/ --prefix=/usr
ninja -C build
sudo ninja -C build install
```

### 2. Install Intel SGX Driver (if needed)

**Kernel 5.11+:** Driver is built-in.

**Older kernels:**
```bash
# Install DCAP driver
git clone https://github.com/intel/SGXDataCenterAttestationPrimitives.git
cd SGXDataCenterAttestationPrimitives/driver/linux
sudo make install
sudo modprobe intel_sgx
```

### 3. Install Passless

```bash
# Build from source
git clone https://github.com/pando85/passless.git
cd passless
cargo build --release
sudo install -m 755 target/release/passless /usr/bin/passless
```

## Building Gramine-Enabled Passless

### Standard Build

```bash
cd passless/gramine
./build.sh
```

This will:
1. Build the Passless binary
2. Generate Gramine manifest files
3. Create an enclave signing key
4. Sign the manifests for SGX

### Build Artifacts

| File | Description |
|------|-------------|
| `passless.manifest` | Generated manifest for standard storage |
| `passless.manifest.sgx` | Signed manifest for SGX execution |
| `passless-sealed.manifest` | Manifest with SGX sealed storage |
| `passless-sealed.manifest.sgx` | Signed sealed storage manifest |
| `enclave-key.pem` | RSA key for enclave signing |

### Custom Build Options

**Specify library path:**
```bash
./build.sh
# The build script auto-detects library paths
# For custom paths, edit the manifest template
```

**Use custom signing key:**
```bash
# Generate your own key
openssl genrsa -3 -out my-key.pem 3072

# Sign manually
gramine-sgx-sign --key my-key.pem \
    --manifest passless.manifest \
    --output passless.manifest.sgx
```

## Running Passless with SGX

### Quick Start

```bash
# Run with standard storage
./gramine/run.sh

# Run with SGX sealed storage (hardware-bound)
./gramine/run.sh --sealed

# Run with verbose output
./gramine/run.sh --verbose

# Pass arguments to passless
./gramine/run.sh -- --backend-type local --local-path /var/lib/passless
```

### Using gramine-sgx Directly

```bash
cd gramine

# Standard storage
gramine-sgx passless

# Sealed storage
gramine-sgx passless-sealed

# With arguments
gramine-sgx passless -- --verbose

# Debug mode
gramine-sgx -v passless
```

### Storage Modes

#### Standard Storage (`passless.manifest`)

- Credentials stored in regular files
- Protected by Gramine filesystem isolation
- Suitable for development and testing
- Files can be backed up and migrated

#### SGX Sealed Storage (`passless-sealed.manifest`)

- Credentials encrypted with SGX seal key
- Hardware-bound to the specific enclave
- Cannot be accessed on different hardware
- Provides maximum security

**Note:** Sealed storage files are stored in `/var/lib/passless-sgx/` on the host.

### UHID Device Setup

```bash
# Load UHID kernel module
sudo modprobe uhid

# Create fido group and add user
sudo groupadd fido 2>/dev/null || true
sudo usermod -a -G fido $USER

# Configure udev rules
echo 'KERNEL=="uhid", GROUP="fido", MODE="0660"' | \
    sudo tee /etc/udev/rules.d/90-uinput.rules
sudo udevadm control --reload-rules
sudo udevadm trigger

# Log out and back in for group changes
```

## Docker/GSC Deployment

### Building GSC Container

```bash
# Install GSC
pip3 install gsc

# Build container
cd passless
gsc build -c gramine/gsc.toml gramine/Dockerfile passless-sgx

# Sign container
gsc sign -c gramine/gsc.toml enclave-key.pem passless-sgx
```

### Running Container

```bash
# Run container with SGX
docker run --device /dev/sgx_enclave \
    -v /dev/uhid:/dev/uhid \
    -v passless-data:/var/lib/passless \
    passless-sgx
```

### Docker Compose

```yaml
version: '3.8'
services:
  passless:
    image: passless-sgx
    devices:
      - /dev/sgx_enclave:/dev/sgx_enclave
      - /dev/uhid:/dev/uhid
    volumes:
      - passless-data:/var/lib/passless
    restart: unless-stopped

volumes:
  passless-data:
```

## Manifest Configuration

### Standard Manifest Options

Edit `gramine/passless.manifest.template`:

```toml
# Enclave size (adjust based on needs)
sgx.enclave_size = "256M"  # 128M, 256M, 512M, 1G

# Number of threads
sgx.thread_num = 4

# Enable/disable EDMM
sgx.enable_edmm = true

# Debug mode (disable in production)
sgx.debug = false
```

### Storage Paths

```toml
# Standard file storage
fs.mount.data.type = "chroot"
fs.mount.data.path = "/var/lib/passless"
fs.mount.data.uri = "file:/var/lib/passless"

# SGX sealed storage
fs.mount.data.type = "encrypted"
fs.mount.data.path = "/var/lib/passless"
fs.mount.data.uri = "file:/var/lib/passless-sgx"
fs.mount.data.key_name = "passless_sgx_key"
```

### Environment Variables

```toml
# Passless configuration
loader.env.PASSLESS_BACKEND_TYPE = "local"
loader.env.PASSLESS_LOCAL_PATH = "/var/lib/passless"
loader.env.PASSLESS_LOG_LEVEL = "info"

# Additional env vars
loader.env.RUST_LOG = "passless=info"
```

## Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Memory dumping | SGX memory encryption |
| Root access | Enclave isolation |
| Kernel compromise | Hardware isolation |
| Cold boot attacks | Memory encryption |
| Physical attacks | CPU-bound encryption |

### Best Practices

1. **Use sealed storage** for production
2. **Disable SGX debug mode** in production
3. **Verify attestation** for remote deployments
4. **Backup signing key** securely
5. **Keep system updated** for security patches
6. **Use secure boot** for full chain of trust

### Limitations

- **Hardware requirement**: Requires Intel SGX CPU
- **Side channels**: SGX has known side-channel vulnerabilities
- **Performance**: ~10-30% overhead
- **Memory limit**: EPC size limits (typically 128-256MB)

## Troubleshooting

### SGX Device Not Found

```bash
# Check kernel module
lsmod | grep intel_sgx

# Load module if missing
sudo modprobe intel_sgx

# Check device nodes
ls -la /dev/sgx*

# Check BIOS settings
# Ensure SGX is enabled in firmware
```

### Manifest Errors

```bash
# Regenerate manifest
cd gramine
gramine-manifest -Darch_libdir=/lib/x86_64-linux-gnu \
    passless.manifest.template passless.manifest

# Re-sign manifest
gramine-sgx-sign --key enclave-key.pem \
    --manifest passless.manifest \
    --output passless.manifest.sgx
```

### Permission Denied

```bash
# Check UHID permissions
ls -la /dev/uhid
groups  # Should include 'fido'

# Add user to fido group
sudo usermod -a -G fido $USER
# Log out and back in

# Or run with sudo for testing
sudo gramine-sgx passless
```

### Memory Allocation Errors

```bash
# Increase enclave size in manifest
sgx.enclave_size = "512M"

# Check available EPC
cat /proc/cpuinfo | grep -i sgx
dmesg | grep -i sgx
```

### Performance Issues

```bash
# Enable EDMM for better memory management
sgx.enable_edmm = true

# Reduce thread count if needed
sgx.thread_num = 2

# Use smaller enclave size
sgx.enclave_size = "128M"
```

## Development

### Building for Development

```bash
# Enable debug output
sed -i 's/sgx.debug = false/sgx.debug = true/' gramine/*.manifest.template
./gramine/build.sh

# Run with verbose logging
gramine-sgx -v passless
```

### Testing

```bash
# Run E2E tests with Gramine
PASSLESS_GRAMINE=1 make test-e2e

# Manual testing
./gramine/run.sh &
cargo test --test e2e_webauthn
```

### Custom Manifest Generation

```bash
# Use custom template
cp gramine/passless.manifest.template gramine/custom.manifest.template

# Edit custom.manifest.template
# ...

# Generate and sign
gramine-manifest -Darch_libdir=/lib/x86_64-linux-gnu \
    custom.manifest.template custom.manifest
gramine-sgx-sign --key enclave-key.pem \
    --manifest custom.manifest \
    --output custom.manifest.sgx

# Run
gramine-sgx custom
```

## Additional Resources

- [Gramine Documentation](https://gramine.readthedocs.io/)
- [Intel SGX Developer Guide](https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/overview.html)
- [Passless Documentation](../README.md)
- [TEE Analysis](../docs/TEE_ANALYSIS.md)

## Contributing

Contributions to improve Gramine integration are welcome:

1. Performance optimizations
2. Additional manifest templates
3. Cloud deployment guides
4. Remote attestation support
5. AMD SEV support

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.
