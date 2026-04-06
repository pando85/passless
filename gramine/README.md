# Gramine Support for Passless

This directory contains files for running Passless in an Intel SGX enclave using Gramine.

## Files

| File | Description |
|------|-------------|
| `passless.manifest.template` | Gramine manifest template (standard storage) |
| `passless-sealed.manifest.template` | Gramine manifest template (SGX sealed storage) |
| `build.sh` | Build script for generating and signing manifests |
| `run.sh` | Convenience script for running Passless in SGX |
| `Dockerfile` | Dockerfile for Gramine Shielded Containers |
| `gsc.toml` | GSC configuration file |
| `QUICK_START.md` | Quick start guide for Gramine setup |

## Quick Start

```bash
# Build Gramine manifest
./build.sh

# Run Passless in SGX enclave
./run.sh

# Run with SGX sealed storage (hardware-bound)
./run.sh --sealed
```

## Requirements

- Intel SGX-capable CPU (6th gen or newer)
- SGX enabled in BIOS
- Linux kernel 5.11+ or DCAP driver
- Gramine installed

## Documentation

See [GRAMINE_INTEGRATION.md](../docs/GRAMINE_INTEGRATION.md) for comprehensive documentation.
