#!/usr/bin/env bash
# Systemd wrapper for running Passless with Gramine/SGX
# Install to /usr/local/bin/passless-sgx

set -e

GRAMINE_DIR="/opt/passless/gramine"

# Check SGX device
if [ ! -e /dev/sgx_enclave ] && [ ! -e /dev/sgx/enclave ]; then
    echo "ERROR: Intel SGX device not found" >&2
    exit 1
fi

# Check UHID device
if [ ! -e /dev/uhid ]; then
    echo "ERROR: UHID device not found" >&2
    exit 1
fi

# Check manifest
if [ ! -f "$GRAMINE_DIR/passless-sealed.manifest.sgx" ]; then
    echo "ERROR: Gramine manifest not found" >&2
    exit 1
fi

# Run in SGX enclave with sealed storage
cd "$GRAMINE_DIR"
exec gramine-sgx passless-sealed "$@"
