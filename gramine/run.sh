#!/usr/bin/env bash
# Run Passless with Gramine SGX
# This script simplifies running Passless in an SGX enclave

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GRAMINE_DIR="$SCRIPT_DIR"

# Default configuration
MANIFEST="${GRAMINE_DIR}/passless.manifest.sgx"
SGX_MANIFEST="${GRAMINE_DIR}/passless-sealed.manifest.sgx"
USE_SEALED=false
VERBOSE=false

usage() {
    echo "Usage: $0 [OPTIONS] [-- PASSLESS_ARGS]"
    echo ""
    echo "Run Passless FIDO2 authenticator in an Intel SGX enclave using Gramine"
    echo ""
    echo "Options:"
    echo "  -s, --sealed     Use SGX sealed storage for credentials"
    echo "  -v, --verbose    Enable verbose Gramine output"
    echo "  -h, --help       Show this help message"
    echo ""
    echo "Passless Args:"
    echo "  Any arguments after -- are passed to passless"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Run with standard storage"
    echo "  $0 --sealed                           # Run with SGX sealed storage"
    echo "  $0 -- --backend-type pass             # Use password-store backend"
    echo "  $0 -v -- --verbose                    # Enable verbose logging"
    echo ""
    echo "Hardware Requirements:"
    echo "  - Intel SGX capable CPU (6th gen or newer)"
    echo "  - SGX enabled in BIOS"
    echo "  - Linux SGX driver (kernel 5.11+)"
    echo ""
    echo "Setup:"
    echo "  sudo modprobe uhid"
    echo "  sudo groupadd fido 2>/dev/null || true"
    echo "  sudo usermod -a -G fido \$USER"
    echo "  echo 'KERNEL==\"uhid\", GROUP=\"fido\", MODE=\"0660\"' | sudo tee /etc/udev/rules.d/90-uinput.rules"
    echo "  sudo udevadm control --reload-rules && sudo udevadm trigger"
    exit 0
}

# Parse arguments
PASSLESS_ARGS=()
while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--sealed)
            USE_SEALED=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        --)
            shift
            PASSLESS_ARGS=("$@")
            break
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Check for SGX support
check_sgx() {
    if [ ! -e /dev/sgx_enclave ] && [ ! -e /dev/sgx/enclave ]; then
        echo "ERROR: Intel SGX device not found"
        echo ""
        echo "Please ensure:"
        echo "  1. Your CPU supports Intel SGX"
        echo "  2. SGX is enabled in BIOS"
        echo "  3. SGX driver is loaded (kernel 5.11+ or DCAP driver)"
        exit 1
    fi
}

# Check for manifest
check_manifest() {
    if $USE_SEALED; then
        if [ ! -f "$SGX_MANIFEST" ]; then
            echo "ERROR: Signed sealed manifest not found: $SGX_MANIFEST"
            echo ""
            echo "Run: $GRAMINE_DIR/build.sh"
            exit 1
        fi
        MANIFEST="$SGX_MANIFEST"
    else
        if [ ! -f "$MANIFEST" ]; then
            echo "ERROR: Signed manifest not found: $MANIFEST"
            echo ""
            echo "Run: $GRAMINE_DIR/build.sh"
            exit 1
        fi
    fi
}

# Run Passless in SGX
run_gramine() {
    local manifest_name
    manifest_name=$(basename "$MANIFEST" .manifest.sgx)
    
    echo "Starting Passless in Intel SGX enclave..."
    echo "Manifest: $manifest_name"
    echo "Storage: $([ "$USE_SEALED" = true ] && echo "SGX Sealed" || echo "Standard")"
    echo ""
    
    cd "$GRAMINE_DIR"
    
    # Build gramine-sgx command
    local cmd="gramine-sgx"
    
    if $VERBOSE; then
        cmd="$cmd -v"
    fi
    
    cmd="$cmd $manifest_name"
    
    # Add passless args if provided
    if [ ${#PASSLESS_ARGS[@]} -gt 0 ]; then
        cmd="$cmd ${PASSLESS_ARGS[*]}"
    fi
    
    exec $cmd
}

# Main
check_sgx
check_manifest
run_gramine