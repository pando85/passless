#!/usr/bin/env bash
# Build script for Gramine-enabled Passless
# This script builds Passless with Gramine/SGX support

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
GRAMINE_DIR="$PROJECT_ROOT/gramine"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check for required tools
check_dependencies() {
    log_info "Checking dependencies..."
    
    local missing=()
    
    # Check for Gramine tools
    if ! command -v gramine-sgx &> /dev/null; then
        missing+=("gramine-sgx")
    fi
    
    if ! command -v gramine-manifest &> /dev/null; then
        missing+=("gramine-manifest")
    fi
    
    if ! command -v gramine-sgx-sign &> /dev/null; then
        missing+=("gramine-sgx-sign")
    fi
    
    # Check for Rust
    if ! command -v cargo &> /dev/null; then
        missing+=("cargo")
    fi
    
    if [ ${#missing[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing[*]}"
        log_info "Install Gramine: https://gramine.readthedocs.io/en/latest/installation.html"
        exit 1
    fi
    
    log_info "All dependencies found"
}

# Build Passless binary
build_passless() {
    log_info "Building Passless binary..."
    cd "$PROJECT_ROOT"
    cargo build --release
    log_info "Passless binary built successfully"
}

# Generate enclave key if it doesn't exist
generate_enclave_key() {
    local key_file="$GRAMINE_DIR/enclave-key.pem"
    
    if [ -f "$key_file" ]; then
        log_info "Enclave key already exists: $key_file"
        return
    fi
    
    log_info "Generating new enclave key..."
    openssl genrsa -3 -out "$key_file" 3072
    log_info "Enclave key generated: $key_file"
}

# Generate manifest files
generate_manifests() {
    local arch_libdir="/lib/x86_64-linux-gnu"
    
    log_info "Generating Gramine manifests..."
    
    cd "$GRAMINE_DIR"
    
    # Generate standard manifest
    if [ -f "passless.manifest.template" ]; then
        gramine-manifest -Darch_libdir="$arch_libdir" \
            passless.manifest.template passless.manifest
        log_info "Generated passless.manifest"
    fi
    
    # Generate sealed storage manifest
    if [ -f "passless-sealed.manifest.template" ]; then
        gramine-manifest -Darch_libdir="$arch_libdir" \
            passless-sealed.manifest.template passless-sealed.manifest
        log_info "Generated passless-sealed.manifest"
    fi
}

# Sign manifests for SGX
sign_manifests() {
    local key_file="$GRAMINE_DIR/enclave-key.pem"
    
    log_info "Signing Gramine manifests..."
    
    cd "$GRAMINE_DIR"
    
    # Sign standard manifest
    if [ -f "passless.manifest" ]; then
        gramine-sgx-sign --key "$key_file" \
            --manifest passless.manifest \
            --output passless.manifest.sgx
        log_info "Signed passless.manifest.sgx"
    fi
    
    # Sign sealed storage manifest
    if [ -f "passless-sealed.manifest" ]; then
        gramine-sgx-sign --key "$key_file" \
            --manifest passless-sealed.manifest \
            --output passless-sealed.manifest.sgx
        log_info "Signed passless-sealed.manifest.sgx"
    fi
}

# Main build process
main() {
    log_info "Starting Gramine build process..."
    
    check_dependencies
    build_passless
    generate_enclave_key
    generate_manifests
    sign_manifests
    
    log_info "Gramine build complete!"
    log_info "Run with: gramine-sgx passless"
    log_info "Or with sealed storage: gramine-sgx passless-sealed"
}

# Handle command line arguments
case "${1:-build}" in
    build)
        main
        ;;
    clean)
        log_info "Cleaning Gramine build artifacts..."
        rm -f "$GRAMINE_DIR"/*.manifest.sgx
        rm -f "$GRAMINE_DIR"/passless.manifest
        rm -f "$GRAMINE_DIR"/passless-sealed.manifest
        log_info "Clean complete"
        ;;
    keygen)
        generate_enclave_key
        ;;
    *)
        echo "Usage: $0 {build|clean|keygen}"
        exit 1
        ;;
esac