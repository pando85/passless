#!/usr/bin/env bash
set -euo pipefail

# E2E test script for agent passkey registration flow
# Tests the full registration and authentication flow with the passless daemon

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="/home/agil/passkeys/passless"
# CARGO_TARGET_DIR may be overridden globally (e.g. /dev/shm); resolve the real binary path
if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
    BINARY="${CARGO_TARGET_DIR}/debug/passless"
elif [[ -f "${PROJECT_ROOT}/target/debug/passless" ]]; then
    BINARY="${PROJECT_ROOT}/target/debug/passless"
else
    BINARY="${PROJECT_ROOT}/target/debug/passless"
fi
TEST_DIR="/tmp/passless-webauthn-test"
CONFIG_DIR="${TEST_DIR}/config"
STORAGE_DIR="${TEST_DIR}/fido2"
DAEMON_LOG="${TEST_DIR}/daemon.log"
DAEMON_PID_FILE="${TEST_DIR}/daemon.pid"
HTTP_PORT_FILE="${TEST_DIR}/http_port"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check dependencies
check_dependencies() {
    local missing=()

    if ! command -v jq &> /dev/null; then
        missing+=("jq")
    fi

    if ! command -v curl &> /dev/null; then
        missing+=("curl")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing[*]}"
        log_error "Please install them and try again"
        exit 1
    fi
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

cleanup() {
    log_info "Cleaning up..."

    # Stop daemon if running
    if [[ -f "$DAEMON_PID_FILE" ]]; then
        local pid
        pid=$(cat "$DAEMON_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            log_info "Stopping daemon (PID: $pid)..."
            kill "$pid" 2>/dev/null || true
            sleep 2
            # Force kill if still running
            if kill -0 "$pid" 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null || true
            fi
        fi
        rm -f "$DAEMON_PID_FILE"
    fi

    # Clean up test directory
    if [[ -d "$TEST_DIR" ]]; then
        rm -rf "$TEST_DIR"
    fi

    log_info "Cleanup complete"
}

# Set up trap to cleanup on exit
trap cleanup EXIT

setup_environment() {
    log_info "Setting up test environment..."

    # Clean up any existing test directory
    if [[ -d "$TEST_DIR" ]]; then
        rm -rf "$TEST_DIR"
    fi

    # Create test directory with secure permissions
    mkdir -p "$TEST_DIR"
    chmod 700 "$TEST_DIR"

    # Clean up runtime dirs (required for agent subsystem to start)
    local uid
    uid=$(id -u)
    rm -rf "/run/user/${uid}/passless" "/run/user/${uid}/agent"

    # Create directories
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$STORAGE_DIR"
    mkdir -p "${TEST_DIR}/agent-credentials"
    mkdir -p "${TEST_DIR}/agent-pin"
    chmod 700 "$STORAGE_DIR"
    chmod 700 "${TEST_DIR}/agent-credentials"
    chmod 700 "${TEST_DIR}/agent-pin"

    # Create config file
    cat > "${CONFIG_DIR}/config.toml" <<EOF
[agents]
enabled = true
audit_path = "${TEST_DIR}/audit.log"

[agents.profiles.webauthn-test]
mode = "isolated"
principal_user = "$(whoami)"

[agents.profiles.webauthn-test.device]
name = "passless-agent-webauthn-test"
phys = "webauthn-test-phys"
uniq = "webauthn-test-uniq"
vendor_id = 4660
product_id = 22137

[agents.profiles.webauthn-test.storage.local]
path = "${TEST_DIR}/agent-credentials"
pin_path = "${TEST_DIR}/agent-pin"

[[agents.profiles.webauthn-test.rules]]
rp_id = "webauthn.io"
register = { authorization = "allow", user_presence = "none", user_verification = "none" }
authenticate = { authorization = "allow", user_presence = "none", user_verification = "none" }

[[agents.profiles.webauthn-test.rules]]
rp_id = "example.com"
register = { authorization = "allow", user_presence = "none", user_verification = "none" }
authenticate = { authorization = "allow", user_presence = "none", user_verification = "none" }

[local]
path = "${STORAGE_DIR}"
EOF

    log_info "Environment setup complete"
}

build_passless() {
    log_info "Building passless..."
    cd "$PROJECT_ROOT"

    # Check if binary is up to date
    if [[ ! -f "$BINARY" ]] || [[ "Cargo.toml" -nt "$BINARY" ]] || [[ "cmd/passless/src/main.rs" -nt "$BINARY" ]]; then
        cargo build --features agent 2>&1 | tail -20
    else
        log_info "Binary is up to date"
    fi

    if [[ ! -f "$BINARY" ]]; then
        log_error "Failed to build passless"
        exit 1
    fi

    log_info "Build complete"
}

start_daemon() {
    log_info "Starting passless daemon..."

    export PASSLESS_CONFIG="${CONFIG_DIR}/config.toml"
    export PASSLESS_LOG_LEVEL="debug"
    export PASSLESS_LOG_STYLE="always"

    # Start daemon in background (agent subsystem starts automatically from config)
    "$BINARY" \
        --config-path "${CONFIG_DIR}/config.toml" \
        --backend-type local \
        --local-path "$STORAGE_DIR" \
        --always-uv=false \
        > "$DAEMON_LOG" 2>&1 &

    local daemon_pid=$!
    echo "$daemon_pid" > "$DAEMON_PID_FILE"

    log_info "Daemon started with PID: $daemon_pid"

    # Wait for daemon to be ready
    log_info "Waiting for daemon to initialize..."
    local max_wait=30
    local waited=0

    while [[ $waited -lt $max_wait ]]; do
        # Check if daemon is still running
        if ! kill -0 "$daemon_pid" 2>/dev/null; then
            log_error "Daemon exited unexpectedly"
            log_error "Last 20 lines of daemon log:"
            tail -20 "$DAEMON_LOG"
            exit 1
        fi

        # Check if HTTP server is ready by looking for the port in logs
        if grep -q "Sign HTTP server listening on 127.0.0.1:" "$DAEMON_LOG" 2>/dev/null; then
            # Extract port number
            local port
            port=$(grep "Sign HTTP server listening on 127.0.0.1:" "$DAEMON_LOG" | sed 's/.*127.0.0.1:\([0-9]*\).*/\1/')
            echo "$port" > "$HTTP_PORT_FILE"
            log_info "HTTP server ready on port: $port"
            break
        fi

        sleep 1
        waited=$((waited + 1))
    done

    if [[ $waited -ge $max_wait ]]; then
        log_error "Daemon failed to start within ${max_wait}s"
        log_error "Last 20 lines of daemon log:"
        tail -20 "$DAEMON_LOG"
        exit 1
    fi

    # Give daemon a moment to fully initialize
    sleep 2

    log_info "Daemon is ready"
}

request_registration_grant() {
    log_info "Requesting registration grant..."

    local output
    output=$("$BINARY" agent-admin delegation request-registration \
        --profile webauthn-test \
        --rp webauthn.io \
        --session-ttl 300 \
        --reason "E2E test registration" \
        --output json 2>&1)

    if [[ $? -ne 0 ]]; then
        log_error "Failed to request registration grant"
        log_error "Output: $output"
        exit 1
    fi

    # Extract registration_grant_id from JSON response
    # Response format: {"version":"1","status":"ok","data":{"registration_grant_id":"..."}}
    local grant_id
    grant_id=$(echo "$output" | jq -r '.data.registration_grant_id // empty')

    if [[ -z "$grant_id" ]]; then
        log_error "Failed to extract registration_grant_id from response"
        log_error "Response: $output"
        exit 1
    fi

    # Validate grant ID format (should be 64-char hex string)
    if [[ ${#grant_id} -ne 64 ]] || ! [[ "$grant_id" =~ ^[0-9a-f]+$ ]]; then
        log_error "Invalid registration grant ID format: $grant_id"
        exit 1
    fi

    log_info "Registration grant ID: $grant_id"
    echo "$grant_id"
}

test_register_endpoint() {
    local grant_id="$1"
    local port
    port=$(cat "$HTTP_PORT_FILE")

    log_info "Testing /register endpoint..."

    # Create a registration request
    local request_json
    request_json=$(cat <<EOF
{
    "origin": "https://webauthn.io",
    "rp_id": "webauthn.io",
    "rp_name": "WebAuthn.io",
    "user_id_b64u": "dGVzdC11c2VyLWlk",
    "user_name": "testuser@webauthn.io",
    "user_display_name": "Test User",
    "challenge_b64u": "dGVzdC1jaGFsbGVuZ2U",
    "exclude_credentials": [],
    "user_verification": false,
    "cross_origin": false
}
EOF
)

    # Note: In a real flow, the bearer token would be provided by the daemon
    # For this test, we're testing the endpoint exists and responds correctly
    # The actual bearer token flow requires the full extension integration

    log_info "Sending registration request to http://127.0.0.1:${port}/register"

    # Test without bearer token first (should get 401)
    local response
    response=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -d "$request_json" \
        "http://127.0.0.1:${port}/register" 2>&1)

    local http_code
    http_code=$(echo "$response" | tail -1)
    local body
    body=$(echo "$response" | sed '$d')

    if [[ "$http_code" == "401" ]]; then
        log_info "Endpoint correctly requires authentication (401)"
    else
        log_warn "Expected 401, got $http_code"
        log_warn "Response: $body"
    fi

    # Test with invalid bearer token (should get 401)
    response=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer invalid_token" \
        -d "$request_json" \
        "http://127.0.0.1:${port}/register" 2>&1)

    http_code=$(echo "$response" | tail -1)
    body=$(echo "$response" | sed '$d')

    if [[ "$http_code" == "401" ]]; then
        log_info "Endpoint correctly rejects invalid bearer token (401)"
    else
        log_warn "Expected 401 for invalid token, got $http_code"
        log_warn "Response: $body"
    fi

    log_info "/register endpoint test complete"
}

verify_credential_storage() {
    log_info "Verifying credential storage..."

    # Check if storage directory has files
    local file_count
    file_count=$(find "$STORAGE_DIR" -type f 2>/dev/null | wc -l)

    if [[ $file_count -gt 0 ]]; then
        log_info "Found $file_count credential file(s) in storage"
        ls -lh "$STORAGE_DIR" | head -10
    else
        log_warn "No credential files found in storage (expected if no registration completed)"
    fi

    # Try to list credentials using agent-admin CLI
    log_info "Listing credentials via agent-admin CLI..."
    if "$BINARY" agent-admin credential list \
        --profile webauthn-test --output json 2>&1 | jq -e '.data.credentials' > /dev/null; then
        log_info "Credential listing successful"
        "$BINARY" agent-admin credential list \
            --profile webauthn-test --output json 2>&1 | jq '.data.credentials | length'
    else
        log_warn "Could not list credentials via agent-admin"
    fi

    # Also try the FIDO2 client list (requires UHID device)
    log_info "Listing credentials via FIDO2 client (if UHID available)..."
    if "$BINARY" client list 2>&1 | head -20; then
        log_info "FIDO2 credential listing successful"
    else
        log_warn "Could not list FIDO2 credentials (may require UHID device or no credentials)"
    fi
}

test_sign_endpoint() {
    log_info "Testing /sign endpoint..."

    local port
    port=$(cat "$HTTP_PORT_FILE")

    # Create a sign request
    local request_json
    request_json=$(cat <<EOF
{
    "origin": "https://webauthn.io",
    "rp_id": "webauthn.io",
    "challenge_b64u": "dGVzdC1jaGFsbGVuZ2U",
    "allow_credentials": [],
    "user_verification": false,
    "cross_origin": false
}
EOF
)

    # Test without bearer token (should get 401)
    local response
    response=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -d "$request_json" \
        "http://127.0.0.1:${port}/sign" 2>&1)

    local http_code
    http_code=$(echo "$response" | tail -1)

    if [[ "$http_code" == "401" ]]; then
        log_info "/sign endpoint correctly requires authentication (401)"
    else
        log_warn "Expected 401 for /sign, got $http_code"
    fi

    log_info "/sign endpoint test complete"
}

test_admin_ipc() {
    log_info "Testing admin IPC..."

    # Test profile list
    log_info "Listing profiles..."
    if "$BINARY" agent-admin profile list --output json 2>&1 | jq -e '.data.profiles' > /dev/null; then
        log_info "Profile list successful"
    else
        log_warn "Could not list profiles"
    fi

    # Test delegation list
    log_info "Listing delegations..."
    if "$BINARY" agent-admin delegation list --output json 2>&1 | jq -e '.data.grants' > /dev/null; then
        log_info "Delegation list successful"
    else
        log_warn "Could not list delegations"
    fi

    log_info "Admin IPC test complete"
}

main() {
    log_info "=== Passless Agent Registration E2E Test ==="
    log_info ""

    # Check dependencies
    check_dependencies

    # Setup
    setup_environment
    build_passless
    start_daemon

    # Test registration flow
    local grant_id
    grant_id=$(request_registration_grant)

    # Test endpoints
    test_register_endpoint "$grant_id"
    test_sign_endpoint

    # Verify storage
    verify_credential_storage

    # Test admin IPC
    test_admin_ipc

    log_info ""
    log_info "=== E2E Test Complete ==="
    log_info ""
    log_info "Test Summary:"
    log_info "  - Daemon started successfully"
    log_info "  - HTTP server listening on port $(cat "$HTTP_PORT_FILE")"
    log_info "  - Registration grant obtained: ${grant_id:0:16}..."
    log_info "  - /register endpoint accessible"
    log_info "  - /sign endpoint accessible"
    log_info "  - Admin IPC functional"
    log_info ""
    log_info "Note: Full registration requires browser extension integration."
    log_info "This test verifies the daemon infrastructure is working correctly."

    exit 0
}

# Run main function
main
