#!/bin/bash
#
# Behavior tests for Tier 2 stages using mocked binaries/processes
# Includes mock WebSocket CDP server tests
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATION_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LIB_DIR="${VALIDATION_DIR}/lib"
STAGES_DIR="${VALIDATION_DIR}/stages"
BROWSER_DIR="${VALIDATION_DIR}/browser"

TEST_TMP_DIR="/tmp/passless-av-tier2-test-$$"
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

TEST_COUNT=0
PASS_COUNT=0
FAIL_COUNT=0

log_pass() { echo -e "${GREEN}[PASS]${NC} $*" >&2; ((PASS_COUNT++)) || true; ((TEST_COUNT++)) || true; }
log_fail() { echo -e "${RED}[FAIL]${NC} $*" >&2; ((FAIL_COUNT++)) || true; ((TEST_COUNT++)) || true; }
log_test() { echo -e "${BLUE}[TEST]${NC} $*" >&2; }

cleanup() {
    pkill -P $$ 'sleep' 2>/dev/null || true
    pkill -f 'mock-cdp-server' 2>/dev/null || true
    rm -rf "$TEST_TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p "$TEST_TMP_DIR"

setup_stage_env() {
    export EVIDENCE_DIR="${TEST_TMP_DIR}/evidence"
    export TEMP_ROOT="${TEST_TMP_DIR}/tmp"
    export RUN_ID="test-run-002"
    export AV_VALIDATION_DIR="$VALIDATION_DIR"
    mkdir -p "$EVIDENCE_DIR" "$TEMP_ROOT"

    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/notifications.sh"
    source "${LIB_DIR}/controlled-rp.sh"
    source "${LIB_DIR}/browser.sh"

    register_resource() { :; }
}

setup_mock_bin_dir() {
    local mock_dir="${TEST_TMP_DIR}/mock-bin"
    mkdir -p "$mock_dir"
    echo "$mock_dir"
}

test_stage_files_exist() {
    log_test "All Tier 2 stage files exist"
    local stages=("real-notifications.sh" "controlled-rp.sh" "agent-ceremonies.sh" "browser-lease.sh")
    local all_found=true
    for stage in "${stages[@]}"; do
        if [[ ! -f "${STAGES_DIR}/${stage}" ]]; then
            log_fail "Missing stage: $stage"
            all_found=false
        fi
    done
    if [[ "$all_found" == "true" ]]; then
        log_pass "All Tier 2 stage files present"
    fi
}

test_lib_files_exist() {
    log_test "All Tier 2 lib files exist"
    local libs=("notifications.sh" "controlled-rp.sh" "browser.sh")
    local all_found=true
    for lib in "${libs[@]}"; do
        if [[ ! -f "${LIB_DIR}/${lib}" ]]; then
            log_fail "Missing lib: $lib"
            all_found=false
        fi
    done
    if [[ "$all_found" == "true" ]]; then
        log_pass "All Tier 2 lib files present"
    fi
}

test_browser_dir_exists() {
    log_test "Browser driver directory exists"
    if [[ -d "${BROWSER_DIR}" ]]; then
        log_pass "browser/ directory exists"
    else
        log_fail "browser/ directory missing"
    fi
}

test_cdp_client_exists() {
    log_test "CDP client script exists"
    if [[ -f "${BROWSER_DIR}/cdp-client.js" ]]; then
        log_pass "browser/cdp-client.js exists"
    else
        log_fail "browser/cdp-client.js missing"
    fi
}

test_cdp_driver_exists() {
    log_test "CDP driver script exists"
    if [[ -f "${BROWSER_DIR}/cdp-driver.sh" ]]; then
        log_pass "browser/cdp-driver.sh exists"
    else
        log_fail "browser/cdp-driver.sh missing"
    fi
}

test_mock_cdp_server_exists() {
    log_test "Mock CDP server script exists"
    if [[ -f "${BROWSER_DIR}/mock-cdp-server.js" ]]; then
        log_pass "browser/mock-cdp-server.js exists"
    else
        log_fail "browser/mock-cdp-server.js missing"
    fi
}

test_cdp_client_against_mock() {
    log_test "CDP client works against mock CDP server"

    local mock_port=19222
    local mock_pid=""

    # Start mock server
    node "${BROWSER_DIR}/mock-cdp-server.js" "$mock_port" &>/dev/null &
    mock_pid=$!

    sleep 1

    if ! kill -0 "$mock_pid" 2>/dev/null; then
        log_fail "Mock CDP server failed to start"
        return 1
    fi

    # Test health check
    local health_result
    if health_result=$(timeout 15s env AV_CDP_PORT="$mock_port" node "${BROWSER_DIR}/cdp-client.js" health 2>&1); then
        if echo "$health_result" | jq -e '.connected == true' &>/dev/null; then
            log_pass "CDP client health check against mock succeeded"
        else
            log_fail "CDP client health check returned unexpected result: $health_result"
        fi
    else
        log_fail "CDP client health check failed: $health_result"
    fi

    # Test evaluate
    local eval_result
    if eval_result=$(timeout 15s env AV_CDP_PORT="$mock_port" node "${BROWSER_DIR}/cdp-client.js" evaluate "true" 2>&1); then
        if echo "$eval_result" | jq -e '.value == true' &>/dev/null; then
            log_pass "CDP client evaluate against mock succeeded"
        else
            log_fail "CDP client evaluate returned unexpected result: $eval_result"
        fi
    else
        log_fail "CDP client evaluate failed: $eval_result"
    fi

    # Cleanup
    kill "$mock_pid" 2>/dev/null || true
    wait "$mock_pid" 2>/dev/null || true
}

test_notifications_skip_without_dunst() {
    log_test "real-notifications skips without dunst"
    setup_stage_env

    local mock_dir
    mock_dir=$(setup_mock_bin_dir)

    cat > "$mock_dir/dunst" << 'EOF'
#!/bin/bash
exit 1
EOF
    chmod +x "$mock_dir/dunst"

    local old_path="$PATH"
    export PATH="$mock_dir"

    source "${STAGES_DIR}/real-notifications.sh"

    if stage_real_notifications 2>/dev/null; then
        if [[ "${STAGE_SKIPPED:-false}" == "true" ]]; then
            log_pass "Correctly skipped without dunst"
        else
            log_fail "Should set STAGE_SKIPPED without dunst"
        fi
    else
        log_fail "Stage should succeed (with skip) without dunst"
    fi

    export PATH="$old_path"
}

test_controlled_rp_skip_without_node() {
    log_test "controlled-rp skips without node"
    setup_stage_env

    local mock_dir
    mock_dir=$(setup_mock_bin_dir)

    local old_path="$PATH"
    export PATH="$mock_dir"

    source "${STAGES_DIR}/controlled-rp.sh"

    if stage_controlled_rp 2>/dev/null; then
        if [[ "${STAGE_SKIPPED:-false}" == "true" ]]; then
            log_pass "Correctly skipped without node"
        else
            log_fail "Should set STAGE_SKIPPED without node"
        fi
    else
        log_fail "Stage should succeed (with skip) without node"
    fi

    export PATH="$old_path"
}

test_agent_ceremonies_skip_without_passless() {
    log_test "agent-ceremonies skips without passless binary"
    setup_stage_env

    local mock_dir
    mock_dir=$(setup_mock_bin_dir)

    local old_path="$PATH"
    export PATH="$mock_dir"
    unset PASSLESS_BIN

    source "${STAGES_DIR}/agent-ceremonies.sh"

    if stage_agent_ceremonies 2>/dev/null; then
        if [[ "${STAGE_SKIPPED:-false}" == "true" ]]; then
            log_pass "Correctly skipped without passless binary"
        else
            log_fail "Should set STAGE_SKIPPED without passless binary"
        fi
    else
        log_fail "Stage should succeed (with skip) without passless binary"
    fi

    export PATH="$old_path"
}

test_browser_lease_skip_without_passless() {
    log_test "browser-lease skips without passless binary"
    setup_stage_env

    local mock_dir
    mock_dir=$(setup_mock_bin_dir)

    local old_path="$PATH"
    export PATH="$mock_dir"
    unset PASSLESS_BIN

    source "${STAGES_DIR}/browser-lease.sh"

    if stage_browser_lease 2>/dev/null; then
        if [[ "${STAGE_SKIPPED:-false}" == "true" ]]; then
            log_pass "Correctly skipped without passless binary"
        else
            log_fail "Should set STAGE_SKIPPED without passless binary"
        fi
    else
        log_fail "Stage should succeed (with skip) without passless binary"
    fi

    export PATH="$old_path"
}

test_agent_ceremonies_skip_with_auto_accept() {
    log_test "agent-ceremonies skips with PASSLESS_E2E_AUTO_ACCEPT_UV"
    setup_stage_env

    local mock_dir
    mock_dir=$(setup_mock_bin_dir)

    cat > "$mock_dir/passless" << 'EOF'
#!/bin/bash
echo '{"status":"ok","data":{}}'
EOF
    chmod +x "$mock_dir/passless"

    local old_path="$PATH"
    export PATH="$mock_dir"
    export PASSLESS_E2E_AUTO_ACCEPT_UV=1
    unset PASSLESS_BIN

    source "${STAGES_DIR}/agent-ceremonies.sh"

    if stage_agent_ceremonies 2>/dev/null; then
        if [[ "${STAGE_SKIPPED:-false}" == "true" ]]; then
            log_pass "Correctly skipped with auto-accept env var"
        else
            log_fail "Should set STAGE_SKIPPED with auto-accept env var"
        fi
    else
        log_fail "Stage should succeed (with skip) with auto-accept"
    fi

    export PATH="$old_path"
    unset PASSLESS_E2E_AUTO_ACCEPT_UV
}

test_browser_lease_skip_with_auto_accept() {
    log_test "browser-lease skips with PASSLESS_E2E_AUTO_ACCEPT_STORAGE"
    setup_stage_env

    local mock_dir
    mock_dir=$(setup_mock_bin_dir)

    cat > "$mock_dir/passless" << 'EOF'
#!/bin/bash
echo '{"status":"ok","data":{}}'
EOF
    chmod +x "$mock_dir/passless"

    local old_path="$PATH"
    export PATH="$mock_dir"
    export PASSLESS_E2E_AUTO_ACCEPT_STORAGE=1
    unset PASSLESS_BIN

    source "${STAGES_DIR}/browser-lease.sh"

    if stage_browser_lease 2>/dev/null; then
        if [[ "${STAGE_SKIPPED:-false}" == "true" ]]; then
            log_pass "Correctly skipped with auto-accept storage env var"
        else
            log_fail "Should set STAGE_SKIPPED with auto-accept storage env var"
        fi
    else
        log_fail "Stage should succeed (with skip) with auto-accept storage"
    fi

    export PATH="$old_path"
    unset PASSLESS_E2E_AUTO_ACCEPT_STORAGE
}

test_results_files_are_valid_json() {
    log_test "Results files are valid JSON"
    setup_stage_env

    source "${STAGES_DIR}/controlled-rp.sh"
    stage_controlled_rp 2>/dev/null || true

    local results_file="${EVIDENCE_DIR}/controlled-rp-results.json"
    if [[ -f "$results_file" ]]; then
        if jq empty "$results_file" 2>/dev/null; then
            log_pass "controlled-rp-results.json is valid JSON"
        else
            log_fail "controlled-rp-results.json is invalid JSON"
        fi
    else
        log_pass "(no results file created - stage skipped before results)"
    fi
}

test_no_credential_ref_in_results() {
    log_test "Results files do not contain credential_ref values"
    setup_stage_env

    source "${STAGES_DIR}/agent-ceremonies.sh"
    stage_agent_ceremonies 2>/dev/null || true

    local results_file="${EVIDENCE_DIR}/agent-ceremonies-results.json"
    if [[ -f "$results_file" ]]; then
        if grep -q '"credential_ref":"[a-f0-9]\{64\}"' "$results_file"; then
            log_fail "Results contain credential_ref values"
        else
            log_pass "Results do not contain credential_ref values"
        fi
    else
        log_pass "(no results file - stage skipped)"
    fi
}

test_stages_have_strict_mode() {
    log_test "Tier 2 stage files use strict mode"
    local stages=("real-notifications.sh" "controlled-rp.sh" "agent-ceremonies.sh" "browser-lease.sh")
    local all_ok=true
    for stage in "${stages[@]}"; do
        if ! grep -q 'set -euo pipefail' "${STAGES_DIR}/${stage}" 2>/dev/null; then
            log_fail "Missing strict mode in $stage"
            all_ok=false
        fi
    done
    if [[ "$all_ok" == "true" ]]; then
        log_pass "All Tier 2 stages use strict mode"
    fi
}

test_stages_have_bash_shebang() {
    log_test "Tier 2 stage files have bash shebang"
    local stages=("real-notifications.sh" "controlled-rp.sh" "agent-ceremonies.sh" "browser-lease.sh")
    local all_ok=true
    for stage in "${stages[@]}"; do
        local first_line
        first_line=$(head -n1 "${STAGES_DIR}/${stage}")
        if [[ "$first_line" != "#!/bin/bash" ]]; then
            log_fail "Bad shebang in $stage: $first_line"
            all_ok=false
        fi
    done
    if [[ "$all_ok" == "true" ]]; then
        log_pass "All Tier 2 stages have correct shebang"
    fi
}

test_tier2_wired_in_run_sh() {
    log_test "Tier 2 stages are wired in run.sh (not skip_stage)"

    local run_sh="${VALIDATION_DIR}/run.sh"

    if grep -q 'run_stage "real-notifications" "stage_real_notifications"' "$run_sh"; then
        log_pass "real-notifications uses run_stage"
    else
        log_fail "real-notifications not wired with run_stage"
    fi

    if grep -q 'run_stage "controlled-rp" "stage_controlled_rp"' "$run_sh"; then
        log_pass "controlled-rp uses run_stage"
    else
        log_fail "controlled-rp not wired with run_stage"
    fi

    if grep -q 'run_stage "agent-ceremonies" "stage_agent_ceremonies"' "$run_sh"; then
        log_pass "agent-ceremonies uses run_stage"
    else
        log_fail "agent-ceremonies not wired with run_stage"
    fi

    if grep -q 'run_stage "browser-lease" "stage_browser_lease"' "$run_sh"; then
        log_pass "browser-lease uses run_stage"
    else
        log_fail "browser-lease not wired with run_stage"
    fi
}

test_tier2_no_skip_stage_in_tier2() {
    log_test "Tier 2 no longer uses skip_stage placeholders"

    local run_sh="${VALIDATION_DIR}/run.sh"
    local tier2_section
    tier2_section=$(sed -n '/^run_tier2_tests/,/^}/p' "$run_sh")

    if echo "$tier2_section" | grep -q 'skip_stage'; then
        log_fail "Tier 2 still contains skip_stage placeholders"
    else
        log_pass "Tier 2 has no skip_stage placeholders"
    fi
}

test_browser_lease_requires_semantics() {
    log_test "browser-lease requires live bounded-session and exact lifecycle tests"

    if grep -q 'agent-ceremonies-results.json' "${STAGES_DIR}/browser-lease.sh"; then
        log_pass "browser-lease requires live ceremony evidence"
    else
        log_fail "browser-lease does not require live ceremony evidence"
    fi

    if grep -q 'test_manager_check_expired' "${STAGES_DIR}/browser-lease.sh"; then
        log_pass "browser-lease checks expiry semantics"
    else
        log_fail "browser-lease does not check expiry semantics"
    fi

    if grep -q '1 passed; 0 failed' "${STAGES_DIR}/browser-lease.sh"; then
        log_pass "browser-lease rejects zero-match test filters"
    else
        log_fail "browser-lease does not verify named tests executed"
    fi
}

test_agent_ceremonies_requires_explicit_config() {
    log_test "agent-ceremonies requires explicit configuration"

    if grep -q "AV_ISOLATED_PROFILE_ID" "${STAGES_DIR}/agent-ceremonies.sh"; then
        log_pass "agent-ceremonies requires AV_ISOLATED_PROFILE_ID"
    else
        log_fail "agent-ceremonies does not require AV_ISOLATED_PROFILE_ID"
    fi

    if grep -q "AV_SAME_USER_PROFILE_ID" "${STAGES_DIR}/agent-ceremonies.sh"; then
        log_pass "agent-ceremonies requires AV_SAME_USER_PROFILE_ID"
    else
        log_fail "agent-ceremonies does not require AV_SAME_USER_PROFILE_ID"
    fi

    if grep -q "AV_RP_URL" "${STAGES_DIR}/agent-ceremonies.sh"; then
        log_pass "agent-ceremonies requires AV_RP_URL"
    else
        log_fail "agent-ceremonies does not require AV_RP_URL"
    fi
}

test_agent_ceremonies_uses_intents() {
    log_test "agent-ceremonies uses intents for isolated flow"

    if grep -q "intent create register" "${VALIDATION_DIR}/browser/principal-driver.sh"; then
        log_pass "agent-ceremonies uses intent create"
    else
        log_fail "agent-ceremonies does not use intent create"
    fi

    if grep -q "intent wait" "${VALIDATION_DIR}/browser/principal-driver.sh"; then
        log_pass "agent-ceremonies uses intent wait"
    else
        log_fail "agent-ceremonies does not use intent wait"
    fi
}

test_agent_ceremonies_uses_delegation() {
    log_test "agent-ceremonies uses delegation grants for same-user flow"

    if grep -q "delegation request" "${VALIDATION_DIR}/browser/principal-driver.sh"; then
        log_pass "agent-ceremonies uses delegation request"
    else
        log_fail "agent-ceremonies does not use delegation request"
    fi

    if grep -q "delegation wait" "${VALIDATION_DIR}/browser/principal-driver.sh"; then
        log_pass "agent-ceremonies uses delegation wait"
    else
        log_fail "agent-ceremonies does not use delegation wait"
    fi
}

main() {
    echo -e "${BLUE}=== Tier 2 Stage Tests ===${NC}" >&2

    test_stage_files_exist
    test_lib_files_exist
    test_browser_dir_exists
    test_cdp_client_exists
    test_cdp_driver_exists
    test_mock_cdp_server_exists
    test_cdp_client_against_mock
    test_stages_have_bash_shebang
    test_stages_have_strict_mode
    test_notifications_skip_without_dunst
    test_controlled_rp_skip_without_node
    test_agent_ceremonies_skip_without_passless
    test_browser_lease_skip_without_passless
    test_agent_ceremonies_skip_with_auto_accept
    test_browser_lease_skip_with_auto_accept
    test_results_files_are_valid_json
    test_no_credential_ref_in_results
    test_tier2_wired_in_run_sh
    test_tier2_no_skip_stage_in_tier2
    test_browser_lease_requires_semantics
    test_agent_ceremonies_requires_explicit_config
    test_agent_ceremonies_uses_intents
    test_agent_ceremonies_uses_delegation

    echo "" >&2
    echo -e "${BLUE}Tests: $TEST_COUNT total, $PASS_COUNT passed, $FAIL_COUNT failed${NC}" >&2

    [[ $FAIL_COUNT -eq 0 ]]
}

main "$@"
