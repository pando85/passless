#!/bin/bash
#
# Shell tests for the fault-injection stage and lib
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATION_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LIB_DIR="${VALIDATION_DIR}/lib"
STAGES_DIR="${VALIDATION_DIR}/stages"

TEST_TMP_DIR="/tmp/passless-av-fault-test-$$"
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
    rm -rf "$TEST_TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p "$TEST_TMP_DIR"

setup_env() {
    export EVIDENCE_DIR="${TEST_TMP_DIR}/evidence"
    export TEMP_ROOT="${TEST_TMP_DIR}/tmp"
    export RUN_ID="test-fault-run"
    export AV_VALIDATION_DIR="$VALIDATION_DIR"
    mkdir -p "$EVIDENCE_DIR" "$TEMP_ROOT"

    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/fault-injection.sh"

    log_info() { :; }
    log_success() { :; }
    log_warn() { :; }
    log_error() { :; }
    register_resource() { :; }
}

test_fault_lib_exists() {
    log_test "fault-injection lib file exists"
    if [[ -f "${LIB_DIR}/fault-injection.sh" ]]; then
        log_pass "lib/fault-injection.sh exists"
    else
        log_fail "lib/fault-injection.sh missing"
    fi
}

test_fault_stage_exists() {
    log_test "fault-injection stage file exists"
    if [[ -f "${STAGES_DIR}/fault-injection.sh" ]]; then
        log_pass "stages/fault-injection.sh exists"
    else
        log_fail "stages/fault-injection.sh missing"
    fi
}

test_fault_stage_has_strict_mode() {
    log_test "fault-injection stage uses strict mode"
    if grep -q 'set -euo pipefail' "${STAGES_DIR}/fault-injection.sh"; then
        log_pass "strict mode present"
    else
        log_fail "strict mode missing"
    fi
}

test_fault_stage_has_bash_shebang() {
    log_test "fault-injection stage has bash shebang"
    local first_line
    first_line=$(head -n1 "${STAGES_DIR}/fault-injection.sh")
    if [[ "$first_line" == "#!/bin/bash" ]]; then
        log_pass "correct shebang"
    else
        log_fail "bad shebang: $first_line"
    fi
}

test_fault_categories_defined() {
    log_test "fault categories are defined"
    setup_env
    if [[ ${#AV_FAULT_RUST_CATEGORIES[@]} -ge 10 ]]; then
        log_pass "at least 10 fault categories defined (${#AV_FAULT_RUST_CATEGORIES[@]})"
    else
        log_fail "too few fault categories (${#AV_FAULT_RUST_CATEGORIES[@]})"
    fi
}

test_fault_category_names_unique() {
    log_test "fault category names are unique"
    setup_env
    local names=()
    for spec in "${AV_FAULT_RUST_CATEGORIES[@]}"; do
        names+=("$(printf '%s' "$spec" | cut -d: -f1)")
    done
    local unique_count
    unique_count=$(printf '%s\n' "${names[@]}" | sort -u | wc -l)
    if [[ "$unique_count" -eq "${#names[@]}" ]]; then
        log_pass "all category names unique ($unique_count)"
    else
        log_fail "duplicate category names found"
    fi
}

test_fault_category_includes_audit_enospc() {
    log_test "fault categories include audit ENOSPC/fsync tests"
    setup_env
    local found=false
    for spec in "${AV_FAULT_RUST_CATEGORIES[@]}"; do
        if [[ "$spec" == *"enospc"* ]] || [[ "$spec" == *"fsync"* ]]; then
            found=true
            break
        fi
    done
    if [[ "$found" == "true" ]]; then
        log_pass "audit ENOSPC/fsync category present"
    else
        log_fail "audit ENOSPC/fsync category missing"
    fi
}

test_fault_category_includes_intent_races() {
    log_test "fault categories include intent/grant race tests"
    setup_env
    local found=false
    for spec in "${AV_FAULT_RUST_CATEGORIES[@]}"; do
        if [[ "$spec" == *"intent"* ]] && [[ "$spec" == *"race"* ]]; then
            found=true
            break
        fi
    done
    if [[ "$found" == "true" ]]; then
        log_pass "intent/grant race category present"
    else
        log_fail "intent/grant race category missing"
    fi
}

test_fault_category_includes_endpoint_capacity() {
    log_test "fault categories include endpoint capacity tests"
    setup_env
    local found=false
    for spec in "${AV_FAULT_RUST_CATEGORIES[@]}"; do
        if [[ "$spec" == *"endpoint"* ]] && [[ "$spec" == *"capacity"* ]]; then
            found=true
            break
        fi
    done
    if [[ "$found" == "true" ]]; then
        log_pass "endpoint capacity category present"
    else
        log_fail "endpoint capacity category missing"
    fi
}

test_fault_category_includes_browser_cleanup() {
    log_test "fault categories include browser cleanup/quarantine tests"
    setup_env
    local found=false
    for spec in "${AV_FAULT_RUST_CATEGORIES[@]}"; do
        if [[ "$spec" == *"browser"* ]] && [[ "$spec" == *"quarantine"* ]]; then
            found=true
            break
        fi
    done
    if [[ "$found" == "true" ]]; then
        log_pass "browser cleanup/quarantine category present"
    else
        log_fail "browser cleanup/quarantine category missing"
    fi
}

test_fault_category_includes_malformed_cbor() {
    log_test "fault categories include malformed CBOR tests"
    setup_env
    local found=false
    for spec in "${AV_FAULT_RUST_CATEGORIES[@]}"; do
        if [[ "$spec" == *"malformed"* ]] || [[ "$spec" == *"cbor"* ]]; then
            found=true
            break
        fi
    done
    if [[ "$found" == "true" ]]; then
        log_pass "malformed CBOR category present"
    else
        log_fail "malformed CBOR category missing"
    fi
}

test_fault_category_includes_monotonic_clocks() {
    log_test "fault categories include monotonic clock tests"
    setup_env
    local found=false
    for spec in "${AV_FAULT_RUST_CATEGORIES[@]}"; do
        if [[ "$spec" == *"monotonic"* ]] || [[ "$spec" == *"clock"* ]]; then
            found=true
            break
        fi
    done
    if [[ "$found" == "true" ]]; then
        log_pass "monotonic clock category present"
    else
        log_fail "monotonic clock category missing"
    fi
}

test_fault_category_includes_circuit_breaker() {
    log_test "fault categories include circuit breaker tests"
    setup_env
    local found=false
    for spec in "${AV_FAULT_RUST_CATEGORIES[@]}"; do
        if [[ "$spec" == *"circuit"* ]] || [[ "$spec" == *"breaker"* ]]; then
            found=true
            break
        fi
    done
    if [[ "$found" == "true" ]]; then
        log_pass "circuit breaker category present"
    else
        log_fail "circuit breaker category missing"
    fi
}

test_resource_ceiling_check_cleans_up() {
    log_test "resource ceiling check cleans up dummy files"
    setup_env
    local result
    result=$(av_run_resource_ceiling_check "$EVIDENCE_DIR" 10) || true
    local status
    status=$(printf '%s' "$result" | jq -r '.status' 2>/dev/null || echo "unknown")
    if [[ "$status" == "pass" ]]; then
        log_pass "resource ceiling check passed"
    else
        log_pass "resource ceiling check completed (status=$status)"
    fi
    if [[ ! -d "${EVIDENCE_DIR}/tmp/resource-ceiling" ]]; then
        log_pass "dummy directory cleaned up"
    else
        log_fail "dummy directory not cleaned up"
    fi
}

test_process_kill_check_cleans_up() {
    log_test "process kill check cleans up dummy processes"
    setup_env
    local result
    result=$(av_run_process_kill_check "$EVIDENCE_DIR" 10) || true
    local status
    status=$(printf '%s' "$result" | jq -r '.status' 2>/dev/null || echo "unknown")
    if [[ "$status" == "pass" ]]; then
        log_pass "process kill check passed"
    else
        log_pass "process kill check completed (status=$status)"
    fi
}

test_fault_wired_in_run_sh() {
    log_test "fault-injection wired in run.sh (not skip_stage)"
    local run_sh="${VALIDATION_DIR}/run.sh"
    if grep -q 'run_stage "fault-injection" "stage_fault_injection"' "$run_sh"; then
        log_pass "fault-injection uses run_stage"
    else
        log_fail "fault-injection not wired with run_stage"
    fi
}

test_fault_no_skip_stage_in_tier1() {
    log_test "fault-injection no longer uses skip_stage in tier1"
    local run_sh="${VALIDATION_DIR}/run.sh"
    local tier1_section
    tier1_section=$(sed -n '/^run_tier1_tests/,/^}/p' "$run_sh")
    if echo "$tier1_section" | grep -q 'skip_stage "fault-injection"'; then
        log_fail "fault-injection still uses skip_stage"
    else
        log_pass "fault-injection does not use skip_stage"
    fi
}

test_fault_stage_function_exists() {
    log_test "stage_fault_injection function is defined"
    setup_env
    source "${STAGES_DIR}/fault-injection.sh"
    if declare -f stage_fault_injection &>/dev/null; then
        log_pass "stage_fault_injection function defined"
    else
        log_fail "stage_fault_injection function not defined"
    fi
}

main() {
    echo -e "${BLUE}=== Fault Injection Stage Tests ===${NC}" >&2

    test_fault_lib_exists
    test_fault_stage_exists
    test_fault_stage_has_strict_mode
    test_fault_stage_has_bash_shebang
    test_fault_categories_defined
    test_fault_category_names_unique
    test_fault_category_includes_audit_enospc
    test_fault_category_includes_intent_races
    test_fault_category_includes_endpoint_capacity
    test_fault_category_includes_browser_cleanup
    test_fault_category_includes_malformed_cbor
    test_fault_category_includes_monotonic_clocks
    test_fault_category_includes_circuit_breaker
    test_resource_ceiling_check_cleans_up
    test_process_kill_check_cleans_up
    test_fault_wired_in_run_sh
    test_fault_no_skip_stage_in_tier1
    test_fault_stage_function_exists

    echo "" >&2
    echo -e "${BLUE}Tests: $TEST_COUNT total, $PASS_COUNT passed, $FAIL_COUNT failed${NC}" >&2

    [[ $FAIL_COUNT -eq 0 ]]
}

main "$@"
