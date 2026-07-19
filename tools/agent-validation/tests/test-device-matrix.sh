#!/bin/bash
#
# Shell tests for lib/device-matrix.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATION_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LIB_DIR="${VALIDATION_DIR}/lib"
PHASE0_DIR="${VALIDATION_DIR}/../agent-uhid-feasibility"

TEST_TMP_DIR="/tmp/passless-av-dev-test-$$"
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

cleanup() { rm -rf "$TEST_TMP_DIR" 2>/dev/null || true; }
trap cleanup EXIT

mkdir -p "$TEST_TMP_DIR"

test_device_matrix_lib_exists() {
    log_test "device-matrix.sh exists"
    if [[ -f "${LIB_DIR}/device-matrix.sh" ]]; then
        log_pass "device-matrix.sh exists"
    else
        log_fail "device-matrix.sh not found"
        return 1
    fi
}

test_discover_device_nodes() {
    log_test "discover_device_nodes returns results"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/device-matrix.sh"

    local devices
    devices=$(av_discover_device_nodes)

    if [[ -e /dev/uhid ]]; then
        if echo "$devices" | grep -q "/dev/uhid"; then
            log_pass "/dev/uhid discovered"
        else
            log_fail "/dev/uhid not discovered"
            return 1
        fi
    else
        log_test "(skipped: /dev/uhid not present)"
    fi
}

test_probe_device_access_produces_json() {
    log_test "probe_device_access produces valid JSON"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/device-matrix.sh"

    local target="/dev/uhid"
    if [[ ! -e "$target" ]]; then
        target="/dev/null"
    fi

    local result
    result=$(av_probe_device_access "$target")

    if echo "$result" | jq empty 2>/dev/null; then
        log_pass "Device probe produces valid JSON"
    else
        log_fail "Device probe produces invalid JSON"
        return 1
    fi
}

test_probe_nonexistent_device() {
    log_test "probe_device_access handles nonexistent device"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/device-matrix.sh"

    local result
    result=$(av_probe_device_access "/dev/nonexistent_device_xyz")

    local exists
    exists=$(echo "$result" | jq -r '.exists')

    if [[ "$exists" == "false" ]]; then
        log_pass "Nonexistent device reported as exists=false"
    else
        log_fail "Nonexistent device not handled correctly"
        return 1
    fi
}

test_build_access_matrix_produces_json() {
    log_test "build_access_matrix produces valid JSON"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/device-matrix.sh"

    local matrix_file="${TEST_TMP_DIR}/matrix.json"
    av_build_access_matrix "$matrix_file"

    if [[ ! -f "$matrix_file" ]]; then
        log_fail "Matrix file not created"
        return 1
    fi

    if jq empty "$matrix_file" 2>/dev/null; then
        log_pass "Access matrix is valid JSON"
    else
        log_fail "Access matrix is not valid JSON"
        return 1
    fi
}

test_access_matrix_contains_identity() {
    log_test "Access matrix contains identity information"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/device-matrix.sh"

    local matrix_file="${TEST_TMP_DIR}/matrix-identity.json"
    av_build_access_matrix "$matrix_file"

    local uid
    uid=$(jq -r '.identity.uid' "$matrix_file" 2>/dev/null || echo "missing")
    local username
    username=$(jq -r '.identity.username' "$matrix_file" 2>/dev/null || echo "missing")

    if [[ "$uid" != "missing" ]] && [[ "$username" != "missing" ]]; then
        log_pass "Identity info present (uid=$uid, user=$username)"
    else
        log_fail "Identity info missing"
        return 1
    fi
}

test_static_udev_analysis() {
    log_test "Static udev analysis produces valid JSON"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/device-matrix.sh"

    local rules_file="${PHASE0_DIR}/policy/90-uhid-feasibility.rules"
    if [[ ! -f "$rules_file" ]]; then
        log_test "(skipped: Phase0 rules file not found)"
        return 0
    fi

    local output_file="${TEST_TMP_DIR}/static-analysis.json"
    av_static_udev_analysis "$rules_file" "$output_file"

    if [[ ! -f "$output_file" ]]; then
        log_fail "Static analysis file not created"
        return 1
    fi

    if jq empty "$output_file" 2>/dev/null; then
        log_pass "Static analysis is valid JSON"
    else
        log_fail "Static analysis is not valid JSON"
        return 1
    fi
}

test_static_analysis_policy_checks() {
    log_test "Static analysis includes PRIN-03/ROUTE-03/ISOL-01 checks"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/device-matrix.sh"

    local rules_file="${PHASE0_DIR}/policy/90-uhid-feasibility.rules"
    if [[ ! -f "$rules_file" ]]; then
        log_test "(skipped: Phase0 rules file not found)"
        return 0
    fi

    local output_file="${TEST_TMP_DIR}/static-policy.json"
    av_static_udev_analysis "$rules_file" "$output_file"

    local prin03 route03 isol01
    prin03=$(jq -r '.policy_checks.PRIN_03' "$output_file" 2>/dev/null || echo "missing")
    route03=$(jq -r '.policy_checks.ROUTE_03' "$output_file" 2>/dev/null || echo "missing")
    isol01=$(jq -r '.policy_checks.ISOL_01' "$output_file" 2>/dev/null || echo "missing")

    if [[ "$prin03" != "missing" ]] && [[ "$route03" != "missing" ]] && [[ "$isol01" != "missing" ]]; then
        log_pass "Policy checks present: PRIN-03=$prin03 ROUTE-03=$route03 ISOL-01=$isol01"
    else
        log_fail "Policy checks missing"
        return 1
    fi
}

test_static_analysis_identity_model() {
    log_test "Static analysis includes expected identity model"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/device-matrix.sh"

    local rules_file="${PHASE0_DIR}/policy/90-uhid-feasibility.rules"
    if [[ ! -f "$rules_file" ]]; then
        log_test "(skipped: Phase0 rules file not found)"
        return 0
    fi

    local output_file="${TEST_TMP_DIR}/static-identity.json"
    av_static_udev_analysis "$rules_file" "$output_file"

    local human_group daemon_group agent_group
    human_group=$(jq -r '.expected_identity_model.human_group' "$output_file" 2>/dev/null || echo "missing")
    daemon_group=$(jq -r '.expected_identity_model.daemon_group' "$output_file" 2>/dev/null || echo "missing")
    agent_group=$(jq -r '.expected_identity_model.agent_group' "$output_file" 2>/dev/null || echo "missing")

    if [[ "$human_group" == "fido" ]] && [[ "$daemon_group" == "uhid-daemon" ]] && [[ "$agent_group" == "fido-agent-probe" ]]; then
        log_pass "Identity model correct: human=$human_group daemon=$daemon_group agent=$agent_group"
    else
        log_fail "Identity model incorrect: human=$human_group daemon=$daemon_group agent=$agent_group"
        return 1
    fi
}

test_uhid_group_not_human() {
    log_test "Static analysis confirms /dev/uhid not in human group"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/device-matrix.sh"

    local rules_file="${PHASE0_DIR}/policy/90-uhid-feasibility.rules"
    if [[ ! -f "$rules_file" ]]; then
        log_test "(skipped: Phase0 rules file not found)"
        return 0
    fi

    local output_file="${TEST_TMP_DIR}/static-uhid.json"
    av_static_udev_analysis "$rules_file" "$output_file"

    local prin03
    prin03=$(jq -r '.policy_checks.PRIN_03' "$output_file" 2>/dev/null || echo "missing")

    if [[ "$prin03" == "pass" ]]; then
        log_pass "/dev/uhid not in human group (PRIN-03 pass)"
    else
        log_fail "/dev/uhid may be in human group (PRIN-03=$prin03)"
        return 1
    fi
}

main() {
    echo -e "${BLUE}=== Device Matrix Tests ===${NC}" >&2

    test_device_matrix_lib_exists
    test_discover_device_nodes
    test_probe_device_access_produces_json
    test_probe_nonexistent_device
    test_build_access_matrix_produces_json
    test_access_matrix_contains_identity
    test_static_udev_analysis
    test_static_analysis_policy_checks
    test_static_analysis_identity_model
    test_uhid_group_not_human

    echo "" >&2
    echo -e "${BLUE}Tests: $TEST_COUNT total, $PASS_COUNT passed, $FAIL_COUNT failed${NC}" >&2

    [[ $FAIL_COUNT -eq 0 ]]
}

main "$@"
