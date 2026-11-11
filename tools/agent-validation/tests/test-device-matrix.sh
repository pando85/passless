#!/bin/bash
#
# Shell tests for lib/device-matrix.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATION_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LIB_DIR="${VALIDATION_DIR}/lib"
REPO_ROOT="$(cd "${VALIDATION_DIR}/../.." && pwd)"

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

test_static_contrib_analysis_produces_json() {
    log_test "Static contrib udev analysis produces valid JSON"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/device-matrix.sh"

    local output_file="${TEST_TMP_DIR}/static-contrib.json"
    if ! av_static_contrib_udev_analysis "$REPO_ROOT" "$output_file"; then
        log_fail "Static contrib analysis failed"
        return 1
    fi

    if jq empty "$output_file" 2>/dev/null; then
        log_pass "Static contrib analysis is valid JSON"
    else
        log_fail "Static contrib analysis is not valid JSON"
        return 1
    fi
}

test_contrib_uhid_human_group_only() {
    log_test "contrib/udev/90-passless.rules grants /dev/uhid only to group fido"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/device-matrix.sh"

    local output_file="${TEST_TMP_DIR}/static-contrib-uhid.json"
    av_static_contrib_udev_analysis "$REPO_ROOT" "$output_file"

    local group mode human_only not_world
    group=$(jq -r '.observed.uhid_group' "$output_file")
    mode=$(jq -r '.observed.uhid_mode' "$output_file")
    human_only=$(jq -r '.policy_checks.UHID_HUMAN_GROUP_ONLY' "$output_file")
    not_world=$(jq -r '.policy_checks.UHID_NOT_WORLD_ACCESSIBLE' "$output_file")

    if [[ "$group" == "fido" ]] && [[ "$human_only" == "pass" ]] && [[ "$not_world" == "pass" ]]; then
        log_pass "/dev/uhid is GROUP=$group MODE=$mode"
    else
        log_fail "/dev/uhid policy incorrect: group=$group mode=$mode human_only=$human_only not_world=$not_world"
        return 1
    fi
}

test_contrib_agent_udev_rule_absent() {
    log_test "contrib/udev/70-passless-agent.rules does not exist"
    if [[ ! -e "${REPO_ROOT}/contrib/udev/70-passless-agent.rules" ]]; then
        log_pass "Agent hidraw udev rule is absent"
    else
        log_fail "contrib/udev/70-passless-agent.rules must not exist"
        return 1
    fi
}

test_contrib_service_no_agent_device_grants() {
    log_test "passless-agent.service has no agent device grants or hidraw rule reference"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/device-matrix.sh"

    local output_file="${TEST_TMP_DIR}/static-contrib-service.json"
    av_static_contrib_udev_analysis "$REPO_ROOT" "$output_file"

    local no_allow no_ref
    no_allow=$(jq -r '.policy_checks.NO_AGENT_DEVICE_ALLOW' "$output_file")
    no_ref=$(jq -r '.policy_checks.NO_AGENT_RULE_REFERENCE' "$output_file")

    if [[ "$no_allow" == "pass" ]] && [[ "$no_ref" == "pass" ]]; then
        log_pass "Service has no DeviceAllow/uhid/hidraw grants and no agent rule reference"
    else
        log_fail "Service device policy incorrect: no_allow=$no_allow no_ref=$no_ref"
        return 1
    fi
}

test_static_contrib_analysis_detects_violations() {
    log_test "Static contrib analysis flags violating fixtures"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/device-matrix.sh"

    local fake="${TEST_TMP_DIR}/fake-root"
    mkdir -p "${fake}/contrib/udev" "${fake}/contrib/systemd"
    printf 'KERNEL=="uhid", GROUP="users", MODE="0666"\n' > "${fake}/contrib/udev/90-passless.rules"
    : > "${fake}/contrib/udev/70-passless-agent.rules"
    printf '[Service]\nDeviceAllow=/dev/uhid rw\n# see 70-passless-agent.rules\n' > "${fake}/contrib/systemd/passless-agent.service"

    local output_file="${TEST_TMP_DIR}/static-contrib-bad.json"
    av_static_contrib_udev_analysis "$fake" "$output_file"

    local fails
    fails=$(jq '[.policy_checks[] | select(. == "fail")] | length' "$output_file")
    if [[ "$fails" == "5" ]]; then
        log_pass "All 5 policy checks flag the violating fixture"
    else
        log_fail "Expected 5 failing checks on violating fixture, got $fails"
        return 1
    fi
}

test_generate_matrix_json_static() {
    log_test "av_generate_matrix_json static targets contrib files"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/device-matrix.sh"

    local output_file="${TEST_TMP_DIR}/matrix-static.json"
    av_generate_matrix_json "$output_file" static

    local rules_file
    rules_file=$(jq -r '.rules_file' "$output_file" 2>/dev/null || echo "missing")
    if [[ "$rules_file" == *"/contrib/udev/90-passless.rules" ]]; then
        log_pass "Static matrix points at contrib/udev/90-passless.rules"
    else
        log_fail "Static matrix rules_file unexpected: $rules_file"
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
    test_static_contrib_analysis_produces_json
    test_contrib_uhid_human_group_only
    test_contrib_agent_udev_rule_absent
    test_contrib_service_no_agent_device_grants
    test_static_contrib_analysis_detects_violations
    test_generate_matrix_json_static

    echo "" >&2
    echo -e "${BLUE}Tests: $TEST_COUNT total, $PASS_COUNT passed, $FAIL_COUNT failed${NC}" >&2

    [[ $FAIL_COUNT -eq 0 ]]
}

main "$@"
