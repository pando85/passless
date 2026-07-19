#!/bin/bash
#
# Shell tests for lib/principal.sh (probe-based)
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATION_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LIB_DIR="${VALIDATION_DIR}/lib"
FIXTURES_DIR="${VALIDATION_DIR}/fixtures/probe"

TEST_TMP_DIR="/tmp/passless-av-prin-test-$$"
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

test_principal_lib_exists() {
    log_test "principal.sh exists"
    if [[ -f "${LIB_DIR}/principal.sh" ]]; then
        log_pass "principal.sh exists"
    else
        log_fail "principal.sh not found"
        return 1
    fi
}

test_fixture_files_exist() {
    log_test "fixture files exist"
    local all_ok=true
    for f in valid-isolated.json root-with-caps.json invalid-schema.json; do
        if [[ ! -f "${FIXTURES_DIR}/$f" ]]; then
            log_fail "missing fixture: $f"
            all_ok=false
        fi
    done
    if [[ "$all_ok" == "true" ]]; then
        log_pass "all fixture files present"
    fi
}

test_validate_schema_valid_fixture() {
    log_test "validate_probe_json_schema accepts valid fixture"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    if av_validate_probe_json_schema "${FIXTURES_DIR}/valid-isolated.json" 2>/dev/null; then
        log_pass "valid fixture passes schema validation"
    else
        log_fail "valid fixture rejected by schema validation"
        return 1
    fi
}

test_validate_schema_rejects_invalid() {
    log_test "validate_probe_json_schema rejects invalid fixture"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    if av_validate_probe_json_schema "${FIXTURES_DIR}/invalid-schema.json" 2>/dev/null; then
        log_fail "invalid fixture should be rejected"
        return 1
    else
        log_pass "invalid fixture correctly rejected"
    fi
}

test_validate_schema_rejects_missing_file() {
    log_test "validate_probe_json_schema rejects missing file"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    if av_validate_probe_json_schema "${TEST_TMP_DIR}/nonexistent.json" 2>/dev/null; then
        log_fail "missing file should be rejected"
        return 1
    else
        log_pass "missing file correctly rejected"
    fi
}

test_validate_schema_rejects_bad_json() {
    log_test "validate_probe_json_schema rejects non-JSON"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    local bad_file="${TEST_TMP_DIR}/bad.json"
    echo "this is not json" > "$bad_file"

    if av_validate_probe_json_schema "$bad_file" 2>/dev/null; then
        log_fail "non-JSON should be rejected"
        return 1
    else
        log_pass "non-JSON correctly rejected"
    fi
}

test_check_uid_gid_match() {
    log_test "check_probe_uid_gid matches expected"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    if av_check_probe_uid_gid "${FIXTURES_DIR}/valid-isolated.json" "1001" "1001" 2>/dev/null; then
        log_pass "UID/GID match for expected values"
    else
        log_fail "UID/GID should match"
        return 1
    fi
}

test_check_uid_gid_mismatch() {
    log_test "check_probe_uid_gid detects mismatch"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    if av_check_probe_uid_gid "${FIXTURES_DIR}/valid-isolated.json" "9999" "9999" 2>/dev/null; then
        log_fail "UID/GID mismatch should be detected"
        return 1
    else
        log_pass "UID/GID mismatch correctly detected"
    fi
}

test_check_groups_match() {
    log_test "check_probe_groups matches expected"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    if av_check_probe_groups "${FIXTURES_DIR}/valid-isolated.json" "100,200" 2>/dev/null; then
        log_pass "groups match expected"
    else
        log_fail "groups should match"
        return 1
    fi
}

test_check_groups_missing() {
    log_test "check_probe_groups detects missing group"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    if av_check_probe_groups "${FIXTURES_DIR}/valid-isolated.json" "100,999" 2>/dev/null; then
        log_fail "missing group should be detected"
        return 1
    else
        log_pass "missing group correctly detected"
    fi
}

test_check_nnp_true() {
    log_test "check_probe_nnp passes for NNP=true"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    if av_check_probe_nnp "${FIXTURES_DIR}/valid-isolated.json" 2>/dev/null; then
        log_pass "NNP=true passes"
    else
        log_fail "NNP=true should pass"
        return 1
    fi
}

test_check_nnp_false() {
    log_test "check_probe_nnp fails for NNP=false"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    if av_check_probe_nnp "${FIXTURES_DIR}/root-with-caps.json" 2>/dev/null; then
        log_fail "NNP=false should fail"
        return 1
    else
        log_pass "NNP=false correctly fails"
    fi
}

test_check_cap_absence_clean() {
    log_test "check_probe_cap_absence passes for clean env"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    if av_check_probe_cap_absence "${FIXTURES_DIR}/valid-isolated.json" 2>/dev/null; then
        log_pass "cap absence passes for clean env"
    else
        log_fail "cap absence should pass"
        return 1
    fi
}

test_check_cap_absence_detects_caps() {
    log_test "check_probe_cap_absence detects capability vars"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    if av_check_probe_cap_absence "${FIXTURES_DIR}/root-with-caps.json" 2>/dev/null; then
        log_fail "cap presence should be detected"
        return 1
    else
        log_pass "cap presence correctly detected"
    fi
}

test_check_resource_outcomes_match() {
    log_test "check_probe_resource_outcomes matches expectations"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    if av_check_probe_resource_outcomes "${FIXTURES_DIR}/valid-isolated.json" \
        "/tmp/probe-readable-file=open_ok" \
        "/var/run/passless-agent/socket=connect_ok" 2>/dev/null; then
        log_pass "resource outcomes match"
    else
        log_fail "resource outcomes should match"
        return 1
    fi
}

test_check_resource_outcomes_mismatch() {
    log_test "check_probe_resource_outcomes detects mismatch"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    if av_check_probe_resource_outcomes "${FIXTURES_DIR}/valid-isolated.json" \
        "/tmp/probe-readable-file=connect_denied" 2>/dev/null; then
        log_fail "resource mismatch should be detected"
        return 1
    else
        log_pass "resource mismatch correctly detected"
    fi
}

test_check_resource_outcomes_not_found() {
    log_test "check_probe_resource_outcomes detects missing path"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    if av_check_probe_resource_outcomes "${FIXTURES_DIR}/valid-isolated.json" \
        "/nonexistent/path=open_ok" 2>/dev/null; then
        log_fail "missing path should be detected"
        return 1
    else
        log_pass "missing path correctly detected"
    fi
}

test_run_probe_rejects_relative_probe_path() {
    log_test "run_principal_probe rejects relative probe path"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    local out="${TEST_TMP_DIR}/probe-out.json"
    local err="${TEST_TMP_DIR}/probe-err.txt"

    if av_run_principal_probe "$out" "$err" "test" "/bin/true" "relative/probe" 2>/dev/null; then
        log_fail "relative probe path should be rejected"
        return 1
    else
        log_pass "relative probe path correctly rejected"
    fi
}

test_run_probe_rejects_missing_passless() {
    log_test "run_principal_probe rejects missing passless binary"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    local out="${TEST_TMP_DIR}/probe-out.json"
    local err="${TEST_TMP_DIR}/probe-err.txt"

    if av_run_principal_probe "$out" "$err" "test" "/nonexistent/passless" "/usr/bin/true" 2>/dev/null; then
        log_fail "missing passless should be rejected"
        return 1
    else
        log_pass "missing passless correctly rejected"
    fi
}

test_run_probe_rejects_missing_probe() {
    log_test "run_principal_probe rejects missing probe binary"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    local out="${TEST_TMP_DIR}/probe-out.json"
    local err="${TEST_TMP_DIR}/probe-err.txt"

    if av_run_principal_probe "$out" "$err" "test" "/bin/true" "/nonexistent/probe" 2>/dev/null; then
        log_fail "missing probe should be rejected"
        return 1
    else
        log_pass "missing probe correctly rejected"
    fi
}

test_check_probe_fd3_present_socket() {
    log_test "check_probe_fd3 passes for present socket with matching peer"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    if av_check_probe_fd3 "${FIXTURES_DIR}/valid-isolated.json" "1000" "1000" 2>/dev/null; then
        log_pass "fd3 present socket with matching peer passes"
    else
        log_fail "fd3 should pass"
        return 1
    fi
}

test_check_probe_fd3_absent() {
    log_test "check_probe_fd3 fails for absent fd3"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    local absent_fixture="${TEST_TMP_DIR}/fd3-absent.json"
    jq '.fd3.present = false' "${FIXTURES_DIR}/valid-isolated.json" > "$absent_fixture"

    if av_check_probe_fd3 "$absent_fixture" "1000" "1000" 2>/dev/null; then
        log_fail "absent fd3 should fail"
        return 1
    else
        log_pass "absent fd3 correctly fails"
    fi
}

test_check_probe_fd3_not_socket() {
    log_test "check_probe_fd3 fails for non-socket fd3"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    local file_fixture="${TEST_TMP_DIR}/fd3-file.json"
    jq '.fd3.fd_type = "file"' "${FIXTURES_DIR}/valid-isolated.json" > "$file_fixture"

    if av_check_probe_fd3 "$file_fixture" "1000" "1000" 2>/dev/null; then
        log_fail "non-socket fd3 should fail"
        return 1
    else
        log_pass "non-socket fd3 correctly fails"
    fi
}

test_check_probe_fd3_peer_mismatch() {
    log_test "check_probe_fd3 fails for peer UID mismatch"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    if av_check_probe_fd3 "${FIXTURES_DIR}/valid-isolated.json" "9999" "1000" 2>/dev/null; then
        log_fail "peer UID mismatch should fail"
        return 1
    else
        log_pass "peer UID mismatch correctly fails"
    fi
}

test_compare_probe_pid_json_metadata() {
    log_test "compare_probe_pid parses JSON .data.pid"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    local stderr_file="${TEST_TMP_DIR}/launch-stderr.json"
    echo '{"version":"1","status":"ok","data":{"pid":12345,"session_id":"test"}}' > "$stderr_file"

    if av_compare_probe_pid_with_launch_metadata "${FIXTURES_DIR}/valid-isolated.json" "$stderr_file" 2>/dev/null; then
        log_pass "JSON .data.pid parsed and matches"
    else
        log_fail "JSON .data.pid should match"
        return 1
    fi
}

test_compare_probe_pid_plain_metadata() {
    log_test "compare_probe_pid parses plain output"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    local stderr_file="${TEST_TMP_DIR}/launch-stderr.txt"
    echo "session_id: test-123" > "$stderr_file"
    echo "pid: 12345" >> "$stderr_file"
    echo "profile_id: test" >> "$stderr_file"

    if av_compare_probe_pid_with_launch_metadata "${FIXTURES_DIR}/valid-isolated.json" "$stderr_file" 2>/dev/null; then
        log_pass "plain pid parsed and matches"
    else
        log_fail "plain pid should match"
        return 1
    fi
}

test_compare_probe_pid_missing_metadata() {
    log_test "compare_probe_pid fails for missing metadata"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    local stderr_file="${TEST_TMP_DIR}/launch-stderr-empty.txt"
    echo "no pid here" > "$stderr_file"

    if av_compare_probe_pid_with_launch_metadata "${FIXTURES_DIR}/valid-isolated.json" "$stderr_file" 2>/dev/null; then
        log_fail "missing metadata should fail"
        return 1
    else
        log_pass "missing metadata correctly fails"
    fi
}

test_compare_probe_pid_mismatch() {
    log_test "compare_probe_pid fails for PID mismatch"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    local stderr_file="${TEST_TMP_DIR}/launch-stderr-wrong.json"
    echo '{"version":"1","status":"ok","data":{"pid":99999}}' > "$stderr_file"

    if av_compare_probe_pid_with_launch_metadata "${FIXTURES_DIR}/valid-isolated.json" "$stderr_file" 2>/dev/null; then
        log_fail "PID mismatch should fail"
        return 1
    else
        log_pass "PID mismatch correctly fails"
    fi
}

test_check_probe_uid_matches_user() {
    log_test "check_probe_uid_matches_user matches current user"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    local current_user
    current_user=$(whoami)

    if av_check_probe_uid_matches_user "${FIXTURES_DIR}/valid-isolated.json" "$current_user" 2>/dev/null; then
        log_pass "UID matches current user"
    else
        log_test "(skipped: UID 1001 does not match $current_user)"
    fi
}

test_check_probe_uid_matches_user_nonexistent() {
    log_test "check_probe_uid_matches_user fails for nonexistent user"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    if av_check_probe_uid_matches_user "${FIXTURES_DIR}/valid-isolated.json" "nonexistent_user_xyz" 2>/dev/null; then
        log_fail "nonexistent user should fail"
        return 1
    else
        log_pass "nonexistent user correctly fails"
    fi
}

test_validate_schema_field_types_in_fixture() {
    log_test "valid fixture has correct field types"
    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/principal.sh"

    local f="${FIXTURES_DIR}/valid-isolated.json"

    local pid_type uid_type nnp_type ns_type
    pid_type=$(jq -r '.pid | type' "$f")
    uid_type=$(jq -r '.uid | type' "$f")
    nnp_type=$(jq -r '.no_new_privs | type' "$f")
    ns_type=$(jq -r '.namespaces | type' "$f")

    if [[ "$pid_type" == "number" ]] && [[ "$uid_type" == "number" ]] && \
       [[ "$nnp_type" == "boolean" ]] && [[ "$ns_type" == "object" ]]; then
        log_pass "fixture field types correct"
    else
        log_fail "fixture field types wrong: pid=$pid_type uid=$uid_type nnp=$nnp_type ns=$ns_type"
        return 1
    fi
}

main() {
    echo -e "${BLUE}=== Principal Checks Tests (probe-based) ===${NC}" >&2

    test_principal_lib_exists
    test_fixture_files_exist
    test_validate_schema_valid_fixture
    test_validate_schema_rejects_invalid
    test_validate_schema_rejects_missing_file
    test_validate_schema_rejects_bad_json
    test_check_uid_gid_match
    test_check_uid_gid_mismatch
    test_check_groups_match
    test_check_groups_missing
    test_check_nnp_true
    test_check_nnp_false
    test_check_cap_absence_clean
    test_check_cap_absence_detects_caps
    test_check_resource_outcomes_match
    test_check_resource_outcomes_mismatch
    test_check_resource_outcomes_not_found
    test_run_probe_rejects_relative_probe_path
    test_run_probe_rejects_missing_passless
    test_run_probe_rejects_missing_probe
    test_check_probe_fd3_present_socket
    test_check_probe_fd3_absent
    test_check_probe_fd3_not_socket
    test_check_probe_fd3_peer_mismatch
    test_compare_probe_pid_json_metadata
    test_compare_probe_pid_plain_metadata
    test_compare_probe_pid_missing_metadata
    test_compare_probe_pid_mismatch
    test_check_probe_uid_matches_user
    test_check_probe_uid_matches_user_nonexistent
    test_validate_schema_field_types_in_fixture

    echo "" >&2
    echo -e "${BLUE}Tests: $TEST_COUNT total, $PASS_COUNT passed, $FAIL_COUNT failed${NC}" >&2

    [[ $FAIL_COUNT -eq 0 ]]
}

main "$@"
