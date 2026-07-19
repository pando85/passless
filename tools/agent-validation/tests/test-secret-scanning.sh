#!/bin/bash
#
# Shell tests for the secret-scanning stage and lib
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATION_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LIB_DIR="${VALIDATION_DIR}/lib"
STAGES_DIR="${VALIDATION_DIR}/stages"
FIXTURES_DIR="${VALIDATION_DIR}/fixtures"

TEST_TMP_DIR="/tmp/passless-av-secret-test-$$"
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

setup_env() {
    export EVIDENCE_DIR="${TEST_TMP_DIR}/evidence"
    export TEMP_ROOT="${TEST_TMP_DIR}/tmp"
    export RUN_ID="test-secret-run"
    export AV_VALIDATION_DIR="$VALIDATION_DIR"
    mkdir -p "$EVIDENCE_DIR" "$TEMP_ROOT"

    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/secret-scanning.sh"

    log_info() { :; }
    log_success() { :; }
    log_warn() { :; }
    log_error() { :; }
    register_resource() { :; }
}

test_secret_lib_exists() {
    log_test "secret-scanning lib file exists"
    if [[ -f "${LIB_DIR}/secret-scanning.sh" ]]; then
        log_pass "lib/secret-scanning.sh exists"
    else
        log_fail "lib/secret-scanning.sh missing"
    fi
}

test_secret_stage_exists() {
    log_test "secret-scanning stage file exists"
    if [[ -f "${STAGES_DIR}/secret-scanning.sh" ]]; then
        log_pass "stages/secret-scanning.sh exists"
    else
        log_fail "stages/secret-scanning.sh missing"
    fi
}

test_secret_fixture_exists() {
    log_test "secret-scan fixture exists"
    if [[ -f "${FIXTURES_DIR}/secret-scan/emit-redacted-metadata.sh" ]]; then
        log_pass "fixture script exists"
    else
        log_fail "fixture script missing"
    fi
}

test_secret_stage_has_strict_mode() {
    log_test "secret-scanning stage uses strict mode"
    if grep -q 'set -euo pipefail' "${STAGES_DIR}/secret-scanning.sh"; then
        log_pass "strict mode present"
    else
        log_fail "strict mode missing"
    fi
}

test_secret_stage_has_bash_shebang() {
    log_test "secret-scanning stage has bash shebang"
    local first_line
    first_line=$(head -n1 "${STAGES_DIR}/secret-scanning.sh")
    if [[ "$first_line" == "#!/bin/bash" ]]; then
        log_pass "correct shebang"
    else
        log_fail "bad shebang: $first_line"
    fi
}

test_sentinel_classes_defined() {
    log_test "sentinel classes are defined"
    setup_env
    if [[ ${#AV_SENTINEL_CLASSES[@]} -ge 9 ]]; then
        log_pass "at least 9 sentinel classes defined (${#AV_SENTINEL_CLASSES[@]})"
    else
        log_fail "too few sentinel classes (${#AV_SENTINEL_CLASSES[@]})"
    fi
}

test_sentinel_generation_creates_file() {
    log_test "sentinel generation creates file"
    setup_env
    local sentinel_file="${TEST_TMP_DIR}/test-sentinels"
    av_generate_sentinels "$sentinel_file"
    if [[ -f "$sentinel_file" ]]; then
        log_pass "sentinel file created"
    else
        log_fail "sentinel file not created"
    fi
    rm -f "$sentinel_file"
}

test_sentinel_file_permissions_600() {
    log_test "sentinel file has 0600 permissions"
    setup_env
    local sentinel_file="${TEST_TMP_DIR}/test-sentinels-perms"
    av_generate_sentinels "$sentinel_file"
    local perms
    perms=$(stat -c '%a' "$sentinel_file" 2>/dev/null || echo "unknown")
    if [[ "$perms" == "600" ]]; then
        log_pass "permissions are 600"
    else
        log_fail "permissions are $perms, expected 600"
    fi
    rm -f "$sentinel_file"
}

test_sentinel_values_unique_per_class() {
    log_test "sentinel values are unique per class"
    setup_env
    local sentinel_file="${TEST_TMP_DIR}/test-sentinels-unique"
    av_generate_sentinels "$sentinel_file"
    local values
    values=$(cut -d= -f2- "$sentinel_file" | sort)
    local unique_values
    unique_values=$(printf '%s\n' "$values" | sort -u)
    if [[ "$values" == "$unique_values" ]]; then
        log_pass "all sentinel values unique"
    else
        log_fail "duplicate sentinel values found"
    fi
    rm -f "$sentinel_file"
}

test_sentinel_load_works() {
    log_test "av_load_sentinel retrieves correct value"
    setup_env
    local sentinel_file="${TEST_TMP_DIR}/test-sentinels-load"
    av_generate_sentinels "$sentinel_file"
    local pin_value
    pin_value=$(av_load_sentinel "$sentinel_file" "pin")
    if [[ -n "$pin_value" ]] && [[ "$pin_value" == AVSENT_*_pin ]]; then
        log_pass "loaded pin sentinel correctly"
    else
        log_fail "could not load pin sentinel: $pin_value"
    fi
    rm -f "$sentinel_file"
}

test_sentinel_detection_exact_match() {
    log_test "sentinel detection finds exact match"
    setup_env
    local sentinel_file="${TEST_TMP_DIR}/test-sentinels-detect"
    av_generate_sentinels "$sentinel_file"
    local findings_file="${TEST_TMP_DIR}/test-findings"
    : > "$findings_file"

    local pin_value
    pin_value=$(av_load_sentinel "$sentinel_file" "pin")
    local test_file="${TEST_TMP_DIR}/test-leak.txt"
    printf 'some log line with %s leaked here\n' "$pin_value" > "$test_file"

    local found=0
    av_scan_file_for_sentinels "$test_file" "$sentinel_file" "$findings_file" || found=$?
    if [[ $found -gt 0 ]]; then
        log_pass "detected sentinel leak ($found finding(s))"
    else
        log_fail "did not detect sentinel leak"
    fi

    rm -f "$sentinel_file" "$findings_file" "$test_file"
}

test_sentinel_detection_clean_pass() {
    log_test "sentinel detection passes on clean file"
    setup_env
    local sentinel_file="${TEST_TMP_DIR}/test-sentinels-clean"
    av_generate_sentinels "$sentinel_file"
    local findings_file="${TEST_TMP_DIR}/test-findings-clean"
    : > "$findings_file"

    local test_file="${TEST_TMP_DIR}/test-clean.txt"
    printf 'this is a clean log line with no secrets\n' > "$test_file"

    local found=0
    av_scan_file_for_sentinels "$test_file" "$sentinel_file" "$findings_file" || found=$?
    if [[ $found -eq 0 ]]; then
        log_pass "clean file passes (0 findings)"
    else
        log_fail "false positive on clean file ($found findings)"
    fi

    rm -f "$sentinel_file" "$findings_file" "$test_file"
}

test_prohibited_field_detection() {
    log_test "prohibited field name detection works"
    setup_env
    local findings_file="${TEST_TMP_DIR}/test-findings-prohibited"
    : > "$findings_file"

    local test_file="${TEST_TMP_DIR}/test-prohibited.json"
    printf '{"pin": "1234", "status": "ok"}\n' > "$test_file"

    local found=0
    av_scan_file_for_prohibited_fields "$test_file" "$findings_file" || found=$?
    if [[ $found -gt 0 ]]; then
        log_pass "detected prohibited field ($found finding(s))"
    else
        log_fail "did not detect prohibited field"
    fi

    rm -f "$findings_file" "$test_file"
}

test_prohibited_field_clean_pass() {
    log_test "prohibited field detection passes on clean JSON"
    setup_env
    local findings_file="${TEST_TMP_DIR}/test-findings-prohibited-clean"
    : > "$findings_file"

    local test_file="${TEST_TMP_DIR}/test-prohibited-clean.json"
    printf '{"correlation_id": "redacted", "status": "ok"}\n' > "$test_file"

    local found=0
    av_scan_file_for_prohibited_fields "$test_file" "$findings_file" || found=$?
    if [[ $found -eq 0 ]]; then
        log_pass "clean JSON passes (0 findings)"
    else
        log_fail "false positive on clean JSON ($found findings)"
    fi

    rm -f "$findings_file" "$test_file"
}

test_raw_payload_marker_detection() {
    log_test "raw payload marker detection works"
    setup_env
    local findings_file="${TEST_TMP_DIR}/test-findings-raw"
    : > "$findings_file"

    local test_file="${TEST_TMP_DIR}/test-raw.json"
    printf '{"raw_payload": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"}\n' > "$test_file"

    local found=0
    av_scan_file_for_raw_payload_markers "$test_file" "$findings_file" || found=$?
    if [[ $found -gt 0 ]]; then
        log_pass "detected raw payload marker ($found finding(s))"
    else
        log_fail "did not detect raw payload marker"
    fi

    rm -f "$findings_file" "$test_file"
}

test_fixture_emits_valid_json() {
    log_test "fixture emits valid JSON"
    setup_env
    local fixture_script="${FIXTURES_DIR}/secret-scan/emit-redacted-metadata.sh"
    local output
    output=$(timeout 10s bash "$fixture_script" 2>&1) || true
    if printf '%s\n' "$output" | jq empty 2>/dev/null; then
        log_pass "fixture output is valid JSON"
    else
        log_fail "fixture output is not valid JSON"
    fi
}

test_fixture_emits_only_allowed_keys() {
    log_test "fixture emits only allowed metadata keys"
    setup_env
    local fixture_script="${FIXTURES_DIR}/secret-scan/emit-redacted-metadata.sh"
    local output
    output=$(timeout 10s bash "$fixture_script" 2>&1) || true

    local keys
    keys=$(printf '%s\n' "$output" | jq -r 'keys[]' 2>/dev/null) || true
    local all_allowed=true
    for key in $keys; do
        if ! av_is_allowed_metadata_key "$key"; then
            all_allowed=false
            break
        fi
    done

    if [[ "$all_allowed" == "true" ]]; then
        log_pass "all fixture keys are allowed"
    else
        log_fail "fixture contains disallowed keys"
    fi
}

test_fixture_no_sentinel_leak() {
    log_test "fixture output contains no sentinel values"
    setup_env
    local sentinel_file="${TEST_TMP_DIR}/test-sentinels-fixture"
    av_generate_sentinels "$sentinel_file"

    local fixture_script="${FIXTURES_DIR}/secret-scan/emit-redacted-metadata.sh"
    local output
    output=$(timeout 10s bash "$fixture_script" --sentinel-file "$sentinel_file" 2>&1) || true

    local findings_file="${TEST_TMP_DIR}/test-findings-fixture"
    : > "$findings_file"
    local fixture_file="${TEST_TMP_DIR}/fixture-output.json"
    printf '%s\n' "$output" > "$fixture_file"

    local found=0
    av_scan_file_for_sentinels "$fixture_file" "$sentinel_file" "$findings_file" || found=$?
    if [[ $found -eq 0 ]]; then
        log_pass "no sentinel values in fixture output"
    else
        log_fail "sentinel values found in fixture output ($found)"
    fi

    rm -f "$sentinel_file" "$findings_file" "$fixture_file"
}

test_secret_wired_in_run_sh() {
    log_test "secret-scanning wired in run.sh (not skip_stage)"
    local run_sh="${VALIDATION_DIR}/run.sh"
    if grep -q 'run_stage "secret-scanning" "stage_secret_scanning"' "$run_sh"; then
        log_pass "secret-scanning uses run_stage"
    else
        log_fail "secret-scanning not wired with run_stage"
    fi
}

test_secret_no_skip_stage_in_tier1() {
    log_test "secret-scanning no longer uses skip_stage in tier1"
    local run_sh="${VALIDATION_DIR}/run.sh"
    local tier1_section
    tier1_section=$(sed -n '/^run_tier1_tests/,/^}/p' "$run_sh")
    if echo "$tier1_section" | grep -q 'skip_stage "secret-scanning"'; then
        log_fail "secret-scanning still uses skip_stage"
    else
        log_pass "secret-scanning does not use skip_stage"
    fi
}

test_secret_stage_function_exists() {
    log_test "stage_secret_scanning function is defined"
    setup_env
    source "${STAGES_DIR}/secret-scanning.sh"
    if declare -f stage_secret_scanning &>/dev/null; then
        log_pass "stage_secret_scanning function defined"
    else
        log_fail "stage_secret_scanning function not defined"
    fi
}

test_allowed_metadata_keys_list() {
    log_test "allowed metadata keys list is populated"
    setup_env
    if [[ ${#AV_ALLOWED_METADATA_KEYS[@]} -ge 15 ]]; then
        log_pass "at least 15 allowed keys (${#AV_ALLOWED_METADATA_KEYS[@]})"
    else
        log_fail "too few allowed keys (${#AV_ALLOWED_METADATA_KEYS[@]})"
    fi
}

test_prohibited_field_names_list() {
    log_test "prohibited field names list is populated"
    setup_env
    if [[ ${#AV_PROHIBITED_FIELD_NAMES[@]} -ge 8 ]]; then
        log_pass "at least 8 prohibited fields (${#AV_PROHIBITED_FIELD_NAMES[@]})"
    else
        log_fail "too few prohibited fields (${#AV_PROHIBITED_FIELD_NAMES[@]})"
    fi
}

test_sentinel_prefix_consistent() {
    log_test "sentinel values use consistent prefix"
    setup_env
    local sentinel_file="${TEST_TMP_DIR}/test-sentinels-prefix"
    av_generate_sentinels "$sentinel_file"

    local all_prefixed=true
    while IFS='=' read -r class value; do
        [[ -z "$class" ]] && continue
        if [[ "$value" != AVSENT_* ]]; then
            all_prefixed=false
            break
        fi
    done < "$sentinel_file"

    if [[ "$all_prefixed" == "true" ]]; then
        log_pass "all sentinels use AVSENT_ prefix"
    else
        log_fail "some sentinels missing AVSENT_ prefix"
    fi

    rm -f "$sentinel_file"
}

main() {
    echo -e "${BLUE}=== Secret Scanning Stage Tests ===${NC}" >&2

    test_secret_lib_exists
    test_secret_stage_exists
    test_secret_fixture_exists
    test_secret_stage_has_strict_mode
    test_secret_stage_has_bash_shebang
    test_sentinel_classes_defined
    test_sentinel_generation_creates_file
    test_sentinel_file_permissions_600
    test_sentinel_values_unique_per_class
    test_sentinel_load_works
    test_sentinel_detection_exact_match
    test_sentinel_detection_clean_pass
    test_prohibited_field_detection
    test_prohibited_field_clean_pass
    test_raw_payload_marker_detection
    test_fixture_emits_valid_json
    test_fixture_emits_only_allowed_keys
    test_fixture_no_sentinel_leak
    test_secret_wired_in_run_sh
    test_secret_no_skip_stage_in_tier1
    test_secret_stage_function_exists
    test_allowed_metadata_keys_list
    test_prohibited_field_names_list
    test_sentinel_prefix_consistent

    echo "" >&2
    echo -e "${BLUE}Tests: $TEST_COUNT total, $PASS_COUNT passed, $FAIL_COUNT failed${NC}" >&2

    [[ $FAIL_COUNT -eq 0 ]]
}

main "$@"
