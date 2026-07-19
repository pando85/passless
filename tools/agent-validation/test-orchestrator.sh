#!/bin/bash
#
# Shell tests for the agent validation orchestrator
#

set -euo pipefail

ORIG_DIR="$PWD"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORCHESTRATOR_SCRIPT="$SCRIPT_DIR/run.sh"

TEST_TMP_DIR="/tmp/passless-agent-validation-test-$$"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

TEST_COUNT=0
PASS_COUNT=0
FAIL_COUNT=0

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*" >&2
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $*" >&2
    ((PASS_COUNT++)) || true
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $*" >&2
    ((FAIL_COUNT++)) || true
}

log_test() {
    echo -e "${BLUE}[TEST]${NC} $*" >&2
    ((TEST_COUNT++)) || true
}

# shellcheck disable=SC2329
cleanup() {
    cd "$ORIG_DIR" || true
    rm -rf "$TEST_TMP_DIR" 2>/dev/null || true
}

trap cleanup EXIT

run_test() {
    local test_name="$1"
    local expected_exit="${2:-0}"
    shift 2
    local command=("$@")

    log_test "$test_name"

    local actual_exit=0
    ("${command[@]}" 2>/dev/null) || actual_exit=$?

    if [[ $actual_exit -eq $expected_exit ]]; then
        log_pass "Expected exit code $expected_exit, got $actual_exit"
    else
        log_fail "Expected exit code $expected_exit, got $actual_exit"
        return 1
    fi
}

test_script_exists() {
    if [[ ! -f "$ORCHESTRATOR_SCRIPT" ]]; then
        log_fail "Script does not exist: $ORCHESTRATOR_SCRIPT"
        return 1
    fi

    if [[ ! -x "$ORCHESTRATOR_SCRIPT" ]]; then
        log_fail "Script is not executable: $ORCHESTRATOR_SCRIPT"
        return 1
    fi

    log_pass "Script exists and is executable"
}

test_help_output() {
    local output
    output=$(timeout 5s bash "$ORCHESTRATOR_SCRIPT" --help 2>&1) || true

    if [[ -n "$output" ]] && [[ "$output" =~ "Usage:" ]]; then
        log_pass "Help output contains expected content"
    else
        log_fail "Help output missing or invalid"
        return 1
    fi
}

test_help_lists_delete_evidence() {
    log_test "Help lists --delete-evidence"

    local output
    output=$(timeout 5s bash "$ORCHESTRATOR_SCRIPT" --help 2>&1) || true

    if [[ "$output" == *"--delete-evidence"* ]]; then
        log_pass "Help lists --delete-evidence"
    else
        log_fail "Help does not list --delete-evidence"
        return 1
    fi
}

test_invalid_args() {
    run_test "Invalid argument handling" 3 bash "$ORCHESTRATOR_SCRIPT" --invalid-arg
}

test_shebang() {
    local first_line
    first_line=$(head -n1 "$ORCHESTRATOR_SCRIPT")

    if [[ "$first_line" == "#!/bin/bash" ]]; then
        log_pass "Correct shebang found"
    else
        log_fail "Incorrect shebang: $first_line"
        return 1
    fi
}

test_strict_mode() {
    local strict_line
    strict_line=$(grep -m1 "set -euo pipefail" "$ORCHESTRATOR_SCRIPT")

    if [[ -n "$strict_line" ]]; then
        log_pass "Strict mode set found"
    else
        log_fail "Strict mode not found"
        return 1
    fi
}

test_path_validation() {
    local test_script="$TEST_TMP_DIR/test_path_validation.sh"
    cat > "$test_script" << 'INNER_EOF'
#!/bin/bash
set -euo pipefail

validate_safe_path() {
    local path="$1"
    local base_dir="$2"

    if [[ ! -d "$base_dir" ]]; then
        return 1
    fi

    local normalized_base
    normalized_base=$(realpath "$base_dir" 2>/dev/null) || return 1

    local normalized_path
    normalized_path=$(realpath -m "$path" 2>/dev/null) || return 1

    if [[ "$normalized_path" == "$normalized_base" ]]; then
        return 1
    fi

    if [[ ! "$normalized_path" =~ ^"$normalized_base"/ ]]; then
        return 1
    fi

    local relative_path="${normalized_path#"$normalized_base"/}"
    local absolute_path
    if [[ "$path" == /* ]]; then
        absolute_path="$path"
    else
        absolute_path="$(pwd)/$path"
    fi

    local check_path=""
    IFS='/' read -ra path_components <<< "$absolute_path"
    for component in "${path_components[@]}"; do
        if [[ -z "$component" ]] || [[ "$component" == "." ]]; then
            continue
        fi
        if [[ -z "$check_path" ]]; then
            check_path="/$component"
        else
            check_path="$check_path/$component"
        fi

        if [[ "$check_path" == "$normalized_base" ]] || [[ "$check_path" == "$normalized_base/"* ]]; then
            if [[ -L "$check_path" ]]; then
                return 1
            fi
        fi
    done

    if [[ -L "$normalized_path" ]]; then
        return 1
    fi

    return 0
}

test_base="$1"

test_cases=(
    "$test_base/target/agent-validation/test/subdir|$test_base/target/agent-validation|PASS"
    "$test_base/target/agent-validation|$test_base/target/agent-validation|FAIL"
    "$test_base/target/other|$test_base/target/agent-validation|FAIL"
    "$test_base/target/agent-validation/../other|$test_base/target/agent-validation|FAIL"
    "$test_base/target/agent-validation-test|$test_base/target/agent-validation|FAIL"
    "/etc/passwd|$test_base/target/agent-validation|FAIL"
    "$test_base/target/agent-validation/valid-run-123|$test_base/target/agent-validation|PASS"
)

all_passed=true
for test_case in "${test_cases[@]}"; do
    IFS='|' read -r path base expected <<< "$test_case"

    mkdir -p "$base" 2>/dev/null || true

    if validate_safe_path "$path" "$base" 2>/dev/null; then
        actual="PASS"
    else
        actual="FAIL"
    fi

    if [[ "$actual" != "$expected" ]]; then
        echo "FAIL: Path validation for '$path'/'$base' - expected $expected, got $actual" >&2
        all_passed=false
    fi
done

if [[ "$all_passed" == true ]]; then
    echo "All path validation tests passed"
    exit 0
else
    echo "Some path validation tests failed" >&2
    exit 1
fi
INNER_EOF

    chmod +x "$test_script"

    if bash "$test_script" "$TEST_TMP_DIR"; then
        log_pass "Path validation logic works correctly"
    else
        log_fail "Path validation logic failed"
        return 1
    fi
}

test_symlink_chain_walks_downward() {
    log_test "Symlink chain check walks downward from base"

    local test_script="$TEST_TMP_DIR/test_symlink_chain.sh"
    cat > "$test_script" << 'INNER_EOF'
#!/bin/bash
set -euo pipefail

validate_safe_path() {
    local path="$1"
    local base_dir="$2"

    if [[ ! -d "$base_dir" ]]; then
        return 1
    fi

    local normalized_base
    normalized_base=$(realpath "$base_dir" 2>/dev/null) || return 1

    local normalized_path
    normalized_path=$(realpath -m "$path" 2>/dev/null) || return 1

    if [[ "$normalized_path" == "$normalized_base" ]]; then
        return 1
    fi

    if [[ ! "$normalized_path" =~ ^"$normalized_base"/ ]]; then
        return 1
    fi

    local absolute_path
    if [[ "$path" == /* ]]; then
        absolute_path="$path"
    else
        absolute_path="$(pwd)/$path"
    fi

    local check_path=""
    IFS='/' read -ra path_components <<< "$absolute_path"
    for component in "${path_components[@]}"; do
        if [[ -z "$component" ]] || [[ "$component" == "." ]]; then
            continue
        fi
        if [[ -z "$check_path" ]]; then
            check_path="/$component"
        else
            check_path="$check_path/$component"
        fi

        if [[ "$check_path" == "$normalized_base" ]] || [[ "$check_path" == "$normalized_base/"* ]]; then
            if [[ -L "$check_path" ]]; then
                return 1
            fi
        fi
    done

    if [[ -L "$normalized_path" ]]; then
        return 1
    fi

    return 0
}

test_base="$1"
mkdir -p "$test_base/real"
ln -sf "$test_base/real" "$test_base/link"

if validate_safe_path "$test_base/link/sub" "$test_base" 2>/dev/null; then
    echo "FAIL: Symlink in intermediate path component not detected" >&2
    exit 1
fi

mkdir -p "$test_base/safe/sub"
if validate_safe_path "$test_base/safe/sub" "$test_base" 2>/dev/null; then
    echo "PASS: Safe path accepted"
    exit 0
else
    echo "FAIL: Safe path rejected" >&2
    exit 1
fi
INNER_EOF

    chmod +x "$test_script"

    if bash "$test_script" "$TEST_TMP_DIR"; then
        log_pass "Symlink chain walks downward correctly"
    else
        log_fail "Symlink chain check failed"
        return 1
    fi
}

test_json_generation() {
    local test_script="$TEST_TMP_DIR/test_json_generation.sh"
    cat > "$test_script" << 'INNER_EOF'
#!/bin/bash
set -euo pipefail

test_data="special chars: \"quote\" 'apos' \$dollar \\backslash \`backtick\` \$((calc))"

result=$(jq -n --arg data "$test_data" '{"test_field": $data}')

if echo "$result" | jq empty 2>/dev/null && echo "$result" | jq -r ".test_field" | grep -F -q "$test_data"; then
    echo "PASS: JSON generation properly escaped special characters"
    exit 0
else
    echo "FAIL: JSON generation did not properly handle special characters" >&2
    exit 1
fi
INNER_EOF

    chmod +x "$test_script"

    if bash "$test_script"; then
        log_pass "JSON generation safety confirmed"
    else
        log_fail "JSON generation safety failed"
        return 1
    fi
}

test_cleanup_preserves_evidence() {
    log_test "Cleanup preserves evidence directory"

    local test_base="$TEST_TMP_DIR/evidence-base-preserve"
    local valid_run_id="agent-validation-preserve-test"
    mkdir -p "$test_base/$valid_run_id"

    jq -n --arg run_id "$valid_run_id" --arg temp_root "$test_base/$valid_run_id/tmp" \
        '{run_id: $run_id, temp_root: $temp_root, resources: [], resource_count: 0, finalized: true}' \
        > "$test_base/$valid_run_id/state.json"

    local exit_code=0
    EVIDENCE_BASE_DIR="$test_base" bash "$ORCHESTRATOR_SCRIPT" --cleanup "$valid_run_id" 2>/dev/null || exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_pass "Cleanup succeeded"
    else
        log_fail "Cleanup failed (exit=$exit_code)"
        return 1
    fi

    if [[ -d "$test_base/$valid_run_id" ]]; then
        log_pass "Evidence directory preserved after cleanup"
    else
        log_fail "Evidence directory was DELETED by cleanup!"
        return 1
    fi
}

test_cleanup_marks_state() {
    log_test "Cleanup marks cleanup_completed in state"

    local test_base="$TEST_TMP_DIR/evidence-base-mark"
    local valid_run_id="agent-validation-mark-test"
    mkdir -p "$test_base/$valid_run_id"

    jq -n --arg run_id "$valid_run_id" --arg temp_root "$test_base/$valid_run_id/tmp" \
        '{run_id: $run_id, temp_root: $temp_root, resources: [], resource_count: 0, finalized: true, cleanup_completed: false}' \
        > "$test_base/$valid_run_id/state.json"

    EVIDENCE_BASE_DIR="$test_base" bash "$ORCHESTRATOR_SCRIPT" --cleanup "$valid_run_id" 2>/dev/null || true

    local cleanup_completed
    cleanup_completed=$(jq -r '.cleanup_completed // false' "$test_base/$valid_run_id/state.json" 2>/dev/null || echo "false")

    if [[ "$cleanup_completed" == "true" ]]; then
        log_pass "State marked cleanup_completed=true"
    else
        log_fail "State not marked cleanup_completed"
        return 1
    fi
}

test_delete_evidence_requires_confirmation() {
    log_test "Delete-evidence requires strict confirmation"

    local test_base="$TEST_TMP_DIR/evidence-base-delete"
    local valid_run_id="agent-validation-delete-test"
    mkdir -p "$test_base/$valid_run_id"

    echo "wrong" | EVIDENCE_BASE_DIR="$test_base" bash "$ORCHESTRATOR_SCRIPT" --delete-evidence "$valid_run_id" 2>/dev/null || true

    if [[ -d "$test_base/$valid_run_id" ]]; then
        log_pass "Evidence preserved with wrong confirmation"
    else
        log_fail "Evidence deleted without proper confirmation!"
        return 1
    fi
}

test_delete_evidence_with_correct_confirmation() {
    log_test "Delete-evidence works with DELETE confirmation"

    local test_base="$TEST_TMP_DIR/evidence-base-delete-ok"
    local valid_run_id="agent-validation-delete-ok-test"
    mkdir -p "$test_base/$valid_run_id"

    echo "DELETE" | EVIDENCE_BASE_DIR="$test_base" bash "$ORCHESTRATOR_SCRIPT" --delete-evidence "$valid_run_id" 2>/dev/null || true

    if [[ ! -d "$test_base/$valid_run_id" ]]; then
        log_pass "Evidence deleted with correct DELETE confirmation"
    else
        log_fail "Evidence not deleted despite DELETE confirmation"
        return 1
    fi
}

test_cleanup_path_traversal() {
    log_test "Cleanup rejects path traversal (../../../etc)"

    local test_base="$TEST_TMP_DIR/evidence-base-traversal"
    mkdir -p "$test_base"

    local exit_code=0
    EVIDENCE_BASE_DIR="$test_base" bash "$ORCHESTRATOR_SCRIPT" --cleanup "../../../etc" 2>/dev/null || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        log_pass "Path traversal rejected (exit=$exit_code)"
    else
        log_fail "Path traversal was NOT rejected"
        return 1
    fi
}

test_cleanup_sibling_prefix() {
    log_test "Cleanup rejects sibling-prefix attack"

    local test_base="$TEST_TMP_DIR/evidence-base-sibling"
    mkdir -p "$test_base/agent-validation-run1"
    mkdir -p "$test_base/agent-validation-run1-evil"

    EVIDENCE_BASE_DIR="$test_base" bash "$ORCHESTRATOR_SCRIPT" --cleanup "agent-validation-run1-evil" 2>/dev/null || true

    if [[ -d "$test_base/agent-validation-run1" ]]; then
        log_pass "Legitimate sibling directory preserved"
    else
        log_fail "Sibling directory was incorrectly affected"
        return 1
    fi
}

test_cleanup_base_directory() {
    log_test "Cleanup rejects base directory itself"

    local test_base="$TEST_TMP_DIR/evidence-base-self"
    mkdir -p "$test_base"

    local exit_code=0
    EVIDENCE_BASE_DIR="$test_base" bash "$ORCHESTRATOR_SCRIPT" --cleanup "$(basename "$test_base")" 2>/dev/null || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        log_pass "Base directory cleanup rejected (exit=$exit_code)"
    else
        log_fail "Base directory cleanup was NOT rejected"
        return 1
    fi

    if [[ -d "$test_base" ]]; then
        log_pass "Base directory still exists"
    else
        log_fail "Base directory was deleted!"
        return 1
    fi
}

test_cleanup_symlink() {
    log_test "Cleanup rejects symlink attack"

    local test_base="$TEST_TMP_DIR/evidence-base-symlink"
    local protected_dir="$TEST_TMP_DIR/protected-dir"
    mkdir -p "$test_base"
    mkdir -p "$protected_dir"

    ln -sf "$protected_dir" "$test_base/symlink-run"

    local exit_code=0
    EVIDENCE_BASE_DIR="$test_base" bash "$ORCHESTRATOR_SCRIPT" --cleanup "symlink-run" 2>/dev/null || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        log_pass "Symlink cleanup rejected (exit=$exit_code)"
    else
        log_fail "Symlink cleanup was NOT rejected"
        return 1
    fi

    if [[ -d "$protected_dir" ]]; then
        log_pass "Protected directory not affected via symlink"
    else
        log_fail "Protected directory was deleted via symlink!"
        return 1
    fi
}

test_cleanup_absolute_path() {
    log_test "Cleanup rejects absolute path in run-id"

    local test_base="$TEST_TMP_DIR/evidence-base-abs"
    mkdir -p "$test_base"

    local exit_code=0
    EVIDENCE_BASE_DIR="$test_base" bash "$ORCHESTRATOR_SCRIPT" --cleanup "/etc/passwd" 2>/dev/null || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        log_pass "Absolute path rejected (exit=$exit_code)"
    else
        log_fail "Absolute path was NOT rejected"
        return 1
    fi
}

test_cleanup_valid_id() {
    log_test "Cleanup accepts valid run-id and preserves evidence"

    local test_base="$TEST_TMP_DIR/evidence-base-valid"
    local valid_run_id="agent-validation-20240101-120000-abcd1234"
    mkdir -p "$test_base/$valid_run_id"

    jq -n --arg run_id "$valid_run_id" --arg temp_root "$test_base/$valid_run_id/tmp" \
        '{run_id: $run_id, temp_root: $temp_root, resources: [], resource_count: 0, finalized: true}' \
        > "$test_base/$valid_run_id/state.json"

    local exit_code=0
    EVIDENCE_BASE_DIR="$test_base" bash "$ORCHESTRATOR_SCRIPT" --cleanup "$valid_run_id" 2>/dev/null || exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_pass "Valid run-id cleanup succeeded"
    else
        log_fail "Valid run-id cleanup failed (exit=$exit_code)"
        return 1
    fi

    if [[ -d "$test_base/$valid_run_id" ]]; then
        log_pass "Evidence preserved after cleanup"
    else
        log_fail "Evidence was deleted by cleanup!"
        return 1
    fi
}

test_tier3_stage_files_exist() {
    log_test "Tier 3 stage files exist"

    local stages=("privileged-setup.sh" "principal-isolation.sh" "device-probes.sh" "lab-safety.sh")
    local all_found=true
    for stage in "${stages[@]}"; do
        if [[ ! -f "$SCRIPT_DIR/stages/$stage" ]]; then
            log_fail "Missing stage file: stages/$stage"
            all_found=false
        fi
    done
    if [[ "$all_found" == "true" ]]; then
        log_pass "All Tier 3 stage files exist"
    fi
}

test_tier3_lib_files_exist() {
    log_test "Tier 3 library files exist"

    local libs=("common.sh" "privilege.sh" "principal.sh" "device-matrix.sh" "snapshot.sh" "credential-store.sh")
    local all_found=true
    for lib in "${libs[@]}"; do
        if [[ ! -f "$SCRIPT_DIR/lib/$lib" ]]; then
            log_fail "Missing lib file: lib/$lib"
            all_found=false
        fi
    done
    if [[ "$all_found" == "true" ]]; then
        log_pass "All Tier 3 library files exist"
    fi
}

test_tier3_stages_wired_in_run_sh() {
    log_test "Tier 3 stages are wired in run.sh (not skip_stage)"

    if grep -q 'run_stage "privileged-setup" "stage_privileged_setup"' "$ORCHESTRATOR_SCRIPT"; then
        log_pass "privileged-setup uses run_stage"
    else
        log_fail "privileged-setup not wired with run_stage"
        return 1
    fi

    if grep -q 'run_stage "principal-isolation" "stage_principal_isolation"' "$ORCHESTRATOR_SCRIPT"; then
        log_pass "principal-isolation uses run_stage"
    else
        log_fail "principal-isolation not wired with run_stage"
        return 1
    fi

    if grep -q 'run_stage "device-probes" "stage_device_probes"' "$ORCHESTRATOR_SCRIPT"; then
        log_pass "device-probes uses run_stage"
    else
        log_fail "device-probes not wired with run_stage"
        return 1
    fi

    if grep -q 'run_stage "lab-safety" "stage_lab_safety"' "$ORCHESTRATOR_SCRIPT"; then
        log_pass "lab-safety uses run_stage"
    else
        log_fail "lab-safety not wired with run_stage"
        return 1
    fi
}

test_tier3_no_skip_stage_in_tier3() {
    log_test "Tier 3 no longer uses skip_stage placeholders"

    local tier3_section
    tier3_section=$(sed -n '/^run_tier3_tests/,/^}/p' "$ORCHESTRATOR_SCRIPT")

    if echo "$tier3_section" | grep -q 'skip_stage'; then
        log_fail "Tier 3 still contains skip_stage placeholders"
        return 1
    else
        log_pass "Tier 3 has no skip_stage placeholders"
    fi
}

test_tier3_stage_skipped_mechanism() {
    log_test "STAGE_SKIPPED mechanism exists in run.sh"

    if grep -q 'STAGE_SKIPPED' "$ORCHESTRATOR_SCRIPT"; then
        log_pass "STAGE_SKIPPED variable referenced in run.sh"
    else
        log_fail "STAGE_SKIPPED mechanism missing"
        return 1
    fi

    if grep -q 'STAGE_SKIPPED=false' "$ORCHESTRATOR_SCRIPT"; then
        log_pass "STAGE_SKIPPED initialized to false"
    else
        log_fail "STAGE_SKIPPED not initialized"
        return 1
    fi
}

test_tier3_libs_sourced_in_run_sh() {
    log_test "Tier 3 libs and stages are sourced in run.sh"

    if grep -q 'AV_VALIDATION_DIR' "$ORCHESTRATOR_SCRIPT"; then
        log_pass "AV_VALIDATION_DIR set in run.sh"
    else
        log_fail "AV_VALIDATION_DIR not set"
        return 1
    fi

    if grep -q 'av_lib.*source' "$ORCHESTRATOR_SCRIPT" || grep -q 'source.*lib/' "$ORCHESTRATOR_SCRIPT"; then
        log_pass "Lib files sourced in run.sh"
    else
        log_fail "Lib files not sourced"
        return 1
    fi
}

test_tier3_fixtures_exist() {
    log_test "Tier 3 fixture files exist"

    if [[ -f "$SCRIPT_DIR/fixtures/test-udev-rules/99-agent-validation-test.rules" ]]; then
        log_pass "Test udev rules fixture exists"
    else
        log_fail "Test udev rules fixture missing"
        return 1
    fi

    if [[ -f "$SCRIPT_DIR/fixtures/expected-identity-matrix.json" ]]; then
        if jq empty "$SCRIPT_DIR/fixtures/expected-identity-matrix.json" 2>/dev/null; then
            log_pass "Expected identity matrix is valid JSON"
        else
            log_fail "Expected identity matrix is invalid JSON"
            return 1
        fi
    else
        log_fail "Expected identity matrix fixture missing"
        return 1
    fi
}

test_tier3_test_files_exist() {
    log_test "Tier 3 test files exist and are executable"

    local tests=("test-privilege-helper.sh" "test-principal-checks.sh" "test-device-matrix.sh" "test-tier3-stages.sh" "test-uninstall-rehearsal.sh")
    local all_ok=true
    for test_file in "${tests[@]}"; do
        if [[ ! -f "$SCRIPT_DIR/tests/$test_file" ]]; then
            log_fail "Missing test file: tests/$test_file"
            all_ok=false
        elif [[ ! -x "$SCRIPT_DIR/tests/$test_file" ]]; then
            log_fail "Test file not executable: tests/$test_file"
            all_ok=false
        fi
    done
    if [[ "$all_ok" == "true" ]]; then
        log_pass "All Tier 3 test files exist and are executable"
    fi
}

test_tier3_explicit_confirmation_preserved() {
    log_test "Tier 3 explicit confirmation prompt preserved"

    if grep -q 'read.*privileged operations.*Continue' "$ORCHESTRATOR_SCRIPT"; then
        log_pass "Explicit confirmation prompt preserved"
    else
        log_fail "Explicit confirmation prompt missing"
        return 1
    fi
}

test_tier3_never_run_as_root() {
    log_test "Tier 3 inherits root-denial from initialize_run"

    if grep -q 'should not run as root' "$ORCHESTRATOR_SCRIPT"; then
        log_pass "Root denial check present"
    else
        log_fail "Root denial check missing"
        return 1
    fi
}

test_cleanup_invalid_chars() {
    log_test "Cleanup rejects run-id with invalid characters"

    local test_base="$TEST_TMP_DIR/evidence-base-invalid"
    mkdir -p "$test_base"

    local exit_code=0
    EVIDENCE_BASE_DIR="$test_base" bash "$ORCHESTRATOR_SCRIPT" --cleanup "run/with/slashes" 2>/dev/null || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        log_pass "Invalid characters rejected (exit=$exit_code)"
    else
        log_fail "Invalid characters were NOT rejected"
        return 1
    fi
}

test_cleanup_dotdot_id() {
    log_test "Cleanup rejects '..' as run-id"

    local test_base="$TEST_TMP_DIR/evidence-base-dotdot"
    mkdir -p "$test_base"

    local exit_code=0
    EVIDENCE_BASE_DIR="$test_base" bash "$ORCHESTRATOR_SCRIPT" --cleanup ".." 2>/dev/null || exit_code=$?

    if [[ $exit_code -ne 0 ]]; then
        log_pass "Dotdot rejected (exit=$exit_code)"
    else
        log_fail "Dotdot was NOT rejected"
        return 1
    fi
}

test_state_file_created_before_mutation() {
    log_test "State file created before mutations"

    local test_base="$TEST_TMP_DIR/evidence-base-state"
    mkdir -p "$test_base"

    local state_check_script="$TEST_TMP_DIR/check_state.sh"
    cat > "$state_check_script" << INNER_EOF
#!/bin/bash
set -euo pipefail
export EVIDENCE_BASE_DIR="$test_base"
export EVIDENCE_DIR=""

test_dir="$test_base/test-state-check"
mkdir -p "\$test_dir"

state_file="\$test_dir/state.json"
if [[ -f "\$state_file" ]]; then
    if jq empty "\$state_file" 2>/dev/null; then
        echo "STATE_VALID"
        exit 0
    fi
fi
echo "STATE_MISSING_OR_INVALID"
exit 1
INNER_EOF
    chmod +x "$state_check_script"

    mkdir -p "$test_base/test-state-check"
    jq -n '{run_id: "test", resources: [], resource_count: 0, finalized: false}' \
        > "$test_base/test-state-check/state.json"

    if bash "$state_check_script" 2>/dev/null; then
        log_pass "State file structure is valid JSON created before mutation"
    else
        log_fail "State file check failed"
        return 1
    fi
}

test_state_file_restricted_permissions() {
    log_test "State file has restricted permissions (600)"

    if grep -q 'chmod 600.*state_path' "$ORCHESTRATOR_SCRIPT"; then
        log_pass "State file permissions set to 600"
    else
        log_fail "State file permissions not restricted"
        return 1
    fi
}

test_zero_resources_reported() {
    log_test "Zero resources accurately reported"

    local test_base="$TEST_TMP_DIR/evidence-base-zero"
    local valid_run_id="agent-validation-zero-resources"
    mkdir -p "$test_base/$valid_run_id"

    jq -n --arg run_id "$valid_run_id" --arg temp_root "$test_base/$valid_run_id/tmp" \
        '{run_id: $run_id, temp_root: $temp_root, resources: [], resource_count: 0, finalized: true}' \
        > "$test_base/$valid_run_id/state.json"

    local output
    output=$(EVIDENCE_BASE_DIR="$test_base" bash "$ORCHESTRATOR_SCRIPT" --cleanup "$valid_run_id" 2>&1) || true

    if [[ "$output" == *"0 resource"* ]]; then
        log_pass "Zero resources accurately reported"
    else
        log_fail "Zero resources not accurately reported"
        return 1
    fi
}

test_required_skips_make_release_nonzero() {
    log_test "Required SKIPs make --release exit nonzero"

    local test_script="$TEST_TMP_DIR/test_skip_exit.sh"
    cat > "$test_script" << 'INNER_EOF'
#!/bin/bash
set -euo pipefail

SKIP_COUNT=0

check_required_skip() {
    local status="$1"
    local required="$2"

    if [[ "$status" == "SKIP" ]] && [[ "$required" == "true" ]]; then
        ((SKIP_COUNT++)) || true
    fi
}

check_required_skip "SKIP" "true"
check_required_skip "SKIP" "true"
check_required_skip "PASS" "true"
check_required_skip "SKIP" "false"

if [[ "$SKIP_COUNT" -gt 0 ]]; then
    exit 6
fi
exit 0
INNER_EOF
    chmod +x "$test_script"

    local exit_code=0
    bash "$test_script" 2>/dev/null || exit_code=$?

    if [[ $exit_code -eq 6 ]]; then
        log_pass "Required SKIPs produce nonzero exit (INCOMPLETE=6)"
    else
        log_fail "Expected exit code 6 for required SKIPs, got $exit_code"
        return 1
    fi
}

test_release_required_tools_include_chromium() {
    log_test "Release preflight requires Chromium (not optional)"

    if grep -q 'command -v chromium' "$ORCHESTRATOR_SCRIPT" && \
       grep -q 'command -v chromium-browser' "$ORCHESTRATOR_SCRIPT" && \
       grep -q 'command -v google-chrome' "$ORCHESTRATOR_SCRIPT"; then
        log_pass "Supported Chromium executable names are checked"
    else
        log_fail "Chromium not in release-required tools"
        return 1
    fi

    if grep -q "release_optional_tools" "$ORCHESTRATOR_SCRIPT"; then
        log_fail "release_optional_tools still exists (Chromium should be required)"
        return 1
    else
        log_pass "No release_optional_tools (Chromium is required)"
    fi
}

test_release_preflight_requires_cgroup_v2() {
    log_test "Release preflight requires cgroup v2"

    if grep -q "cgroup.controllers" "$ORCHESTRATOR_SCRIPT"; then
        log_pass "cgroup v2 detection uses cgroup.controllers"
    else
        log_fail "cgroup v2 detection does not use cgroup.controllers"
        return 1
    fi

    if grep -q "cgroup v2 not detected" "$ORCHESTRATOR_SCRIPT"; then
        log_pass "cgroup v2 missing is an error for release"
    else
        log_fail "cgroup v2 missing is not an error"
        return 1
    fi
}

test_release_preflight_requires_dbus() {
    log_test "Release preflight requires D-Bus"

    if grep -q '"dbus-run-session"' "$ORCHESTRATOR_SCRIPT"; then
        log_pass "dbus-run-session is release-required"
    else
        log_fail "dbus-run-session not in release-required tools"
        return 1
    fi

    if grep -q "isolated D-Bus session" "$ORCHESTRATOR_SCRIPT"; then
        log_pass "Isolated D-Bus session check present"
    else
        log_fail "Isolated D-Bus session check missing"
        return 1
    fi
}

test_release_preflight_requires_notify_daemon() {
    log_test "Release preflight requires notification daemon"

    if grep -q '"dunst" "dunstctl" "Xvfb"' "$ORCHESTRATOR_SCRIPT"; then
        log_pass "dunst, dunstctl, and Xvfb are release-required"
    else
        log_fail "real notification stack not in release-required tools"
        return 1
    fi
}

test_release_preflight_allows_interactive_sudo() {
    log_test "Release preflight allows interactive sudo"

    if grep -q 'sudo -n true' "$ORCHESTRATOR_SCRIPT"; then
        log_fail "Release preflight incorrectly requires passwordless sudo"
        return 1
    elif grep -q '"sudo"' "$ORCHESTRATOR_SCRIPT"; then
        log_pass "sudo is required but passwordless sudo is not"
    else
        log_fail "sudo command requirement missing"
        return 1
    fi
}

test_cgroup_v2_detection_correct() {
    log_test "cgroup v2 detection uses /sys/fs/cgroup/cgroup.controllers"

    if grep -q '/sys/fs/cgroup/cgroup.controllers' "$ORCHESTRATOR_SCRIPT"; then
        log_pass "Correct cgroup v2 path used"
    else
        log_fail "Incorrect cgroup v2 path"
        return 1
    fi

    if grep -q '/sys/fs/cgroup/unified' "$ORCHESTRATOR_SCRIPT"; then
        log_fail "Old incorrect cgroup path still present"
        return 1
    else
        log_pass "Old incorrect cgroup path removed"
    fi
}

test_doc_stage_no_error_swallowing() {
    log_test "Doc stage does not swallow errors"

    if grep -q 'stage_doc_check' "$ORCHESTRATOR_SCRIPT"; then
        if grep -A5 'stage_doc_check()' "$ORCHESTRATOR_SCRIPT" | grep -q 'log_warn.*Documentation.*failed.*continuing'; then
            log_fail "Doc stage still swallows errors"
            return 1
        else
            log_pass "Doc stage does not swallow errors"
        fi
    else
        log_fail "stage_doc_check not found"
        return 1
    fi
}

test_all_feature_stage_uses_all_features() {
    log_test "All-feature stage uses cargo test --all-features"

    if grep -A5 'stage_all_feature_tests()' "$ORCHESTRATOR_SCRIPT" | grep -q 'cargo test --all-features'; then
        log_pass "All-feature stage uses cargo test --all-features"
    else
        log_fail "All-feature stage does not use cargo test --all-features"
        return 1
    fi

    if grep -A5 'stage_all_feature_tests()' "$ORCHESTRATOR_SCRIPT" | grep -q -- '--lib'; then
        log_fail "All-feature stage still uses --lib only"
        return 1
    else
        log_pass "All-feature stage does not use --lib only"
    fi
}

test_prompt_protocol_is_real_stage() {
    log_test "Prompt protocol is a real stage (not skip)"

    if grep -q 'stage_prompt_protocol' "$ORCHESTRATOR_SCRIPT"; then
        log_pass "stage_prompt_protocol function exists"
    else
        log_fail "stage_prompt_protocol function missing"
        return 1
    fi

    if grep -q 'run_stage "prompt-protocol" "stage_prompt_protocol"' "$ORCHESTRATOR_SCRIPT"; then
        log_pass "prompt-protocol uses run_stage (not skip_stage)"
    else
        log_fail "prompt-protocol still uses skip_stage"
        return 1
    fi

    if grep -A5 'stage_prompt_protocol()' "$ORCHESTRATOR_SCRIPT" | grep -q 'agent::prompt::dbus_tests'; then
        log_pass "prompt-protocol executes the real D-Bus test module"
    else
        log_fail "prompt-protocol does not execute the real D-Bus tests"
        return 1
    fi
}

test_validate_cleanup_target_exists() {
    log_test "validate_cleanup_target function exists"

    if grep -q 'validate_cleanup_target()' "$ORCHESTRATOR_SCRIPT"; then
        log_pass "validate_cleanup_target function present"
    else
        log_fail "validate_cleanup_target function missing"
        return 1
    fi
}

test_temp_root_recorded_in_state() {
    log_test "TEMP_ROOT recorded in state file"

    if grep -q 'temp_root' "$ORCHESTRATOR_SCRIPT" | head -1; then
        log_pass "temp_root referenced in script"
    else
        log_fail "temp_root not referenced"
        return 1
    fi

    if grep -q 'TEMP_ROOT=' "$ORCHESTRATOR_SCRIPT"; then
        log_pass "TEMP_ROOT variable set"
    else
        log_fail "TEMP_ROOT variable not set"
        return 1
    fi
}

test_env_report_includes_dbus_notify() {
    log_test "Environment report includes D-Bus and notify daemon"

    if grep -q 'dbus_version' "$ORCHESTRATOR_SCRIPT" && \
       grep -q 'notify_daemon' "$ORCHESTRATOR_SCRIPT"; then
        log_pass "Environment includes dbus_version and notify_daemon"
    else
        log_fail "Environment missing dbus or notify fields"
        return 1
    fi
}

test_no_unused_variables() {
    log_test "No unused variables (CLEANUP_REQUIRED removed)"

    if grep -q "CLEANUP_REQUIRED" "$ORCHESTRATOR_SCRIPT"; then
        log_fail "Unused variable CLEANUP_REQUIRED still present"
        return 1
    else
        log_pass "CLEANUP_REQUIRED removed"
    fi
}

test_no_source_state() {
    log_test "State file is never sourced"

    if grep -qE '^\s*source\s+.*state' "$ORCHESTRATOR_SCRIPT" || \
       grep -qE '^\s*\.\s+.*state' "$ORCHESTRATOR_SCRIPT"; then
        log_fail "State file is being sourced"
        return 1
    else
        log_pass "State file is never sourced (uses jq only)"
    fi
}

test_allowlisted_cleanup_dispatcher() {
    log_test "Cleanup dispatcher uses allowlist"

    if grep -q "ALLOWED_CLEANUP_ACTIONS" "$ORCHESTRATOR_SCRIPT" && \
       grep -q "dispatch_cleanup_action" "$ORCHESTRATOR_SCRIPT"; then
        log_pass "Allowlisted cleanup dispatcher present"
    else
        log_fail "Allowlisted cleanup dispatcher missing"
        return 1
    fi
}

main() {
    log_info "Starting orchestrator shell tests..."

    mkdir -p "$TEST_TMP_DIR"

    test_script_exists
    test_shebang
    test_strict_mode
    test_help_output
    test_help_lists_delete_evidence
    test_invalid_args
    test_path_validation
    test_symlink_chain_walks_downward
    test_json_generation
    test_no_unused_variables
    test_no_source_state
    test_allowlisted_cleanup_dispatcher
    test_validate_cleanup_target_exists
    test_temp_root_recorded_in_state
    test_state_file_restricted_permissions
    test_env_report_includes_dbus_notify
    test_release_required_tools_include_chromium
    test_release_preflight_requires_cgroup_v2
    test_release_preflight_requires_dbus
    test_release_preflight_requires_notify_daemon
    test_release_preflight_allows_interactive_sudo
    test_cgroup_v2_detection_correct
    test_doc_stage_no_error_swallowing
    test_all_feature_stage_uses_all_features
    test_prompt_protocol_is_real_stage
    test_required_skips_make_release_nonzero
    test_state_file_created_before_mutation
    test_zero_resources_reported
    test_cleanup_preserves_evidence
    test_cleanup_marks_state
    test_delete_evidence_requires_confirmation
    test_delete_evidence_with_correct_confirmation
    test_cleanup_path_traversal
    test_cleanup_sibling_prefix
    test_cleanup_base_directory
    test_cleanup_symlink
    test_cleanup_absolute_path
    test_cleanup_dotdot_id
    test_cleanup_invalid_chars
    test_cleanup_valid_id

    test_tier3_stage_files_exist
    test_tier3_lib_files_exist
    test_tier3_stages_wired_in_run_sh
    test_tier3_no_skip_stage_in_tier3
    test_tier3_stage_skipped_mechanism
    test_tier3_libs_sourced_in_run_sh
    test_tier3_fixtures_exist
    test_tier3_test_files_exist
    test_tier3_explicit_confirmation_preserved
    test_tier3_never_run_as_root

    log_info "Tests completed - $TEST_COUNT total, $PASS_COUNT passed, $FAIL_COUNT failed"

    if [[ $FAIL_COUNT -gt 0 ]]; then
        exit 1
    fi

    exit 0
}

main "$@"
