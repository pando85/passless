#!/bin/bash
#
# Shell tests for the uninstall-rehearsal stage and credential-store lib
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATION_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LIB_DIR="${VALIDATION_DIR}/lib"
STAGES_DIR="${VALIDATION_DIR}/stages"

TEST_TMP_DIR="/tmp/passless-av-uninstall-test-$$"
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
    export RUN_ID="test-run-uninstall"
    export AV_VALIDATION_DIR="$VALIDATION_DIR"
    export PASSLESS_VALIDATION_DRY_RUN=1
    mkdir -p "$EVIDENCE_DIR" "$TEMP_ROOT"

    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/privilege.sh"
    source "${LIB_DIR}/credential-store.sh"

    STAGE_SKIPPED=false
}

create_mock_store() {
    local store_dir="${TEST_TMP_DIR}/mock-store"
    mkdir -p "$store_dir"
    cat > "$store_dir/cred-001.json" << 'JSON_EOF'
{"id":"cred-001","rp_id":"example.com","sign_count":42,"public_key":"abc123"}
JSON_EOF
    cat > "$store_dir/cred-002.json" << 'JSON_EOF'
{"id":"cred-002","rp_id":"example.com","sign_count":10,"public_key":"def456"}
JSON_EOF
    chmod 600 "$store_dir"/*
    printf '%s' "$store_dir"
}

create_mock_passless_bin() {
    local bin_path="${TEST_TMP_DIR}/mock-passless"
    cat > "$bin_path" << 'MOCK_EOF'
#!/bin/bash
case "$*" in
    *"agent-admin --output json session list --profile"*)
        echo '{"sessions":[{"session_id":"sess-001"}]}'
        ;;
    *"agent-admin --output json delegation list --profile"*)
        echo '{"grants":[{"grant_id":"grant-001"}]}'
        ;;
    *"agent-admin --output json profile check test-profile"*)
        echo '{"profile_id":"test-profile","audit_gate_healthy":true}'
        ;;
    *"agent-admin --output json profile disable"*)
        echo '{"profile_id":"test-profile","enabled":false}'
        ;;
    *"agent-admin --output json session revoke"*)
        echo '{"revoked":true}'
        ;;
    *"agent-admin --output json delegation revoke"*)
        echo '{"revoked":true}'
        ;;
    *"agent-admin --output json shutdown --confirm"*)
        echo '{"shutdown_initiated":true}'
        ;;
    *)
        echo '{}'
        ;;
esac
MOCK_EOF
    chmod +x "$bin_path"
    printf '%s' "$bin_path"
}

test_credential_store_lib_exists() {
    log_test "credential-store.sh lib exists"
    if [[ -f "${LIB_DIR}/credential-store.sh" ]]; then
        log_pass "credential-store.sh exists"
    else
        log_fail "credential-store.sh missing"
    fi
}

test_uninstall_rehearsal_stage_exists() {
    log_test "uninstall-rehearsal.sh stage exists"
    if [[ -f "${STAGES_DIR}/uninstall-rehearsal.sh" ]]; then
        log_pass "uninstall-rehearsal.sh exists"
    else
        log_fail "uninstall-rehearsal.sh missing"
    fi
}

test_stage_has_bash_shebang() {
    log_test "uninstall-rehearsal.sh has bash shebang"
    local first_line
    first_line=$(head -n1 "${STAGES_DIR}/uninstall-rehearsal.sh")
    if [[ "$first_line" == "#!/bin/bash" ]]; then
        log_pass "correct shebang"
    else
        log_fail "bad shebang: $first_line"
    fi
}

test_stage_has_strict_mode() {
    log_test "uninstall-rehearsal.sh uses strict mode"
    if grep -q 'set -euo pipefail' "${STAGES_DIR}/uninstall-rehearsal.sh"; then
        log_pass "strict mode present"
    else
        log_fail "strict mode missing"
    fi
}

test_validate_absolute_path_rejects_relative() {
    log_test "av_validate_absolute_path rejects relative paths"
    setup_env

    if av_validate_absolute_path "relative/path" "test" 2>/dev/null; then
        log_fail "relative path should be rejected"
    else
        log_pass "relative path rejected"
    fi
}

test_validate_absolute_path_rejects_symlink() {
    log_test "av_validate_absolute_path rejects symlinks"
    setup_env

    local target="${TEST_TMP_DIR}/real-target"
    local link="${TEST_TMP_DIR}/symlink-target"
    mkdir -p "$target"
    ln -sf "$target" "$link"

    if av_validate_absolute_path "$link" "test" 2>/dev/null; then
        log_fail "symlink should be rejected"
    else
        log_pass "symlink rejected"
    fi
}

test_validate_absolute_path_accepts_valid() {
    log_test "av_validate_absolute_path accepts valid absolute path"
    setup_env

    local valid_dir="${TEST_TMP_DIR}/valid-dir"
    mkdir -p "$valid_dir"

    if av_validate_absolute_path "$valid_dir" "test" 2>/dev/null; then
        log_pass "valid absolute path accepted"
    else
        log_fail "valid absolute path rejected"
    fi
}

test_validate_store_path_allows_directories() {
    log_test "av_validate_store_path allows nested directories"
    setup_env

    local store_dir="${TEST_TMP_DIR}/store-with-dirs"
    mkdir -p "$store_dir/subdir1/subdir2"
    echo "data" > "$store_dir/file1.json"
    echo "data" > "$store_dir/subdir1/file2.json"

    if av_validate_store_path "$store_dir" 2>/dev/null; then
        log_pass "store with nested directories accepted"
    else
        log_fail "store with nested directories rejected"
    fi
}

test_validate_store_path_rejects_symlinks_in_store() {
    log_test "av_validate_store_path rejects symlinks inside store"
    setup_env

    local store_dir="${TEST_TMP_DIR}/store-with-symlink"
    mkdir -p "$store_dir"
    echo "data" > "${TEST_TMP_DIR}/external-file"
    ln -sf "${TEST_TMP_DIR}/external-file" "$store_dir/symlinked-file"

    if av_validate_store_path "$store_dir" 2>/dev/null; then
        log_fail "store with symlink should be rejected"
    else
        log_pass "store with symlink rejected"
    fi
}

test_validate_store_path_rejects_special_files() {
    log_test "av_validate_store_path rejects special files (FIFO)"
    setup_env

    local store_dir="${TEST_TMP_DIR}/store-with-fifo"
    mkdir -p "$store_dir"
    mkfifo "$store_dir/test-fifo" 2>/dev/null || {
        log_test "(skipped: cannot create FIFO)"
        return 0
    }

    if av_validate_store_path "$store_dir" 2>/dev/null; then
        log_fail "store with FIFO should be rejected"
    else
        log_pass "store with FIFO rejected"
    fi
}

test_manifest_credential_store_creates_valid_json() {
    log_test "av_manifest_credential_store creates valid JSON"
    setup_env

    local store_dir
    store_dir=$(create_mock_store)
    local manifest_file="${TEST_TMP_DIR}/manifest.json"

    if av_manifest_credential_store "$store_dir" "$manifest_file" "local-json" 2>/dev/null; then
        if jq empty "$manifest_file" 2>/dev/null; then
            log_pass "manifest is valid JSON"
        else
            log_fail "manifest is invalid JSON"
        fi
    else
        log_fail "manifest creation failed"
    fi
}

test_manifest_contains_semantic_hashes() {
    log_test "manifest entries contain semantic hashes"
    setup_env

    local store_dir
    store_dir=$(create_mock_store)
    local manifest_file="${TEST_TMP_DIR}/manifest-hashes.json"

    av_manifest_credential_store "$store_dir" "$manifest_file" "local-json" 2>/dev/null || true

    local hash_count
    hash_count=$(jq '[.entries[] | select(.semantic_hash != "unavailable" and .semantic_hash != "")] | length' "$manifest_file" 2>/dev/null || echo "0")

    if [[ "$hash_count" -gt 0 ]]; then
        log_pass "manifest contains $hash_count semantically hashed entries"
    else
        log_fail "manifest has no semantically hashed entries"
    fi
}

test_manifest_contains_sign_counts() {
    log_test "manifest entries contain sign_count values"
    setup_env

    local store_dir
    store_dir=$(create_mock_store)
    local manifest_file="${TEST_TMP_DIR}/manifest-counts.json"

    av_manifest_credential_store "$store_dir" "$manifest_file" "local-json" 2>/dev/null || true

    local count_with_sign
    count_with_sign=$(jq '[.entries[] | select(.sign_count != "")] | length' "$manifest_file" 2>/dev/null || echo "0")

    if [[ "$count_with_sign" -gt 0 ]]; then
        log_pass "manifest contains $count_with_sign entries with sign_count"
    else
        log_fail "manifest has no entries with sign_count"
    fi
}

test_manifest_rejects_unsupported_format() {
    log_test "av_manifest_credential_store rejects unsupported format"
    setup_env

    local store_dir
    store_dir=$(create_mock_store)
    local manifest_file="${TEST_TMP_DIR}/manifest-bad-format.json"

    if av_manifest_credential_store "$store_dir" "$manifest_file" "unsupported-format" 2>/dev/null; then
        log_fail "manifest should reject unsupported format"
    else
        log_pass "manifest rejected unsupported format"
    fi
}

test_compare_manifests_detects_single_sign_count_increase() {
    log_test "av_compare_store_manifests allows exactly one sign_count increase"
    setup_env

    local store_dir
    store_dir=$(create_mock_store)
    local pre="${TEST_TMP_DIR}/pre-counter.json"
    local post="${TEST_TMP_DIR}/post-counter.json"
    local comparison="${TEST_TMP_DIR}/comparison-counter.json"

    av_manifest_credential_store "$store_dir" "$pre" "local-json" 2>/dev/null || true

    cat > "$store_dir/cred-001.json" << 'JSON_EOF'
{"id":"cred-001","rp_id":"example.com","sign_count":43,"public_key":"abc123"}
JSON_EOF
    av_manifest_credential_store "$store_dir" "$post" "local-json" 2>/dev/null || true

    if av_compare_store_manifests "$pre" "$post" "$comparison" 2>/dev/null; then
        local status
        status=$(jq -r '.status' "$comparison")
        if [[ "$status" == "expected_single_sign_count_increase" ]]; then
            log_pass "single sign_count increase correctly allowed"
        else
            log_fail "expected status=expected_single_sign_count_increase, got $status"
        fi
    else
        log_fail "single sign_count increase should have been allowed"
    fi
}

test_compare_manifests_rejects_multiple_sign_count_increases() {
    log_test "av_compare_store_manifests rejects multiple sign_count increases"
    setup_env

    local store_dir
    store_dir=$(create_mock_store)
    local pre="${TEST_TMP_DIR}/pre-multi.json"
    local post="${TEST_TMP_DIR}/post-multi.json"
    local comparison="${TEST_TMP_DIR}/comparison-multi.json"

    av_manifest_credential_store "$store_dir" "$pre" "local-json" 2>/dev/null || true

    cat > "$store_dir/cred-001.json" << 'JSON_EOF'
{"id":"cred-001","rp_id":"example.com","sign_count":43,"public_key":"abc123"}
JSON_EOF
    cat > "$store_dir/cred-002.json" << 'JSON_EOF'
{"id":"cred-002","rp_id":"example.com","sign_count":11,"public_key":"def456"}
JSON_EOF
    av_manifest_credential_store "$store_dir" "$post" "local-json" 2>/dev/null || true

    if av_compare_store_manifests "$pre" "$post" "$comparison" 2>/dev/null; then
        log_fail "multiple sign_count increases should be rejected"
    else
        local status
        status=$(jq -r '.status' "$comparison" 2>/dev/null || echo "unknown")
        if [[ "$status" == "multiple_sign_count_increases" ]]; then
            log_pass "multiple sign_count increases correctly rejected"
        else
            log_fail "expected status=multiple_sign_count_increases, got $status"
        fi
    fi
}

test_compare_manifests_rejects_semantic_changes() {
    log_test "av_compare_store_manifests rejects semantic content changes"
    setup_env

    local store_dir
    store_dir=$(create_mock_store)
    local pre="${TEST_TMP_DIR}/pre-semantic.json"
    local post="${TEST_TMP_DIR}/post-semantic.json"
    local comparison="${TEST_TMP_DIR}/comparison-semantic.json"

    av_manifest_credential_store "$store_dir" "$pre" "local-json" 2>/dev/null || true

    cat > "$store_dir/cred-001.json" << 'JSON_EOF'
{"id":"cred-001","rp_id":"example.com","sign_count":42,"public_key":"CHANGED"}
JSON_EOF
    av_manifest_credential_store "$store_dir" "$post" "local-json" 2>/dev/null || true

    if av_compare_store_manifests "$pre" "$post" "$comparison" 2>/dev/null; then
        log_fail "semantic changes should be rejected"
    else
        local unexpected
        unexpected=$(jq '.unexpected_changes' "$comparison" 2>/dev/null || echo "0")
        if [[ "$unexpected" -gt 0 ]]; then
            log_pass "semantic changes correctly detected ($unexpected)"
        else
            log_fail "unexpected_changes count is 0 despite failure"
        fi
    fi
}

test_compare_manifests_rejects_metadata_changes() {
    log_test "av_compare_store_manifests rejects metadata changes"
    setup_env

    local store_dir
    store_dir=$(create_mock_store)
    local pre="${TEST_TMP_DIR}/pre-metadata.json"
    local post="${TEST_TMP_DIR}/post-metadata.json"
    local comparison="${TEST_TMP_DIR}/comparison-metadata.json"

    av_manifest_credential_store "$store_dir" "$pre" "local-json" 2>/dev/null || true

    chmod 777 "$store_dir/cred-001.json"
    av_manifest_credential_store "$store_dir" "$post" "local-json" 2>/dev/null || true

    if av_compare_store_manifests "$pre" "$post" "$comparison" 2>/dev/null; then
        log_fail "metadata changes should be rejected"
    else
        local unexpected
        unexpected=$(jq '.unexpected_changes' "$comparison" 2>/dev/null || echo "0")
        if [[ "$unexpected" -gt 0 ]]; then
            log_pass "metadata changes correctly detected ($unexpected)"
        else
            log_fail "unexpected_changes count is 0 despite failure"
        fi
    fi
}

test_restart_mechanism_rejects_invalid() {
    log_test "av_restart_human_authenticator rejects invalid mechanism"
    setup_env

    if av_restart_human_authenticator "arbitrary-command" 2>/dev/null; then
        log_fail "invalid mechanism should be rejected"
    else
        log_pass "invalid mechanism rejected"
    fi
}

test_restart_mechanism_rejects_passless_service() {
    log_test "av_restart_human_authenticator rejects passless-service"
    setup_env

    if av_restart_human_authenticator "passless-service" 2>/dev/null; then
        log_fail "passless-service should be rejected"
    else
        log_pass "passless-service rejected"
    fi
}

test_restart_mechanism_accepts_none() {
    log_test "av_restart_human_authenticator accepts 'none'"
    setup_env

    if av_restart_human_authenticator "none" 2>/dev/null; then
        log_pass "'none' mechanism accepted"
    else
        log_fail "'none' mechanism should be accepted"
    fi
}

test_stage_dry_run_always_skips() {
    log_test "uninstall-rehearsal dry-run always SKIPs"
    setup_env
    source "${STAGES_DIR}/uninstall-rehearsal.sh"

    export AV_UNINSTALL_PASSLESS_BIN="/usr/bin/passless"
    export AV_UNINSTALL_PROFILE_IDS="test-isolated,test-delegated"
    export AV_UNINSTALL_HUMAN_STORE="/tmp/human-store"
    export AV_UNINSTALL_STORE_FORMAT="local-json"
    export AV_UNINSTALL_RP_URL="http://127.0.0.1:8443"
    export AV_UNINSTALL_RP_PORT="8443"
    export AV_UNINSTALL_BROWSER_USER="testuser"
    export AV_UNINSTALL_RESTART_MECHANISM="none"

    if stage_uninstall_rehearsal 2>/dev/null; then
        if [[ "${STAGE_SKIPPED}" == "true" ]]; then
            log_pass "dry-run correctly SKIPs"
        else
            log_fail "dry-run should set STAGE_SKIPPED"
        fi
    else
        log_fail "dry-run should succeed (with skip)"
    fi
}

test_stage_skips_without_env_vars() {
    log_test "uninstall-rehearsal skips without required env vars (live mode)"
    setup_env
    export PASSLESS_VALIDATION_DRY_RUN=0
    source "${STAGES_DIR}/uninstall-rehearsal.sh"

    unset AV_UNINSTALL_PASSLESS_BIN AV_UNINSTALL_PROFILE_IDS AV_UNINSTALL_HUMAN_STORE
    unset AV_UNINSTALL_STORE_FORMAT AV_UNINSTALL_RP_URL AV_UNINSTALL_RP_PORT
    unset AV_UNINSTALL_BROWSER_USER AV_UNINSTALL_RESTART_MECHANISM

    if stage_uninstall_rehearsal 2>/dev/null; then
        if [[ "${STAGE_SKIPPED}" == "true" ]]; then
            log_pass "correctly skipped without env vars"
        else
            log_fail "should set STAGE_SKIPPED without env vars"
        fi
    else
        log_fail "stage should succeed (with skip) without env vars"
    fi
}

test_stage_skips_with_unsupported_format() {
    log_test "uninstall-rehearsal skips with unsupported store format"
    setup_env
    export PASSLESS_VALIDATION_DRY_RUN=0
    source "${STAGES_DIR}/uninstall-rehearsal.sh"

    export AV_UNINSTALL_PASSLESS_BIN="/usr/bin/passless"
    export AV_UNINSTALL_PROFILE_IDS="test-isolated,test-delegated"
    export AV_UNINSTALL_HUMAN_STORE="${TEST_TMP_DIR}/some-store"
    export AV_UNINSTALL_STORE_FORMAT="tpm"
    export AV_UNINSTALL_RP_URL="http://127.0.0.1:8443"
    export AV_UNINSTALL_RP_PORT="8443"
    local current_user
    current_user="$(whoami)"
    export AV_UNINSTALL_BROWSER_USER="$current_user"
    export AV_UNINSTALL_RESTART_MECHANISM="none"
    mkdir -p "$AV_UNINSTALL_HUMAN_STORE"

    if stage_uninstall_rehearsal 2>/dev/null; then
        if [[ "${STAGE_SKIPPED}" == "true" ]]; then
            log_pass "correctly skipped with unsupported format"
        else
            log_fail "should set STAGE_SKIPPED with unsupported format"
        fi
    else
        log_fail "stage should succeed (with skip) with unsupported format"
    fi
}

test_mock_passless_bin_uses_correct_argv() {
    log_test "mock passless binary uses correct Clap argv"
    local mock_bin
    mock_bin=$(create_mock_passless_bin)

    local output
    output=$("$mock_bin" agent-admin --output json session list --profile test 2>/dev/null)
    if echo "$output" | jq -e '.sessions' &>/dev/null; then
        log_pass "mock uses correct argv: agent-admin --output json session list --profile"
    else
        log_fail "mock argv incorrect"
    fi

    output=$("$mock_bin" agent-admin --output json session revoke sess-001 --confirm 2>/dev/null)
    if echo "$output" | jq -e '.revoked == true' &>/dev/null; then
        log_pass "mock uses correct argv: session revoke SESSION_ID --confirm"
    else
        log_fail "mock session revoke argv incorrect"
    fi

    output=$("$mock_bin" agent-admin --output json profile disable test-profile 2>/dev/null)
    if echo "$output" | jq -e '.enabled == false' &>/dev/null; then
        log_pass "mock uses correct argv: profile disable PROFILE (no --confirm)"
    else
        log_fail "mock profile disable argv incorrect"
    fi
}

test_record_agent_state_with_mock() {
    log_test "av_record_agent_state works with mock binary"
    setup_env

    local mock_bin
    mock_bin=$(create_mock_passless_bin)
    local state_file="${TEST_TMP_DIR}/agent-state.json"

    if av_record_agent_state "$mock_bin" "test-profile" "$state_file" "0" 2>/dev/null; then
        if jq empty "$state_file" 2>/dev/null; then
            local session_count
            session_count=$(jq '.sessions | length' "$state_file" 2>/dev/null || echo "0")
            if [[ "$session_count" -gt 0 ]]; then
                log_pass "agent state recorded with $session_count session(s)"
            else
                log_fail "no sessions recorded"
            fi
        else
            log_fail "agent state file is invalid JSON"
        fi
    else
        log_fail "record_agent_state failed with mock"
    fi
}

test_disable_profile_with_mock() {
    log_test "av_disable_agent_profile works with mock binary"
    setup_env

    local mock_bin
    mock_bin=$(create_mock_passless_bin)

    if av_disable_agent_profile "$mock_bin" "test-profile" "0" 2>/dev/null; then
        log_pass "profile disable succeeded with mock"
    else
        log_fail "profile disable failed with mock"
    fi
}

test_verify_agent_absent_with_no_daemon() {
    log_test "av_verify_agent_absent passes when no daemon running"
    setup_env

    local verify_file="${TEST_TMP_DIR}/agent-absent.json"

    if av_verify_agent_absent "/bin/false" "nonexistent-profile-$$" "" "$verify_file" 2>/dev/null; then
        log_pass "agent absent verification passed"
    else
        log_fail "agent absent verification failed"
    fi
}

test_no_eval_in_stage() {
    log_test "uninstall-rehearsal.sh contains no eval"
    if grep -q '^\s*eval\s' "${STAGES_DIR}/uninstall-rehearsal.sh"; then
        log_fail "stage contains eval"
    else
        log_pass "no eval in stage"
    fi
}

test_no_eval_in_lib() {
    log_test "credential-store.sh contains no eval"
    if grep -q '^\s*eval\s' "${LIB_DIR}/credential-store.sh"; then
        log_fail "lib contains eval"
    else
        log_pass "no eval in lib"
    fi
}

test_stage_wired_in_run_sh() {
    log_test "uninstall-rehearsal is wired in run.sh"
    if grep -q 'run_stage "uninstall-rehearsal" "stage_uninstall_rehearsal"' "${VALIDATION_DIR}/run.sh"; then
        log_pass "uninstall-rehearsal uses run_stage"
    else
        log_fail "uninstall-rehearsal not wired with run_stage"
    fi
}

test_stage_before_lab_safety() {
    log_test "uninstall-rehearsal is before lab-safety in run.sh"
    local uninstall_line lab_safety_line
    uninstall_line=$(grep -n 'run_stage "uninstall-rehearsal"' "${VALIDATION_DIR}/run.sh" | head -1 | cut -d: -f1)
    lab_safety_line=$(grep -n 'run_stage "lab-safety"' "${VALIDATION_DIR}/run.sh" | head -1 | cut -d: -f1)

    if [[ -n "$uninstall_line" ]] && [[ -n "$lab_safety_line" ]] && [[ "$uninstall_line" -lt "$lab_safety_line" ]]; then
        log_pass "uninstall-rehearsal (line $uninstall_line) before lab-safety (line $lab_safety_line)"
    else
        log_fail "ordering incorrect: uninstall=$uninstall_line lab-safety=$lab_safety_line"
    fi
}

test_allowed_restart_mechanisms_enum() {
    log_test "AV_ALLOWED_RESTART_MECHANISMS is a fixed enum without passless-service"
    setup_env

    local count=${#AV_ALLOWED_RESTART_MECHANISMS[@]}
    if [[ $count -gt 0 ]]; then
        log_pass "restart mechanisms enum has $count entries"
    else
        log_fail "restart mechanisms enum is empty"
    fi

    local has_user=false has_system=false has_none=false has_passless_service=false
    for m in "${AV_ALLOWED_RESTART_MECHANISMS[@]}"; do
        [[ "$m" == "systemctl-user-passless" ]] && has_user=true
        [[ "$m" == "systemctl-system-passless" ]] && has_system=true
        [[ "$m" == "none" ]] && has_none=true
        [[ "$m" == "passless-service" ]] && has_passless_service=true
    done

    if [[ "$has_user" == true ]] && [[ "$has_system" == true ]] && [[ "$has_none" == true ]] && [[ "$has_passless_service" == false ]]; then
        log_pass "enum contains fixed user/system passless services and none"
    else
        log_fail "enum values incorrect"
    fi
}

test_allowed_store_formats_enum() {
    log_test "AV_ALLOWED_STORE_FORMATS contains only local-json"
    setup_env

    local count=${#AV_ALLOWED_STORE_FORMATS[@]}
    if [[ $count -eq 1 ]]; then
        log_pass "store formats enum has exactly 1 entry"
    else
        log_fail "store formats enum should have exactly 1 entry"
    fi

    if [[ "${AV_ALLOWED_STORE_FORMATS[0]}" == "local-json" ]]; then
        log_pass "store format is local-json"
    else
        log_fail "store format should be local-json"
    fi
}

test_store_max_bounds_enforced() {
    log_test "store max bounds constants exist"
    setup_env

    if [[ $AV_STORE_MAX_FILES -gt 0 ]] && [[ $AV_STORE_MAX_BYTES -gt 0 ]]; then
        log_pass "bounds set: max_files=$AV_STORE_MAX_FILES max_bytes=$AV_STORE_MAX_BYTES"
    else
        log_fail "bounds not set properly"
    fi
}

main() {
    echo -e "${BLUE}=== Uninstall Rehearsal Tests ===${NC}" >&2

    test_credential_store_lib_exists
    test_uninstall_rehearsal_stage_exists
    test_stage_has_bash_shebang
    test_stage_has_strict_mode
    test_validate_absolute_path_rejects_relative
    test_validate_absolute_path_rejects_symlink
    test_validate_absolute_path_accepts_valid
    test_validate_store_path_allows_directories
    test_validate_store_path_rejects_symlinks_in_store
    test_validate_store_path_rejects_special_files
    test_manifest_credential_store_creates_valid_json
    test_manifest_contains_semantic_hashes
    test_manifest_contains_sign_counts
    test_manifest_rejects_unsupported_format
    test_compare_manifests_detects_single_sign_count_increase
    test_compare_manifests_rejects_multiple_sign_count_increases
    test_compare_manifests_rejects_semantic_changes
    test_compare_manifests_rejects_metadata_changes
    test_restart_mechanism_rejects_invalid
    test_restart_mechanism_rejects_passless_service
    test_restart_mechanism_accepts_none
    test_stage_dry_run_always_skips
    test_stage_skips_without_env_vars
    test_stage_skips_with_unsupported_format
    test_mock_passless_bin_uses_correct_argv
    test_record_agent_state_with_mock
    test_disable_profile_with_mock
    test_verify_agent_absent_with_no_daemon
    test_no_eval_in_stage
    test_no_eval_in_lib
    test_stage_wired_in_run_sh
    test_stage_before_lab_safety
    test_allowed_restart_mechanisms_enum
    test_allowed_store_formats_enum
    test_store_max_bounds_enforced

    echo "" >&2
    echo -e "${BLUE}Tests: $TEST_COUNT total, $PASS_COUNT passed, $FAIL_COUNT failed${NC}" >&2

    [[ $FAIL_COUNT -eq 0 ]]
}

main "$@"
