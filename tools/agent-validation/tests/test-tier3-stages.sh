#!/bin/bash
#
# Shell tests for Tier 3 stage functions
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATION_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LIB_DIR="${VALIDATION_DIR}/lib"
STAGES_DIR="${VALIDATION_DIR}/stages"
# shellcheck disable=SC2034
PHASE0_DIR="${VALIDATION_DIR}/../agent-uhid-feasibility"

TEST_TMP_DIR="/tmp/passless-av-tier3-test-$$"
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

setup_stage_env() {
    export EVIDENCE_DIR="${TEST_TMP_DIR}/evidence"
    export TEMP_ROOT="${TEST_TMP_DIR}/tmp"
    export RUN_ID="test-run-001"
    export AV_VALIDATION_DIR="$VALIDATION_DIR"
    export PASSLESS_VALIDATION_DRY_RUN=1
    mkdir -p "$EVIDENCE_DIR" "$TEMP_ROOT"

    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/privilege.sh"
    source "${LIB_DIR}/principal.sh"
    source "${LIB_DIR}/device-matrix.sh"
    source "${LIB_DIR}/snapshot.sh"

    register_resource() { :; }
}

test_stage_files_exist() {
    log_test "All stage files exist"
    local stages=("privileged-setup.sh" "principal-isolation.sh" "device-probes.sh" "lab-safety.sh" "uninstall-rehearsal.sh")
    local all_found=true
    for stage in "${stages[@]}"; do
        if [[ ! -f "${STAGES_DIR}/${stage}" ]]; then
            log_fail "Missing stage: $stage"
            all_found=false
        fi
    done
    if [[ "$all_found" == "true" ]]; then
        log_pass "All stage files present"
    fi
}

test_stages_are_bash_scripts() {
    log_test "Stage files have bash shebang"
    local stages=("privileged-setup.sh" "principal-isolation.sh" "device-probes.sh" "lab-safety.sh" "uninstall-rehearsal.sh")
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
        log_pass "All stages have correct shebang"
    fi
}

test_stages_have_strict_mode() {
    log_test "Stage files use strict mode"
    local stages=("privileged-setup.sh" "principal-isolation.sh" "device-probes.sh" "lab-safety.sh" "uninstall-rehearsal.sh")
    local all_ok=true
    for stage in "${stages[@]}"; do
        if ! grep -q 'set -euo pipefail' "${STAGES_DIR}/${stage}" 2>/dev/null; then
            log_fail "Missing strict mode in $stage"
            all_ok=false
        fi
    done
    if [[ "$all_ok" == "true" ]]; then
        log_pass "All stages use strict mode"
    fi
}

test_stage_privileged_setup_dry_run() {
    log_test "privileged-setup stage runs in dry-run mode"
    setup_stage_env
    source "${STAGES_DIR}/privileged-setup.sh"

    if stage_privileged_setup 2>/dev/null; then
        log_pass "privileged-setup dry-run succeeded"
    else
        log_fail "privileged-setup dry-run failed"
        return 1
    fi
}

test_stage_principal_isolation_dry_run() {
    log_test "principal-isolation stage skips without required env vars"
    setup_stage_env
    source "${STAGES_DIR}/principal-isolation.sh"

    unset AV_PRINCIPAL_PROFILE AV_PRINCIPAL_USER AV_PASSLESS_BIN AV_PRINCIPAL_PROBE_BIN

    if stage_principal_isolation 2>/dev/null; then
        if [[ "${STAGE_SKIPPED}" == "true" ]]; then
            log_pass "principal-isolation correctly skipped without env vars"
        else
            log_fail "principal-isolation should set STAGE_SKIPPED without env vars"
            return 1
        fi
    else
        log_fail "principal-isolation should succeed (with skip) without env vars"
        return 1
    fi

    if [[ -f "${EVIDENCE_DIR}/principal-checks.json" ]]; then
        local status
        status=$(jq -r '.status' "${EVIDENCE_DIR}/principal-checks.json" 2>/dev/null || echo "")
        if [[ "$status" == "skipped" ]]; then
            log_pass "checks file reports skipped status"
        else
            log_fail "checks file should report skipped status"
            return 1
        fi
    else
        log_fail "Principal checks file not created"
        return 1
    fi
}

test_stage_device_probes_dry_run() {
    log_test "device-probes stage runs in dry-run mode"
    setup_stage_env
    source "${STAGES_DIR}/device-probes.sh"

    if stage_device_probes 2>/dev/null; then
        log_pass "device-probes dry-run succeeded"
    else
        log_fail "device-probes dry-run failed"
        return 1
    fi
}

test_stage_lab_safety_dry_run() {
    log_test "lab-safety stage runs in dry-run mode"
    setup_stage_env
    source "${STAGES_DIR}/lab-safety.sh"

    if stage_lab_safety 2>/dev/null; then
        log_pass "lab-safety dry-run succeeded"
    else
        log_fail "lab-safety dry-run failed"
        return 1
    fi
}

test_stage_uninstall_rehearsal_dry_run() {
    log_test "uninstall-rehearsal stage runs in dry-run mode"
    setup_stage_env
    source "${STAGES_DIR}/uninstall-rehearsal.sh"

    export AV_UNINSTALL_PASSLESS_BIN="/usr/bin/passless"
    export AV_UNINSTALL_PROFILE_IDS="test-isolated,test-same-user"
    export AV_UNINSTALL_HUMAN_STORE="/tmp/human-store"
    export AV_UNINSTALL_STORE_FORMAT="local-json"
    export AV_UNINSTALL_RP_URL="http://127.0.0.1:8443"
    export AV_UNINSTALL_RP_PORT="8443"
    export AV_UNINSTALL_BROWSER_USER="testuser"
    export AV_UNINSTALL_RESTART_MECHANISM="none"

    if stage_uninstall_rehearsal 2>/dev/null; then
        log_pass "uninstall-rehearsal dry-run succeeded"
    else
        log_fail "uninstall-rehearsal dry-run failed"
        return 1
    fi
}

test_stage_principal_isolation_no_fake_pass() {
    log_test "principal-isolation does not fake PASS with missing prerequisites"
    setup_stage_env
    source "${STAGES_DIR}/principal-isolation.sh"

    unset AV_PRINCIPAL_PROFILE AV_PRINCIPAL_USER AV_PASSLESS_BIN AV_PRINCIPAL_PROBE_BIN

    if stage_principal_isolation 2>/dev/null; then
        local checks_file="${EVIDENCE_DIR}/principal-checks.json"
        if [[ -f "$checks_file" ]]; then
            local status
            status=$(jq -r '.status // empty' "$checks_file" 2>/dev/null || echo "")
            if [[ "$status" == "skipped" ]] && [[ "${STAGE_SKIPPED}" == "true" ]]; then
                log_pass "Correctly skips without prerequisites (never fakes pass)"
            else
                log_fail "Expected skipped status, got status=$status skipped=${STAGE_SKIPPED}"
                return 1
            fi
        fi
    else
        log_fail "Stage should succeed (with skip) even without prerequisites"
        return 1
    fi
}

test_stage_device_probes_dry_run_produces_evidence() {
    log_test "device-probes dry-run produces evidence files"
    setup_stage_env
    source "${STAGES_DIR}/device-probes.sh"

    stage_device_probes 2>/dev/null || true

    if [[ -f "${EVIDENCE_DIR}/udev-static-analysis.json" ]]; then
        if jq empty "${EVIDENCE_DIR}/udev-static-analysis.json" 2>/dev/null; then
            log_pass "Static analysis evidence is valid JSON"
        else
            log_fail "Static analysis evidence is invalid JSON"
            return 1
        fi
    else
        log_test "(skipped: Phase0 rules not found)"
    fi
}

test_stage_lab_safety_dry_run_produces_report() {
    log_test "lab-safety dry-run produces safety report"
    setup_stage_env
    source "${STAGES_DIR}/lab-safety.sh"

    stage_lab_safety 2>/dev/null || true

    if [[ -f "${EVIDENCE_DIR}/lab-safety-report.json" ]]; then
        if jq empty "${EVIDENCE_DIR}/lab-safety-report.json" 2>/dev/null; then
            log_pass "Lab safety report is valid JSON"
        else
            log_fail "Lab safety report is invalid JSON"
            return 1
        fi
    else
        log_fail "Lab safety report not created"
        return 1
    fi
}

test_fixtures_exist() {
    log_test "Fixture files exist"
    if [[ -f "${VALIDATION_DIR}/fixtures/test-udev-rules/99-agent-validation-test.rules" ]]; then
        log_pass "Test udev rules fixture exists"
    else
        log_fail "Test udev rules fixture missing"
        return 1
    fi

    if [[ -f "${VALIDATION_DIR}/fixtures/expected-identity-matrix.json" ]]; then
        if jq empty "${VALIDATION_DIR}/fixtures/expected-identity-matrix.json" 2>/dev/null; then
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

test_test_udev_rules_do_not_grant_human_uhid() {
    log_test "Test udev rules do not grant human group /dev/uhid"
    local test_rules="${VALIDATION_DIR}/fixtures/test-udev-rules/99-agent-validation-test.rules"
    if [[ ! -f "$test_rules" ]]; then
        log_fail "Test rules file not found"
        return 1
    fi

    local uhid_human_match
    uhid_human_match=$(grep -E 'KERNEL=="uhid"' "$test_rules" | grep -v '^#' | grep 'GROUP="fido"' || true)

    if [[ -z "$uhid_human_match" ]]; then
        log_pass "Test rules do not grant fido group /dev/uhid"
    else
        log_fail "Test rules grant fido group /dev/uhid"
        return 1
    fi
}

main() {
    echo -e "${BLUE}=== Tier 3 Stage Tests ===${NC}" >&2

    test_stage_files_exist
    test_stages_are_bash_scripts
    test_stages_have_strict_mode
    test_stage_privileged_setup_dry_run
    test_stage_principal_isolation_dry_run
    test_stage_device_probes_dry_run
    test_stage_lab_safety_dry_run
    test_stage_uninstall_rehearsal_dry_run
    test_stage_principal_isolation_no_fake_pass
    test_stage_device_probes_dry_run_produces_evidence
    test_stage_lab_safety_dry_run_produces_report
    test_fixtures_exist
    test_test_udev_rules_do_not_grant_human_uhid

    echo "" >&2
    echo -e "${BLUE}Tests: $TEST_COUNT total, $PASS_COUNT passed, $FAIL_COUNT failed${NC}" >&2

    [[ $FAIL_COUNT -eq 0 ]]
}

main "$@"
