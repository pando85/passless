#!/bin/bash
#
# Shell tests for lib/privilege.sh - behavior tests with mocked commands
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATION_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LIB_DIR="${VALIDATION_DIR}/lib"

TEST_TMP_DIR="/tmp/passless-av-priv-test-$$"
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

test_privilege_lib_exists() {
    log_test "privilege.sh exists and is readable"
    if [[ -f "${LIB_DIR}/privilege.sh" ]]; then
        log_pass "privilege.sh exists"
    else
        log_fail "privilege.sh not found"
        return 1
    fi
}

test_no_arbitrary_command_execution() {
    log_test "privilege.sh does not allow arbitrary command execution"

    if grep -q 'av_run_privileged' "${LIB_DIR}/privilege.sh"; then
        log_fail "av_run_privileged function still exists (allows arbitrary commands)"
        return 1
    else
        log_pass "No av_run_privileged function (no arbitrary command execution)"
    fi

    if grep -q '^av_run_as_root()' "${LIB_DIR}/privilege.sh"; then
        log_fail "generic av_run_as_root function still exists"
        return 1
    else
        log_pass "No generic privileged command dispatcher exists"
    fi
}

test_dedicated_helpers_exist() {
    log_test "Dedicated privilege helpers exist"

    local helpers=("av_phase0_setup" "av_phase0_cleanup" "av_install_test_udev_rule" "av_remove_test_udev_rule" "av_reload_udev" "av_trigger_udev")
    local all_found=true

    for helper in "${helpers[@]}"; do
        if ! grep -q "^${helper}()" "${LIB_DIR}/privilege.sh"; then
            log_fail "Helper function not found: $helper"
            all_found=false
        fi
    done

    if [[ "$all_found" == "true" ]]; then
        log_pass "All dedicated helpers exist"
    fi
}

test_phase0_setup_validates_script() {
    log_test "av_phase0_setup validates script exists and is executable"

    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/privilege.sh"

    local fake_phase0="${TEST_TMP_DIR}/fake-phase0"
    mkdir -p "$fake_phase0/policy"

    # Test with missing script
    if av_phase0_setup "$fake_phase0" 2>/dev/null; then
        log_fail "av_phase0_setup succeeded with missing script"
        return 1
    else
        log_pass "av_phase0_setup fails with missing script"
    fi

    # Test with non-executable script
    touch "$fake_phase0/policy/setup.sh"
    if av_phase0_setup "$fake_phase0" 2>/dev/null; then
        log_fail "av_phase0_setup succeeded with non-executable script"
        return 1
    else
        log_pass "av_phase0_setup fails with non-executable script"
    fi
}

test_install_test_udev_validates_path() {
    log_test "av_install_test_udev_rule validates destination path"

    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/privilege.sh"

    local src_file="${TEST_TMP_DIR}/test.rules"
    touch "$src_file"

    # Test with invalid path
    if av_install_test_udev_rule "$src_file" "/tmp/invalid.rules" 2>/dev/null; then
        log_fail "av_install_test_udev_rule accepted invalid path"
        return 1
    else
        log_pass "av_install_test_udev_rule rejects invalid path"
    fi

    # Test with valid path (will fail due to no sudo, but validates path first)
    if av_install_test_udev_rule "$src_file" "/etc/udev/rules.d/99-test.rules" 2>&1 | grep -q "Invalid destination"; then
        log_fail "av_install_test_udev_rule rejected valid path pattern"
        return 1
    else
        log_pass "av_install_test_udev_rule accepts valid path pattern"
    fi
}

test_remove_test_udev_validates_path() {
    log_test "av_remove_test_udev_rule validates path pattern"

    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/privilege.sh"

    # Test with invalid path
    if av_remove_test_udev_rule "/etc/udev/rules.d/99-other.rules" 2>/dev/null; then
        log_fail "av_remove_test_udev_rule accepted invalid path"
        return 1
    else
        log_pass "av_remove_test_udev_rule rejects invalid path"
    fi
}

test_interactive_sudo_allowed() {
    log_test "privilege.sh allows interactive sudo (not just sudo -n)"

    if grep -q 'sudo -n' "${LIB_DIR}/privilege.sh"; then
        log_fail "privilege.sh requires sudo -n (passwordless)"
        return 1
    else
        log_pass "privilege.sh allows interactive sudo"
    fi
}

main() {
    echo -e "${BLUE}=== Privilege Helper Tests ===${NC}" >&2

    test_privilege_lib_exists
    test_no_arbitrary_command_execution
    test_dedicated_helpers_exist
    test_phase0_setup_validates_script
    test_install_test_udev_validates_path
    test_remove_test_udev_validates_path
    test_interactive_sudo_allowed

    echo "" >&2
    echo -e "${BLUE}Tests: $TEST_COUNT total, $PASS_COUNT passed, $FAIL_COUNT failed${NC}" >&2

    [[ $FAIL_COUNT -eq 0 ]]
}

main "$@"
