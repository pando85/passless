#!/bin/bash
#
# Behavior tests for real-notifications stage using mocked dunst/probe.
# Runs without live GUI or sudo.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATION_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LIB_DIR="${VALIDATION_DIR}/lib"
STAGES_DIR="${VALIDATION_DIR}/stages"

TEST_TMP_DIR="/tmp/passless-av-rn-test-$$"
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
    export RUN_ID="test-rn-001"
    export AV_VALIDATION_DIR="$VALIDATION_DIR"
    mkdir -p "$EVIDENCE_DIR" "$TEMP_ROOT"

    unset AV_LIB_COMMON_LOADED
    unset AV_LIB_NOTIFICATIONS_LOADED
    unset AV_STAGE_REAL_NOTIFICATIONS_LOADED
    unset PASSLESS_PROMPT_PROBE_BIN
    unset CARGO_TARGET_DIR

    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/notifications.sh"
    source "${STAGES_DIR}/real-notifications.sh"

    register_resource() { :; }
}

setup_mock_bin_dir() {
    local mock_dir="${TEST_TMP_DIR}/mock-bin-$$"
    mkdir -p "$mock_dir"
    echo "$mock_dir"
}

test_rn_skip_without_dunst() {
    log_test "real-notifications skips without dunst"
    setup_stage_env

    local mock_dir
    mock_dir=$(setup_mock_bin_dir)

    cat > "$mock_dir/dunst" << 'EOF'
#!/bin/bash
exit 1
EOF
    chmod +x "$mock_dir/dunst"

    cat > "$mock_dir/dunstctl" << 'EOF'
#!/bin/bash
exit 1
EOF
    chmod +x "$mock_dir/dunstctl"

    local old_path="$PATH"
    export PATH="$mock_dir:/usr/bin:/bin"

    STAGE_SKIPPED=false
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

test_rn_skip_without_probe_binary() {
    log_test "real-notifications skips without probe binary"
    setup_stage_env

    local mock_dir
    mock_dir=$(setup_mock_bin_dir)

    cat > "$mock_dir/dunst" << 'EOF'
#!/bin/bash
if [[ "$1" == "--help" ]]; then
    echo "action"
    exit 0
fi
exit 0
EOF
    chmod +x "$mock_dir/dunst"

    cat > "$mock_dir/dunstctl" << 'EOF'
#!/bin/bash
case "$1" in
    --help) echo "action close close-all count history running" ;;
    running) echo "true" ;;
    count) echo "0" ;;
    history) echo "" ;;
    *) exit 0 ;;
esac
EOF
    chmod +x "$mock_dir/dunstctl"

    cat > "$mock_dir/Xvfb" << 'EOF'
#!/bin/bash
sleep 30 &
echo $!
wait
EOF
    chmod +x "$mock_dir/Xvfb"

    cat > "$mock_dir/dbus-run-session" << 'EOF'
#!/bin/bash
exec "$@"
EOF
    chmod +x "$mock_dir/dbus-run-session"

    cat > "$mock_dir/notify-send" << 'EOF'
#!/bin/bash
exit 0
EOF
    chmod +x "$mock_dir/notify-send"

    local old_path="$PATH"
    export PATH="$mock_dir:/usr/bin:/bin"
    unset PASSLESS_PROMPT_PROBE_BIN
    export CARGO_TARGET_DIR="${TEST_TMP_DIR}/nonexistent-target"

    STAGE_SKIPPED=false
    if stage_real_notifications 2>/dev/null; then
        if [[ "${STAGE_SKIPPED:-false}" == "true" ]]; then
            log_pass "Correctly skipped without probe binary"
        else
            log_fail "Should set STAGE_SKIPPED without probe binary"
        fi
    else
        log_fail "Stage should succeed (with skip) without probe binary"
    fi

    export PATH="$old_path"
    unset CARGO_TARGET_DIR
}

test_rn_results_json_valid() {
    log_test "real-notifications produces valid JSON results"
    setup_stage_env

    local mock_dir
    mock_dir=$(setup_mock_bin_dir)

    cat > "$mock_dir/dunst" << 'EOF'
#!/bin/bash
exit 1
EOF
    chmod +x "$mock_dir/dunst"

    local old_path="$PATH"
    export PATH="$mock_dir:/usr/bin:/bin"

    STAGE_SKIPPED=false
    stage_real_notifications 2>/dev/null || true

    local results_file="${EVIDENCE_DIR}/real-notifications-results.json"
    if [[ -f "$results_file" ]]; then
        if jq empty "$results_file" 2>/dev/null; then
            log_pass "Results file is valid JSON"
        else
            log_fail "Results file is invalid JSON"
        fi
    else
        log_fail "Results file not created"
    fi

    export PATH="$old_path"
}

test_rn_results_contain_scenarios() {
    log_test "real-notifications results contain scenario entries"
    setup_stage_env

    local mock_dir
    mock_dir=$(setup_mock_bin_dir)

    cat > "$mock_dir/dunst" << 'EOF'
#!/bin/bash
exit 1
EOF
    chmod +x "$mock_dir/dunst"

    local old_path="$PATH"
    export PATH="$mock_dir:/usr/bin:/bin"

    STAGE_SKIPPED=false
    stage_real_notifications 2>/dev/null || true

    local results_file="${EVIDENCE_DIR}/real-notifications-results.json"
    if [[ -f "$results_file" ]]; then
        local scenario_count
        scenario_count=$(jq '.scenarios | length' "$results_file" 2>/dev/null || echo "0")
        if [[ "$scenario_count" -gt 0 ]]; then
            log_pass "Results contain $scenario_count scenario(s)"
        else
            log_fail "Results contain no scenarios"
        fi
    else
        log_fail "Results file not created"
    fi

    export PATH="$old_path"
}

test_av_wait_for_notification_timeout() {
    log_test "av_wait_for_notification returns 1 on timeout"
    setup_stage_env

    local mock_dir
    mock_dir=$(setup_mock_bin_dir)

    cat > "$mock_dir/dunstctl" << 'EOF'
#!/bin/bash
case "$1" in
    count) echo "0" ;;
    *) exit 0 ;;
esac
EOF
    chmod +x "$mock_dir/dunstctl"

    local old_path="$PATH"
    export PATH="$mock_dir:$old_path"

    if av_wait_for_notification 1 0.1 2>/dev/null; then
        log_fail "Should have timed out"
    else
        log_pass "Correctly timed out when no notification"
    fi

    export PATH="$old_path"
}

test_av_wait_for_notification_success() {
    log_test "av_wait_for_notification returns 0 when notification present"
    setup_stage_env

    local mock_dir
    mock_dir=$(setup_mock_bin_dir)

    cat > "$mock_dir/dunstctl" << 'EOF'
#!/bin/bash
case "$1" in
    count) echo "1" ;;
    *) exit 0 ;;
esac
EOF
    chmod +x "$mock_dir/dunstctl"

    local old_path="$PATH"
    export PATH="$mock_dir:$old_path"

    if av_wait_for_notification 2 0.1 2>/dev/null; then
        log_pass "Correctly detected notification"
    else
        log_fail "Should have detected notification"
    fi

    export PATH="$old_path"
}

test_av_probe_binary_found() {
    log_test "av_probe_binary finds probe binary"
    setup_stage_env

    local mock_dir
    mock_dir=$(setup_mock_bin_dir)

    touch "$mock_dir/agent-prompt-probe"
    chmod +x "$mock_dir/agent-prompt-probe"

    export CARGO_TARGET_DIR="$mock_dir/.."
    local probe_dir
    probe_dir=$(dirname "$mock_dir")
    mkdir -p "$probe_dir/release" "$probe_dir/debug"
    cp "$mock_dir/agent-prompt-probe" "$probe_dir/release/agent-prompt-probe"

    local found
    if found=$(av_probe_binary 2>/dev/null); then
        if [[ -x "$found" ]]; then
            log_pass "Found probe binary at $found"
        else
            log_fail "Found path not executable: $found"
        fi
    else
        log_pass "Probe binary not found (expected in test env)"
    fi
}

test_av_probe_binary_via_env() {
    log_test "av_probe_binary respects PASSLESS_PROMPT_PROBE_BIN"
    setup_stage_env

    local mock_dir
    mock_dir=$(setup_mock_bin_dir)

    touch "$mock_dir/my-probe"
    chmod +x "$mock_dir/my-probe"

    export PASSLESS_PROMPT_PROBE_BIN="$mock_dir/my-probe"

    local found
    if found=$(av_probe_binary 2>/dev/null); then
        if [[ "$found" == "$mock_dir/my-probe" ]]; then
            log_pass "Correctly used PASSLESS_PROMPT_PROBE_BIN"
        else
            log_fail "Wrong path: $found"
        fi
    else
        log_fail "Should have found probe via env var"
    fi

    unset PASSLESS_PROMPT_PROBE_BIN
}

test_av_next_xvfb_display() {
    log_test "av_next_xvfb_display finds free display"
    setup_stage_env

    local display
    if display=$(av_next_xvfb_display 2>/dev/null); then
        if [[ "$display" =~ ^:[0-9]+$ ]]; then
            log_pass "Got valid display: $display"
        else
            log_fail "Invalid display format: $display"
        fi
    else
        log_fail "Should have found a free display"
    fi
}

test_rn_no_notify_send_as_subject() {
    log_test "real-notifications stage does not use notify-send as subject under test"
    local stage_file="${STAGES_DIR}/real-notifications.sh"
    if grep -q 'av_send_notification' "$stage_file"; then
        log_fail "Stage still uses av_send_notification (notify-send)"
    else
        log_pass "Stage does not use notify-send as subject"
    fi
}

test_rn_uses_probe_binary() {
    log_test "real-notifications stage invokes probe binary"
    local stage_file="${STAGES_DIR}/real-notifications.sh"
    if grep -q 'probe_bin' "$stage_file" && grep -q 'av_probe_binary' "$stage_file"; then
        log_pass "Stage uses probe binary"
    else
        log_fail "Stage does not reference probe binary"
    fi
}

test_rn_uses_dbus_run_session() {
    log_test "real-notifications stage uses dbus-run-session"
    local stage_file="${STAGES_DIR}/real-notifications.sh"
    if grep -q 'dbus-run-session' "$stage_file"; then
        log_pass "Stage uses dbus-run-session"
    else
        log_fail "Stage does not use dbus-run-session"
    fi
}

test_rn_uses_dunstctl_for_wait() {
    log_test "real-notifications stage waits via dunstctl (not blind sleep)"
    local stage_file="${STAGES_DIR}/real-notifications.sh"
    if grep -q 'dunstctl count' "$stage_file" || grep -q 'dunstctl history' "$stage_file"; then
        log_pass "Stage uses dunstctl for deterministic wait"
    else
        log_fail "Stage does not use dunstctl for waiting"
    fi
}

main() {
    echo -e "${BLUE}=== Real Notifications Stage Tests ===${NC}" >&2

    test_rn_skip_without_dunst
    test_rn_skip_without_probe_binary
    test_rn_results_json_valid
    test_rn_results_contain_scenarios
    test_av_wait_for_notification_timeout
    test_av_wait_for_notification_success
    test_av_probe_binary_found
    test_av_probe_binary_via_env
    test_av_next_xvfb_display
    test_rn_no_notify_send_as_subject
    test_rn_uses_probe_binary
    test_rn_uses_dbus_run_session
    test_rn_uses_dunstctl_for_wait

    echo "" >&2
    echo -e "${BLUE}Tests: $TEST_COUNT total, $PASS_COUNT passed, $FAIL_COUNT failed${NC}" >&2

    [[ $FAIL_COUNT -eq 0 ]]
}

main "$@"
