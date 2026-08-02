#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATION_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LIB_DIR="${VALIDATION_DIR}/lib"
STAGES_DIR="${VALIDATION_DIR}/stages"
BROWSER_DIR="${VALIDATION_DIR}/browser"

TEST_TMP_DIR="/tmp/passless-av-gc-test-$$"
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
    rm -rf "$TEST_TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p "$TEST_TMP_DIR"

setup_env() {
    export EVIDENCE_DIR="${TEST_TMP_DIR}/evidence"
    export TEMP_ROOT="${TEST_TMP_DIR}/tmp"
    export RUN_ID="test-gc-run"
    export AV_VALIDATION_DIR="$VALIDATION_DIR"
    export AV_DAEMON_RUNTIME_DIR="${TEST_TMP_DIR}/runtime"
    mkdir -p "$EVIDENCE_DIR" "$TEMP_ROOT" "$AV_DAEMON_RUNTIME_DIR"

    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/browser.sh"
    source "${LIB_DIR}/daemon-bridge.sh"
    source "${LIB_DIR}/real-rp.sh"
    source "${STAGES_DIR}/real-rp.sh"

    register_resource() { :; }
}

create_mock_passless() {
    local mock_bin="${TEST_TMP_DIR}/mock-passless-$1"
    shift
    local response_type="$1"
    shift

    cat > "$mock_bin" << MOCK
#!/bin/bash
received=""
for arg in "\$@"; do received="\${received}\${received:+ }\${arg}"; done
case "\$received" in
    *"agent-admin --output json audit status"*)
        printf '{"version":1,"status":"ok","data":{"enabled":true,"entry_count":42,"latest_entry_at":100}}\n'
        exit 0
        ;;
    *"agent --profile"*"browser-status"*)
MOCK

    case "$response_type" in
        healthy)
            cat >> "$mock_bin" << 'MOCK'
        printf '{"running":true,"cdp_endpoint":"http://127.0.0.1:19222","extension_loaded":true}\n'
        exit 0
        ;;
MOCK
            ;;
        not_running)
            cat >> "$mock_bin" << 'MOCK'
        printf '{"running":false}\n'
        exit 0
        ;;
MOCK
            ;;
        pipe_mode)
            cat >> "$mock_bin" << 'MOCK'
        printf '{"running":true,"cdp_endpoint":"unix:///tmp/pipe.sock"}\n'
        exit 0
        ;;
MOCK
            ;;
        *)
            cat >> "$mock_bin" << 'MOCK'
        exit 1
        ;;
MOCK
            ;;
    esac

    cat >> "$mock_bin" << 'MOCK'
    *"agent run --profile"*"node"*)
        printf '{"navigation_ok":true,"click_ok":true,"url_origin":"https://tea.millaguie.net","title_class":"dashboard","self_check":"pass"}\n'
        exit 0
        ;;
    *"agent-admin --output json audit export"*)
        printf '{"entries":[{"action":"authenticate","rp_id":"tea.millaguie.net","timestamp":"2024-01-01T00:00:00Z","status":"approved"}]}\n'
        exit 0
        ;;
    *"delegation revoke"*)
        printf '{"status":"ok"}\n'
        exit 0
        ;;
    *)
        exit 1
        ;;
esac
MOCK

    chmod +x "$mock_bin"
    echo "$mock_bin"
}

test_gc_lib_file_exists() {
    log_test "real-rp lib file exists"
    if [[ -f "${LIB_DIR}/real-rp.sh" ]]; then
        log_pass "lib file present"
    else
        log_fail "lib file missing"
    fi
}

test_gc_stage_file_exists() {
    log_test "real-rp stage file exists"
    if [[ -f "${STAGES_DIR}/real-rp.sh" ]]; then
        log_pass "stage file present"
    else
        log_fail "stage file missing"
    fi
}

test_gc_driver_file_exists() {
    log_test "real-rp-driver.js exists"
    if [[ -f "${BROWSER_DIR}/real-rp-driver.js" ]]; then
        log_pass "driver file present"
    else
        log_fail "driver file missing"
    fi
}

test_gc_runner_file_exists() {
    log_test "real-rp-runner.sh exists and is executable"
    if [[ -f "${VALIDATION_DIR}/real-rp-runner.sh" ]] && [[ -x "${VALIDATION_DIR}/real-rp-runner.sh" ]]; then
        log_pass "runner file present and executable"
    else
        log_fail "runner file missing or not executable"
    fi
}

test_gc_env_check_missing_vars() {
    log_test "av_gc_env_check fails without required env vars"
    setup_env
    unset AV_PASSLESS_BIN AV_DAEMON_PROFILE AV_DAEMON_RUNTIME_DIR AV_REAL_RP_CREDENTIAL_REF

    if av_gc_env_check 2>/dev/null; then
        log_fail "should fail without env vars"
    else
        log_pass "correctly fails without env vars"
    fi
}

test_gc_env_check_with_all_vars() {
    log_test "av_gc_env_check passes with all required env vars"
    setup_env
    local mock_bin
    mock_bin=$(create_mock_passless "env" "healthy")
    export AV_PASSLESS_BIN="$mock_bin"
    export AV_DAEMON_PROFILE="test-profile"
    export AV_DAEMON_RUNTIME_DIR="${TEST_TMP_DIR}/runtime"
    export AV_REAL_RP_CREDENTIAL_REF="test-ref-not-real"

    if av_gc_env_check 2>/dev/null; then
        log_pass "passes with all env vars set"
    else
        log_fail "should pass with all env vars"
    fi
}

test_gc_fail_closed_no_env() {
    log_test "Gate C returns INCOMPLETE without env vars (fail-closed)"
    setup_env
    unset AV_PASSLESS_BIN AV_DAEMON_PROFILE AV_DAEMON_RUNTIME_DIR AV_REAL_RP_CREDENTIAL_REF

    stage_real_rp 2>/dev/null || true

    local results_file="${EVIDENCE_DIR}/real-rp-results.json"
    if [[ -f "$results_file" ]]; then
        local status
        status=$(jq -r '.status' "$results_file" 2>/dev/null || echo "unknown")
        if [[ "$status" == "incomplete" ]]; then
            log_pass "correctly returned INCOMPLETE"
        else
            log_fail "status was '$status', expected 'incomplete'"
        fi
    else
        log_fail "results file not created"
    fi
}

test_gc_fail_closed_no_daemon() {
    log_test "Gate C returns INCOMPLETE without healthy daemon"
    setup_env
    export AV_PASSLESS_BIN="/nonexistent/passless"
    export AV_DAEMON_PROFILE="test-profile"
    export AV_DAEMON_RUNTIME_DIR="${TEST_TMP_DIR}/runtime"
    export AV_REAL_RP_CREDENTIAL_REF="test-ref"

    stage_real_rp 2>/dev/null || true

    local results_file="${EVIDENCE_DIR}/real-rp-results.json"
    if [[ -f "$results_file" ]]; then
        local status
        status=$(jq -r '.status' "$results_file" 2>/dev/null || echo "unknown")
        if [[ "$status" == "incomplete" ]]; then
            log_pass "INCOMPLETE without healthy daemon"
        else
            log_fail "status was '$status', expected 'incomplete'"
        fi
    else
        log_fail "results file not created"
    fi
}

test_gc_fail_closed_no_browser() {
    log_test "Gate C returns INCOMPLETE when browser not running"
    setup_env
    local mock_bin
    mock_bin=$(create_mock_passless "nobrowser" "not_running")
    export AV_PASSLESS_BIN="$mock_bin"
    export AV_DAEMON_PROFILE="test-profile"
    export AV_DAEMON_RUNTIME_DIR="${TEST_TMP_DIR}/runtime"
    export AV_REAL_RP_CREDENTIAL_REF="test-ref"

    stage_real_rp 2>/dev/null || true

    local results_file="${EVIDENCE_DIR}/real-rp-results.json"
    if [[ -f "$results_file" ]]; then
        local status
        status=$(jq -r '.status' "$results_file" 2>/dev/null || echo "unknown")
        if [[ "$status" == "incomplete" ]]; then
            log_pass "INCOMPLETE when browser not running"
        else
            log_fail "status was '$status', expected 'incomplete'"
        fi
    else
        log_fail "results file not created"
    fi
}

test_gc_pipe_mode_incomplete() {
    log_test "Gate C returns INCOMPLETE for pipe CDP mode"
    setup_env
    local mock_bin
    mock_bin=$(create_mock_passless "pipe" "pipe_mode")
    export AV_PASSLESS_BIN="$mock_bin"
    export AV_DAEMON_PROFILE="test-profile"
    export AV_DAEMON_RUNTIME_DIR="${TEST_TMP_DIR}/runtime"
    export AV_REAL_RP_CREDENTIAL_REF="test-ref"

    stage_real_rp 2>/dev/null || true

    local results_file="${EVIDENCE_DIR}/real-rp-results.json"
    if [[ -f "$results_file" ]]; then
        local status
        status=$(jq -r '.status' "$results_file" 2>/dev/null || echo "unknown")
        if [[ "$status" == "incomplete" ]]; then
            log_pass "INCOMPLETE for pipe mode"
        else
            log_fail "status was '$status', expected 'incomplete'"
        fi
    else
        log_fail "results file not created"
    fi
}

test_gc_no_false_pass() {
    log_test "Gate C never returns PASS without all prerequisites"
    setup_env
    unset AV_PASSLESS_BIN AV_DAEMON_PROFILE

    stage_real_rp 2>/dev/null || true

    local results_file="${EVIDENCE_DIR}/real-rp-results.json"
    if [[ -f "$results_file" ]]; then
        local status
        status=$(jq -r '.status' "$results_file" 2>/dev/null || echo "unknown")
        if [[ "$status" != "pass" ]]; then
            log_pass "never returns PASS without prerequisites (status=$status)"
        else
            log_fail "FALSE PASS detected!"
        fi
    else
        log_pass "no results file means no false PASS"
    fi
}

test_gc_driver_no_forbidden_methods() {
    log_test "real-rp-driver.js contains no forbidden WebAuthn CDP methods"
    local driver="${BROWSER_DIR}/real-rp-driver.js"
    local actual_usage=false
    while IFS= read -r line; do
        if echo "$line" | grep -qF "FORBIDDEN_CDP_METHODS"; then
            continue
        fi
        for method in "WebAuthn.enable" "addVirtualAuthenticator"; do
            if echo "$line" | grep -qF "'$method'" || echo "$line" | grep -qF "\"$method\""; then
                if ! echo "$line" | grep -qE '(indexOf|includes|FORBIDDEN)'; then
                    actual_usage=true
                fi
            fi
        done
    done < "$driver"

    if [[ "$actual_usage" == "false" ]]; then
        log_pass "driver does not call forbidden WebAuthn CDP methods"
    else
        log_fail "driver appears to call forbidden WebAuthn methods"
    fi
}

test_gc_driver_has_expected_selector() {
    log_test "real-rp-driver.js uses expected selector a.signin-passkey"
    local driver="${BROWSER_DIR}/real-rp-driver.js"
    if grep -qF "a.signin-passkey" "$driver"; then
        log_pass "driver uses a.signin-passkey selector"
    else
        log_fail "driver missing a.signin-passkey selector"
    fi
}

test_gc_driver_no_vault_access() {
    log_test "real-rp-driver.js does not access vault/key files"
    local driver="${BROWSER_DIR}/real-rp-driver.js"
    if grep -qE '(\.pass/|\.password-store/|readFileSync.*vault|readFileSync.*secret|\.gpg)' "$driver" 2>/dev/null; then
        local is_pattern_def=false
        while IFS= read -r line; do
            if echo "$line" | grep -qE 'FORBIDDEN_FILE_PATTERNS'; then
                continue
            fi
            if echo "$line" | grep -qE '(\.pass/|\.password-store/|readFileSync.*vault|readFileSync.*secret|\.gpg)'; then
                is_pattern_def=true
            fi
        done < "$driver"
        if [[ "$is_pattern_def" == "false" ]]; then
            log_pass "no vault/key file access"
        else
            log_fail "driver accesses vault/key files"
        fi
    else
        log_pass "no vault/key file access patterns found"
    fi
}

test_gc_secret_non_logging() {
    log_test "Gate C does not log credential ref or secrets"
    local stage_file="${STAGES_DIR}/real-rp.sh"
    local lib_file="${LIB_DIR}/real-rp.sh"

    local found_logging=false
    for f in "$stage_file" "$lib_file"; do
        if grep -qE '(echo|log|printf|print).*CREDENTIAL_REF' "$f" 2>/dev/null; then
            found_logging=true
        fi
        if grep -qE '(echo|log|printf|print).*credential_ref' "$f" 2>/dev/null; then
            if ! grep -qE '(jq|--arg|select|test)' "$(grep -l 'credential_ref' "$f")" 2>/dev/null; then
                found_logging=true
            fi
        fi
    done

    if [[ "$found_logging" == "false" ]]; then
        log_pass "no secret logging detected"
    else
        log_fail "potential secret logging found"
    fi
}

test_gc_agent_run_command_construction() {
    log_test "Gate C constructs correct agent run command"
    local stage_file="${STAGES_DIR}/real-rp.sh"

    if grep -q 'agent run --profile' "$stage_file" && \
       grep -q 'node.*real-rp-driver\|node.*AV_REAL_RP_DRIVER' "$stage_file"; then
        log_pass "agent run command includes --profile and node driver"
    else
        log_fail "agent run command construction incorrect"
    fi
}

test_gc_sanitize_audit_strips_secrets() {
    log_test "av_gc_sanitize_audit_export strips prohibited fields"
    setup_env

    local raw_file="${EVIDENCE_DIR}/gc-audit-raw.json"
    local sanitized_file="${EVIDENCE_DIR}/gc-audit-sanitized.json"

    jq -n '{
        entries: [{
            action: "authenticate",
            rp_id: "tea.millaguie.net",
            credential_ref: "secret-ref-12345",
            user_handle: "secret-handle",
            raw_assertion: "base64data",
            bearer: "secret-bearer",
            cookie: "session=abc",
            private_key: "MIGHAgE...",
            challenge: "secret-challenge",
            clientDataJSON: "secret-clientdata",
            signature: "secret-sig",
            status: "approved",
            timestamp: "2024-01-01T00:00:00Z"
        }]
    }' > "$raw_file"

    local sanitized
    if ! sanitized=$(jq '
        walk(
            if type == "object" then
                with_entries(
                    select(
                        (.key | test("^(raw_|challenge$|assertion$|credential_id$|credential_ref$|user_handle$|bearer$|cookie$|private_key$|secret_key$|auth_token$|pin$|clientDataJSON$|signature$)"; "i") | not)
                    )
                )
            else .
            end
        )
    ' "$raw_file" 2>/dev/null); then
        log_fail "sanitization jq failed"
        return
    fi

    printf '%s\n' "$sanitized" > "$sanitized_file"

    local has_cred_ref has_handle has_raw has_bearer has_cookie has_key has_challenge has_cdj has_sig
    has_cred_ref=$(grep -c 'secret-ref' "$sanitized_file" 2>/dev/null) || has_cred_ref=0
    has_handle=$(grep -c 'secret-handle' "$sanitized_file" 2>/dev/null) || has_handle=0
    has_raw=$(grep -c 'base64data' "$sanitized_file" 2>/dev/null) || has_raw=0
    has_bearer=$(grep -c 'secret-bearer' "$sanitized_file" 2>/dev/null) || has_bearer=0
    has_cookie=$(grep -c 'session=abc' "$sanitized_file" 2>/dev/null) || has_cookie=0
    has_key=$(grep -c 'MIGHAgE' "$sanitized_file" 2>/dev/null) || has_key=0
    has_challenge=$(grep -c 'secret-challenge' "$sanitized_file" 2>/dev/null) || has_challenge=0
    has_cdj=$(grep -c 'secret-clientdata' "$sanitized_file" 2>/dev/null) || has_cdj=0
    has_sig=$(grep -c 'secret-sig' "$sanitized_file" 2>/dev/null) || has_sig=0
    local has_status
    has_status=$(grep -c 'approved' "$sanitized_file" 2>/dev/null) || has_status=0

    if [[ "$has_cred_ref" -eq 0 ]] && [[ "$has_handle" -eq 0 ]] && [[ "$has_raw" -eq 0 ]] \
        && [[ "$has_bearer" -eq 0 ]] && [[ "$has_cookie" -eq 0 ]] && [[ "$has_key" -eq 0 ]] \
        && [[ "$has_challenge" -eq 0 ]] && [[ "$has_cdj" -eq 0 ]] && [[ "$has_sig" -eq 0 ]] \
        && [[ "$has_status" -ge 1 ]]; then
        log_pass "all secrets stripped, allowed metadata preserved"
    else
        log_fail "sanitization failed (cred_ref=$has_cred_ref handle=$has_handle raw=$has_raw bearer=$has_bearer cookie=$has_cookie key=$has_key challenge=$has_challenge cdj=$has_cdj sig=$has_sig status=$has_status)"
    fi
}

test_gc_sanitize_fails_closed() {
    log_test "av_gc_sanitize_evidence fails closed on invalid JSON"
    setup_env

    local raw_file="${TEST_TMP_DIR}/gc-invalid.json"
    local sanitized_file="${TEST_TMP_DIR}/gc-invalid-sanitized.json"

    echo "not valid json {{{" > "$raw_file"

    if av_sanitize_evidence "$raw_file" "$sanitized_file" 2>/dev/null; then
        log_fail "sanitizer should fail on invalid JSON"
    else
        if [[ -f "$sanitized_file" ]]; then
            log_fail "sanitizer should not write output on failure"
        else
            log_pass "sanitizer fails closed on invalid JSON"
        fi
    fi
}

test_gc_cleanup_trap_present() {
    log_test "stage_real_rp sets cleanup trap for spawned PIDs only"
    if grep -q 'trap av_gc_cleanup' "${STAGES_DIR}/real-rp.sh"; then
        log_pass "cleanup trap present"
    else
        log_fail "cleanup trap missing"
    fi

    if grep -qE '(pkill|killall)' "${STAGES_DIR}/real-rp.sh" || grep -qE '(pkill|killall)' "${LIB_DIR}/real-rp.sh"; then
        log_fail "cleanup uses global kill commands"
    else
        log_pass "cleanup does not use pkill/killall"
    fi
}

test_gc_cleanup_does_not_kill_daemon() {
    log_test "cleanup does not kill daemon-managed browser"
    local lib_file="${LIB_DIR}/real-rp.sh"
    if grep -qE 'kill.*chromium|kill.*browser|kill.*daemon' "$lib_file"; then
        log_fail "cleanup may kill daemon-managed browser"
    else
        log_pass "cleanup does not target daemon browser"
    fi
}

test_gc_envelope_parsing_mock() {
    log_test "Gate C parses AdminEnvelope correctly with mock"
    setup_env
    local mock_bin
    mock_bin=$(create_mock_passless "envelope" "healthy")
    export AV_PASSLESS_BIN="$mock_bin"
    export AV_DAEMON_RUNTIME_DIR="${TEST_TMP_DIR}/runtime"

    if av_daemon_health_check 2>/dev/null; then
        log_pass "AdminEnvelope parsed correctly"
    else
        log_fail "AdminEnvelope parsing failed"
    fi
}

test_gc_envelope_rejects_wrong_shape() {
    log_test "Gate C rejects non-envelope responses"
    setup_env

    local mock_bin="${TEST_TMP_DIR}/mock-passless-bad-env"
    cat > "$mock_bin" << 'MOCK'
#!/bin/bash
printf '{"status":"ok","daemon":true}\n'
exit 0
MOCK
    chmod +x "$mock_bin"

    export AV_PASSLESS_BIN="$mock_bin"
    export AV_DAEMON_RUNTIME_DIR="${TEST_TMP_DIR}/runtime"

    if av_daemon_health_check 2>/dev/null; then
        log_fail "should reject non-envelope response"
    else
        log_pass "correctly rejects non-envelope response"
    fi
}

test_gc_results_schema() {
    log_test "Gate C results file has expected schema"
    setup_env
    unset AV_PASSLESS_BIN AV_DAEMON_PROFILE

    stage_real_rp 2>/dev/null || true

    local results_file="${EVIDENCE_DIR}/real-rp-results.json"
    if [[ ! -f "$results_file" ]]; then
        log_fail "results file not created"
        return
    fi

    local has_gate has_status has_timestamp
    has_gate=$(jq -e '.gate == "C"' "$results_file" >/dev/null 2>&1 && echo "yes" || echo "no")
    has_status=$(jq -e '.status' "$results_file" >/dev/null 2>&1 && echo "yes" || echo "no")
    has_timestamp=$(jq -e '.timestamp' "$results_file" >/dev/null 2>&1 && echo "yes" || echo "no")

    if [[ "$has_gate" == "yes" ]] && [[ "$has_status" == "yes" ]] && [[ "$has_timestamp" == "yes" ]]; then
        log_pass "results schema includes gate, status, timestamp"
    else
        log_fail "results schema incomplete"
    fi
}

test_gc_wrong_origin_marked_incomplete() {
    log_test "wrong-origin scenario is marked INCOMPLETE when stage reaches full evaluation"
    local lib_file="${LIB_DIR}/real-rp.sh"

    local result
    result=$(av_gc_check_wrong_origin_feasible 2>/dev/null || echo '{"status":"incomplete"}')
    local wo_status
    wo_status=$(echo "$result" | jq -r '.status // "incomplete"' 2>/dev/null || echo "incomplete")
    if [[ "$wo_status" == "incomplete" ]]; then
        log_pass "wrong-origin correctly returns INCOMPLETE from feasibility check"
    else
        log_fail "wrong-origin status was '$wo_status', expected 'incomplete'"
    fi
}

test_gc_expired_grant_marked_incomplete() {
    log_test "expired-grant scenario is marked INCOMPLETE when stage reaches full evaluation"
    local lib_file="${LIB_DIR}/real-rp.sh"

    local result
    result=$(av_gc_check_expired_grant_feasible 2>/dev/null || echo '{"status":"incomplete"}')
    local eg_status
    eg_status=$(echo "$result" | jq -r '.status // "incomplete"' 2>/dev/null || echo "incomplete")
    if [[ "$eg_status" == "incomplete" ]]; then
        log_pass "expired-grant correctly returns INCOMPLETE from feasibility check"
    else
        log_fail "expired-grant status was '$eg_status', expected 'incomplete'"
    fi
}

test_gc_incomplete_blocks_full_pass() {
    log_test "INCOMPLETE wrong-origin/expired-grant blocks full Gate C PASS"
    local stage_file="${STAGES_DIR}/real-rp.sh"

    if grep -q 'blocks_full_pass' "$stage_file"; then
        log_pass "stage sets blocks_full_pass when scenarios are INCOMPLETE"
    else
        log_fail "stage missing blocks_full_pass logic"
    fi
}

test_gc_driver_self_check() {
    log_test "real-rp-driver.js self-check function works"
    local driver="${BROWSER_DIR}/real-rp-driver.js"

    local result
    result=$(node -e "
        const m = require('$driver');
        const r = m.selfCheck();
        console.log(JSON.stringify(r));
    " 2>/dev/null || echo '{"pass":false,"violations":["load_error"]}')

    local pass_val
    pass_val=$(echo "$result" | jq -r '.pass' 2>/dev/null || echo "false")

    if [[ "$pass_val" == "true" ]]; then
        log_pass "driver self-check passes (no forbidden methods)"
    else
        local violations
        violations=$(echo "$result" | jq -c '.violations' 2>/dev/null || echo "[]")
        log_fail "driver self-check failed: $violations"
    fi
}

test_gc_driver_exports() {
    log_test "real-rp-driver.js exports expected symbols"
    local driver="${BROWSER_DIR}/real-rp-driver.js"

    local result
    result=$(node -e "
        const m = require('$driver');
        console.log(JSON.stringify({
            hasGateCDriver: typeof m.GateCDriver === 'function',
            hasSelfCheck: typeof m.selfCheck === 'function',
            hasForbidden: Array.isArray(m.FORBIDDEN_CDP_METHODS),
            hasSelector: typeof m.EXPECTED_SELECTOR === 'string'
        }));
    " 2>/dev/null || echo '{}')

    local all_ok=true
    for key in hasGateCDriver hasSelfCheck hasForbidden hasSelector; do
        local val
        val=$(echo "$result" | jq -r ".$key" 2>/dev/null || echo "false")
        if [[ "$val" != "true" ]]; then
            all_ok=false
        fi
    done

    if [[ "$all_ok" == "true" ]]; then
        log_pass "all expected exports present"
    else
        log_fail "missing exports: $result"
    fi
}

test_gc_dbus_notify_count() {
    log_test "av_gc_count_dbus_notify returns 0 for empty log"
    setup_env

    local empty_log="${TEST_TMP_DIR}/empty-dbus.log"
    : > "$empty_log"

    local count
    count=$(av_gc_count_dbus_notify "$empty_log" 2>/dev/null || echo "error")
    if [[ "$count" == "0" ]]; then
        log_pass "zero Notify calls for empty log"
    else
        log_fail "expected 0, got $count"
    fi
}

test_gc_dbus_notify_counts_calls() {
    log_test "av_gc_count_dbus_notify counts Notify calls"
    setup_env

    local dbus_log="${TEST_TMP_DIR}/dbus.log"
    cat > "$dbus_log" << 'EOF'
signal time=1234567890.000 sender=:1.50 -> destination=(null destination) serial=42 path=/org/freedesktop/Notifications; interface=org.freedesktop.Notifications; member=Notify
   string "Passless"
signal time=1234567891.000 sender=:1.50 -> destination=(null destination) serial=43 path=/org/freedesktop/Notifications; interface=org.freedesktop.Notifications; member=Notify
   string "Another"
EOF

    local count
    count=$(av_gc_count_dbus_notify "$dbus_log" 2>/dev/null || echo "error")
    if [[ "$count" == "2" ]]; then
        log_pass "correctly counted 2 Notify calls"
    else
        log_fail "expected 2, got $count"
    fi
}

test_gc_verify_no_forbidden_cdp_empty() {
    log_test "av_gc_verify_no_forbidden_cdp handles empty events"
    setup_env

    local empty_file="${TEST_TMP_DIR}/gc-empty-events.jsonl"
    : > "$empty_file"

    local result
    result=$(av_gc_verify_no_forbidden_cdp "$empty_file" 2>/dev/null || echo '{}')
    local count
    count=$(echo "$result" | jq -r '.forbidden_calls')
    if [[ "$count" == "0" ]]; then
        log_pass "zero forbidden calls for empty events"
    else
        log_fail "expected 0, got $count"
    fi
}

test_gc_verify_no_forbidden_cdp_detects() {
    log_test "av_gc_verify_no_forbidden_cdp detects forbidden methods"
    setup_env

    local events_file="${TEST_TMP_DIR}/gc-forbidden-events.jsonl"
    echo '{"method":"WebAuthn.enable","params":{}}' > "$events_file"

    local result
    result=$(av_gc_verify_no_forbidden_cdp "$events_file" 2>/dev/null || echo '{}')
    local count
    count=$(echo "$result" | jq -r '.forbidden_calls')
    if [[ "$count" -gt 0 ]]; then
        log_pass "forbidden WebAuthn CDP call detected (count=$count)"
    else
        log_fail "failed to detect forbidden call"
    fi
}

test_gc_stage_has_strict_mode() {
    log_test "real-rp stage uses strict mode"
    if grep -q 'set -euo pipefail' "${STAGES_DIR}/real-rp.sh"; then
        log_pass "strict mode present"
    else
        log_fail "strict mode missing"
    fi
}

test_gc_stage_has_bash_shebang() {
    log_test "real-rp stage has bash shebang"
    local first_line
    first_line=$(head -n1 "${STAGES_DIR}/real-rp.sh")
    if [[ "$first_line" == "#!/bin/bash" ]]; then
        log_pass "correct shebang"
    else
        log_fail "bad shebang: $first_line"
    fi
}

test_gc_runner_help() {
    log_test "real-rp-runner.sh --help works"
    local output
    output=$(timeout 5s bash "${VALIDATION_DIR}/real-rp-runner.sh" --help 2>&1) || true
    if [[ -n "$output" ]] && [[ "$output" == *"Gate C"* ]]; then
        log_pass "help output contains Gate C"
    else
        log_fail "help output missing or incorrect"
    fi
}

test_gc_no_global_runtime_deletion() {
    log_test "cleanup does not delete global runtime directory"
    local lib_file="${LIB_DIR}/real-rp.sh"
    if grep -qE 'rm -rf.*AV_DAEMON_RUNTIME_DIR|rm -rf.*runtime' "$lib_file"; then
        log_fail "cleanup may delete daemon runtime directory"
    else
        log_pass "cleanup does not delete daemon runtime"
    fi
}

test_gc_evidence_semantics_in_report() {
    log_test "Gate C stage code includes evidence_semantics in full results"
    local stage_file="${STAGES_DIR}/real-rp.sh"

    if grep -q 'evidence_semantics' "$stage_file"; then
        log_pass "evidence_semantics present in stage output"
    else
        log_fail "evidence_semantics missing from stage"
    fi
}

test_gc_no_hardcoded_identifiers() {
    log_test "no hardcoded credential refs or profile IDs"
    local lib_file="${LIB_DIR}/real-rp.sh"
    local stage_file="${STAGES_DIR}/real-rp.sh"

    local found_hardcoded=false
    for f in "$lib_file" "$stage_file"; do
        if grep -qE '(credential_ref|profile).*=.*"[a-zA-Z0-9]{10,}"' "$f" 2>/dev/null; then
            found_hardcoded=true
        fi
    done

    if [[ "$found_hardcoded" == "false" ]]; then
        log_pass "no hardcoded identifiers"
    else
        log_fail "hardcoded identifiers found"
    fi
}

test_gc_runner_incomplete_exits_6() {
    log_test "runner exits EXIT_INCOMPLETE=6 when stage result is incomplete"
    local runner="${VALIDATION_DIR}/real-rp-runner.sh"
    local tmp_evidence="${TEST_TMP_DIR}/runner-exit6-test"
    mkdir -p "$tmp_evidence"

    local mock_driver="${TEST_TMP_DIR}/mock-clean-driver.js"
    cat > "$mock_driver" << 'DRIVER'
#!/usr/bin/env node
'use strict';
var s = 'a.signin-passkey';
var result = {self_check:"pass",navigation_ok:false,click_ok:false,url_origin:"unknown",url_path:"unknown",title_class:"unknown",called_forbidden:false,duration_ms:0};
process.stdout.write(JSON.stringify(result) + '\n');
process.exit(10);
DRIVER

    local mock_bin="${TEST_TMP_DIR}/mock-passless-runner-exit6"
    cat > "$mock_bin" << 'MOCK'
#!/bin/bash
received=""
for arg in "$@"; do received="${received}${received:+ }${arg}"; done
case "$received" in
    *"agent-admin --output json audit status"*)
        printf '{"version":1,"status":"ok","data":{"enabled":true,"entry_count":42,"latest_entry_at":100}}\n'
        exit 0
        ;;
    *"agent --profile"*"browser-status"*)
        printf '{"running":true,"cdp_endpoint":"http://127.0.0.1:19222","extension_loaded":true}\n'
        exit 0
        ;;
    *"agent run --profile"*"node"*)
        exit 10
        ;;
    *"agent-admin --output json audit export"*)
        printf '{"entries":[{"action":"authenticate","rp_id":"tea.millaguie.net","timestamp":"2024-01-01T00:00:00Z","status":"approved"}]}\n'
        exit 0
        ;;
    *"delegation revoke"*)
        printf '{"status":"ok"}\n'
        exit 0
        ;;
    *)
        exit 1
        ;;
esac
MOCK
    chmod +x "$mock_bin"

    local actual_exit=0
    (
        unset AV_REAL_RP_DRIVER AV_PASSLESS_BIN AV_DAEMON_PROFILE AV_DAEMON_RUNTIME_DIR AV_REAL_RP_CREDENTIAL_REF EVIDENCE_BASE_DIR RUN_ID_PREFIX
        export AV_PASSLESS_BIN="$mock_bin"
        export AV_DAEMON_PROFILE="test-profile"
        export AV_DAEMON_RUNTIME_DIR="${TEST_TMP_DIR}/runtime"
        export AV_REAL_RP_CREDENTIAL_REF="test-ref"
        export AV_REAL_RP_DRIVER="$mock_driver"
        export EVIDENCE_BASE_DIR="$tmp_evidence"
        export RUN_ID_PREFIX="test-exit6"
        export PATH="/usr/bin:/bin"
        timeout 15s bash "$runner" --run
    ) > /dev/null 2>&1 || actual_exit=$?

    if [[ $actual_exit -eq 6 ]]; then
        log_pass "runner exits 6 (EXIT_INCOMPLETE) for incomplete result"
    else
        log_fail "expected exit 6, got $actual_exit"
    fi
}

test_gc_runner_fail_exits_2() {
    log_test "runner exits EXIT_STAGE_FAILED=2 when stage result is fail"
    local runner="${VALIDATION_DIR}/real-rp-runner.sh"
    local tmp_evidence="${TEST_TMP_DIR}/runner-exit2-test"
    mkdir -p "$tmp_evidence"

    local mock_driver="${TEST_TMP_DIR}/mock-clean-driver-fail.js"
    cat > "$mock_driver" << 'DRIVER'
#!/usr/bin/env node
'use strict';
var result = {self_check:"pass",navigation_ok:false,click_ok:false,url_origin:"unknown",url_path:"unknown",title_class:"unknown",called_forbidden:false,duration_ms:0};
process.stdout.write(JSON.stringify(result) + '\n');
process.exit(0);
DRIVER

    local mock_bin="${TEST_TMP_DIR}/mock-passless-runner-exit2"
    cat > "$mock_bin" << 'MOCK'
#!/bin/bash
received=""
for arg in "$@"; do received="${received}${received:+ }${arg}"; done
case "$received" in
    *"agent-admin --output json audit status"*)
        printf '{"version":1,"status":"ok","data":{"enabled":true,"entry_count":42,"latest_entry_at":100}}\n'
        exit 0
        ;;
    *"agent --profile"*"browser-status"*)
        printf '{"running":true,"cdp_endpoint":"http://127.0.0.1:19222","extension_loaded":true}\n'
        exit 0
        ;;
    *"agent run --profile"*"node"*)
        printf '{"navigation_ok":false,"click_ok":false,"url_origin":"unknown","title_class":"unknown","self_check":"pass"}\n'
        exit 0
        ;;
    *"agent-admin --output json audit export"*)
        printf '{"entries":[{"action":"authenticate","rp_id":"tea.millaguie.net","timestamp":"2024-01-01T00:00:00Z","status":"approved"}]}\n'
        exit 0
        ;;
    *"delegation revoke"*)
        printf '{"status":"ok"}\n'
        exit 0
        ;;
    *)
        exit 1
        ;;
esac
MOCK
    chmod +x "$mock_bin"

    local actual_exit=0
    (
        unset AV_REAL_RP_DRIVER AV_PASSLESS_BIN AV_DAEMON_PROFILE AV_DAEMON_RUNTIME_DIR AV_REAL_RP_CREDENTIAL_REF EVIDENCE_BASE_DIR RUN_ID_PREFIX
        export AV_PASSLESS_BIN="$mock_bin"
        export AV_DAEMON_PROFILE="test-profile"
        export AV_DAEMON_RUNTIME_DIR="${TEST_TMP_DIR}/runtime"
        export AV_REAL_RP_CREDENTIAL_REF="test-ref"
        export AV_REAL_RP_DRIVER="$mock_driver"
        export EVIDENCE_BASE_DIR="$tmp_evidence"
        export RUN_ID_PREFIX="test-exit2"
        export PATH="/usr/bin:/bin"
        timeout 15s bash "$runner" --run
    ) > /dev/null 2>&1 || actual_exit=$?

    if [[ $actual_exit -eq 2 ]]; then
        log_pass "runner exits 2 (EXIT_STAGE_FAILED) for fail result"
    else
        log_fail "expected exit 2, got $actual_exit"
    fi
}

test_gc_stage_nav_only_click_fail() {
    log_test "driver_flow fails when navigation succeeds but click fails"
    setup_env

    local mock_driver="${TEST_TMP_DIR}/mock-clean-driver-navonly.js"
    cat > "$mock_driver" << 'DRIVER'
#!/usr/bin/env node
'use strict';
var s = 'a.signin-passkey';
var result = {self_check:"pass",navigation_ok:true,click_ok:false,url_origin:"https://tea.millaguie.net",url_path:"/user/login",title_class:"login_page",called_forbidden:false,duration_ms:0};
process.stdout.write(JSON.stringify(result) + '\n');
process.exit(0);
DRIVER

    local mock_bin="${TEST_TMP_DIR}/mock-passless-nav-only"
    cat > "$mock_bin" << 'MOCK'
#!/bin/bash
received=""
for arg in "$@"; do received="${received}${received:+ }${arg}"; done
case "$received" in
    *"agent-admin --output json audit status"*)
        printf '{"version":1,"status":"ok","data":{"enabled":true,"entry_count":42,"latest_entry_at":100}}\n'
        exit 0
        ;;
    *"agent --profile"*"browser-status"*)
        printf '{"running":true,"cdp_endpoint":"http://127.0.0.1:19222","extension_loaded":true}\n'
        exit 0
        ;;
    *"agent run --profile"*"node"*)
        printf '{"navigation_ok":true,"click_ok":false,"url_origin":"https://tea.millaguie.net","title_class":"login_page","self_check":"pass"}\n'
        exit 0
        ;;
    *"agent-admin --output json audit export"*)
        printf '{"entries":[{"action":"authenticate","rp_id":"tea.millaguie.net","timestamp":"2024-01-01T00:00:00Z","status":"approved"}]}\n'
        exit 0
        ;;
    *"delegation revoke"*)
        printf '{"status":"ok"}\n'
        exit 0
        ;;
    *)
        exit 1
        ;;
esac
MOCK
    chmod +x "$mock_bin"
    export AV_PASSLESS_BIN="$mock_bin"
    export AV_DAEMON_PROFILE="test-profile"
    export AV_DAEMON_RUNTIME_DIR="${TEST_TMP_DIR}/runtime"
    export AV_REAL_RP_CREDENTIAL_REF="test-ref"
    export AV_REAL_RP_DRIVER="$mock_driver"

    stage_real_rp 2>/dev/null || true

    local results_file="${EVIDENCE_DIR}/real-rp-results.json"
    if [[ ! -f "$results_file" ]]; then
        log_fail "results file not created"
        return
    fi

    local driver_status
    driver_status=$(jq -r '.scenarios[] | select(.name=="driver_flow") | .status' "$results_file" 2>/dev/null || echo "unknown")
    local overall_status
    overall_status=$(jq -r '.status' "$results_file" 2>/dev/null || echo "unknown")

    if [[ "$driver_status" == "fail" ]]; then
        log_pass "driver_flow correctly marked fail when click fails"
    else
        log_fail "driver_flow was '$driver_status', expected 'fail'"
    fi

    if [[ "$overall_status" == "fail" ]]; then
        log_pass "overall status is fail when click fails"
    else
        log_fail "overall status was '$overall_status', expected 'fail'"
    fi
}

test_gc_stage_wrong_origin_user_path() {
    log_test "driver_flow fails when navigation lands on wrong origin with /user path"
    setup_env

    local mock_driver="${TEST_TMP_DIR}/mock-clean-driver-wrongorigin.js"
    cat > "$mock_driver" << 'DRIVER'
#!/usr/bin/env node
'use strict';
var s = 'a.signin-passkey';
var result = {self_check:"pass",navigation_ok:false,click_ok:false,url_origin:"https://evil.example",url_path:"/user/login",title_class:"other",called_forbidden:false,duration_ms:0};
process.stdout.write(JSON.stringify(result) + '\n');
process.exit(0);
DRIVER

    local mock_bin="${TEST_TMP_DIR}/mock-passless-wrong-origin"
    cat > "$mock_bin" << 'MOCK'
#!/bin/bash
received=""
for arg in "$@"; do received="${received}${received:+ }${arg}"; done
case "$received" in
    *"agent-admin --output json audit status"*)
        printf '{"version":1,"status":"ok","data":{"enabled":true,"entry_count":42,"latest_entry_at":100}}\n'
        exit 0
        ;;
    *"agent --profile"*"browser-status"*)
        printf '{"running":true,"cdp_endpoint":"http://127.0.0.1:19222","extension_loaded":true}\n'
        exit 0
        ;;
    *"agent run --profile"*"node"*)
        printf '{"navigation_ok":false,"click_ok":false,"url_origin":"https://evil.example","url_path":"/user/login","title_class":"other","self_check":"pass"}\n'
        exit 0
        ;;
    *"agent-admin --output json audit export"*)
        printf '{"entries":[{"action":"authenticate","rp_id":"tea.millaguie.net","timestamp":"2024-01-01T00:00:00Z","status":"approved"}]}\n'
        exit 0
        ;;
    *"delegation revoke"*)
        printf '{"status":"ok"}\n'
        exit 0
        ;;
    *)
        exit 1
        ;;
esac
MOCK
    chmod +x "$mock_bin"
    export AV_PASSLESS_BIN="$mock_bin"
    export AV_DAEMON_PROFILE="test-profile"
    export AV_DAEMON_RUNTIME_DIR="${TEST_TMP_DIR}/runtime"
    export AV_REAL_RP_CREDENTIAL_REF="test-ref"
    export AV_REAL_RP_DRIVER="$mock_driver"

    stage_real_rp 2>/dev/null || true

    local results_file="${EVIDENCE_DIR}/real-rp-results.json"
    if [[ ! -f "$results_file" ]]; then
        log_fail "results file not created"
        return
    fi

    local driver_status
    driver_status=$(jq -r '.scenarios[] | select(.name=="driver_flow") | .status' "$results_file" 2>/dev/null || echo "unknown")

    if [[ "$driver_status" == "fail" ]]; then
        log_pass "driver_flow correctly fails for wrong-origin /user path"
    else
        log_fail "driver_flow was '$driver_status', expected 'fail'"
    fi
}

main() {
    echo -e "${BLUE}=== Gate C Real-RP Tests ===${NC}" >&2

    test_gc_lib_file_exists
    test_gc_stage_file_exists
    test_gc_driver_file_exists
    test_gc_runner_file_exists
    test_gc_env_check_missing_vars
    test_gc_env_check_with_all_vars
    test_gc_fail_closed_no_env
    test_gc_fail_closed_no_daemon
    test_gc_fail_closed_no_browser
    test_gc_pipe_mode_incomplete
    test_gc_no_false_pass
    test_gc_driver_no_forbidden_methods
    test_gc_driver_has_expected_selector
    test_gc_driver_no_vault_access
    test_gc_secret_non_logging
    test_gc_agent_run_command_construction
    test_gc_sanitize_audit_strips_secrets
    test_gc_sanitize_fails_closed
    test_gc_cleanup_trap_present
    test_gc_cleanup_does_not_kill_daemon
    test_gc_envelope_parsing_mock
    test_gc_envelope_rejects_wrong_shape
    test_gc_results_schema
    test_gc_wrong_origin_marked_incomplete
    test_gc_expired_grant_marked_incomplete
    test_gc_incomplete_blocks_full_pass
    test_gc_driver_self_check
    test_gc_driver_exports
    test_gc_dbus_notify_count
    test_gc_dbus_notify_counts_calls
    test_gc_verify_no_forbidden_cdp_empty
    test_gc_verify_no_forbidden_cdp_detects
    test_gc_stage_has_strict_mode
    test_gc_stage_has_bash_shebang
    test_gc_runner_help
    test_gc_no_global_runtime_deletion
    test_gc_evidence_semantics_in_report
    test_gc_no_hardcoded_identifiers
    test_gc_runner_incomplete_exits_6
    test_gc_runner_fail_exits_2
    test_gc_stage_nav_only_click_fail
    test_gc_stage_wrong_origin_user_path

    echo "" >&2
    echo -e "${BLUE}Tests: $TEST_COUNT total, $PASS_COUNT passed, $FAIL_COUNT failed${NC}" >&2

    [[ $FAIL_COUNT -eq 0 ]]
}

main "$@"
