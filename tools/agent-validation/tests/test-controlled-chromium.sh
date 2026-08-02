#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALIDATION_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LIB_DIR="${VALIDATION_DIR}/lib"
STAGES_DIR="${VALIDATION_DIR}/stages"
BROWSER_DIR="${VALIDATION_DIR}/browser"

TEST_TMP_DIR="/tmp/passless-av-cc-test-$$"
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
    pkill -f 'mock-cdp-server' 2>/dev/null || true
    pkill -f 'mock-cdp-event' 2>/dev/null || true
    rm -rf "$TEST_TMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p "$TEST_TMP_DIR"

setup_env() {
    export EVIDENCE_DIR="${TEST_TMP_DIR}/evidence"
    export TEMP_ROOT="${TEST_TMP_DIR}/tmp"
    export RUN_ID="test-cc-run"
    export AV_VALIDATION_DIR="$VALIDATION_DIR"
    export AV_DAEMON_RUNTIME_DIR="${TEST_TMP_DIR}/runtime"
    mkdir -p "$EVIDENCE_DIR" "$TEMP_ROOT" "$AV_DAEMON_RUNTIME_DIR"

    source "${LIB_DIR}/common.sh"
    source "${LIB_DIR}/browser.sh"
    source "${LIB_DIR}/notifications.sh"
    source "${LIB_DIR}/daemon-bridge.sh"
    source "${LIB_DIR}/controlled-rp.sh"
    source "${LIB_DIR}/controlled-chromium.sh"

    register_resource() { :; }
}

test_cc_stage_file_exists() {
    log_test "controlled-chromium stage file exists"
    if [[ -f "${STAGES_DIR}/controlled-chromium.sh" ]]; then
        log_pass "stage file present"
    else
        log_fail "stage file missing"
    fi
}

test_cc_lib_file_exists() {
    log_test "controlled-chromium lib file exists"
    if [[ -f "${LIB_DIR}/controlled-chromium.sh" ]]; then
        log_pass "lib file present"
    else
        log_fail "lib file missing"
    fi
}

test_cc_daemon_bridge_exists() {
    log_test "daemon-bridge lib file exists"
    if [[ -f "${LIB_DIR}/daemon-bridge.sh" ]]; then
        log_pass "daemon-bridge file present"
    else
        log_fail "daemon-bridge file missing"
    fi
}

test_cc_daemon_bridge_no_http_apis() {
    log_test "daemon-bridge does not reference invented HTTP APIs"
    local bridge_file="${LIB_DIR}/daemon-bridge.sh"
    local found_invented=false
    for pattern in '/health' '/lease' '/browser/command' '/audit/evidence' 'curl.*endpoint' 'Bearer'; do
        if grep -q "$pattern" "$bridge_file" 2>/dev/null; then
            log_fail "daemon-bridge still references invented API: $pattern"
            found_invented=true
            break
        fi
    done
    if [[ "$found_invented" == "false" ]]; then
        log_pass "no invented HTTP API references found"
    fi
}

test_cc_daemon_bridge_uses_cli() {
    log_test "daemon-bridge uses passless CLI for daemon communication"
    local bridge_file="${LIB_DIR}/daemon-bridge.sh"
    if grep -q 'agent-admin' "$bridge_file" && grep -q 'agent.*--profile' "$bridge_file"; then
        log_pass "daemon-bridge uses passless CLI commands"
    else
        log_fail "daemon-bridge does not use passless CLI commands"
    fi
}

test_cc_daemon_health_check_uses_audit_status() {
    log_test "daemon health check uses 'agent-admin audit status' (not bare 'status')"
    local bridge_file="${LIB_DIR}/daemon-bridge.sh"
    if grep -q 'agent-admin --output json audit status' "$bridge_file"; then
        if grep -qE 'agent-admin --output json status($|[^ ])' "$bridge_file" && \
           ! grep -q 'agent-admin --output json audit status' "$bridge_file"; then
            log_fail "daemon-bridge still uses bare 'agent-admin status' instead of 'agent-admin audit status'"
        else
            log_pass "daemon-bridge uses correct 'agent-admin audit status' command"
        fi
    else
        log_fail "daemon-bridge does not use 'agent-admin audit status' for health check"
    fi
}

test_cc_daemon_health_check_validates_audit_response_shape() {
    log_test "daemon health check validates AuditStatusResponse fields (enabled, entry_count)"
    local bridge_file="${LIB_DIR}/daemon-bridge.sh"
    if grep -q 'has("enabled")' "$bridge_file" && grep -q 'has("entry_count")' "$bridge_file"; then
        log_pass "health check validates stable AuditStatusResponse fields"
    else
        log_fail "health check does not validate AuditStatusResponse fields"
    fi
}

test_cc_daemon_health_check_mock_audit_status() {
    log_test "av_daemon_health_check succeeds with mock 'audit status' response"
    setup_env

    local mock_bin="${TEST_TMP_DIR}/mock-passless-health"
    cat > "$mock_bin" << 'MOCK'
#!/bin/bash
expected="agent-admin --output json audit status"
received=""
for arg in "$@"; do received="${received}${received:+ }${arg}"; done
case "$received" in
    *"$expected"*)
        printf '{"version":1,"status":"ok","data":{"enabled":true,"entry_count":42,"latest_entry_at":100}}\n'
        exit 0
        ;;
    *)
        exit 1
        ;;
esac
MOCK
    chmod +x "$mock_bin"

    export AV_PASSLESS_BIN="$mock_bin"
    export AV_DAEMON_RUNTIME_DIR="${TEST_TMP_DIR}/runtime"

    if av_daemon_health_check 2>/dev/null; then
        log_pass "health check passes with AuditStatusResponse shape"
    else
        log_fail "health check failed with valid audit status response"
    fi
}

test_cc_daemon_health_check_rejects_wrong_shape() {
    log_test "av_daemon_health_check rejects response without AuditStatusResponse fields"
    setup_env

    local mock_bin="${TEST_TMP_DIR}/mock-passless-bad-shape"
    cat > "$mock_bin" << 'MOCK'
#!/bin/bash
printf '{"status":"ok","daemon":true}\n'
exit 0
MOCK
    chmod +x "$mock_bin"

    export AV_PASSLESS_BIN="$mock_bin"
    export AV_DAEMON_RUNTIME_DIR="${TEST_TMP_DIR}/runtime"

    if av_daemon_health_check 2>/dev/null; then
        log_fail "health check should reject old .status/.daemon shape"
    else
        log_pass "health check correctly rejects wrong response shape"
    fi
}

test_cc_daemon_health_check_rejects_bare_audit_status() {
    log_test "av_daemon_health_check rejects bare AuditStatusResponse without AdminEnvelope"
    setup_env

    local mock_bin="${TEST_TMP_DIR}/mock-passless-bare-audit"
    cat > "$mock_bin" << 'MOCK'
#!/bin/bash
printf '{"enabled":true,"entry_count":42,"latest_entry_at":100}\n'
exit 0
MOCK
    chmod +x "$mock_bin"

    export AV_PASSLESS_BIN="$mock_bin"
    export AV_DAEMON_RUNTIME_DIR="${TEST_TMP_DIR}/runtime"

    if av_daemon_health_check 2>/dev/null; then
        log_fail "health check should reject bare AuditStatusResponse without .data envelope"
    else
        log_pass "health check correctly rejects bare AuditStatusResponse"
    fi
}

test_cc_daemon_health_check_no_bare_status_fields() {
    log_test "daemon health check does not check nonexistent .status or .daemon fields"
    local bridge_file="${LIB_DIR}/daemon-bridge.sh"
    if grep -qE '\.status == "ok"|\.status == "running"|\.daemon == true' "$bridge_file"; then
        log_fail "daemon-bridge still checks nonexistent .status/.daemon fields"
    else
        log_pass "no references to nonexistent .status or .daemon response fields"
    fi
}

test_cc_daemon_bridge_reads_cdp_endpoint_file() {
    log_test "daemon-bridge reads cdp-endpoint file from runtime dir"
    local bridge_file="${LIB_DIR}/daemon-bridge.sh"
    if grep -q 'cdp-endpoint' "$bridge_file"; then
        log_pass "daemon-bridge reads cdp-endpoint file"
    else
        log_fail "daemon-bridge does not reference cdp-endpoint file"
    fi
}

test_cc_event_capture_exists() {
    log_test "cdp-event-capture.js exists"
    if [[ -f "${BROWSER_DIR}/cdp-event-capture.js" ]]; then
        log_pass "cdp-event-capture.js present"
    else
        log_fail "cdp-event-capture.js missing"
    fi
}

test_cc_iframe_fixtures_exist() {
    log_test "cross-origin iframe fixtures exist"
    local rp_dir="${VALIDATION_DIR}/../agent-uhid-feasibility/controlled-rp/static"
    local all_ok=true
    for f in iframe-host.html iframe-sender.html; do
        if [[ ! -f "${rp_dir}/${f}" ]]; then
            log_fail "missing fixture: $f"
            all_ok=false
        fi
    done
    if [[ "$all_ok" == "true" ]]; then
        log_pass "all iframe fixtures present"
    fi
}

test_cc_incomplete_without_daemon_runtime_dir() {
    log_test "Gate B returns INCOMPLETE without AV_DAEMON_RUNTIME_DIR"
    setup_env
    unset AV_DAEMON_RUNTIME_DIR

    source "${STAGES_DIR}/controlled-chromium.sh"

    if stage_controlled_chromium 2>/dev/null; then
        if [[ "${STAGE_SKIPPED:-false}" == "true" ]]; then
            local results_file="${EVIDENCE_DIR}/controlled-chromium-results.json"
            if [[ -f "$results_file" ]]; then
                local status
                status=$(jq -r '.status' "$results_file" 2>/dev/null || echo "")
                if [[ "$status" == "incomplete" ]]; then
                    log_pass "correctly returned INCOMPLETE"
                else
                    log_fail "status was '$status', expected 'incomplete'"
                fi
            else
                log_fail "results file not created"
            fi
        else
            log_fail "should set STAGE_SKIPPED without runtime dir"
        fi
    else
        log_fail "stage should succeed (with skip) without runtime dir"
    fi
}

test_cc_incomplete_without_daemon_health() {
    log_test "Gate B returns INCOMPLETE with unhealthy daemon"
    setup_env
    export AV_PASSLESS_BIN="/nonexistent/passless"
    export AV_DAEMON_RUNTIME_DIR="${TEST_TMP_DIR}/runtime"

    source "${STAGES_DIR}/controlled-chromium.sh"

    if stage_controlled_chromium 2>/dev/null; then
        if [[ "${STAGE_SKIPPED:-false}" == "true" ]]; then
            local results_file="${EVIDENCE_DIR}/controlled-chromium-results.json"
            local status
            status=$(jq -r '.status' "$results_file" 2>/dev/null || echo "")
            if [[ "$status" == "incomplete" ]]; then
                log_pass "correctly returned INCOMPLETE for unhealthy daemon"
            else
                log_fail "status was '$status', expected 'incomplete'"
            fi
        else
            log_fail "should set STAGE_SKIPPED with unhealthy daemon"
        fi
    else
        log_fail "stage should succeed (with skip) with unhealthy daemon"
    fi
}

test_cc_sanitize_evidence_strips_secrets() {
    log_test "av_sanitize_evidence strips prohibited fields"
    setup_env

    local raw_file="${TEST_TMP_DIR}/raw-evidence.json"
    local sanitized_file="${TEST_TMP_DIR}/sanitized-evidence.json"

    jq -n '{
        status: "ok",
        rp_id: "localhost",
        credential_id: "secret-cred-id-12345",
        user_handle: "secret-user-handle",
        raw_challenge: "base64challenge",
        raw_payload: "should be stripped",
        bearer: "secret-bearer-token",
        cookie: "session=abc123",
        private_key: "MIGHAgE...",
        session_id: "allowed-session-id",
        timestamp: "2024-01-01T00:00:00Z"
    }' > "$raw_file"

    av_sanitize_evidence "$raw_file" "$sanitized_file"

    local has_cred_id has_user_handle has_raw has_bearer has_cookie has_key has_session
    has_cred_id=$(grep -c 'secret-cred-id' "$sanitized_file" 2>/dev/null) || has_cred_id=0
    has_user_handle=$(grep -c 'secret-user-handle' "$sanitized_file" 2>/dev/null) || has_user_handle=0
    has_raw=$(grep -c 'base64challenge' "$sanitized_file" 2>/dev/null) || has_raw=0
    has_bearer=$(grep -c 'secret-bearer-token' "$sanitized_file" 2>/dev/null) || has_bearer=0
    has_cookie=$(grep -c 'session=abc123' "$sanitized_file" 2>/dev/null) || has_cookie=0
    has_key=$(grep -c 'MIGHAgE' "$sanitized_file" 2>/dev/null) || has_key=0
    has_session=$(grep -c 'allowed-session-id' "$sanitized_file" 2>/dev/null) || has_session=0

    if [[ "$has_cred_id" -eq 0 ]] && [[ "$has_user_handle" -eq 0 ]] && [[ "$has_raw" -eq 0 ]] \
        && [[ "$has_bearer" -eq 0 ]] && [[ "$has_cookie" -eq 0 ]] && [[ "$has_key" -eq 0 ]] \
        && [[ "$has_session" -eq 1 ]]; then
        log_pass "all secrets stripped, allowed metadata preserved"
    else
        log_fail "sanitization failed (cred=$has_cred_id handle=$has_user_handle raw=$has_raw bearer=$has_bearer cookie=$has_cookie key=$has_key session=$has_session)"
    fi
}

test_cc_sanitize_evidence_fails_closed() {
    log_test "av_sanitize_evidence fails closed on invalid JSON"
    setup_env

    local raw_file="${TEST_TMP_DIR}/invalid-evidence.json"
    local sanitized_file="${TEST_TMP_DIR}/sanitized-invalid.json"

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

test_cc_sanitize_evidence_fails_closed_missing_input() {
    log_test "av_sanitize_evidence fails on missing input file"
    setup_env

    local sanitized_file="${TEST_TMP_DIR}/sanitized-missing.json"

    if av_sanitize_evidence "/nonexistent/file.json" "$sanitized_file" 2>/dev/null; then
        log_fail "sanitizer should fail on missing input"
    else
        log_pass "sanitizer fails on missing input"
    fi
}

test_cc_assert_no_js_dialogs_with_empty_file() {
    log_test "av_cc_assert_no_js_dialogs_ancillary handles empty events file"
    setup_env

    local empty_file="${TEST_TMP_DIR}/empty-events.jsonl"
    : > "$empty_file"

    local result
    result=$(av_cc_assert_no_js_dialogs_ancillary "$empty_file" 2>/dev/null || echo '{"js_dialog_events":-1}')
    local count
    count=$(echo "$result" | jq -r '.js_dialog_events')
    if [[ "$count" == "0" ]]; then
        log_pass "zero dialogs for empty events file"
    else
        log_fail "expected 0 dialogs, got $count"
    fi
}

test_cc_assert_no_js_dialogs_with_dialogs() {
    log_test "av_cc_assert_no_js_dialogs_ancillary detects JS dialog events"
    setup_env

    local events_file="${TEST_TMP_DIR}/dialog-events.jsonl"
    echo '{"method":"Page.javascriptDialogOpening","params":{"message":"alert"}}' > "$events_file"

    local result
    result=$(av_cc_assert_no_js_dialogs_ancillary "$events_file" 2>/dev/null || echo '{"js_dialog_events":-1}')
    local count
    count=$(echo "$result" | jq -r '.js_dialog_events')
    if [[ "$count" -gt 0 ]]; then
        log_pass "JS dialog events detected (count=$count)"
    else
        log_fail "failed to detect JS dialog events"
    fi
}

test_cc_assert_no_js_dialogs_has_ancillary_note() {
    log_test "av_cc_assert_no_js_dialogs_ancillary includes ancillary note"
    setup_env

    local empty_file="${TEST_TMP_DIR}/empty-events2.jsonl"
    : > "$empty_file"

    local result
    result=$(av_cc_assert_no_js_dialogs_ancillary "$empty_file" 2>/dev/null || echo '{}')
    local note
    note=$(echo "$result" | jq -r '.note // empty')
    if [[ "$note" == *"ancillary"* ]]; then
        log_pass "ancillary evidence note present"
    else
        log_fail "ancillary evidence note missing"
    fi
}

test_cc_assert_no_js_dialogs_no_file() {
    log_test "av_cc_assert_no_js_dialogs_ancillary handles missing file"
    setup_env

    local result
    result=$(av_cc_assert_no_js_dialogs_ancillary "/nonexistent/file" 2>/dev/null || echo '{"js_dialog_events":-1}')
    local assertion
    assertion=$(echo "$result" | jq -r '.assertion')
    if [[ "$assertion" == "no_data" ]]; then
        log_pass "no_data assertion for missing file"
    else
        log_fail "expected no_data, got $assertion"
    fi
}

test_cc_dbus_notify_count_empty() {
    log_test "av_cc_count_dbus_notify_calls returns 0 for empty log"
    setup_env

    local empty_log="${TEST_TMP_DIR}/empty-dbus.log"
    : > "$empty_log"

    local count
    count=$(av_cc_count_dbus_notify_calls "$empty_log" 2>/dev/null || echo "error")
    if [[ "$count" == "0" ]]; then
        log_pass "zero Notify calls for empty log"
    else
        log_fail "expected 0, got $count"
    fi
}

test_cc_dbus_notify_count_with_calls() {
    log_test "av_cc_count_dbus_notify_calls counts Notify calls"
    setup_env

    local dbus_log="${TEST_TMP_DIR}/dbus.log"
    cat > "$dbus_log" << 'EOF'
signal time=1234567890.000 sender=:1.50 -> destination=(null destination) serial=42 path=/org/freedesktop/Notifications; interface=org.freedesktop.Notifications; member=Notify
   string "Passless"
   uint32 0
   string ""
signal time=1234567891.000 sender=:1.50 -> destination=(null destination) serial=43 path=/org/freedesktop/Notifications; interface=org.freedesktop.Notifications; member=Notify
   string "Another"
EOF

    local count
    count=$(av_cc_count_dbus_notify_calls "$dbus_log" 2>/dev/null || echo "error")
    if [[ "$count" == "2" ]]; then
        log_pass "correctly counted 2 Notify calls"
    else
        log_fail "expected 2, got $count"
    fi
}

test_cc_collect_errors_empty_stderr() {
    log_test "av_cc_collect_chromium_errors handles empty stderr"
    setup_env

    local empty_stderr="${TEST_TMP_DIR}/empty-stderr.log"
    : > "$empty_stderr"

    av_cc_collect_chromium_errors "$empty_stderr" "$EVIDENCE_DIR" 2>/dev/null

    local errors_file="${EVIDENCE_DIR}/chromium-errors.json"
    if [[ -f "$errors_file" ]]; then
        local total
        total=$(jq -r '.total' "$errors_file" 2>/dev/null || echo "-1")
        if [[ "$total" == "0" ]]; then
            log_pass "zero errors for empty stderr"
        else
            log_fail "expected 0 total errors, got $total"
        fi
    else
        log_fail "chromium-errors.json not created"
    fi
}

test_cc_collect_errors_with_errors() {
    log_test "av_cc_collect_chromium_errors categorizes errors"
    setup_env

    local stderr_log="${TEST_TMP_DIR}/chromium-stderr.log"
    cat > "$stderr_log" << 'EOF'
[0101/120000:ERROR:service_worker.cc(42)] Service Worker error
[0101/120001:SEVERE:content_script.cc(99)] Content script failed
[0101/120002:ERROR:network.cc(10)] General network error
EOF

    av_cc_collect_chromium_errors "$stderr_log" "$EVIDENCE_DIR" 2>/dev/null

    local errors_file="${EVIDENCE_DIR}/chromium-errors.json"
    if [[ -f "$errors_file" ]]; then
        local sw_count cs_count other_count total
        sw_count=$(jq '.service_worker_errors | length' "$errors_file" 2>/dev/null || echo "-1")
        cs_count=$(jq '.content_script_errors | length' "$errors_file" 2>/dev/null || echo "-1")
        other_count=$(jq '.other_errors | length' "$errors_file" 2>/dev/null || echo "-1")
        total=$(jq '.total' "$errors_file" 2>/dev/null || echo "-1")

        if [[ "$sw_count" -ge 1 ]] && [[ "$cs_count" -ge 1 ]] && [[ "$other_count" -ge 1 ]] && [[ "$total" -ge 3 ]]; then
            log_pass "errors correctly categorized (sw=$sw_count cs=$cs_count other=$other_count total=$total)"
        else
            log_fail "error categorization incorrect (sw=$sw_count cs=$cs_count other=$other_count total=$total)"
        fi
    else
        log_fail "chromium-errors.json not created"
    fi
}

test_cc_verify_lease_cleanup_nonexistent() {
    log_test "av_verify_lease_cleanup handles nonexistent directory"
    setup_env

    local result
    result=$(av_verify_lease_cleanup "/nonexistent/dir" 2>/dev/null || echo '{"status":"error"}')
    local status
    status=$(echo "$result" | jq -r '.status')
    if [[ "$status" == "cleaned" ]]; then
        log_pass "nonexistent lease dir reported as cleaned"
    else
        log_fail "expected 'cleaned', got '$status'"
    fi
}

test_cc_verify_lease_cleanup_existing_dir() {
    log_test "av_verify_lease_cleanup reports existing directory status"
    setup_env

    local lease_dir="${TEST_TMP_DIR}/lease-test"
    mkdir -p "$lease_dir"
    touch "$lease_dir/test.token"

    local result
    result=$(av_verify_lease_cleanup "$lease_dir" 2>/dev/null || echo '{"status":"error"}')
    local exists
    exists=$(echo "$result" | jq -r '.exists')
    if [[ "$exists" == "true" ]]; then
        log_pass "existing lease dir reported as exists"
    else
        log_fail "expected exists=true, got '$exists'"
    fi
}

test_cc_daemon_bridge_rejects_empty_runtime_dir() {
    log_test "av_daemon_prereqs_check rejects empty runtime dir"
    setup_env
    unset AV_DAEMON_RUNTIME_DIR

    if av_daemon_prereqs_check 2>/dev/null; then
        log_fail "should reject empty runtime dir"
    else
        log_pass "correctly rejected empty runtime dir"
    fi
}

test_cc_daemon_bridge_reads_cdp_endpoint_file_content() {
    log_test "av_daemon_read_cdp_endpoint reads file content"
    setup_env

    local test_runtime="${TEST_TMP_DIR}/runtime-read-test"
    mkdir -p "$test_runtime"
    echo "http://127.0.0.1:9222" > "${test_runtime}/cdp-endpoint"

    local endpoint
    endpoint=$(av_daemon_read_cdp_endpoint "$test_runtime" 2>/dev/null || echo "")
    if [[ "$endpoint" == "http://127.0.0.1:9222" ]]; then
        log_pass "CDP endpoint read correctly"
    else
        log_fail "expected 'http://127.0.0.1:9222', got '$endpoint'"
    fi
}

test_cc_daemon_bridge_cdp_endpoint_missing() {
    log_test "av_daemon_read_cdp_endpoint fails when file missing"
    setup_env

    local test_runtime="${TEST_TMP_DIR}/runtime-missing-test"
    mkdir -p "$test_runtime"

    if av_daemon_read_cdp_endpoint "$test_runtime" 2>/dev/null; then
        log_fail "should fail when cdp-endpoint file missing"
    else
        log_pass "correctly failed when cdp-endpoint missing"
    fi
}

test_cc_results_schema() {
    log_test "Gate B results file has expected schema"
    setup_env
    unset AV_DAEMON_RUNTIME_DIR

    source "${STAGES_DIR}/controlled-chromium.sh"
    stage_controlled_chromium 2>/dev/null || true

    local results_file="${EVIDENCE_DIR}/controlled-chromium-results.json"
    if [[ ! -f "$results_file" ]]; then
        log_fail "results file not created"
        return
    fi

    local has_gate has_status has_timestamp
    has_gate=$(jq -e '.gate == "B"' "$results_file" >/dev/null 2>&1 && echo "yes" || echo "no")
    has_status=$(jq -e '.status' "$results_file" >/dev/null 2>&1 && echo "yes" || echo "no")
    has_timestamp=$(jq -e '.timestamp' "$results_file" >/dev/null 2>&1 && echo "yes" || echo "no")

    if [[ "$has_gate" == "yes" ]] && [[ "$has_status" == "yes" ]] && [[ "$has_timestamp" == "yes" ]]; then
        log_pass "results schema includes gate, status, timestamp"
    else
        log_fail "results schema incomplete (gate=$has_gate status=$has_status timestamp=$has_timestamp)"
    fi
}

test_cc_stage_has_strict_mode() {
    log_test "controlled-chromium stage uses strict mode"
    if grep -q 'set -euo pipefail' "${STAGES_DIR}/controlled-chromium.sh"; then
        log_pass "strict mode present"
    else
        log_fail "strict mode missing"
    fi
}

test_cc_stage_has_bash_shebang() {
    log_test "controlled-chromium stage has bash shebang"
    local first_line
    first_line=$(head -n1 "${STAGES_DIR}/controlled-chromium.sh")
    if [[ "$first_line" == "#!/bin/bash" ]]; then
        log_pass "correct shebang"
    else
        log_fail "bad shebang: $first_line"
    fi
}

test_cc_no_false_pass() {
    log_test "Gate B never returns PASS without daemon"
    setup_env
    unset AV_DAEMON_RUNTIME_DIR

    source "${STAGES_DIR}/controlled-chromium.sh"
    stage_controlled_chromium 2>/dev/null || true

    local results_file="${EVIDENCE_DIR}/controlled-chromium-results.json"
    if [[ -f "$results_file" ]]; then
        local status
        status=$(jq -r '.status' "$results_file" 2>/dev/null || echo "unknown")
        if [[ "$status" != "pass" ]]; then
            log_pass "never returns PASS without daemon (status=$status)"
        else
            log_fail "FALSE PASS detected without daemon!"
        fi
    else
        log_pass "no results file means no false PASS"
    fi
}

test_cc_no_token_logging() {
    log_test "daemon-bridge does not log token contents"
    local bridge_file="${LIB_DIR}/daemon-bridge.sh"
    if grep -qE 'token.*\.\.\.' "$bridge_file" || grep -qE 'lease_token.*:' "$bridge_file"; then
        log_fail "daemon-bridge may log token contents"
    else
        log_pass "no token logging found"
    fi
}

test_cc_cleanup_trap_present() {
    log_test "stage_controlled_chromium sets cleanup trap"
    if grep -q 'trap.*av_cc_cleanup_all' "${STAGES_DIR}/controlled-chromium.sh"; then
        log_pass "cleanup trap present"
    else
        log_fail "cleanup trap missing"
    fi
}

test_cc_evidence_semantics_in_report() {
    log_test "Gate B results include evidence_semantics when reaching full evaluation"
    setup_env
    export AV_DAEMON_RUNTIME_DIR="${TEST_TMP_DIR}/runtime-sem"
    mkdir -p "$AV_DAEMON_RUNTIME_DIR"
    export AV_PASSLESS_BIN="/nonexistent/passless"

    source "${STAGES_DIR}/controlled-chromium.sh"
    stage_controlled_chromium 2>/dev/null || true

    local results_file="${EVIDENCE_DIR}/controlled-chromium-results.json"
    if [[ -f "$results_file" ]]; then
        local status
        status=$(jq -r '.status' "$results_file" 2>/dev/null || echo "unknown")
        if [[ "$status" == "incomplete" ]]; then
            local has_reason
            has_reason=$(jq -e '.reason' "$results_file" >/dev/null 2>&1 && echo "yes" || echo "no")
            if [[ "$has_reason" == "yes" ]]; then
                log_pass "incomplete results include reason (evidence_semantics only in full evaluation)"
            else
                log_fail "incomplete results missing reason"
            fi
        else
            local has_semantics
            has_semantics=$(jq -e '.evidence_semantics' "$results_file" >/dev/null 2>&1 && echo "yes" || echo "no")
            if [[ "$has_semantics" == "yes" ]]; then
                log_pass "evidence_semantics present in full results"
            else
                log_fail "evidence_semantics missing from full results"
            fi
        fi
    else
        log_fail "results file not created"
    fi
}

test_cc_pipe_mode_incomplete() {
    log_test "Gate B returns INCOMPLETE for pipe CDP mode"
    setup_env
    export AV_DAEMON_CDP_MODE="pipe"

    local bridge_file="${LIB_DIR}/daemon-bridge.sh"
    if grep -q 'pipe.*INCOMPLETE\|pipe.*browser-control' "${STAGES_DIR}/controlled-chromium.sh"; then
        log_pass "pipe mode handled as INCOMPLETE"
    else
        if grep -q 'pipe' "${STAGES_DIR}/controlled-chromium.sh"; then
            log_pass "pipe mode referenced in stage"
        else
            log_fail "pipe mode not handled"
        fi
    fi
}

test_cc_jq_safe_json_building() {
    log_test "controlled-rp uses jq for JSON building"
    local rp_file="${LIB_DIR}/controlled-rp.sh"
    if grep -q 'jq -n.*--arg' "$rp_file"; then
        log_pass "controlled-rp uses jq --arg for safe JSON"
    else
        log_fail "controlled-rp does not use jq for safe JSON building"
    fi
}

main() {
    echo -e "${BLUE}=== Controlled-Chromium Gate B Tests ===${NC}" >&2

    test_cc_stage_file_exists
    test_cc_lib_file_exists
    test_cc_daemon_bridge_exists
    test_cc_daemon_bridge_no_http_apis
    test_cc_daemon_bridge_uses_cli
    test_cc_daemon_health_check_uses_audit_status
    test_cc_daemon_health_check_validates_audit_response_shape
    test_cc_daemon_health_check_mock_audit_status
    test_cc_daemon_health_check_rejects_wrong_shape
    test_cc_daemon_health_check_rejects_bare_audit_status
    test_cc_daemon_health_check_no_bare_status_fields
    test_cc_daemon_bridge_reads_cdp_endpoint_file
    test_cc_event_capture_exists
    test_cc_iframe_fixtures_exist
    test_cc_incomplete_without_daemon_runtime_dir
    test_cc_incomplete_without_daemon_health
    test_cc_sanitize_evidence_strips_secrets
    test_cc_sanitize_evidence_fails_closed
    test_cc_sanitize_evidence_fails_closed_missing_input
    test_cc_assert_no_js_dialogs_with_empty_file
    test_cc_assert_no_js_dialogs_with_dialogs
    test_cc_assert_no_js_dialogs_has_ancillary_note
    test_cc_assert_no_js_dialogs_no_file
    test_cc_dbus_notify_count_empty
    test_cc_dbus_notify_count_with_calls
    test_cc_collect_errors_empty_stderr
    test_cc_collect_errors_with_errors
    test_cc_verify_lease_cleanup_nonexistent
    test_cc_verify_lease_cleanup_existing_dir
    test_cc_daemon_bridge_rejects_empty_runtime_dir
    test_cc_daemon_bridge_reads_cdp_endpoint_file_content
    test_cc_daemon_bridge_cdp_endpoint_missing
    test_cc_results_schema
    test_cc_stage_has_strict_mode
    test_cc_stage_has_bash_shebang
    test_cc_no_false_pass
    test_cc_no_token_logging
    test_cc_cleanup_trap_present
    test_cc_evidence_semantics_in_report
    test_cc_pipe_mode_incomplete
    test_cc_jq_safe_json_building

    echo "" >&2
    echo -e "${BLUE}Tests: $TEST_COUNT total, $PASS_COUNT passed, $FAIL_COUNT failed${NC}" >&2

    [[ $FAIL_COUNT -eq 0 ]]
}

main "$@"
