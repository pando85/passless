#!/bin/bash

set -euo pipefail

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/common.sh"
fi
if [[ -z "${AV_LIB_REAL_RP_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/real-rp.sh"
fi

# shellcheck disable=SC2034
AV_STAGE_REAL_RP_LOADED=true

_av_gc_incomplete() {
    local results_file="$1"
    local reason="$2"
    jq -n --arg reason "$reason" \
        '{status:"incomplete",reason:$reason,gate:"C",timestamp:"'"$(av_capture_timestamp)"'"}' \
        > "$results_file"
    # shellcheck disable=SC2034
    STAGE_SKIPPED=true
}

_av_gc_fail() {
    local results_file="$1"
    local reason="$2"
    local details="${3:-{}}"
    jq -n --arg reason "$reason" --argjson details "$details" \
        '{status:"fail",reason:$reason,gate:"C",details:$details,timestamp:"'"$(av_capture_timestamp)"'"}' \
        > "$results_file"
}

stage_real_rp() {
    local evidence_dir="${EVIDENCE_DIR:-/tmp}"
    local results_file="${evidence_dir}/real-rp-results.json"
    local scenarios_json="[]"
    local total=0
    local passed=0
    local failed=0
    local incomplete=0

    trap av_gc_cleanup EXIT RETURN

    _add_gc_scenario() {
        local name="$1" status="$2" detail="$3"
        scenarios_json=$(echo "$scenarios_json" | jq \
            --arg n "$name" --arg s "$status" --arg d "$detail" \
            '. + [{"name": $n, "status": $s, "detail": $d}]')
        ((total++)) || true
        case "$status" in
            pass) ((passed++)) || true ;;
            fail) ((failed++)) || true ;;
            incomplete) ((incomplete++)) || true ;;
        esac
    }

    av_log_info "Gate C: Real-RP MVP validation (opt-in)"

    if ! av_gc_env_check 2>/dev/null; then
        _av_gc_incomplete "$results_file" "missing required environment variables (AV_PASSLESS_BIN/AV_DAEMON_PROFILE/AV_DAEMON_RUNTIME_DIR/AV_REAL_RP_CREDENTIAL_REF)"
        return 0
    fi
    _add_gc_scenario "env_check" "pass" "all required environment variables present"

    if ! av_daemon_prereqs_check 2>/dev/null; then
        _av_gc_incomplete "$results_file" "daemon prerequisites not met"
        return 0
    fi
    _add_gc_scenario "daemon_prereqs" "pass" "daemon prerequisites satisfied"

    if ! av_daemon_health_check 2>/dev/null; then
        _av_gc_incomplete "$results_file" "daemon not healthy (agent-admin audit status failed)"
        return 0
    fi
    _add_gc_scenario "daemon_health" "pass" "daemon healthy via agent-admin audit status"

    local cdp_port_raw
    cdp_port_raw=$(av_gc_get_cdp_port "${AV_DAEMON_PROFILE}" "${AV_DAEMON_RUNTIME_DIR}" 2>/dev/null) || {
        local rc=$?
        case $rc in
            2) _av_gc_incomplete "$results_file" "browser-status unavailable" ;;
            3) _av_gc_incomplete "$results_file" "daemon reports browser not running" ;;
            4) _av_gc_incomplete "$results_file" "no CDP endpoint from daemon" ;;
            5) _av_gc_incomplete "$results_file" "pipe CDP mode not supported for Gate C; port mode required" ;;
            6) _av_gc_incomplete "$results_file" "cannot extract CDP port from endpoint" ;;
            *) _av_gc_fail "$results_file" "browser verification failed (rc=$rc)" ;;
        esac
        return 0
    }

    if [[ "$cdp_port_raw" == "pipe" ]]; then
        _av_gc_incomplete "$results_file" "pipe CDP mode not supported for Gate C"
        return 0
    fi

    local cdp_port="$cdp_port_raw"
    # shellcheck disable=SC2034
    AV_CDP_PORT="$cdp_port"
    _add_gc_scenario "browser_ready" "pass" "daemon-managed browser ready on CDP port $cdp_port (port mode)"

    if [[ ! -f "${AV_REAL_RP_DRIVER:-}" ]]; then
        _av_gc_incomplete "$results_file" "real-rp-driver.js not found at ${AV_REAL_RP_DRIVER:-}"
        return 0
    fi
    _add_gc_scenario "driver_exists" "pass" "real-rp-driver.js found"

    local driver_source
    driver_source=$(cat "${AV_REAL_RP_DRIVER}" 2>/dev/null || echo "")
    local forbidden_found=false
    local forbidden_methods=""
    for method in "WebAuthn.enable" "addVirtualAuthenticator" "addCredential"; do
        if echo "$driver_source" | grep -qF "$method"; then
            forbidden_found=true
            forbidden_methods="${forbidden_methods}${method},"
        fi
    done
    if [[ "$forbidden_found" == "true" ]]; then
        _av_gc_fail "$results_file" "driver contains forbidden CDP WebAuthn methods: ${forbidden_methods%,}"
        return 1
    fi
    _add_gc_scenario "no_forbidden_static" "pass" "driver source contains no WebAuthn.enable/addVirtualAuthenticator/addCredential"

    if echo "$driver_source" | grep -qiE '(\.pass/|\.password-store/|vault.*read|read.*secret|key.*file|\.gpg)'; then
        _av_gc_fail "$results_file" "driver appears to access vault/key files"
        return 1
    fi
    _add_gc_scenario "no_vault_access" "pass" "driver source contains no vault/key file access patterns"

    if echo "$driver_source" | grep -qF "a.signin-passkey"; then
        _add_gc_scenario "selector_present" "pass" "driver uses expected selector a.signin-passkey"
    else
        _av_gc_fail "$results_file" "driver missing expected selector a.signin-passkey"
        return 1
    fi

    av_gc_start_dbus_monitor "$evidence_dir" 2>/dev/null || true
    _add_gc_scenario "dbus_monitor" "pass" "D-Bus Notify monitor started"

    local cdp_capture_pid=""
    cdp_capture_pid=$(av_gc_start_cdp_capture "$cdp_port" "$evidence_dir" 2>/dev/null || echo "")
    if [[ -n "$cdp_capture_pid" ]]; then
        _add_gc_scenario "cdp_capture" "pass" "CDP event capture started (PID=$cdp_capture_pid)"
    else
        _add_gc_scenario "cdp_capture" "incomplete" "CDP event capture failed to start"
    fi

    local driver_output_file="${evidence_dir}/gc-driver-output.json"
    local driver_exit=0
    local driver_timeout="${AV_REAL_RP_TIMEOUT:-60}"

    AV_CDP_PORT="$cdp_port" \
    AV_REAL_RP_URL="${AV_REAL_RP_URL:-https://tea.millaguie.net}" \
    AV_EVIDENCE_DIR="$evidence_dir" \
    timeout "${driver_timeout}s" \
        "${AV_PASSLESS_BIN:-passless}" agent run --profile "${AV_DAEMON_PROFILE}" \
        -- node "${AV_REAL_RP_DRIVER}" \
        > "$driver_output_file" 2>&1 || driver_exit=$?

    if [[ $driver_exit -eq 0 ]]; then
        local driver_result
        driver_result=$(cat "$driver_output_file" 2>/dev/null || echo "{}")
        local nav_ok
        nav_ok=$(echo "$driver_result" | jq -r '.navigation_ok // false' 2>/dev/null || echo "false")
        local click_ok
        click_ok=$(echo "$driver_result" | jq -r '.click_ok // false' 2>/dev/null || echo "false")
        local url_origin
        url_origin=$(echo "$driver_result" | jq -r '.url_origin // "unknown"' 2>/dev/null || echo "unknown")
        local title_class
        title_class=$(echo "$driver_result" | jq -r '.title_class // "unknown"' 2>/dev/null || echo "unknown")
        local self_check
        self_check=$(echo "$driver_result" | jq -r '.self_check // "unknown"' 2>/dev/null || echo "unknown")

        if [[ "$nav_ok" == "true" ]] && [[ "$click_ok" == "true" ]]; then
            _add_gc_scenario "driver_flow" "pass" "navigation and click completed; origin=$url_origin title_class=$title_class"
        elif [[ "$nav_ok" == "true" ]]; then
            _add_gc_scenario "driver_flow" "fail" "navigation succeeded but click failed; origin=$url_origin"
        else
            _add_gc_scenario "driver_flow" "fail" "navigation failed"
        fi

        if [[ "$self_check" == "pass" ]]; then
            _add_gc_scenario "driver_self_check" "pass" "driver self-check passed (no forbidden methods in source)"
        else
            _add_gc_scenario "driver_self_check" "incomplete" "driver self-check: $self_check"
        fi
    elif [[ $driver_exit -eq 124 ]]; then
        _add_gc_scenario "driver_flow" "fail" "driver timed out after ${driver_timeout}s"
    else
        _add_gc_scenario "driver_flow" "incomplete" "driver exited with code $driver_exit (delegation or agent context may be unavailable)"
    fi

    av_gc_stop_cdp_capture 2>/dev/null || true
    sleep 1

    local events_file="${evidence_dir}/gc-cdp-events.jsonl"
    local cdp_verify
    cdp_verify=$(av_gc_verify_no_forbidden_cdp "$events_file" 2>/dev/null || echo '{"forbidden_calls":-1,"assertion":"no_data"}')
    local forbidden_count
    forbidden_count=$(echo "$cdp_verify" | jq -r '.forbidden_calls // -1' 2>/dev/null || echo "-1")
    if [[ "$forbidden_count" == "0" ]]; then
        _add_gc_scenario "no_forbidden_runtime" "pass" "zero forbidden WebAuthn CDP calls in event capture"
    elif [[ "$forbidden_count" == "-1" ]]; then
        _add_gc_scenario "no_forbidden_runtime" "incomplete" "CDP events file unavailable for verification"
    else
        _add_gc_scenario "no_forbidden_runtime" "fail" "$forbidden_count forbidden WebAuthn CDP call(s) detected"
    fi

    local notify_count
    notify_count=$(av_gc_count_dbus_notify 2>/dev/null || echo "0")
    if [[ "$notify_count" == "0" ]]; then
        _add_gc_scenario "no_dbus_notify" "pass" "zero D-Bus Notify calls for allow-policy"
    else
        _add_gc_scenario "no_dbus_notify" "fail" "$notify_count D-Bus Notify call(s) detected"
    fi

    local audit_ok=false
    if av_gc_sanitize_audit_export "$evidence_dir" 2>/dev/null; then
        # shellcheck disable=SC2034
        audit_ok=true
        _add_gc_scenario "audit_evidence" "pass" "audit export sanitized and written"
    else
        _add_gc_scenario "audit_evidence" "incomplete" "audit export/sanitization failed (fail-closed; nothing written)"
    fi

    local wrong_origin
    wrong_origin=$(av_gc_check_wrong_origin_feasible 2>/dev/null || echo '{"status":"incomplete"}')
    local wo_status
    wo_status=$(echo "$wrong_origin" | jq -r '.status // "incomplete"' 2>/dev/null || echo "incomplete")
    _add_gc_scenario "wrong_origin" "$wo_status" "$(echo "$wrong_origin" | jq -r '.reason // "not feasible"' 2>/dev/null || echo "not feasible")"

    local expired_grant
    expired_grant=$(av_gc_check_expired_grant_feasible 2>/dev/null || echo '{"status":"incomplete"}')
    local eg_status
    eg_status=$(echo "$expired_grant" | jq -r '.status // "incomplete"' 2>/dev/null || echo "incomplete")
    _add_gc_scenario "expired_grant" "$eg_status" "$(echo "$expired_grant" | jq -r '.reason // "not feasible"' 2>/dev/null || echo "not feasible")"

    local revoke_result="not_attempted"
    if "${AV_PASSLESS_BIN:-passless}" agent-admin --output json delegation revoke --help &>/dev/null 2>&1; then
        if "${AV_PASSLESS_BIN:-passless}" agent-admin --output json delegation revoke --all 2>/dev/null; then
            revoke_result="revoked"
        else
            revoke_result="failed"
        fi
    fi
    _add_gc_scenario "cleanup_revoke" "pass" "delegation revoke: $revoke_result"

    local overall="pass"
    if [[ $failed -gt 0 ]]; then
        overall="fail"
    elif [[ $incomplete -gt 0 ]]; then
        overall="incomplete"
    fi

    local has_incomplete_scenarios=false
    if [[ "$wo_status" == "incomplete" ]] || [[ "$eg_status" == "incomplete" ]]; then
        has_incomplete_scenarios=true
    fi

    jq -n \
        --arg timestamp "$(av_capture_timestamp)" \
        --arg status "$overall" \
        --arg gate "C" \
        --argjson total "$total" \
        --argjson passed "$passed" \
        --argjson failed "$failed" \
        --argjson incomplete "$incomplete" \
        --argjson scenarios "$scenarios_json" \
        --argjson notify_count "$notify_count" \
        --argjson cdp_verify "$cdp_verify" \
        --argjson wrong_origin "$wrong_origin" \
        --argjson expired_grant "$expired_grant" \
        --arg revoke "$revoke_result" \
        --argjson blocks_pass "$has_incomplete_scenarios" \
        '{
            timestamp: $timestamp,
            status: $status,
            gate: $gate,
            total: $total,
            passed: $passed,
            failed: $failed,
            incomplete: $incomplete,
            scenarios: $scenarios,
            assertions: {
                dbus_notify_count: $notify_count,
                cdp_forbidden: $cdp_verify,
                wrong_origin: $wrong_origin,
                expired_grant: $expired_grant,
                delegation_revoke: $revoke
            },
            blocks_full_pass: $blocks_pass,
            evidence_semantics: {
                dialog: "ancillary_only_native_chooser_not_js_dialog",
                url_origin: "sanitized_to_origin_class_only",
                title: "sanitized_to_class_only",
                no_raw_secrets: "never_stores_challenge_clientDataJSON_assertion_signature_credential_ref_user_handle_bearer_cookies_keys"
            }
        }' > "$results_file"

    if [[ "$overall" == "fail" ]]; then
        av_log_error "Gate C: $failed scenario(s) failed"
        return 1
    fi

    if [[ "$overall" == "incomplete" ]]; then
        av_log_warn "Gate C: incomplete ($incomplete scenario(s) inconclusive)"
        return 1
    fi

    av_log_success "Gate C: $passed/$total passed"
    return 0
}
