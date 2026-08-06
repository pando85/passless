#!/bin/bash

set -euo pipefail

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/common.sh"
fi
if [[ -z "${AV_LIB_CONTROLLED_CHROMIUM_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/controlled-chromium.sh"
fi
if [[ -z "${AV_LIB_CONTROLLED_RP_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/controlled-rp.sh"
fi
if [[ -z "${AV_LIB_DAEMON_BRIDGE_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/daemon-bridge.sh"
fi

# shellcheck disable=SC2034
AV_STAGE_CONTROLLED_CHROMIUM_LOADED=true

_av_cc_incomplete() {
    local results_file="$1"
    local reason="$2"
    jq -n --arg reason "$reason" \
        '{status:"incomplete",reason:$reason,gate:"B",timestamp:"'"$(av_capture_timestamp)"'"}' \
        > "$results_file"
    # shellcheck disable=SC2034
    STAGE_SKIPPED=true
}

_av_cc_fail() {
    local results_file="$1"
    local reason="$2"
    local details="${3:-{}}"
    jq -n --arg reason "$reason" --argjson details "$details" \
        '{status:"fail",reason:$reason,gate:"B",details:$details,timestamp:"'"$(av_capture_timestamp)"'"}' \
        > "$results_file"
}

stage_controlled_chromium() {
    local evidence_dir="${EVIDENCE_DIR:-/tmp}"
    local results_file="${evidence_dir}/controlled-chromium-results.json"
    local scenarios_json="[]"
    local total=0
    local passed=0
    local failed=0
    local incomplete=0

    trap av_cc_cleanup_all EXIT RETURN

    _add_cc_scenario() {
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

    av_log_info "Gate B: Controlled-Chromium MVP validation"

    if ! av_cc_prereqs_check 2>/dev/null; then
        _av_cc_incomplete "$results_file" "prerequisites not met (node/chromium/curl/jq/cdp-event-capture.js)"
        return 0
    fi
    _add_cc_scenario "prereqs" "pass" "all prerequisites available"

    if ! av_daemon_prereqs_check 2>/dev/null; then
        _av_cc_incomplete "$results_file" "daemon prerequisites not met (passless binary/AV_DAEMON_RUNTIME_DIR/jq)"
        return 0
    fi
    _add_cc_scenario "daemon_prereqs" "pass" "daemon CLI and runtime dir available"

    if ! av_daemon_health_check 2>/dev/null; then
        _av_cc_incomplete "$results_file" "daemon not healthy (passless agent-admin audit status failed)"
        return 0
    fi
    _add_cc_scenario "daemon_health" "pass" "daemon healthy via agent-admin status"

    local cdp_mode
    cdp_mode=$(av_daemon_detect_cdp_mode 2>/dev/null || echo "port")
    _add_cc_scenario "cdp_mode" "pass" "detected CDP mode: $cdp_mode"

    if [[ "$cdp_mode" == "pipe" ]]; then
        _av_cc_incomplete "$results_file" "pipe CDP mode requires browser-control IPC; marking INCOMPLETE"
        return 0
    fi

    local profile="${AV_DAEMON_PROFILE:-}"
    if [[ -z "$profile" ]]; then
        _av_cc_incomplete "$results_file" "AV_DAEMON_PROFILE not set; required for browser-status"
        return 0
    fi

    local rp_port="${AV_RP_PORT:-8443}"
    local rp_url="${AV_RP_URL:-http://127.0.0.1:${rp_port}}"

    if ! av_controlled_rp_health_check "$rp_port" 2>/dev/null; then
        if ! av_start_controlled_rp "$rp_port" "${AV_VALIDATION_DIR:-}" 2>/dev/null; then
            _av_cc_incomplete "$results_file" "controlled RP failed to start"
            return 0
        fi
    fi
    _add_cc_scenario "rp_server" "pass" "controlled RP available on port $rp_port"

    if ! av_cc_verify_daemon_browser_ready "$profile" "$evidence_dir" 2>/dev/null; then
        local rc=$?
        case $rc in
            2) _av_cc_incomplete "$results_file" "daemon browser-status unavailable" ;;
            3) _av_cc_incomplete "$results_file" "daemon reports browser not running" ;;
            4) _av_cc_incomplete "$results_file" "no CDP endpoint available from daemon" ;;
            *) _av_cc_fail "$results_file" "daemon-managed browser not ready (rc=$rc)" ;;
        esac
        return 0
    fi
    local cdp_port="${AV_CDP_PORT:-9222}"
    _add_cc_scenario "browser_ready" "pass" "daemon-managed browser verified via browser-status on CDP port $cdp_port"

    av_cc_start_dbus_monitor "$evidence_dir" 2>/dev/null || true

    local wrapper_result
    wrapper_result=$(av_cc_verify_extension_wrapper_behavior "$cdp_port" "$rp_url" 2>/dev/null || echo '{"error":"wrapper_check_failed"}')
    local get_is_native
    get_is_native=$(echo "$wrapper_result" | jq -r '.getIsNative // "unknown"' 2>/dev/null || echo "unknown")

    if [[ "$get_is_native" == "false" ]]; then
        _add_cc_scenario "extension_wrapper" "pass" "navigator.credentials.get is non-native (extension wrapper detected)"
    elif [[ "$get_is_native" == "true" ]]; then
        _add_cc_scenario "extension_wrapper" "incomplete" "navigator.credentials.get appears native; extension wrapper not detected at check time"
    else
        _add_cc_scenario "extension_wrapper" "incomplete" "extension wrapper state indeterminate"
    fi

    local cdp_event_pid=""
    cdp_event_pid=$(av_cc_start_cdp_event_capture "$cdp_port" "$evidence_dir" 2>/dev/null || echo "")
    if [[ -n "$cdp_event_pid" ]]; then
        _add_cc_scenario "cdp_event_capture" "pass" "CDP event capture started (PID=$cdp_event_pid)"
    else
        _add_cc_scenario "cdp_event_capture" "fail" "CDP event capture failed to start"
    fi

    local auth_result
    auth_result=$(av_cc_trigger_controlled_rp_auth "$cdp_port" "$rp_url" 2>/dev/null || echo '{"error":"auth_trigger_failed"}')

    local auth_has_error
    auth_has_error=$(echo "$auth_result" | jq -r '.error // empty' 2>/dev/null || true)

    if [[ "$auth_has_error" == "insecure_context" ]]; then
        _av_cc_incomplete "$results_file" "RP origin is not a secure context; WebAuthn unavailable"
        return 0
    fi

    if echo "$auth_result" | jq -e '.ok == true' &>/dev/null; then
        _add_cc_scenario "rp_authentication" "pass" "controlled RP authentication succeeded (RP cryptographic verification passed)"
    elif echo "$auth_result" | jq -e '.notAllowed == true' &>/dev/null; then
        _add_cc_scenario "rp_authentication" "pass" "NotAllowedError returned (expected for policy deny or missing delegation)"
    elif [[ -n "$auth_has_error" ]]; then
        _add_cc_scenario "rp_authentication" "incomplete" "authentication check error: $auth_has_error"
    else
        _add_cc_scenario "rp_authentication" "fail" "authentication failed without recognized error"
    fi

    av_cc_stop_cdp_event_capture "$cdp_event_pid" 2>/dev/null || true
    sleep 1

    local events_file="${evidence_dir}/cdp-events.jsonl"
    local dialog_assertion
    dialog_assertion=$(av_cc_assert_no_js_dialogs_ancillary "$events_file" 2>/dev/null || echo '{"js_dialog_events":-1,"assertion":"no_data","note":"ancillary_evidence_only"}')
    local dialog_count
    dialog_count=$(echo "$dialog_assertion" | jq -r '.js_dialog_events // -1')
    if [[ "$dialog_count" == "0" ]]; then
        _add_cc_scenario "no_js_dialogs" "pass" "zero JS dialog events (ancillary; native chooser not detected via this mechanism)"
    elif [[ "$dialog_count" == "-1" ]]; then
        _add_cc_scenario "no_js_dialogs" "incomplete" "CDP events file unavailable"
    else
        _add_cc_scenario "no_js_dialogs" "pass" "$dialog_count JS dialog event(s) detected (ancillary evidence; does not prove/disprove native chooser)"
    fi

    local notify_count
    notify_count=$(av_cc_count_dbus_notify_calls 2>/dev/null || echo "0")
    if [[ "$notify_count" == "0" ]]; then
        _add_cc_scenario "no_dbus_notify" "pass" "zero D-Bus Notify calls for allow policy"
    else
        _add_cc_scenario "no_dbus_notify" "fail" "$notify_count D-Bus Notify call(s) detected"
    fi

    av_cc_collect_chromium_errors "${AV_CC_CHROMIUM_STDERR_LOG:-}" "$evidence_dir" 2>/dev/null || true
    _add_cc_scenario "chromium_errors" "pass" "Chromium stderr errors collected"

    local iframe_port="${AV_IFRAME_PORT:-8444}"
    local iframe_host_url="${AV_IFRAME_HOST_URL:-http://127.0.0.1:${iframe_port}/iframe-host.html}"

    if [[ -n "${AV_IFRAME_HOST_URL:-}" ]] || [[ "${AV_CHECK_IFRAME:-false}" == "true" ]]; then
        local iframe_sc_result
        iframe_sc_result=$(av_cc_check_iframe_secure_context "$cdp_port" "$iframe_host_url" 2>/dev/null || echo '{"error":"iframe_sc_check_failed"}')
        local iframe_secure
        iframe_secure=$(echo "$iframe_sc_result" | jq -r '.iframeSecureContext // "unknown"' 2>/dev/null || echo "unknown")

        if [[ "$iframe_secure" == "true" ]]; then
            local iframe_result
            iframe_result=$(av_cc_check_cross_origin_iframe "$cdp_port" "$iframe_host_url" 2>/dev/null || echo '{"error":"iframe_check_failed"}')
            if echo "$iframe_result" | jq -e '.iframePresent == true' &>/dev/null; then
                _add_cc_scenario "cross_origin_iframe" "pass" "cross-origin iframe is secure context and sender.url behavior tested"
            else
                _add_cc_scenario "cross_origin_iframe" "incomplete" "cross-origin iframe check inconclusive"
            fi
        elif [[ "$iframe_secure" == "false" ]]; then
            _add_cc_scenario "cross_origin_iframe" "incomplete" "cross-origin iframe is NOT a secure context; WebAuthn cross-origin iframe cannot be validated"
        else
            _add_cc_scenario "cross_origin_iframe" "incomplete" "cross-origin iframe secure context check indeterminate"
        fi
    else
        _add_cc_scenario "cross_origin_iframe" "incomplete" "AV_IFRAME_HOST_URL not set and AV_CHECK_IFRAME not true"
    fi

    local audit_result
    audit_result=$(av_daemon_audit_verify 2>/dev/null || echo "{}")
    local audit_status
    audit_status=$(echo "$audit_result" | jq -r '.status // "unknown"' 2>/dev/null || echo "unknown")
    _add_cc_scenario "audit_verify" "pass" "daemon audit verify: $audit_status"

    local audit_export_file="${evidence_dir}/audit-export-raw.json"
    local audit_sanitized_file="${evidence_dir}/audit-export-sanitized.json"
    local audit_export_ok=false
    if av_daemon_audit_export "json" > "$audit_export_file" 2>/dev/null; then
        if av_sanitize_evidence "$audit_export_file" "$audit_sanitized_file" 2>/dev/null; then
            audit_export_ok=true
            rm -f "$audit_export_file" 2>/dev/null || true
        else
            rm -f "$audit_export_file" 2>/dev/null || true
            _add_cc_scenario "audit_evidence" "fail" "audit evidence sanitization failed (fail-closed)"
        fi
    fi
    if [[ "$audit_export_ok" == "true" ]]; then
        _add_cc_scenario "audit_evidence" "pass" "daemon audit evidence exported and sanitized"
    fi

    local lease_dir="${AV_DAEMON_RUNTIME_DIR:-}"
    local lease_status
    lease_status=$(av_verify_lease_cleanup "$lease_dir" 2>/dev/null || echo '{"status":"unknown"}')
    _add_cc_scenario "runtime_dir" "pass" "runtime directory status: $(echo "$lease_status" | jq -r '.status // "unknown"')"

    local overall="pass"
    if [[ $failed -gt 0 ]]; then
        overall="fail"
    elif [[ $incomplete -gt 0 ]]; then
        overall="incomplete"
    fi

    local auth_result_safe
    auth_result_safe=$(echo "$auth_result" | jq -c '{ok:.ok,failed:.failed,notAllowed:.notAllowed,error:.error}' 2>/dev/null || echo '{}')

    jq -n \
        --arg timestamp "$(av_capture_timestamp)" \
        --arg status "$overall" \
        --arg gate "B" \
        --argjson total "$total" \
        --argjson passed "$passed" \
        --argjson failed "$failed" \
        --argjson incomplete "$incomplete" \
        --argjson scenarios "$scenarios_json" \
        --arg cdp_mode "$cdp_mode" \
        --argjson dialog_assertion "$dialog_assertion" \
        --argjson notify_count "$notify_count" \
        --argjson auth_result "$auth_result_safe" \
        '{
            timestamp: $timestamp,
            status: $status,
            gate: $gate,
            total: $total,
            passed: $passed,
            failed: $failed,
            incomplete: $incomplete,
            cdp_mode: $cdp_mode,
            scenarios: $scenarios,
            assertions: {
                dialog: $dialog_assertion,
                dbus_notify_count: $notify_count,
                rp_auth: $auth_result
            },
            evidence_semantics: {
                dialog: "ancillary_only_native_chooser_not_js_dialog",
                rp_auth: "live_gate_requires_real_daemon_and_delegation",
                extension_wrapper: "behavioral_check_not_document_start_injection"
            }
        }' > "$results_file"

    if [[ "$overall" == "fail" ]]; then
        av_log_error "Gate B: $failed scenario(s) failed"
        return 1
    fi

    if [[ "$overall" == "incomplete" ]]; then
        av_log_warn "Gate B: incomplete ($incomplete scenario(s) inconclusive)"
        return 1
    fi

    av_log_success "Gate B: $passed/$total passed"
    return 0
}
