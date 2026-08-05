#!/bin/bash

set -euo pipefail

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
fi

if [[ -z "${AV_LIB_BROWSER_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/browser.sh"
fi

if [[ -z "${AV_LIB_DAEMON_BRIDGE_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/daemon-bridge.sh"
fi

if [[ -z "${AV_LIB_NOTIFICATIONS_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/notifications.sh"
fi

# shellcheck disable=SC2034
AV_LIB_CONTROLLED_CHROMIUM_LOADED=true

AV_CC_CDP_EVENT_CAPTURE="${AV_VALIDATION_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}/browser/cdp-event-capture.js"
AV_CC_DBUS_MONITOR_PID=""
AV_CC_DBUS_NOTIFY_LOG=""
AV_CC_CHROMIUM_STDERR_LOG=""
AV_CC_CDP_EVENT_PID=""
AV_CC_RP_PID=""

av_cc_prereqs_check() {
    local missing=()

    if ! command -v node &>/dev/null; then
        missing+=("node")
    fi

    if ! command -v curl &>/dev/null; then
        missing+=("curl")
    fi

    if ! command -v jq &>/dev/null; then
        missing+=("jq")
    fi

    if ! av_find_chromium 2>/dev/null; then
        missing+=("chromium")
    fi

    if [[ ! -f "${AV_CC_CDP_EVENT_CAPTURE:-}" ]]; then
        missing+=("cdp-event-capture.js")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        av_log_error "Controlled-Chromium prerequisites missing: ${missing[*]}"
        return 1
    fi

    return 0
}

av_cc_verify_daemon_browser_ready() {
    local profile="${1:-${AV_DAEMON_PROFILE:-}}"
    local evidence_dir="${2:-${EVIDENCE_DIR:-/tmp}}"

    if [[ -z "$profile" ]]; then
        av_log_error "No profile specified for daemon browser verification"
        return 1
    fi

    local browser_status
    browser_status=$(av_daemon_get_browser_status "$profile" 2>/dev/null) || {
        av_log_error "Failed to get browser status from daemon"
        return 2
    }

    local running
    running=$(echo "$browser_status" | jq -r '.running // false' 2>/dev/null || echo "false")
    if [[ "$running" != "true" ]]; then
        av_log_error "Daemon reports browser not running"
        return 3
    fi

    local cdp_endpoint
    cdp_endpoint=$(echo "$browser_status" | jq -r '.cdp_endpoint // empty' 2>/dev/null || true)

    if [[ -z "$cdp_endpoint" ]]; then
        cdp_endpoint=$(av_daemon_read_cdp_endpoint 2>/dev/null || true)
    fi

    if [[ -z "$cdp_endpoint" ]]; then
        av_log_error "No CDP endpoint available from daemon"
        return 4
    fi

    local cdp_port=""
    if [[ "$cdp_endpoint" =~ :([0-9]+) ]]; then
        cdp_port="${BASH_REMATCH[1]}"
    fi

    if [[ -z "$cdp_port" ]]; then
        av_log_error "Cannot extract CDP port from endpoint: $cdp_endpoint"
        return 5
    fi

    AV_CDP_PORT="$cdp_port"

    local waited=0
    local max_wait=15
    while [[ $waited -lt $max_wait ]]; do
        if av_cdp_health_check "$cdp_port" 2>/dev/null; then
            av_log_success "Daemon-managed browser ready on CDP port $cdp_port"
            return 0
        fi
        sleep 0.5
        ((waited++)) || true
    done

    av_log_error "CDP port $cdp_port not responsive within ${max_wait}s"
    return 6
}

av_cc_start_dbus_monitor() {
    local evidence_dir="${1:-${EVIDENCE_DIR:-/tmp}}"
    AV_CC_DBUS_NOTIFY_LOG="${evidence_dir}/dbus-notify-capture.log"
    : > "$AV_CC_DBUS_NOTIFY_LOG"

    if ! command -v dbus-monitor &>/dev/null; then
        av_log_warn "dbus-monitor not found; D-Bus Notify monitoring disabled"
        return 0
    fi

    local bus_address="${DBUS_SESSION_BUS_ADDRESS:-}"
    if [[ -z "$bus_address" ]]; then
        av_log_warn "DBUS_SESSION_BUS_ADDRESS not set; D-Bus monitoring disabled"
        return 0
    fi

    dbus-monitor --session "interface=org.freedesktop.Notifications,member=Notify" \
        > "$AV_CC_DBUS_NOTIFY_LOG" 2>/dev/null &
    AV_CC_DBUS_MONITOR_PID=$!

    av_log_info "D-Bus Notify monitor started (PID=$AV_CC_DBUS_MONITOR_PID)"
    return 0
}

av_cc_stop_dbus_monitor() {
    if [[ -n "${AV_CC_DBUS_MONITOR_PID:-}" ]] && kill -0 "$AV_CC_DBUS_MONITOR_PID" 2>/dev/null; then
        kill "$AV_CC_DBUS_MONITOR_PID" 2>/dev/null || true
        local waited=0
        while kill -0 "$AV_CC_DBUS_MONITOR_PID" 2>/dev/null && [[ $waited -lt 3 ]]; do
            sleep 0.3
            ((waited++)) || true
        done
        if kill -0 "$AV_CC_DBUS_MONITOR_PID" 2>/dev/null; then
            kill -9 "$AV_CC_DBUS_MONITOR_PID" 2>/dev/null || true
        fi
    fi
    AV_CC_DBUS_MONITOR_PID=""
}

av_cc_count_dbus_notify_calls() {
    local log_file="${1:-${AV_CC_DBUS_NOTIFY_LOG:-}}"

    if [[ -z "$log_file" || ! -f "$log_file" ]]; then
        echo "0"
        return 0
    fi

    local count
    count=$(grep -c 'member=Notify' "$log_file" 2>/dev/null) || count=0
    echo "$count"
}

av_cc_start_cdp_event_capture() {
    local cdp_port="${1:-${AV_CDP_PORT:-9222}}"
    local evidence_dir="${2:-${EVIDENCE_DIR:-/tmp}}"
    local output_file="${evidence_dir}/cdp-events.jsonl"

    if [[ ! -f "${AV_CC_CDP_EVENT_CAPTURE:-}" ]]; then
        av_log_error "CDP event capture script not found: ${AV_CC_CDP_EVENT_CAPTURE:-}"
        return 1
    fi

    AV_CDP_PORT="$cdp_port" node "$AV_CC_CDP_EVENT_CAPTURE" capture \
        --output "$output_file" \
        --domains "Page,Runtime,Log" \
        > "${evidence_dir}/cdp-event-capture.log" 2>&1 &
    local capture_pid=$!

    sleep 1
    if ! kill -0 "$capture_pid" 2>/dev/null; then
        av_log_error "CDP event capture process died"
        return 1
    fi

    AV_CC_CDP_EVENT_PID="$capture_pid"
    echo "$capture_pid"
    return 0
}

av_cc_stop_cdp_event_capture() {
    local capture_pid="${AV_CC_CDP_EVENT_PID:-}"
    if [[ -n "$capture_pid" ]] && kill -0 "$capture_pid" 2>/dev/null; then
        kill -INT "$capture_pid" 2>/dev/null || true
        sleep 0.5
        if kill -0 "$capture_pid" 2>/dev/null; then
            kill "$capture_pid" 2>/dev/null || true
        fi
    fi
    AV_CC_CDP_EVENT_PID=""
}

av_cc_verify_extension_wrapper_behavior() {
    local cdp_port="${1:-${AV_CDP_PORT:-}}"
    local rp_url="${2:-${AV_RP_URL:-http://127.0.0.1:8443}}"

    if [[ -z "$cdp_port" ]]; then
        av_log_error "No CDP port for extension wrapper verification"
        return 1
    fi

    local check_expr
    check_expr=$(cat << 'JSEOF'
(function(){
    var getStr = navigator.credentials ? navigator.credentials.get.toString() : '';
    var hasNative = getStr.indexOf('[native code]') !== -1;
    return JSON.stringify({
        hasCredentials: !!navigator.credentials,
        hasGet: typeof navigator.credentials.get === 'function',
        getIsNative: hasNative,
        isSecureContext: window.isSecureContext
    });
})()
JSEOF
)

    local check_result
    check_result=$(av_cdp_evaluate "$check_expr" "$cdp_port" 2>/dev/null) || {
        av_log_error "Failed to check extension wrapper state"
        return 1
    }

    local check_value
    check_value=$(echo "$check_result" | jq -r '.value // "{}"' 2>/dev/null || echo "{}")

    local get_is_native
    get_is_native=$(echo "$check_value" | jq -r '.getIsNative // true' 2>/dev/null || echo "true")

    if [[ "$get_is_native" == "false" ]]; then
        echo "$check_value"
        return 0
    fi

    echo "$check_value"
    return 2
}

av_cc_assert_no_js_dialogs_ancillary() {
    local events_file="${1:-}"

    if [[ -z "$events_file" || ! -f "$events_file" ]]; then
        jq -n '{js_dialog_events:0,assertion:"no_data",note:"ancillary_evidence_only"}'
        return 0
    fi

    local dialog_count=0
    if [[ -s "$events_file" ]]; then
        dialog_count=$(grep -c 'javascriptDialogOpening\|javascriptDialogClosed\|Page.dialogOpening' \
            "$events_file" 2>/dev/null) || dialog_count=0
    fi

    jq -n --argjson count "$dialog_count" \
        '{js_dialog_events:$count,assertion:(if $count == 0 then "zero_js_dialogs" else "js_dialogs_detected" end),note:"ancillary_evidence_only_native_chooser_not_detected_by_this"}'
}

av_cc_trigger_controlled_rp_auth() {
    local cdp_port="${1:-${AV_CDP_PORT:-}}"
    local rp_url="${2:-${AV_RP_URL:-http://127.0.0.1:8443}}"

    if ! av_cdp_navigate "$rp_url" "$cdp_port" 2>/dev/null; then
        av_log_error "Navigation to RP failed"
        return 1
    fi

    sleep 2

    local secure_context_expr
    secure_context_expr='(function(){return JSON.stringify({isSecureContext:window.isSecureContext,origin:location.origin})})()'

    local sc_result
    sc_result=$(av_cdp_evaluate "$secure_context_expr" "$cdp_port" 2>/dev/null) || {
        av_log_error "Failed to check secure context"
        return 2
    }

    local sc_value
    sc_value=$(echo "$sc_result" | jq -r '.value // "{}"' 2>/dev/null || echo "{}")

    local is_secure
    is_secure=$(echo "$sc_value" | jq -r '.isSecureContext // false' 2>/dev/null || echo "false")

    if [[ "$is_secure" != "true" ]]; then
        av_log_error "RP origin is not a secure context"
        local sc_detail
        sc_detail=$(echo "$sc_value" | jq -c '.' 2>/dev/null || echo "{}")
        jq -n --argjson detail "$sc_detail" '{error:"insecure_context",detail:$detail}'
        return 3
    fi

    local click_expr
    click_expr=$(cat << 'JSEOF'
(async () => {
    try {
        const btn = document.getElementById('btnAuthenticate');
        if (!btn) return JSON.stringify({error: 'authenticate_button_not_found'});
        btn.click();
        await new Promise(r => setTimeout(r, 10000));
        const log = document.getElementById('log');
        const lines = log ? log.innerText : '';
        const hasOk = lines.includes('AUTH OK');
        const hasFail = lines.includes('AUTH FAIL') || lines.includes('Authentication error');
        const hasNotAllowed = lines.includes('NotAllowedError');
        return JSON.stringify({ok: hasOk, failed: hasFail, notAllowed: hasNotAllowed, logSnippet: lines.slice(-500)});
    } catch(e) {
        return JSON.stringify({error: 'browser_exception', message: e.message});
    }
})()
JSEOF
)

    local eval_result
    eval_result=$(av_cdp_evaluate "$click_expr" "$cdp_port" 2>/dev/null) || {
        av_log_error "CDP evaluate for RP auth failed"
        return 1
    }

    local page_result
    page_result=$(echo "$eval_result" | jq -r '.value // "{}"' 2>/dev/null || echo "{}")
    echo "$page_result"
}

av_cc_collect_chromium_errors() {
    local stderr_log="${1:-${AV_CC_CHROMIUM_STDERR_LOG:-}}"
    local evidence_dir="${2:-${EVIDENCE_DIR:-/tmp}}"
    local errors_file="${evidence_dir}/chromium-errors.json"

    if [[ -z "$stderr_log" || ! -f "$stderr_log" ]]; then
        jq -n '{service_worker_errors:[],content_script_errors:[],other_errors:[],total:0}' > "$errors_file"
        return 0
    fi

    local sw_errors="[]"
    local cs_errors="[]"
    local other_errors="[]"

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if echo "$line" | grep -qi 'service.worker\|service_worker\|sw.js'; then
            sw_errors=$(echo "$sw_errors" | jq --arg l "$line" '. + [$l]')
        elif echo "$line" | grep -qi 'content.script\|content_script'; then
            cs_errors=$(echo "$cs_errors" | jq --arg l "$line" '. + [$l]')
        else
            other_errors=$(echo "$other_errors" | jq --arg l "$line" '. + [$l]')
        fi
    done < <(grep -iE 'error|SEVERE|FATAL|exception|uncaught' "$stderr_log" 2>/dev/null || true)

    local sw_count cs_count other_count
    sw_count=$(echo "$sw_errors" | jq 'length')
    cs_count=$(echo "$cs_errors" | jq 'length')
    other_count=$(echo "$other_errors" | jq 'length')
    local total=$((sw_count + cs_count + other_count))

    jq -n \
        --argjson sw "$sw_errors" \
        --argjson cs "$cs_errors" \
        --argjson other "$other_errors" \
        --argjson total "$total" \
        '{service_worker_errors:$sw,content_script_errors:$cs,other_errors:$other,total:$total}' \
        > "$errors_file"
}

av_cc_check_cross_origin_iframe() {
    local cdp_port="${1:-${AV_CDP_PORT:-}}"
    local host_url="${2:-}"

    if [[ -z "$host_url" || -z "$cdp_port" ]]; then
        av_log_error "Cross-origin iframe check requires host URL and CDP port"
        return 1
    fi

    if ! av_cdp_navigate "$host_url" "$cdp_port" 2>/dev/null; then
        av_log_error "Navigation to iframe host page failed"
        return 1
    fi

    sleep 2

    local iframe_expr
    iframe_expr=$(cat << 'JSEOF'
(async () => {
    try {
        const iframe = document.getElementById('sender-iframe');
        if (!iframe) return JSON.stringify({error: 'iframe_not_found'});
        await new Promise(r => setTimeout(r, 3000));
        const msg = window.__iframe_sender_result || null;
        return JSON.stringify({iframePresent: true, senderResult: msg});
    } catch(e) {
        return JSON.stringify({error: 'iframe_check_exception', message: e.message});
    }
})()
JSEOF
)

    local result
    result=$(av_cdp_evaluate "$iframe_expr" "$cdp_port" 2>/dev/null) || {
        av_log_error "Cross-origin iframe check failed"
        return 1
    }

    echo "$result" | jq -r '.value // "{}"' 2>/dev/null || echo "{}"
}

av_cc_check_iframe_secure_context() {
    local cdp_port="${1:-${AV_CDP_PORT:-}}"
    local host_url="${2:-}"

    if [[ -z "$host_url" || -z "$cdp_port" ]]; then
        return 1
    fi

    if ! av_cdp_navigate "$host_url" "$cdp_port" 2>/dev/null; then
        return 1
    fi

    sleep 2

    local expr
    expr=$(cat << 'JSEOF'
(async () => {
    try {
        const iframe = document.getElementById('sender-iframe');
        if (!iframe) return JSON.stringify({error: 'iframe_not_found'});
        await new Promise(r => setTimeout(r, 2000));
        const msg = window.__iframe_sender_result || null;
        var isSecure = null;
        if (msg && msg.isSecureContext !== undefined) isSecure = msg.isSecureContext;
        return JSON.stringify({iframePresent: true, iframeSecureContext: isSecure, senderResult: msg});
    } catch(e) {
        return JSON.stringify({error: 'iframe_secure_check_exception', message: e.message});
    }
})()
JSEOF
)

    local result
    result=$(av_cdp_evaluate "$expr" "$cdp_port" 2>/dev/null) || {
        return 1
    }

    echo "$result" | jq -r '.value // "{}"' 2>/dev/null || echo "{}"
}

av_cc_cleanup_all() {
    av_cc_stop_cdp_event_capture 2>/dev/null || true
    av_cc_stop_dbus_monitor 2>/dev/null || true
    if [[ -n "${AV_CC_RP_PID:-}" ]] && kill -0 "$AV_CC_RP_PID" 2>/dev/null; then
        kill "$AV_CC_RP_PID" 2>/dev/null || true
        AV_CC_RP_PID=""
    fi
}
