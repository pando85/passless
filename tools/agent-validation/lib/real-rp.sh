#!/bin/bash

set -euo pipefail

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
fi

if [[ -z "${AV_LIB_DAEMON_BRIDGE_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/daemon-bridge.sh"
fi

if [[ -z "${AV_LIB_BROWSER_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/browser.sh"
fi

# shellcheck disable=SC2034
AV_LIB_REAL_RP_LOADED=true

AV_REAL_RP_URL="${AV_REAL_RP_URL:-https://tea.millaguie.net}"
AV_REAL_RP_CREDENTIAL_REF="${AV_REAL_RP_CREDENTIAL_REF:-}"
# shellcheck disable=SC2034
AV_REAL_RP_DRIVER="${AV_REAL_RP_DRIVER:-${AV_VALIDATION_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}/browser/real-rp-driver.js}"
AV_GC_DBUS_MONITOR_PID=""
AV_GC_DBUS_NOTIFY_LOG=""
AV_GC_CDP_EVENT_PID=""

av_gc_env_check() {
    local missing=()
    if [[ -z "${AV_PASSLESS_BIN:-}" ]]; then
        missing+=("AV_PASSLESS_BIN")
    fi
    if [[ -z "${AV_DAEMON_PROFILE:-}" ]]; then
        missing+=("AV_DAEMON_PROFILE")
    fi
    if [[ -z "${AV_DAEMON_RUNTIME_DIR:-}" ]]; then
        missing+=("AV_DAEMON_RUNTIME_DIR")
    fi
    if [[ -z "${AV_REAL_RP_CREDENTIAL_REF:-}" ]]; then
        missing+=("AV_REAL_RP_CREDENTIAL_REF")
    fi
    if [[ ${#missing[@]} -gt 0 ]]; then
        av_log_error "Gate C env vars missing: ${missing[*]}"
        return 1
    fi
    if [[ ! -x "${AV_PASSLESS_BIN}" ]] && ! command -v "${AV_PASSLESS_BIN}" &>/dev/null; then
        av_log_error "passless binary not found or not executable: ${AV_PASSLESS_BIN}"
        return 1
    fi
    return 0
}

av_gc_real_rp_reachable() {
    local url="${1:-${AV_REAL_RP_URL:-https://tea.millaguie.net}}"
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$url" 2>/dev/null) || code="000"
    if [[ "$code" == "000" ]]; then
        av_log_error "Real RP not reachable: $url"
        return 1
    fi
    if [[ "$code" =~ ^[23] ]]; then
        return 0
    fi
    av_log_error "Real RP returned HTTP $code: $url"
    return 1
}

av_gc_get_cdp_port() {
    local profile="${1:-${AV_DAEMON_PROFILE:-}}"
    local runtime_dir="${2:-${AV_DAEMON_RUNTIME_DIR:-}}"

    local browser_status
    if ! browser_status=$("${AV_PASSLESS_BIN:-passless}" agent --profile "$profile" --output json browser-status 2>/dev/null); then
        av_log_error "browser-status failed"
        return 2
    fi

    local running
    running=$(echo "$browser_status" | jq -r '.running // false' 2>/dev/null || echo "false")
    if [[ "$running" != "true" ]]; then
        av_log_error "Daemon reports browser not running"
        return 3
    fi

    local cdp_endpoint
    cdp_endpoint=$(echo "$browser_status" | jq -r '.cdp_endpoint // empty' 2>/dev/null || true)

    if [[ -z "$cdp_endpoint" ]] && [[ -n "$runtime_dir" ]] && [[ -f "${runtime_dir}/cdp-endpoint" ]]; then
        cdp_endpoint=$(<"${runtime_dir}/cdp-endpoint")
    fi

    if [[ -z "$cdp_endpoint" ]]; then
        av_log_error "No CDP endpoint from daemon"
        return 4
    fi

    if [[ "$cdp_endpoint" == *"unix"* ]] || [[ "$cdp_endpoint" == *"pipe"* ]]; then
        echo "pipe"
        return 5
    fi

    local cdp_port=""
    if [[ "$cdp_endpoint" =~ :([0-9]+) ]]; then
        cdp_port="${BASH_REMATCH[1]}"
    fi

    if [[ -z "$cdp_port" ]]; then
        av_log_error "Cannot extract CDP port from: $cdp_endpoint"
        return 6
    fi

    echo "$cdp_port"
}

av_gc_start_dbus_monitor() {
    local evidence_dir="${1:-${EVIDENCE_DIR:-/tmp}}"
    AV_GC_DBUS_NOTIFY_LOG="${evidence_dir}/gc-dbus-notify.log"
    : > "$AV_GC_DBUS_NOTIFY_LOG"

    if ! command -v dbus-monitor &>/dev/null; then
        return 0
    fi

    local bus_address="${DBUS_SESSION_BUS_ADDRESS:-}"
    if [[ -z "$bus_address" ]]; then
        return 0
    fi

    dbus-monitor --session "interface=org.freedesktop.Notifications,member=Notify" \
        > "$AV_GC_DBUS_NOTIFY_LOG" 2>/dev/null &
    AV_GC_DBUS_MONITOR_PID=$!
    return 0
}

av_gc_stop_dbus_monitor() {
    if [[ -n "${AV_GC_DBUS_MONITOR_PID:-}" ]] && kill -0 "$AV_GC_DBUS_MONITOR_PID" 2>/dev/null; then
        kill "$AV_GC_DBUS_MONITOR_PID" 2>/dev/null || true
        local waited=0
        while kill -0 "$AV_GC_DBUS_MONITOR_PID" 2>/dev/null && [[ $waited -lt 3 ]]; do
            sleep 0.3
            ((waited++)) || true
        done
        if kill -0 "$AV_GC_DBUS_MONITOR_PID" 2>/dev/null; then
            kill -9 "$AV_GC_DBUS_MONITOR_PID" 2>/dev/null || true
        fi
    fi
    AV_GC_DBUS_MONITOR_PID=""
}

av_gc_count_dbus_notify() {
    local log_file="${1:-${AV_GC_DBUS_NOTIFY_LOG:-}}"
    if [[ -z "$log_file" || ! -f "$log_file" ]]; then
        echo "0"
        return 0
    fi
    local count
    count=$(grep -c 'member=Notify' "$log_file" 2>/dev/null) || count=0
    echo "$count"
}

av_gc_start_cdp_capture() {
    local cdp_port="${1:-${AV_CDP_PORT:-9222}}"
    local evidence_dir="${2:-${EVIDENCE_DIR:-/tmp}}"
    local output_file="${evidence_dir}/gc-cdp-events.jsonl"
    local capture_script="${AV_VALIDATION_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}/browser/cdp-event-capture.js"

    if [[ ! -f "$capture_script" ]]; then
        return 1
    fi

    AV_CDP_PORT="$cdp_port" node "$capture_script" capture \
        --output "$output_file" \
        --domains "Page,Runtime,Log" \
        > "${evidence_dir}/gc-cdp-capture.log" 2>&1 &
    local capture_pid=$!

    sleep 1
    if ! kill -0 "$capture_pid" 2>/dev/null; then
        return 1
    fi

    AV_GC_CDP_EVENT_PID="$capture_pid"
    echo "$capture_pid"
    return 0
}

av_gc_stop_cdp_capture() {
    local capture_pid="${1:-${AV_GC_CDP_EVENT_PID:-}}"
    if [[ -n "$capture_pid" ]] && kill -0 "$capture_pid" 2>/dev/null; then
        kill -INT "$capture_pid" 2>/dev/null || true
        sleep 0.5
        if kill -0 "$capture_pid" 2>/dev/null; then
            kill "$capture_pid" 2>/dev/null || true
        fi
    fi
    AV_GC_CDP_EVENT_PID=""
}

av_gc_verify_no_forbidden_cdp() {
    local events_file="${1:-}"
    if [[ -z "$events_file" || ! -f "$events_file" ]]; then
        jq -n '{forbidden_calls:0,assertion:"no_data"}'
        return 0
    fi

    local count=0
    count=$(grep -cE 'WebAuthn\.enable|addVirtualAuthenticator|addCredential' \
        "$events_file" 2>/dev/null) || count=0

    jq -n --argjson count "$count" \
        '{forbidden_calls:$count,assertion:(if $count == 0 then "zero_forbidden_webauthn_cdp" else "forbidden_webauthn_cdp_detected" end)}'
}

av_gc_sanitize_audit_export() {
    local evidence_dir="${1:-${EVIDENCE_DIR:-/tmp}}"
    local raw_file="${evidence_dir}/gc-audit-raw.json"
    local sanitized_file="${evidence_dir}/gc-audit-sanitized.json"

    if ! "${AV_PASSLESS_BIN:-passless}" agent-admin --output json audit export --format json > "$raw_file" 2>/dev/null; then
        av_log_error "Audit export failed"
        rm -f "$raw_file" 2>/dev/null || true
        return 1
    fi

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
        av_log_error "Audit sanitization failed; writing nothing"
        rm -f "$raw_file" 2>/dev/null || true
        return 1
    fi

    if [[ -z "$sanitized" ]]; then
        av_log_error "Audit sanitization produced empty output; writing nothing"
        rm -f "$raw_file" 2>/dev/null || true
        return 1
    fi

    printf '%s\n' "$sanitized" > "$sanitized_file"
    rm -f "$raw_file" 2>/dev/null || true

    if [[ ! -s "$sanitized_file" ]]; then
        rm -f "$sanitized_file" 2>/dev/null || true
        return 1
    fi

    return 0
}

av_gc_check_wrong_origin_feasible() {
    jq -n '{status:"incomplete",reason:"wrong-origin scenario requires test fixture with alternate RP ID; not available in MVP"}'
}

av_gc_check_expired_grant_feasible() {
    jq -n '{status:"incomplete",reason:"expired-grant scenario requires short-TTL grant fixture; not available in MVP"}'
}

av_gc_cleanup() {
    av_gc_stop_cdp_capture 2>/dev/null || true
    av_gc_stop_dbus_monitor 2>/dev/null || true
}
