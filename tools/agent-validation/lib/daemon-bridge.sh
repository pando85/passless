#!/bin/bash

set -euo pipefail

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
fi

# shellcheck disable=SC2034
AV_LIB_DAEMON_BRIDGE_LOADED=true

AV_DAEMON_RUNTIME_DIR="${AV_DAEMON_RUNTIME_DIR:-}"
AV_DAEMON_CDP_MODE="${AV_DAEMON_CDP_MODE:-port}"
AV_PASSLESS_BIN="${AV_PASSLESS_BIN:-passless}"
AV_DAEMON_PROFILE="${AV_DAEMON_PROFILE:-}"

av_daemon_prereqs_check() {
    if ! av_command_exists "${AV_PASSLESS_BIN:-passless}"; then
        av_log_error "passless binary not found"
        return 1
    fi

    if ! av_command_exists jq; then
        av_log_error "jq not found"
        return 1
    fi

    if [[ -z "${AV_DAEMON_RUNTIME_DIR:-}" ]]; then
        av_log_error "AV_DAEMON_RUNTIME_DIR not set"
        return 1
    fi

    return 0
}

av_daemon_health_check() {
    local output
    output=$("${AV_PASSLESS_BIN:-passless}" agent-admin --output json audit status 2>/dev/null) || return 1
    echo "$output" | jq -e '.data | has("enabled") and has("entry_count")' &>/dev/null
}

av_daemon_read_cdp_endpoint() {
    local runtime_dir="${1:-${AV_DAEMON_RUNTIME_DIR:-}}"
    if [[ -z "$runtime_dir" ]]; then
        av_log_error "No runtime directory for CDP endpoint"
        return 1
    fi

    local cdp_file="${runtime_dir}/cdp-endpoint"
    if [[ ! -f "$cdp_file" ]]; then
        av_log_error "CDP endpoint file not found: $cdp_file"
        return 1
    fi

    local endpoint
    endpoint=$(<"$cdp_file")
    if [[ -z "$endpoint" ]]; then
        av_log_error "CDP endpoint file is empty"
        return 1
    fi

    echo "$endpoint"
}

av_daemon_get_browser_status() {
    local profile="${1:-${AV_DAEMON_PROFILE:-}}"
    if [[ -z "$profile" ]]; then
        av_log_error "No profile for browser status"
        return 1
    fi

    local output
    output=$("${AV_PASSLESS_BIN:-passless}" agent --profile "$profile" --output json browser-status 2>/dev/null) || {
        av_log_error "Failed to get browser status"
        return 1
    }

    echo "$output"
}

av_daemon_get_endpoint_status() {
    local profile="${1:-${AV_DAEMON_PROFILE:-}}"
    if [[ -z "$profile" ]]; then
        av_log_error "No profile for endpoint status"
        return 1
    fi

    local output
    output=$("${AV_PASSLESS_BIN:-passless}" agent --profile "$profile" --output json endpoint-status 2>/dev/null) || {
        av_log_error "Failed to get endpoint status"
        return 1
    }

    echo "$output"
}

av_daemon_audit_verify() {
    local output
    output=$("${AV_PASSLESS_BIN:-passless}" agent-admin --output json audit verify 2>/dev/null) || {
        av_log_error "Audit verification failed"
        return 1
    }

    echo "$output"
}

av_daemon_audit_export() {
    local format="${1:-json}"
    local output
    output=$("${AV_PASSLESS_BIN:-passless}" agent-admin --output json audit export --format "$format" 2>/dev/null) || {
        av_log_error "Audit export failed"
        return 1
    }

    echo "$output"
}

av_sanitize_evidence() {
    local input_file="$1"
    local output_file="$2"

    if [[ ! -f "$input_file" ]]; then
        return 1
    fi

    local sanitized
    if ! sanitized=$(jq '
        walk(
            if type == "object" then
                with_entries(
                    select(
                        (.key | test("^(raw_|challenge$|assertion$|credential_id$|credential_ref$|user_handle$|bearer$|cookie$|private_key$|secret_key$|auth_token$|pin$)"; "i") | not)
                    )
                )
            else .
            end
        )
    ' "$input_file" 2>/dev/null); then
        av_log_error "Evidence sanitization failed; refusing to write unsanitized data"
        return 1
    fi

    if [[ -z "$sanitized" ]]; then
        av_log_error "Evidence sanitization produced empty output; refusing to write"
        return 1
    fi

    printf '%s\n' "$sanitized" > "$output_file"
}

av_verify_lease_cleanup() {
    local lease_dir="${1:-}"

    if [[ -z "$lease_dir" ]]; then
        return 0
    fi

    if [[ ! -e "$lease_dir" ]]; then
        jq -n '{status:"cleaned",exists:false}'
        return 0
    fi

    if [[ -d "$lease_dir" ]]; then
        local token_count
        token_count=$(find "$lease_dir" -maxdepth 1 -name '*.token' 2>/dev/null | wc -l)
        jq -n --argjson count "$token_count" '{status:"exists",exists:true,type:"directory",token_files:$count}'
        return 0
    fi

    jq -n '{status:"exists",exists:true,type:"file"}'
}

av_daemon_detect_cdp_mode() {
    local profile="${1:-${AV_DAEMON_PROFILE:-}}"

    if [[ -n "$profile" ]]; then
        local browser_status
        browser_status=$(av_daemon_get_browser_status "$profile" 2>/dev/null || echo "{}")
        local cdp_endpoint
        cdp_endpoint=$(echo "$browser_status" | jq -r '.cdp_endpoint // empty' 2>/dev/null || true)
        if [[ -n "$cdp_endpoint" ]]; then
            if [[ "$cdp_endpoint" == ws://* ]]; then
                echo "pipe"
            elif [[ "$cdp_endpoint" == http://* || "$cdp_endpoint" == *"://"* ]]; then
                echo "port"
            else
                echo "port"
            fi
            return 0
        fi
    fi

    local runtime_dir="${AV_DAEMON_RUNTIME_DIR:-}"
    if [[ -n "$runtime_dir" ]] && [[ -f "${runtime_dir}/cdp-endpoint" ]]; then
        local endpoint
        endpoint=$(<"${runtime_dir}/cdp-endpoint")
        if [[ "$endpoint" == *"://127.0.0.1:"* || "$endpoint" == *"://localhost:"* ]]; then
            echo "port"
            return 0
        fi
    fi

    echo "port"
}
