#!/bin/bash
#
# Controlled RP server utilities for Tier 2 validation
#

set -euo pipefail

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
fi

# shellcheck disable=SC2034
AV_LIB_CONTROLLED_RP_LOADED=true

AV_RP_SERVER_PID=""
AV_RP_SERVER_PORT=""
AV_RP_SERVER_LOG=""
AV_RP_SERVER_DIR=""

av_find_controlled_rp() {
    local validation_dir="${1:-}"

    if [[ -z "$validation_dir" ]]; then
        validation_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    fi

    local rp_dir="${validation_dir}/../agent-uhid-feasibility/controlled-rp"

    if [[ ! -d "$rp_dir" ]]; then
        av_log_error "Controlled RP directory not found: $rp_dir"
        return 1
    fi

    if [[ ! -f "$rp_dir/server.js" ]]; then
        av_log_error "Controlled RP server.js not found"
        return 1
    fi

    if [[ ! -f "$rp_dir/package.json" ]]; then
        av_log_error "Controlled RP package.json not found"
        return 1
    fi

    if [[ ! -d "$rp_dir/node_modules" ]]; then
        av_log_error "Controlled RP node_modules not found (run npm install first)"
        return 1
    fi

    AV_RP_SERVER_DIR="$rp_dir"
    return 0
}

av_start_controlled_rp() {
    local port="${1:-8443}"
    local validation_dir="${2:-}"

    if [[ -z "${AV_RP_SERVER_DIR:-}" ]]; then
        av_find_controlled_rp "$validation_dir" || return 1
    fi

    if ! command -v node &>/dev/null; then
        av_log_error "node not found (required for controlled RP server)"
        return 1
    fi

    AV_RP_SERVER_PORT="$port"
    AV_RP_SERVER_LOG="${EVIDENCE_DIR:-/tmp}/controlled-rp.log"

    (cd "$AV_RP_SERVER_DIR" && PORT="$port" HOST="127.0.0.1" node server.js) \
        > "$AV_RP_SERVER_LOG" 2>&1 &
    AV_RP_SERVER_PID=$!

    av_log_info "Controlled RP server starting (PID=$AV_RP_SERVER_PID, port=$port)..."

    local waited=0
    local max_wait=15
    while [[ $waited -lt $max_wait ]]; do
        if av_controlled_rp_health_check "$port" 2>/dev/null; then
            av_log_success "Controlled RP server ready on port $port"
            return 0
        fi

        if ! kill -0 "$AV_RP_SERVER_PID" 2>/dev/null; then
            av_log_error "Controlled RP server process died"
            if [[ -f "$AV_RP_SERVER_LOG" ]]; then
                av_log_error "Server log: $(tail -5 "$AV_RP_SERVER_LOG" 2>/dev/null || echo '(empty)')"
            fi
            AV_RP_SERVER_PID=""
            return 1
        fi

        sleep 0.5
        ((waited++)) || true
    done

    av_log_error "Controlled RP server did not become ready within ${max_wait}s"
    av_stop_controlled_rp 2>/dev/null || true
    return 1
}

av_stop_controlled_rp() {
    if [[ -n "${AV_RP_SERVER_PID:-}" ]] && kill -0 "$AV_RP_SERVER_PID" 2>/dev/null; then
        kill "$AV_RP_SERVER_PID" 2>/dev/null || true
        local waited=0
        while kill -0 "$AV_RP_SERVER_PID" 2>/dev/null && [[ $waited -lt 5 ]]; do
            sleep 0.5
            ((waited++)) || true
        done
        if kill -0 "$AV_RP_SERVER_PID" 2>/dev/null; then
            kill -9 "$AV_RP_SERVER_PID" 2>/dev/null || true
        fi
    fi
    AV_RP_SERVER_PID=""
    AV_RP_SERVER_PORT=""
}

av_controlled_rp_health_check() {
    local port="${1:-${AV_RP_SERVER_PORT:-}}"
    if [[ -z "$port" ]]; then
        return 1
    fi

    local response
    response=$(curl -s --max-time 2 "http://127.0.0.1:${port}/api/status" 2>/dev/null) || return 1
    echo "$response" | jq -e '.status == "ok"' &>/dev/null
}

av_controlled_rp_register_begin() {
    local port="${1:-${AV_RP_SERVER_PORT:-}}"
    local user_name="${2:-testuser}"
    local user_id="${3:-default-user}"

    curl -s --max-time 10 \
        -X POST \
        -H "Content-Type: application/json" \
        -d "{\"userName\":\"${user_name}\",\"userId\":\"${user_id}\"}" \
        "http://127.0.0.1:${port}/api/register/begin" 2>/dev/null
}

av_controlled_rp_register_finish() {
    local port="${1:-${AV_RP_SERVER_PORT:-}}"
    local payload="$2"

    curl -s --max-time 10 \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$payload" \
        "http://127.0.0.1:${port}/api/register/finish" 2>/dev/null
}

av_controlled_rp_auth_begin() {
    local port="${1:-${AV_RP_SERVER_PORT:-}}"
    local user_id="${2:-}"

    local payload
    if [[ -n "$user_id" ]]; then
        payload="{\"userId\":\"${user_id}\"}"
    else
        payload="{}"
    fi

    curl -s --max-time 10 \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$payload" \
        "http://127.0.0.1:${port}/api/authenticate/begin" 2>/dev/null
}

av_controlled_rp_auth_finish() {
    local port="${1:-${AV_RP_SERVER_PORT:-}}"
    local payload="$2"

    curl -s --max-time 10 \
        -X POST \
        -H "Content-Type: application/json" \
        -d "$payload" \
        "http://127.0.0.1:${port}/api/authenticate/finish" 2>/dev/null
}

av_controlled_rp_status() {
    local port="${1:-${AV_RP_SERVER_PORT:-}}"

    curl -s --max-time 2 "http://127.0.0.1:${port}/api/status" 2>/dev/null
}

av_controlled_rp_prereqs_check() {
    if ! command -v node &>/dev/null; then
        av_log_error "node not found (required for controlled RP server)"
        return 1
    fi

    if ! command -v curl &>/dev/null; then
        av_log_error "curl not found (required for RP API communication)"
        return 1
    fi

    if ! command -v jq &>/dev/null; then
        av_log_error "jq not found (required for JSON processing)"
        return 1
    fi

    return 0
}
