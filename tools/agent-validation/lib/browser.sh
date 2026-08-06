#!/bin/bash
#
# Browser/CDP utilities for Tier 2 validation
# Calls real Node CDP client using WebSocket protocol
#

set -euo pipefail

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
fi

# shellcheck disable=SC2034
AV_LIB_BROWSER_LOADED=true

AV_CHROMIUM_BIN=""
AV_CHROMIUM_PID=""
AV_CDP_PORT=""
AV_CDP_USER_DATA_DIR=""
AV_CDP_CLIENT="${AV_VALIDATION_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}/browser/cdp-client.js"

av_find_chromium() {
    local bin
    for bin in chromium chromium-browser google-chrome; do
        if command -v "$bin" &>/dev/null; then
            AV_CHROMIUM_BIN="$bin"
            return 0
        fi
    done
    return 1
}

av_chromium_version() {
    if [[ -z "${AV_CHROMIUM_BIN:-}" ]]; then
        av_find_chromium || return 1
    fi
    "$AV_CHROMIUM_BIN" --version 2>/dev/null | head -n1
}

av_start_chromium_headless() {
    local port="${1:-9222}"
    local user_data_dir="${2:-}"

    if [[ -z "${AV_CHROMIUM_BIN:-}" ]]; then
        av_find_chromium || return 1
    fi

    if [[ -z "$user_data_dir" ]]; then
        user_data_dir="${TEMP_ROOT:-/tmp}/chromium-profile-$$"
    fi
    mkdir -p "$user_data_dir"
    chmod 700 "$user_data_dir"

    AV_CDP_PORT="$port"
    AV_CDP_USER_DATA_DIR="$user_data_dir"

    local browser_cmd=("$AV_CHROMIUM_BIN" \
        --headless=new \
        --disable-gpu \
        --disable-dev-shm-usage \
        --disable-extensions \
        --remote-debugging-port="$port" \
        --user-data-dir="$user_data_dir" \
        --no-first-run \
        --no-default-browser-check \
        --disable-background-networking \
        --disable-sync \
        --disable-translate \
        about:blank)

    if [[ -n "${AV_BROWSER_USER:-}" ]]; then
        if ! id "$AV_BROWSER_USER" &>/dev/null; then
            av_log_error "Browser user does not exist: $AV_BROWSER_USER"
            return 1
        fi
        if [[ ! -d "$user_data_dir" || "$(stat -c '%U' "$user_data_dir")" != "$AV_BROWSER_USER" ]]; then
            av_log_error "Browser profile is not owned by $AV_BROWSER_USER: $user_data_dir"
            return 1
        fi
        if [[ $EUID -eq 0 ]]; then
            runuser -u "$AV_BROWSER_USER" -- "${browser_cmd[@]}" &>/dev/null &
        else
            sudo -- runuser -u "$AV_BROWSER_USER" -- "${browser_cmd[@]}" &>/dev/null &
        fi
    else
        "${browser_cmd[@]}" &>/dev/null &
    fi
    AV_CHROMIUM_PID=$!

    local waited=0
    local max_wait=10
    while [[ $waited -lt $max_wait ]]; do
        if av_cdp_health_check "$port" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
        ((waited++)) || true
    done

    av_log_error "Chromium did not become ready on CDP port $port within ${max_wait}s"
    av_stop_chromium 2>/dev/null || true
    return 1
}

av_stop_chromium() {
    if [[ -n "${AV_CHROMIUM_PID:-}" ]] && kill -0 "$AV_CHROMIUM_PID" 2>/dev/null; then
        kill "$AV_CHROMIUM_PID" 2>/dev/null || true
        local waited=0
        while kill -0 "$AV_CHROMIUM_PID" 2>/dev/null && [[ $waited -lt 10 ]]; do
            sleep 0.5
            ((waited++)) || true
        done
        if kill -0 "$AV_CHROMIUM_PID" 2>/dev/null; then
            kill -9 "$AV_CHROMIUM_PID" 2>/dev/null || true
        fi
    fi
    AV_CHROMIUM_PID=""

    if [[ -n "${AV_CDP_USER_DATA_DIR:-}" ]] && [[ -d "${AV_CDP_USER_DATA_DIR:-}" ]]; then
        rm -rf "${AV_CDP_USER_DATA_DIR}" 2>/dev/null || true
    fi
    AV_CDP_USER_DATA_DIR=""
    AV_CDP_PORT=""
}

av_cdp_health_check() {
    local port="${1:-${AV_CDP_PORT:-}}"
    if [[ -z "$port" ]]; then
        return 1
    fi

    if [[ ! -f "$AV_CDP_CLIENT" ]]; then
        av_log_error "CDP client not found: $AV_CDP_CLIENT"
        return 1
    fi

    local result
    result=$(AV_CDP_PORT="$port" node "$AV_CDP_CLIENT" health 2>&1) || return 1
    echo "$result" | jq -e '.connected == true' &>/dev/null
}

av_cdp_send() {
    local method="$1"
    local params="${2:-{}}"
    local port="${3:-${AV_CDP_PORT:-}}"

    if [[ -z "$port" ]]; then
        av_log_error "No CDP port specified"
        return 1
    fi

    if [[ ! -f "$AV_CDP_CLIENT" ]]; then
        av_log_error "CDP client not found: $AV_CDP_CLIENT"
        return 1
    fi

    local result
    result=$(AV_CDP_PORT="$port" node "$AV_CDP_CLIENT" send "$method" "$params" 2>&1) || {
        av_log_error "CDP send failed: $result"
        return 1
    }

    echo "$result"
}

av_cdp_navigate() {
    local url="$1"
    local port="${2:-${AV_CDP_PORT:-}}"

    if [[ -z "$port" ]]; then
        av_log_error "No CDP port specified"
        return 1
    fi

    if [[ ! -f "$AV_CDP_CLIENT" ]]; then
        av_log_error "CDP client not found: $AV_CDP_CLIENT"
        return 1
    fi

    local result
    result=$(AV_CDP_PORT="$port" node "$AV_CDP_CLIENT" navigate "$url" 2>&1) || {
        av_log_error "CDP navigate failed: $result"
        return 1
    }

    if echo "$result" | jq -e '.status == "ok"' &>/dev/null; then
        return 0
    else
        av_log_error "CDP navigate returned error: $result"
        return 1
    fi
}

av_cdp_evaluate() {
    local expression="$1"
    local port="${2:-${AV_CDP_PORT:-}}"

    if [[ -z "$port" ]]; then
        av_log_error "No CDP port specified"
        return 1
    fi

    if [[ ! -f "$AV_CDP_CLIENT" ]]; then
        av_log_error "CDP client not found: $AV_CDP_CLIENT"
        return 1
    fi

    local result
    result=$(AV_CDP_PORT="$port" node "$AV_CDP_CLIENT" evaluate "$expression" 2>&1) || {
        av_log_error "CDP evaluate failed"
        return 1
    }

    if echo "$result" | jq -e '.type' &>/dev/null; then
        echo "$result"
        return 0
    else
        av_log_error "CDP evaluate returned an invalid result"
        return 1
    fi
}

av_wait_for_page_text() {
    local text="$1"
    local timeout_secs="${2:-30}"
    local port="${3:-${AV_CDP_PORT:-}}"

    local waited=0
    while [[ $waited -lt $timeout_secs ]]; do
        local check_expr="document.body.innerText.includes('$text')"
        local result
        result=$(av_cdp_evaluate "$check_expr" "$port" 2>/dev/null) || true
        if echo "$result" | jq -e '.value == true' &>/dev/null; then
            return 0
        fi
        sleep 1
        ((waited++)) || true
    done

    av_log_error "Timed out waiting for text: $text"
    return 1
}

av_chromium_prereqs_check() {
    if ! av_find_chromium; then
        av_log_error "No Chromium browser found (chromium, chromium-browser, or google-chrome)"
        return 1
    fi

    if ! command -v node &>/dev/null; then
        av_log_error "node not found (required for CDP client)"
        return 1
    fi

    if ! command -v curl &>/dev/null; then
        av_log_error "curl not found (required for CDP communication)"
        return 1
    fi

    if ! command -v jq &>/dev/null; then
        av_log_error "jq not found (required for JSON processing)"
        return 1
    fi

    if [[ ! -f "${AV_CDP_CLIENT:-}" ]]; then
        av_log_error "CDP client not found: ${AV_CDP_CLIENT:-}"
        return 1
    fi

    return 0
}
