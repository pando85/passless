#!/bin/bash

set -euo pipefail

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/common.sh"
fi
if [[ -z "${AV_LIB_BROWSER_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/browser.sh"
fi
if [[ -z "${AV_LIB_CONTROLLED_RP_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/controlled-rp.sh"
fi

# shellcheck disable=SC2034
AV_STAGE_AGENT_CEREMONIES_LOADED=true

_av_ceremony_skip() {
    local results_file="$1"
    local reason="$2"
    jq -n --arg reason "$reason" '{status:"skipped",reason:$reason}' > "$results_file"
    # shellcheck disable=SC2034 # consumed by run_stage in the orchestrator
    STAGE_SKIPPED=true
}

_av_wait_event() {
    local path="$1"
    local timeout_secs="$2"
    local waited=0
    while [[ "$waited" -lt $((timeout_secs * 10)) ]]; do
        [[ -s "$path" ]] && return 0
        sleep 0.1
        ((waited++)) || true
    done
    return 1
}

_av_start_prompt_approver() {
    local delay_secs="${AV_PROMPT_APPROVAL_DELAY_SECS:-2}"
    (
        while true; do
            local count
            count=$(dunstctl count 2>/dev/null || echo 0)
            if [[ "$count" =~ ^[0-9]+$ && "$count" -gt 0 ]]; then
                sleep "$delay_secs"
                dunstctl action 0 >/dev/null 2>&1 || true
            else
                sleep 0.1
            fi
        done
    ) &
    AV_PROMPT_APPROVER_PID=$!
}

_av_stop_ceremony_processes() {
    if [[ -n "${AV_PROMPT_APPROVER_PID:-}" ]] && kill -0 "$AV_PROMPT_APPROVER_PID" 2>/dev/null; then
        kill "$AV_PROMPT_APPROVER_PID" 2>/dev/null || true
        wait "$AV_PROMPT_APPROVER_PID" 2>/dev/null || true
    fi
    av_stop_chromium 2>/dev/null || true
    if [[ "${AV_CEREMONY_OWNS_RP:-false}" == "true" ]]; then
        av_stop_controlled_rp 2>/dev/null || true
    fi
}

_av_run_principal() {
    local profile="$1"
    shift
    if [[ "${AV_AGENT_ADMIN_USE_SUDO:-0}" == "1" ]]; then
        sudo --preserve-env=PASSLESS_AGENT_RUNTIME_DIR -- env "$@" \
            "$AV_PASSLESS_BIN" agent run --profile "$profile" -- "$AV_PRINCIPAL_DRIVER"
    else
        env "$@" "$AV_PASSLESS_BIN" agent run --profile "$profile" -- "$AV_PRINCIPAL_DRIVER"
    fi
}

stage_agent_ceremonies() {
    local results_file="${EVIDENCE_DIR:-/tmp}/agent-ceremonies-results.json"
    local passless_bin="${AV_PASSLESS_BIN:-}"
    local isolated_profile="${AV_ISOLATED_PROFILE_ID:-}"
    local delegated_profile="${AV_DELEGATED_PROFILE_ID:-}"
    local rp_id="${AV_RP_ID:-}"
    local rp_url="${AV_RP_URL:-}"
    local browser_user="${AV_BROWSER_USER:-}"
    local principal_user="${AV_PRINCIPAL_USER:-}"
    local shared_root="${AV_SHARED_RUNTIME_ROOT:-}"
    local driver="${AV_VALIDATION_DIR:-}/browser/principal-driver.sh"
    local timeout_secs="${AV_FLOW_TIMEOUT_SECS:-90}"

    if [[ -n "${PASSLESS_E2E_AUTO_ACCEPT_UV:-}" || -n "${PASSLESS_E2E_AUTO_ACCEPT_STORAGE:-}" ]]; then
        _av_ceremony_skip "$results_file" "debug auto-accept environment is set"
        return 0
    fi

    if [[ -z "$passless_bin" || -z "$isolated_profile" || -z "$delegated_profile" \
        || -z "$rp_id" || -z "$rp_url" || -z "$browser_user" \
        || -z "$principal_user" || -z "$shared_root" ]]; then
        _av_ceremony_skip "$results_file" "live ceremony variables are incomplete"
        return 0
    fi
    if [[ "$passless_bin" != /* || ! -x "$passless_bin" || ! -x "$driver" ]]; then
        _av_ceremony_skip "$results_file" "validation binaries are unavailable"
        return 0
    fi
    if [[ "$shared_root" != /* || ! -d "$shared_root" || -L "$shared_root" ]]; then
        _av_ceremony_skip "$results_file" "AV_SHARED_RUNTIME_ROOT is not a prepared absolute directory"
        return 0
    fi
    if ! id "$browser_user" &>/dev/null || ! av_find_chromium \
        || ! command -v node &>/dev/null || ! command -v dunstctl &>/dev/null; then
        _av_ceremony_skip "$results_file" "browser identity, Chromium, Node, or dunst is unavailable"
        return 0
    fi
    if ! dunstctl running 2>/dev/null | grep -Eqi 'true|yes|1|running'; then
        _av_ceremony_skip "$results_file" "the daemon and dunst must share the active D-Bus session"
        return 0
    fi

    local rp_port="${AV_RP_PORT:?AV_RP_PORT is required}"
    AV_CEREMONY_OWNS_RP=false
    if ! av_controlled_rp_health_check "$rp_port" 2>/dev/null; then
        if ! av_start_controlled_rp "$rp_port" "${AV_VALIDATION_DIR:-}"; then
            _av_ceremony_skip "$results_file" "controlled RP could not start"
            return 0
        fi
        AV_CEREMONY_OWNS_RP=true
    fi

    export AV_PASSLESS_BIN="$passless_bin"
    export AV_PRINCIPAL_DRIVER="$driver"

    local coord_root="${shared_root}/ceremonies-${RUN_ID:-manual}"
    mkdir -p "$coord_root"
    chmod 711 "$coord_root"

    _av_start_prompt_approver
    trap _av_stop_ceremony_processes RETURN

    local cdp_port="${AV_CDP_PORT:-9222}"
    mkdir -p "$coord_root/chromium"
    if [[ $EUID -eq 0 ]]; then
        chown "$browser_user" "$coord_root/chromium"
    else
        sudo -- chown "$browser_user" "$coord_root/chromium"
    fi
    chmod 700 "$coord_root/chromium"
    AV_BROWSER_USER="$browser_user" av_start_chromium_headless "$cdp_port" "$coord_root/chromium"
    av_cdp_navigate "$rp_url" "$cdp_port" >/dev/null

    local isolated_dir="$coord_root/isolated"
    mkdir -p "$isolated_dir"
    local principal_gid
    principal_gid=$(id -g "$principal_user")
    if [[ $EUID -eq 0 ]]; then
        chown "$(id -u):$principal_gid" "$isolated_dir"
    else
        sudo -- chown "$(id -u):$principal_gid" "$isolated_dir"
    fi
    chmod 770 "$isolated_dir"

    _av_run_principal "$isolated_profile" \
        AV_PASSLESS_BIN="$passless_bin" AV_PROFILE_ID="$isolated_profile" AV_RP_ID="$rp_id" \
        AV_PRINCIPAL_FLOW=isolated AV_COORD_DIR="$isolated_dir" \
        >"$isolated_dir/result.json" 2>"$isolated_dir/launch.stderr" &
    local isolated_pid=$!

    _av_wait_event "$isolated_dir/register_ready.json" "$timeout_secs" \
        && AV_CDP_PORT="$cdp_port" AV_RP_URL="$rp_url" AV_EVIDENCE_DIR="$coord_root" \
            "${AV_VALIDATION_DIR}/browser/cdp-driver.sh" register >/dev/null
    _av_wait_event "$isolated_dir/authenticate_ready.json" "$timeout_secs" \
        && AV_CDP_PORT="$cdp_port" AV_RP_URL="$rp_url" AV_EVIDENCE_DIR="$coord_root" \
            "${AV_VALIDATION_DIR}/browser/cdp-driver.sh" authenticate >/dev/null
    wait "$isolated_pid"
    jq -e '.flow == "isolated" and .registration == "approved" and .authentication == "approved"' \
        "$isolated_dir/result.json" >/dev/null

    local delegated_dir="$coord_root/delegated"
    mkdir -p "$delegated_dir"
    if [[ $EUID -eq 0 ]]; then
        chown "$(id -u):$principal_gid" "$delegated_dir"
    else
        sudo -- chown "$(id -u):$principal_gid" "$delegated_dir"
    fi
    chmod 770 "$delegated_dir"

    _av_run_principal "$delegated_profile" \
        AV_PASSLESS_BIN="$passless_bin" AV_PROFILE_ID="$delegated_profile" AV_RP_ID="$rp_id" \
        AV_PRINCIPAL_FLOW=delegated \
        AV_COORD_DIR="$delegated_dir" \
        >"$delegated_dir/result.json" 2>"$delegated_dir/launch.stderr"
    jq -e '.flow == "delegated" and .authentication == "approved" and .second_assertion == "denied" \
        and .wrong_rp == "denied" and .wrong_credential == "denied"' \
        "$delegated_dir/result.json" >/dev/null

    jq -n '{status:"passed",isolated:{registration:"approved",authentication:"approved"},delegated:{authentication:"approved",second_assertion:"denied",wrong_rp:"denied",wrong_credential:"denied"}}' \
        > "$results_file"
}
