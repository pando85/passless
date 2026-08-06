#!/bin/bash
#
# Shared utilities for agent-validation Tier 3 stages
#

# shellcheck disable=SC2034
AV_LIB_COMMON_LOADED=true

AV_COLOR_RESET='\033[0m'
AV_COLOR_RED='\033[0;31m'
AV_COLOR_GREEN='\033[0;32m'
AV_COLOR_YELLOW='\033[1;33m'
AV_COLOR_BLUE='\033[0;34m'

av_is_dry_run() {
    [[ "${PASSLESS_VALIDATION_DRY_RUN:-0}" == "1" ]]
}

av_json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

av_write_json() {
    local file="$1"
    local json="$2"
    if command -v jq &>/dev/null; then
        printf '%s' "$json" | jq '.' > "$file" 2>/dev/null || printf '%s\n' "$json" > "$file"
    else
        printf '%s\n' "$json" > "$file"
    fi
}

av_command_exists() {
    command -v "$1" &>/dev/null
}

av_log_info() {
    echo -e "${AV_COLOR_BLUE}[T3-INFO]${AV_COLOR_RESET} $*" >&2
}

av_log_success() {
    echo -e "${AV_COLOR_GREEN}[T3-OK]${AV_COLOR_RESET} $*" >&2
}

av_log_warn() {
    echo -e "${AV_COLOR_YELLOW}[T3-WARN]${AV_COLOR_RESET} $*" >&2
}

av_log_error() {
    echo -e "${AV_COLOR_RED}[T3-ERR]${AV_COLOR_RESET} $*" >&2
}

av_resolve_phase0_dir() {
    local validation_dir="${1:-}"
    if [[ -z "$validation_dir" ]]; then
        validation_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    fi
    local phase0_dir="${validation_dir}/../agent-uhid-feasibility"
    if [[ -d "$phase0_dir" ]]; then
        printf '%s' "$(cd "$phase0_dir" && pwd)"
        return 0
    fi
    return 1
}

av_sanitize_path() {
    local p="$1"
    printf '%s' "${p//$HOME/~}"
}

av_capture_timestamp() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}
