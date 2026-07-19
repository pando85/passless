#!/bin/bash
#
# Passless Agent Validation Orchestrator
#

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
RUN_ID=""
EVIDENCE_DIR=""
LOG_FILE=""
STATE_FILE=""
TEMP_ROOT=""
START_TIME=$(date -u +%Y%m%d-%H%M%S)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

EXIT_SUCCESS=0
EXIT_PREFLIGHT_FAILED=1
EXIT_STAGE_FAILED=2
EXIT_INVALID_ARGS=3
EXIT_CLEANUP_FAILED=4
EXIT_ROOT_DENIED=5
EXIT_INCOMPLETE=6

REGISTERED_RESOURCES=()
RESOURCE_COUNT=0

STAGE_SKIPPED=false

AV_VALIDATION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for _av_lib in "${AV_VALIDATION_DIR}/lib/"*.sh; do
    # shellcheck disable=SC1090
    [[ -f "$_av_lib" ]] && source "$_av_lib"
done
for _av_stage in "${AV_VALIDATION_DIR}/stages/"*.sh; do
    # shellcheck disable=SC1090
    [[ -f "$_av_stage" ]] && source "$_av_stage"
done
unset _av_lib _av_stage

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*" | (tee -a "${LOG_FILE:-/dev/null}" 2>/dev/null || true) >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*" | (tee -a "${LOG_FILE:-/dev/null}" 2>/dev/null || true) >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" | (tee -a "${LOG_FILE:-/dev/null}" 2>/dev/null || true) >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" | (tee -a "${LOG_FILE:-/dev/null}" 2>/dev/null || true) >&2
}

usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

Options:
    --preflight             Run preflight checks only
    --automated             Run automated tests only (Tier 1 and Tier 2)
    --release               Run full release validation (Tier 1, Tier 2, and Tier 3)
    --allow-dirty           Allow --release from a dirty worktree and record that limitation
    --cleanup <run-id>      Clean up registered host resources (preserves evidence)
    --delete-evidence <run-id>  Delete evidence directory (requires confirmation)
    --help                  Show this help message

Environment variables:
    RUN_ID_PREFIX           Prefix for the run ID (default: agent-validation)
    EVIDENCE_BASE_DIR       Base directory for evidence (default: target/agent-validation)
EOF
}

ALLOWED_CLEANUP_ACTIONS=("remove_temp_file" "remove_test_socket" "remove_test_udev_rule")

validate_cleanup_target() {
    local action="$1"
    local target="$2"
    local temp_root="${3:-}"

    case "$action" in
        remove_temp_file|remove_test_socket)
            if [[ -z "$temp_root" ]]; then
                log_error "No temp root configured for action: $action"
                return 1
            fi

            if [[ ! -d "$temp_root" ]]; then
                log_error "Temp root does not exist: $temp_root"
                return 1
            fi

            local canonical_target
            canonical_target=$(realpath -m "$target" 2>/dev/null) || {
                log_error "Cannot canonicalize target: $target"
                return 1
            }

            local canonical_temp_root
            canonical_temp_root=$(realpath "$temp_root" 2>/dev/null) || {
                log_error "Cannot canonicalize temp root: $temp_root"
                return 1
            }

            if [[ "$canonical_target" != "$canonical_temp_root"/* ]]; then
                log_error "Target not beneath temp root: $target (must be under $temp_root)"
                return 1
            fi

            if [[ -L "$target" ]]; then
                log_error "Target is a symlink (unsafe): $target"
                return 1
            fi
            ;;
        remove_test_udev_rule)
            if [[ ! "$target" =~ ^/etc/udev/rules.d/99-agent-validation-test-[a-zA-Z0-9][a-zA-Z0-9._-]{0,255}\.rules$ ]] \
                || [[ "$(basename "$target")" == *..* ]]; then
                log_error "Invalid test udev rule path: $target (must match /etc/udev/rules.d/99-agent-validation-test-*.rules)"
                return 1
            fi

            if [[ -L "$target" ]]; then
                log_error "Target is a symlink (unsafe): $target"
                return 1
            fi
            ;;
        *)
            log_error "Unknown cleanup action: $action"
            return 1
            ;;
    esac

    return 0
}

dispatch_cleanup_action() {
    local action="$1"
    local target="$2"
    local temp_root="${3:-}"
    local is_allowed=false

    for allowed in "${ALLOWED_CLEANUP_ACTIONS[@]}"; do
        if [[ "$action" == "$allowed" ]]; then
            is_allowed=true
            break
        fi
    done

    if [[ "$is_allowed" != true ]]; then
        log_error "Cleanup action not in allowlist: $action"
        return 1
    fi

    if ! validate_cleanup_target "$action" "$target" "$temp_root"; then
        log_error "Cleanup target validation failed for $action:$target"
        return 1
    fi

    case "$action" in
        remove_temp_file)
            if [[ -f "$target" ]]; then
                rm -f -- "$target"
                log_info "Removed temp file: $target"
            fi
            ;;
        remove_test_socket)
            if [[ -S "$target" ]]; then
                rm -f -- "$target"
                log_info "Removed test socket: $target"
            fi
            ;;
        remove_test_udev_rule)
            if [[ -f "$target" ]]; then
                if [[ $EUID -eq 0 ]]; then
                    rm -f -- "$target"
                    log_info "Removed test udev rule: $target"
                elif av_check_sudo_binary_exists 2>/dev/null; then
                    sudo -- rm -f -- "$target"
                    log_info "Removed test udev rule: $target"
                else
                    log_error "Cannot remove test udev rule (no sudo): $target"
                    return 1
                fi
            fi
            ;;
    esac
    return 0
}

# shellcheck disable=SC2329
register_resource() {
    local action="$1"
    local target="$2"

    REGISTERED_RESOURCES+=("${action}:${target}")
    ((RESOURCE_COUNT++)) || true

    if [[ -n "${STATE_FILE:-}" ]] && [[ -f "${STATE_FILE:-}" ]]; then
        local temp_state="${STATE_FILE}.tmp"
        jq --arg action "$action" --arg target "$target" \
            '.resources += [{"action": $action, "target": $target}] | .resource_count = (.resources | length)' \
            "$STATE_FILE" > "$temp_state" 2>/dev/null && mv "$temp_state" "$STATE_FILE"
    fi
}

create_state_file() {
    local state_path="$1"
    local run_id="$2"
    local temp_root="$3"

    jq -n \
        --arg run_id "$run_id" \
        --arg created "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --arg temp_root "$temp_root" \
        '{run_id: $run_id, created: $created, temp_root: $temp_root, resources: [], resource_count: 0, finalized: false, cleanup_completed: false}' \
        > "$state_path"

    chmod 600 "$state_path"
    STATE_FILE="$state_path"
}

finalize_state_file() {
    if [[ -n "${STATE_FILE:-}" ]] && [[ -f "${STATE_FILE:-}" ]]; then
        local temp_state="${STATE_FILE}.tmp"
        jq '.finalized = true | .finalized_at = (now | todate)' \
            "$STATE_FILE" > "$temp_state" 2>/dev/null && mv "$temp_state" "$STATE_FILE"
    fi
}

mark_cleanup_completed() {
    local state_path="$1"
    if [[ -f "$state_path" ]]; then
        local temp_state="${state_path}.tmp"
        jq '.cleanup_completed = true | .cleanup_completed_at = (now | todate)' \
            "$state_path" > "$temp_state" 2>/dev/null && mv "$temp_state" "$state_path"
    fi
}

# shellcheck disable=SC2329
cleanup_host_resources() {
    local cleanup_count=0
    local cleanup_failed=false

    if [[ ${#REGISTERED_RESOURCES[@]} -eq 0 ]]; then
        log_info "No registered host resources to clean up (0 resources)"
        return 0
    fi

    log_info "Cleaning up ${#REGISTERED_RESOURCES[@]} registered host resource(s)..."

    for entry in "${REGISTERED_RESOURCES[@]}"; do
        local action="${entry%%:*}"
        local target="${entry#*:}"
        if dispatch_cleanup_action "$action" "$target" "${TEMP_ROOT:-}"; then
            ((cleanup_count++)) || true
        else
            cleanup_failed=true
        fi
    done

    if [[ "$cleanup_failed" == true ]]; then
        log_error "Host resource cleanup incomplete: $cleanup_count of ${#REGISTERED_RESOURCES[@]} resources cleaned"
    else
        log_success "Host resource cleanup completed: $cleanup_count of ${#REGISTERED_RESOURCES[@]} resources cleaned"
    fi
    REGISTERED_RESOURCES=()
    RESOURCE_COUNT=0
    [[ "$cleanup_failed" == false ]]
}

trap cleanup_host_resources EXIT

validate_run_id() {
    local run_id="$1"

    if [[ -z "$run_id" ]]; then
        log_error "Run ID is empty"
        return 1
    fi

    if [[ ${#run_id} -gt 256 ]]; then
        log_error "Run ID exceeds maximum length (256): ${#run_id}"
        return 1
    fi

    if [[ ! "$run_id" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]]; then
        log_error "Run ID contains invalid characters (only alphanumeric, hyphen, underscore, dot allowed; must start with alphanumeric): $run_id"
        return 1
    fi

    if [[ "$run_id" == "." ]] || [[ "$run_id" == ".." ]]; then
        log_error "Run ID is a reserved name: $run_id"
        return 1
    fi

    if [[ "$run_id" == */* ]] || [[ "$run_id" == *\\* ]]; then
        log_error "Run ID contains path separator: $run_id"
        return 1
    fi

    return 0
}

validate_safe_path() {
    local path="$1"
    local base_dir="$2"

    if [[ ! -d "$base_dir" ]]; then
        log_error "Base directory does not exist: $base_dir"
        return 1
    fi

    local normalized_base
    normalized_base=$(realpath "$base_dir" 2>/dev/null) || {
        log_error "Cannot resolve base directory: $base_dir"
        return 1
    }

    local normalized_path
    normalized_path=$(realpath -m "$path" 2>/dev/null) || {
        log_error "Cannot resolve path: $path"
        return 1
    }

    if [[ "$normalized_path" == "$normalized_base" ]]; then
        log_error "Path equals base directory (not a subdirectory): $path"
        return 1
    fi

    if [[ ! "$normalized_path" =~ ^"$normalized_base"/ ]]; then
        log_error "Unsafe path detected: $path (not beneath $base_dir)"
        return 1
    fi

    local absolute_path
    if [[ "$path" == /* ]]; then
        absolute_path="$path"
    else
        absolute_path="$(pwd)/$path"
    fi

    local check_path=""
    IFS='/' read -ra path_components <<< "$absolute_path"
    for component in "${path_components[@]}"; do
        if [[ -z "$component" ]] || [[ "$component" == "." ]]; then
            continue
        fi
        if [[ -z "$check_path" ]]; then
            check_path="/$component"
        else
            check_path="$check_path/$component"
        fi

        if [[ "$check_path" == "$normalized_base" ]] || [[ "$check_path" == "$normalized_base/"* ]]; then
            if [[ -L "$check_path" ]]; then
                log_error "Symlink in path chain: $check_path"
                return 1
            fi
        fi
    done

    if [[ -L "$normalized_path" ]]; then
        log_error "Target path is a symlink: $normalized_path"
        return 1
    fi

    return 0
}

check_base_ownership() {
    local base_dir="$1"

    if [[ ! -d "$base_dir" ]]; then
        log_error "Base directory does not exist: $base_dir"
        return 1
    fi

    local base_owner
    base_owner=$(stat -c '%u' "$base_dir" 2>/dev/null) || {
        log_error "Cannot stat base directory: $base_dir"
        return 1
    }

    local current_uid
    current_uid=$(id -u)

    if [[ "$base_owner" != "$current_uid" ]] && [[ "$current_uid" -ne 0 ]]; then
        log_error "Base directory owned by UID $base_owner, current UID is $current_uid"
        return 1
    fi

    local base_perms
    base_perms=$(stat -c '%a' "$base_dir" 2>/dev/null) || {
        log_error "Cannot stat base directory permissions: $base_dir"
        return 1
    }

    if [[ "$base_perms" == *7* ]] && [[ "${base_perms: -1}" -ge 7 ]]; then
        log_warn "Base directory has world-writable permissions: $base_perms"
    fi

    return 0
}

initialize_run() {
    local mode="$1"

    if [[ "$mode" != "cleanup" ]] && [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        log_error "This orchestrator should not run as root. Use narrowly scoped privileged helpers instead."
        exit $EXIT_ROOT_DENIED
    fi

    if [[ -z "${RUN_ID:-}" ]]; then
        RUN_ID="${RUN_ID_PREFIX:-agent-validation}-${START_TIME}-$(openssl rand -hex 4 2>/dev/null || date +%s%N)"
    fi

    if ! validate_run_id "$RUN_ID"; then
        log_error "Generated or provided RUN_ID is invalid: $RUN_ID"
        exit $EXIT_INVALID_ARGS
    fi

    local evidence_base_dir="${EVIDENCE_BASE_DIR:-target/agent-validation}"
    mkdir -p "$evidence_base_dir"

    if ! check_base_ownership "$evidence_base_dir"; then
        log_error "Evidence base directory ownership check failed"
        exit $EXIT_INVALID_ARGS
    fi

    EVIDENCE_DIR="${evidence_base_dir}/${RUN_ID}"

    if ! validate_safe_path "$EVIDENCE_DIR" "$evidence_base_dir"; then
        log_error "Invalid evidence directory path"
        exit $EXIT_INVALID_ARGS
    fi

    mkdir -p "$EVIDENCE_DIR"
    chmod 700 "$EVIDENCE_DIR"

    TEMP_ROOT="${EVIDENCE_DIR}/tmp"
    mkdir -p "$TEMP_ROOT"
    chmod 700 "$TEMP_ROOT"

    LOG_FILE="${EVIDENCE_DIR}/orchestrator.log"

    local report_file="${EVIDENCE_DIR}/report.json"
    jq -n '{}' > "$report_file"

    create_state_file "${EVIDENCE_DIR}/state.json" "$RUN_ID" "$TEMP_ROOT"

    log_info "Initialized run with ID: $RUN_ID"
    log_info "Evidence directory: $EVIDENCE_DIR"
    log_info "Temp root: $TEMP_ROOT"
}

run_preflight() {
    local mode="${1:-release}"

    log_info "Running preflight checks for $mode mode..."

    local all_passed=true

    local required_tools=("bash" "cargo" "rustc" "git" "jq" "timeout" "dbus-daemon")

    local release_required_tools=(
        "systemctl" "sudo" "dbus-run-session" "dunst" "dunstctl" "Xvfb"
        "node" "curl" "udevadm" "pass" "gpg" "swtpm" "shellcheck"
    )

    for tool in "${required_tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            log_info "Found required tool: $tool"
        else
            log_error "Required tool not found: $tool"
            all_passed=false
        fi
    done

    if [[ "$mode" == "release" ]]; then
        for tool in "${release_required_tools[@]}"; do
            if command -v "$tool" &> /dev/null; then
                log_info "Found release-required tool: $tool"
            else
                log_error "Release-required tool not found: $tool (required for --release mode)"
                all_passed=false
            fi
        done

        if ! command -v chromium &>/dev/null \
            && ! command -v chromium-browser &>/dev/null \
            && ! command -v google-chrome &>/dev/null; then
            log_error "No Chromium browser found (chromium, chromium-browser, or google-chrome required for --release mode)"
            all_passed=false
        fi

        if ! dbus-run-session -- true &>/dev/null; then
            log_error "Unable to create an isolated D-Bus session (required for --release mode)"
            all_passed=false
        else
            log_info "Isolated D-Bus session available"
        fi

        if [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then
            if [[ "${ALLOW_DIRTY_LAB:-false}" == true ]]; then
                log_warn "Release validation is running from an explicitly allowed dirty worktree"
            else
                log_error "Dirty worktree refused; commit/stash changes or pass --allow-dirty"
                all_passed=false
            fi
        fi
    fi

    local arch
    arch=$(uname -m)
    local os
    os=$(uname -s)

    if [[ "$mode" == "release" ]]; then
        if [[ "$arch" != "x86_64" ]] && [[ "$arch" != "amd64" ]]; then
            log_error "Architecture is not x86_64: $arch (required for release mode)"
            all_passed=false
        else
            log_info "Architecture check passed: $arch"
        fi

        if [[ "$os" != "Linux" ]]; then
            log_error "OS is not Linux: $os (required for release mode)"
            all_passed=false
        else
            log_info "OS check passed: $os"
        fi

        if ! systemctl --version &>/dev/null; then
            log_error "systemd not available (required for release mode)"
            all_passed=false
        else
            log_info "systemd available"
        fi

        if [[ ! -e /dev/uhid ]]; then
            log_error "/dev/uhid not accessible (required for release mode)"
            all_passed=false
        else
            log_info "UHID device accessible"
        fi

        if [[ ! -f /sys/fs/cgroup/cgroup.controllers ]]; then
            log_error "cgroup v2 not detected (required for release mode)"
            all_passed=false
        else
            log_info "cgroup v2 detected"
        fi
    else
        if [[ "$arch" != "x86_64" ]] && [[ "$arch" != "amd64" ]]; then
            log_warn "Architecture is not x86_64: $arch"
        fi

        if [[ "$os" != "Linux" ]]; then
            log_warn "OS is not Linux: $os"
        fi
    fi

    if ! cargo --version &>/dev/null; then
        log_error "Rust/Cargo not available"
        all_passed=false
    else
        log_info "Rust/Cargo available"
    fi

    if [[ "$all_passed" == false ]]; then
        return 1
    fi

    log_success "Preflight checks passed for $mode mode"
    return 0
}

capture_environment() {
    log_info "Capturing environment manifest..."

    local env_file="${EVIDENCE_DIR}/environment.json"

    local git_commit
    git_commit=$(git rev-parse HEAD 2>/dev/null || echo 'unknown')
    local git_dirty
    if [[ -z $(git status --porcelain 2>/dev/null | head -c 1) ]]; then
        git_dirty=false
    else
        git_dirty=true
    fi
    local os
    os=$(uname -s)
    local arch
    arch=$(uname -m)
    local kernel_version
    kernel_version=$(uname -r 2>/dev/null || echo 'unknown')
    local rust_version
    rust_version=$(rustc --version 2>/dev/null | head -n1 || echo 'unavailable')
    local cargo_version
    cargo_version=$(cargo --version 2>/dev/null | head -n1 || echo 'unavailable')
    local systemd_version
    systemd_version=$(systemctl --version 2>/dev/null | head -n1 | cut -d' ' -f2- 2>/dev/null || echo 'unavailable')
    local chromium_version
    chromium_version=$(chromium --version 2>/dev/null | head -n1 || chromium-browser --version 2>/dev/null | head -n1 || google-chrome --version 2>/dev/null | head -n1 || echo 'unavailable')
    local cgroup_version
    if [[ -f /sys/fs/cgroup/cgroup.controllers ]]; then
        cgroup_version='cgroup_v2'
    elif [[ -d /sys/fs/cgroup/systemd ]]; then
        cgroup_version='cgroup_v1'
    else
        cgroup_version='unknown'
    fi
    local pass_version
    pass_version=$(pass --version 2>/dev/null | head -n1 2>/dev/null || echo 'unavailable')
    local gpg_version
    gpg_version=$(gpg --version 2>/dev/null | head -n1 2>/dev/null || echo 'unavailable')
    local swtpm_version
    swtpm_version=$(swtpm --version 2>/dev/null | head -n1 2>/dev/null || echo 'unavailable')
    local dbus_version
    dbus_version=$(dbus-daemon --version 2>&1 | head -n1 || echo 'unavailable')
    local notify_daemon
    notify_daemon=$(dunst --version 2>&1 | head -n1 || echo 'unavailable')
    local distribution
    distribution=$(grep '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"' || echo 'unavailable')
    local libc_version
    libc_version=$(ldd --version 2>&1 | head -n1 || echo 'unavailable')
    local udev_version
    udev_version=$(udevadm --version 2>/dev/null || echo 'unavailable')

    jq -n \
        --arg run_id "$RUN_ID" \
        --arg start_time "$START_TIME" \
        --arg git_commit "$git_commit" \
        --argjson git_dirty "$git_dirty" \
        --arg os "$os" \
        --arg arch "$arch" \
        --arg kernel_version "$kernel_version" \
        --arg rust_version "$rust_version" \
        --arg cargo_version "$cargo_version" \
        --arg systemd_version "$systemd_version" \
        --arg chromium_version "$chromium_version" \
        --arg cgroup_version "$cgroup_version" \
        --arg pass_version "$pass_version" \
        --arg gpg_version "$gpg_version" \
        --arg swtpm_version "$swtpm_version" \
        --arg dbus_version "$dbus_version" \
        --arg notify_daemon "$notify_daemon" \
        --arg distribution "$distribution" \
        --arg libc_version "$libc_version" \
        --arg udev_version "$udev_version" \
        --arg feature_set "all-features,agent-validation" \
        --arg temp_root "${TEMP_ROOT:-}" \
        '{
          run_id: $run_id,
          start_time: $start_time,
          git_commit: $git_commit,
          git_dirty: $git_dirty,
          os: $os,
          architecture: $arch,
          kernel_version: $kernel_version,
          rust_version: $rust_version,
          cargo_version: $cargo_version,
          systemd_version: $systemd_version,
          chromium_version: $chromium_version,
          cgroup_version: $cgroup_version,
          pass_version: $pass_version,
          gpg_version: $gpg_version,
          swtpm_version: $swtpm_version,
          dbus_version: $dbus_version,
          notify_daemon: $notify_daemon,
          distribution: $distribution,
          libc_version: $libc_version,
          udev_version: $udev_version,
          feature_set: $feature_set,
          temp_root: $temp_root
        }' > "$env_file"

    log_success "Environment manifest saved to $env_file"
}

run_stage() {
    local stage_name="$1"
    local stage_func="$2"
    local stage_description="${3:-Stage $stage_name}"
    local required="${4:-true}"

    log_info "Starting: $stage_description ($stage_name)"

    local stage_start
    stage_start=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local status="RUNNING"
    local error_msg=""
    STAGE_SKIPPED=false

    if "$stage_func"; then
        if [[ "${STAGE_SKIPPED}" == "true" ]]; then
            status="SKIP"
            error_msg="Prerequisites not met (honest skip)"
            log_warn "Skipped: $stage_description ($stage_name) - prerequisites unavailable"
        else
            status="PASS"
            log_success "Completed: $stage_description ($stage_name)"
        fi
    else
        status="FAIL"
        error_msg="Stage $stage_name failed"
        log_error "Failed: $stage_description ($stage_name)"
    fi

    local stage_end
    stage_end=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    local report_file="${EVIDENCE_DIR}/report.json"
    local temp_report="${report_file}.tmp"

    jq -s '.[0] * {stages: (.[0].stages // []) + [{name: $name, description: $desc, start_time: $start, end_time: $end, status: $status, required: $required, error_msg: $error}]}' \
        --arg name "$stage_name" \
        --arg desc "$stage_description" \
        --arg start "$stage_start" \
        --arg end "$stage_end" \
        --arg status "$status" \
        --argjson required "$required" \
        --arg error_msg "$error_msg" \
        "$report_file" /dev/null > "$temp_report" 2>/dev/null || {
            echo '{}' | jq -s '.[0] * {stages: [{name: $name, description: $desc, start_time: $start, end_time: $end, status: $status, required: $required, error_msg: $error}]}' \
                --arg name "$stage_name" \
                --arg desc "$stage_description" \
                --arg start "$stage_start" \
                --arg end "$stage_end" \
                --arg status "$status" \
                --argjson required "$required" \
                --arg error_msg "$error_msg" > "$temp_report"
        }
    mv "$temp_report" "$report_file"

    if [[ "$status" == "FAIL" ]]; then
        return 1
    fi

    if [[ "$status" == "SKIP" ]] && [[ "$required" == "true" ]]; then
        return 1
    fi

    return 0
}

# shellcheck disable=SC2329
skip_stage() {
    local stage_name="$1"
    local stage_description="${2:-Stage $stage_name}"
    local required="${3:-false}"

    log_warn "Skipping: $stage_description ($stage_name) - PLACEHOLDER"

    local stage_start
    stage_start=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local stage_end="$stage_start"
    local status="SKIP"
    local error_msg="Implementation not yet available"

    local report_file="${EVIDENCE_DIR}/report.json"
    local temp_report="${report_file}.tmp"

    jq -s '.[0] * {stages: (.[0].stages // []) + [{name: $name, description: $desc, start_time: $start, end_time: $end, status: $status, required: $required, error_msg: $error}]}' \
        --arg name "$stage_name" \
        --arg desc "$stage_description" \
        --arg start "$stage_start" \
        --arg end "$stage_end" \
        --arg status "$status" \
        --argjson required "$required" \
        --arg error_msg "$error_msg" \
        "$report_file" /dev/null > "$temp_report" 2>/dev/null || {
            echo '{}' | jq -s '.[0] * {stages: [{name: $name, description: $desc, start_time: $start, end_time: $end, status: $status, required: $required, error_msg: $error}]}' \
                --arg name "$stage_name" \
                --arg desc "$stage_description" \
                --arg start "$stage_start" \
                --arg end "$stage_end" \
                --arg status "$status" \
                --argjson required "$required" \
                --arg error_msg "$error_msg" > "$temp_report"
        }
    mv "$temp_report" "$report_file"

    return 0
}

run_tier1_tests() {
    log_info "Running Tier 1: Deterministic automated tests"

    run_stage "fmt-check" "stage_fmt_check" "Code formatting check (cargo fmt --all)" || return $?
    run_stage "clippy-check" "stage_clippy_check" "Linter check (cargo clippy)" || return $?
    run_stage "all-feature-tests" "stage_all_feature_tests" "All-feature unit and integration tests" || return $?
    run_stage "doc-check" "stage_doc_check" "Documentation link check" || return $?
    run_stage "prompt-protocol" "stage_prompt_protocol" "Production prompt protocol tests (D-Bus)" || return $?
    run_stage "agent-policy" "stage_agent_policy" "Agent policy and authorization tests" || return $?
    run_stage "backend-composition" "stage_backend_composition" "Local, pass, and swtpm agent storage composition" || return $?

    run_stage "transport-boundary" "stage_transport_boundary" "Test-only CTAP response UP/UV observer" || return $?
    run_stage "secret-scanning" "stage_secret_scanning" "Secret scanning in logs" "true" || return $?
    run_stage "fault-injection" "stage_fault_injection" "Fault injection tests" "true" || return $?

    log_success "Tier 1 tests completed"
}

run_tier2_tests() {
    log_info "Running Tier 2: Automated browser session"

    run_stage "real-notifications" "stage_real_notifications" "Real notification tests (dunst + dunstctl)" "true" || return $?
    run_stage "controlled-rp" "stage_controlled_rp" "Controlled RP tests" "true" || return $?
    run_stage "agent-ceremonies" "stage_agent_ceremonies" "Agent ceremony tests" "true" || return $?
    run_stage "browser-lease" "stage_browser_lease" "Browser lease tests" "true" || return $?

    log_success "Tier 2 tests completed"
}

run_tier3_tests() {
    log_info "Running Tier 3: Privileged release lab (requires explicit confirmation)"

    read -r -p "This will run privileged operations. Continue? (yes/no): " response
    if [[ ! "$response" =~ ^[Yy]([Ee][Ss])?$ ]]; then
        log_error "Tier 3 tests declined by user - release workflow is incomplete"
        return 1
    fi

    run_stage "privileged-setup" "stage_privileged_setup" "Privileged setup (Phase0 + test udev)" "true" || return $?
    run_stage "principal-isolation" "stage_principal_isolation" "Principal isolation (UID/GID/ns/cgroup/NnP/caps)" "true" || return $?
    run_stage "device-probes" "stage_device_probes" "Device policy and cross-identity probes" "true" || return $?
    run_stage "uninstall-rehearsal" "stage_uninstall_rehearsal" "Uninstall rehearsal (teardown/rollback)" "true" || return $?
    run_stage "lab-safety" "stage_lab_safety" "Lab safety and final inventory" "true" || return $?

    log_success "Tier 3 tests completed"
}

# shellcheck disable=SC2329
stage_fmt_check() {
    log_info "Running cargo fmt --all -- --check..."
    cargo fmt --all -- --check
}

# shellcheck disable=SC2329
stage_clippy_check() {
    log_info "Running cargo clippy..."
    cargo clippy --all-targets --all-features -- -D warnings
}

# shellcheck disable=SC2329
stage_all_feature_tests() {
    log_info "Running cargo test --all-features..."
    cargo test --all-features
}

# shellcheck disable=SC2329
stage_doc_check() {
    log_info "Checking documentation..."
    if command -v make &>/dev/null && [[ -f "Makefile" ]]; then
        make check-doc-links
    else
        cargo doc --no-deps --document-private-items
    fi
}

# shellcheck disable=SC2329
stage_prompt_protocol() {
    log_info "Running production DesktopPromptHandle tests on a private D-Bus..."
    timeout 60s cargo test --all-features -p passless-rs --bin passless \
        agent::prompt::dbus_tests -- --test-threads=1
}

# shellcheck disable=SC2329
stage_agent_policy() {
    log_info "Running focused agent policy and authorization tests..."
    cargo test --all-features -p passless-core agent::policy
    cargo test --all-features -p passless-rs --bin passless agent::policy_engine
}

# shellcheck disable=SC2329
stage_transport_boundary() {
    log_info "Running non-secret CTAP response observer tests..."
    cargo test --all-features -p passless-rs --bin passless ceremony_observer -- --test-threads=1
}

# shellcheck disable=SC2329
stage_backend_composition() {
    log_info "Running local agent storage composition tests..."
    cargo test --all-features -p passless-rs --bin passless \
        agent::storage_factory::tests::composition_conformance -- --test-threads=1

    local required=(gpg pass swtpm)
    local missing=()
    local command
    for command in "${required[@]}"; do
        command -v "$command" &>/dev/null || missing+=("$command")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_warn "Backend composition prerequisites unavailable: ${missing[*]}"
        STAGE_SKIPPED=true
        return 0
    fi

    local tests=(
        agent::storage_factory::tests::composition_conformance::pass_composition_full_flow
        agent::storage_factory::tests::composition_conformance::tpm_composition::tpm_composition_full_flow
        agent::storage_factory::tests::composition_conformance::tpm_composition::tpm_profile_isolation
        agent::storage_factory::tests::composition_conformance::tpm_composition::tpm_cleanup_propagation
    )
    local test_name
    for test_name in "${tests[@]}"; do
        cargo test --all-features -p passless-rs --bin passless "$test_name" -- \
            --exact --ignored --test-threads=1
    done
}

generate_final_report() {
    log_info "Generating final report..."

    local report_file="${EVIDENCE_DIR}/report.json"
    local markdown_report="${EVIDENCE_DIR}/report.md"

    local overall_status="INCOMPLETE"
    local has_failures=false
    local has_skips_required=false

    if jq -e '.stages[] | select(.status == "FAIL")' "$report_file" >/dev/null 2>&1; then
        has_failures=true
    fi

    if jq -e '.stages[] | select(.status == "SKIP" and .required == true)' "$report_file" >/dev/null 2>&1; then
        has_skips_required=true
    fi

    if [[ "$has_failures" == true ]]; then
        overall_status="FAIL"
    elif [[ "$has_skips_required" == true ]]; then
        overall_status="INCOMPLETE"
    else
        local required_stages_count
        required_stages_count=$(jq -r '[.stages[] | select(.required == true)] | length' "$report_file" 2>/dev/null || echo "0")

        local required_passed_count
        required_passed_count=$(jq -r '[.stages[] | select(.required == true and .status == "PASS")] | length' "$report_file" 2>/dev/null || echo "0")

        if [[ "$required_stages_count" -eq "$required_passed_count" ]] && [[ "$required_stages_count" -gt 0 ]]; then
            overall_status="PASS"
        else
            overall_status="INCOMPLETE"
        fi
    fi

    local temp_report="${report_file}.tmp"
    jq -s '.[0] * {summary: {run_id: $run_id, start_time: $start, end_time: $end, status: $status}}' \
        --arg run_id "$RUN_ID" \
        --arg start "$START_TIME" \
        --arg end "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --arg status "$overall_status" \
        "$report_file" /dev/null > "$temp_report" 2>/dev/null || {
            echo '{}' | jq -s '.[0] * {summary: {run_id: $run_id, start_time: $start, end_time: $end, status: $status}}' \
                --arg run_id "$RUN_ID" \
                --arg start "$START_TIME" \
                --arg end "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
                --arg status "$overall_status" > "$temp_report"
        }
    mv "$temp_report" "$report_file"

    local end_time
    end_time=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    {
        echo "# Agent Validation Report"
        echo ""
        echo "## Run Information"
        echo "- Run ID: $RUN_ID"
        echo "- Start Time: $START_TIME"
        echo "- End Time: $end_time"
        echo "- Overall Status: $overall_status"
        echo ""
        echo "## Environment"
        echo '```json'
        jq -r '.' "${EVIDENCE_DIR}/environment.json" 2>/dev/null || echo "{}"
        echo '```'
        echo ""
        echo "## Stage Results"
    } > "$markdown_report"

    if jq -e '.stages | length > 0' "$report_file" >/dev/null 2>&1; then
        jq -r '.stages[] | "- **\(.name)**: \(.status) (\(.description)) [Required: \(.required)]"' "$report_file" >> "$markdown_report" 2>/dev/null || echo "No stage results found" >> "$markdown_report"
    else
        echo "No stage results found" >> "$markdown_report"
    fi

    {
        echo ""
        echo ""
        echo "## Summary"
        echo "Overall validation status: $overall_status"
    } >> "$markdown_report"

    log_success "Final report saved to $markdown_report"
    log_info "Evidence preserved in: $EVIDENCE_DIR"
}

run_cleanup() {
    local cleanup_run_id="$1"

    if [[ -z "$cleanup_run_id" ]]; then
        log_error "Run ID required for cleanup"
        exit $EXIT_INVALID_ARGS
    fi

    if ! validate_run_id "$cleanup_run_id"; then
        log_error "Invalid run ID for cleanup: $cleanup_run_id"
        exit $EXIT_CLEANUP_FAILED
    fi

    local evidence_base_dir="${EVIDENCE_BASE_DIR:-target/agent-validation}"

    if [[ ! -d "$evidence_base_dir" ]]; then
        log_error "Evidence base directory does not exist: $evidence_base_dir"
        exit $EXIT_CLEANUP_FAILED
    fi

    if ! check_base_ownership "$evidence_base_dir"; then
        log_error "Evidence base directory ownership check failed"
        exit $EXIT_CLEANUP_FAILED
    fi

    local cleanup_evidence_dir="${evidence_base_dir}/${cleanup_run_id}"

    if ! validate_safe_path "$cleanup_evidence_dir" "$evidence_base_dir"; then
        log_error "Cleanup path validation failed for: $cleanup_run_id"
        exit $EXIT_CLEANUP_FAILED
    fi

    local canonical_target
    canonical_target=$(realpath -m "$cleanup_evidence_dir" 2>/dev/null) || {
        log_error "Cannot canonicalize cleanup path"
        exit $EXIT_CLEANUP_FAILED
    }

    local canonical_base
    canonical_base=$(realpath "$evidence_base_dir" 2>/dev/null) || {
        log_error "Cannot canonicalize evidence base"
        exit $EXIT_CLEANUP_FAILED
    }

    if [[ "$canonical_target" == "$canonical_base" ]]; then
        log_error "Refusing to clean the evidence base directory itself"
        exit $EXIT_CLEANUP_FAILED
    fi

    if [[ "$canonical_target" != "$canonical_base"/* ]]; then
        log_error "Canonicalized path is not beneath evidence base: $canonical_target"
        exit $EXIT_CLEANUP_FAILED
    fi

    if [[ ! -d "$canonical_target" ]]; then
        log_error "Evidence directory not found: $canonical_target"
        exit $EXIT_CLEANUP_FAILED
    fi

    local state_file="$canonical_target/state.json"
    if [[ -f "$state_file" ]]; then
        if ! jq empty "$state_file" 2>/dev/null; then
            log_error "Invalid JSON in state file: $state_file"
            exit $EXIT_CLEANUP_FAILED
        fi

        if ! jq -e '
            (.run_id | type == "string") and
            (.temp_root | type == "string") and
            (.resources | type == "array") and
            (.resource_count | type == "number") and
            (.resource_count == (.resources | length)) and
            (all(.resources[]?; (.action | type == "string") and (.target | type == "string")))
        ' "$state_file" >/dev/null; then
            log_error "State file schema is invalid: $state_file"
            exit $EXIT_CLEANUP_FAILED
        fi

        local recorded_run_id
        recorded_run_id=$(jq -r '.run_id // empty' "$state_file" 2>/dev/null || echo "")
        if [[ -n "$recorded_run_id" ]] && [[ "$recorded_run_id" != "$cleanup_run_id" ]]; then
            log_error "Run ID mismatch in state file: expected $cleanup_run_id, got $recorded_run_id"
            exit $EXIT_CLEANUP_FAILED
        fi

        local temp_root
        temp_root=$(jq -r '.temp_root // empty' "$state_file" 2>/dev/null || echo "")

        local resource_count
        resource_count=$(jq -r '.resource_count // 0' "$state_file" 2>/dev/null || echo "0")
        log_info "State file reports $resource_count registered resource(s)"

        local cleanup_failed=false
        if [[ "$resource_count" -gt 0 ]]; then
            local resource_entries
            resource_entries=$(jq -r '.resources[]? | "\(.action):\(.target)"' "$state_file" 2>/dev/null || echo "")

            if [[ -n "$resource_entries" ]]; then
                while IFS= read -r entry; do
                    local action="${entry%%:*}"
                    local target="${entry#*:}"
                    if ! dispatch_cleanup_action "$action" "$target" "$temp_root"; then
                        cleanup_failed=true
                    fi
                done <<< "$resource_entries"
            fi
        else
            log_info "No registered resources to clean up (0 resources)"
        fi

        if [[ "$cleanup_failed" == true ]]; then
            log_error "One or more registered resources could not be cleaned"
            exit $EXIT_CLEANUP_FAILED
        fi
        mark_cleanup_completed "$state_file"
    else
        log_warn "No state file found; no resources to clean"
    fi

    log_success "Cleanup completed for run: $cleanup_run_id (evidence preserved)"
}

run_delete_evidence() {
    local delete_run_id="$1"

    if [[ -z "$delete_run_id" ]]; then
        log_error "Run ID required for delete-evidence"
        exit $EXIT_INVALID_ARGS
    fi

    if ! validate_run_id "$delete_run_id"; then
        log_error "Invalid run ID for delete-evidence: $delete_run_id"
        exit $EXIT_CLEANUP_FAILED
    fi

    local evidence_base_dir="${EVIDENCE_BASE_DIR:-target/agent-validation}"

    if [[ ! -d "$evidence_base_dir" ]]; then
        log_error "Evidence base directory does not exist: $evidence_base_dir"
        exit $EXIT_CLEANUP_FAILED
    fi

    local delete_evidence_dir="${evidence_base_dir}/${delete_run_id}"

    if ! validate_safe_path "$delete_evidence_dir" "$evidence_base_dir"; then
        log_error "Delete-evidence path validation failed for: $delete_run_id"
        exit $EXIT_CLEANUP_FAILED
    fi

    local canonical_target
    canonical_target=$(realpath -m "$delete_evidence_dir" 2>/dev/null) || {
        log_error "Cannot canonicalize delete-evidence path"
        exit $EXIT_CLEANUP_FAILED
    }

    local canonical_base
    canonical_base=$(realpath "$evidence_base_dir" 2>/dev/null) || {
        log_error "Cannot canonicalize evidence base"
        exit $EXIT_CLEANUP_FAILED
    }

    if [[ "$canonical_target" == "$canonical_base" ]]; then
        log_error "Refusing to delete the evidence base directory itself"
        exit $EXIT_CLEANUP_FAILED
    fi

    if [[ "$canonical_target" != "$canonical_base"/* ]]; then
        log_error "Canonicalized path is not beneath evidence base: $canonical_target"
        exit $EXIT_CLEANUP_FAILED
    fi

    if [[ ! -d "$canonical_target" ]]; then
        log_error "Evidence directory not found: $canonical_target"
        exit $EXIT_CLEANUP_FAILED
    fi

    log_warn "WARNING: This will permanently delete evidence directory: $canonical_target"
    read -r -p "Type 'DELETE' to confirm: " confirmation
    if [[ "$confirmation" != "DELETE" ]]; then
        log_error "Delete-evidence cancelled by user"
        exit $EXIT_CLEANUP_FAILED
    fi

    log_info "Deleting evidence directory: $canonical_target"

    chmod -R 700 "$canonical_target" 2>/dev/null || true
    rm -rf "$canonical_target" 2>/dev/null || {
        log_error "Failed to delete evidence directory"
        exit $EXIT_CLEANUP_FAILED
    }

    log_success "Evidence deleted for run: $delete_run_id"
}

check_required_stages_status() {
    local report_file="${EVIDENCE_DIR}/report.json"

    local required_skipped_count
    required_skipped_count=$(jq -r '[.stages[] | select(.status == "SKIP" and .required == true)] | length' "$report_file" 2>/dev/null || echo "0")

    if [[ "$required_skipped_count" -gt 0 ]]; then
        log_error "Found $required_skipped_count required stage(s) that were skipped - validation incomplete"
        return 1
    fi

    local failed_count
    failed_count=$(jq -r '[.stages[] | select(.status == "FAIL")] | length' "$report_file" 2>/dev/null || echo "0")

    if [[ "$failed_count" -gt 0 ]]; then
        log_error "Found $failed_count stage(s) that failed - validation failed"
        return 1
    fi

    return 0
}

main() {
    local mode=""
    local arg_cleanup_run_id=""
    local arg_delete_run_id=""
    ALLOW_DIRTY_LAB=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --preflight)
                mode="preflight"
                shift
                ;;
            --automated)
                mode="automated"
                shift
                ;;
            --release)
                mode="release"
                shift
                ;;
            --allow-dirty)
                ALLOW_DIRTY_LAB=true
                shift
                ;;
            --cleanup)
                mode="cleanup"
                if [[ -n "${2:-}" ]]; then
                    arg_cleanup_run_id="$2"
                    shift 2
                else
                    log_error "Missing run ID for cleanup"
                    usage
                    exit $EXIT_INVALID_ARGS
                fi
                ;;
            --delete-evidence)
                mode="delete-evidence"
                if [[ -n "${2:-}" ]]; then
                    arg_delete_run_id="$2"
                    shift 2
                else
                    log_error "Missing run ID for delete-evidence"
                    usage
                    exit $EXIT_INVALID_ARGS
                fi
                ;;
            --help|-h)
                usage
                exit $EXIT_SUCCESS
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit $EXIT_INVALID_ARGS
                ;;
        esac
    done

    if [[ -z "$mode" ]]; then
        log_error "No mode specified"
        usage
        exit $EXIT_INVALID_ARGS
    fi

    case "$mode" in
        "preflight")
            if run_preflight "release"; then
                log_success "Preflight checks passed"
                exit $EXIT_SUCCESS
            else
                log_error "Preflight checks failed"
                exit $EXIT_PREFLIGHT_FAILED
            fi
            ;;
        "cleanup")
            run_cleanup "$arg_cleanup_run_id"
            exit $EXIT_SUCCESS
            ;;
        "delete-evidence")
            run_delete_evidence "$arg_delete_run_id"
            exit $EXIT_SUCCESS
            ;;
        "automated"|"release")
            initialize_run "$mode"

            if ! run_preflight "$mode"; then
                log_error "Preflight checks failed"
                exit $EXIT_PREFLIGHT_FAILED
            fi

            capture_environment

            if ! run_tier1_tests; then
                log_error "Tier 1 tests failed"
                generate_final_report
                finalize_state_file
                exit $EXIT_STAGE_FAILED
            fi

            if [[ "$mode" == "automated" ]]; then
                if ! run_tier2_tests; then
                    log_error "Tier 2 tests failed"
                    generate_final_report
                    finalize_state_file
                    exit $EXIT_STAGE_FAILED
                fi
            elif [[ "$mode" == "release" ]]; then
                if ! run_tier2_tests; then
                    log_error "Tier 2 tests failed"
                    generate_final_report
                    finalize_state_file
                    exit $EXIT_STAGE_FAILED
                fi

                if ! run_tier3_tests; then
                    log_error "Tier 3 tests declined or failed - release validation incomplete"
                    generate_final_report
                    finalize_state_file
                    exit $EXIT_INCOMPLETE
                fi
            fi

            if ! run_stage "final-secret-scan" "stage_secret_scanning" \
                "Final scan of complete local evidence" "true"; then
                log_error "Final secret scan failed"
                generate_final_report
                finalize_state_file
                exit $EXIT_STAGE_FAILED
            fi

            generate_final_report
            finalize_state_file

            if ! check_required_stages_status; then
                log_error "Release validation incomplete due to skipped required stages"
                exit $EXIT_INCOMPLETE
            fi

            log_success "Validation completed successfully: $mode mode"
            exit $EXIT_SUCCESS
            ;;
        *)
            log_error "Unknown mode: $mode"
            exit $EXIT_INVALID_ARGS
            ;;
    esac
}

main "$@"
