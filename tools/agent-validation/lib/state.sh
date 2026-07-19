#!/bin/bash
#
# State resource tracking for cleanup
#

set -euo pipefail

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
fi

# shellcheck disable=SC2034
AV_LIB_STATE_LOADED=true

AV_STATE_RESOURCES=()

av_register_resource() {
    local resource_type="$1"
    local resource_path="$2"

    case "$resource_type" in
        test_udev_rule)
            if [[ "$resource_path" != /etc/udev/rules.d/99-agent-validation-test-*.rules ]]; then
                av_log_error "Invalid test udev rule path: $resource_path"
                return 1
            fi
            ;;
        temp_file)
            local temp_root="${EVIDENCE_DIR:-}/tmp"
            if [[ -n "$temp_root" ]] && [[ "$resource_path" != "$temp_root"/* ]]; then
                av_log_error "Temp file not under TEMP_ROOT: $resource_path"
                return 1
            fi
            ;;
        *)
            av_log_error "Unknown resource type: $resource_type"
            return 1
            ;;
    esac

    AV_STATE_RESOURCES+=("${resource_type}:${resource_path}")
}

av_cleanup_registered_resources() {
    local cleanup_count=0

    for entry in "${AV_STATE_RESOURCES[@]}"; do
        local resource_type="${entry%%:*}"
        local resource_path="${entry#*:}"

        case "$resource_type" in
            test_udev_rule)
                if av_remove_test_udev_rule "$resource_path" 2>/dev/null; then
                    ((cleanup_count++)) || true
                    av_log_info "Removed test udev rule: $resource_path"
                fi
                ;;
            temp_file)
                if [[ -f "$resource_path" ]]; then
                    rm -f "$resource_path" 2>/dev/null || true
                    ((cleanup_count++)) || true
                    av_log_info "Removed temp file: $resource_path"
                fi
                ;;
        esac
    done

    av_log_info "Cleaned up $cleanup_count registered resource(s)"
    AV_STATE_RESOURCES=()
}

av_save_state() {
    local state_file="${EVIDENCE_DIR:-}/state.json"

    local resources_json="[]"
    for entry in "${AV_STATE_RESOURCES[@]}"; do
        local resource_type="${entry%%:*}"
        local resource_path="${entry#*:}"
        resources_json=$(echo "$resources_json" | jq --arg t "$resource_type" --arg p "$resource_path" \
            '. + [{"type": $t, "path": $p}]')
    done

    jq -n \
        --arg run_id "${RUN_ID:-unknown}" \
        --arg timestamp "$(av_capture_timestamp)" \
        --argjson resources "$resources_json" \
        '{
            run_id: $run_id,
            timestamp: $timestamp,
            resources: $resources,
            resource_count: ($resources | length)
        }' > "$state_file"

    chmod 600 "$state_file"
}

av_load_state() {
    local state_file="$1"

    if [[ ! -f "$state_file" ]]; then
        av_log_warn "State file not found: $state_file"
        return 1
    fi

    AV_STATE_RESOURCES=()

    local count
    count=$(jq '.resource_count' "$state_file" 2>/dev/null || echo "0")

    for i in $(seq 0 $((count - 1))); do
        local resource_type resource_path
        resource_type=$(jq -r ".resources[$i].type" "$state_file" 2>/dev/null || echo "")
        resource_path=$(jq -r ".resources[$i].path" "$state_file" 2>/dev/null || echo "")

        if [[ -n "$resource_type" ]] && [[ -n "$resource_path" ]]; then
            AV_STATE_RESOURCES+=("${resource_type}:${resource_path}")
        fi
    done

    av_log_info "Loaded ${#AV_STATE_RESOURCES[@]} resource(s) from state"
}
