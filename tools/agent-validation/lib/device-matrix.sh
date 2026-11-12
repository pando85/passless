#!/bin/bash
#
# Cross-identity device access matrix
#

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
fi

# shellcheck disable=SC2034
AV_LIB_DEVICE_MATRIX_LOADED=true

av_discover_device_nodes() {
    local devices=()

    if [[ -e /dev/uhid ]]; then
        devices+=("/dev/uhid")
    fi

    local f
    for f in /dev/hidraw*; do
        if [[ -e "$f" ]]; then
            devices+=("$f")
        fi
    done

    printf '%s\n' "${devices[@]}"
}

av_probe_device_access() {
    local device="$1"

    if [[ ! -e "$device" ]]; then
        jq -n \
            --arg path "$device" \
            '{path: $path, exists: false, readable: false, writable: false, open_rw: false}'
        return
    fi

    local mode owner group owner_uid group_gid
    mode=$(stat -c '%a' "$device" 2>/dev/null || echo "0")
    owner=$(stat -c '%U' "$device" 2>/dev/null || echo "unknown")
    group=$(stat -c '%G' "$device" 2>/dev/null || echo "unknown")
    owner_uid=$(stat -c '%u' "$device" 2>/dev/null || echo "-1")
    group_gid=$(stat -c '%g' "$device" 2>/dev/null || echo "-1")

    local readable="false" writable="false" open_rw="false"
    [[ -r "$device" ]] && readable="true"
    [[ -w "$device" ]] && writable="true"

    if [[ -r "$device" ]] && [[ -w "$device" ]]; then
        if (exec 3<>"$device") 2>/dev/null; then
            open_rw="true"
            exec 3<&- 3>&- 2>/dev/null || true
        fi
    fi

    jq -n \
        --arg path "$device" \
        --argjson exists true \
        --arg mode "$mode" \
        --arg owner "$owner" \
        --arg group "$group" \
        --arg owner_uid "$owner_uid" \
        --arg group_gid "$group_gid" \
        --argjson readable "$readable" \
        --argjson writable "$writable" \
        --argjson open_rw "$open_rw" \
        '{
            path: $path,
            exists: $exists,
            mode: $mode,
            owner: $owner,
            group: $group,
            owner_uid: $owner_uid,
            group_gid: $group_gid,
            readable: $readable,
            writable: $writable,
            open_rw: $open_rw
        }'
}

av_build_access_matrix() {
    local output_file="$1"

    local devices_json="[]"
    local device_list
    device_list=$(av_discover_device_nodes)

    if [[ -n "$device_list" ]]; then
        local probes=()
        while IFS= read -r device; do
            [[ -z "$device" ]] && continue
            local probe
            probe=$(av_probe_device_access "$device")
            probes+=("$probe")
        done <<< "$device_list"

        if [[ ${#probes[@]} -gt 0 ]]; then
            local joined
            joined=$(printf '%s,' "${probes[@]}")
            devices_json="[$(printf '%s' "${joined%,}")]  "
            devices_json=$(printf '%s' "${probes[@]}" | jq -s '.' 2>/dev/null || echo "[]")
        fi
    fi

    local identity_json
    identity_json=$(jq -n \
        --arg uid "$(id -u)" \
        --arg gid "$(id -g)" \
        --arg username "$(id -un 2>/dev/null || echo unknown)" \
        --arg groups "$(id -G 2>/dev/null || echo '')" \
        '{uid: $uid, gid: $gid, username: $username, groups: $groups}')

    jq -n \
        --argjson timestamp "\"$(av_capture_timestamp)\"" \
        --argjson identity "$identity_json" \
        --argjson devices "$devices_json" \
        '{
            timestamp: $timestamp,
            identity: $identity,
            devices: $devices,
            matrix_type: "cross-identity-open"
        }' > "$output_file"
}

av_static_udev_analysis() {
    local rules_file="$1"
    local output_file="$2"

    if [[ ! -f "$rules_file" ]]; then
        av_log_error "Rules file not found: $rules_file"
        return 1
    fi

    local uhid_group="unset"
    local uhid_mode="unset"
    uhid_group=$(grep -E 'KERNEL=="uhid"' "$rules_file" 2>/dev/null | grep -v '^#' | grep -oP 'GROUP="\K[^"]+' || echo "unset")
    uhid_mode=$(grep -E 'KERNEL=="uhid"' "$rules_file" 2>/dev/null | grep -v '^#' | grep -oP 'MODE="\K[^"]+' || echo "unset")

    local probe_group="unset"
    local probe_mode="unset"
    probe_group=$(grep -E 'SUBSYSTEM=="hidraw".*FEASIBILITY_PROBE' "$rules_file" 2>/dev/null | grep -v '^#' | grep -oP 'GROUP="\K[^"]+' || echo "unset")
    probe_mode=$(grep -E 'SUBSYSTEM=="hidraw".*FEASIBILITY_PROBE' "$rules_file" 2>/dev/null | grep -v '^#' | grep -oP 'MODE="\K[^"]+' || echo "unset")

    local human_group="fido"
    local daemon_group="uhid-daemon"
    local agent_group="fido-agent-probe"

    local prin03="pass"
    if [[ "$uhid_group" == "$human_group" ]]; then
        prin03="fail"
    fi

    local route03="pass"
    if grep -E 'KERNEL=="uhid"' "$rules_file" 2>/dev/null | grep -v '^#' | grep -q "GROUP=\"${human_group}\""; then
        route03="fail"
    fi

    local isol01="pass"
    if [[ "$probe_group" == "$human_group" ]] || [[ "$probe_group" == "$daemon_group" ]]; then
        isol01="fail"
    fi

    jq -n \
        --arg rules_file "$rules_file" \
        --arg uhid_group "$uhid_group" \
        --arg uhid_mode "$uhid_mode" \
        --arg probe_group "$probe_group" \
        --arg probe_mode "$probe_mode" \
        --arg human_group "$human_group" \
        --arg daemon_group "$daemon_group" \
        --arg agent_group "$agent_group" \
        --arg prin03 "$prin03" \
        --arg route03 "$route03" \
        --arg isol01 "$isol01" \
        --arg analysis_type "static" \
        --arg timestamp "$(av_capture_timestamp)" \
        '{
            timestamp: $timestamp,
            analysis_type: $analysis_type,
            rules_file: $rules_file,
            expected_identity_model: {
                human_group: $human_group,
                daemon_group: $daemon_group,
                agent_group: $agent_group
            },
            observed: {
                uhid_group: $uhid_group,
                uhid_mode: $uhid_mode,
                probe_hidraw_group: $probe_group,
                probe_hidraw_mode: $probe_mode
            },
            policy_checks: {
                PRIN_03: $prin03,
                ROUTE_03: $route03,
                ISOL_01: $isol01
            }
        }' > "$output_file"
}

av_resolve_repo_root() {
    local validation_dir="${1:-}"
    if [[ -z "$validation_dir" ]]; then
        validation_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    fi
    (cd "${validation_dir}/../.." && pwd)
}

# Static checks on the shipped contrib files. Agents use only the browser
# extension path, so the only device grant is /dev/uhid for the human group and
# no agent hidraw udev rule or systemd device grant may exist.
av_static_contrib_udev_analysis() {
    local repo_root="$1"
    local output_file="$2"
    local rules_file="${repo_root}/contrib/udev/90-passless.rules"
    local agent_rules_file="${repo_root}/contrib/udev/70-passless-agent.rules"
    local service_file="${repo_root}/contrib/systemd/passless-agent.service"

    if [[ ! -f "$rules_file" ]]; then
        av_log_error "Rules file not found: $rules_file"
        return 1
    fi
    if [[ ! -f "$service_file" ]]; then
        av_log_error "Service file not found: $service_file"
        return 1
    fi

    local human_group="fido"
    local uhid_line uhid_group="unset" uhid_mode="unset"
    uhid_line=$(grep -E 'KERNEL=="uhid"' "$rules_file" 2>/dev/null | grep -vE '^[[:space:]]*#' || true)
    if [[ -n "$uhid_line" ]]; then
        uhid_group=$(grep -oP 'GROUP="\K[^"]+' <<< "$uhid_line" | head -n1 || true)
        uhid_mode=$(grep -oP 'MODE="\K[^"]+' <<< "$uhid_line" | head -n1 || true)
        : "${uhid_group:=unset}" "${uhid_mode:=unset}"
    fi

    local uhid_human_only="fail"
    if [[ "$uhid_group" == "$human_group" ]]; then
        uhid_human_only="pass"
    fi

    local uhid_not_world="fail"
    if [[ "$uhid_mode" =~ ^[0-7]{3,4}$ ]] && [[ "${uhid_mode: -1}" == "0" ]]; then
        uhid_not_world="pass"
    fi

    local agent_rule_absent="pass"
    if [[ -e "$agent_rules_file" ]]; then
        agent_rule_absent="fail"
    fi

    local unit_active
    unit_active=$(grep -vE '^[[:space:]]*#' "$service_file" || true)

    local no_device_allow="pass"
    if grep -qiE '^[[:space:]]*(DeviceAllow|DevicePolicy)[[:space:]]*=' <<< "$unit_active" \
        || grep -qiE 'uhid|hidraw' <<< "$unit_active"; then
        no_device_allow="fail"
    fi

    local no_agent_rule_ref="pass"
    if grep -qiE '70-passless-agent|passless-agent\.rules' "$service_file"; then
        no_agent_rule_ref="fail"
    fi

    jq -n \
        --arg rules_file "$rules_file" \
        --arg uhid_group "$uhid_group" \
        --arg uhid_mode "$uhid_mode" \
        --arg human_group "$human_group" \
        --arg uhid_human_only "$uhid_human_only" \
        --arg uhid_not_world "$uhid_not_world" \
        --arg agent_rule_absent "$agent_rule_absent" \
        --arg no_device_allow "$no_device_allow" \
        --arg no_agent_rule_ref "$no_agent_rule_ref" \
        --arg timestamp "$(av_capture_timestamp)" \
        '{
            timestamp: $timestamp,
            analysis_type: "static-contrib",
            rules_file: $rules_file,
            expected_identity_model: {human_group: $human_group},
            observed: {uhid_group: $uhid_group, uhid_mode: $uhid_mode},
            policy_checks: {
                UHID_HUMAN_GROUP_ONLY: $uhid_human_only,
                UHID_NOT_WORLD_ACCESSIBLE: $uhid_not_world,
                NO_AGENT_UDEV_RULE: $agent_rule_absent,
                NO_AGENT_DEVICE_ALLOW: $no_device_allow,
                NO_AGENT_RULE_REFERENCE: $no_agent_rule_ref
            }
        }' > "$output_file"
}

av_generate_matrix_json() {
    local output_file="$1"
    local mode="${2:-live}"

    if [[ "$mode" == "static" ]]; then
        local repo_root
        repo_root=$(av_resolve_repo_root "${AV_VALIDATION_DIR:-}") || {
            av_log_error "Repository root not found"
            return 1
        }
        av_static_contrib_udev_analysis "$repo_root" "$output_file"
    else
        av_build_access_matrix "$output_file"
    fi
}
