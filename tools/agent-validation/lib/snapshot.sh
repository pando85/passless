#!/bin/bash
#
# Pre/post environment snapshots
#

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
fi

if [[ -z "${AV_LIB_DEVICE_MATRIX_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/device-matrix.sh"
fi

# shellcheck disable=SC2034
AV_LIB_SNSHOT_LOADED=true

av_capture_principal_snapshot() {
    local output_file="$1"
    local groups_json
    groups_json=$(id -G | tr ' ' '\n' | jq -R 'select(length > 0) | tonumber' | jq -s '.')
    local cgroup_path
    cgroup_path=$(cut -d: -f3- /proc/self/cgroup 2>/dev/null | sed -n '1p')

    jq -n \
        --arg timestamp "$(av_capture_timestamp)" \
        --argjson uid "$(id -u)" \
        --argjson gid "$(id -g)" \
        --argjson supplementary_gids "$groups_json" \
        --arg cgroup_path "${cgroup_path:-unavailable}" \
        '{timestamp:$timestamp,uid:$uid,gid:$gid,supplementary_gids:$supplementary_gids,cgroup_path:$cgroup_path}' \
        > "$output_file"
    chmod 600 "$output_file"
}

av_take_snapshot() {
    local output_file="$1"
    local label="${2:-snapshot}"

    local uhid_exists="false"
    local uhid_mode="unavailable"
    local uhid_owner="unavailable"
    local uhid_group="unavailable"
    if [[ -e /dev/uhid ]]; then
        uhid_exists="true"
        uhid_mode=$(stat -c '%a' /dev/uhid 2>/dev/null || echo "unavailable")
        uhid_owner=$(stat -c '%U' /dev/uhid 2>/dev/null || echo "unavailable")
        uhid_group=$(stat -c '%G' /dev/uhid 2>/dev/null || echo "unavailable")
    fi

    local hidraw_count=0
    local hidraw_devices="[]"
    local hidraw_list=()
    local f
    for f in /dev/hidraw*; do
        if [[ -e "$f" ]]; then
            ((hidraw_count++)) || true
            local info
            info=$(jq -n \
                --arg path "$f" \
                --arg mode "$(stat -c '%a' "$f" 2>/dev/null || echo 0)" \
                --arg group "$(stat -c '%G' "$f" 2>/dev/null || echo unknown)" \
                '{path: $path, mode: $mode, group: $group}')
            hidraw_list+=("$info")
        fi
    done
    if [[ ${#hidraw_list[@]} -gt 0 ]]; then
        hidraw_devices=$(printf '%s' "${hidraw_list[@]}" | jq -s '.' 2>/dev/null || echo "[]")
    fi

    local udev_rules=()
    local rule_file
    for rule_file in /etc/udev/rules.d/*uhid* /etc/udev/rules.d/*passless*; do
        if [[ -f "$rule_file" ]]; then
            udev_rules+=("$(basename "$rule_file")")
        fi
    done
    local udev_rules_json
    udev_rules_json=$(printf '%s\n' "${udev_rules[@]}" 2>/dev/null | jq -R '.' 2>/dev/null | jq -s '.' 2>/dev/null || echo "[]")

    local cgroup_v2="false"
    [[ -f /sys/fs/cgroup/cgroup.controllers ]] && cgroup_v2="true"

    local uhid_module_loaded="false"
    [[ -d /sys/module/uhid ]] && uhid_module_loaded="true"

    local principal_snapshot_file="${output_file%.json}-principal.json"
    if ! av_capture_principal_snapshot "$principal_snapshot_file"; then
        av_log_error "Failed to capture principal snapshot"
        return 1
    fi

    local principal_ref="none"
    if [[ -f "$principal_snapshot_file" ]]; then
        principal_ref="$(basename "$principal_snapshot_file")"
    fi

    jq -n \
        --arg label "$label" \
        --arg timestamp "$(av_capture_timestamp)" \
        --argjson uhid_exists "$uhid_exists" \
        --arg uhid_mode "$uhid_mode" \
        --arg uhid_owner "$uhid_owner" \
        --arg uhid_group "$uhid_group" \
        --argjson hidraw_count "$hidraw_count" \
        --argjson hidraw_devices "$hidraw_devices" \
        --argjson udev_rules "$udev_rules_json" \
        --argjson cgroup_v2 "$cgroup_v2" \
        --argjson uhid_module_loaded "$uhid_module_loaded" \
        --arg principal_ref "$principal_ref" \
        '{
            label: $label,
            timestamp: $timestamp,
            devices: {
                uhid: {
                    exists: $uhid_exists,
                    mode: $uhid_mode,
                    owner: $uhid_owner,
                    group: $uhid_group
                },
                hidraw_count: $hidraw_count,
                hidraw_devices: $hidraw_devices
            },
            udev_rules: $udev_rules,
            system: {
                cgroup_v2: $cgroup_v2,
                uhid_module_loaded: $uhid_module_loaded
            },
            principal_snapshot: $principal_ref
        }' > "$output_file"
}

av_take_pre_snapshot() {
    local evidence_dir="$1"
    av_take_snapshot "${evidence_dir}/pre-snapshot.json" "pre-privileged-setup"
}

av_take_post_snapshot() {
    local evidence_dir="$1"
    av_take_snapshot "${evidence_dir}/post-snapshot.json" "post-privileged-setup"
}

av_compare_snapshots() {
    local pre_file="$1"
    local post_file="$2"
    local output_file="$3"

    if [[ ! -f "$pre_file" ]] || [[ ! -f "$post_file" ]]; then
        av_log_error "Snapshot files not found"
        return 1
    fi

    jq -n \
        --slurpfile pre "$pre_file" \
        --slurpfile post "$post_file" \
        --arg timestamp "$(av_capture_timestamp)" \
        '{
            timestamp: $timestamp,
            pre: $pre[0],
            post: $post[0],
            changes: {
                uhid_perms_changed: ($pre[0].devices.uhid.mode != $post[0].devices.uhid.mode),
                uhid_group_changed: ($pre[0].devices.uhid.group != $post[0].devices.uhid.group),
                hidraw_count_changed: ($pre[0].devices.hidraw_count != $post[0].devices.hidraw_count),
                udev_rules_changed: ($pre[0].udev_rules != $post[0].udev_rules)
            }
        }' > "$output_file"
}

av_generate_final_inventory() {
    local evidence_dir="$1"
    local output_file="${evidence_dir}/final-inventory.json"

    local evidence_files=()
    local f
    for f in "${evidence_dir}"/*.json; do
        if [[ -f "$f" ]]; then
            local basename_f
            basename_f=$(basename "$f")
            local size
            size=$(stat -c '%s' "$f" 2>/dev/null || echo 0)
            evidence_files+=("$(jq -n --arg name "$basename_f" --argjson size "$size" '{file: $name, size_bytes: $size}')")
        fi
    done

    local files_json="[]"
    if [[ ${#evidence_files[@]} -gt 0 ]]; then
        files_json=$(printf '%s' "${evidence_files[@]}" | jq -s '.' 2>/dev/null || echo "[]")
    fi

    jq -n \
        --arg timestamp "$(av_capture_timestamp)" \
        --argjson file_count "${#evidence_files[@]}" \
        --argjson files "$files_json" \
        '{
            timestamp: $timestamp,
            type: "final-inventory",
            file_count: $file_count,
            files: $files
        }' > "$output_file"
}
