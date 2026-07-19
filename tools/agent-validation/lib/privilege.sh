#!/bin/bash
#
# Narrowly-scoped privilege helpers with fixed commands
#

set -euo pipefail

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
fi

# shellcheck disable=SC2034
AV_LIB_PRIVILEGE_LOADED=true

av_check_sudo_binary_exists() {
    av_command_exists sudo
}

av_phase0_setup() {
    local phase0_dir="$1"
    local setup_script="${phase0_dir}/policy/setup.sh"

    if [[ ! -f "$setup_script" ]]; then
        av_log_error "Phase0 setup script not found: $setup_script"
        return 1
    fi

    if [[ ! -x "$setup_script" ]]; then
        av_log_error "Phase0 setup script not executable: $setup_script"
        return 1
    fi

    if [[ $EUID -eq 0 ]]; then
        "$setup_script"
    else
        sudo -- "$setup_script"
    fi
}

av_phase0_cleanup() {
    local phase0_dir="$1"
    local cleanup_script="${phase0_dir}/policy/cleanup.sh"

    if [[ ! -f "$cleanup_script" ]]; then
        av_log_error "Phase0 cleanup script not found: $cleanup_script"
        return 1
    fi

    if [[ ! -x "$cleanup_script" ]]; then
        av_log_error "Phase0 cleanup script not executable: $cleanup_script"
        return 1
    fi

    if [[ $EUID -eq 0 ]]; then
        "$cleanup_script"
    else
        sudo -- "$cleanup_script"
    fi
}

av_install_test_udev_rule() {
    local src_file="$1"
    local dst_file="$2"

    if [[ ! -f "$src_file" ]]; then
        av_log_error "Source udev rule not found: $src_file"
        return 1
    fi

    if [[ "$dst_file" != /etc/udev/rules.d/*.rules ]]; then
        av_log_error "Invalid destination path: $dst_file (must be in /etc/udev/rules.d/)"
        return 1
    fi

    if [[ $EUID -eq 0 ]]; then
        cp -- "$src_file" "$dst_file"
    else
        sudo -- cp -- "$src_file" "$dst_file"
    fi
}

av_remove_test_udev_rule() {
    local rule_file="$1"

    if [[ "$rule_file" != /etc/udev/rules.d/99-agent-validation-test-*.rules ]]; then
        av_log_error "Invalid test udev rule path: $rule_file"
        return 1
    fi

    if [[ -f "$rule_file" ]]; then
        if [[ $EUID -eq 0 ]]; then
            rm -f -- "$rule_file"
        else
            sudo -- rm -f -- "$rule_file"
        fi
    fi
}

av_reload_udev() {
    if [[ $EUID -eq 0 ]]; then
        udevadm control --reload-rules
    else
        sudo -- udevadm control --reload-rules
    fi
}

av_trigger_udev() {
    if [[ $EUID -eq 0 ]]; then
        udevadm trigger --subsystem-match=misc --subsystem-match=hid --subsystem-match=hidraw
    else
        sudo -- udevadm trigger --subsystem-match=misc --subsystem-match=hid --subsystem-match=hidraw
    fi
}

av_prereqs_summary() {
    local has_sudo="false"
    local has_phase0="false"
    local has_udevadm="false"
    local has_uhid="false"

    av_check_sudo_binary_exists && has_sudo="true"

    if av_resolve_phase0_dir "${1:-}" >/dev/null 2>&1; then
        has_phase0="true"
    fi

    av_command_exists udevadm && has_udevadm="true"
    [[ -e /dev/uhid ]] && has_uhid="true"

    jq -n \
        --argjson has_sudo "$has_sudo" \
        --argjson has_phase0 "$has_phase0" \
        --argjson has_udevadm "$has_udevadm" \
        --argjson has_uhid "$has_uhid" \
        --argjson dry_run "$(av_is_dry_run && echo true || echo false)" \
        '{sudo_available: $has_sudo, phase0_scripts: $has_phase0, udevadm: $has_udevadm, uhid_device: $has_uhid, dry_run: $dry_run}'
}
