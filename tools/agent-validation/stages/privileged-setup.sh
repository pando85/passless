#!/bin/bash
#
# Tier 3 Stage: Privileged Setup
# Invokes Phase0 privileged setup with explicit confirmation and run-specific udev rules.
#

set -euo pipefail

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/common.sh"
fi
if [[ -z "${AV_LIB_PRIVILEGE_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/privilege.sh"
fi
if [[ -z "${AV_LIB_SNSHOT_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/snapshot.sh"
fi

# shellcheck disable=SC2034
AV_STAGE_PRIVILEGED_SETUP_LOADED=true

stage_privileged_setup() {
    local phase0_dir
    phase0_dir=$(av_resolve_phase0_dir "${AV_VALIDATION_DIR:-}") || {
        av_log_error "Phase0 directory not found"
        return 1
    }

    local setup_script="${phase0_dir}/policy/setup.sh"
    local rules_file="${phase0_dir}/policy/90-uhid-feasibility.rules"

    if [[ ! -f "$setup_script" ]]; then
        av_log_error "Phase0 setup script not found: $setup_script"
        return 1
    fi

    if [[ ! -f "$rules_file" ]]; then
        av_log_error "Phase0 rules file not found: $rules_file"
        return 1
    fi

    local prereqs
    prereqs=$(av_prereqs_summary "${AV_VALIDATION_DIR:-}")

    if av_is_dry_run; then
        av_log_info "[DRY-RUN] Static validation of Phase0 scripts..."

        if [[ ! -x "$setup_script" ]]; then
            av_log_error "Phase0 setup script not executable: $setup_script"
            return 1
        fi

        if ! bash -n "$setup_script" 2>/dev/null; then
            av_log_error "Phase0 setup script has syntax errors"
            return 1
        fi

        av_log_info "[DRY-RUN] Prerequisites: $prereqs"
        av_log_info "[DRY-RUN] Would invoke: sudo $setup_script"
        av_log_info "[DRY-RUN] Would install run-specific test udev rules"

        local static_analysis_file="${EVIDENCE_DIR:-/tmp}/phase0-static-analysis.json"
        av_static_udev_analysis "$rules_file" "$static_analysis_file" 2>/dev/null || true

        av_log_info "[DRY-RUN] Static validation complete (not a live pass)"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi

    if ! av_check_sudo_binary_exists; then
        av_log_error "sudo not available"
        av_log_info "Set PASSLESS_VALIDATION_DRY_RUN=1 for static/dry-run mode"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi

    if [[ ! -e /dev/uhid ]]; then
        av_log_warn "/dev/uhid does not exist (uhid module may not be loaded)"
    fi

    av_log_info "Taking pre-privileged-setup snapshot..."
    av_take_pre_snapshot "${EVIDENCE_DIR}"

    av_log_info "Invoking Phase0 privileged setup..."
    if ! av_phase0_setup "$phase0_dir"; then
        av_log_error "Phase0 setup failed"
        return 1
    fi

    local test_rules_src="${AV_VALIDATION_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}/fixtures/test-udev-rules/99-agent-validation-test.rules"
    local test_rules_dst="/etc/udev/rules.d/99-agent-validation-test-${RUN_ID:-unknown}.rules"

    if [[ -f "$test_rules_src" ]]; then
        av_log_info "Installing run-specific test udev rules..."
        if av_install_test_udev_rule "$test_rules_src" "$test_rules_dst"; then
            register_resource "remove_test_udev_rule" "$test_rules_dst" 2>/dev/null || true

            if av_reload_udev 2>/dev/null; then
                av_trigger_udev 2>/dev/null || true
            fi
        else
            av_log_warn "Failed to install test udev rules (non-fatal)"
        fi
    else
        av_log_warn "Test udev rules fixture not found: $test_rules_src"
    fi

    av_log_info "Taking post-privileged-setup snapshot..."
    av_take_post_snapshot "${EVIDENCE_DIR}"

    if [[ -f "${EVIDENCE_DIR}/pre-snapshot.json" ]] && [[ -f "${EVIDENCE_DIR}/post-snapshot.json" ]]; then
        av_compare_snapshots \
            "${EVIDENCE_DIR}/pre-snapshot.json" \
            "${EVIDENCE_DIR}/post-snapshot.json" \
            "${EVIDENCE_DIR}/snapshot-comparison.json" 2>/dev/null || true
    fi

    av_log_success "Privileged setup completed"
    return 0
}
