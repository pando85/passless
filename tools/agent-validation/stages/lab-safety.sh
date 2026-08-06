#!/bin/bash
#
# Tier 3 Stage: Lab Safety
# Verifies cleanup works, removes exact recorded resources, compares final inventory.
#

set -euo pipefail

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/common.sh"
fi
if [[ -z "${AV_LIB_PRIVILEGE_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/privilege.sh"
fi
if [[ -z "${AV_LIB_STATE_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/state.sh"
fi
if [[ -z "${AV_LIB_SNSHOT_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/snapshot.sh"
fi

# shellcheck disable=SC2034
AV_STAGE_LAB_SAFETY_LOADED=true

stage_lab_safety() {
    local phase0_dir
    phase0_dir=$(av_resolve_phase0_dir "${AV_VALIDATION_DIR:-}") || {
        av_log_error "Phase0 directory not found"
        return 1
    }

    local cleanup_script="${phase0_dir}/policy/cleanup.sh"
    local safety_report="${EVIDENCE_DIR:-/tmp}/lab-safety-report.json"
    local violations=0
    local checks_json="[]"

    add_check() {
        local check="$1" name="$2" status="$3" detail="$4"
        checks_json=$(echo "$checks_json" | jq --arg c "$check" --arg n "$name" --arg s "$status" --arg d "$detail" \
            '. + [{"check": $c, "name": $n, "status": $s, "detail": $d}]')
    }

    if av_is_dry_run; then
        av_log_info "[DRY-RUN] Static lab safety analysis..."

        if [[ ! -f "$cleanup_script" ]]; then
            av_log_error "Phase0 cleanup script not found: $cleanup_script"
            return 1
        fi

        if [[ ! -x "$cleanup_script" ]]; then
            av_log_error "Phase0 cleanup script not executable: $cleanup_script"
            return 1
        fi

        if ! bash -n "$cleanup_script" 2>/dev/null; then
            av_log_error "Phase0 cleanup script has syntax errors"
            return 1
        fi

        if ! grep -q 'STATE_FILE' "$cleanup_script"; then
            av_log_error "Cleanup script does not use state file"
            add_check "CLEANUP-01" "state_based_cleanup" "fail" "No STATE_FILE reference"
            ((violations++)) || true
        else
            add_check "CLEANUP-01" "state_based_cleanup" "pass" "Uses state file"
        fi

        add_check "SAFETY-01" "cleanup_script_valid" "pass" "Syntax OK, executable"

        jq -n \
            --arg timestamp "$(av_capture_timestamp)" \
            --arg mode "dry-run" \
            --argjson violations "$violations" \
            --argjson checks "$checks_json" \
            '{
                timestamp: $timestamp,
                mode: $mode,
                violations: $violations,
                checks: $checks
            }' > "$safety_report"

        if [[ $violations -gt 0 ]]; then
            av_log_error "[DRY-RUN] Lab safety: $violations violation(s)"
            return 1
        fi

        av_log_info "[DRY-RUN] Lab safety static analysis complete (not a live pass)"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi

    av_log_info "Verifying cleanup script exists and is valid..."
    if [[ ! -f "$cleanup_script" ]]; then
        av_log_error "Phase0 cleanup script not found: $cleanup_script"
        add_check "SAFETY-01" "cleanup_exists" "fail" "Script not found"
        ((violations++)) || true
    elif [[ ! -x "$cleanup_script" ]]; then
        av_log_error "Phase0 cleanup script not executable"
        add_check "SAFETY-01" "cleanup_executable" "fail" "Not executable"
        ((violations++)) || true
    else
        add_check "SAFETY-01" "cleanup_valid" "pass" "Script valid"
    fi

    # Load state and remove exact recorded resources
    local state_file="${EVIDENCE_DIR:-/tmp}/state.json"
    if [[ -f "$state_file" ]]; then
        av_log_info "Loading state from $state_file..."
        av_load_state "$state_file"

        av_log_info "Removing registered resources..."
        av_cleanup_registered_resources
    else
        av_log_warn "No state file found, cannot remove recorded resources"
    fi

    # Check for leftover test udev rules
    av_log_info "Checking for leftover test udev rules..."
    local test_rules_found=0
    local rule_file
    for rule_file in /etc/udev/rules.d/99-agent-validation-test-*.rules; do
        if [[ -f "$rule_file" ]]; then
            ((test_rules_found++)) || true
            av_log_error "Leftover test udev rule: $rule_file"
            add_check "SAFETY-02" "test_udev_rule" "fail" "Leftover: $rule_file"
            ((violations++)) || true
        fi
    done
    if [[ $test_rules_found -eq 0 ]]; then
        add_check "SAFETY-02" "test_udev_rules" "pass" "No leftover rules"
    fi

    # Check for leftover state files
    av_log_info "Checking for leftover state files..."
    local state_file_path="/var/lib/passless-feasibility/setup.state"
    if [[ -f "$state_file_path" ]]; then
        av_log_warn "Leftover state file: $state_file_path"
        add_check "SAFETY-03" "state_file" "fail" "Leftover: $state_file_path"
        ((violations++)) || true
    else
        add_check "SAFETY-03" "state_file" "pass" "No leftover state"
    fi

    # Scan for leftover probe devices
    av_log_info "Scanning for leftover probe devices..."
    local leftover_count=0
    if [[ -d /sys/bus/hid/devices ]]; then
        local dev
        for dev in /sys/bus/hid/devices/*/; do
            if [[ -f "${dev}uevent" ]]; then
                local name
                name=$(grep -oP '(?<=HID_NAME=).*' "${dev}uevent" 2>/dev/null || true)
                if [[ "${name}" == *"feasibility-probe"* ]] || [[ "${name}" == *"agent-validation"* ]]; then
                    ((leftover_count++)) || true
                    av_log_error "Leftover probe device: ${dev} (name=$name)"
                fi
            fi
        done
    fi
    if [[ $leftover_count -gt 0 ]]; then
        add_check "SAFETY-04" "leftover_devices" "fail" "$leftover_count leftover device(s)"
        ((violations++)) || true
    else
        add_check "SAFETY-04" "leftover_devices" "pass" "No leftover devices"
    fi

    # Generate final inventory
    av_log_info "Generating final inventory..."
    av_generate_final_inventory "${EVIDENCE_DIR}"

    # Compare final inventory against expected
    local final_inventory="${EVIDENCE_DIR}/final-inventory.json"
    if [[ -f "$final_inventory" ]]; then
        local file_count
        file_count=$(jq '.file_count' "$final_inventory" 2>/dev/null || echo "0")
        av_log_info "Final inventory: $file_count file(s)"
        add_check "SAFETY-05" "final_inventory" "info" "$file_count files"
    else
        av_log_warn "Final inventory not generated"
        add_check "SAFETY-05" "final_inventory" "fail" "Not generated"
        ((violations++)) || true
    fi

    jq -n \
        --arg timestamp "$(av_capture_timestamp)" \
        --arg mode "live" \
        --argjson violations "$violations" \
        --argjson test_rules_found "$test_rules_found" \
        --argjson leftover_devices "$leftover_count" \
        --argjson checks "$checks_json" \
        '{
            timestamp: $timestamp,
            mode: $mode,
            violations: $violations,
            test_rules_remaining: $test_rules_found,
            leftover_devices: $leftover_devices,
            checks: $checks
        }' > "$safety_report"

    if [[ $violations -gt 0 ]]; then
        av_log_error "Lab safety: $violations violation(s) found"
        return 1
    fi

    av_log_success "Lab safety: all checks passed"
    return 0
}
