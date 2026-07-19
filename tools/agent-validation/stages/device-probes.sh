#!/bin/bash
#
# Tier 3 Stage: Device Probes
# Cross-identity device access matrix using sudo -u for each identity.
#

set -euo pipefail

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/common.sh"
fi
if [[ -z "${AV_LIB_PRIVILEGE_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/privilege.sh"
fi
if [[ -z "${AV_LIB_DEVICE_MATRIX_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/device-matrix.sh"
fi

# shellcheck disable=SC2034
AV_STAGE_DEVICE_PROBES_LOADED=true

stage_device_probes() {
    local phase0_dir
    phase0_dir=$(av_resolve_phase0_dir "${AV_VALIDATION_DIR:-}") || {
        av_log_error "Phase0 directory not found"
        return 1
    }

    local rules_file="${phase0_dir}/policy/90-uhid-feasibility.rules"
    local matrix_file="${EVIDENCE_DIR:-/tmp}/device-access-matrix.json"
    local static_analysis_file="${EVIDENCE_DIR:-/tmp}/udev-static-analysis.json"
    local violations=0
    local checks_json="[]"

    add_check() {
        local check="$1" name="$2" status="$3" detail="$4"
        checks_json=$(echo "$checks_json" | jq --arg c "$check" --arg n "$name" --arg s "$status" --arg d "$detail" \
            '. + [{"check": $c, "name": $n, "status": $s, "detail": $d}]')
    }

    if av_is_dry_run; then
        av_log_info "[DRY-RUN] Static device analysis..."

        if [[ ! -f "$rules_file" ]]; then
            av_log_error "Phase0 rules file not found: $rules_file"
            return 1
        fi

        av_static_udev_analysis "$rules_file" "$static_analysis_file"

        local prin03 route03 isol01
        prin03=$(jq -r '.policy_checks.PRIN_03' "$static_analysis_file" 2>/dev/null || echo "unknown")
        route03=$(jq -r '.policy_checks.ROUTE_03' "$static_analysis_file" 2>/dev/null || echo "unknown")
        isol01=$(jq -r '.policy_checks.ISOL_01' "$static_analysis_file" 2>/dev/null || echo "unknown")

        av_log_info "[DRY-RUN] Policy checks: PRIN-03=$prin03 ROUTE-03=$route03 ISOL-01=$isol01"

        if [[ "$prin03" == "fail" ]] || [[ "$route03" == "fail" ]] || [[ "$isol01" == "fail" ]]; then
            av_log_error "[DRY-RUN] Policy violations detected in static analysis"
            return 1
        fi

        local devices
        devices=$(av_discover_device_nodes)
        local device_count=0
        if [[ -n "$devices" ]]; then
            device_count=$(echo "$devices" | wc -l)
        fi
        av_log_info "[DRY-RUN] Discovered $device_count device node(s)"

        av_log_info "[DRY-RUN] Static device analysis complete (not a live pass)"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi

    if ! av_check_sudo_binary_exists; then
        av_log_error "sudo not available for cross-identity probes"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi

    av_log_info "Building cross-identity device access matrix..."

    # Discover devices
    local devices
    devices=$(av_discover_device_nodes)

    if [[ -z "$devices" ]]; then
        av_log_error "No devices discovered"
        add_check "DEV-01" "devices_discovered" "fail" "No devices found"
        ((violations++)) || true
    else
        local device_count
        device_count=$(echo "$devices" | wc -l)
        av_log_info "Discovered $device_count device node(s)"
        add_check "DEV-01" "devices_discovered" "pass" "$device_count devices"
    fi

    # Define test identities
    local test_identities=("passless-daemon" "passless-browser" "fido-agent-probe")
    local identity_matrix="[]"

    for identity in "${test_identities[@]}"; do
        if ! id "$identity" &>/dev/null; then
            av_log_warn "Test identity does not exist: $identity (skipping)"
            continue
        fi

        av_log_info "Probing devices as $identity..."

        for device in $devices; do
            local probe_result
            probe_result=$(sudo -u "$identity" -- stat -c '%a %U %G' "$device" 2>&1) || probe_result="error:$?"

            local expected_access="none"
            local actual_access="none"

            if [[ "$probe_result" != error:* ]]; then
                # Check if identity can read/write
                if sudo -u "$identity" -- test -r "$device" 2>/dev/null; then
                    actual_access="r"
                fi
                if sudo -u "$identity" -- test -w "$device" 2>/dev/null; then
                    actual_access="${actual_access}w"
                fi
            fi

            # Determine expected access based on identity and device
            if [[ "$device" == "/dev/uhid" ]]; then
                if [[ "$identity" == "passless-daemon" ]]; then
                    expected_access="rw"
                else
                    expected_access="none"
                fi
            elif [[ "$device" == /dev/hidraw* ]]; then
                if [[ "$identity" == "fido-agent-probe" ]]; then
                    expected_access="rw"
                else
                    expected_access="none"
                fi
            fi

            # Check for mismatches
            if [[ "$actual_access" != "$expected_access" ]]; then
                av_log_error "DEV-MISMATCH: $identity on $device: expected=$expected_access actual=$actual_access"
                add_check "DEV-MISMATCH" "${identity}_${device##*/}" "fail" "expected=$expected_access actual=$actual_access"
                ((violations++)) || true
            else
                av_log_info "DEV-OK: $identity on $device: $actual_access"
            fi

            identity_matrix=$(echo "$identity_matrix" | jq \
                --arg id "$identity" \
                --arg dev "$device" \
                --arg exp "$expected_access" \
                --arg act "$actual_access" \
                '. + [{"identity": $id, "device": $dev, "expected": $exp, "actual": $act}]')
        done
    done

    # Run Phase0 permission probes
    local perm_probes_script="${phase0_dir}/scripts/run-permission-probes.sh"
    if [[ -f "$perm_probes_script" ]] && [[ -x "$perm_probes_script" ]]; then
        av_log_info "Running Phase0 permission probes..."
        if ! "$perm_probes_script" > "${EVIDENCE_DIR}/phase0-perm-probes.log" 2>&1; then
            av_log_error "Phase0 permission probes returned non-zero"
            add_check "DEV-02" "phase0_probes" "fail" "Non-zero exit"
            ((violations++)) || true
        else
            av_log_success "Phase0 permission probes completed"
            add_check "DEV-02" "phase0_probes" "pass" "Success"
        fi
    else
        av_log_warn "Phase0 permission probes script not found or not executable"
        add_check "DEV-02" "phase0_probes" "fail" "Script not found"
        ((violations++)) || true
    fi

    # Save matrix
    jq -n \
        --arg timestamp "$(av_capture_timestamp)" \
        --argjson matrix "$identity_matrix" \
        --argjson violations "$violations" \
        '{
            timestamp: $timestamp,
            matrix: $matrix,
            violations: $violations
        }' > "$matrix_file"

    if [[ $violations -gt 0 ]]; then
        av_log_error "Device probes: $violations violation(s) found"
        return 1
    fi

    av_log_success "Device probes: all checks passed"
    return 0
}
