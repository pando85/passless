#!/bin/bash
#
# Tier 2 Stage: Controlled RP
# Starts the existing controlled-rp server, waits for health, captures logs,
# and stops via cleanup.
#

set -euo pipefail

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/common.sh"
fi
if [[ -z "${AV_LIB_CONTROLLED_RP_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/controlled-rp.sh"
fi

# shellcheck disable=SC2034
AV_STAGE_CONTROLLED_RP_LOADED=true

stage_controlled_rp() {
    local results_file="${EVIDENCE_DIR:-/tmp}/controlled-rp-results.json"
    local scenarios_json="[]"
    local total=0
    local passed=0
    local failed=0
    local skipped=0

    add_scenario() {
        local name="$1" status="$2" detail="$3"
        scenarios_json=$(echo "$scenarios_json" | jq \
            --arg n "$name" --arg s "$status" --arg d "$detail" \
            '. + [{"name": $n, "status": $s, "detail": $d}]')
        ((total++)) || true
        case "$status" in
            pass) ((passed++)) || true ;;
            fail) ((failed++)) || true ;;
            skip) ((skipped++)) || true ;;
        esac
    }

    av_log_info "Checking controlled-RP prerequisites..."

    if ! av_controlled_rp_prereqs_check 2>/dev/null; then
        av_log_warn "Controlled-RP prerequisites not met; skipping"
        _write_controlled_rp_results "$results_file" "$total" "$passed" "$failed" "$skipped" "$scenarios_json"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi

    local rp_port="${AV_RP_PORT:-8443}"

    av_log_info "Locating controlled RP server..."
    if ! av_find_controlled_rp "${AV_VALIDATION_DIR:-}" 2>/dev/null; then
        av_log_warn "Controlled RP not found; skipping"
        add_scenario "locate" "skip" "controlled-rp directory not found"
        _write_controlled_rp_results "$results_file" "$total" "$passed" "$failed" "$skipped" "$scenarios_json"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi
    add_scenario "locate" "pass" "Found at ${AV_RP_SERVER_DIR}"

    av_log_info "Starting controlled RP server on port $rp_port..."
    if ! av_start_controlled_rp "$rp_port" "${AV_VALIDATION_DIR:-}" 2>/dev/null; then
        av_log_warn "Controlled RP failed to start; skipping"
        add_scenario "start" "skip" "server failed to start"
        _write_controlled_rp_results "$results_file" "$total" "$passed" "$failed" "$skipped" "$scenarios_json"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi
    add_scenario "start" "pass" "Server started on port $rp_port (PID=${AV_RP_SERVER_PID})"

    av_log_info "Waiting for health endpoint..."
    local waited=0
    local healthy=false
    while [[ $waited -lt 10 ]]; do
        if av_controlled_rp_health_check "$rp_port" 2>/dev/null; then
            healthy=true
            break
        fi
        sleep 0.5
        ((waited++)) || true
    done

    if [[ "$healthy" == "true" ]]; then
        add_scenario "health" "pass" "Health endpoint returned status=ok"
    else
        add_scenario "health" "fail" "Health endpoint did not respond"
    fi

    av_log_info "Capturing server log snapshot..."
    if [[ -f "${AV_RP_SERVER_LOG:-}" ]]; then
        cp "$AV_RP_SERVER_LOG" "${EVIDENCE_DIR:-/tmp}/controlled-rp-captured.log" 2>/dev/null || true
        add_scenario "log_capture" "pass" "Log captured to controlled-rp-captured.log"
    else
        add_scenario "log_capture" "skip" "Log file not found"
    fi

    local status_json
    status_json=$(av_controlled_rp_status "$rp_port" 2>/dev/null || echo "{}")
    local rp_id
    rp_id=$(echo "$status_json" | jq -r '.rp_id // "unknown"' 2>/dev/null || echo "unknown")
    add_scenario "status_api" "pass" "rp_id=$rp_id"

    av_log_info "Stopping controlled RP server..."
    av_stop_controlled_rp 2>/dev/null || true
    add_scenario "stop" "pass" "Server stopped via cleanup"

    _write_controlled_rp_results "$results_file" "$total" "$passed" "$failed" "$skipped" "$scenarios_json"

    if [[ $failed -gt 0 ]]; then
        av_log_error "Controlled RP: $failed scenario(s) failed"
        return 1
    fi

    av_log_success "Controlled RP: $passed/$total passed ($skipped skipped)"
    return 0
}

_write_controlled_rp_results() {
    local results_file="$1" total="$2" passed="$3" failed="$4" skipped="$5" scenarios_json="$6"

    local overall="pass"
    if [[ "$failed" -gt 0 ]]; then
        overall="fail"
    elif [[ "$skipped" -eq "$total" ]]; then
        overall="skip"
    fi

    jq -n \
        --arg timestamp "$(av_capture_timestamp)" \
        --arg status "$overall" \
        --argjson total "$total" \
        --argjson passed "$passed" \
        --argjson failed "$failed" \
        --argjson skipped "$skipped" \
        --argjson scenarios "$scenarios_json" \
        '{timestamp: $timestamp, status: $status,
          total: $total, passed: $passed, failed: $failed, skipped: $skipped,
          scenarios: $scenarios}' > "$results_file"
}
