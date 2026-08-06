#!/bin/bash
#
# Tier 1 Stage: Fault Injection
# Runs focused existing Rust tests for fault categories plus bounded
# shell process-kill/resource-ceiling checks on orchestrator-owned dummies.
#

set -euo pipefail

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/common.sh"
fi
if [[ -z "${AV_LIB_FAULT_INJECTION_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/fault-injection.sh"
fi

# shellcheck disable=SC2034
AV_STAGE_FAULT_INJECTION_LOADED=true

stage_fault_injection() {
    local results_file="${EVIDENCE_DIR:-/tmp}/fault-injection-results.json"
    local timeout_secs="${AV_FAULT_DEFAULT_TIMEOUT:-120}"
    local scenarios_json="[]"
    local total=0
    local passed=0
    local failed=0
    local timed_out=0

    add_result() {
        local name="$1" status="$2" detail="${3:-}"
        scenarios_json=$(printf '%s' "$scenarios_json" | jq \
            --arg n "$name" --arg s "$status" --arg d "$detail" \
            '. + [{"name": $n, "status": $s, "detail": $d}]')
        ((total++)) || true
        case "$status" in
            pass) ((passed++)) || true ;;
            fail) ((failed++)) || true ;;
            timeout) ((timed_out++)) || true; ((failed++)) || true ;;
        esac
    }

    av_log_info "Starting fault injection stage (timeout=${timeout_secs}s per category)"

    if ! command -v cargo &>/dev/null; then
        av_log_warn "cargo not available; skipping fault injection"
        jq -n --arg ts "$(av_capture_timestamp)" \
            '{timestamp: $ts, status: "skipped", reason: "cargo unavailable", total: 0, passed: 0, failed: 0, timed_out: 0, scenarios: []}' \
            > "$results_file"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi

    for category_spec in "${AV_FAULT_RUST_CATEGORIES[@]}"; do
        local category_name
        category_name="${category_spec%%;*}"
        av_log_info "Running fault category: $category_name"

        local result_json
        local rc=0
        result_json=$(av_run_fault_rust_category "$category_spec" "$timeout_secs" "${EVIDENCE_DIR:-/tmp}") || rc=$?

        local status
        status=$(printf '%s' "$result_json" | jq -r '.status // "unknown"' 2>/dev/null || echo "unknown")
        local detail
        detail=$(printf '%s' "$result_json" | jq -r '.detail // empty' 2>/dev/null || echo "")

        case $rc in
            0) add_result "$category_name" "pass" "$detail" ;;
            2) add_result "$category_name" "timeout" "exceeded ${timeout_secs}s" ;;
            *) add_result "$category_name" "fail" "exit_code=${rc} ${detail}" ;;
        esac
    done

    av_log_info "Running resource-ceiling check"
    local rc_result
    local rc_rc=0
    rc_result=$(av_run_resource_ceiling_check "${EVIDENCE_DIR:-/tmp}" 30) || rc_rc=$?
    local rc_detail
    rc_detail=$(printf '%s' "$rc_result" | jq -r '.detail // empty' 2>/dev/null || echo "")
    if [[ $rc_rc -ne 0 ]]; then
        add_result "resource-ceiling" "fail" "$rc_detail"
    else
        add_result "resource-ceiling" "pass" "$rc_detail"
    fi

    av_log_info "Running process-kill check"
    local pk_result
    local pk_rc=0
    pk_result=$(av_run_process_kill_check "${EVIDENCE_DIR:-/tmp}" 15) || pk_rc=$?
    local pk_detail
    pk_detail=$(printf '%s' "$pk_result" | jq -r '.detail // empty' 2>/dev/null || echo "")
    if [[ $pk_rc -ne 0 ]]; then
        add_result "process-kill" "fail" "$pk_detail"
    else
        add_result "process-kill" "pass" "$pk_detail"
    fi

    local overall="pass"
    if [[ $failed -gt 0 ]]; then
        overall="fail"
    fi

    jq -n \
        --arg ts "$(av_capture_timestamp)" \
        --arg status "$overall" \
        --argjson total "$total" \
        --argjson passed "$passed" \
        --argjson failed "$failed" \
        --argjson timed_out "$timed_out" \
        --argjson scenarios "$scenarios_json" \
        '{timestamp: $ts, status: $status, total: $total, passed: $passed, failed: $failed, timed_out: $timed_out, scenarios: $scenarios}' \
        > "$results_file"

    if [[ $failed -gt 0 ]]; then
        av_log_error "Fault injection: $failed/$total categories failed"
        return 1
    fi

    av_log_success "Fault injection: $passed/$total categories passed"
    return 0
}
