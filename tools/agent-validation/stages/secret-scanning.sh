#!/bin/bash
#
# Tier 1 Stage: Secret Scanning
# Generates unique sentinels, runs fixture command + existing redaction tests,
# scans orchestrator logs/evidence for sentinel leaks, and ensures reports are clean.
#

set -euo pipefail

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/common.sh"
fi
if [[ -z "${AV_LIB_SECRET_SCANNING_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/secret-scanning.sh"
fi

# shellcheck disable=SC2034
AV_STAGE_SECRET_SCANNING_LOADED=true

AV_REDACTION_TEST_FILTERS=(
    "passless-rs|agent::audit_events::tests::test_no_secret_value_patterns"
    "passless-rs|agent::intent::tests::test_claim_token_display_redacted"
    "passless-rs|agent::intent::tests::test_claim_token_debug_redacted"
    "passless-rs|agent::interaction::tests::test_debug_redacts_token_bytes"
    "passless-rs|agent::launcher::tests::test_session_capability_debug_redacted"
    "passless-rs|agent::launcher::tests::test_session_capability_display_redacted"
    "passless-rs|agent::ceremony_observer::tests::test_observation_debug_has_no_secret_fields"
    "passless-rs|agent::ceremony_observer::tests::response_extraction::test_observation_correlation_id_is_non_secret"
)

stage_secret_scanning() {
    local results_file="${EVIDENCE_DIR:-/tmp}/secret-scanning-results.json"
    local evidence_dir="${EVIDENCE_DIR:-/tmp}"
    local temp_root="${TEMP_ROOT:-${evidence_dir}/tmp}"
    local scenarios_json="[]"
    local total=0
    local passed=0
    local failed=0
    local skipped=0
    local sentinel_file
    sentinel_file="${temp_root}/sentinels.$(date +%s).tmp"
    local findings_file
    findings_file="${temp_root}/scan-findings.$(date +%s).tmp"

    : > "$findings_file"

    cleanup_sentinels() {
        rm -f "$sentinel_file" 2>/dev/null || true
        rm -f "$findings_file" 2>/dev/null || true
    }
    trap cleanup_sentinels RETURN

    add_result() {
        local name="$1" status="$2" detail="${3:-}"
        scenarios_json=$(printf '%s' "$scenarios_json" | jq \
            --arg n "$name" --arg s "$status" --arg d "$detail" \
            '. + [{"name": $n, "status": $s, "detail": $d}]')
        ((total++)) || true
        case "$status" in
            pass) ((passed++)) || true ;;
            fail) ((failed++)) || true ;;
            skip) ((skipped++)) || true ;;
        esac
    }

    av_log_info "Starting secret scanning stage"

    av_log_info "Generating sentinel values"
    if ! av_generate_sentinels "$sentinel_file"; then
        add_result "sentinel_generation" "fail" "could not generate sentinels"
        _write_scan_results "$results_file" "$total" "$passed" "$failed" "$skipped" "$scenarios_json" "fail"
        return 1
    fi

    if [[ ! -f "$sentinel_file" ]]; then
        add_result "sentinel_generation" "fail" "sentinel file missing after generation"
        _write_scan_results "$results_file" "$total" "$passed" "$failed" "$skipped" "$scenarios_json" "fail"
        return 1
    fi

    local sentinel_perms
    sentinel_perms=$(stat -c '%a' "$sentinel_file" 2>/dev/null || echo "unknown")
    if [[ "$sentinel_perms" == "600" ]]; then
        add_result "sentinel_permissions" "pass" "mode=$sentinel_perms"
    else
        add_result "sentinel_permissions" "fail" "expected 600, got $sentinel_perms"
    fi

    local sentinel_count
    sentinel_count=$(wc -l < "$sentinel_file" 2>/dev/null || echo 0)
    if [[ "$sentinel_count" -ge "${#AV_SENTINEL_CLASSES[@]}" ]]; then
        add_result "sentinel_count" "pass" "count=$sentinel_count"
    else
        add_result "sentinel_count" "fail" "expected >= ${#AV_SENTINEL_CLASSES[@]}, got $sentinel_count"
    fi

    av_log_info "Running fixture command (emit-redacted-metadata)"
    local fixture_script="${AV_VALIDATION_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}/fixtures/secret-scan/emit-redacted-metadata.sh"
    local fixture_output=""
    local fixture_rc=0

    if [[ -x "$fixture_script" ]] || [[ -f "$fixture_script" ]]; then
        fixture_output=$(timeout 10s bash "$fixture_script" --sentinel-file "$sentinel_file" 2>&1) || fixture_rc=$?
        if [[ $fixture_rc -eq 0 ]]; then
            add_result "fixture_emit" "pass" "redacted metadata emitted"

            local fixture_file="${temp_root}/fixture-output.json"
            printf '%s\n' "$fixture_output" > "$fixture_file"

            local fixture_findings=0
            av_scan_file_for_sentinels "$fixture_file" "$sentinel_file" "$findings_file" || fixture_findings=$?
            if [[ $fixture_findings -eq 0 ]]; then
                add_result "fixture_sentinel_check" "pass" "no sentinels in fixture output"
            else
                add_result "fixture_sentinel_check" "fail" "${fixture_findings} sentinel(s) found in fixture output"
            fi

            local fixture_prohibited=0
            av_scan_file_for_prohibited_fields "$fixture_file" "$findings_file" || fixture_prohibited=$?
            if [[ $fixture_prohibited -eq 0 ]]; then
                add_result "fixture_prohibited_fields" "pass" "no prohibited fields"
            else
                add_result "fixture_prohibited_fields" "fail" "${fixture_prohibited} prohibited field(s) found"
            fi
        else
            add_result "fixture_emit" "fail" "exit_code=$fixture_rc"
        fi
    else
        add_result "fixture_emit" "skip" "fixture script not found"
    fi

    av_log_info "Running existing redaction tests"
    if command -v cargo &>/dev/null; then
        local redaction_log="${evidence_dir}/secret-scan-redaction-tests.log"
        local redaction_rc=0
        : > "$redaction_log"

        for spec in "${AV_REDACTION_TEST_FILTERS[@]}"; do
            local crate="${spec%%|*}"
            local test_path="${spec#*|}"
            local one_log="${temp_root}/redaction-test.log"
            timeout --kill-after=15s 180s cargo test --all-features -p "$crate" --bin passless \
                "$test_path" -- --exact --test-threads=1 > "$one_log" 2>&1 || redaction_rc=$?
            cat "$one_log" >> "$redaction_log"
            if [[ $redaction_rc -ne 0 ]] \
                || ! grep -q 'test result: ok\. 1 passed; 0 failed' "$one_log"; then
                [[ $redaction_rc -eq 0 ]] && redaction_rc=1
                rm -f "$one_log"
                break
            fi
            rm -f "$one_log"
        done

        if [[ $redaction_rc -eq 0 ]]; then
            add_result "redaction_tests" "pass" "all redaction tests passed"
        elif [[ $redaction_rc -eq 124 ]]; then
            add_result "redaction_tests" "fail" "timeout after 180s"
        else
            add_result "redaction_tests" "fail" "exit_code=$redaction_rc"
        fi
    else
        add_result "redaction_tests" "skip" "cargo not available"
    fi

    av_log_info "Scanning orchestrator logs and evidence"
    local scan_targets=()
    if [[ -f "${evidence_dir}/orchestrator.log" ]]; then
        scan_targets+=("${evidence_dir}/orchestrator.log")
    fi
    if [[ -f "${evidence_dir}/report.json" ]]; then
        scan_targets+=("${evidence_dir}/report.json")
    fi
    if [[ -f "${evidence_dir}/environment.json" ]]; then
        scan_targets+=("${evidence_dir}/environment.json")
    fi
    for f in "${evidence_dir}"/*.log; do
        [[ -f "$f" ]] && scan_targets+=("$f")
    done
    for f in "${evidence_dir}"/*-results.json; do
        [[ -f "$f" ]] && scan_targets+=("$f")
    done

    local evidence_findings=0
    for target in "${scan_targets[@]}"; do
        local f_findings=0
        av_scan_file_for_sentinels "$target" "$sentinel_file" "$findings_file" || f_findings=$?
        evidence_findings=$((evidence_findings + f_findings))

        local p_findings=0
        av_scan_file_for_prohibited_fields "$target" "$findings_file" || p_findings=$?
        evidence_findings=$((evidence_findings + p_findings))

        local r_findings=0
        av_scan_file_for_raw_payload_markers "$target" "$findings_file" || r_findings=$?
        evidence_findings=$((evidence_findings + r_findings))
    done

    if [[ ${#scan_targets[@]} -gt 0 ]]; then
        if [[ $evidence_findings -eq 0 ]]; then
            add_result "evidence_scan" "pass" "scanned ${#scan_targets[@]} file(s), no leaks"
        else
            add_result "evidence_scan" "fail" "${evidence_findings} finding(s) in evidence"
        fi
    else
        add_result "evidence_scan" "pass" "no evidence files to scan"
    fi

    av_log_info "Verifying sentinel file cleanup"
    cleanup_sentinels
    trap - RETURN

    if [[ ! -f "$sentinel_file" ]]; then
        add_result "sentinel_cleanup" "pass" "sentinel file deleted before report"
    else
        add_result "sentinel_cleanup" "fail" "sentinel file still exists"
        rm -f "$sentinel_file" 2>/dev/null || true
    fi

    local overall="pass"
    if [[ $failed -gt 0 ]]; then
        overall="fail"
    fi

    _write_scan_results "$results_file" "$total" "$passed" "$failed" "$skipped" "$scenarios_json" "$overall"

    if [[ $failed -gt 0 ]]; then
        av_log_error "Secret scanning: $failed/$total checks failed"
        return 1
    fi

    av_log_success "Secret scanning: $passed/$total checks passed ($skipped skipped)"
    return 0
}

_write_scan_results() {
    local results_file="$1" total="$2" passed="$3" failed="$4" skipped="$5" scenarios_json="$6" overall="$7"

    jq -n \
        --arg ts "$(av_capture_timestamp)" \
        --arg status "$overall" \
        --argjson total "$total" \
        --argjson passed "$passed" \
        --argjson failed "$failed" \
        --argjson skipped "$skipped" \
        --argjson scenarios "$scenarios_json" \
        '{timestamp: $ts, status: $status, total: $total, passed: $passed, failed: $failed, skipped: $skipped, scenarios: $scenarios}' \
        > "$results_file"
}
