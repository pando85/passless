#!/bin/bash
#
# Shared helpers for the fault-injection stage
#

# shellcheck disable=SC2034
AV_LIB_FAULT_INJECTION_LOADED=true

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
fi

AV_FAULT_DEFAULT_TIMEOUT="${AV_FAULT_DEFAULT_TIMEOUT:-120}"

AV_FAULT_RUST_CATEGORIES=(
    "audit-enospc-fsync;passless-rs;agent::audit::tests;test_enospc_failure,test_fsync_failure,test_partial_write_failure"
    "audit-recovery;passless-rs;agent::audit::tests;test_audit_gate_detects_tampering,test_audit_gate_detects_segment_deletion,test_crash_tail_before_anchor,test_reorder_detected,test_delete_middle_segment"
    "audit-circuit-breaker;passless-rs;agent::audit::tests;test_circuit_breaker_permanent"
    "audit-rotation;passless-rs;agent::audit::tests;test_audit_gate_rotation,test_cross_segment_reopen,test_empty_rotated_segment_restart"
    "intent-grant-races;passless-rs;agent::intent::tests;test_cancel_approve_race_cancel_wins,agent::policy_engine::tests::test_two_authorize_races_one_intent_one_succeeds,agent::policy_engine::tests::test_intent_replay_denied,agent::policy_engine::tests::test_concurrent_authorize_one_claim,agent::grant::tests::test_concurrent_claim_only_one_succeeds"
    "policy-reload;passless-rs;agent::policy_engine::tests;test_reload_invalidates_stores"
    "endpoint-capacity;passless-rs;agent::endpoint_manager::tests;test_create_rejected_capacity_exceeded,test_endpoint_creation_failure_marks_endpoint_failed"
    "browser-cleanup-quarantine;passless-rs;agent::browser::tests;test_quarantine_path_format,test_quarantine_path_unique,test_pid_mismatch_cleanup_quarantines"
    "protocol-malformed-cbor;passless-rs;agent::ceremony::tests;test_parse_make_credential_invalid_cbor,test_parse_response_malformed_cbor,test_fuzz_truncated_cbor,test_malformed_truncated_cbor,test_malformed_indefinite_length_not_supported"
    "protocol-ipc;passless-rs;agent::ipc::tests;test_malformed_message_rejected"
    "monotonic-clocks;passless-rs;agent::browser::tests;test_system_clock_monotonic,test_mock_clock_advance,test_mock_clock_set_offset,test_mock_clock_concurrent_advance"
    "redaction;passless-rs;agent::audit_events::tests;test_no_secret_value_patterns,agent::intent::tests::test_claim_token_display_redacted,agent::intent::tests::test_claim_token_debug_redacted,agent::interaction::tests::test_debug_redacts_token_bytes,agent::launcher::tests::test_session_capability_debug_redacted,agent::launcher::tests::test_session_capability_display_redacted,agent::ceremony_observer::tests::test_observation_debug_has_no_secret_fields"
)

av_run_fault_rust_category() {
    local category_spec="$1"
    local timeout_secs="${2:-$AV_FAULT_DEFAULT_TIMEOUT}"
    local evidence_dir="${3:-/tmp}"

    IFS=';' read -r category_name crate test_module test_names <<< "$category_spec"

    local log_file="${evidence_dir}/fault-${category_name}.log"
    local exit_code=0

    : > "$log_file"
    IFS=',' read -ra individual_tests <<< "$test_names"
    for test_name in "${individual_tests[@]}"; do
        local full_name="$test_name"
        if [[ "$test_name" != *::* ]]; then
            full_name="${test_module}::${test_name}"
        fi

        local test_log="${log_file}.one"
        timeout "${timeout_secs}s" cargo test --all-features -p "$crate" \
            --bin passless "$full_name" -- --exact --test-threads=1 \
            > "$test_log" 2>&1 || exit_code=$?
        cat "$test_log" >> "$log_file"

        if [[ $exit_code -ne 0 ]]; then
            rm -f "$test_log"
            break
        fi
        if ! grep -q 'test result: ok\. 1 passed; 0 failed' "$test_log"; then
            printf 'named test did not execute exactly once: %s\n' "$full_name" >> "$log_file"
            exit_code=1
            rm -f "$test_log"
            break
        fi
        rm -f "$test_log"
    done

    if [[ $exit_code -eq 124 ]]; then
        printf '%s\n' "{\"category\":\"${category_name}\",\"status\":\"timeout\",\"timeout_secs\":${timeout_secs}}"
        return 2
    fi

    if [[ $exit_code -ne 0 ]]; then
        printf '%s\n' "{\"category\":\"${category_name}\",\"status\":\"fail\",\"exit_code\":${exit_code}}"
        return 1
    fi

    printf '%s\n' "{\"category\":\"${category_name}\",\"status\":\"pass\"}"
    return 0
}

av_run_resource_ceiling_check() {
    local evidence_dir="${1:-/tmp}"
    local timeout_secs="${2:-30}"
    local log_file="${evidence_dir}/fault-resource-ceiling.log"

    local dummy_dir="${evidence_dir}/tmp/resource-ceiling"
    mkdir -p "$dummy_dir"

    local dummy_file="${dummy_dir}/ceiling-test.bin"
    local dummy_pid=""
    local result="pass"
    local detail=""

    {
        timeout "${timeout_secs}s" dd if=/dev/zero of="$dummy_file" bs=1M count=8 2>&1 || true

        local file_size
        file_size=$(stat -c %s "$dummy_file" 2>/dev/null || echo 0)
        echo "dummy_file_size=${file_size}"

        sleep infinity &
        dummy_pid=$!

        local ulimit_v
        ulimit_v=$(ulimit -v 2>/dev/null || echo "unlimited")
        echo "ulimit_virtual_kb=${ulimit_v}"

        local ulimit_f
        ulimit_f=$(ulimit -f 2>/dev/null || echo "unlimited")
        echo "ulimit_file_size=${ulimit_f}"

        if kill -0 "$dummy_pid" 2>/dev/null; then
            kill "$dummy_pid" 2>/dev/null || true
            wait "$dummy_pid" 2>/dev/null || true
        fi

        rm -f "$dummy_file" 2>/dev/null || true
    } > "$log_file" 2>&1

    if [[ -n "$dummy_pid" ]] && kill -0 "$dummy_pid" 2>/dev/null; then
        kill "$dummy_pid" 2>/dev/null || true
        wait "$dummy_pid" 2>/dev/null || true
        result="fail"
        detail="dummy process not terminated"
    fi

    rm -rf "$dummy_dir" 2>/dev/null || true

    printf '%s\n' "{\"category\":\"resource-ceiling\",\"status\":\"${result}\",\"detail\":\"${detail}\"}"
    if [[ "$result" == "fail" ]]; then
        return 1
    fi
    return 0
}

av_run_process_kill_check() {
    local evidence_dir="${1:-/tmp}"
    local timeout_secs="${2:-15}"
    local log_file="${evidence_dir}/fault-process-kill.log"

    local result="pass"
    local detail=""

    {
        sleep infinity &
        local pid1=$!

        sleep infinity &
        local pid2=$!

        echo "spawned_pids=${pid1},${pid2}"

        if kill -0 "$pid1" 2>/dev/null; then
            kill "$pid1" 2>/dev/null || true
            local waited=0
            while kill -0 "$pid1" 2>/dev/null && [[ $waited -lt $((timeout_secs * 10)) ]]; do
                sleep 0.1
                ((waited++)) || true
            done
            if kill -0 "$pid1" 2>/dev/null; then
                kill -9 "$pid1" 2>/dev/null || true
                wait "$pid1" 2>/dev/null || true
                result="fail"
                detail="pid1 required SIGKILL"
            fi
        fi
        wait "$pid1" 2>/dev/null || true

        if kill -0 "$pid2" 2>/dev/null; then
            kill -TERM "$pid2" 2>/dev/null || true
            local waited=0
            while kill -0 "$pid2" 2>/dev/null && [[ $waited -lt $((timeout_secs * 10)) ]]; do
                sleep 0.1
                ((waited++)) || true
            done
            if kill -0 "$pid2" 2>/dev/null; then
                kill -9 "$pid2" 2>/dev/null || true
                wait "$pid2" 2>/dev/null || true
                if [[ "$result" == "pass" ]]; then
                    result="fail"
                    detail="pid2 required SIGKILL"
                fi
            fi
        fi
        wait "$pid2" 2>/dev/null || true

        echo "cleanup_complete=true"
    } > "$log_file" 2>&1

    printf '%s\n' "{\"category\":\"process-kill\",\"status\":\"${result}\",\"detail\":\"${detail}\"}"
    if [[ "$result" == "fail" ]]; then
        return 1
    fi
    return 0
}
