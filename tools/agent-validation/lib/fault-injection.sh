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
    "grant-races;passless-rs;agent::grant::tests;test_concurrent_claim_only_one_succeeds,agent::policy_engine::tests::test_concurrent_reloads_get_unique_monotonic_generations"
    "policy-reload;passless-rs;agent::policy_engine::tests;test_unchanged_reload_keeps_session_grants_and_changed_reload_drops_them,test_reload_cancels_pending_requests"
    "browser-cleanup-quarantine;passless-rs;agent::browser::tests;test_quarantine_path_format,test_quarantine_path_unique,test_pid_mismatch_cleanup_quarantines"
    "protocol-ipc;passless-rs;agent::ipc::tests;test_malformed_message_rejected"
    "monotonic-clocks;passless-rs;agent::browser::tests;test_system_clock_monotonic,test_mock_clock_advance,test_mock_clock_set_offset,test_mock_clock_concurrent_advance"
    "redaction;passless-rs;agent::audit_events::tests;test_no_secret_value_patterns,agent::launcher::tests::test_session_capability_debug_redacted,agent::launcher::tests::test_session_capability_display_redacted"
)

# Dummy-process helpers.
#
# Why these exist: a bash that has an EXIT trap installed (the test and stage
# harnesses do) also catches SIGTERM itself. A `sleep infinity &` child is a
# forked bash until it execs sleep; a SIGTERM that lands in that window runs
# bash's catch-and-record handler and is then discarded by execve, so the
# sleep never sees it and survives. Wait for the exec before signalling, and
# treat an unreaped zombie as exited.

# Succeeds once pid is exec'd into the given program (comm name), or fails after
# the deadline (seconds).
av_fault_wait_exec() {
    local pid="$1"
    local want="$2"
    local deadline_secs="${3:-10}"
    local ticks=$((deadline_secs * 100))
    local comm=""
    while [[ $ticks -gt 0 ]]; do
        comm=$(cat "/proc/${pid}/comm" 2>/dev/null) || return 1
        if [[ "$comm" == "$want" ]]; then
            return 0
        fi
        sleep 0.01
        ((ticks--)) || true
    done
    return 1
}

# Succeeds while pid is running (a zombie awaiting reap counts as exited).
av_fault_pid_running() {
    local pid="$1"
    local state=""
    kill -0 "$pid" 2>/dev/null || return 1
    state=$(awk '/^State:/ {print $2}' "/proc/${pid}/status" 2>/dev/null) || return 1
    [[ -n "$state" && "$state" != "Z" && "$state" != "X" ]]
}

# Spawn `sleep infinity` into the global AV_FAULT_SPAWNED_PID, ready for signals.
av_fault_spawn_sleeper() {
    sleep infinity &
    AV_FAULT_SPAWNED_PID=$!
    av_fault_wait_exec "$AV_FAULT_SPAWNED_PID" sleep 10
}

# Send SIGTERM and poll (generous deadline) until pid exits. Returns 0 if it
# exited on SIGTERM, 1 if SIGKILL was required. Always reaps the pid.
av_fault_terminate() {
    local pid="$1"
    local deadline_secs="${2:-15}"
    local ticks=$((deadline_secs * 10))
    local rc=0
    kill -TERM "$pid" 2>/dev/null || true
    while av_fault_pid_running "$pid" && [[ $ticks -gt 0 ]]; do
        sleep 0.1
        ((ticks--)) || true
    done
    if av_fault_pid_running "$pid"; then
        kill -KILL "$pid" 2>/dev/null || true
        rc=1
    fi
    wait "$pid" 2>/dev/null || true
    return $rc
}

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
        timeout --kill-after=15s "${timeout_secs}s" cargo test --all-features -p "$crate" \
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

        av_fault_spawn_sleeper || echo "dummy_exec_wait_failed=true"
        dummy_pid="$AV_FAULT_SPAWNED_PID"

        local ulimit_v
        ulimit_v=$(ulimit -v 2>/dev/null || echo "unlimited")
        echo "ulimit_virtual_kb=${ulimit_v}"

        local ulimit_f
        ulimit_f=$(ulimit -f 2>/dev/null || echo "unlimited")
        echo "ulimit_file_size=${ulimit_f}"

        av_fault_terminate "$dummy_pid" 15 || true

        rm -f "$dummy_file" 2>/dev/null || true
    } > "$log_file" 2>&1

    if [[ -n "$dummy_pid" ]] && av_fault_pid_running "$dummy_pid"; then
        kill -KILL "$dummy_pid" 2>/dev/null || true
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
        local pid1 pid2
        av_fault_spawn_sleeper || echo "pid1_exec_wait_failed=true"
        pid1="$AV_FAULT_SPAWNED_PID"
        av_fault_spawn_sleeper || echo "pid2_exec_wait_failed=true"
        pid2="$AV_FAULT_SPAWNED_PID"

        echo "spawned_pids=${pid1},${pid2}"

        if ! av_fault_terminate "$pid1" "$timeout_secs"; then
            result="fail"
            detail="pid1 required SIGKILL"
        fi

        if ! av_fault_terminate "$pid2" "$timeout_secs"; then
            if [[ "$result" == "pass" ]]; then
                result="fail"
                detail="pid2 required SIGKILL"
            fi
        fi

        echo "cleanup_complete=true"
    } > "$log_file" 2>&1

    printf '%s\n' "{\"category\":\"process-kill\",\"status\":\"${result}\",\"detail\":\"${detail}\"}"
    if [[ "$result" == "fail" ]]; then
        return 1
    fi
    return 0
}
