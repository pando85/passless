#!/bin/bash
#
# Principal identity checks — probe-based
#
# Invokes the agent-principal-probe binary via `passless agent run`
# and validates the emitted JSON report.
#

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
fi

# shellcheck disable=SC2034
AV_LIB_PRINCIPAL_LOADED=true

av_validate_probe_json_schema() {
    local json_file="$1"

    if [[ ! -f "$json_file" ]]; then
        av_log_error "probe JSON file not found: $json_file"
        return 1
    fi

    if ! jq empty "$json_file" 2>/dev/null; then
        av_log_error "probe output is not valid JSON"
        return 1
    fi

    local required_fields=("pid" "ppid" "start_time" "uid" "gid" "supplementary_gids" "namespaces" "cgroup_v2_path" "no_new_privs" "cap_env_names" "fd3" "resources")
    for field in "${required_fields[@]}"; do
        if ! jq -e "has(\"$field\")" "$json_file" &>/dev/null; then
            av_log_error "missing required field: $field"
            return 1
        fi
    done

    local pid_type uid_type gid_type nnp_type
    pid_type=$(jq -r '.pid | type' "$json_file")
    uid_type=$(jq -r '.uid | type' "$json_file")
    gid_type=$(jq -r '.gid | type' "$json_file")
    nnp_type=$(jq -r '.no_new_privs | type' "$json_file")

    if [[ "$pid_type" != "number" ]]; then
        av_log_error "pid must be a number, got: $pid_type"
        return 1
    fi
    if [[ "$uid_type" != "number" ]]; then
        av_log_error "uid must be a number, got: $uid_type"
        return 1
    fi
    if [[ "$gid_type" != "number" ]]; then
        av_log_error "gid must be a number, got: $gid_type"
        return 1
    fi
    if [[ "$nnp_type" != "boolean" ]]; then
        av_log_error "no_new_privs must be a boolean, got: $nnp_type"
        return 1
    fi

    local ns_type gids_type caps_type fd3_type res_type
    ns_type=$(jq -r '.namespaces | type' "$json_file")
    gids_type=$(jq -r '.supplementary_gids | type' "$json_file")
    caps_type=$(jq -r '.cap_env_names | type' "$json_file")
    fd3_type=$(jq -r '.fd3 | type' "$json_file")
    res_type=$(jq -r '.resources | type' "$json_file")

    if [[ "$ns_type" != "object" ]]; then
        av_log_error "namespaces must be an object, got: $ns_type"
        return 1
    fi
    if [[ "$gids_type" != "array" ]]; then
        av_log_error "supplementary_gids must be an array, got: $gids_type"
        return 1
    fi
    if [[ "$caps_type" != "array" ]]; then
        av_log_error "cap_env_names must be an array, got: $caps_type"
        return 1
    fi
    if [[ "$fd3_type" != "object" ]]; then
        av_log_error "fd3 must be an object, got: $fd3_type"
        return 1
    fi
    if [[ "$res_type" != "array" ]]; then
        av_log_error "resources must be an array, got: $res_type"
        return 1
    fi

    local cap_count
    cap_count=$(jq -r '.cap_env_names | length' "$json_file")
    if [[ "$cap_count" -gt 64 ]]; then
        av_log_error "cap_env_names has too many entries: $cap_count"
        return 1
    fi

    local ns_pid_ino
    ns_pid_ino=$(jq -r '.namespaces.pid // empty' "$json_file")
    if [[ -z "$ns_pid_ino" ]]; then
        av_log_error "namespaces.pid inode missing"
        return 1
    fi

    return 0
}

av_check_probe_uid_gid() {
    local json_file="$1"
    local expected_uid="$2"
    local expected_gid="$3"
    local violations=0

    local actual_uid actual_gid
    actual_uid=$(jq -r '.uid' "$json_file")
    actual_gid=$(jq -r '.gid' "$json_file")

    if [[ -n "$expected_uid" ]] && [[ "$actual_uid" != "$expected_uid" ]]; then
        av_log_error "UID mismatch: expected=$expected_uid actual=$actual_uid"
        ((violations++)) || true
    fi

    if [[ -n "$expected_gid" ]] && [[ "$actual_gid" != "$expected_gid" ]]; then
        av_log_error "GID mismatch: expected=$expected_gid actual=$actual_gid"
        ((violations++)) || true
    fi

    return $violations
}

av_check_probe_groups() {
    local json_file="$1"
    local expected_groups_csv="$2"
    local violations=0

    if [[ -z "$expected_groups_csv" ]]; then
        return 0
    fi

    local actual_gids
    actual_gids=$(jq -r '.supplementary_gids[]' "$json_file" 2>/dev/null || true)

    IFS=',' read -ra expected_gids <<< "$expected_groups_csv"
    for expected_gid in "${expected_gids[@]}"; do
        expected_gid="${expected_gid## }"
        expected_gid="${expected_gid%% }"
        if [[ -z "$expected_gid" ]]; then
            continue
        fi
        if ! echo "$actual_gids" | grep -qx "$expected_gid"; then
            av_log_error "expected supplementary GID $expected_gid not found"
            ((violations++)) || true
        fi
    done

    return $violations
}

av_check_probe_nnp() {
    local json_file="$1"
    local nnp_val
    nnp_val=$(jq -r '.no_new_privs' "$json_file")

    if [[ "$nnp_val" != "true" ]]; then
        av_log_error "NoNewPrivs is not true: $nnp_val"
        return 1
    fi
    return 0
}

av_check_probe_cap_absence() {
    local json_file="$1"
    local cap_count
    cap_count=$(jq -r '.cap_env_names | length' "$json_file")

    if [[ "$cap_count" -gt 0 ]]; then
        local cap_names
        cap_names=$(jq -r '.cap_env_names[]' "$json_file" | tr '\n' ',' | sed 's/,$//')
        av_log_error "capability-like env vars present (names only): $cap_names"
        return 1
    fi
    return 0
}

av_check_probe_namespace_separation() {
    local json_file="$1"
    local orchestrator_pid="${2:-$$}"
    local violations=0

    local probe_pid_ns probe_mnt_ns
    probe_pid_ns=$(jq -r '.namespaces.pid' "$json_file")
    probe_mnt_ns=$(jq -r '.namespaces.mnt' "$json_file")

    if [[ "$probe_pid_ns" == "null" ]] || [[ -z "$probe_pid_ns" ]] || \
       [[ "$probe_mnt_ns" == "null" ]] || [[ -z "$probe_mnt_ns" ]]; then
        av_log_error "namespace inodes unavailable in probe report"
        return 1
    fi

    local orch_pid_ns orch_mnt_ns
    orch_pid_ns=$(stat -c '%i' "/proc/${orchestrator_pid}/ns/pid" 2>/dev/null || echo "0")
    orch_mnt_ns=$(stat -c '%i' "/proc/${orchestrator_pid}/ns/mnt" 2>/dev/null || echo "0")

    if [[ "$orch_pid_ns" == "0" ]] || [[ "$orch_mnt_ns" == "0" ]]; then
        av_log_error "orchestrator namespace inodes unavailable"
        return 1
    fi

    if [[ "$probe_pid_ns" == "$orch_pid_ns" ]] && [[ "$probe_mnt_ns" == "$orch_mnt_ns" ]]; then
        av_log_error "probe shares pid+mnt namespaces with orchestrator"
        ((violations++)) || true
    fi

    return $violations
}

av_check_probe_cgroup_separation() {
    local json_file="$1"
    local orchestrator_pid="${2:-$$}"
    local violations=0

    local probe_cgroup orch_cgroup
    probe_cgroup=$(jq -r '.cgroup_v2_path' "$json_file")

    if [[ "$probe_cgroup" == "null" ]] || [[ -z "$probe_cgroup" ]] || [[ "$probe_cgroup" == "unavailable" ]]; then
        av_log_error "cgroup v2 path unavailable in probe report"
        return 1
    fi

    orch_cgroup=$(head -1 "/proc/${orchestrator_pid}/cgroup" 2>/dev/null | sed 's/^[^:]*:[^:]*://' || echo "unavailable")

    if [[ "$orch_cgroup" == "unavailable" ]] || [[ -z "$orch_cgroup" ]]; then
        av_log_error "orchestrator cgroup path unavailable"
        return 1
    fi

    if [[ "$probe_cgroup" == "$orch_cgroup" ]]; then
        av_log_error "probe in same cgroup as orchestrator: $probe_cgroup"
        ((violations++)) || true
    fi

    return $violations
}

av_check_probe_fd3() {
    local json_file="$1"
    local expected_peer_uid="$2"
    local expected_peer_gid="$3"
    local violations=0

    local fd3_present fd3_type
    fd3_present=$(jq -r '.fd3.present' "$json_file")
    fd3_type=$(jq -r '.fd3.fd_type' "$json_file")

    if [[ "$fd3_present" != "true" ]]; then
        av_log_error "fd3 is not present"
        return 1
    fi

    if [[ "$fd3_type" != "socket" ]]; then
        av_log_error "fd3 is not a socket: $fd3_type"
        ((violations++)) || true
    fi

    if [[ -n "$expected_peer_uid" ]]; then
        local actual_peer_uid
        actual_peer_uid=$(jq -r '.fd3.peer_uid // empty' "$json_file")
        if [[ "$actual_peer_uid" != "$expected_peer_uid" ]]; then
            av_log_error "fd3 peer UID mismatch: expected=$expected_peer_uid actual=$actual_peer_uid"
            ((violations++)) || true
        fi
    fi

    if [[ -n "$expected_peer_gid" ]]; then
        local actual_peer_gid
        actual_peer_gid=$(jq -r '.fd3.peer_gid // empty' "$json_file")
        if [[ "$actual_peer_gid" != "$expected_peer_gid" ]]; then
            av_log_error "fd3 peer GID mismatch: expected=$expected_peer_gid actual=$actual_peer_gid"
            ((violations++)) || true
        fi
    fi

    return $violations
}

av_check_probe_resource_outcomes() {
    local json_file="$1"
    shift
    local expectations=("$@")
    local violations=0

    for expectation in "${expectations[@]}"; do
        local res_path expected_outcome
        res_path="${expectation%%=*}"
        expected_outcome="${expectation#*=}"

        local actual_outcome
        actual_outcome=$(jq -r --arg p "$res_path" '.resources[] | select(.path == $p) | .outcome' "$json_file" 2>/dev/null || echo "not_found")

        if [[ "$actual_outcome" != "$expected_outcome" ]]; then
            av_log_error "resource $res_path: expected=$expected_outcome actual=$actual_outcome"
            ((violations++)) || true
        fi
    done

    return $violations
}

av_run_principal_probe() {
    local output_file="$1"
    local stderr_file="$2"
    local profile="$3"
    local passless_bin="$4"
    local probe_bin="$5"
    shift 5
    local resource_paths=("$@")

    if [[ ! -x "$passless_bin" ]]; then
        av_log_error "passless binary not found or not executable: $passless_bin"
        return 1
    fi

    if [[ ! -x "$probe_bin" ]]; then
        av_log_error "probe binary not found or not executable: $probe_bin"
        return 1
    fi

    if [[ "$probe_bin" != /* ]]; then
        av_log_error "probe binary path must be absolute: $probe_bin"
        return 1
    fi

    local cmd=()
    if [[ "${AV_AGENT_ADMIN_USE_SUDO:-0}" == "1" ]]; then
        cmd+=(sudo --)
    fi
    cmd+=("$passless_bin" "agent" "run" "--profile" "$profile" "--" "$probe_bin")
    cmd+=("${resource_paths[@]}")

    local env_vars=()
    if [[ -n "${PASSLESS_AGENT_RUNTIME_DIR:-}" ]]; then
        if [[ "$PASSLESS_AGENT_RUNTIME_DIR" == /* ]] && [[ ! -L "$PASSLESS_AGENT_RUNTIME_DIR" ]]; then
            env_vars+=("PASSLESS_AGENT_RUNTIME_DIR=$PASSLESS_AGENT_RUNTIME_DIR")
        else
            av_log_error "PASSLESS_AGENT_RUNTIME_DIR must be absolute and not a symlink"
            return 1
        fi
    fi

    if [[ ${#env_vars[@]} -gt 0 ]]; then
        env "${env_vars[@]}" "${cmd[@]}" >"$output_file" 2>"$stderr_file"
    else
        "${cmd[@]}" >"$output_file" 2>"$stderr_file"
    fi

    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        av_log_error "probe invocation failed (exit=$exit_code)"
        return 1
    fi

    if [[ ! -s "$output_file" ]]; then
        av_log_error "probe produced no stdout output"
        return 1
    fi

    return 0
}

av_compare_probe_pid_with_launch_metadata() {
    local json_file="$1"
    local stderr_file="$2"

    local probe_pid
    probe_pid=$(jq -r '.pid' "$json_file" 2>/dev/null || echo "0")

    local launched_pid=""
    if [[ -f "$stderr_file" ]]; then
        if jq empty "$stderr_file" 2>/dev/null; then
            launched_pid=$(jq -r '.data.pid // empty' "$stderr_file" 2>/dev/null || echo "")
        fi
        if [[ -z "$launched_pid" ]]; then
            launched_pid=$(grep -oP 'pid:\s*\K[0-9]+' "$stderr_file" 2>/dev/null || echo "")
        fi
    fi

    if [[ -z "$launched_pid" ]]; then
        av_log_error "PrincipalLaunched PID metadata not found"
        return 1
    fi

    if [[ "$probe_pid" != "$launched_pid" ]]; then
        av_log_error "probe pid ($probe_pid) differs from PrincipalLaunched pid ($launched_pid)"
        return 1
    fi

    av_log_info "probe pid ($probe_pid) matches PrincipalLaunched pid"
    return 0
}

av_check_probe_uid_matches_user() {
    local json_file="$1"
    local username="$2"

    if [[ -z "$username" ]]; then
        return 0
    fi

    local expected_uid
    expected_uid=$(getent passwd "$username" 2>/dev/null | cut -d: -f3 || echo "")

    if [[ -z "$expected_uid" ]]; then
        av_log_error "cannot resolve UID for user: $username"
        return 1
    fi

    local actual_uid
    actual_uid=$(jq -r '.uid' "$json_file")

    if [[ "$actual_uid" != "$expected_uid" ]]; then
        av_log_error "probe UID ($actual_uid) does not match user $username (expected $expected_uid)"
        return 1
    fi

    return 0
}
