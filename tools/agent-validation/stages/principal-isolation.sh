#!/bin/bash
#
# Tier 3 Stage: Principal Isolation
#
# Invokes the agent-principal-probe via `passless agent run --profile <profile>`
# and validates the emitted JSON report against isolation constraints.
#
# Required environment variables:
#   AV_PRINCIPAL_PROFILE      - agent profile name
#   AV_PRINCIPAL_USER         - expected OS username for the profile
#   AV_PASSLESS_BIN           - absolute path to release-built passless binary
#   AV_PRINCIPAL_PROBE_BIN    - absolute path to agent-principal-probe binary
#   AV_PRINCIPAL_EXPECT_UID   - expected UID (numeric)
#   AV_PRINCIPAL_EXPECT_GID   - expected GID (numeric)
#   AV_PRINCIPAL_EXPECT_GROUPS - comma-separated expected supplementary GIDs
#   AV_PRINCIPAL_EXPECT_FD3_PEER_UID - expected fd3 peer UID
#   AV_PRINCIPAL_EXPECT_FD3_PEER_GID - expected fd3 peer GID
#   AV_PRINCIPAL_RESOURCE_PATHS - comma-separated absolute resource paths to probe
#   AV_PRINCIPAL_RESOURCE_EXPECT_<N> - expected outcome for resource N (path=outcome)
#   AV_AGENT_ADMIN_USE_SUDO   - set to "1" to invoke passless via sudo --
#   PASSLESS_AGENT_RUNTIME_DIR - optional runtime dir (must be absolute, no symlink)
#
# Missing live prerequisites => STAGE_SKIPPED, never pass.
#

set -euo pipefail

if [[ -z "${AV_LIB_COMMON_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/common.sh"
fi
if [[ -z "${AV_LIB_PRIVILEGE_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/privilege.sh"
fi
if [[ -z "${AV_LIB_PRINCIPAL_LOADED:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" && pwd)/principal.sh"
fi

# shellcheck disable=SC2034
AV_STAGE_PRINCIPAL_ISOLATION_LOADED=true

stage_principal_isolation() {
    local evidence_dir="${EVIDENCE_DIR:-/tmp}"
    local probe_json="${evidence_dir}/principal-probe.json"
    local probe_stderr="${evidence_dir}/principal-probe.stderr"
    local checks_file="${evidence_dir}/principal-checks.json"
    local violations=0
    local checks_json="[]"

    add_check() {
        local check="$1" name="$2" status="$3" detail="$4"
        checks_json=$(echo "$checks_json" | jq --arg c "$check" --arg n "$name" --arg s "$status" --arg d "$detail" \
            '. + [{"check": $c, "name": $n, "status": $s, "detail": $d}]')
    }

    local profile="${AV_PRINCIPAL_PROFILE:-}"
    local principal_user="${AV_PRINCIPAL_USER:-}"
    local passless_bin="${AV_PASSLESS_BIN:-}"
    local probe_bin="${AV_PRINCIPAL_PROBE_BIN:-}"
    local expect_uid="${AV_PRINCIPAL_EXPECT_UID:-}"
    local expect_gid="${AV_PRINCIPAL_EXPECT_GID:-}"
    local expect_groups="${AV_PRINCIPAL_EXPECT_GROUPS:-}"
    local expect_fd3_peer_uid="${AV_PRINCIPAL_EXPECT_FD3_PEER_UID:-}"
    local expect_fd3_peer_gid="${AV_PRINCIPAL_EXPECT_FD3_PEER_GID:-}"
    local resource_paths_csv="${AV_PRINCIPAL_RESOURCE_PATHS:-}"

    if [[ -z "$profile" ]] || [[ -z "$principal_user" ]] || [[ -z "$passless_bin" ]] || [[ -z "$probe_bin" ]]; then
        av_log_error "Missing required env: AV_PRINCIPAL_PROFILE, AV_PRINCIPAL_USER, AV_PASSLESS_BIN, AV_PRINCIPAL_PROBE_BIN"
        av_log_info "This stage requires an actual agent principal to test"
        add_check "PRIN-00" "prerequisites" "skip" "missing required env vars"

        jq -n \
            --argjson violations 0 \
            --argjson checks "$checks_json" \
            '{violations: $violations, checks: $checks, status: "skipped"}' > "$checks_file"

        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi

    if [[ -z "$expect_uid" ]] || [[ -z "$expect_gid" ]] || [[ -z "$expect_groups" ]]; then
        av_log_error "Missing mandatory: AV_PRINCIPAL_EXPECT_UID, AV_PRINCIPAL_EXPECT_GID, AV_PRINCIPAL_EXPECT_GROUPS"
        add_check "PRIN-00" "prerequisites" "skip" "missing mandatory identity vars"
        jq -n \
            --argjson violations 0 \
            --argjson checks "$checks_json" \
            '{violations: $violations, checks: $checks, status: "skipped"}' > "$checks_file"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi

    if [[ -z "$expect_fd3_peer_uid" ]] || [[ -z "$expect_fd3_peer_gid" ]]; then
        av_log_error "Missing mandatory: AV_PRINCIPAL_EXPECT_FD3_PEER_UID, AV_PRINCIPAL_EXPECT_FD3_PEER_GID"
        add_check "PRIN-00" "prerequisites" "skip" "missing mandatory fd3 peer vars"
        jq -n \
            --argjson violations 0 \
            --argjson checks "$checks_json" \
            '{violations: $violations, checks: $checks, status: "skipped"}' > "$checks_file"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi

    if [[ -z "$resource_paths_csv" ]]; then
        av_log_error "Missing mandatory: AV_PRINCIPAL_RESOURCE_PATHS (non-empty)"
        add_check "PRIN-00" "prerequisites" "skip" "missing resource paths"
        jq -n \
            --argjson violations 0 \
            --argjson checks "$checks_json" \
            '{violations: $violations, checks: $checks, status: "skipped"}' > "$checks_file"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi

    if [[ ! -x "$passless_bin" ]]; then
        av_log_error "passless binary not executable: $passless_bin"
        add_check "PRIN-00" "prerequisites" "skip" "passless binary not found"
        jq -n \
            --argjson violations 0 \
            --argjson checks "$checks_json" \
            '{violations: $violations, checks: $checks, status: "skipped"}' > "$checks_file"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi

    if [[ ! -x "$probe_bin" ]]; then
        av_log_error "probe binary not executable: $probe_bin"
        add_check "PRIN-00" "prerequisites" "skip" "probe binary not found"
        jq -n \
            --argjson violations 0 \
            --argjson checks "$checks_json" \
            '{violations: $violations, checks: $checks, status: "skipped"}' > "$checks_file"
        # shellcheck disable=SC2034
        STAGE_SKIPPED=true
        return 0
    fi

    if [[ "$probe_bin" != /* ]]; then
        av_log_error "probe binary path must be absolute: $probe_bin"
        add_check "PRIN-00" "prerequisites" "fail" "probe path not absolute"
        ((violations++)) || true
        jq -n \
            --argjson violations "$violations" \
            --argjson checks "$checks_json" \
            '{violations: $violations, checks: $checks}' > "$checks_file"
        return 1
    fi

    IFS=',' read -ra resource_paths <<< "$resource_paths_csv"

    local resource_expectations=()
    local i=1
    while true; do
        local var_name="AV_PRINCIPAL_RESOURCE_EXPECT_${i}"
        local var_value="${!var_name:-}"
        if [[ -z "$var_value" ]]; then
            break
        fi
        resource_expectations+=("$var_value")
        ((i++)) || true
    done

    av_log_info "Running principal probe: profile=$profile user=$principal_user"
    av_log_info "passless=$passless_bin probe=$probe_bin"
    av_log_info "resource paths: ${resource_paths[*]}"

    if ! av_run_principal_probe "$probe_json" "$probe_stderr" "$profile" "$passless_bin" "$probe_bin" "${resource_paths[@]}"; then
        av_log_error "Probe invocation failed"
        add_check "PRIN-00" "probe_invocation" "fail" "probe execution failed"
        ((violations++)) || true
        jq -n \
            --argjson violations "$violations" \
            --argjson checks "$checks_json" \
            '{violations: $violations, checks: $checks}' > "$checks_file"
        return 1
    fi

    av_log_info "Validating probe JSON schema..."
    if ! av_validate_probe_json_schema "$probe_json"; then
        av_log_error "Probe JSON schema validation failed"
        add_check "PRIN-00" "json_schema" "fail" "schema validation failed"
        ((violations++)) || true
        jq -n \
            --argjson violations "$violations" \
            --argjson checks "$checks_json" \
            '{violations: $violations, checks: $checks}' > "$checks_file"
        return 1
    fi
    add_check "PRIN-00" "json_schema" "pass" "valid schema"

    local probe_uid
    probe_uid=$(jq -r '.uid' "$probe_json")

    if [[ "$probe_uid" == "0" ]]; then
        av_log_error "PRIN-01: Running as root (UID 0)"
        add_check "PRIN-01" "not_root" "fail" "UID=0"
        ((violations++)) || true
    else
        av_log_info "PRIN-01: Not root (UID=$probe_uid)"
        add_check "PRIN-01" "not_root" "pass" "UID=$probe_uid"
    fi

    if av_check_probe_uid_matches_user "$probe_json" "$principal_user"; then
        add_check "PRIN-02" "uid_matches_user" "pass" "uid matches $principal_user"
    else
        add_check "PRIN-02" "uid_matches_user" "fail" "uid mismatch for $principal_user"
        ((violations++)) || true
    fi

    if av_check_probe_uid_gid "$probe_json" "$expect_uid" "$expect_gid"; then
        add_check "PRIN-03" "uid_gid_match" "pass" "uid=$probe_uid"
    else
        add_check "PRIN-03" "uid_gid_match" "fail" "uid/gid mismatch"
        ((violations++)) || true
    fi

    if av_check_probe_groups "$probe_json" "$expect_groups"; then
        add_check "PRIN-04" "supplementary_groups" "pass" "groups match"
    else
        add_check "PRIN-04" "supplementary_groups" "fail" "group mismatch"
        ((violations++)) || true
    fi

    if av_check_probe_nnp "$probe_json"; then
        av_log_info "PRIN-05: NoNewPrivs=true"
        add_check "PRIN-05" "no_new_privs" "pass" "NNP=true"
    else
        av_log_error "PRIN-05: NoNewPrivs is not true"
        add_check "PRIN-05" "no_new_privs" "fail" "NNP!=true"
        ((violations++)) || true
    fi

    if av_check_probe_cap_absence "$probe_json"; then
        av_log_info "PRIN-06: No capability-like env vars"
        add_check "PRIN-06" "no_cap_env" "pass" "clean env"
    else
        av_log_error "PRIN-06: Capability-like env vars found"
        add_check "PRIN-06" "no_cap_env" "fail" "cap env vars present"
        ((violations++)) || true
    fi

    if av_check_probe_namespace_separation "$probe_json" "$$"; then
        add_check "PRIN-07" "namespace_separation" "pass" "namespaces isolated"
    else
        add_check "PRIN-07" "namespace_separation" "fail" "namespace check failed"
        ((violations++)) || true
    fi

    if av_check_probe_cgroup_separation "$probe_json" "$$"; then
        add_check "PRIN-08" "cgroup_separation" "pass" "cgroup isolated"
    else
        add_check "PRIN-08" "cgroup_separation" "fail" "cgroup check failed"
        ((violations++)) || true
    fi

    if av_check_probe_fd3 "$probe_json" "$expect_fd3_peer_uid" "$expect_fd3_peer_gid"; then
        add_check "PRIN-09" "fd3_check" "pass" "fd3 socket with expected peer"
    else
        add_check "PRIN-09" "fd3_check" "fail" "fd3 check failed"
        ((violations++)) || true
    fi

    if [[ ${#resource_expectations[@]} -gt 0 ]]; then
        if av_check_probe_resource_outcomes "$probe_json" "${resource_expectations[@]}"; then
            add_check "PRIN-10" "resource_outcomes" "pass" "all match"
        else
            add_check "PRIN-10" "resource_outcomes" "fail" "outcome mismatch"
            ((violations++)) || true
        fi
    else
        add_check "PRIN-10" "resource_outcomes" "info" "no resource expectations"
    fi

    if av_compare_probe_pid_with_launch_metadata "$probe_json" "$probe_stderr"; then
        add_check "PRIN-11" "pid_comparison" "pass" "pid matches launch metadata"
    else
        add_check "PRIN-11" "pid_comparison" "fail" "pid mismatch or missing metadata"
        ((violations++)) || true
    fi

    local probe_pid
    probe_pid=$(jq -r '.pid' "$probe_json")
    av_log_info "Probe PID: $probe_pid"

    jq -n \
        --argjson violations "$violations" \
        --argjson checks "$checks_json" \
        '{violations: $violations, checks: $checks}' > "$checks_file"

    if [[ $violations -gt 0 ]]; then
        av_log_error "Principal isolation: $violations violation(s) found"
        return 1
    fi

    av_log_success "Principal isolation: all hard constraints satisfied"
    return 0
}
